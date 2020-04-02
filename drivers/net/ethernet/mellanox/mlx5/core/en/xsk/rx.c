// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2019 Mellanox Technologies. */

#include "rx.h"
#include "en/xdp.h"
#include <net/xdp_sock.h>
#include <net/xdp_sock_buff.h>

/* RX data path */

bool mlx5e_xsk_pages_enough_umem(struct mlx5e_rq *rq, int count)
{
	/* Check in advance that we have enough frames, instead of allocating
	 * one-by-one, failing and moving frames to the Reuse Ring.
	 */
	return xsk_buff_can_alloc(rq->umem, count);
}

int mlx5e_xsk_page_alloc_umem(struct mlx5e_rq *rq,
			      struct mlx5e_dma_info *dma_info)
{
	struct xdp_umem *umem = rq->umem;
	dma_addr_t dma;

	dma_info->xsk = xsk_buff_alloc(umem);
	if (!dma_info->xsk)
		return -ENOMEM;

	dma = xsk_buff_xdp_get_dma(umem, dma_info->xsk);

	dma_sync_single_for_device(rq->pdev, dma, PAGE_SIZE, DMA_BIDIRECTIONAL);

	return 0;
}

/* XSKRQ uses pages from UMEM, they must not be released. They are returned to
 * the userspace if possible, and if not, this function is called to reuse them
 * in the driver.
 */
void mlx5e_xsk_page_release(struct mlx5e_rq *rq,
			    struct mlx5e_dma_info *dma_info)
{
	xsk_buff_free(dma_info->xsk);
}

static struct sk_buff *mlx5e_xsk_construct_skb(struct mlx5e_rq *rq, void *data,
					       u32 cqe_bcnt)
{
	struct sk_buff *skb;

	skb = napi_alloc_skb(rq->cq.napi, cqe_bcnt);
	if (unlikely(!skb)) {
		rq->stats->buff_alloc_err++;
		return NULL;
	}

	skb_put_data(skb, data, cqe_bcnt);

	return skb;
}

struct sk_buff *mlx5e_xsk_skb_from_cqe_mpwrq_linear(struct mlx5e_rq *rq,
						    struct mlx5e_mpw_info *wi,
						    u16 cqe_bcnt,
						    u32 head_offset,
						    u32 page_idx)
{
	struct mlx5e_dma_info *di = &wi->umr.dma_info[page_idx];
	u32 cqe_bcnt32 = cqe_bcnt;
	u16 rx_headroom = 0;
	dma_addr_t dma;
	bool consumed;

	/* Check packet size. Note LRO doesn't use linear SKB */
	if (unlikely(cqe_bcnt > rq->hw_mtu)) {
		rq->stats->oversize_pkts_sw_drop++;
		return NULL;
	}

	/* head_offset is not used in this function, because di->xsk.data and
	 * di->addr point directly to the necessary place. Furthermore, in the
	 * current implementation, UMR pages are mapped to XSK frames, so
	 * head_offset should always be 0.
	 */
	WARN_ON_ONCE(head_offset);

	dma = xsk_buff_xdp_get_dma(rq->umem, di->xsk);
	dma_sync_single_for_cpu(rq->pdev, dma, cqe_bcnt32, DMA_BIDIRECTIONAL);
	prefetch(di->xsk->data);

	rcu_read_lock();
	consumed = mlx5e_xdp_handle(rq, NULL, NULL, &rx_headroom, &cqe_bcnt32, di->xsk);
	rcu_read_unlock();

	/* Possible flows:
	 * - XDP_REDIRECT to XSKMAP:
	 *   The page is owned by the userspace from now.
	 * - XDP_TX and other XDP_REDIRECTs:
	 *   The page was returned by ZCA and recycled.
	 * - XDP_DROP:
	 *   Recycle the page.
	 * - XDP_PASS:
	 *   Allocate an SKB, copy the data and recycle the page.
	 *
	 * Pages to be recycled go to the Reuse Ring on MPWQE deallocation. Its
	 * size is the same as the Driver RX Ring's size, and pages for WQEs are
	 * allocated first from the Reuse Ring, so it has enough space.
	 */

	if (likely(consumed)) {
		if (likely(__test_and_clear_bit(MLX5E_RQ_FLAG_XDP_XMIT, rq->flags)))
			__set_bit(page_idx, wi->xdp_xmit_bitmap); /* non-atomic */
		return NULL; /* page/packet was consumed by XDP */
	}

	/* XDP_PASS: copy the data from the UMEM to a new SKB and reuse the
	 * frame. On SKB allocation failure, NULL is returned.
	 */
	return mlx5e_xsk_construct_skb(rq, di->xsk->data, cqe_bcnt32);
}

struct sk_buff *mlx5e_xsk_skb_from_cqe_linear(struct mlx5e_rq *rq,
					      struct mlx5_cqe64 *cqe,
					      struct mlx5e_wqe_frag_info *wi,
					      u32 cqe_bcnt)
{
	struct mlx5e_dma_info *di = wi->di;
	u16 rx_headroom = 0;
	dma_addr_t dma;
	bool consumed;

	/* wi->offset is not used in this function, because di->xsk.data and
	 * di->addr point directly to the necessary place. Furthermore, in the
	 * current implementation, one page = one packet = one frame, so
	 * wi->offset should always be 0.
	 */
	WARN_ON_ONCE(wi->offset);

	dma = xsk_buff_xdp_get_dma(rq->umem, di->xsk);
	dma_sync_single_for_cpu(rq->pdev, dma, cqe_bcnt, DMA_BIDIRECTIONAL);
	prefetch(di->xsk->data);

	if (unlikely(get_cqe_opcode(cqe) != MLX5_CQE_RESP_SEND)) {
		rq->stats->wqe_err++;
		return NULL;
	}

	rcu_read_lock();
	consumed = mlx5e_xdp_handle(rq, NULL, NULL, &rx_headroom, &cqe_bcnt, di->xsk);
	rcu_read_unlock();

	if (likely(consumed))
		return NULL; /* page/packet was consumed by XDP */

	/* XDP_PASS: copy the data from the UMEM to a new SKB. The frame reuse
	 * will be handled by mlx5e_put_rx_frag.
	 * On SKB allocation failure, NULL is returned.
	 */
	return mlx5e_xsk_construct_skb(rq, di->xsk->data, cqe_bcnt);
}

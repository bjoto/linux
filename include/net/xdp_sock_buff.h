#ifndef XDP_SOCK_BUFF_H_
#define XDP_SOCK_BUFF_H_

#include <net/xdp_sock.h>
#include <net/xsk_buff.h>
#include <net/xsk_buff_unaligned.h>

struct xdp_buff_base {
	struct xdp_buff xdp;
	dma_addr_t dma;
	void *pool;
	bool unaligned;
};

static inline void xsk_buff_set_rxq_info(struct xdp_umem *umem,
					 struct xdp_rxq_info *rxq)
{
	umem->unaligned_buff_pool ?
		xpu_set_rxq_info(umem->buff_pool, rxq) :
		xp_set_rxq_info(umem->buff_pool, rxq);
}

static inline void xsk_buff_dma_unmap(struct xdp_umem *umem, struct device *dev,
				      unsigned long attrs)
{
	umem->unaligned_buff_pool ?
		xpu_dma_unmap(umem->buff_pool, dev, attrs) :
		xp_dma_unmap(umem->buff_pool, dev, attrs);
}

static inline int xsk_buff_dma_map(struct xdp_umem *umem, struct device *dev,
				   unsigned long attrs)
{
	return umem->unaligned_buff_pool ?
		xpu_dma_map(umem->buff_pool, dev, attrs, umem->pgs,
			    umem->npgs) :
		xp_dma_map(umem->buff_pool, dev, attrs, umem->pgs, umem->npgs);
}

static inline dma_addr_t xsk_buff_xdp_get_dma(struct xdp_umem *umem,
					      struct xdp_buff *xdp)
{
	return ((struct xdp_buff_base *)xdp)->dma;
}

static inline struct xdp_buff *xsk_buff_alloc(struct xdp_umem *umem)
{
	return umem->unaligned_buff_pool ?
		xpu_alloc(umem->buff_pool) :
		xp_alloc(umem->buff_pool);
}

static inline bool xsk_buff_can_alloc(struct xdp_umem *umem, u32 count)
{
	return umem->unaligned_buff_pool ?
		xpu_can_alloc(umem->buff_pool, count) :
		xp_can_alloc(umem->buff_pool, count);
}

static inline void xsk_buff_free(struct xdp_buff *xdp)
{
	struct xdp_buff_base *b = (struct xdp_buff_base *)xdp;

	b->unaligned ? xpu_free(b->pool, xdp) : xp_free(b->pool, xdp);
}

static inline void xsk_buff_release(struct xdp_buff *xdp)
{
	struct xdp_buff_base *b = (struct xdp_buff_base *)xdp;

	b->unaligned ? xpu_release(b->pool, xdp) : xp_release(b->pool, xdp);
}

static inline u64 xsk_buff_get_handle(struct xdp_buff *xdp)
{
	struct xdp_buff_base *b = (struct xdp_buff_base *)xdp;

	return b->unaligned ? xpu_get_handle(b->pool, xdp) :
		xp_get_handle(b->pool, xdp);
}

static inline dma_addr_t xsk_buff_raw_get_dma(struct xdp_umem *umem, u64 addr)
{
	return umem->unaligned_buff_pool ? xpu_get_dma(umem->buff_pool, addr) :
		xp_get_dma(umem->buff_pool, addr);
}

static inline void *xsk_buff_raw_get_data(struct xdp_umem *umem, u64 addr)
{
	return umem->unaligned_buff_pool ? xpu_get_data(umem->buff_pool, addr) :
		xp_get_data(umem->buff_pool, addr);
}

static inline bool xsk_buff_raw_validate_desc(struct xdp_umem *umem,
					      struct xdp_desc *desc)
{
	return umem->unaligned_buff_pool ?
		xpu_validate_desc(umem->buff_pool, desc) :
		xp_validate_desc(umem->buff_pool, desc);
}

static inline void xsk_buff_dma_sync_for_device(struct xdp_umem *umem,
						struct xdp_buff *xdp,
						size_t size)
{
	return umem->unaligned_buff_pool ?
		xpu_dma_sync_for_device(umem->buff_pool, xdp, size) :
		xp_dma_sync_for_device(umem->buff_pool, xdp, size);
}

static inline void xsk_buff_dma_sync_for_cpu(struct xdp_umem *umem,
					     struct xdp_buff *xdp,
					     size_t size)
{
	return umem->unaligned_buff_pool ?
		xpu_dma_sync_for_cpu(umem->buff_pool, xdp, size) :
		xp_dma_sync_for_cpu(umem->buff_pool, xdp, size);
}

#endif /* XDP_SOCK_BUFF_H_ */

#ifndef XSK_BUFF_H_
#define XSK_BUFF_H_

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/cache.h>
#include <linux/bpf.h>
#include <linux/if_xdp.h>
#include <net/xdp.h>
#include <linux/dma-mapping.h>

struct page;
struct device;
struct xsk_queue;
struct xdp_desc;

struct xdp_buff_xp {
	struct xdp_buff xdp;
	dma_addr_t dma;
	struct xsk_buff_pool *pool;
	bool unaligned;
	bool highmem;
};

struct xsk_buff_pool {
	struct xsk_queue *fq;
	struct xdp_buff_xp **free_buffs;
	u32 free_buffs_cnt;
	u32 headroom;
	u32 chunk_bits;
	u32 base_size;
	u32 active;
	bool cheap_dma;
	struct device *dev;
	struct xdp_buff_xp base[];
};

struct xsk_buff_pool *xp_create(struct page **pages,u32 nr_pages, u32 chunks,
			   u32 chunk_size, u32 headroom);
void xp_destroy(struct xsk_buff_pool *xp);

void xp_set_rxq_info(struct xsk_buff_pool *xp, struct xdp_rxq_info *rxq);
void xp_set_fq(struct xsk_buff_pool *xp, struct xsk_queue *fq);
void xp_dma_unmap(struct xsk_buff_pool *xp, struct device *dev,
		  unsigned long attrs);
int xp_dma_map(struct xsk_buff_pool *xp, struct device *dev,
	       unsigned long attrs, struct page **pages, u32 nr_pages);

struct xdp_buff *xp_alloc(struct xsk_buff_pool *xp);
bool xp_can_alloc(struct xsk_buff_pool *xp, u32 count);
void xp_free(struct xsk_buff_pool *xp, struct xdp_buff *xdp);

static inline void xp_release(struct xsk_buff_pool *xp, struct xdp_buff *xdp)
{
	xp->active--;
}

static inline u64 xp_get_handle(struct xsk_buff_pool *xp, struct xdp_buff *xdp)
{
	struct xdp_buff_xp *buff = (struct xdp_buff_xp *)xdp;
	u64 addr, offset;

	addr = (buff - &xp->base[0]) << xp->chunk_bits;
	offset = xdp->data - xdp->data_hard_start;
	return addr + xp->headroom + offset;
}

static inline dma_addr_t xp_get_dma(struct xsk_buff_pool *xp, u64 addr)
{
	struct xdp_buff_xp *buff;
	u64 offset, chunk;

	chunk = addr >> xp->chunk_bits;
	buff = &xp->base[chunk];

	chunk <<= xp->chunk_bits;
	offset = addr - chunk;
	return buff->dma - xp->headroom - XDP_PACKET_HEADROOM + offset;
}

static inline void *xp_get_data(struct xsk_buff_pool *xp, u64 addr)
{
	struct xdp_buff_xp *buff;
	u64 offset, chunk;

	chunk = addr >> xp->chunk_bits;
	buff = &xp->base[chunk];

	chunk <<= xp->chunk_bits;
	offset = addr - chunk;
	return buff->xdp.data_hard_start - xp->headroom + offset;
}

static inline bool xp_validate_desc(struct xsk_buff_pool *xp,
				    struct xdp_desc *desc)
{
	u64 chunk, chunk_end;

	chunk = desc->addr >> xp->chunk_bits;;
	chunk_end = (desc->addr + desc->len) >> xp->chunk_bits;
	if (chunk != chunk_end)
		return false;

	if (chunk >= xp->base_size)
		return false;

	if (desc->options)
		return false;
	return true;
}

static inline void xp_dma_sync_for_device(struct xsk_buff_pool *xp,
					  dma_addr_t dma, size_t size)
{
	if (xp->cheap_dma)
		return;

	dma_sync_single_range_for_device(xp->dev, dma, 0, size,
					 DMA_BIDIRECTIONAL);
}

static inline void xp_dma_sync_for_cpu(struct xsk_buff_pool *xp,
				       struct xdp_buff *xdp, size_t size)
{
	struct xdp_buff_xp *buff = (struct xdp_buff_xp *)xdp;

	if (xp->cheap_dma)
		return;

	dma_sync_single_range_for_cpu(xp->dev, buff->dma, 0,
				      size, DMA_BIDIRECTIONAL);
}

#endif /* XSK_BUFF_H_ */

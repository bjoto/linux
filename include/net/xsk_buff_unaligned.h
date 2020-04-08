#ifndef XSK_BUFF_UNALIGNED_H_
#define XSK_BUFF_UNALIGNED_H_

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/cache.h>
#include <linux/if_xdp.h>
#include <net/xdp.h>

struct page;
struct device;
struct xsk_queue;

struct xdp_buff_xpu {
	struct xdp_buff xdp;
	dma_addr_t dma;
	struct xsk_buff_pool_unaligned *pool;
	bool unaligned;
	u64 addr;
};

struct xsk_buff_pool_unaligned {
	struct xsk_queue *fq;
	struct xdp_buff_xpu **free_buffs;
	u32 free_buffs_cnt;
	u32 headroom;
	u32 chunk_size;
	u32 dma_pages_size;
	void *addrs;
	dma_addr_t *dma_pages;
	struct xdp_rxq_info *rxq;
	u32 handles_cnt;
	bool cheap_dma;
	struct device *dev;
	struct xdp_buff_xpu* handles[];
};

struct xsk_buff_pool_unaligned *xpu_create(struct page **pages,u32 nr_pages,
				      u32 chunks, u32 chunk_size, u32 headroom);
void xpu_destroy(struct xsk_buff_pool_unaligned *xpu);

void xpu_set_rxq_info(struct xsk_buff_pool_unaligned *xpu,
		      struct xdp_rxq_info *rxq);
void xpu_set_fq(struct xsk_buff_pool_unaligned *xpu, struct xsk_queue *fq);
void xpu_dma_unmap(struct xsk_buff_pool_unaligned *xpu, struct device *dev,
		   unsigned long attrs);
int xpu_dma_map(struct xsk_buff_pool_unaligned *xpu, struct device *dev,
		unsigned long attrs, struct page **pages, u32 nr_pages);

struct xdp_buff *xpu_alloc(struct xsk_buff_pool_unaligned *xpu);
bool xpu_can_alloc(struct xsk_buff_pool_unaligned *xpu, u32 count);
void xpu_free(struct xsk_buff_pool_unaligned *xpu, struct xdp_buff *xdp);
void xpu_release(struct xsk_buff_pool_unaligned *xpu, struct xdp_buff *xdp);

static inline u64 xpu_get_handle(struct xsk_buff_pool_unaligned *xpu,
				 struct xdp_buff *xdp)
{
	struct xdp_buff_xpu *buff = (struct xdp_buff_xpu *)xdp;
	u64 offset = xdp->data - xdp->data_hard_start;

	offset += xpu->headroom;
	return buff->addr + (offset << XSK_UNALIGNED_BUF_OFFSET_SHIFT);
}

static inline u64 xpu_extract_addr(u64 addr)
{
	return addr & XSK_UNALIGNED_BUF_ADDR_MASK;
}

static inline u64 xpu_extract_offset(u64 addr)
{
	return addr >> XSK_UNALIGNED_BUF_OFFSET_SHIFT;
}

static inline u64 xpu_add_offset_to_addr(u64 addr)
{
	return xpu_extract_addr(addr) + xpu_extract_offset(addr);
}

static inline void *xpu_get_data(struct xsk_buff_pool_unaligned *xpu, u64 addr)
{
	addr = xpu_add_offset_to_addr(addr);
	return xpu->addrs + addr;
}

static inline dma_addr_t xpu_get_dma(struct xsk_buff_pool_unaligned *xpu,
				     u64 addr)
{
	addr = xpu_add_offset_to_addr(addr);
	return (xpu->dma_pages[addr >> PAGE_SHIFT] & ~1ULL) +
		(addr & ~PAGE_MASK);
}

bool xpu_validate_desc(struct xsk_buff_pool_unaligned *xp,
		       struct xdp_desc *desc);

static inline void xpu_dma_sync_for_device(struct xsk_buff_pool_unaligned *xpu,
					   dma_addr_t dma, size_t size)
{
	if (xpu->cheap_dma)
		return;

	dma_sync_single_range_for_device(xpu->dev, dma, 0,
					 size, DMA_BIDIRECTIONAL);
}

static inline void xpu_dma_sync_for_cpu(struct xsk_buff_pool_unaligned *xpu,
				       struct xdp_buff *xdp, size_t size)
{
	struct xdp_buff_xpu *buff = (struct xdp_buff_xpu *)xdp;

	if (xpu->cheap_dma)
		return;

	dma_sync_single_range_for_cpu(xpu->dev, buff->dma, 0,
				      size, DMA_BIDIRECTIONAL);
}

#endif /* XSK_BUFF_UNALIGNED_H_ */

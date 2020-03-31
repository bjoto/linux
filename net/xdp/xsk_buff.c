#include <net/xsk_buff.h>
#include "xsk_queue.h"

static void xp_addr_unmap(struct xsk_buff_pool *xp)
{
	u32 i, chunks_per_page;
	void *addr;

	chunks_per_page = PAGE_SIZE / (1 << xp->chunk_bits);

	for (i = 0; i < xp->base_size; i += chunks_per_page) {
		addr = xp->base[i].xdp.data_hard_start;
		if (xp->base[i].highmem)
			vunmap(addr);
	}
}

static int xp_addr_map(struct xsk_buff_pool *xp, struct page **pages,
		       u32 nr_pages)
{
	u32 i, j, k, chunks_per_page, chunk_size;
	bool highmem;
	void *addr;

	chunk_size = 1 << xp->chunk_bits;
	chunks_per_page = PAGE_SIZE / chunk_size;
	k = 0;

	for (i = 0; i < nr_pages; i++) {
		if (PageHighMem(pages[i])) {
			addr = vmap(&pages[i], 1, VM_MAP, PAGE_KERNEL);
			highmem = true;
		} else {
			addr = page_address(pages[i]);
			highmem = false;
		}

		if (!addr) {
			xp_addr_unmap(xp);
			return -ENOMEM;
		}

		for (j = 0; j < chunks_per_page; j++) {
			xp->base[k].xdp.data_hard_start = addr + xp->headroom;
			xp->base[k].highmem = highmem;
			xp->base[k].pool = xp;
			xp->base[k].unaligned = false;;
			k++;
			addr += chunk_size;
		}
	}
	return 0;
}

void xp_destroy(struct xsk_buff_pool *xp)
{
	if (!xp)
		return;

	if (xp->free_buffs)
		xp_addr_unmap(xp);

	kvfree(xp->free_buffs);
	kvfree(xp);
}

struct xsk_buff_pool *xp_create(struct page **pages, u32 nr_pages, u32 chunks,
			   u32 chunk_size, u32 headroom)
{
	struct xsk_buff_pool *xp;
	int err;

	xp = kvzalloc(struct_size(xp, base, chunks), GFP_KERNEL);
	if (!xp)
		goto out;

	xp->free_buffs = kvcalloc(chunks, sizeof(*xp->free_buffs), GFP_KERNEL);
	if (!xp->free_buffs)
		goto out;

	xp->headroom = headroom;
	xp->chunk_bits = __ffs(chunk_size);
	xp->base_size = chunks;

	err = xp_addr_map(xp, pages, nr_pages);
	if (err)
		goto out;
	return xp;

out:
	xp_destroy(xp);
	return NULL;
}

void xp_set_fq(struct xsk_buff_pool *xp, struct xsk_queue *fq)
{
	xp->fq = fq;
}

void xp_dma_unmap(struct xsk_buff_pool *xp, struct device *dev,
		  unsigned long attrs)
{
	u32 i, j, chunks_per_page;
	dma_addr_t dma;

	chunks_per_page = PAGE_SIZE / (1 << xp->chunk_bits);

	for (i = 0; i < xp->base_size; i += chunks_per_page) {
		dma = xp->base[i].dma;
		if (dma)
			dma_unmap_page_attrs(dev, dma, PAGE_SIZE,
					     DMA_BIDIRECTIONAL, attrs);

		for (j = 0; j < chunks_per_page; j++)
			xp->base[j].dma = 0;
	}
}
EXPORT_SYMBOL(xp_dma_unmap);

int xp_dma_map(struct xsk_buff_pool *xp, struct device *dev,
	       unsigned long attrs, struct page **pages, u32 nr_pages)
{
	u32 i, j, k, chunks_per_page, chunk_size;
	dma_addr_t dma;

	chunk_size = 1 << xp->chunk_bits;
	chunks_per_page = PAGE_SIZE / chunk_size;
	k = 0;

	for (i = 0; i < nr_pages; i++) {
		dma = dma_map_page_attrs(dev, pages[i], 0, PAGE_SIZE,
					 DMA_BIDIRECTIONAL, attrs);
		if (dma_mapping_error(dev, dma)) {
			xp_dma_unmap(xp, dev, attrs);
			return -ENOMEM;
		}

		for (j = 0; j < chunks_per_page; j++) {
			xp->base[k].dma = dma + xp->headroom +
					  XDP_PACKET_HEADROOM;
			k++;
			dma += chunk_size;
		}
	}
	return 0;
}
EXPORT_SYMBOL(xp_dma_map);

void xp_set_rxq_info(struct xsk_buff_pool *xp, struct xdp_rxq_info *rxq)
{
	u32 i;

	for (i = 0; i < xp->base_size; i++)
		xp->base[i].xdp.rxq = rxq;
}
EXPORT_SYMBOL(xp_set_rxq_info);

struct xdp_buff *xp_alloc(struct xsk_buff_pool *xp)
{
	struct xdp_buff *xdp;
	u64 addr;

	if (xp->free_buffs_cnt) {
		xdp = (struct xdp_buff *)xp->free_buffs[--xp->free_buffs_cnt];
	} else {
		if (!xskq_cons_peek_addr_aligned(xp->fq, &addr))
			return NULL;
		xskq_cons_release(xp->fq);
		addr >>= xp->chunk_bits;
		xdp = (struct xdp_buff *)(&xp->base[addr]);
	}
	if (xp->active > xp->base_size)
		return NULL;
	xp->active++;
	xdp->data = xdp->data_hard_start + XDP_PACKET_HEADROOM;
	xdp->data_meta = xdp->data;
	return xdp;
}
EXPORT_SYMBOL(xp_alloc);

bool xp_can_alloc(struct xsk_buff_pool *xp, u32 count)
{
	if (xp->free_buffs_cnt >= count)
		return true;
	return xskq_cons_has_entries(xp->fq, count - xp->free_buffs_cnt);
}
EXPORT_SYMBOL(xp_can_alloc);

void xp_free(struct xsk_buff_pool *xp, struct xdp_buff *xdp)
{
	xp->free_buffs[xp->free_buffs_cnt++] = (struct xdp_buff_xp *)xdp;
	xp->active--;
}
EXPORT_SYMBOL(xp_free);



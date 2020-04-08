#include <net/xdp_sock.h>
#include <net/xsk_buff_unaligned.h>
#include <linux/mm.h>

#include "xsk_queue.h"

static void xpu_check_page_contiguity(struct xsk_buff_pool_unaligned *xpu)
{
	u32 i;

	for (i = 0; i < xpu->dma_pages_size - 1; i++) {
		if (xpu->dma_pages[i] + PAGE_SIZE == xpu->dma_pages[i + 1])
			xpu->dma_pages[i] |= XSK_NEXT_PG_CONTIG_MASK;
		else
			xpu->dma_pages[i] &= ~XSK_NEXT_PG_CONTIG_MASK;
	}
}

static void xpu_addr_unmap(struct xsk_buff_pool_unaligned *xpu)
{
	vunmap(xpu->addrs);
}

static int xpu_addr_map(struct xsk_buff_pool_unaligned *xpu,
			struct page **pages, u32 nr_pages)
{
	xpu->addrs = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!xpu->addrs)
		return -ENOMEM;
	return 0;
}

void xpu_destroy(struct xsk_buff_pool_unaligned *xpu)
{
	u32 i;

	if (!xpu)
		return;

	xpu_addr_unmap(xpu);

	if (xpu->free_buffs) {
		for (i = 0; i < xpu->free_buffs_cnt; i++)
			kfree(xpu->free_buffs[i]);
		xpu->free_buffs_cnt = 0;
	}

	for (i = 0; i < xpu->handles_cnt; i++)
		kfree(xpu->handles[i]);
	xpu->handles_cnt = 0;

	kvfree(xpu->free_buffs);
	kvfree(xpu);
}

struct xsk_buff_pool_unaligned *xpu_create(struct page **pages, u32 nr_pages,
					   u32 chunks, u32 chunk_size,
					   u32 headroom)
{
	struct xsk_buff_pool_unaligned *xpu;
	int err;
	u32 i;

	xpu = kvzalloc(struct_size(xpu, handles, chunks), GFP_KERNEL);
	if (!xpu)
		goto out;

	xpu->free_buffs = kvcalloc(chunks, sizeof(*xpu->free_buffs),
				   GFP_KERNEL);
	if (!xpu->free_buffs)
		goto out;

	xpu->headroom = headroom;
	xpu->chunk_size = chunk_size;

	for (i = 0; i < chunks; i++) {
		xpu->handles[i] = kzalloc(sizeof(struct xdp_buff_xpu),
					  GFP_KERNEL);
		if (!xpu->handles[i])
			goto out;
		xpu->handles[i]->pool = xpu;
		xpu->handles[i]->unaligned = true;
		xpu->handles_cnt++;
	}

	err = xpu_addr_map(xpu, pages, nr_pages);
	if (err)
		goto out;
	return xpu;

out:
	xpu_destroy(xpu);
	return NULL;
}

void xpu_set_fq(struct xsk_buff_pool_unaligned *xpu, struct xsk_queue *fq)
{
	xpu->fq = fq;
}

void xpu_dma_unmap(struct xsk_buff_pool_unaligned *xpu, struct device *dev,
		   unsigned long attrs)
{
	dma_addr_t *dma;
	u32 i;

	if (xpu->dma_pages_size == 0)
		return;

	for (i = 0; i < xpu->dma_pages_size; i++) {
		dma = &xpu->dma_pages[i];

		if (*dma) {
			dma_unmap_page_attrs(dev, *dma, PAGE_SIZE,
					     DMA_BIDIRECTIONAL, attrs);
			*dma = 0;
		}
	}

	kvfree(xpu->dma_pages);
	xpu->dma_pages_size = 0;
	xpu->dev = NULL;
}
EXPORT_SYMBOL(xpu_dma_unmap);

int xpu_dma_map(struct xsk_buff_pool_unaligned *xpu, struct device *dev,
		unsigned long attrs, struct page **pages, u32 nr_pages)
{
	dma_addr_t dma;
	u32 i;

	xpu->dma_pages = kvcalloc(nr_pages, sizeof(*xpu->dma_pages),
				  GFP_KERNEL);
	if (!xpu->dma_pages)
		return -ENOMEM;
	xpu->dma_pages_size = nr_pages;

	for (i = 0; i < xpu->dma_pages_size; i++) {
		dma = dma_map_page_attrs(dev, pages[i], 0, PAGE_SIZE,
					 DMA_BIDIRECTIONAL, attrs);
		if (dma_mapping_error(dev, dma)) {
			xpu_dma_unmap(xpu, dev, attrs);
			return -ENOMEM;
		}
		xpu->dma_pages[i] = dma;
	}

	xpu_check_page_contiguity(xpu);
	// XXX
	xpu->cheap_dma = true;
	xpu->dev = dev;
	return 0;
}
EXPORT_SYMBOL(xpu_dma_map);

void xpu_set_rxq_info(struct xsk_buff_pool_unaligned *xpu,
		      struct xdp_rxq_info *rxq)
{
	xpu->rxq = rxq;
}
EXPORT_SYMBOL(xpu_set_rxq_info);

static bool xpu_desc_crosses_non_contig_pg(struct xsk_buff_pool_unaligned *xpu,
					   u64 addr, u32 len)
{
	bool cross_pg = (addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE;

	if (xpu->dma_pages_size && cross_pg) {
		return !(xpu->dma_pages[addr >> PAGE_SHIFT] &
			 XSK_NEXT_PG_CONTIG_MASK);
	}

	return false;

}

static bool xpu_addr_crosses_non_contig_pg(struct xsk_buff_pool_unaligned *xpu,
					   u64 addr)
{
	return xpu_desc_crosses_non_contig_pg(xpu, addr, xpu->chunk_size);
}

void xpu_release(struct xsk_buff_pool_unaligned *xpu, struct xdp_buff *xdp)
{
	xpu->handles[xpu->handles_cnt++] = (struct xdp_buff_xpu *)xdp;
}

struct xdp_buff *xpu_alloc(struct xsk_buff_pool_unaligned *xpu)
{
	struct xdp_buff_xpu *xdp;
	u64 addr;

	if (xpu->free_buffs_cnt) {
		xdp = xpu->free_buffs[--xpu->free_buffs_cnt];
		goto init;
	}

	if (xpu->handles_cnt == 0)
		return NULL;

	xdp = xpu->handles[--xpu->handles_cnt];

retry:
	if (!xskq_cons_peek_addr_unchecked(xpu->fq, &addr)) {
		xpu_release(xpu, (struct xdp_buff *)xdp);
		return NULL;
	}

	addr = xpu_extract_addr(addr);
	if (addr >= xpu->fq->size || addr + xpu->chunk_size > xpu->fq->size
	    || xpu_addr_crosses_non_contig_pg(xpu, addr)) {
		xpu->fq->invalid_descs++;
		xskq_cons_release(xpu->fq);
		goto retry;
	}

	xskq_cons_release(xpu->fq);
	xdp->xdp.data_hard_start = xpu->addrs + addr;
	if (xpu->dma_pages_size) {
		xdp->dma = (xpu->dma_pages[addr >> PAGE_SHIFT] & ~1ULL) +
			   (addr & ~PAGE_MASK) +
			   xpu->headroom + XDP_PACKET_HEADROOM;
	}
	xdp->addr = addr;
	xdp->xdp.rxq = xpu->rxq;

init:
	xdp->xdp.data = xdp->xdp.data_hard_start + XDP_PACKET_HEADROOM;
	xdp->xdp.data_meta = xdp->xdp.data;

	return (struct xdp_buff *)xdp;
}
EXPORT_SYMBOL(xpu_alloc);

bool xpu_can_alloc(struct xsk_buff_pool_unaligned *xpu, u32 count)
{
	if (xpu->free_buffs_cnt >= count)
		return true;
	return xskq_cons_has_entries(xpu->fq, count - xpu->free_buffs_cnt);
}
EXPORT_SYMBOL(xpu_can_alloc);

void xpu_free(struct xsk_buff_pool_unaligned *xpu, struct xdp_buff *xdp)
{
	xpu->free_buffs[xpu->free_buffs_cnt++] = (struct xdp_buff_xpu *)xdp;
}
EXPORT_SYMBOL(xpu_free);

bool xpu_validate_desc(struct xsk_buff_pool_unaligned *xpu,
		       struct xdp_desc *desc)
{
	u64 addr, base_addr;

	base_addr = xpu_extract_addr(desc->addr);
	addr = xpu_add_offset_to_addr(desc->addr);

	if (desc->len > xpu->chunk_size)
		return false;

	if (base_addr >= xpu->fq->size || addr >= xpu->fq->size ||
	    xpu_desc_crosses_non_contig_pg(xpu, addr, desc->len))
		return false;

	if (desc->options)
		return false;
	return true;
}

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#ifndef _ASM_RISCV_IRQ_H
#define _ASM_RISCV_IRQ_H

#include <linux/interrupt.h>
#include <linux/linkage.h>

#include <asm-generic/irq.h>

void riscv_set_intc_hwnode_fn(struct fwnode_handle *(*fn)(void));

struct fwnode_handle *riscv_get_intc_hwnode(void);

#ifdef CONFIG_ACPI

enum riscv_irqchip_type {
	ACPI_RISCV_IRQCHIP_INTC		= 0x00,
	ACPI_RISCV_IRQCHIP_IMSIC	= 0x01,
	ACPI_RISCV_IRQCHIP_PLIC		= 0x02,
	ACPI_RISCV_IRQCHIP_APLIC	= 0x03,
};

/*
 * The ext_intc_id format is as follows:
 * Bits [31:24] APLIC/PLIC ID
 * Bits [15:0] APLIC IDC ID / PLIC S-Mode Context ID for this hart
 */
#define APLIC_PLIC_ID(x) ((x) >> 24)
#define IDC_CONTEXT_ID(x) ((x) & 0x0000ffff)

int riscv_acpi_get_gsi_info(struct fwnode_handle *fwnode, u32 *gsi_base,
			    u32 *id, u32 *nr_irqs, u32 *nr_idcs);
struct fwnode_handle *riscv_acpi_get_gsi_domain_id(u32 gsi);
int __init acpi_get_intc_index_hartid(u32 index, unsigned long *hartid);
int acpi_get_ext_intc_parent_hartid(u8 id, u32 idx, unsigned long *hartid);
void acpi_get_plic_nr_contexts(u8 id, int *nr_contexts);
int acpi_get_plic_context(u8 id, u32 idx, int *context_id);
int __init acpi_get_imsic_mmio_info(u32 index, struct resource *res);

#else
static inline int riscv_acpi_get_gsi_info(struct fwnode_handle *fwnode, u32 *gsi_base,
					  u32 *id, u32 *nr_irqs, u32 *nr_idcs)
{
	return 0;
}

static inline int __init acpi_get_intc_index_hartid(u32 index, unsigned long *hartid)
{
	return -EINVAL;
}

static inline int acpi_get_ext_intc_parent_hartid(u8 id, u32 idx, unsigned long *hartid)
{
	return -EINVAL;
}

static inline void acpi_get_plic_nr_contexts(u8 id, int *nr_contexts) { }

static inline int acpi_get_plic_context(u8 id, u32 idx, int *context_id)
{
	return -EINVAL;
}

static inline int __init acpi_get_imsic_mmio_info(u32 index, struct resource *res)
{
	return 0;
}

#endif /* CONFIG_ACPI */

#endif /* _ASM_RISCV_IRQ_H */

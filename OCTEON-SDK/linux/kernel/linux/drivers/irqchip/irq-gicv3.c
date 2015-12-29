/*
 *  linux/arch/arm/common/gic.c
 *
 *  Copyright (C) 2002 ARM Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Interrupt architecture for the GIC:
 *
 * o There is one Interrupt Distributor, which receives interrupts
 *   from system devices and sends them to the Interrupt Controllers.
 *
 * o There is one CPU Interface per CPU, which sends interrupts sent
 *   by the Distributor, and interrupts generated locally, to the
 *   associated CPU. The base address of the CPU interface is usually
 *   aliased so that the same address points to different chips depending
 *   on the CPU it is accessed from.
 *
 * Note that IRQs 0-31 are special - they are local to each CPU.
 * As such, the enable set/clear, pending set/clear and active bit
 * registers are banked per-cpu for these sources.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/cpu_pm.h>
#include <linux/cpumask.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/irqdomain.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/irqchip/arm-gic.h>

#include <asm/arm_sysregs.h>
#include <asm/irq.h>
#include <asm/exception.h>
#include <asm/smp_plat.h>

#include "irqchip.h"

union gicv3_base {
	void __iomem *common_base;
	void __percpu __iomem **percpu_base;
};

struct gicv3_chip_data {
	union gicv3_base dist_base;
	union gicv3_base cpu_base;
#ifdef CONFIG_CPU_PM
	u32 saved_spi_enable[DIV_ROUND_UP(1020, 32)];
	u32 saved_spi_conf[DIV_ROUND_UP(1020, 16)];
	u32 saved_spi_target[DIV_ROUND_UP(1020, 4)];
	u32 __percpu *saved_ppi_enable;
	u32 __percpu *saved_ppi_conf;
#endif
	struct irq_domain *domain;
	unsigned int gicv3_irqs;
#ifdef CONFIG_GIC_NON_BANKED
	void __iomem *(*get_base)(union gicv3_base *);
#endif
};

static DEFINE_RAW_SPINLOCK(irq_controller_lock);

/*
 * The GIC mapping of CPU interfaces does not necessarily match
 * the logical CPU numbering.  Let's use a mapping as returned
 * by the GIC itself.
 */
#define NR_GICV3_CPU_IF 8
static u8 gicv3_cpu_map[NR_GICV3_CPU_IF] __read_mostly;

/*
 * Supported arch specific GIC irq extension.
 * Default make them NULL.
 */
struct irq_chip gicv3_arch_extn = {
	.irq_eoi	= NULL,
	.irq_mask	= NULL,
	.irq_unmask	= NULL,
	.irq_retrigger	= NULL,
	.irq_set_type	= NULL,
	.irq_set_wake	= NULL,
};

#ifndef MAX_GICV3_NR
#define MAX_GICV3_NR	1
#endif

static struct gicv3_chip_data gicv3_data[MAX_GICV3_NR] __read_mostly;

#ifdef CONFIG_GIC_NON_BANKED
static void __iomem *gicv3_get_percpu_base(union gicv3_base *base)
{
	return *__this_cpu_ptr(base->percpu_base);
}

static void __iomem *gicv3_get_common_base(union gicv3_base *base)
{
	return base->common_base;
}

static inline void __iomem *gicv3_data_dist_base(struct gicv3_chip_data *data)
{
	return data->get_base(&data->dist_base);
}

static inline void __iomem *gicv3_data_cpu_base(struct gicv3_chip_data *data)
{
	return data->get_base(&data->cpu_base);
}

static inline void gicv3_set_base_accessor(struct gicv3_chip_data *data,
					 void __iomem *(*f)(union gicv3_base *))
{
	data->get_base = f;
}
#else
#define gicv3_data_dist_base(d)	((d)->dist_base.common_base)
#define gicv3_data_cpu_base(d)	((d)->cpu_base.common_base)
#define gicv3_set_base_accessor(d, f)
#endif

static inline void __iomem *gicv3_dist_base(struct irq_data *d)
{
	struct gicv3_chip_data *gicv3_data = irq_data_get_irq_chip_data(d);
	return gicv3_data_dist_base(gicv3_data);
}

static inline void __iomem *gicv3_cpu_base(struct irq_data *d)
{
	struct gicv3_chip_data *gicv3_data = irq_data_get_irq_chip_data(d);
	return gicv3_data_cpu_base(gicv3_data);
}

static inline unsigned int gicv3_irq(struct irq_data *d)
{
	return d->hwirq;
}

/*
 * Routines to acknowledge, disable and enable interrupts
 */
static void gicv3_mask_irq(struct irq_data *d)
{
	u32 mask = 1 << (gicv3_irq(d) % 32);

	raw_spin_lock(&irq_controller_lock);
	writel_relaxed(mask, gicv3_dist_base(d) + GIC_DIST_ENABLE_CLEAR + (gicv3_irq(d) / 32) * 4);
	if (gicv3_arch_extn.irq_mask)
		gicv3_arch_extn.irq_mask(d);
	raw_spin_unlock(&irq_controller_lock);
}

static void gicv3_unmask_irq(struct irq_data *d)
{
	u32 mask = 1 << (gicv3_irq(d) % 32);

	raw_spin_lock(&irq_controller_lock);
	if (gicv3_arch_extn.irq_unmask)
		gicv3_arch_extn.irq_unmask(d);
	writel_relaxed(mask, gicv3_dist_base(d) + GIC_DIST_ENABLE_SET + (gicv3_irq(d) / 32) * 4);
	raw_spin_unlock(&irq_controller_lock);
}

static void gicv3_eoi_irq(struct irq_data *d)
{
	if (gicv3_arch_extn.irq_eoi) {
		raw_spin_lock(&irq_controller_lock);
		gicv3_arch_extn.irq_eoi(d);
		raw_spin_unlock(&irq_controller_lock);
	}

	writel_icc_eoir1(gicv3_irq(d));
}

static int gicv3_set_type(struct irq_data *d, unsigned int type)
{
	void __iomem *base = gicv3_dist_base(d);
	unsigned int gicirq = gicv3_irq(d);
	u32 enablemask = 1 << (gicirq % 32);
	u32 enableoff = (gicirq / 32) * 4;
	u32 confmask = 0x2 << ((gicirq % 16) * 2);
	u32 confoff = (gicirq / 16) * 4;
	bool enabled = false;
	u32 val;

	/* Interrupt configuration for SGIs can't be changed */
	if (gicirq < 16)
		return -EINVAL;

	if (type != IRQ_TYPE_LEVEL_HIGH && type != IRQ_TYPE_EDGE_RISING)
		return -EINVAL;

	raw_spin_lock(&irq_controller_lock);

	if (gicv3_arch_extn.irq_set_type)
		gicv3_arch_extn.irq_set_type(d, type);

	val = readl_relaxed(base + GIC_DIST_CONFIG + confoff);
	if (type == IRQ_TYPE_LEVEL_HIGH)
		val &= ~confmask;
	else if (type == IRQ_TYPE_EDGE_RISING)
		val |= confmask;

	/*
	 * As recommended by the spec, disable the interrupt before changing
	 * the configuration
	 */
	if (readl_relaxed(base + GIC_DIST_ENABLE_SET + enableoff) & enablemask) {
		writel_relaxed(enablemask, base + GIC_DIST_ENABLE_CLEAR + enableoff);
		enabled = true;
	}

	writel_relaxed(val, base + GIC_DIST_CONFIG + confoff);

	if (enabled)
		writel_relaxed(enablemask, base + GIC_DIST_ENABLE_SET + enableoff);

	raw_spin_unlock(&irq_controller_lock);

	return 0;
}

static int gicv3_retrigger(struct irq_data *d)
{
	if (gicv3_arch_extn.irq_retrigger)
		return gicv3_arch_extn.irq_retrigger(d);

	/* the genirq layer expects 0 if we can't retrigger in hardware */
	return 0;
}

#ifdef CONFIG_SMP
static int gicv3_set_affinity(struct irq_data *d, const struct cpumask *mask_val,
			    bool force)
{
	void __iomem *reg = gicv3_dist_base(d) + GIC_DIST_TARGET + (gicv3_irq(d) & ~3);
	unsigned int shift = (gicv3_irq(d) % 4) * 8;
	unsigned int cpu = cpumask_any_and(mask_val, cpu_online_mask);
	u32 val, mask, bit;

	if (cpu >= NR_GICV3_CPU_IF || cpu >= nr_cpu_ids)
		return -EINVAL;

	mask = 0xff << shift;
	bit = 1 << (cpu + shift);

	raw_spin_lock(&irq_controller_lock);
	val = readl_relaxed(reg) & ~mask;
	writel_relaxed(val | bit, reg);
	raw_spin_unlock(&irq_controller_lock);

	return IRQ_SET_MASK_OK;
}
#endif

#ifdef CONFIG_PM
static int gicv3_set_wake(struct irq_data *d, unsigned int on)
{
	int ret = -ENXIO;

	if (gicv3_arch_extn.irq_set_wake)
		ret = gicv3_arch_extn.irq_set_wake(d, on);

	return ret;
}

#else
#define gicv3_set_wake	NULL
#endif

static asmlinkage void __exception_irq_entry gicv3_handle_irq(struct pt_regs *regs)
{
	u32 irqstat, irqnr;
	struct gicv3_chip_data *gic = &gicv3_data[0];
	//void __iomem *cpu_base = gicv3_data_cpu_base(gic);

	do {
		irqstat = readl_icc_iar1();
		irqnr = irqstat & ~0x1c00;

		if (likely(irqnr > 15 && irqnr < 1021)) {
			irqnr = irq_find_mapping(gic->domain, irqnr);
			handle_IRQ(irqnr, regs);
                        /* MSI interrupts are edge triggered, to clear write to EOI register */
                        if ((irqnr >= 50) && (irqnr < 306)) {
				writel_icc_eoir1(irqstat);
                        }
			continue;
		}
		if (irqnr < 16) {
			writel_icc_eoir1(irqstat);
#ifdef CONFIG_SMP
			handle_IPI(irqnr, regs);
#endif
			continue;
		}
		break;
	} while (1);
}

static void gicv3_handle_cascade_irq(unsigned int irq, struct irq_desc *desc)
{
	struct gicv3_chip_data *chip_data = irq_get_handler_data(irq);
	struct irq_chip *chip = irq_get_chip(irq);
	unsigned int cascade_irq, gicv3_irq;
	unsigned long status;

	chained_irq_enter(chip, desc);

	raw_spin_lock(&irq_controller_lock);
	status = readl_icc_iar1();
	raw_spin_unlock(&irq_controller_lock);

	gicv3_irq = (status & 0x3ff);
	if (gicv3_irq == 1023)
		goto out;

	cascade_irq = irq_find_mapping(chip_data->domain, gicv3_irq);
	if (unlikely(gicv3_irq < 32 || gicv3_irq > 1020))
		handle_bad_irq(cascade_irq, desc);
	else
		generic_handle_irq(cascade_irq);

 out:
	chained_irq_exit(chip, desc);
}

static struct irq_chip gicv3_chip = {
	.name			= "GICv3",
	.irq_mask		= gicv3_mask_irq,
	.irq_unmask		= gicv3_unmask_irq,
	.irq_eoi		= gicv3_eoi_irq,
	.irq_set_type		= gicv3_set_type,
	.irq_retrigger		= gicv3_retrigger,
#ifdef CONFIG_SMP
	.irq_set_affinity	= gicv3_set_affinity,
#endif
	.irq_set_wake		= gicv3_set_wake,
};

void __init gicv3_cascade_irq(unsigned int gic_nr, unsigned int irq)
{
	if (gic_nr >= MAX_GICV3_NR)
		BUG();
	if (irq_set_handler_data(irq, &gicv3_data[gic_nr]) != 0)
		BUG();
	irq_set_chained_handler(irq, gicv3_handle_cascade_irq);
}

static u8 gicv3_get_cpumask(struct gicv3_chip_data *gic)
{
	void __iomem *base = gicv3_data_dist_base(gic);
	u32 mask, i;

	for (i = mask = 0; i < 32; i += 4) {
		mask = readl_relaxed(base + GIC_DIST_TARGET + i);
		mask |= mask >> 16;
		mask |= mask >> 8;
		if (mask)
			break;
	}

	if (!mask)
		pr_crit("GIC CPU mask not found - kernel will fail to boot.\n");

	return mask;
}

static void __init gicv3_dist_init(struct gicv3_chip_data *gic)
{
	unsigned int i;
	u32 cpumask = 1 << smp_processor_id();
	unsigned int gic_irqs = gic->gicv3_irqs;
	void __iomem *base = gicv3_data_dist_base(gic);

	writel_relaxed(0, base + GIC_DIST_CTRL);

	/*
	 * Set all global interrupts to be level triggered, active low.
	 */
	for (i = 32; i < gic_irqs; i += 16)
		writel_relaxed(0, base + GIC_DIST_CONFIG + i * 4 / 16);

	/*
	 * Set all global interrupts to this CPU only.
	 */
	/*cpumask = gicv3_get_cpumask(gic);*/
	cpumask |= cpumask << 8;
	cpumask |= cpumask << 16;
	for (i = 32; i < gic_irqs; i += 4)
		writel_relaxed(cpumask, base + GIC_DIST_TARGET + i * 4 / 4);

	/*
	 * Set priority on all global interrupts.
	 */
	for (i = 32; i < gic_irqs; i += 4)
		writel_relaxed(0xa0a0a0a0, base + GIC_DIST_PRI + i * 4 / 4);

	/*
	 * Disable all interrupts.  Leave the PPI and SGIs alone
	 * as these enables are banked registers.
	 */
	for (i = 32; i < gic_irqs; i += 32)
		writel_relaxed(0xffffffff, base + GIC_DIST_ENABLE_CLEAR + i * 4 / 32);

	writel_relaxed(1, base + GIC_DIST_CTRL);
}

static void __cpuinit gicv3_cpu_init(struct gicv3_chip_data *gic)
{
	void __iomem *dist_base = gicv3_data_dist_base(gic);
	void __iomem *base = gicv3_data_cpu_base(gic);
	int i;
#if 0
	unsigned int cpu_mask, cpu = smp_processor_id();

	/*
	 * Get what the GIC says our CPU mask is.
	 */
	BUG_ON(cpu >= NR_GICV3_CPU_IF);
	cpu_mask = gicv3_get_cpumask(gic);
	gicv3_cpu_map[cpu] = cpu_mask;

	/*
	 * Clear our mask from the other map entries in case they're
	 * still undefined.
	 */
	for (i = 0; i < NR_GICV3_CPU_IF; i++)
		if (i != cpu)
			gicv3_cpu_map[i] &= ~cpu_mask;
#endif

	/*
	 * Deal with the banked PPI and SGI interrupts - disable all
	 * PPI interrupts, ensure all SGI interrupts are enabled.
	 */
	writel_relaxed(0xffff0000, dist_base + GIC_DIST_ENABLE_CLEAR);
	writel_relaxed(0x0000ffff, dist_base + GIC_DIST_ENABLE_SET);

	/*
	 * Set priority on PPI and SGI interrupts
	 */
	for (i = 0; i < 32; i += 4)
		writel_relaxed(0xa0a0a0a0, dist_base + GIC_DIST_PRI + i * 4 / 4);

	writel_icc_pmr(0xf0);	
}

#ifdef CONFIG_CPU_PM
/*
 * Saves the GIC distributor registers during suspend or idle.  Must be called
 * with interrupts disabled but before powering down the GIC.  After calling
 * this function, no interrupts will be delivered by the GIC, and another
 * platform-specific wakeup source must be enabled.
 */
static void gicv3_dist_save(unsigned int gic_nr)
{
	unsigned int gic_irqs;
	void __iomem *dist_base;
	int i;

	if (gic_nr >= MAX_GICV3_NR)
		BUG();

	gic_irqs = gicv3_data[gic_nr].gicv3_irqs;
	dist_base = gicv3_data_dist_base(&gicv3_data[gic_nr]);

	if (!dist_base)
		return;

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 16); i++)
		gicv3_data[gic_nr].saved_spi_conf[i] =
			readl_relaxed(dist_base + GIC_DIST_CONFIG + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 4); i++)
		gicv3_data[gic_nr].saved_spi_target[i] =
			readl_relaxed(dist_base + GIC_DIST_TARGET + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 32); i++)
		gicv3_data[gic_nr].saved_spi_enable[i] =
			readl_relaxed(dist_base + GIC_DIST_ENABLE_SET + i * 4);
}

/*
 * Restores the GIC distributor registers during resume or when coming out of
 * idle.  Must be called before enabling interrupts.  If a level interrupt
 * that occured while the GIC was suspended is still present, it will be
 * handled normally, but any edge interrupts that occured will not be seen by
 * the GIC and need to be handled by the platform-specific wakeup source.
 */
static void gicv3_dist_restore(unsigned int gic_nr)
{
	unsigned int gic_irqs;
	unsigned int i;
	void __iomem *dist_base;

	if (gic_nr >= MAX_GICV3_NR)
		BUG();

	gic_irqs = gicv3_data[gic_nr].gicv3_irqs;
	dist_base = gicv3_data_dist_base(&gic_data[gic_nr]);

	if (!dist_base)
		return;

	writel_relaxed(0, dist_base + GIC_DIST_CTRL);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 16); i++)
		writel_relaxed(gicv3_data[gic_nr].saved_spi_conf[i],
			dist_base + GIC_DIST_CONFIG + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 4); i++)
		writel_relaxed(0xa0a0a0a0,
			dist_base + GIC_DIST_PRI + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 4); i++)
		writel_relaxed(gic_data[gic_nr].saved_spi_target[i],
			dist_base + GIC_DIST_TARGET + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 32); i++)
		writel_relaxed(gicv3_data[gic_nr].saved_spi_enable[i],
			dist_base + GIC_DIST_ENABLE_SET + i * 4);

	writel_relaxed(1, dist_base + GIC_DIST_CTRL);
}

static void gicv3_cpu_save(unsigned int gic_nr)
{
	int i;
	u32 *ptr;
	void __iomem *dist_base;
	void __iomem *cpu_base;

	if (gic_nr >= MAX_GICV3_NR)
		BUG();

	dist_base = gicv3_data_dist_base(&gicv3_data[gic_nr]);
	cpu_base = gicv3_data_cpu_base(&gicv3_data[gic_nr]);

	if (!dist_base || !cpu_base)
		return;

	ptr = __this_cpu_ptr(gicv3_data[gic_nr].saved_ppi_enable);
	for (i = 0; i < DIV_ROUND_UP(32, 32); i++)
		ptr[i] = readl_relaxed(dist_base + GIC_DIST_ENABLE_SET + i * 4);

	ptr = __this_cpu_ptr(gicv3_data[gic_nr].saved_ppi_conf);
	for (i = 0; i < DIV_ROUND_UP(32, 16); i++)
		ptr[i] = readl_relaxed(dist_base + GIC_DIST_CONFIG + i * 4);

}

static void gicv3_cpu_restore(unsigned int gic_nr)
{
	int i;
	u32 *ptr;
	void __iomem *dist_base;
	void __iomem *cpu_base;

	if (gic_nr >= MAX_GICV3_NR)
		BUG();

	dist_base = gicv3_data_dist_base(&gicv3_data[gic_nr]);
	cpu_base = gicv3_data_cpu_base(&gicv3_data[gic_nr]);

	if (!dist_base || !cpu_base)
		return;

	ptr = __this_cpu_ptr(gicv3_data[gic_nr].saved_ppi_enable);
	for (i = 0; i < DIV_ROUND_UP(32, 32); i++)
		writel_relaxed(ptr[i], dist_base + GIC_DIST_ENABLE_SET + i * 4);

	ptr = __this_cpu_ptr(gicv3_data[gic_nr].saved_ppi_conf);
	for (i = 0; i < DIV_ROUND_UP(32, 16); i++)
		writel_relaxed(ptr[i], dist_base + GIC_DIST_CONFIG + i * 4);

	for (i = 0; i < DIV_ROUND_UP(32, 4); i++)
		writel_relaxed(0xa0a0a0a0, dist_base + GIC_DIST_PRI + i * 4);

	writel_relaxed(0xf0, cpu_base + GIC_CPU_PRIMASK);
	writel_relaxed(1, cpu_base + GIC_CPU_CTRL);
}

static int gicv3_notifier(struct notifier_block *self, unsigned long cmd,	void *v)
{
	int i;

	for (i = 0; i < MAX_GICV3_NR; i++) {
#ifdef CONFIG_GIC_NON_BANKED
		/* Skip over unused GICs */
		if (!gicv3_data[i].get_base)
			continue;
#endif
		switch (cmd) {
		case CPU_PM_ENTER:
			gicv3_cpu_save(i);
			break;
		case CPU_PM_ENTER_FAILED:
		case CPU_PM_EXIT:
			gicv3_cpu_restore(i);
			break;
		case CPU_CLUSTER_PM_ENTER:
			gicv3_dist_save(i);
			break;
		case CPU_CLUSTER_PM_ENTER_FAILED:
		case CPU_CLUSTER_PM_EXIT:
			gicv3_dist_restore(i);
			break;
		}
	}

	return NOTIFY_OK;
}

static struct notifier_block gicv3_notifier_block = {
	.notifier_call = gicv3_notifier,
};

static void __init gicv3_pm_init(struct gicv3_chip_data *gic)
{
	gic->saved_ppi_enable = __alloc_percpu(DIV_ROUND_UP(32, 32) * 4,
		sizeof(u32));
	BUG_ON(!gic->saved_ppi_enable);

	gic->saved_ppi_conf = __alloc_percpu(DIV_ROUND_UP(32, 16) * 4,
		sizeof(u32));
	BUG_ON(!gic->saved_ppi_conf);

	if (gic == &gicv3_data[0])
		cpu_pm_register_notifier(&gicv3_notifier_block);
}
#else
static void __init gicv3_pm_init(struct gicv3_chip_data *gic)
{
}
#endif

#ifdef CONFIG_SMP
void gicv3_raise_softirq(const struct cpumask *mask, unsigned int irq)
{
#if 0
	int cpu;
	unsigned long map = 0;

	/* Convert our logical CPU mask into a physical one. */
	for_each_cpu(cpu, mask)
		map |= gicv3_cpu_map[cpu];

	/*
	 * Ensure that stores to Normal memory are visible to the
	 * other CPUs before issuing the IPI.
	 */
	dsb();

	/* this always happens on GIC0 */
	writel_relaxed(map << 16 | irq, gicv3_data_dist_base(&gicv3_data[0]) + GIC_DIST_SOFTINT);
#endif
	unsigned long map = *cpus_addr(*mask);
	unsigned int i;

	BUG_ON(irq > 15);
	
	/*
	 * Ensure that stores to Normal memory are visible to the
	 * other CPUs before issuing the IPI.
	 */
	dsb();

	for(i=0; i<NR_CPUS; i+=16) {
		if((map >> i) & 0xffff)
			writel_icc_sgi1r(((i/16) << 16) | irq << 24 | ((map >> i) & 0xffff));
	}
}
#endif

static int gicv3_irq_domain_map(struct irq_domain *d, unsigned int irq,
				irq_hw_number_t hw)
{
	if (hw < 32) {
		irq_set_percpu_devid(irq);
		irq_set_chip_and_handler(irq, &gicv3_chip,
					 handle_percpu_devid_irq);
		set_irq_flags(irq, IRQF_VALID | IRQF_NOAUTOEN);
	} else {
		irq_set_chip_and_handler(irq, &gicv3_chip,
					 handle_fasteoi_irq);
		set_irq_flags(irq, IRQF_VALID | IRQF_PROBE);
	}
	irq_set_chip_data(irq, d->host_data);
	return 0;
}

static int gicv3_irq_domain_xlate(struct irq_domain *d,
				struct device_node *controller,
				const u32 *intspec, unsigned int intsize,
				unsigned long *out_hwirq, unsigned int *out_type)
{
	if (d->of_node != controller)
		return -EINVAL;
	if (intsize < 3)
		return -EINVAL;

	/* Get the interrupt number and add 16 to skip over SGIs */
	*out_hwirq = intspec[1] + 16;

	/* For SPIs, we need to add 16 more to get the GIC irq ID number */
	if (!intspec[0])
		*out_hwirq += 16;

	*out_type = intspec[2] & IRQ_TYPE_SENSE_MASK;
	return 0;
}

#ifdef CONFIG_SMP
static int __cpuinit gicv3_secondary_init(struct notifier_block *nfb,
					unsigned long action, void *hcpu)
{
	if (action == CPU_STARTING)
		gicv3_cpu_init(&gicv3_data[0]);
	return NOTIFY_OK;
}

/*
 * Notifier for enabling the GIC CPU interface. Set an arbitrarily high
 * priority because the GIC needs to be up before the ARM generic timers.
 */
static struct notifier_block __cpuinitdata gicv3_cpu_notifier = {
	.notifier_call = gicv3_secondary_init,
	.priority = 100,
};
#endif

const struct irq_domain_ops gicv3_irq_domain_ops = {
	.map = gicv3_irq_domain_map,
	.xlate = gicv3_irq_domain_xlate,
};

void __init gicv3_init_bases(unsigned int gic_nr, int irq_start,
			   void __iomem *dist_base, void __iomem *cpu_base,
			   u32 percpu_offset, struct device_node *node)
{
	irq_hw_number_t hwirq_base;
	struct gicv3_chip_data *gic;
	int gic_irqs, irq_base, i;

	BUG_ON(gic_nr >= MAX_GICV3_NR);

	gic = &gicv3_data[gic_nr];
#ifdef CONFIG_GIC_NON_BANKED
	if (percpu_offset) { /* Frankein-GIC without banked registers... */
		unsigned int cpu;

		gic->dist_base.percpu_base = alloc_percpu(void __iomem *);
		gic->cpu_base.percpu_base = alloc_percpu(void __iomem *);
		if (WARN_ON(!gic->dist_base.percpu_base ||
			    !gic->cpu_base.percpu_base)) {
			free_percpu(gic->dist_base.percpu_base);
			free_percpu(gic->cpu_base.percpu_base);
			return;
		}

		for_each_possible_cpu(cpu) {
			unsigned long offset = percpu_offset * cpu_logical_map(cpu);
			*per_cpu_ptr(gic->dist_base.percpu_base, cpu) = dist_base + offset;
			*per_cpu_ptr(gic->cpu_base.percpu_base, cpu) = cpu_base + offset;
		}

		gicv3_set_base_accessor(gic, gicv3_get_percpu_base);
	} else
#endif
	{			/* Normal, sane GIC... */
		WARN(percpu_offset,
		     "GIC_NON_BANKED not enabled, ignoring %08x offset!",
		     percpu_offset);
		gic->dist_base.common_base = dist_base;
		gic->cpu_base.common_base = cpu_base;
		gicv3_set_base_accessor(gic, gicv3_get_common_base);
	}

#if 0
	/*
	 * Initialize the CPU interface map to all CPUs.
	 * It will be refined as each CPU probes its ID.
	 */
	for (i = 0; i < NR_GICV3_CPU_IF; i++)
		gicv3_cpu_map[i] = 0xff;
#endif

	/*
	 * For primary GICs, skip over SGIs.
	 * For secondary GICs, skip over PPIs, too.
	 */
	if (gic_nr == 0 && (irq_start & 31) > 0) {
		hwirq_base = 16;
		if (irq_start != -1)
			irq_start = (irq_start & ~31) + 16;
	} else {
		hwirq_base = 32;
	}

	/*
	 * Find out how many interrupts are supported.
	 * The GIC only supports up to 1020 interrupt sources.
	 */
	gic_irqs = readl_relaxed(gicv3_data_dist_base(gic) + GIC_DIST_CTR) & 0x1f;
	gic_irqs = (gic_irqs + 1) * 32;
	if (gic_irqs > 1020)
		gic_irqs = 1020;
	gic->gicv3_irqs = gic_irqs;

	gic_irqs -= hwirq_base; /* calculate # of irqs to allocate */
	irq_base = irq_alloc_descs(irq_start, 16, gic_irqs, numa_node_id());
	if (IS_ERR_VALUE(irq_base)) {
		WARN(1, "Cannot allocate irq_descs @ IRQ%d, assuming pre-allocated\n",
		     irq_start);
		irq_base = irq_start;
	}
	gic->domain = irq_domain_add_legacy(node, gic_irqs, irq_base,
				    hwirq_base, &gicv3_irq_domain_ops, gic);
	if (WARN_ON(!gic->domain))
		return;

#ifdef CONFIG_SMP
	set_smp_cross_call(gicv3_raise_softirq);
	register_cpu_notifier(&gicv3_cpu_notifier);
#endif

	set_handle_irq(gicv3_handle_irq);

	gicv3_chip.flags |= gicv3_arch_extn.flags;
	gicv3_dist_init(gic);
	gicv3_cpu_init(gic);
	gicv3_pm_init(gic);
}

#ifdef CONFIG_OF
static int gicv3_cnt __initdata;

int __init gicv3_of_init(struct device_node *node, struct device_node *parent)
{
	void __iomem *cpu_base;
	void __iomem *dist_base;
	u32 percpu_offset;
	int irq;

	if (WARN_ON(!node))
		return -ENODEV;

	dist_base = of_iomap(node, 0);
	WARN(!dist_base, "unable to map gic dist registers\n");

	cpu_base = of_iomap(node, 1);
	WARN(!cpu_base, "unable to map gic cpu registers\n");

	if (of_property_read_u32(node, "cpu-offset", &percpu_offset))
		percpu_offset = 0;

	gicv3_init_bases(gicv3_cnt, -1, dist_base, cpu_base, percpu_offset, node);

	if (parent) {
		irq = irq_of_parse_and_map(node, 0);
		gicv3_cascade_irq(gicv3_cnt, irq);
	}
	gicv3_cnt++;
	return 0;
}
IRQCHIP_DECLARE(thunder_gicv3, "cavium,thunder-gicv3", gicv3_of_init);
#endif

/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2013 Cavium, Inc.
 */
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/msi.h>
#include <linux/irq.h>
#include <linux/pci.h>

#include "pcie-thunder.h"

/*
 * SLI regs
 */
#define SLI_MSI_WR_MAP   (0x0000000000003C90ull)
#define SLI_MSI_RCV      (0x0000000000003CB0ull)

#define THUNDER_IRQ_MSI_START	(50)

/*
 * Each bit in msi_free_irq_bitmask represents a MSI interrupt that is
 * in use.
 */
static u64 msi_free_irq_bitmask[4];

/*
 * Each bit in msi_multiple_irq_bitmask tells that the device using
 * this bit in msi_free_irq_bitmask is also using the next bit. This
 * is used so we can disable all of the MSI interrupts when a device
 * uses multiple.
 */
static u64 msi_multiple_irq_bitmask[4];

/*
 * This lock controls updates to msi_free_irq_bitmask and
 * msi_multiple_irq_bitmask.
 */
static DEFINE_SPINLOCK(msi_free_irq_bitmask_lock);

/*
 * Number of MSI IRQs used. This variable is set up in
 * the module init time.
 */
static int msi_irq_size = 256;

/**
 * Called when a driver request MSI interrupts instead of the
 * legacy INT A-D. This routine will allocate multiple interrupts
 * for MSI devices that support them. A device can override this by
 * programming the MSI control bits [6:4] before calling
 * pci_enable_msi().
 *
 * @dev:    Device requesting MSI interrupts
 * @desc:   MSI descriptor
 *
 * Returns 0 on success.
 */
int arch_setup_msi_irq(struct pci_dev *dev, struct msi_desc *desc)
{
	struct msi_msg msg;
	u16 control;
	int configured_private_bits;
	int request_private_bits;
	int irq = 0;
	int irq_step;
	u64 search_mask;
	int index;

	/*
	 * Read the MSI config to figure out how many IRQs this device
	 * wants.  Most devices only want 1, which will give
	 * configured_private_bits and request_private_bits equal 0.
	 */
	pci_read_config_word(dev, desc->msi_attrib.pos + PCI_MSI_FLAGS,
			     &control);

	/*
	 * If the number of private bits has been configured then use
	 * that value instead of the requested number. This gives the
	 * driver the chance to override the number of interrupts
	 * before calling pci_enable_msi().
	 */
	configured_private_bits = (control & PCI_MSI_FLAGS_QSIZE) >> 4;
	if (configured_private_bits == 0) {
		/* Nothing is configured, so use the hardware requested size */
		request_private_bits = (control & PCI_MSI_FLAGS_QMASK) >> 1;
	} else {
		/*
		 * Use the number of configured bits, assuming the
		 * driver wanted to override the hardware request
		 * value.
		 */
		request_private_bits = configured_private_bits;
	}

	/*
	 * The PCI 2.3 spec mandates that there are at most 32
	 * interrupts. If this device asks for more, only give it one.
	 */
	if (request_private_bits > 5)
		request_private_bits = 0;

try_only_one:
	/*
	 * The IRQs have to be aligned on a power of two based on the
	 * number being requested.
	 */
	irq_step = 1 << request_private_bits;

	/* Mask with one bit for each IRQ */
	search_mask = (1 << irq_step) - 1;

	/*
	 * We're going to search msi_free_irq_bitmask_lock for zero
	 * bits. This represents an MSI interrupt number that isn't in
	 * use.
	 */
	spin_lock(&msi_free_irq_bitmask_lock);
	for (index = 0; index < msi_irq_size/64; index++) {
		for (irq = 0; irq < 64; irq += irq_step) {
			if ((msi_free_irq_bitmask[index] & (search_mask << irq)) == 0) {
				msi_free_irq_bitmask[index] |= search_mask << irq;
				msi_multiple_irq_bitmask[index] |= (search_mask >> 1) << irq;
				goto msi_irq_allocated;
			}
		}
	}
msi_irq_allocated:
	spin_unlock(&msi_free_irq_bitmask_lock);

	/* Make sure the search for available interrupts didn't fail */
	if (irq >= 64) {
		if (request_private_bits) {
			pr_err("arch_setup_msi_irq: Unable to find %d free interrupts, trying just one",
			       1 << request_private_bits);
			request_private_bits = 0;
			goto try_only_one;
		} else
			panic("arch_setup_msi_irq: Unable to find a free MSI interrupt");
	}

	/* MSI interrupts start at logical IRQ THUNDER_IRQ_MSI_START */
	irq += index*64;
	msg.data = irq;
	irq += THUNDER_IRQ_MSI_START;

	/* When using PCIe2, Bar 0 is based at 0 */
	msg.address_lo = (0 + SLI_MSI_RCV) & 0xffffffff;
	msg.address_hi = (0 + SLI_MSI_RCV) >> 32;

	/* Update the number of IRQs the device has available to it */
	control &= ~PCI_MSI_FLAGS_QSIZE;
	control |= request_private_bits << 4;
	pci_write_config_word(dev, desc->msi_attrib.pos + PCI_MSI_FLAGS,
			      control);

	irq_set_msi_desc(irq, desc);
	write_msi_msg(irq, &msg);
	return 0;
}

int arch_setup_msi_irqs(struct pci_dev *dev, int nvec, int type)
{
	struct msi_desc *entry;
	int ret;

	/*
	 * MSI-X is not supported.
	 */
	if (type == PCI_CAP_ID_MSIX)
		return -EINVAL;

	/*
	 * If an architecture wants to support multiple MSI, it needs to
	 * override arch_setup_msi_irqs()
	 */
	if (type == PCI_CAP_ID_MSI && nvec > 1)
		return 1;

	list_for_each_entry(entry, &dev->msi_list, list) {
		ret = arch_setup_msi_irq(dev, entry);
		if (ret < 0)
			return ret;
		if (ret > 0)
			return -ENOSPC;
	}

	return 0;
}

/**
 * Called when a device no longer needs its MSI interrupts. All
 * MSI interrupts for the device are freed.
 *
 * @irq:    The devices first irq number. There may be multple in sequence.
 */
void arch_teardown_msi_irq(unsigned int irq)
{
	int number_irqs;
	u64 bitmask;
	int index = 0;
	int irq0;

	if ((irq < THUNDER_IRQ_MSI_START)
		|| (irq > msi_irq_size + THUNDER_IRQ_MSI_START - 1))
		panic("arch_teardown_msi_irq: Attempted to teardown illegal MSI interrupt (%d)",
		      irq);

	irq -= THUNDER_IRQ_MSI_START;
	index = irq / 64;
	irq0 = irq % 64;
	/*
	 * Count the number of IRQs we need to free by looking at the
	 * msi_multiple_irq_bitmask. Each bit set means that the next
	 * IRQ is also owned by this device.
	 */
	number_irqs = 0;
	while ((irq0 + number_irqs < 64) &&
	       (msi_multiple_irq_bitmask[index]
		& (1ull << (irq0 + number_irqs))))
		number_irqs++;
	number_irqs++;
	/* Mask with one bit for each IRQ */
	bitmask = (1 << number_irqs) - 1;
	/* Shift the mask to the correct bit location */
	bitmask <<= irq0;
	if ((msi_free_irq_bitmask[index] & bitmask) != bitmask)
		panic("arch_teardown_msi_irq: Attempted to teardown MSI interrupt (%d) not in use",
		      irq);

	/* Checks are done, update the in use bitmask */
	spin_lock(&msi_free_irq_bitmask_lock);
	msi_free_irq_bitmask[index] &= ~bitmask;
	msi_multiple_irq_bitmask[index] &= ~bitmask;
	spin_unlock(&msi_free_irq_bitmask_lock);
}

/*
 * Programs MSI Interrupt to SLI_RCV register bit mapping
 */
int __init thunder_msi_initialize(void)
{
        uint32_t  msi;
        uint32_t  ciu;
        uint64_t  e;
	uint64_t  sli_reg_addr;

        sli_reg_addr = (uint64_t)ioremap_nocache(THUNDER_PCIE_SLI_REG, THUNDER_PCIE_SLI_REG_SZ);
	if (!sli_reg_addr) {
		pr_err("Failed to map Octeon's SLI registers\n");
		goto ioremap_fail;
	}

        for (msi = 0; msi < 256; msi++) {
                ciu = (msi >> 2) | ((msi << 6) & 0xc0);
                e = (ciu << 8) | msi;
                writeq_relaxed(e, (void *)(sli_reg_addr + SLI_MSI_WR_MAP));
        }

	iounmap((void *)sli_reg_addr);
ioremap_fail:
	return 0;
}
subsys_initcall(thunder_msi_initialize);

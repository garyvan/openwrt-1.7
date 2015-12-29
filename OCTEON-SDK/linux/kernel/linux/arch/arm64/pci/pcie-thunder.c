/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2013 Cavium, Inc.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/swab.h>
#include <linux/of_platform.h>
#include <linux/of_gpio.h>
#include <linux/of_irq.h>
#include <linux/of_pci.h>
#include <linux/of_address.h>

#include <asm/cacheflush.h>
#include "pcie-thunder.h"

static int thunder_pcie0_read_config(struct pci_bus *bus, unsigned int devfn,
				    int reg, int size, u32 *val);
static int thunder_pcie1_read_config(struct pci_bus *bus, unsigned int devfn,
				    int reg, int size, u32 *val);
static int thunder_pcie0_write_config(struct pci_bus *bus, unsigned int devfn,
				     int reg, int size, u32 val);
static int thunder_pcie1_write_config(struct pci_bus *bus, unsigned int devfn,
				     int reg, int size, u32 val);

static struct resource thunder_pcie0_mem_resource;
static struct resource thunder_pcie0_io_resource;
static struct resource thunder_pcie1_mem_resource;
static struct resource thunder_pcie1_io_resource;

static struct pci_ops thunder_pcie0_ops = {
	thunder_pcie0_read_config,
	thunder_pcie0_write_config,
};

static struct pci_controller thunder_pcie0_controller = {
	.pci_ops = &thunder_pcie0_ops,
	.mem_resource = &thunder_pcie0_mem_resource,
	.io_resource = &thunder_pcie0_io_resource,
};

static struct pci_ops thunder_pcie1_ops = {
	thunder_pcie1_read_config,
	thunder_pcie1_write_config,
};

static struct pci_controller thunder_pcie1_controller = {
	.pci_ops = &thunder_pcie1_ops,
	.mem_resource = &thunder_pcie1_mem_resource,
	.io_resource = &thunder_pcie1_io_resource,
};

static int thunder_dummy_read_config(struct pci_bus *bus, unsigned int devfn,
                                    int reg, int size, u32 *val)
{
        return PCIBIOS_FUNC_NOT_SUPPORTED;
}

static int thunder_dummy_write_config(struct pci_bus *bus, unsigned int devfn,
                                     int reg, int size, u32 val)
{
        return PCIBIOS_FUNC_NOT_SUPPORTED;
}

static struct pci_ops thunder_dummy_ops = {
        thunder_dummy_read_config,
        thunder_dummy_write_config,
};

static struct resource thunder_dummy_mem_resource = {
        .name = "Virtual PCIe MEM",
        .flags = IORESOURCE_MEM,
};

static struct resource thunder_dummy_io_resource = {
        .name = "Virtual PCIe IO",
        .flags = IORESOURCE_IO,
};

static struct pci_controller thunder_dummy_controller = {
        .pci_ops = &thunder_dummy_ops,
        .mem_resource = &thunder_dummy_mem_resource,
        .io_resource = &thunder_dummy_io_resource,
};

static inline void cvmx_write_csr(uint64_t val, uint64_t csr_addr)
{
	writeq_relaxed(swab64(val), (void *)csr_addr);

	/*
	 * Perform an immediate read after every write to an RSL
	 * register to force the write to complete. It doesn't matter
	 * what RSL read we do, so we choose CVMX_MIO_BOOT_BIST_STAT
	 * because it is fast and harmless.
	 */
	readq_relaxed((void *)pemx_cfg_reg);
}

static inline uint64_t cvmx_read_csr(uint64_t csr_addr)
{
	return swab64(readq_relaxed((void *)csr_addr));
}

/*
 * Read a PCIe core configuration register
 */
static uint32_t cvmx_pcie_cfgx_read(int pcie_port, uint32_t cfg_offset)
{
	cvmx_pemx_cfg_rd_t pemx_cfg_rd;

	pemx_cfg_rd.u64 = 0;
	pemx_cfg_rd.s.addr = cfg_offset;
	cvmx_write_csr(pemx_cfg_rd.u64, CVMX_PEMX_CFG_RD(pcie_port));
	pemx_cfg_rd.u64 = cvmx_read_csr(CVMX_PEMX_CFG_RD(pcie_port));
	return pemx_cfg_rd.s.data;
}

#if 0
/*
 * Write into a PCIe core configuration register.
 */
static void cvmx_pcie_cfgx_write(int pcie_port, uint32_t cfg_offset,
				 uint32_t val)
{
	cvmx_pemx_cfg_wr_t pemx_cfg_wr;

	pemx_cfg_wr.u64 = 0;
	pemx_cfg_wr.s.addr = cfg_offset;
	pemx_cfg_wr.s.data = val;
	cvmx_write_csr(pemx_cfg_wr.u64, CVMX_PEMX_CFG_WR(pcie_port));
}
#endif

bool  cvmx_pemx_is_link_active(int pcie_port) 
{
	cvmx_pciercx_cfg032_t pciercx_cfg032;

	/* Check the link status */	
	pciercx_cfg032.u32 = cvmx_pcie_cfgx_read(pcie_port, CVMX_PCIERCX_CFG032);
	if ((pciercx_cfg032.s.dlla == 0) || (pciercx_cfg032.s.lt == 1))
		return 0;

	/* Display the link status */
	pciercx_cfg032.u32 = cvmx_pcie_cfgx_read(pcie_port, CVMX_PCIERCX_CFG032);
	pr_notice("PCIe: Port %d link active, %d lanes, speed gen%d\n", pcie_port, pciercx_cfg032.s.nlw, pciercx_cfg032.s.ls);

	return 1;
}

/**
 * Build a PCIe config space request address for a device
 *
 * @pcie_port: PCIe port to access
 * @bus:       Sub bus
 * @dev:       Device ID
 * @fn:        Device sub function
 * @reg:       Register to access
 *
 * Returns 64bit Octeon IO address
 */
static inline uint64_t __cvmx_pcie_build_config_addr(int pcie_port, int bus,
						     int dev, int fn, int reg)
{
	union cvmx_pcie_address pcie_addr;
	uint32_t pbnum = 1;

        if ((bus <= pbnum) && (dev != 0))
	        return 0;
	
	pcie_addr.u64 = 0;
	pcie_addr.config.bus = bus;
	pcie_addr.config.ty = bus > pbnum;
	pcie_addr.config.dev = dev;
	pcie_addr.config.func = fn;
	pcie_addr.config.reg = reg;
        
        if (pcie_port == 0) {
		pcie_addr.u64 += thunder_pcie0_controller.cfg_base;
        } else if (pcie_port == 1) { 
		pcie_addr.u64 += thunder_pcie1_controller.cfg_base;
        }

	return pcie_addr.u64;
}

/**
 * Read 8bits from a Device's config space
 *
 * @pcie_port: PCIe port the device is on
 * @bus:       Sub bus
 * @dev:       Device ID
 * @fn:        Device sub function
 * @reg:       Register to access
 *
 * Returns Result of the read
 */
static uint8_t cvmx_pcie_config_read8(int pcie_port, int bus, int dev,
				      int fn, int reg)
{
	uint64_t address =
	    __cvmx_pcie_build_config_addr(pcie_port, bus, dev, fn, reg);

	if (address)
		return *((uint8_t *)address);
	else
		return 0xff;
}

/**
 * Read 16bits from a Device's config space
 *
 * @pcie_port: PCIe port the device is on
 * @bus:       Sub bus
 * @dev:       Device ID
 * @fn:        Device sub function
 * @reg:       Register to access
 *
 * Returns Result of the read
 */
static uint16_t cvmx_pcie_config_read16(int pcie_port, int bus, int dev,
					int fn, int reg)
{
	uint64_t address =
	    __cvmx_pcie_build_config_addr(pcie_port, bus, dev, fn, reg);
	
	if (address)
		return be16_to_cpu(*(uint16_t *)address);
	else
		return 0xffff;
}

/**
 * Read 32bits from a Device's config space
 *
 * @pcie_port: PCIe port the device is on
 * @bus:       Sub bus
 * @dev:       Device ID
 * @fn:        Device sub function
 * @reg:       Register to access
 *
 * Returns Result of the read
 */
static uint32_t cvmx_pcie_config_read32(int pcie_port, int bus, int dev,
					int fn, int reg)
{
	uint64_t address =
	    __cvmx_pcie_build_config_addr(pcie_port, bus, dev, fn, reg);
   
	if (address)
		return be32_to_cpu(*((uint32_t *)address));
	else
		return 0xffffffff;
}

/**
 * Write 8bits to a Device's config space
 *
 * @pcie_port: PCIe port the device is on
 * @bus:       Sub bus
 * @dev:       Device ID
 * @fn:        Device sub function
 * @reg:       Register to access
 * @val:       Value to write
 */
static void cvmx_pcie_config_write8(int pcie_port, int bus, int dev, int fn,
				    int reg, uint8_t val)
{
	uint64_t address =
	    __cvmx_pcie_build_config_addr(pcie_port, bus, dev, fn, reg);
	if (address)
		*((uint8_t *)address) = val;              
}

/**
 * Write 16bits to a Device's config space
 *
 * @pcie_port: PCIe port the device is on
 * @bus:       Sub bus
 * @dev:       Device ID
 * @fn:        Device sub function
 * @reg:       Register to access
 * @val:       Value to write
 */
static void cvmx_pcie_config_write16(int pcie_port, int bus, int dev, int fn,
				     int reg, uint16_t val)
{
	uint64_t address =
	    __cvmx_pcie_build_config_addr(pcie_port, bus, dev, fn, reg);
	if (address)
		*((uint16_t *)address) = cpu_to_be16(val);              
}

/**
 * Write 32bits to a Device's config space
 *
 * @pcie_port: PCIe port the device is on
 * @bus:       Sub bus
 * @dev:       Device ID
 * @fn:        Device sub function
 * @reg:       Register to access
 * @val:       Value to write
 */
static void cvmx_pcie_config_write32(int pcie_port, int bus, int dev, int fn,
				     int reg, uint32_t val)
{
	uint64_t address =
	    __cvmx_pcie_build_config_addr(pcie_port, bus, dev, fn, reg);
	if (address)
		*((uint32_t *)address) = cpu_to_be32(val);              
}

/*
 * Read a value from configuration space
 *
 */
static int thunder_pcie_read_config(unsigned int pcie_port, struct pci_bus *bus,
				   unsigned int devfn, int reg, int size,
				   u32 *val)
{
	int bus_number = bus->number;

	/*
	 * PCIe only has a single device connected to Octeon. It is
	 * always device ID 0. Don't bother doing reads for other
	 * device IDs on the first segment.
	 */
	if ((bus->parent == NULL) && (devfn >> 3 != 0))
		return PCIBIOS_FUNC_NOT_SUPPORTED;

	pr_debug("pcie_cfg_rd port=%d b=%d devfn=0x%03x reg=0x%03x"
		 " size=%d ", pcie_port, bus_number, devfn, reg, size);
	switch (size) {
	case 4:
		*val = cvmx_pcie_config_read32(pcie_port, bus_number,
			devfn >> 3, devfn & 0x7, reg);
	break;
	case 2:
		*val = cvmx_pcie_config_read16(pcie_port, bus_number,
			devfn >> 3, devfn & 0x7, reg);
	break;
	case 1:
		*val = cvmx_pcie_config_read8(pcie_port, bus_number,
			devfn >> 3, devfn & 0x7, reg);
	break;
	default:
		return PCIBIOS_FUNC_NOT_SUPPORTED;
	}

	pr_debug("val=%08x\n", *val);
	return PCIBIOS_SUCCESSFUL;
}

static int thunder_pcie0_read_config(struct pci_bus *bus, unsigned int devfn,
				    int reg, int size, u32 *val)
{
	return thunder_pcie_read_config(0, bus, devfn, reg, size, val);
}

static int thunder_pcie1_read_config(struct pci_bus *bus, unsigned int devfn,
				    int reg, int size, u32 *val)
{
	return thunder_pcie_read_config(1, bus, devfn, reg, size, val);
}

/*
 * Write a value to PCI configuration space
 */
static int thunder_pcie_write_config(unsigned int pcie_port, struct pci_bus *bus,
				    unsigned int devfn, int reg,
				    int size, u32 val)
{
	int bus_number = bus->number;

	if (bus->parent == NULL)
		bus_number = 0;

	pr_debug("pcie_cfg_wr port=%d b=%d devfn=0x%03x"
		 " reg=0x%03x size=%d val=%08x\n", pcie_port, bus_number, devfn,
		 reg, size, val);

	switch (size) {
	case 4:
		cvmx_pcie_config_write32(pcie_port, bus_number, 
                                         devfn >> 3, devfn & 0x7, reg, val);
		break;
	case 2:
		cvmx_pcie_config_write16(pcie_port, bus_number, 
                                         devfn >> 3, devfn & 0x7, reg, val);
		break;
	case 1:
		cvmx_pcie_config_write8(pcie_port, bus_number, 
                                        devfn >> 3, devfn & 0x7, reg, val);
		break;
	default:
		return PCIBIOS_FUNC_NOT_SUPPORTED;
	}
#if PCI_CONFIG_SPACE_DELAY
	/*
	 * Delay on writes so that devices have time to come up. Some
	 * bridges need this to allow time for the secondary busses to
	 * work
	 */
	udelay(PCI_CONFIG_SPACE_DELAY);
#endif
	return PCIBIOS_SUCCESSFUL;
}

static int thunder_pcie0_write_config(struct pci_bus *bus, unsigned int devfn,
				     int reg, int size, u32 val)
{
	return thunder_pcie_write_config(0, bus, devfn, reg, size, val);
}

static int thunder_pcie1_write_config(struct pci_bus *bus, unsigned int devfn,
				     int reg, int size, u32 val)
{
	return thunder_pcie_write_config(1, bus, devfn, reg, size, val);
}

static int pci_load_of_ranges(struct pci_controller *hose, 
			      struct device_node *node, uint32_t pcie_port)
{
	const __be32 *ranges;
	int start;
	int rlen;
	int nac = of_n_addr_cells(node);
	int nsc = of_n_size_cells(node);
	int np;

	np = nac + nsc + 1;

	pr_info("PCI host bridge %s ranges:\n", node->full_name);
	ranges = of_get_property(node, "ranges", &rlen);
	if (ranges == NULL)
		return 0;
	hose->of_node = node;
	start = pcie_port * ((nac + nsc) * 2);

	ranges = ranges + start;
	rlen = np * 2; /* IO + Mem resource */
	while (rlen > 0) {
		u32 pci_space;
		struct resource *res = NULL;
		u64 addr, size;

		pci_space = be32_to_cpup(&ranges[0]);
		addr = of_translate_address(node, ranges + 1);
		size = of_read_number(ranges + nac + 1, nsc);
		ranges += np;
		switch (pci_space) {
		case 0:		/* PCIe IO space */
			pr_info("  IO 0x%016llx..0x%016llx\n",
					addr, addr + size - 1);
			res = hose->io_resource;
			res->flags = IORESOURCE_IO;
			ioport_resource.start += addr;
			ioport_resource.end = ioport_resource.start + size; 
			break;
		case 1:		/* PCIe 64 bits Memory space */
			pr_info(" MEM 0x%016llx..0x%016llx\n",
					addr, addr + size - 1);
			res = hose->mem_resource;
			res->flags = IORESOURCE_MEM;
			break;
		}
		if (res != NULL) {
			res->start = addr;
			res->name = node->full_name;
			res->end = res->start + size - 1;
			res->parent = NULL;
			res->sibling = NULL;
			res->child = NULL;
		}
		rlen -= np;
	}
	return 1;
}

/**
 * Initialize the Octeon PCIe controllers
 *
 * Returns
 */
static int thunder_pcie_setup(struct platform_device *pdev)
{
	struct resource res;

	/* Map Octeon's PCIe core registers */
	pemx_cfg_reg = (uint64_t) ioremap_nocache(THUNDER_PCIE_PEMX_CFG_REG, 
				                  THUNDER_PCIE_PEMX_CFG_REG_SIZE);
	/*
	 * Create a dummy PCIe controller to swallow up bus 0. IDT bridges
	 * don't work if the primary bus number is zero. Here we add a fake
	 * PCIe controller that the kernel will give bus 0. This allows
	 * us to not change the normal kernel bus enumeration
	 */
        thunder_dummy_controller.io_map_base = -1;
        thunder_dummy_controller.mem_resource->start = (1ull<<32);
        thunder_dummy_controller.mem_resource->end = (1ull<<32);
        thunder_dummy_controller.io_resource->start = 0x100;
        thunder_dummy_controller.io_resource->end = 0x200;
        register_pci_controller(&thunder_dummy_controller);

	if (of_address_to_resource(pdev->dev.of_node, 0, &res)) {
		return -EINVAL;
	}

	pr_notice("PCIe: Register port 0 \n");
	if (!request_mem_region(res.start, resource_size(&res), "thunder-pcie")) {
		pr_notice("PCIe: couldn't request %pR\n", &res);
		return -EBUSY;
	}

        /* Map PCIe config space */
	thunder_pcie0_controller.cfg_base = 
		(uint64_t)ioremap_nocache(res.start, resource_size(&res));
        if (!thunder_pcie0_controller.cfg_base) {
		pr_err("PCIe: Failed to map port 0 config space\n");
            return ENOMEM;
        }

	if (cvmx_pemx_is_link_active(0) && 
	    pci_load_of_ranges(&thunder_pcie0_controller, pdev->dev.of_node, 0)) {

		register_pci_controller(&thunder_pcie0_controller);
	} else {
		iounmap((void *)thunder_pcie1_controller.cfg_base);
		pr_err("PCIe: Link not active on port 0, probably the slot is empty\n");
	}

	if (of_address_to_resource(pdev->dev.of_node, 1, &res)) {
		return -EINVAL;
	}

	pr_notice("PCIe: Register port 1\n");
	if (!request_mem_region(res.start, resource_size(&res), "thunder-pcie")) {
		pr_notice("PCIe: couldn't request %pR\n", &res);
		return -EBUSY;
	}

        /* Map PCIe config space */
	thunder_pcie1_controller.cfg_base = 
              (uint64_t)ioremap_nocache(res.start, resource_size(&res));
        if (!thunder_pcie1_controller.cfg_base) {
            pr_err("PCIe: Failed to map port 1 config space\n");
            return ENOMEM;
        }

	if (cvmx_pemx_is_link_active(1) && 
	    pci_load_of_ranges(&thunder_pcie1_controller, pdev->dev.of_node, 1)) {
		register_pci_controller(&thunder_pcie1_controller);
	} else {
		iounmap((void *)thunder_pcie1_controller.cfg_base);
		pr_err("PCIe: Link not active on port 1, probably the slot is empty\n");
	}

	return 0;
}

static const struct of_device_id thunder_pcie[] = {
        { .compatible = "thunder-pcie" },
        {},
};
MODULE_DEVICE_TABLE(of, thunder_pcie);

static struct platform_driver thunder_pcie_driver = {
        .probe = thunder_pcie_setup,
        .driver = {
                .name = "thunder-pcie",
                .owner = THIS_MODULE,
                .of_match_table = thunder_pcie,
        },
};

int __init thunder_pcie_init(void)
{
        int ret = platform_driver_register(&thunder_pcie_driver);
        if (ret)
                pr_err("Thunder pcie: Error registering platform driver!");
        return ret;
}
arch_initcall(thunder_pcie_init);



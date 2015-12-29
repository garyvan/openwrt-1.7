/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2013 Cavium, Inc.
 */
#ifndef __PCIE_THUNDER_H__
#define __PCIE_THUNDER_H__

/* Some PCI cards require delays when accessing config space. */
#define PCI_CONFIG_SPACE_DELAY 500

#define THUNDER_PCIE_SLI_REG              0x700010000
#define THUNDER_PCIE_SLI_REG_SZ           0x10000

#define THUNDER_PCIE_PEMX_CFG_REG         0x3C0000000
#define THUNDER_PCIE_PEMX_CFG_REG_SIZE    0x1000FFF

static uint64_t  pemx_cfg_reg;

#define	 CVMX_PCIERCX_CFG032       (0x0000000000000080ull)

#define CVMX_PEMX_CTL_STATUS(port) (pemx_cfg_reg + 0x00 + (port * 0x1000000ull))
#define CVMX_PEMX_CFG_WR(port)     (pemx_cfg_reg + 0x28 + (port * 0x1000000ull))
#define CVMX_PEMX_CFG_RD(port)     (pemx_cfg_reg + 0x30 + (port * 0x1000000ull))

/**
 * cvmx_pem#_cfg_rd
 *
 * PEM_CFG_RD = PEM Configuration Read
 *
 * Allows read access to the configuration in the PCIe Core.
 */
union cvmx_pemx_cfg_rd {
        uint64_t u64;
        struct cvmx_pemx_cfg_rd_s {
#ifdef __BIG_ENDIAN_BITFIELD
        uint64_t data                         : 32; /**< Data. */
        uint64_t addr                         : 32; /**< Address to read. A write to this register
                                                         starts a read operation. */
#else
        uint64_t addr                         : 32;
        uint64_t data                         : 32;
#endif
        } s;
};
typedef union cvmx_pemx_cfg_rd cvmx_pemx_cfg_rd_t;

/**
 * cvmx_pem#_cfg_wr
 *
 * PEM_CFG_WR = PEM Configuration Write
 *
 * Allows write access to the configuration in the PCIe Core.
 */
union cvmx_pemx_cfg_wr {
	uint64_t u64;
	struct cvmx_pemx_cfg_wr_s {
#ifdef __BIG_ENDIAN_BITFIELD
	uint64_t data                         : 32; /**< Data to write. A write to this register starts
                                                         a write operation. */
	uint64_t addr                         : 32; /**< Address to write. A write to this register starts
                                                         a write operation. */
#else
	uint64_t addr                         : 32;
	uint64_t data                         : 32;
#endif
	} s;
};
typedef union cvmx_pemx_cfg_wr cvmx_pemx_cfg_wr_t;

/*
 *  cvmx_pcierc#_cfg032
 * 
 *  PCIE_CFG032 = Thirty-third 32-bits of PCIE type 1 config space
 *  (Link Control Register/Link Status Register)
 */

union cvmx_pciercx_cfg032 {
	uint32_t u32;
	struct cvmx_pciercx_cfg032_s {
#ifdef __BIG_ENDIAN_BITFIELD
		uint32_t lab:1;
		uint32_t lbm:1;
		uint32_t dlla:1;
		uint32_t scc:1;
		uint32_t lt:1;
		uint32_t reserved_26_26:1;
		uint32_t nlw:6;
		uint32_t ls:4;
		uint32_t reserved_12_15:4;
		uint32_t lab_int_enb:1;
		uint32_t lbm_int_enb:1;
		uint32_t hawd:1;
		uint32_t ecpm:1;
		uint32_t es:1;
		uint32_t ccc:1;
		uint32_t rl:1;
		uint32_t ld:1;
		uint32_t rcb:1;
		uint32_t reserved_2_2:1;
		uint32_t aslpc:2;
#else
		uint32_t aslpc:2;
		uint32_t reserved_2_2:1;
		uint32_t rcb:1;
		uint32_t ld:1;
		uint32_t rl:1;
		uint32_t ccc:1;
		uint32_t es:1;
		uint32_t ecpm:1;
		uint32_t hawd:1;
		uint32_t lbm_int_enb:1;
		uint32_t lab_int_enb:1;
		uint32_t reserved_12_15:4;
		uint32_t ls:4;
		uint32_t nlw:6;
		uint32_t reserved_26_26:1;
		uint32_t lt:1;
		uint32_t scc:1;
		uint32_t dlla:1;
		uint32_t lbm:1;
		uint32_t lab:1;
#endif
	} s;
};
typedef union cvmx_pciercx_cfg032 cvmx_pciercx_cfg032_t;

union cvmx_pcie_address {
	uint64_t u64;
#ifdef __BIG_ENDIAN_BITFIELD	/* A Linux compatible proxy for __BIG_ENDIAN */
	struct {
		uint64_t upper:2;	/* Normally 2 for XKPHYS */
		uint64_t reserved_49_61:13;	/* Must be zero */
		uint64_t io:1;	/* 1 for IO space access */
		uint64_t did:5;	/* PCIe DID = 3 */
		uint64_t subdid:3;	/* PCIe SubDID = 1 */
		uint64_t reserved_36_39:4;	/* Must be zero */
		uint64_t es:2;	/* Endian swap = 1 */
		uint64_t port:2;	/* PCIe port 0,1 */
		uint64_t reserved_29_31:3;	/* Must be zero */
		uint64_t ty:1;	/* Selects the type of the configuration request (0 = type 0, 1 = type 1). */
		uint64_t bus:8;	/* Target bus number sent in the ID in the request. */
		uint64_t dev:5;	/* Target device number sent in the ID in the request. Note that Dev must be
				   zero for type 0 configuration requests. */
		uint64_t func:3;	/* Target function number sent in the ID in the request. */
		uint64_t reg:12;	/* Selects a register in the configuration space of the target. */
	} config;
	struct {
		uint64_t upper:2;	/* Normally 2 for XKPHYS */
		uint64_t reserved_49_61:13;	/* Must be zero */
		uint64_t io:1;	/* 1 for IO space access */
		uint64_t did:5;	/* PCIe DID = 3 */
		uint64_t subdid:3;	/* PCIe SubDID = 2 */
		uint64_t reserved_36_39:4;	/* Must be zero */
		uint64_t es:2;	/* Endian swap = 1 */
		uint64_t port:2;	/* PCIe port 0,1 */
		uint64_t address:32;	/* PCIe IO address */
	} io;
	struct {
		uint64_t upper:2;	/* Normally 2 for XKPHYS */
		uint64_t reserved_49_61:13;	/* Must be zero */
		uint64_t io:1;	/* 1 for IO space access */
		uint64_t did:5;	/* PCIe DID = 3 */
		uint64_t subdid:3;	/* PCIe SubDID = 3-6 */
		uint64_t reserved_36_39:4;	/* Must be zero */
		uint64_t address:36;	/* PCIe Mem address */
	} mem;
#else
	struct {
		uint64_t reg:12;
		uint64_t func:3;
		uint64_t dev:5;
		uint64_t bus:8;
		uint64_t ty:1;
		uint64_t reserved_29_31:3;
		uint64_t port:2;
		uint64_t es:2;
		uint64_t reserved_36_39:4;
		uint64_t subdid:3;
		uint64_t did:5;
		uint64_t io:1;
		uint64_t reserved_49_61:13;
		uint64_t upper:2;
	} config;
	struct {
		uint64_t address:32;
		uint64_t port:2;
		uint64_t es:2;
		uint64_t reserved_36_39:4;
		uint64_t subdid:3;
		uint64_t did:5;
		uint64_t io:1;
		uint64_t reserved_49_61:13;
		uint64_t upper:2;
	} io;
	struct {
		uint64_t address:36;
		uint64_t reserved_36_39:4;
		uint64_t subdid:3;
		uint64_t did:5;
		uint64_t io:1;
		uint64_t reserved_49_61:13;
		uint64_t upper:2;
	} mem;
#endif
};

#endif

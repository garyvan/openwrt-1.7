/*
 * Driver for Vitesse PHYs
 *
 * Author: Kriston Carson
 *
 * Copyright (c) 2005, 2009 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/phy.h>

//liteon add+
#ifdef ENABLE_VSC8574
#include <linux/of.h>
#endif
//liteon add-

/* Vitesse Extended Control Register 1 */
#define MII_VSC8244_EXT_CON1           0x17
#define MII_VSC8244_EXTCON1_INIT       0x0000
#define MII_VSC8244_EXTCON1_TX_SKEW_MASK	0x0c00
#define MII_VSC8244_EXTCON1_RX_SKEW_MASK	0x0300
#define MII_VSC8244_EXTCON1_TX_SKEW	0x0800
#define MII_VSC8244_EXTCON1_RX_SKEW	0x0200

/* Vitesse Interrupt Mask Register */
#define MII_VSC8244_IMASK		0x19
#define MII_VSC8244_IMASK_IEN		0x8000
#define MII_VSC8244_IMASK_SPEED		0x4000
#define MII_VSC8244_IMASK_LINK		0x2000
#define MII_VSC8244_IMASK_DUPLEX	0x1000
#define MII_VSC8244_IMASK_MASK		0xf000

#define MII_VSC8221_IMASK_MASK		0xa000

/* Vitesse Interrupt Status Register */
#define MII_VSC8244_ISTAT		0x1a
#define MII_VSC8244_ISTAT_STATUS	0x8000
#define MII_VSC8244_ISTAT_SPEED		0x4000
#define MII_VSC8244_ISTAT_LINK		0x2000
#define MII_VSC8244_ISTAT_DUPLEX	0x1000

/* Vitesse Auxiliary Control/Status Register */
#define MII_VSC8244_AUX_CONSTAT        	0x1c
#define MII_VSC8244_AUXCONSTAT_INIT    	0x0000
#define MII_VSC8244_AUXCONSTAT_DUPLEX  	0x0020
#define MII_VSC8244_AUXCONSTAT_SPEED   	0x0018
#define MII_VSC8244_AUXCONSTAT_GBIT    	0x0010
#define MII_VSC8244_AUXCONSTAT_100     	0x0008

#define MII_VSC8221_AUXCONSTAT_INIT	0x0004 /* need to set this bit? */
#define MII_VSC8221_AUXCONSTAT_RESERVED	0x0004

#define PHY_ID_VSC8244			0x000fc6c0
#define PHY_ID_VSC8221			0x000fc550

//liteon add+
#ifdef ENABLE_VSC8574
#define PHY_EXT_PAGE_ACCESS    0x1f
#define PHY_ID_VSC8574			0x000704a2
#define PHY_EXT_PAGE_ACCESS_GENERAL	0x10
#define PHY_EXT_PAGE_ACCESS_EXTENDED3	0x3

/* Vitesse VSC8574 control register */
#define MIIM_VSC8574_MAC_SERDES_CON	0x10
#define MIIM_VSC8574_MAC_SERDES_ANEG	0x80
#define MIIM_VSC8574_GENERAL18		0x12
#define MIIM_VSC8574_GENERAL19		0x13

#define MIIM_VSC8574_MAIN_REG23     0x17

/* Vitesse VSC8574 gerenal purpose register 18 */
#define MIIM_VSC8574_18G_SGMII		0x80f0
#define MIIM_VSC8574_18G_QSGMII		0x80e0
#define MIIM_VSC8574_18G_CMDSTAT	0x8000


/* Vitesse Interrupt Mask Register */
#define MII_VSC8574_IMASK		0x19
#define MII_VSC8574_IMASK_IEN		0x8000
#define MII_VSC8574_IMASK_SPEED		0x4000
#define MII_VSC8574_IMASK_LINK		0x2000
#define MII_VSC8574_IMASK_DUPLEX	0x1000
#define MII_VSC8574_IMASK_MASK		0xf000

#define MII_VSC8574_AUX_CONSTAT        	0x1c
#define MII_VSC8574_AUXCONSTAT_INIT    	0x0000


#endif
//liteon add-

MODULE_DESCRIPTION("Vitesse PHY driver");
MODULE_AUTHOR("Kriston Carson");
MODULE_LICENSE("GPL");

static int vsc824x_add_skew(struct phy_device *phydev)
{
	int err;
	int extcon;

	extcon = phy_read(phydev, MII_VSC8244_EXT_CON1);

	if (extcon < 0)
		return extcon;

	extcon &= ~(MII_VSC8244_EXTCON1_TX_SKEW_MASK |
			MII_VSC8244_EXTCON1_RX_SKEW_MASK);

	extcon |= (MII_VSC8244_EXTCON1_TX_SKEW |
			MII_VSC8244_EXTCON1_RX_SKEW);

	err = phy_write(phydev, MII_VSC8244_EXT_CON1, extcon);

	return err;
}

static int vsc824x_config_init(struct phy_device *phydev)
{
	int err;

	err = phy_write(phydev, MII_VSC8244_AUX_CONSTAT,
			MII_VSC8244_AUXCONSTAT_INIT);
	if (err < 0)
		return err;

	if (phydev->interface == PHY_INTERFACE_MODE_RGMII_ID)
		err = vsc824x_add_skew(phydev);

	return err;
}

static int vsc824x_ack_interrupt(struct phy_device *phydev)
{
	int err = 0;
	
	/*
	 * Don't bother to ACK the interrupts if interrupts
	 * are disabled.  The 824x cannot clear the interrupts
	 * if they are disabled.
	 */
	if (phydev->interrupts == PHY_INTERRUPT_ENABLED)
		err = phy_read(phydev, MII_VSC8244_ISTAT);

	return (err < 0) ? err : 0;
}

static int vsc82xx_config_intr(struct phy_device *phydev)
{
	int err;

	if (phydev->interrupts == PHY_INTERRUPT_ENABLED)
		err = phy_write(phydev, MII_VSC8244_IMASK,
			phydev->drv->phy_id == PHY_ID_VSC8244 ?
				MII_VSC8244_IMASK_MASK :
				MII_VSC8221_IMASK_MASK);
	else {
		/*
		 * The Vitesse PHY cannot clear the interrupt
		 * once it has disabled them, so we clear them first
		 */
		err = phy_read(phydev, MII_VSC8244_ISTAT);

		if (err < 0)
			return err;

		err = phy_write(phydev, MII_VSC8244_IMASK, 0);
	}

	return err;
}

static int vsc8221_config_init(struct phy_device *phydev)
{
	int err;

	err = phy_write(phydev, MII_VSC8244_AUX_CONSTAT,
			MII_VSC8221_AUXCONSTAT_INIT);
	return err;

	/* Perhaps we should set EXT_CON1 based on the interface?
	   Options are 802.3Z SerDes or SGMII */
}


//liteon add+
#ifdef ENABLE_VSC8574


#ifdef CONFIG_OF_MDIO
/*
 * Set and/or override some configuration registers based on the
 * marvell,reg-init property stored in the of_node for the phydev.
 *
 * marvell,reg-init = <reg-page reg mask value>,...;
 *
 * There may be one or more sets of <reg-page reg mask value>:
 *
 * reg-page: which register bank to use.
 * reg: the register.
 * mask: if non-zero, ANDed with existing register value.
 * value: ORed with the masked value and written to the regiser.
 *
 */
static int vitesse_of_reg_init(struct phy_device *phydev)
{
	const __be32 *paddr;
	int len, i, saved_page, current_page, page_changed, ret;
  printk("[liteon]vitesse_of_reg_init\n");


	if (!phydev->dev.of_node)
		return 0;

	paddr = of_get_property(phydev->dev.of_node, "vitesse,reg-init", &len);
	if (!paddr || len < (4 * sizeof(*paddr)))
		return 0;

	saved_page = phy_read(phydev, PHY_EXT_PAGE_ACCESS);
	if (saved_page < 0)
		return saved_page;
	page_changed = 0;
	current_page = saved_page;

	ret = 0;
	len /= sizeof(*paddr);
	for (i = 0; i < len - 3; i += 4) {
		u16 reg_page = be32_to_cpup(paddr + i);
		u16 reg = be32_to_cpup(paddr + i + 1);
		u16 mask = be32_to_cpup(paddr + i + 2);
		u16 val_bits = be32_to_cpup(paddr + i + 3);
		int val;

        printk("[liteon]reg_page=[%x],reg=[%x],mask=[%x],val_bits=[%x]\n",reg_page,reg,mask,val_bits);
  
		if (reg_page != current_page) {
			current_page = reg_page;
			page_changed = 1;
			ret = phy_write(phydev, PHY_EXT_PAGE_ACCESS, reg_page);
			if (ret < 0)
				goto err;
		}

		val = 0;
		if (mask) {
			val = phy_read(phydev, reg);
			if (val < 0) {
				ret = val;
				goto err;
			}
			val &= mask;
		}
		val |= val_bits;

		ret = phy_write(phydev, reg, val);
		if (ret < 0)
			goto err;


        if(current_page==PHY_EXT_PAGE_ACCESS_GENERAL && reg==MIIM_VSC8574_GENERAL18)
        {
        	val = phy_read(phydev,MIIM_VSC8574_GENERAL18);
        	/* When bit 15 is cleared the command has completed */
        	while (val & MIIM_VSC8574_18G_CMDSTAT)
        		val = phy_read(phydev, MIIM_VSC8574_GENERAL18);
        }

	}
err:
	if (page_changed) {
		i = phy_write(phydev, PHY_EXT_PAGE_ACCESS, saved_page);
		if (ret == 0)
			ret = i;
	}
	return ret;
}
#else
static int vitesse_of_reg_init(struct phy_device *phydev)
{
	return 0;
}
#endif /* CONFIG_OF_MDIO */


static int vsc8574_config_init(struct phy_device *phydev)
{
#ifdef CONFIG_OF_MDIO

	int err;

	err = phy_write(phydev, MII_VSC8574_AUX_CONSTAT,
			MII_VSC8574_AUXCONSTAT_INIT);


    vitesse_of_reg_init(phydev);
	phy_write(phydev,  PHY_EXT_PAGE_ACCESS, 0);

	genphy_config_aneg(phydev);
#else
	u32 val;
	int err;

	err = phy_write(phydev, MII_VSC8574_AUX_CONSTAT,
			MII_VSC8574_AUXCONSTAT_INIT);


	/* configure regiser 19G for MAC */
	phy_write(phydev, PHY_EXT_PAGE_ACCESS,
			PHY_EXT_PAGE_ACCESS_GENERAL);

	val = phy_read(phydev,  MIIM_VSC8574_GENERAL19);
	if (phydev->interface == PHY_INTERFACE_MODE_QSGMII) {
		/* set bit 15:14 to '01' for QSGMII mode */
		val = (val & 0x3fff) | (1 << 14);
		phy_write(phydev, 	MIIM_VSC8574_GENERAL19, val);
		/* Enable 4 ports MAC QSGMII */
		phy_write(phydev,  MIIM_VSC8574_GENERAL18,
				MIIM_VSC8574_18G_QSGMII);
	} else {
		/* set bit 15:14 to '00' for SGMII mode */
		val = val & 0x3fff;
		phy_write(phydev,  MIIM_VSC8574_GENERAL19, val);
		/* Enable 4 ports MAC SGMII */
		phy_write(phydev, MIIM_VSC8574_GENERAL18,
				MIIM_VSC8574_18G_SGMII);
	}
	val = phy_read(phydev,MIIM_VSC8574_GENERAL18);
	/* When bit 15 is cleared the command has completed */
	while (val & MIIM_VSC8574_18G_CMDSTAT)
		val = phy_read(phydev, MIIM_VSC8574_GENERAL18);

	/* Enable Serdes Auto-negotiation */
	phy_write(phydev,  PHY_EXT_PAGE_ACCESS,
			PHY_EXT_PAGE_ACCESS_EXTENDED3);
	val = phy_read(phydev, MIIM_VSC8574_MAC_SERDES_CON);
	val = val | MIIM_VSC8574_MAC_SERDES_ANEG;
	phy_write(phydev, MIIM_VSC8574_MAC_SERDES_CON, val);

	phy_write(phydev,  PHY_EXT_PAGE_ACCESS, 0);
	val = phy_read(phydev, MDIO_DEVAD_NONE , MIIM_VSC8574_MAIN_REG23);
    val =  0x0880;
    phy_write(phydev, MDIO_DEVAD_NONE,MIIM_VSC8574_MAIN_REG23,val);

    val = phy_read(phydev, MDIO_DEVAD_NONE , 0);
    val |= 0x8000; //software reset

    val = phy_read(phydev, MDIO_DEVAD_NONE, 0);
    while (val & 0x8000)
      val = phy_read(phydev, MDIO_DEVAD_NONE, 0);
    

    phy_write(phydev,  PHY_EXT_PAGE_ACCESS, 0);

	genphy_config_aneg(phydev);
#endif
	return 0;


}


static int vscc8574_config_intr(struct phy_device *phydev)
{
	int err;

	if (phydev->interrupts == PHY_INTERRUPT_ENABLED)
		err = phy_write(phydev, MII_VSC8574_IMASK,
				MII_VSC8574_IMASK_MASK);
	else {
		/*
		 * The Vitesse PHY cannot clear the interrupt
		 * once it has disabled them, so we clear them first
		 */
		err = phy_read(phydev, MII_VSC8244_ISTAT);

		if (err < 0)
			return err;

		err = phy_write(phydev, MII_VSC8574_IMASK_MASK, 0);
	}

	return err;
}




#endif
//liteon add-


/* Vitesse 824x */
static struct phy_driver vsc82xx_driver[] = {
{
	.phy_id		= PHY_ID_VSC8244,
	.name		= "Vitesse VSC8244",
	.phy_id_mask	= 0x000fffc0,
	.features	= PHY_GBIT_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.config_init	= &vsc824x_config_init,
	.config_aneg	= &genphy_config_aneg,
	.read_status	= &genphy_read_status,
	.ack_interrupt	= &vsc824x_ack_interrupt,
	.config_intr	= &vsc82xx_config_intr,
	.driver		= { .owner = THIS_MODULE,},
}, {
	/* Vitesse 8221 */
	.phy_id		= PHY_ID_VSC8221,
	.phy_id_mask	= 0x000ffff0,
	.name		= "Vitesse VSC8221",
	.features	= PHY_GBIT_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.config_init	= &vsc8221_config_init,
	.config_aneg	= &genphy_config_aneg,
	.read_status	= &genphy_read_status,
	.ack_interrupt	= &vsc824x_ack_interrupt,
	.config_intr	= &vsc82xx_config_intr,
	.driver		= { .owner = THIS_MODULE,},
//liteon add+
}, {
	.phy_id		= PHY_ID_VSC8574,
	.phy_id_mask	= 0x000ffff0,
	.name		= "Vitesse VSC8574",
	.features	= PHY_GBIT_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.config_init	= &vsc8574_config_init,
	.config_aneg	= &genphy_config_aneg,
	.read_status	= &genphy_read_status,
	.ack_interrupt	= &vsc824x_ack_interrupt,
	.config_intr	= &vscc8574_config_intr,
	.driver 	= { .owner = THIS_MODULE,},
//liteon add-
} };

static int __init vsc82xx_init(void)
{
	return phy_drivers_register(vsc82xx_driver,
		ARRAY_SIZE(vsc82xx_driver));
}

static void __exit vsc82xx_exit(void)
{
	return phy_drivers_unregister(vsc82xx_driver,
		ARRAY_SIZE(vsc82xx_driver));
}

module_init(vsc82xx_init);
module_exit(vsc82xx_exit);

static struct mdio_device_id __maybe_unused vitesse_tbl[] = {
	{ PHY_ID_VSC8244, 0x000fffc0 },
	{ PHY_ID_VSC8221, 0x000ffff0 },
	{ }
};

MODULE_DEVICE_TABLE(mdio, vitesse_tbl);

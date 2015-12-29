/*
 * drivers/net/phy/at803x.c
 *
 * Driver for Atheros 803x PHY
 *
 * Author: Matus Ujhelyi <ujhelyi.m@gmail.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/phy.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include "liteon_config.h" //liteon add +
#include <linux/of_device.h>  //liteon add +
#include <linux/of_platform.h> //liteon add +

#define AT803X_INTR_ENABLE			0x12
#define AT803X_INTR_STATUS			0x13
#define AT803X_WOL_ENABLE			0x01
#define AT803X_DEVICE_ADDR			0x03
#define AT803X_LOC_MAC_ADDR_0_15_OFFSET		0x804C
#define AT803X_LOC_MAC_ADDR_16_31_OFFSET	0x804B
#define AT803X_LOC_MAC_ADDR_32_47_OFFSET	0x804A
#define AT803X_MMD_ACCESS_CONTROL		0x0D
#define AT803X_MMD_ACCESS_CONTROL_DATA		0x0E
#define AT803X_FUNC_DATA			0x4003

MODULE_DESCRIPTION("Atheros 803x PHY driver");
MODULE_AUTHOR("Matus Ujhelyi");
MODULE_LICENSE("GPL");


//liteon+
#include "athrs17_phy.h"
#define PROC_ENTRY  1
#if PROC_ENTRY
struct phy_device *my_phydev=NULL;
#include <linux/proc_fs.h>
#endif
uint32_t athrs17_reg_read(struct phy_device *phydev,uint32_t reg_addr);
void athrs17_reg_write(struct phy_device *phydev, uint32_t reg_addr, uint32_t reg_val);
static uint8_t athr17_init_flag = 0;

 const char *sprop;



//liteon-

static void at803x_set_wol_mac_addr(struct phy_device *phydev)
{
	struct net_device *ndev = phydev->attached_dev;
	const u8 *mac;
	unsigned int i, offsets[] = {
		AT803X_LOC_MAC_ADDR_32_47_OFFSET,
		AT803X_LOC_MAC_ADDR_16_31_OFFSET,
		AT803X_LOC_MAC_ADDR_0_15_OFFSET,
	};

	if (!ndev)
		return;

	mac = (const u8 *) ndev->dev_addr;

	if (!is_valid_ether_addr(mac))
		return;

	for (i = 0; i < 3; i++) {
		phy_write(phydev, AT803X_MMD_ACCESS_CONTROL,
				  AT803X_DEVICE_ADDR);
		phy_write(phydev, AT803X_MMD_ACCESS_CONTROL_DATA,
				  offsets[i]);
		phy_write(phydev, AT803X_MMD_ACCESS_CONTROL,
				  AT803X_FUNC_DATA);
		phy_write(phydev, AT803X_MMD_ACCESS_CONTROL_DATA,
				  mac[(i * 2) + 1] | (mac[(i * 2)] << 8));
	}
}

static int at803x_config_init(struct phy_device *phydev)
{
	int val;
	u32 features;
	int status;

	features = SUPPORTED_TP | SUPPORTED_MII | SUPPORTED_AUI |
		   SUPPORTED_FIBRE | SUPPORTED_BNC;

	val = phy_read(phydev, MII_BMSR);
	if (val < 0)
		return val;

	if (val & BMSR_ANEGCAPABLE)
		features |= SUPPORTED_Autoneg;
	if (val & BMSR_100FULL)
		features |= SUPPORTED_100baseT_Full;
	if (val & BMSR_100HALF)
		features |= SUPPORTED_100baseT_Half;
	if (val & BMSR_10FULL)
		features |= SUPPORTED_10baseT_Full;
	if (val & BMSR_10HALF)
		features |= SUPPORTED_10baseT_Half;

	if (val & BMSR_ESTATEN) {
		val = phy_read(phydev, MII_ESTATUS);
		if (val < 0)
			return val;

		if (val & ESTATUS_1000_TFULL)
			features |= SUPPORTED_1000baseT_Full;
		if (val & ESTATUS_1000_THALF)
			features |= SUPPORTED_1000baseT_Half;
	}

	phydev->supported = features;
	phydev->advertising = features;

	/* enable WOL */
	at803x_set_wol_mac_addr(phydev);
	status = phy_write(phydev, AT803X_INTR_ENABLE, AT803X_WOL_ENABLE);
	status = phy_read(phydev, AT803X_INTR_STATUS);

	return 0;
}

//liteon+

void phy_mode_setup(void)
{
#if 0
#ifdef ATHRS17_VER_1_0

  /*work around for phy4 rgmii mode*/
  phy_reg_write(ATHR_PHYBASE(ATHR_IND_PHY), ATHR_PHYADDR(ATHR_IND_PHY), 29, 18);
  phy_reg_write(ATHR_PHYBASE(ATHR_IND_PHY), ATHR_PHYADDR(ATHR_IND_PHY), 30, 0x480c);

  /*rx delay*/
  phy_reg_write(ATHR_PHYBASE(ATHR_IND_PHY), ATHR_PHYADDR(ATHR_IND_PHY), 29, 0);
  phy_reg_write(ATHR_PHYBASE(ATHR_IND_PHY), ATHR_PHYADDR(ATHR_IND_PHY), 30, 0x824e);

  /*tx delay*/
  phy_reg_write(ATHR_PHYBASE(ATHR_IND_PHY), ATHR_PHYADDR(ATHR_IND_PHY), 29, 5);
  phy_reg_write(ATHR_PHYBASE(ATHR_IND_PHY), ATHR_PHYADDR(ATHR_IND_PHY), 30, 0x3d47);

#endif
#endif
}  

/*
 * V-lan configuration given by Switch team
 * Vlan 1:PHY0,1,2,3 and Mac 0 of s17
 * Vlam 2:PHY4 and Mac 6 of s17
 */

void athrs17_vlan_config(struct phy_device *phydev)
{

	if (strcmp(sprop,"cavium,wp868cp,wp868cp_v4"))//liteon add +
	{
		athrs17_reg_write(phydev,S17_P0LOOKUP_CTRL_REG, 0x0014001e);
		athrs17_reg_write(phydev,S17_P0VLAN_CTRL0_REG, 0x10001);

		athrs17_reg_write(phydev,S17_P1LOOKUP_CTRL_REG, 0x0014001d);
		athrs17_reg_write(phydev,S17_P1VLAN_CTRL0_REG, 0x10001);

		athrs17_reg_write(phydev,S17_P2LOOKUP_CTRL_REG, 0x0014001b);
		athrs17_reg_write(phydev,S17_P2VLAN_CTRL0_REG, 0x10001);

		athrs17_reg_write(phydev,S17_P3LOOKUP_CTRL_REG, 0x00140017);
		athrs17_reg_write(phydev,S17_P3VLAN_CTRL0_REG, 0x10001);

		athrs17_reg_write(phydev,S17_P4LOOKUP_CTRL_REG, 0x0014000f);
		athrs17_reg_write(phydev,S17_P4VLAN_CTRL0_REG, 0x10001);

		athrs17_reg_write(phydev,S17_P5LOOKUP_CTRL_REG, 0x00140040);
		athrs17_reg_write(phydev,S17_P5VLAN_CTRL0_REG, 0x20001);

		athrs17_reg_write(phydev,S17_P6LOOKUP_CTRL_REG, 0x00140020);
		athrs17_reg_write(phydev,S17_P6VLAN_CTRL0_REG, 0x20001);
	}
	else
	{
		//liteon add +
		
		athrs17_reg_write(phydev,S17_P0LOOKUP_CTRL_REG, 0x00140004);
		athrs17_reg_write(phydev,S17_P0VLAN_CTRL0_REG, 0x10001);

		athrs17_reg_write(phydev,S17_P2LOOKUP_CTRL_REG, 0x00140001);
		athrs17_reg_write(phydev,S17_P2VLAN_CTRL0_REG, 0x10001);

		athrs17_reg_write(phydev,S17_P3LOOKUP_CTRL_REG, 0x00140040);
		athrs17_reg_write(phydev,S17_P3VLAN_CTRL0_REG, 0x20001);

		athrs17_reg_write(phydev,S17_P6LOOKUP_CTRL_REG, 0x00140008);
		athrs17_reg_write(phydev,S17_P6VLAN_CTRL0_REG, 0x20001);	
		//liteon add +
	}
}

void athrs17_reg_init_wan(struct phy_device *phydev)
{
#define ATH_S17_MAC0_SGMII
#ifdef ATH_S17_MAC0_SGMII
    //athrs17_reg_write(phydev,S17_P6PAD_MODE_REG,0x07600000);
	athrs17_reg_write(phydev,S17_P6PAD_MODE_REG,0x07000000);
#else
    athrs17_reg_write(phydev,S17_P6PAD_MODE_REG,
    athrs17_reg_read(phydev,S17_P6PAD_MODE_REG)|S17_MAC6_SGMII_EN);
#endif
    athrs17_reg_write(phydev,S17_P6STATUS_REG, S17_PORT_STATUS_AZ_DEFAULT);
//liteon+
    athrs17_reg_write(phydev,S17_SGMII_CTRL_REG , 0xc78164de); /* SGMII control */
//liteon-

    athrs17_vlan_config(phydev);
    printk(KERN_ERR"%s done\n",__func__);

}


static int qca8334_config_init(struct phy_device *phydev)
{
	int val;
	u32 features;
	int status;

    if (athr17_init_flag)
    {
        printk(KERN_ERR"athr17_init_flag=1\n");
      return -1;
    }

    athrs17_reg_write(phydev,S17_P0PAD_MODE_REG, S17_MAC0_SGMII_EN);

    athrs17_reg_write(phydev,S17_P0STATUS_REG,  0x0000007e);
    //athrs17_reg_write(phydev,S17_P0STATUS_REG,  0x00001280);
	//athrs17_reg_write(phydev,S17_P0PAD_MODE_REG,   0x00080080);
	
	//liteon add +
	if (strcmp(sprop,"cavium,wp868cp,wp868cp_v4"))
		athrs17_reg_write(phydev,S17_P0PAD_MODE_REG,   0x00080080);
	else
		athrs17_reg_write(phydev,S17_P0PAD_MODE_REG,   0x80080080);
	//liteon add +
	
    athrs17_reg_write(phydev,S17_GLOFW_CTRL1_REG,  0x007f7f7f);

    //phy mode
    athrs17_reg_write(phydev,S17_SGMII_CTRL_REG , 0xc74164de); /* SGMII control */
    
    //mac mode
    //athrs17_reg_write(phydev,S17_SGMII_CTRL_REG , 0xc78164de); /* SGMII control */


    
	features = SUPPORTED_TP | SUPPORTED_MII | SUPPORTED_AUI |
		   SUPPORTED_FIBRE | SUPPORTED_BNC;
     

	val = phy_read(phydev, MII_BMSR);
	if (val < 0)
		return val;

	if (val & BMSR_ANEGCAPABLE)
		features |= SUPPORTED_Autoneg;
	if (val & BMSR_100FULL)
		features |= SUPPORTED_100baseT_Full;
	if (val & BMSR_100HALF)
		features |= SUPPORTED_100baseT_Half;
	if (val & BMSR_10FULL)
		features |= SUPPORTED_10baseT_Full;
	if (val & BMSR_10HALF)
		features |= SUPPORTED_10baseT_Half;

	if (val & BMSR_ESTATEN) {
		val = phy_read(phydev, MII_ESTATUS);
		if (val < 0)
			return val;

		if (val & ESTATUS_1000_TFULL)
			features |= SUPPORTED_1000baseT_Full;
		if (val & ESTATUS_1000_THALF)
			features |= SUPPORTED_1000baseT_Half;
	}

	phydev->supported = features;
	phydev->advertising = features;


#ifdef PHY_LED    
    printf("\n LED0=0x%x\n",athrs17_reg_read(phydev,S17_LED_CTRL0_REG));
    printf("\n LED1=0x%x\n",athrs17_reg_read(phydev,S17_LED_CTRL1_REG));
    printf("\n LED2=0x%x\n",athrs17_reg_read(phydev,S17_LED_CTRL2_REG));
    printf("\n LED3=0x%x\n",athrs17_reg_read(phydev,S17_LED_CTRL3_REG));
    athrs17_reg_write(phydev,S17_LED_CTRL0_REG , 0x00008000);
    athrs17_reg_write(phydev,S17_LED_CTRL1_REG , 0x00008000);
    athrs17_reg_write(phydev,S17_LED_CTRL2_REG , 0x00008000);
    athrs17_reg_write(phydev,S17_LED_CTRL3_REG , 0x03faaa00);
#endif        

    //athr17_init_flag = 1;
	//athrs17_reg_init_wan(phydev);
	
	//liteon add +
	if (!strcmp(sprop,"cavium,wp868cp,wp868cp_v4"))
		athrs17_reg_init_wan(phydev);
	//liteon add +
		
		
    //phy reset
	status = phy_write(phydev,ATHR_PHY_CONTROL , ATHR_CTRL_SOFTWARE_RESET);
    //printk(KERN_ERR"__status=%d\n",status);


    //genphy_config_aneg(phydev);

    //liteon+
    //set this  flag for switch chip,
    //because cavium does not support switch chip.
    phydev->irq = PHY_POLL;
    //liteon-

    printk(KERN_ERR"%s: complete\n",__func__);
	return 0;
}

uint32_t athrs17_reg_read(struct phy_device *phydev,uint32_t reg_addr)
{
    uint32_t reg_word_addr;
    uint32_t phy_addr, tmp_val, reg_val;
    uint16_t phy_val;
    uint8_t phy_reg;

    //liteon+
    int org_phy_addr = phydev->addr;
    //liteon-

    /* change reg_addr to 16-bit word address, 32-bit aligned */
    reg_word_addr = (reg_addr & 0xfffffffc) >> 1;
    //printk(KERN_ERR"__286_org_phy_addr=%d\n",phydev->addr);

    /* configure register high address */
    phy_addr = 0x18;
    phy_reg = 0x0;
    phy_val = (uint16_t) ((reg_word_addr >> 8) & 0x1ff);  /* bit16-8 of reg address */
    //liteon+
    phydev->addr = phy_addr;
    ////liteon-
    phy_write(phydev, phy_reg, phy_val);
    
    /* For some registers such as MIBs, since it is read/clear, we should */
    /* read the lower 16-bit register then the higher one */
    
    /* read register in lower address */
    phy_addr = 0x10 | ((reg_word_addr >> 5) & 0x7); /* bit7-5 of reg address */
    phy_reg = (uint8_t) (reg_word_addr & 0x1f);   /* bit4-0 of reg address */
    //liteon+
    phydev->addr = phy_addr;
    //liteon-
    reg_val = (uint32_t) phy_read(phydev, phy_reg);
    
    /* read register in higher address */
    reg_word_addr++;
    phy_addr = 0x10 | ((reg_word_addr >> 5) & 0x7); /* bit7-5 of reg address */
    phy_reg = (uint8_t) (reg_word_addr & 0x1f);   /* bit4-0 of reg address */
    //liteon+
    phydev->addr = phy_addr;
    //liteon-
    tmp_val = (uint32_t) phy_read(phydev, phy_reg);
    reg_val |= (tmp_val << 16);
    
    //liteon+
    phydev->addr = org_phy_addr;
    //liteon-
    
    return reg_val;
    
}

void athrs17_reg_write(struct phy_device *phydev, uint32_t reg_addr, uint32_t reg_val)
{
    uint32_t reg_word_addr;
    uint32_t phy_addr;
    uint16_t phy_val;
    uint8_t phy_reg;
//liteon+
    int org_phy_addr = phydev->addr;
//liteon-
    //printk(KERN_ERR"__327__org_phy_addr=%d\n",phydev->addr);
    
    /* change reg_addr to 16-bit word address, 32-bit aligned */
    reg_word_addr = (reg_addr & 0xfffffffc) >> 1;

    /* configure register high address */
    phy_addr = 0x18;
    phy_reg = 0x0;
    phy_val = (uint16_t) ((reg_word_addr >> 8) & 0x1ff);  /* bit16-8 of reg address */
    //liteon+
    phydev->addr = phy_addr;
    //liteon-
    phy_write(phydev, phy_reg, phy_val);
    
    /* For some registers such as ARL and VLAN, since they include BUSY bit */
    /* in lower address, we should write the higher 16-bit register then the */
    /* lower one */

    /* read register in higher address */
    reg_word_addr++;
    phy_addr = 0x10 | ((reg_word_addr >> 5) & 0x7); /* bit7-5 of reg address */
    phy_reg = (uint8_t) (reg_word_addr & 0x1f);   /* bit4-0 of reg address */
    phy_val = (uint16_t) ((reg_val >> 16) & 0xffff);
    //liteon+
    phydev->addr = phy_addr;
    //liteon-
    phy_write(phydev, phy_reg, phy_val);

    /* write register in lower address */
    reg_word_addr--;
    phy_addr = 0x10 | ((reg_word_addr >> 5) & 0x7); /* bit7-5 of reg address */
    phy_reg = (uint8_t) (reg_word_addr & 0x1f);   /* bit4-0 of reg address */
    phy_val = (uint16_t) (reg_val & 0xffff);
    //liteon+
    phydev->addr = phy_addr;
    //liteon-
    phy_write(phydev, phy_reg, phy_val);

    //liteon+
    phydev->addr = org_phy_addr;
    //liteon-
}

int qca8334_read_status(struct phy_device *phydev)
{
  int phy_status;
  int pma_ctrl1;
  int org_addr = phydev->addr;
  int i=0;

  //printk(KERN_ERR"__399__org_phy_addr=%d\n",phydev->addr);

  phydev->link = 0;

	if (strcmp(sprop,"cavium,wp868cp,wp868cp_v4"))
	{
	  for (i=0;i<4;i++)//liteon mark -
	  {
		   phydev->addr = i;

		/* All the speed information can be read from register 17 in one go. */
		phy_status = phy_read(phydev, 17);
		//printk("2..phy_status=0x%x,phy_addr=%d,link=%d\n",phy_status,phydev->addr,phydev->link);
	   
		/* If the resolve bit 11 isn't set, see if autoneg is turned off
		   (bit 12, reg 0). The resolve bit doesn't get set properly when
		   autoneg is off, so force it */
		if ((phy_status & (1 << 11)) == 0) 
		{
			int auto_status = phy_read(phydev, 0);
			//printk(KERN_ERR"__379__\n");
			//printk(KERN_ERR"..auto_status=0x%x\n",auto_status);

			if ((auto_status & (1 << 12)) == 0)
			{
				//printk(KERN_ERR"\n__382__");
				phy_status |= 1 << 11;
			}
		}


	   /* Only return a link if the PHY has finished auto negotiation
		*    and set the resolved bit (bit 11) */
		   if (phy_status & (1 << 11)) 
		   {
			  phydev->link = 1;

			  if ((phy_status >> 13) & 1)
					phydev->duplex = DUPLEX_FULL ;

			  switch ((phy_status >> 14) & 3) 
			  {
				case 0: /* 10 Mbps */
					  phydev->speed = SPEED_10;
					  break;
				case 1: /* 100 Mbps */
					  phydev->speed = SPEED_100;
					  break;
				case 2: /* 1 Gbps */
					  phydev->speed = SPEED_1000;
					  break;
				case 3: /* Illegal */
					  phydev->speed = 0;
					  break;
			  }
		  }

		   if (phydev->link)
		   {
			 //printk("link=%d",phydev->link);
			   break;  
		   }
	  }
	  if (phydev->duplex == DUPLEX_FULL)
			phydev->pause = phydev->asym_pause = (phy_status >> 2) & 1;
	  
	  phydev->addr = org_addr;
		return 0;
	}
	//liteon add +
	else
	{
	  //for (i=0;i<4;i++)
	  //{
		   //phydev->addr = i;

		/* All the speed information can be read from register 17 in one go. */
		phy_status = phy_read(phydev, 17);
		//printk("2..phy_status=0x%x,phy_addr=%d,link=%d\n",phy_status,phydev->addr,phydev->link);
	   
		/* If the resolve bit 11 isn't set, see if autoneg is turned off
		   (bit 12, reg 0). The resolve bit doesn't get set properly when
		   autoneg is off, so force it */
		if ((phy_status & (1 << 11)) == 0) 
		{
			int auto_status = phy_read(phydev, 0);
			//printk(KERN_ERR"__379__\n");
			//printk(KERN_ERR"..auto_status=0x%x\n",auto_status);

			if ((auto_status & (1 << 12)) == 0)
			{
				//printk(KERN_ERR"\n__382__");
				phy_status |= 1 << 11;
			}
		}


	   /* Only return a link if the PHY has finished auto negotiation
		*    and set the resolved bit (bit 11) */
		   if (phy_status & (1 << 11)) 
		   {
			  phydev->link = 1;

			  if ((phy_status >> 13) & 1)
					phydev->duplex = DUPLEX_FULL ;

			  switch ((phy_status >> 14) & 3) 
			  {
				case 0: /* 10 Mbps */
					  phydev->speed = SPEED_10;
					  break;
				case 1: /* 100 Mbps */
					  phydev->speed = SPEED_100;
					  break;
				case 2: /* 1 Gbps */
					  phydev->speed = SPEED_1000;
					  break;
				case 3: /* Illegal */
					  phydev->speed = 0;
					  break;
			  }
		  }

		   if (phydev->link)
		   {
			 //printk("link=%d",phydev->link);
			 //break;  
		   }
	  //}
	  if (phydev->duplex == DUPLEX_FULL)
			phydev->pause = phydev->asym_pause = (phy_status >> 2) & 1;
	  
	  phydev->addr = org_addr;
		return 0;	
	}
//liteon add +
}

static int qca8334_config_aneg(struct phy_device *phydev)
{
      int err;
      int i;
      int org_addr = phydev->addr;

      //printk(KERN_ERR"__474__qca8334_config_aneg\n");
      
      //save to global var
      my_phydev = phydev;

      //for (i=0;i<4;i++)
      //{
          //err = phy_write(phydev, MII_BMCR, BMCR_RESET);
          //if (err < 0)
          //   return err;

      #if 0
      err = phy_write(phydev, MII_M1011_PHY_SCR, MII_M1011_PHY_SCR_AUTO_CROSS);
      if (err < 0)
         return err;
      #endif

      for (i=0;i<4;i++)
      {
           phydev->addr = i;
           err = genphy_config_aneg(phydev);
           //printk(KERN_ERR"ang_val=0x%x\n",err);
      }

      phydev->addr = org_addr;
      return err;
}


static int qca8334_phy_is_link_alive(struct phy_device *phydev)
{
  uint16_t phyHwStatus;
  phyHwStatus = phy_read(phydev, 17);

  if (phyHwStatus & S17_STATUS_LINK_PASS)
    return 1;


      return 0;
}


#if 1
static int qca8334_ack_interrupt(struct phy_device *phydev)
{
	int err;

	err = phy_read(phydev, ATHR_PHY_INTR_STATUS);

    //printk(KERN_ERR"ack_intr=0x%x\n",err);

	return (err < 0) ? err : 0;
}


static int qca8334_config_interrupt(struct phy_device *phydev)
{
	int err;

	if (phydev->interrupts == PHY_INTERRUPT_ENABLED)
    {
		err = phy_write(phydev, ATHR_PHY_INTR_CONTROL,ATHR_PHY_INTRS);

        //printk(KERN_ERR"config_intr1=0x%x\n",err);
    }
	else
    {
		err = phy_write(phydev, ATHR_PHY_INTR_CONTROL, 0);
        //printk(KERN_ERR"config_intr2=0x%x\n",err);
        athr17_init_flag = 0;

    //printk(KERN_ERR"__286_org_phy_addr=%d\n",phydev->addr);
    }

	return  err;
}


static int qca8334_ack_interrupt_(struct phy_device *phydev)
{
    int status = 0, intr_reg_val;
    uint32_t phyUnit = 0 ,phyOrgAddr = 0;
    uint32_t phymask = 0x0;
    uint32_t linkDown = 0x0;
    //athr_gmac_t *mac0 = athr_macs[0];

    //store original phy_addr
    phyOrgAddr = phydev->addr;

    athrs17_reg_write(phydev, S17_GLOBAL_INTMASK1, 0x0);

    intr_reg_val = athrs17_reg_read(phydev, S17_GLOBAL_INT1_REG);

    /* clear global link interrupt */
    athrs17_reg_write(phydev, S17_GLOBAL_INT1_REG, intr_reg_val);

    if (intr_reg_val & S17_GLOBAL_INT_PHYMASK)
    {
        for (phyUnit=0; phyUnit < S17_PHY_MAX; phyUnit++)
        {
            phydev->addr = phyUnit;
            status = phy_read(phydev, ATHR_PHY_INTR_STATUS);

            if(status & ATHR_PHY_INTR_LINK_UP)
            {
                printk(KERN_ERR"LINK UP - Port %d:%x\n",phyUnit,status);
                phymask = (phymask | (1 << phyUnit));
            }
            if(status & ATHR_PHY_INTR_LINK_DOWN)
            {
                printk(KERN_ERR"LINK DOWN - Port %d:%x\n",phyUnit,status);
                phymask = (phymask | (1 << phyUnit));
                linkDown = (linkDown | (1 << phyUnit));
            }
            if(status & ATHR_PHY_INTR_DUPLEX_CHANGE)
            {
                printk(KERN_ERR"LINK DUPLEX CHANGE - Port %d:%x\n",phyUnit,status);
                phymask = (phymask | (1 << phyUnit));
            }
            if(status & ATHR_PHY_INTR_SPEED_CHANGE)
            {
                printk(KERN_ERR"LINK SPEED CHANGE %d:%x\n",phyUnit,status);
                phymask = (phymask | (1 << phyUnit));
            }
        }
        for (phyUnit=0; phyUnit < S17_PHY_MAX; phyUnit++)
        {
            if ((phymask >> phyUnit) & 0x1)
            {
               phydev->addr = phyUnit ;

               status = phy_read(phydev,ATHR_PHY_INTR_STATUS);

               if (!qca8334_phy_is_link_alive(phydev) && !((linkDown >> phyUnit) & 0x1))
                   continue;
               //mac0->ops->check_link(mac0,phyUnit);

               //liteon+
               return phymask;
               //liteon-
            }
        }

        athrs17_reg_write(phydev, S17_GLOBAL_INTMASK1, S17_GLOBAL_INT_PHYMASK);

    }
    else
    {
        printk(KERN_ERR"Spurious link interrupt:%s,status:%x\n",__func__,status);
        athrs17_reg_write(phydev, S17_GLOBAL_INTMASK1, S17_GLOBAL_INT_PHYMASK);
    }

    //restore original phy_addr
    phydev->addr = phyOrgAddr ;

    return 0;
}
#endif
//liteon-

/* ATHEROS 8035 */
static struct phy_driver at8035_driver = {
	.phy_id		= 0x004dd072,
	.name		= "Atheros 8035 ethernet",
	.phy_id_mask	= 0xffffffef,
	.config_init	= at803x_config_init,
	.features	= PHY_GBIT_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.config_aneg	= &genphy_config_aneg,
	.read_status	= &genphy_read_status,
	.driver		= {
		.owner = THIS_MODULE,
	},
};

/* ATHEROS 8030 */
static struct phy_driver at8030_driver = {
	.phy_id		= 0x004dd076,
	.name		= "Atheros 8030 ethernet",
	.phy_id_mask	= 0xffffffef,
	.config_init	= at803x_config_init,
	.features	= PHY_GBIT_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.config_aneg	= &genphy_config_aneg,
	.read_status	= &genphy_read_status,
	.driver		= {
		.owner = THIS_MODULE,
	},
};

//liteon+
/* ATHEROS QCA8334 */
static struct phy_driver qca8334_driver = {
	.phy_id		= 0x004dd036,
	.name		= "Atheros 8334 ethernet",
	.phy_id_mask	= 0xfffffff0,
	.config_init	= qca8334_config_init,
	.features	= PHY_GBIT_FEATURES,
	//.flags		= PHY_HAS_INTERRUPT,
    .flags      = PHY_HAS_MAGICANEG | PHY_HAS_INTERRUPT | PHY_QCA_SWITCH,
    //.flags      = PHY_HAS_INTERRUPT | PHY_HAS_MAGICANEG,
    //.flags      = PHY_POLL,
	//.ack_interrupt	= &rtl821x_ack_interrupt,
	//.config_intr	= &rtl8211b_config_intr,
	.ack_interrupt	= qca8334_ack_interrupt,
    .config_intr  = qca8334_config_interrupt,
    .config_aneg = qca8334_config_aneg,
	//.config_aneg	= &genphy_config_aneg,
    .read_status = qca8334_read_status,
	//.read_status	= &genphy_read_status,
	.driver		= {
		.owner = THIS_MODULE,
	},
};


#if PROC_ENTRY
uint32_t g_reg_num=0;
unsigned int g_eth_n=0,g_reg=0;
uint32_t g_reg_val=0;

static int phy_proc_write(struct file *file, const char *buf, unsigned long count, void *data)
{
   char cmd_buf[256]; 
   int ret;

   unsigned int eth_n,reg,rw;
   uint32_t reg_val;
   

   if (count == 0)return -1;
   if(count > 255)count = 255;

   ret = copy_from_user(cmd_buf, buf, count);
   if (ret < 0)return -1;

   cmd_buf[count] = '\0';
   printk("qca8334 write reg = %s\n", cmd_buf);

   sscanf(cmd_buf, "%d %d %x %x " ,&rw,&eth_n, &reg,&reg_val);

   printk(" rw=%d ,eth_port=%d, reg_addr=0x%x , reg_val=0x%x \n" ,rw, eth_n, reg, reg_val);
  
   if (my_phydev)
   {
       if (rw)
       {

       g_eth_n = my_phydev->addr = eth_n;
       g_reg = reg;
       g_reg_val = reg_val;
       athrs17_reg_write(my_phydev,g_reg , reg_val);
       }
       else
       {
           my_phydev->addr = eth_n;
           printk("reg%x =0x%x\n",reg,athrs17_reg_read(my_phydev,reg ));
       }
   }



   return count;
}

static int qca8334_proc_show(struct seq_file *seq, void *offset)
{
    int err;
    //seq_printf(seq,"__proc__test=%s\n",__func__);

#if 1
    if (my_phydev)
    {
    seq_printf(seq,"reg:0x%x=0x%x\n",g_reg,athrs17_reg_read(my_phydev,g_reg ));

    }
#endif

    return 0;
}

static int qca8334_proc_open(struct inode *inode, struct file *file)
{
    int ret;

    if (!try_module_get(THIS_MODULE))
       return -ENODEV;

    ret = single_open(file, qca8334_proc_show, NULL);
    if (ret)
       module_put(THIS_MODULE);

    return ret;
}

static int qca8334_proc_release(struct inode *inode, struct file *file)
{
    int res = single_release(inode, file);
    module_put(THIS_MODULE);

    return res;
}

static const struct file_operations qca8334_proc_fops = {
    .open       = qca8334_proc_open,
    .read       = seq_read,
    .write      = phy_proc_write,
    .llseek     = seq_lseek,
    .release    = qca8334_proc_release,
};
#endif
//liteon-

static int __init atheros_init(void)
{
	int ret;

	ret = phy_driver_register(&at8035_driver);
	if (ret)
		goto err1;

	ret = phy_driver_register(&at8030_driver);
	if (ret)
		goto err2;
//liteon+
    ret = phy_driver_register(&qca8334_driver);
#if PROC_ENTRY
    struct proc_file_entry *fe = proc_create("qca8334", 0667, NULL,&qca8334_proc_fops);
    if (!fe) 
    {
        remove_proc_entry("qca8334", 0);
        return -EIO;
    }
#endif
    if (ret)
        goto err3;
//liteon-

//liteon add +
	sprop = of_get_property(of_find_node_by_path("/"),"model",NULL);
	
//liteon add +

	return 0;

//liteon+
err3:
    phy_driver_unregister(&qca8334_driver);
    return ret;
//liteon-    

err2:
	phy_driver_unregister(&at8035_driver);
err1:
	return ret;
}

static void __exit atheros_exit(void)
{
	phy_driver_unregister(&at8035_driver);
	phy_driver_unregister(&at8030_driver);
//liteon+    
	phy_driver_unregister(&qca8334_driver);
//liteon-    
}

module_init(atheros_init);
module_exit(atheros_exit);

static struct mdio_device_id __maybe_unused atheros_tbl[] = {
	{ 0x004dd076, 0xffffffef },
	{ 0x004dd072, 0xffffffef },
//liteon+    
	{ 0x004dd036, 0xfffffff0 },
//liteon-    
	{ }
};

MODULE_DEVICE_TABLE(mdio, atheros_tbl);

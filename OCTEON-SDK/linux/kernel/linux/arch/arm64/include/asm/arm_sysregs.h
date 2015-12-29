/*
 * arch/arm64/include/asm/arm_sysregs.h
 *
 * Copyright (C) 2013 Cavium Inc.
 * Author: Radha Mohan Chintakuntla <rchintakuntla@cavium.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_ARM_SYSREGS_H
#define __ASM_ARM_SYSREGS_H
static inline u32 readl_icc_sre(void)
{
	u32 val;
	
	asm volatile("mrs %0,  icc_sre_el1" : "=r" (val));

	return val;
}

static inline u32 readl_icc_iar0(void)
{
	u32 val;
	
	asm volatile("mrs %0,  icc_iar0_el1" : "=r" (val));

	return val;
}

static inline u32 readl_icc_iar1(void)
{
	u32 val;
	
	asm volatile("mrs %0,  icc_iar1_el1" : "=r" (val));

	return val;
}
static inline void writel_icc_pmr(u32 val)
{
	asm volatile("msr icc_pmr_el1,  %0" : : "r" (val));
}

static inline void writel_icc_ctlr(u32 val)
{
	asm volatile("msr icc_ctlr_el1,  %0" : : "r" (val));
}

static inline void writel_icc_eoir0(u32 val)
{
	asm volatile("msr icc_eoir0_el1,  %0" : : "r" (val));
}

static inline void writel_icc_eoir1(u32 val)
{
	asm volatile("msr icc_eoir1_el1,  %0" : : "r" (val));
}

static inline void writel_icc_sgi0r(u32 val)
{
	asm volatile("msr icc_sgi0r_el1,  %0" : : "r" (val));
}

static inline void writel_icc_sgi1r(u32 val)
{
	asm volatile("msr icc_sgi1r_el1,  %0" : : "r" (val));
}

#endif

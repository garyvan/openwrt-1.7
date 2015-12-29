/*
 * Aarch64 KGDB support
 *
 * Most of the contents are extracted from 
 * arch/arm/include/kgdb.h
 *
 * Copyright (C) 2013 Cavium Inc.
 *
 * Author: Vijaya Kumar K <vijaya.kumar@caviumnetworks.com>
 */

#ifndef __ARM_KGDB_H__
#define __ARM_KGDB_H__

#include <linux/ptrace.h>

/*
 * Break Instruction encoding
 */

#define BREAK_INSTR_SIZE		4
#define KGDB_BREAKINST_ESR_VAL		0xf2000000
#define KGDB_COMPILED_BREAK_ESR_VAL	0xf2000001
#define CACHE_FLUSH_IS_SAFE		1
#define ARM64_KGDB_COMPILE_BRK_IMM      1

#ifndef	__ASSEMBLY__

static inline void arch_kgdb_breakpoint(void)
{
	asm ("brk %0" :: "I" (ARM64_KGDB_COMPILE_BRK_IMM));
}

extern void kgdb_handle_bus_error(void);
extern int kgdb_fault_expected;

#endif /* !__ASSEMBLY__ */

/*
 * gdb is expecting the following registers layout.
 *
 * r0-r31: 64bit each
 * f0-f31: unused
 * fps:    unused
 *
 */

#define _GP_REGS		34
#define _FP_REGS		32
#define _EXTRA_REGS		2
#define GDB_MAX_REGS		(_GP_REGS + (_FP_REGS * 3) + _EXTRA_REGS)
#define DBG_MAX_REG_NUM		(_GP_REGS + _FP_REGS + _EXTRA_REGS)

#define KGDB_MAX_NO_CPUS	1
#define BUFMAX			400
#define NUMREGBYTES		(DBG_MAX_REG_NUM << 2)

#endif /* __ASM_KGDB_H__ */

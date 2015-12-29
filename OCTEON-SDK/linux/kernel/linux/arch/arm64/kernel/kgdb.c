/*
 * arch/arm64/kernel/kgdb.c
 *
 * Aarch64 KGDB support. 
 *
 * most part of code copied from arch/arm/kernel/kgdb.c
 *
 * Author:  Vijaya Kumar K <vijaya.kumar@caviumnetworks.com>
 */

#include <linux/irq.h>
#include <linux/kdebug.h>
#include <linux/kgdb.h>
#include <asm/traps.h>
#include <asm/debug-monitors.h>

struct dbg_reg_def_t dbg_reg_def[DBG_MAX_REG_NUM] =
{
	{ "x0", 8, offsetof(struct pt_regs, regs[0])},
	{ "x1", 8, offsetof(struct pt_regs, regs[1])},
	{ "x2", 8, offsetof(struct pt_regs, regs[2])},
	{ "x3", 8, offsetof(struct pt_regs, regs[3])},
	{ "x4", 8, offsetof(struct pt_regs, regs[4])},
	{ "x5", 8, offsetof(struct pt_regs, regs[5])},
	{ "x6", 8, offsetof(struct pt_regs, regs[6])},
	{ "x7", 8, offsetof(struct pt_regs, regs[7])},
	{ "x8", 8, offsetof(struct pt_regs, regs[8])},
	{ "x9", 8, offsetof(struct pt_regs, regs[9])},
	{ "x10", 8, offsetof(struct pt_regs, regs[10])},
	{ "x11", 8, offsetof(struct pt_regs, regs[11])},
	{ "x12", 8, offsetof(struct pt_regs, regs[12])},
	{ "x13", 8, offsetof(struct pt_regs, regs[13])},
	{ "x14", 8, offsetof(struct pt_regs, regs[14])},
	{ "x15", 8, offsetof(struct pt_regs, regs[15])},
	{ "x16", 8, offsetof(struct pt_regs, regs[16])},
	{ "x17", 8, offsetof(struct pt_regs, regs[17])},
	{ "x18", 8, offsetof(struct pt_regs, regs[18])},
	{ "x19", 8, offsetof(struct pt_regs, regs[19])},
	{ "x20", 8, offsetof(struct pt_regs, regs[20])},
	{ "x21", 8, offsetof(struct pt_regs, regs[21])},
	{ "x22", 8, offsetof(struct pt_regs, regs[22])},
	{ "x23", 8, offsetof(struct pt_regs, regs[23])},
	{ "x24", 8, offsetof(struct pt_regs, regs[24])},
	{ "x25", 8, offsetof(struct pt_regs, regs[25])},
	{ "x26", 8, offsetof(struct pt_regs, regs[26])},
	{ "x27", 8, offsetof(struct pt_regs, regs[27])},
	{ "x28", 8, offsetof(struct pt_regs, regs[28])},
	{ "x29", 8, offsetof(struct pt_regs, regs[29])},
	{ "x30", 8, offsetof(struct pt_regs, regs[30])},
	{ "sp", 8, offsetof(struct pt_regs, sp)},
	{ "pc", 8, offsetof(struct pt_regs, pc)},
	{ "cpsr", 4, offsetof(struct pt_regs, pstate)},
	{ "v0", 16, -1 },
	{ "v1", 16, -1 },
	{ "v2", 16, -1 },
	{ "v3", 16, -1 },
	{ "v4", 16, -1 },
	{ "v5", 16, -1 },
	{ "v6", 16, -1 },
	{ "v7", 16, -1 },
	{ "v8", 16, -1 },
	{ "v9", 16, -1 },
	{ "v10", 16, -1 },
	{ "v11", 16, -1 },
	{ "v12", 16, -1 },
	{ "v13", 16, -1 },
	{ "v14", 16, -1 },
	{ "v15", 16, -1 },
	{ "v16", 16, -1 },
	{ "v17", 16, -1 },
	{ "v18", 16, -1 },
	{ "v19", 16, -1 },
	{ "v20", 16, -1 },
	{ "v21", 16, -1 },
	{ "v22", 16, -1 },
	{ "v23", 16, -1 },
	{ "v24", 16, -1 },
	{ "v25", 16, -1 },
	{ "v26", 16, -1 },
	{ "v27", 16, -1 },
	{ "v28", 16, -1 },
	{ "v29", 16, -1 },
	{ "v30", 16, -1 },
	{ "v31", 16, -1 },
	{ "fpsr", 4, -1 },
	{ "fpcr", 4, -1 },
};

char *dbg_get_reg(int regno, void *mem, struct pt_regs *regs)
{
	if (regno >= DBG_MAX_REG_NUM || regno < 0)
		return NULL;

	if (dbg_reg_def[regno].offset != -1)
		memcpy(mem, (void *)regs + dbg_reg_def[regno].offset,
		       dbg_reg_def[regno].size);
	else
		memset(mem, 0, dbg_reg_def[regno].size);
	return dbg_reg_def[regno].name;
}

int dbg_set_reg(int regno, void *mem, struct pt_regs *regs)
{
	if (regno >= DBG_MAX_REG_NUM || regno < 0)
		return -EINVAL;

	if (dbg_reg_def[regno].offset != -1)
		memcpy((void *)regs + dbg_reg_def[regno].offset, mem,
		       dbg_reg_def[regno].size);
	return 0;
}

void
sleeping_thread_to_gdb_regs(unsigned long *gdb_regs, struct task_struct *task)
{
	struct pt_regs *thread_regs;
	int regno;
	int i;

	/* Just making sure... */
	if (task == NULL)
		return;

	/* Initialize to zero */
	for (regno = 0; regno < GDB_MAX_REGS; regno++)
		gdb_regs[regno] = 0;

	thread_regs		= task_pt_regs(task);

	for(i = 0; i < 31; i++)
		gdb_regs[i] = thread_regs->regs[i];

        gdb_regs[31]            = thread_regs->sp;
        gdb_regs[32]            = thread_regs->pc;
        gdb_regs[33]            = thread_regs->pstate;
}

void kgdb_arch_set_pc(struct pt_regs *regs, unsigned long pc)
{
	regs->pc = pc;
}

static int compiled_break;

int kgdb_arch_handle_exception(int exception_vector, int signo,
			       int err_code, char *remcom_in_buffer,
			       char *remcom_out_buffer,
			       struct pt_regs *linux_regs)
{
	unsigned long addr;
	char *ptr;
	int err;

	switch (remcom_in_buffer[0]) {
	case 'D':
	case 'k':
	case 'c':
		/*
		 * Try to read optional parameter, pc unchanged if no parm.
		 * If this was a compiled breakpoint, we need to move
		 * to the next instruction or we will just breakpoint
		 * over and over again.
		 */
		ptr = &remcom_in_buffer[1];
		if (kgdb_hex2long(&ptr, &addr))
			linux_regs->pc = addr;
		else if (compiled_break == 1)
			linux_regs->pc += 4;

		compiled_break = 0;

		/* Disable single step if enabled */
		if (kernel_active_single_step())
			kernel_disable_single_step();
		err = 0;
		break;
	case 's':
		/*
		 * Workaround disable step debug for every step command
		 */
                if (kernel_active_single_step())
                        kernel_disable_single_step();

		/* 
		 * Update PC value with step address passed
		 */
		ptr = &remcom_in_buffer[1];
		if (kgdb_hex2long(&ptr, &addr))
			kgdb_arch_set_pc(linux_regs, addr);

		if (compiled_break == 1)
			compiled_break = 0;

		/* Enable step handling if not enable */
		if (!kernel_active_single_step())
			kernel_enable_single_step(linux_regs);
		err = 0;
		break;
	default:
		err = -1;
	}
	return err;
}

static int
kgdb_brk_fn(struct pt_regs *regs, unsigned int esr, unsigned long addr)
{
	kgdb_handle_exception(1, SIGTRAP, 0, regs);
	return 0;
}

static int kgdb_compiled_brk_fn(struct pt_regs *regs, unsigned int esr,
				unsigned long addr)
{
	compiled_break = 1;
	kgdb_handle_exception(1, SIGTRAP, 0, regs);

	return 0;
}

static int kgdb_step_brk_fn(struct pt_regs *regs, unsigned int esr,
                               unsigned long addr)
{
	kgdb_handle_exception(1, SIGTRAP, 0, regs);
	return 0;
}

static struct break_hook kgdb_brkpt_hook = {
	.esr_mask		= 0xffffffff,
	.esr_magic		= KGDB_BREAKINST_ESR_VAL,
	.fn			= kgdb_brk_fn
};

static struct break_hook kgdb_compiled_brkpt_hook = {
	.esr_mask		= 0xffffffff,
	.esr_magic		= KGDB_COMPILED_BREAK_ESR_VAL,
	.fn			= kgdb_compiled_brk_fn
};

static struct step_hook kgdb_step_hook = {
	.fn                     = kgdb_step_brk_fn
};

static void kgdb_call_nmi_hook(void *ignored)
{
       kgdb_nmicallback(raw_smp_processor_id(), get_irq_regs());
}

void kgdb_roundup_cpus(unsigned long flags)
{
       local_irq_enable();
       smp_call_function(kgdb_call_nmi_hook, NULL, 0);
       local_irq_disable();
}

static int __kgdb_notify(struct die_args *args, unsigned long cmd)
{
	struct pt_regs *regs = args->regs;

	if (kgdb_handle_exception(1, args->signr, cmd, regs))
		return NOTIFY_DONE;
	return NOTIFY_STOP;
}

static int
kgdb_notify(struct notifier_block *self, unsigned long cmd, void *ptr)
{
	unsigned long flags;
	int ret;

	local_irq_save(flags);
	ret = __kgdb_notify(ptr, cmd);
	local_irq_restore(flags);

	return ret;
}

static struct notifier_block kgdb_notifier = {
	.notifier_call	= kgdb_notify,
	.priority	= -INT_MAX,
};


/**
 *	kgdb_arch_init - Perform any architecture specific initalization.
 *
 *	This function will handle the initalization of any architecture
 *	specific callbacks.
 */
int kgdb_arch_init(void)
{
	int ret = register_die_notifier(&kgdb_notifier);

	if (ret != 0)
		return ret;

	register_break_hook(&kgdb_brkpt_hook);
	register_break_hook(&kgdb_compiled_brkpt_hook);
	register_step_hook(&kgdb_step_hook);

	return 0;
}

/**
 *	kgdb_arch_exit - Perform any architecture specific uninitalization.
 *
 *	This function will handle the uninitalization of any architecture
 *	specific callbacks, for dynamic registration and unregistration.
 */
void kgdb_arch_exit(void)
{
	unregister_break_hook(&kgdb_brkpt_hook);
	unregister_break_hook(&kgdb_compiled_brkpt_hook);
	unregister_step_hook(&kgdb_step_hook);
	unregister_die_notifier(&kgdb_notifier);
}

/*
 * Register our undef instruction hooks with ARM undef core.
 * We regsiter a hook specifically looking for the KGB break inst
 * and we handle the normal undef case within the do_undefinstr
 * handler.
 */
struct kgdb_arch arch_kgdb_ops = {
	.gdb_bpt_instr		= {0x00, 0x00, 0x20, 0xd4}
};

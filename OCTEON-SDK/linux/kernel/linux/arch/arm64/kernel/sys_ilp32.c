/*
 * AArch64- ILP32 specific system calls implementation
 *
 * Copyright (C) 2013 Cavium Inc.
 * Author: Andrew Pinski <apinski@cavium.com>
 *
 * This program is free software; you can redistribute it and/or modify
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

#include <linux/compat.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/statfs.h>
#include <linux/futex.h>

/*
 * Wrappers to pass the pt_regs argument.
 */
#define sys_rt_sigreturn sys_ilp32_rt_sigreturn_wrapper

#include <asm/syscalls.h>

#ifndef __AARCH64EB__
#define __LONG_LONG_PAIR(HI,LO) LO,HI
#else
#define __LONG_LONG_PAIR(HI,LO) HI,LO
#endif



/* Using Compat syscalls where necessary */
#define sys_ioctl		compat_sys_ioctl
#define sys_readv		compat_sys_readv
#define sys_writev		compat_sys_writev
#define sys_preadv		compat_sys_preadv
#define sys_pwritev		compat_sys_pwritev
#define sys_vmsplice		compat_sys_vmsplice
#define sys_waitid		compat_sys_waitid
#define sys_set_robust_list	compat_sys_set_robust_list
#define sys_get_robust_list	compat_sys_get_robust_list
#define sys_kexec_load		compat_sys_kexec_load
#define sys_timer_create	compat_sys_timer_create
#define sys_ptrace		compat_sys_ptrace
#define sys_sigaltstack		compat_sys_sigaltstack
#define sys_rt_sigaction	compat_sys_rt_sigaction
#define sys_rt_sigpending	compat_sys_rt_sigpending
#define sys_rt_sigtimedwait	compat_sys_rt_sigtimedwait
#define sys_rt_sigqueueinfo	compat_sys_rt_sigqueueinfo
#define sys_mq_notify		compat_sys_mq_notify
#define sys_recvfrom		compat_sys_recvfrom
#define sys_setsockopt		compat_sys_setsockopt
#define sys_getsockopt		compat_sys_getsockopt
#define sys_sendmsg		compat_sys_sendmsg
#define sys_recvmsg		compat_sys_recvmsg
#define sys_execve		compat_sys_execve
#define sys_move_pages		compat_sys_move_pages
#define sys_rt_tgsigqueueinfo	compat_sys_rt_tgsigqueueinfo
#define sys_recvmmsg		compat_sys_recvmmsg
#define sys_sendmmsg		compat_sys_sendmmsg
#define sys_process_vm_readv	compat_sys_process_vm_readv
#define sys_process_vm_writev	compat_sys_process_vm_writev
#define sys_lookup_dcookie	compat_sys_lookup_dcookie



#define sys_io_setup		compat_sys_io_setup
#define sys_io_submit           compat_sys_io_submit
#define sys_fcntl64             compat_sys_fcntl64
#define sys_mount               compat_sys_mount
#define sys_getdents64          compat_sys_getdents64
#define sys_signalfd4           compat_sys_signalfd4
#define sys_sched_setaffinity   compat_sys_sched_setaffinity
#define sys_sched_getaffinity   compat_sys_sched_getaffinity
#define sys_rt_sigssuspend      compat_sys_rt_sigssuspend
#define sys_rt_sigprocmask      compat_sys_rt_sigprocmask
#define sys_getrlimit           compat_sys_getrlimit
#define sys_setrlimit           compat_sys_setrlimit
#define sys_msgrcv              compat_sys_msgrcv
#define sys_msgsnd              compat_sys_msgsnd
#define sys_semtimedop          compat_sys_semtimedop
#define sys_keyctl              compat_sys_keyctl
#define sys_mbind               compat_sys_mbind
#define sys_get_mempolicy       compat_sys_get_mempolicy
#define sys_set_mempolicy       compat_sys_set_mempolicy
#define sys_migrate_pages       compat_sys_migrate_pages
#define sys_open_by_handle_at   compat_sys_open_by_handle_at
#define sys_lseek		sys_llseek
#define sys_newstat		sys_stat64
#define sys_newlstat		sys_lstat64
#define sys_epoll_pwait		compat_sys_epoll_pwait
#define sys_openat		compat_sys_openat
#define sys_waitd		compat_sys_waitd
#define sys_rt_sigsuspend	compat_sys_rt_sigsuspend
#define sys_rt_sigprocmask	compat_sys_rt_sigprocmask
#define sys_fcntl		compat_sys_fcntl64

asmlinkage long ilp32_statfs64(const char __user *pathname, compat_size_t sz, struct statfs __user *buf)
{
	int error;
	if (sz != sizeof(*buf))
		return -EINVAL;
	error = sys_statfs(pathname, buf);
	return error;
}

asmlinkage long ilp32_fstatfs64(unsigned int fd, compat_size_t sz, struct statfs __user *buf)
{
	int error;
	if (sz != sizeof(*buf))
		return -EINVAL;
	error = sys_fstatfs(fd, buf);
	return error;
}

asmlinkage long ilp32_fallocate(int fd, int mode, __LONG_LONG_PAIR(u32 offset_hi, u32 offset_lo), __LONG_LONG_PAIR(u32 len_hi, u32 len_lo))
{
	return sys_fallocate(fd, mode, ((loff_t)offset_hi << 32) | offset_lo,
			     ((loff_t)len_hi << 32) | len_lo);
}

asmlinkage long ilp32_fadvise64_64(int fd,
				   __LONG_LONG_PAIR(unsigned long offhi, unsigned long offlo),
				   __LONG_LONG_PAIR(unsigned long lenhi, unsigned long lenlo),
				   int advice)
{
	return sys_fadvise64_64(fd,
				(offhi << 32) | offlo,
				(lenhi << 32) | lenlo,
				advice);
}

asmlinkage int ilp32_truncate64(const char __user * path,
				__LONG_LONG_PAIR(unsigned long high, unsigned long low))
{
	return sys_truncate(path, (high << 32) | low);
}

asmlinkage int ilp32_ftruncate64(unsigned int fd, __LONG_LONG_PAIR(unsigned long high,
				 unsigned long low))
{
	return sys_ftruncate(fd, (high << 32) | low);
}

compat_ssize_t ilp32_pread64(unsigned int fd, char __user *ubuf, compat_size_t count,
			      __LONG_LONG_PAIR(u32 poshi, u32 poslo))
{
	return sys_pread64(fd, ubuf, count, ((loff_t)poshi << 32) | poslo);
}

compat_ssize_t ilp32_pwrite64(unsigned int fd, const char __user *ubuf, compat_size_t count,
			       __LONG_LONG_PAIR(u32 poshi, u32 poslo))
{
	return sys_pwrite64(fd, ubuf, count, ((loff_t)poshi << 32) | poslo);
}

asmlinkage long ilp32_sync_file_range(int fd, 
				   __LONG_LONG_PAIR(unsigned offset_hi, unsigned offset_lo),
				   __LONG_LONG_PAIR(unsigned nbytes_hi, unsigned nbytes_lo),
				   unsigned int flags)
{
	loff_t offset = ((loff_t)offset_hi << 32) | offset_lo;
	loff_t nbytes = ((loff_t)nbytes_hi << 32) | nbytes_lo;

	return sys_sync_file_range(fd, offset, nbytes, flags);
}

asmlinkage long ilp32_sync_file_range2(int fd, unsigned int flags,
                       __LONG_LONG_PAIR(u32 offset_hi, u32 offset_lo),
                       __LONG_LONG_PAIR(u32 nbytes_hi, u32 nbytes_lo))
{
	loff_t offset = ((loff_t)offset_hi << 32) | offset_lo;
	loff_t nbytes = ((loff_t)nbytes_hi << 32) | nbytes_lo;

	return sys_sync_file_range(fd, offset, nbytes, flags);
	
}

compat_ssize_t ilp32_readahead(int fd, u32 r4, __LONG_LONG_PAIR(u32 offhi, u32 offlo), u32 count)
{
	return sys_readahead(fd, ((loff_t)offhi << 32) | offlo, count);
}

compat_int_t ilp32_futex(u32 __user *uaddr, int op, u32 val,
		struct timespec __user *utime, u32 __user *uaddr2,
		u32 val3)
{
	struct timespec ts;
	ktime_t t, *tp = NULL;
	int val2 = 0;
	int cmd = op & FUTEX_CMD_MASK;

	if (utime && (cmd == FUTEX_WAIT || cmd == FUTEX_LOCK_PI ||
		      cmd == FUTEX_WAIT_BITSET ||
		      cmd == FUTEX_WAIT_REQUEUE_PI)) {
		if (copy_from_user(&ts, utime, sizeof(ts)) != 0)
			return -EFAULT;
		if (!timespec_valid(&ts))
			return -EINVAL;

		t = timespec_to_ktime(ts);
		if (cmd == FUTEX_WAIT)
			t = ktime_add_safe(ktime_get(), t);
		tp = &t;
	}
	if (cmd == FUTEX_REQUEUE || cmd == FUTEX_CMP_REQUEUE ||
	    cmd == FUTEX_CMP_REQUEUE_PI || cmd == FUTEX_WAKE_OP)
		val2 = (int) (unsigned long) utime;

	return do_futex(uaddr, op, val, tp, uaddr2, val2, val3);
}

/*
 * This is a virtual copy of sys_select from fs/select.c and probably
 * should be compared to it from time to time
 */

extern int compat_core_sys_select(int n, compat_ulong_t __user *inp,
				  compat_ulong_t __user *outp, compat_ulong_t __user *exp,
				  struct timespec *end_time);

extern int poll_select_copy_remaining(struct timespec *end_time, void __user *p,
			      	      int timeval, int ret);

static long do_compat_pselect(int n, compat_ulong_t __user *inp,
	compat_ulong_t __user *outp, compat_ulong_t __user *exp,
	struct timespec __user *tsp, sigset_t __user *sigmask,
	compat_size_t sigsetsize)
{
	sigset_t ksigmask, sigsaved;
	struct timespec ts, end_time, *to = NULL;
	int ret;

	if (tsp) {
		if (copy_from_user(&ts, tsp, sizeof(ts)))
			return -EFAULT;

		to = &end_time;
		if (poll_select_set_timeout(to, ts.tv_sec, ts.tv_nsec))
			return -EINVAL;
	}

	if (sigmask) {
		if (sigsetsize != sizeof(sigset_t))
			return -EINVAL;
		if (copy_from_user(&ksigmask, sigmask, sizeof(ksigmask)))
			return -EFAULT;

		sigdelsetmask(&ksigmask, sigmask(SIGKILL)|sigmask(SIGSTOP));
		sigprocmask(SIG_SETMASK, &ksigmask, &sigsaved);
	}

	ret = compat_core_sys_select(n, inp, outp, exp, to);
	ret = poll_select_copy_remaining(&end_time, tsp, 0, ret);

	if (ret == -ERESTARTNOHAND) {
		/*
		 * Don't restore the signal mask yet. Let do_signal() deliver
		 * the signal on the way back to userspace, before the signal
		 * mask is restored.
		 */
		if (sigmask) {
			memcpy(&current->saved_sigmask, &sigsaved,
					sizeof(sigsaved));
			set_restore_sigmask();
		}
	} else if (sigmask)
		sigprocmask(SIG_SETMASK, &sigsaved, NULL);

	return ret;
}

asmlinkage long ilp32_sys_pselect6(int n, compat_ulong_t __user *inp,
	compat_ulong_t __user *outp, compat_ulong_t __user *exp,
	struct timespec __user *tsp, void __user *sig)
{
	compat_size_t sigsetsize = 0;
	compat_uptr_t up = 0;

	if (sig) {
		if (!access_ok(VERIFY_READ, sig,
				sizeof(compat_uptr_t)+sizeof(compat_size_t)) ||
		    	__get_user(up, (compat_uptr_t __user *)sig) ||
		    	__get_user(sigsetsize,
				(compat_size_t __user *)(sig+sizeof(up))))
			return -EFAULT;
	}
	return do_compat_pselect(n, inp, outp, exp, tsp, compat_ptr(up),
				 sigsetsize);
}

/* These system calls all split their 64bit arguments into high/low parts. */
#define sys_ftruncate ilp32_ftruncate64
#define sys_truncate ilp32_truncate64
#define sys_pread64 ilp32_pread64
#define sys_pwrite64 ilp32_pwrite64
#define sys_sync_file_range ilp32_sync_file_range
#define sys_sync_file_range2 ilp32_sync_file_range2
#define sys_readahead ilp32_readahead
#define sys_statfs ilp32_statfs64
#define sys_fstatfs ilp32_fstatfs64
#define sys_fallocate ilp32_fallocate
#define sys_fadvise64_64 ilp32_fadvise64_64

#define sys_mmap sys_mmap_pgoff

/* futex uses 32-bit pointers but 64-bit time values */
#define sys_futex ilp32_futex
/* pselect is special as we have both compat ulong and native timespec. */
#define sys_pselect6 ilp32_sys_pselect6



#undef __SYSCALL
#define __SYSCALL(nr, sym)	[nr] = sym,

/*
 * The sys_call_table array must be 4K aligned to be accessible from
 * kernel/entry.S.
 */
void *sys_ilp32_call_table[__NR_syscalls] __aligned(4096) = {
	[0 ... __NR_syscalls - 1] = sys_ni_syscall,
#include <asm/unistd.h>
};

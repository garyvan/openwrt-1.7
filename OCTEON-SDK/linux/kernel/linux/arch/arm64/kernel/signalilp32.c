
#ifdef CONFIG_COMPAT

#define rt_sigframe rt_sigframe_ilp32
#define restore_sigframe restore_sigframe_ilp32
#define sys_rt_sigreturn sys_ilp32_rt_sigreturn
#define restore_altstack compat_restore_altstack
#define setup_sigframe setup_sigframe_ilp32
#define get_sigframe get_sigframe_ilp32
#define setup_return setup_return_ilp32
#define setup_rt_frame setup_rt_frame_ilp32
#define __save_altstack __compat_save_altstack
#define copy_siginfo_to_user copy_siginfo_to_user32
#define ilp32

#include "signal_template.c"

#undef rt_sigframe
#undef restore_sigframe
#undef sys_rt_sigreturn
#undef restore_altstack
#undef setup_sigframe
#undef get_sigframe
#undef setup_return
#undef setup_rt_frame
#undef __save_altstack
#undef copy_siginfo_to_user
#undef ilp32

#endif

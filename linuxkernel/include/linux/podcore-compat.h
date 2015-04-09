#ifndef _LINUX_PODCORE_COMPAT_H
#define _LINUX_PODCORE_COMPAT_H

#include <linux/pod.h>
#include <linux/podcore.h>
#include <linux/compat.h>

/*
 * Make sure these layouts match the linux/podcore.h native definitions.
 */

struct compat_pod_siginfo
{
	compat_int_t			si_signo;
	compat_int_t			si_code;
	compat_int_t			si_errno;
};

struct compat_pod_prstatus
{
	struct compat_pod_siginfo	pr_info;
	short				pr_cursig;
	compat_ulong_t			pr_sigpend;
	compat_ulong_t			pr_sighold;
	compat_pid_t			pr_pid;
	compat_pid_t			pr_ppid;
	compat_pid_t			pr_pgrp;
	compat_pid_t			pr_sid;
	struct compat_timeval		pr_utime;
	struct compat_timeval		pr_stime;
	struct compat_timeval		pr_cutime;
	struct compat_timeval		pr_cstime;
	compat_pod_gregset_t		pr_reg;
#ifdef CONFIG_BINFMT_POD_FDPIC
	compat_ulong_t			pr_exec_fdpic_loadmap;
	compat_ulong_t			pr_interp_fdpic_loadmap;
#endif
	compat_int_t			pr_fpvalid;
};

struct compat_pod_prpsinfo
{
	char				pr_state;
	char				pr_sname;
	char				pr_zomb;
	char				pr_nice;
	compat_ulong_t			pr_flag;
	__compat_uid_t			pr_uid;
	__compat_gid_t			pr_gid;
	compat_pid_t			pr_pid, pr_ppid, pr_pgrp, pr_sid;
	char				pr_fname[16];
	char				pr_psargs[POD_PRARGSZ];
};

#endif /* _LINUX_PODCORE_COMPAT_H */

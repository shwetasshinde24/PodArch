/*
 *  Created on: 10 Oct, 2013
 *  Author: Shweta
 *
 * 	linux/fs/binfmt_pod.c
 *
 * 	These are the functions used to load pod format executables as used
 * 	by PodArch.
 *
 */

#include <linux/podcore-compat.h>
#include <linux/time.h>

/*
 * Rename the basic POD layout types to refer to the 32-bit class of files.
 */
#undef	POD_CLASS
#define POD_CLASS	PODCLASS32

#undef	podhdr
#undef	pod_phdr
#undef	pod_shdr
#undef	pod_note
#undef	pod_addr_t
#define podhdr		pod32_hdr
#define pod_phdr	pod32_phdr
#define pod_shdr	pod32_shdr
#define pod_note	pod32_note
#define pod_addr_t	Pod32_Addr

/*
 * The machine-dependent core note format types are defined in podcore-compat.h,
 * which requires asm/pod.h to define compat_pod_gregset_t et al.
 */
#define pod_prstatus	compat_pod_prstatus
#define pod_prpsinfo	compat_pod_prpsinfo

/*
 * Compat version of cputime_to_compat_timeval, perhaps this
 * should be an inline in <linux/compat.h>.
 */
static void cputime_to_compat_timeval(const cputime_t cputime,
				      struct compat_timeval *value)
{
	struct timeval tv;
	cputime_to_timeval(cputime, &tv);
	value->tv_sec = tv.tv_sec;
	value->tv_usec = tv.tv_usec;
}

#undef cputime_to_timeval
#define cputime_to_timeval cputime_to_compat_timeval


/*
 * To use this file, asm/pod.h must define compat_pod_check_arch.
 * The other following macros can be defined if the compat versions
 * differ from the native ones, or omitted when they match.
 */

#undef	POD_ARCH
#undef	pod_check_arch
#define	pod_check_arch	compat_pod_check_arch

#ifdef	COMPAT_POD_PLATFORM
#undef	POD_PLATFORM
#define	POD_PLATFORM		COMPAT_POD_PLATFORM
#endif

#ifdef	COMPAT_POD_HWCAP
#undef	POD_HWCAP
#define	POD_HWCAP		COMPAT_POD_HWCAP
#endif

/*
#ifdef	COMPAT_ARCH_DLINFO
#undef	ARCH_DLINFO
#define	ARCH_DLINFO		COMPAT_ARCH_DLINFO
#endif
*/

#ifdef	COMPAT_POD_ET_DYN_BASE
#undef	POD_ET_DYN_BASE
#define	POD_ET_DYN_BASE		COMPAT_POD_ET_DYN_BASE
#endif

#ifdef COMPAT_POD_EXEC_PAGESIZE
#undef	POD_EXEC_PAGESIZE
#define	POD_EXEC_PAGESIZE	COMPAT_POD_EXEC_PAGESIZE
#endif

#ifdef	COMPAT_POD_PLAT_INIT
#undef	POD_PLAT_INIT
#define	POD_PLAT_INIT		COMPAT_POD_PLAT_INIT
#endif

/*
#ifdef	COMPAT_SET_PERSONALITY
#undef	SET_PERSONALITY
#define	SET_PERSONALITY		COMPAT_SET_PERSONALITY
#endif
*/

#ifdef	compat_start_thread
#undef	start_thread
#define	start_thread		compat_start_thread
#endif

#ifdef	compat_arch_setup_additional_pages
#undef	ARCH_HAS_SETUP_ADDITIONAL_PAGES
#define ARCH_HAS_SETUP_ADDITIONAL_PAGES 1
#undef	arch_setup_additional_pages
#define	arch_setup_additional_pages compat_arch_setup_additional_pages
#endif

/*
 * Rename a few of the symbols that binfmt_pod.c will define.
 * These are all local so the names don't really matter, but it
 * might make some debugging less confusing not to duplicate them.
 */
#define pod_format		compat_pod_format
#define init_pod_binfmt		init_compat_pod_binfmt
#define exit_pod_binfmt		exit_compat_pod_binfmt

/*
 * We share all the actual code with the native (64-bit) version.
 */
#include "binfmt_pod.c"

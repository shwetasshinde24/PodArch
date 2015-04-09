/* pod-fdpic.h: FDPIC POD load map
 *
 * Copyright (C) 2003 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _LINUX_POD_FDPIC_H
#define _LINUX_POD_FDPIC_H

#include <linux/pod.h>

#define PT_GNU_STACK    (PT_LOOS + 0x474e551)

/* segment mappings for POD FDPIC libraries/executables/interpreters */
struct pod32_fdpic_loadseg {
	Pod32_Addr	addr;		/* core address to which mapped */
	Pod32_Addr	p_vaddr;	/* VMA recorded in file */
	Pod32_Word	p_memsz;	/* allocation size recorded in file */
};

struct pod32_fdpic_loadmap {
	Pod32_Half	version;	/* version of these structures, just in case... */
	Pod32_Half	nsegs;		/* number of segments */
	struct pod32_fdpic_loadseg segs[];
};

#define POD32_FDPIC_LOADMAP_VERSION	0x0000

/*
 * binfmt binary parameters structure
 */
struct pod_fdpic_params {
	struct podhdr			hdr;		/* ref copy of POD header */
	struct pod_phdr			*phdrs;		/* ref copy of PT_PHDR table */
	struct pod32_fdpic_loadmap	*loadmap;	/* loadmap to be passed to userspace */
	unsigned long			podhdr_addr;	/* mapped POD header user address */
	unsigned long			ph_addr;	/* mapped PT_PHDR user address */
	unsigned long			map_addr;	/* mapped loadmap user address */
	unsigned long			entry_addr;	/* mapped entry user address */
	unsigned long			stack_size;	/* stack size requested (PT_GNU_STACK) */
	unsigned long			dynamic_addr;	/* mapped PT_DYNAMIC user address */
	unsigned long			load_addr;	/* user address at which to map binary */
	unsigned long			flags;
#define POD_FDPIC_FLAG_ARRANGEMENT	0x0000000f	/* PT_LOAD arrangement flags */
#define POD_FDPIC_FLAG_INDEPENDENT	0x00000000	/* PT_LOADs can be put anywhere */
#define POD_FDPIC_FLAG_HONOURVADDR	0x00000001	/* PT_LOAD.vaddr must be honoured */
#define POD_FDPIC_FLAG_CONSTDISP	0x00000002	/* PT_LOADs require constant
							 * displacement */
#define POD_FDPIC_FLAG_CONTIGUOUS	0x00000003	/* PT_LOADs should be contiguous */
#define POD_FDPIC_FLAG_EXEC_STACK	0x00000010	/* T if stack to be executable */
#define POD_FDPIC_FLAG_NOEXEC_STACK	0x00000020	/* T if stack not to be executable */
#define POD_FDPIC_FLAG_EXECUTABLE	0x00000040	/* T if this object is the executable */
#define POD_FDPIC_FLAG_PRESENT		0x80000000	/* T if this object is present */
};

#ifdef __KERNEL__
#ifdef CONFIG_MMU
extern void pod_fdpic_arch_lay_out_mm(struct pod_fdpic_params *exec_params,
				      struct pod_fdpic_params *interp_params,
				      unsigned long *start_stack,
				      unsigned long *start_brk);
#endif
#endif /* __KERNEL__ */

#endif /* _LINUX_POD_FDPIC_H */

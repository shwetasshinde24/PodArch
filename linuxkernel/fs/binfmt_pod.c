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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/binfmts.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/personality.h>
#include <linux/podcore.h>
#include <linux/init.h>
#include <linux/highuid.h>
#include <linux/compiler.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/security.h>
#include <linux/random.h>
#include <linux/pod.h>
#include <linux/utsname.h>
#include <linux/coredump.h>
#include <asm/uaccess.h>
#include <asm/param.h>
#include <asm/page.h>
static int load_pod_binary(struct linux_binprm *bprm, struct pt_regs *regs);
static int load_pod_library(struct file *);
static unsigned long pod_map(struct file *, unsigned long, struct pod_phdr *,
				int, int, unsigned long);

/*
 * If we don't support core dumping, then supply a NULL so we
 * don't even try.
 */
#ifdef CONFIG_POD_CORE
static int pod_core_dump(struct coredump_params *cprm);
#else
#define pod_core_dump	NULL
#endif

#if POD_EXEC_PAGESIZE > PAGE_SIZE
#define POD_MIN_ALIGN	POD_EXEC_PAGESIZE
#else
#define POD_MIN_ALIGN	PAGE_SIZE
#endif

#ifndef POD_CORE_EFLAGS
#define POD_CORE_EFLAGS	0
#endif

#define POD_PAGESTART(_v) ((_v) & ~(unsigned long)(POD_MIN_ALIGN-1))
#define POD_PAGEOFFSET(_v) ((_v) & (POD_MIN_ALIGN-1))
#define POD_PAGEALIGN(_v) (((_v) + POD_MIN_ALIGN - 1) & ~(POD_MIN_ALIGN - 1))

static struct linux_binfmt pod_format = {
	.module		= THIS_MODULE,
	.load_binary	= load_pod_binary,
	.load_shlib	= load_pod_library,
	.core_dump	= pod_core_dump,
	.min_coredump	= POD_EXEC_PAGESIZE,
};

#define BAD_ADDR(x) ((unsigned long)(x) >= TASK_SIZE)

static int set_brk(unsigned long start, unsigned long end)
{
	start = POD_PAGEALIGN(start);
	end = POD_PAGEALIGN(end);
	if (end > start) {
		unsigned long addr;
		down_write(&current->mm->mmap_sem);
		addr = do_brk(start, end - start);
		up_write(&current->mm->mmap_sem);
		if (BAD_ADDR(addr))
			return addr;
	}
	current->mm->start_brk = current->mm->brk = end;
	return 0;
}

/* We need to explicitly zero any fractional pages
   after the data section (i.e. bss).  This would
   contain the junk from the file that should not
   be in memory
 */
static int padzero(unsigned long pod_bss)
{
	unsigned long nbyte;

	nbyte = POD_PAGEOFFSET(pod_bss);
	if (nbyte) {
		nbyte = POD_MIN_ALIGN - nbyte;
		if (clear_user((void __user *) pod_bss, nbyte))
			return -EFAULT;
	}
	return 0;
}

/* Let's use some macros to make this stack manipulation a little clearer */
#ifdef CONFIG_STACK_GROWSUP
#define STACK_ADD(sp, items) ((pod_addr_t __user *)(sp) + (items))
#define STACK_ROUND(sp, items) \
	((15 + (unsigned long) ((sp) + (items))) &~ 15UL)
#define STACK_ALLOC(sp, len) ({ \
	pod_addr_t __user *old_sp = (pod_addr_t __user *)sp; sp += len; \
	old_sp; })
#else
#define STACK_ADD(sp, items) ((pod_addr_t __user *)(sp) - (items))
#define STACK_ROUND(sp, items) \
	(((unsigned long) (sp - items)) &~ 15UL)
#define STACK_ALLOC(sp, len) ({ sp -= len ; sp; })
#endif

#ifndef POD_BASE_PLATFORM
/*
 * AT_BASE_PLATFORM indicates the "real" hardware/microarchitecture.
 * If the arch defines POD_BASE_PLATFORM (in asm/pod.h), the value
 * will be copied to the user stack in the same manner as AT_PLATFORM.
 */
#define POD_BASE_PLATFORM NULL
#endif

static int
create_pod_tables(struct linux_binprm *bprm, struct podhdr *exec,
		unsigned long load_addr, unsigned long interp_load_addr)
{
	unsigned long p = bprm->p;
	int argc = bprm->argc;
	int envc = bprm->envc;
	pod_addr_t __user *argv;
	pod_addr_t __user *envp;
	pod_addr_t __user *sp;
	pod_addr_t __user *u_platform;
	pod_addr_t __user *u_base_platform;
	pod_addr_t __user *u_rand_bytes;
	const char *k_platform = POD_PLATFORM;
	const char *k_base_platform = POD_BASE_PLATFORM;
	unsigned char k_rand_bytes[16];
	int items;
	pod_addr_t *pod_info;
	int ei_index = 0;
	const struct cred *cred = current_cred();
	struct vm_area_struct *vma;

	/*
	 * In some cases (e.g. Hyper-Threading), we want to avoid L1
	 * evictions by the processes running on the same package. One
	 * thing we can do is to shuffle the initial stack for them.
	 */

	p = arch_align_stack(p);

	/*
	 * If this architecture has a platform capability string, copy it
	 * to userspace.  In some cases (Sparc), this info is impossible
	 * for userspace to get any other way, in others (i386) it is
	 * merely difficult.
	 */
	u_platform = NULL;
	if (k_platform) {
		size_t len = strlen(k_platform) + 1;

		u_platform = (pod_addr_t __user *)STACK_ALLOC(p, len);
		if (__copy_to_user(u_platform, k_platform, len))
			return -EFAULT;
	}

	/*
	 * If this architecture has a "base" platform capability
	 * string, copy it to userspace.
	 */
	u_base_platform = NULL;
	if (k_base_platform) {
		size_t len = strlen(k_base_platform) + 1;

		u_base_platform = (pod_addr_t __user *)STACK_ALLOC(p, len);
		if (__copy_to_user(u_base_platform, k_base_platform, len))
			return -EFAULT;
	}

	/*
	 * Generate 16 random bytes for userspace PRNG seeding.
	 */
	get_random_bytes(k_rand_bytes, sizeof(k_rand_bytes));
	u_rand_bytes = (pod_addr_t __user *)
		       STACK_ALLOC(p, sizeof(k_rand_bytes));
	if (__copy_to_user(u_rand_bytes, k_rand_bytes, sizeof(k_rand_bytes)))
		return -EFAULT;

	/* Create the POD interpreter info */
	pod_info = (pod_addr_t *)current->mm->saved_auxv;
	/* update AT_VECTOR_SIZE_BASE if the number of NEW_AUX_ENT() changes */
#define NEW_AUX_ENT(id, val) \
	do { \
		pod_info[ei_index++] = id; \
		pod_info[ei_index++] = val; \
	} while (0)

#ifdef ARCH_DLINFO
	/* 
	 * ARCH_DLINFO must come first so PPC can do its special alignment of
	 * AUXV.
	 * update AT_VECTOR_SIZE_ARCH if the number of NEW_AUX_ENT() in
	 * ARCH_DLINFO changes
	 */
	ARCH_DLINFO;
#endif
	NEW_AUX_ENT(AT_HWCAP, POD_HWCAP);
	NEW_AUX_ENT(AT_PAGESZ, POD_EXEC_PAGESIZE);
	NEW_AUX_ENT(AT_CLKTCK, CLOCKS_PER_SEC);
	NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
	NEW_AUX_ENT(AT_PHENT, sizeof(struct pod_phdr));
	NEW_AUX_ENT(AT_PHNUM, exec->e_phnum);
	NEW_AUX_ENT(AT_BASE, interp_load_addr);
	NEW_AUX_ENT(AT_FLAGS, 0);
	NEW_AUX_ENT(AT_ENTRY, exec->e_entry);
	NEW_AUX_ENT(AT_UID, cred->uid);
	NEW_AUX_ENT(AT_EUID, cred->euid);
	NEW_AUX_ENT(AT_GID, cred->gid);
	NEW_AUX_ENT(AT_EGID, cred->egid);
 	NEW_AUX_ENT(AT_SECURE, security_bprm_secureexec(bprm));
	NEW_AUX_ENT(AT_RANDOM, (pod_addr_t)(unsigned long)u_rand_bytes);
	NEW_AUX_ENT(AT_EXECFN, bprm->exec);
	if (k_platform) {
		NEW_AUX_ENT(AT_PLATFORM,
			    (pod_addr_t)(unsigned long)u_platform);
	}
	if (k_base_platform) {
		NEW_AUX_ENT(AT_BASE_PLATFORM,
			    (pod_addr_t)(unsigned long)u_base_platform);
	}
	if (bprm->interp_flags & BINPRM_FLAGS_EXECFD) {
		NEW_AUX_ENT(AT_EXECFD, bprm->interp_data);
	}
#undef NEW_AUX_ENT
	/* AT_NULL is zero; clear the rest too */
	memset(&pod_info[ei_index], 0,
	       sizeof current->mm->saved_auxv - ei_index * sizeof pod_info[0]);

	/* And advance past the AT_NULL entry.  */
	ei_index += 2;

	sp = STACK_ADD(p, ei_index);

	items = (argc + 1) + (envc + 1) + 1;
	bprm->p = STACK_ROUND(sp, items);

	/* Point sp at the lowest address on the stack */
#ifdef CONFIG_STACK_GROWSUP
	sp = (pod_addr_t __user *)bprm->p - items - ei_index;
	bprm->exec = (unsigned long)sp; /* XXX: PARISC HACK */
#else
	sp = (pod_addr_t __user *)bprm->p;
#endif


	/*
	 * Grow the stack manually; some architectures have a limit on how
	 * far ahead a user-space access may be in order to grow the stack.
	 */
	vma = find_extend_vma(current->mm, bprm->p);
	if (!vma)
		return -EFAULT;

	/* Now, let's put argc (and argv, envp if appropriate) on the stack */
	if (__put_user(argc, sp++))
		return -EFAULT;
	argv = sp;
	envp = argv + argc + 1;

	/* Populate argv and envp */
	p = current->mm->arg_end = current->mm->arg_start;
	while (argc-- > 0) {
		size_t len;
		if (__put_user((pod_addr_t)p, argv++))
			return -EFAULT;
		len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		if (!len || len > MAX_ARG_STRLEN)
			return -EINVAL;
		p += len;
	}
	if (__put_user(0, argv))
		return -EFAULT;
	current->mm->arg_end = current->mm->env_start = p;
	while (envc-- > 0) {
		size_t len;
		if (__put_user((pod_addr_t)p, envp++))
			return -EFAULT;
		len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		if (!len || len > MAX_ARG_STRLEN)
			return -EINVAL;
		p += len;
	}
	if (__put_user(0, envp))
		return -EFAULT;
	current->mm->env_end = p;

	/* Put the pod_info on the stack in the right place.  */
	sp = (pod_addr_t __user *)envp + 1;
	if (copy_to_user(sp, pod_info, ei_index * sizeof(pod_addr_t)))
		return -EFAULT;
	return 0;
}

static unsigned long pod_map(struct file *filep, unsigned long addr,
		struct pod_phdr *eppnt, int prot, int type,
		unsigned long total_size)
{
	unsigned long map_addr;
	unsigned long size = eppnt->p_filesz + POD_PAGEOFFSET(eppnt->p_vaddr);
	unsigned long off = eppnt->p_offset - POD_PAGEOFFSET(eppnt->p_vaddr);
	addr = POD_PAGESTART(addr);
	size = POD_PAGEALIGN(size);

	/* mmap() will return -EINVAL if given a zero size, but a
	 * segment with zero filesize is perfectly valid */
	if (!size)
		return addr;

	down_write(&current->mm->mmap_sem);
	/*
	* total_size is the size of the POD (interpreter) image.
	* The _first_ mmap needs to know the full size, otherwise
	* randomization might put this image into an overlapping
	* position with the POD binary image. (since size < total_size)
	* So we first map the 'big' image - and unmap the remainder at
	* the end. (which unmap is needed for POD images with holes.)
	*/
	if (total_size) {
		total_size = POD_PAGEALIGN(total_size);
		map_addr = do_mmap(filep, addr, total_size, prot, type, off);
		if (!BAD_ADDR(map_addr))
			do_munmap(current->mm, map_addr+size, total_size-size);
	} else
		map_addr = do_mmap(filep, addr, size, prot, type, off);

	up_write(&current->mm->mmap_sem);
	return(map_addr);
}

static unsigned long total_mapping_size(struct pod_phdr *cmds, int nr)
{
	int i, first_idx = -1, last_idx = -1;

	for (i = 0; i < nr; i++) {
		if (cmds[i].p_type == PT_LOAD) {
			last_idx = i;
			if (first_idx == -1)
				first_idx = i;
		}
	}
	if (first_idx == -1)
		return 0;

	return cmds[last_idx].p_vaddr + cmds[last_idx].p_memsz -
				POD_PAGESTART(cmds[first_idx].p_vaddr);
}


/* This is much more generalized than the library routine read function,
   so we keep this separate.  Technically the library read function
   is only provided so that we can read a.out libraries that have
   an POD header */

static unsigned long load_pod_interp(struct podhdr *interp_pod_ex,
		struct file *interpreter, unsigned long *interp_map_addr,
		unsigned long no_base)
{
	struct pod_phdr *pod_phdata;
	struct pod_phdr *eppnt;
	unsigned long load_addr = 0;
	int load_addr_set = 0;
	unsigned long last_bss = 0, pod_bss = 0;
	unsigned long error = ~0UL;
	unsigned long total_size;
	int retval, i, size;

	/* First of all, some simple consistency checks */
	if (interp_pod_ex->e_type != ET_EXEC &&
	    interp_pod_ex->e_type != ET_DYN)
		goto out;
	if (!pod_check_arch(interp_pod_ex))
		goto out;
	if (!interpreter->f_op || !interpreter->f_op->mmap)
		goto out;

	/*
	 * If the size of this structure has changed, then punt, since
	 * we will be doing the wrong thing.
	 */
	if (interp_pod_ex->e_phentsize != sizeof(struct pod_phdr))
		goto out;
	if (interp_pod_ex->e_phnum < 1 ||
		interp_pod_ex->e_phnum > 65536U / sizeof(struct pod_phdr))
		goto out;

	/* Now read in all of the header information */
	size = sizeof(struct pod_phdr) * interp_pod_ex->e_phnum;
	if (size > POD_MIN_ALIGN)
		goto out;
	pod_phdata = kmalloc(size, GFP_KERNEL);
	if (!pod_phdata)
		goto out;

	retval = kernel_read(interpreter, interp_pod_ex->e_phoff,
			     (char *)pod_phdata, size);
	error = -EIO;
	if (retval != size) {
		if (retval < 0)
			error = retval;	
		goto out_close;
	}

	total_size = total_mapping_size(pod_phdata, interp_pod_ex->e_phnum);
	if (!total_size) {
		error = -EINVAL;
		goto out_close;
	}

	eppnt = pod_phdata;
	for (i = 0; i < interp_pod_ex->e_phnum; i++, eppnt++) {
		if (eppnt->p_type == PT_LOAD) {
			int pod_type = MAP_PRIVATE | MAP_DENYWRITE;
			int pod_prot = 0;
			unsigned long vaddr = 0;
			unsigned long k, map_addr;

			if (eppnt->p_flags & PF_R)
		    		pod_prot = PROT_READ;
			if (eppnt->p_flags & PF_W)
				pod_prot |= PROT_WRITE;
			if (eppnt->p_flags & PF_X)
				pod_prot |= PROT_EXEC;
			vaddr = eppnt->p_vaddr;
			if (interp_pod_ex->e_type == ET_EXEC || load_addr_set)
				pod_type |= MAP_FIXED;
			else if (no_base && interp_pod_ex->e_type == ET_DYN)
				load_addr = -vaddr;

			map_addr = pod_map(interpreter, load_addr + vaddr,
					eppnt, pod_prot, pod_type, total_size);

			// SS++
		//	POD_ADD_VA(map_addr, podarch_podenter_flag);
			// SS--

			total_size = 0;
			if (!*interp_map_addr)
				*interp_map_addr = map_addr;
			error = map_addr;
			if (BAD_ADDR(map_addr))
				goto out_close;

			if (!load_addr_set &&
			    interp_pod_ex->e_type == ET_DYN) {
				load_addr = map_addr - POD_PAGESTART(vaddr);
				load_addr_set = 1;
			}

			/*
			 * Check to see if the section's size will overflow the
			 * allowed task size. Note that p_filesz must always be
			 * <= p_memsize so it's only necessary to check p_memsz.
			 */
			k = load_addr + eppnt->p_vaddr;
			if (BAD_ADDR(k) ||
			    eppnt->p_filesz > eppnt->p_memsz ||
			    eppnt->p_memsz > TASK_SIZE ||
			    TASK_SIZE - eppnt->p_memsz < k) {
				error = -ENOMEM;
				goto out_close;
			}

			/*
			 * Find the end of the file mapping for this phdr, and
			 * keep track of the largest address we see for this.
			 */
			k = load_addr + eppnt->p_vaddr + eppnt->p_filesz;
			if (k > pod_bss)
				pod_bss = k;

			/*
			 * Do the same thing for the memory mapping - between
			 * pod_bss and last_bss is the bss section.
			 */
			k = load_addr + eppnt->p_memsz + eppnt->p_vaddr;
			if (k > last_bss)
				last_bss = k;
		}
	}

	if (last_bss > pod_bss) {
		/*
		 * Now fill out the bss section.  First pad the last page up
		 * to the page boundary, and then perform a mmap to make sure
		 * that there are zero-mapped pages up to and including the
		 * last bss page.
		 */
		if (padzero(pod_bss)) {
			error = -EFAULT;
			goto out_close;
		}

		/* What we have mapped so far */
		pod_bss = POD_PAGESTART(pod_bss + POD_MIN_ALIGN - 1);

		/* Map the last of the bss segment */
		down_write(&current->mm->mmap_sem);
		error = do_brk(pod_bss, last_bss - pod_bss);
		up_write(&current->mm->mmap_sem);
		if (BAD_ADDR(error))
			goto out_close;
	}

	error = load_addr;

out_close:
	kfree(pod_phdata);
out:
	return error;
}

/*
 * These are the functions used to load POD style executables and shared
 * libraries.  There is no binary dependent code anywhere else.
 */

#define INTERPRETER_NONE 0
#define INTERPRETER_POD 2

#ifndef STACK_RND_MASK
#define STACK_RND_MASK (0x7ff >> (PAGE_SHIFT - 12))	/* 8MB of VA */
#endif

static unsigned long randomize_stack_top(unsigned long stack_top)
{
	unsigned int random_variable = 0;

	if ((current->flags & PF_RANDOMIZE) &&
		!(current->personality & ADDR_NO_RANDOMIZE)) {
		random_variable = get_random_int() & STACK_RND_MASK;
		random_variable <<= PAGE_SHIFT;
	}
#ifdef CONFIG_STACK_GROWSUP
	return PAGE_ALIGN(stack_top) + random_variable;
#else
	return PAGE_ALIGN(stack_top) - random_variable;
#endif
}

static int load_pod_binary(struct linux_binprm *bprm, struct pt_regs *regs)
{

	struct file *interpreter = NULL; /* to shut gcc up */
 	unsigned long load_addr = 0, load_bias = 0;
	int load_addr_set = 0;
	char * pod_interpreter = NULL;
	unsigned long error;
	struct pod_phdr *pod_ppnt, *pod_phdata;
	unsigned long pod_bss, pod_brk;
	int retval, i;
	unsigned int size;
	unsigned long pod_entry;
	unsigned long interp_load_addr = 0;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long reloc_func_desc __maybe_unused = 0;
	int executable_stack = EXSTACK_DEFAULT;
	unsigned long def_flags = 0;
	struct {
		struct podhdr pod_ex;
		struct podhdr interp_pod_ex;
	} *loc;

        // SS++
	printk("PodArch-BINFMT_POD: Loading file: %s\n", bprm->filename);
        // SS--

	loc = kmalloc(sizeof(*loc), GFP_KERNEL);
	if (!loc) {
		retval = -ENOMEM;
		goto out_ret;
	}
	
	/* Get the exec-header */
	loc->pod_ex = *((struct podhdr *)bprm->buf);

	retval = -ENOEXEC;
	/* First of all, some simple consistency checks */
	if (memcmp(loc->pod_ex.e_ident, PODMAG, SELFMAG) != 0)
		goto out;

	if (loc->pod_ex.e_type != ET_EXEC && loc->pod_ex.e_type != ET_DYN)
		goto out;
	if (!pod_check_arch(&loc->pod_ex))
		goto out;
	if (!bprm->file->f_op || !bprm->file->f_op->mmap)
		goto out;

	/* Now read in all of the header information */
	if (loc->pod_ex.e_phentsize != sizeof(struct pod_phdr))
		goto out;
	if (loc->pod_ex.e_phnum < 1 ||
	 	loc->pod_ex.e_phnum > 65536U / sizeof(struct pod_phdr))
		goto out;
	size = loc->pod_ex.e_phnum * sizeof(struct pod_phdr);
	retval = -ENOMEM;
	pod_phdata = kmalloc(size, GFP_KERNEL);
	if (!pod_phdata)
		goto out;

	retval = kernel_read(bprm->file, loc->pod_ex.e_phoff,
			     (char *)pod_phdata, size);
	if (retval != size) {
		if (retval >= 0)
			retval = -EIO;
		goto out_free_ph;
	}

	pod_ppnt = pod_phdata;
	pod_bss = 0;
	pod_brk = 0;

	start_code = ~0UL;
	end_code = 0;
	start_data = 0;
	end_data = 0;

	for (i = 0; i < loc->pod_ex.e_phnum; i++) {
		if (pod_ppnt->p_type == PT_INTERP) {
			/* This is the program interpreter used for
			 * shared libraries - for now assume that this
			 * is an a.out format binary
			 */
			retval = -ENOEXEC;
			if (pod_ppnt->p_filesz > PATH_MAX || 
			    pod_ppnt->p_filesz < 2)
				goto out_free_ph;

			retval = -ENOMEM;
			pod_interpreter = kmalloc(pod_ppnt->p_filesz,
						  GFP_KERNEL);
			if (!pod_interpreter)
				goto out_free_ph;

			retval = kernel_read(bprm->file, pod_ppnt->p_offset,
					     pod_interpreter,
					     pod_ppnt->p_filesz);
			if (retval != pod_ppnt->p_filesz) {
				if (retval >= 0)
					retval = -EIO;
				goto out_free_interp;
			}
			/* make sure path is NULL terminated */
			retval = -ENOEXEC;
			if (pod_interpreter[pod_ppnt->p_filesz - 1] != '\0')
				goto out_free_interp;

			interpreter = open_exec(pod_interpreter);
			retval = PTR_ERR(interpreter);
			if (IS_ERR(interpreter))
				goto out_free_interp;

			/*
			 * If the binary is not readable then enforce
			 * mm->dumpable = 0 regardless of the interpreter's
			 * permissions.
			 */
			would_dump(bprm, interpreter);

			retval = kernel_read(interpreter, 0, bprm->buf,
					     BINPRM_BUF_SIZE);
			if (retval != BINPRM_BUF_SIZE) {
				if (retval >= 0)
					retval = -EIO;
				goto out_free_dentry;
			}

			/* Get the exec headers */
			loc->interp_pod_ex = *((struct podhdr *)bprm->buf);
			break;
		}
		pod_ppnt++;
	}

	pod_ppnt = pod_phdata;
	for (i = 0; i < loc->pod_ex.e_phnum; i++, pod_ppnt++)
		if (pod_ppnt->p_type == PT_GNU_STACK) {
			if (pod_ppnt->p_flags & PF_X)
				executable_stack = EXSTACK_ENABLE_X;
			else
				executable_stack = EXSTACK_DISABLE_X;
			break;
		}

	pod_ppnt = pod_phdata;
	for (i = 0; i < loc->pod_ex.e_phnum; i++, pod_ppnt++){
		if (pod_ppnt->p_type == PT_LOAD) {
			if(pod_ppnt->p_filesz==pod_ppnt->p_memsz && pod_ppnt->p_filesz==256)
				printk("FOUND POD_IDENTITY\n");
			else
				printk("Inside PT_LOAD, but POD_IDENTITY NOT FOUND\n");
				
		}
	}



	


	/* Some simple consistency checks for the interpreter */
	if (pod_interpreter) {
		retval = -ELIBBAD;
		/* Not an POD interpreter */
		if (memcmp(loc->interp_pod_ex.e_ident, PODMAG, SELFMAG) != 0)
			goto out_free_dentry;
		/* Verify the interpreter has a valid arch */
		if (!pod_check_arch(&loc->interp_pod_ex))
			goto out_free_dentry;
	}

	/* Flush all traces of the currently running executable */
	retval = flush_old_exec(bprm);
	if (retval)
		goto out_free_dentry;

	/* OK, This is the point of no return */
	current->flags &= ~PF_FORKNOEXEC;
	current->mm->def_flags = def_flags;

	/* Do this immediately, since STACK_TOP as used in setup_arg_pages
	   may depend on the personality.  */
	SET_PERSONALITY(loc->pod_ex);
	if (pod_read_implies_exec(loc->pod_ex, executable_stack))
		current->personality |= READ_IMPLIES_EXEC;

	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		current->flags |= PF_RANDOMIZE;

	setup_new_exec(bprm);

	/* Do this so that we can load the interpreter, if need be.  We will
	   change some of these later */
	current->mm->free_area_cache = current->mm->mmap_base;
	current->mm->cached_hole_size = 0;
	retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
				 executable_stack);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto out_free_dentry;
	}
	
	current->mm->start_stack = bprm->p;

	/* Now we do a little grungy work by mmapping the POD image into
	   the correct location in memory. */

	// SS++
	//printk("\nmmaping memory in load_pod_binary"); // for %s(%s)", bprm->filename, bprm->interp);
	// SS--
	for(i = 0, pod_ppnt = pod_phdata;
	    i < loc->pod_ex.e_phnum; i++, pod_ppnt++) {
		int pod_prot = 0, pod_flags;
		unsigned long k, vaddr;

		if (pod_ppnt->p_type != PT_LOAD)
			continue;

		if (unlikely (pod_brk > pod_bss)) {
			unsigned long nbyte;
	            
			/* There was a PT_LOAD segment with p_memsz > p_filesz
			   before this one. Map anonymous pages, if needed,
			   and clear the area.  */
			retval = set_brk(pod_bss + load_bias,
					 pod_brk + load_bias);
			if (retval) {
				send_sig(SIGKILL, current, 0);
				goto out_free_dentry;
			}
			nbyte = POD_PAGEOFFSET(pod_bss);
			if (nbyte) {
				nbyte = POD_MIN_ALIGN - nbyte;
				if (nbyte > pod_brk - pod_bss)
					nbyte = pod_brk - pod_bss;
				if (clear_user((void __user *)pod_bss +
							load_bias, nbyte)) {
					/*
					 * This bss-zeroing can fail if the POD
					 * file specifies odd protections. So
					 * we don't check the return value
					 */
				}
			}
		}

		if (pod_ppnt->p_flags & PF_R)
			pod_prot |= PROT_READ;
		if (pod_ppnt->p_flags & PF_W)
			pod_prot |= PROT_WRITE;
		if (pod_ppnt->p_flags & PF_X)
			pod_prot |= PROT_EXEC;

		pod_flags = MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE;

		vaddr = pod_ppnt->p_vaddr;
		if (loc->pod_ex.e_type == ET_EXEC || load_addr_set) {
			pod_flags |= MAP_FIXED;
		} else if (loc->pod_ex.e_type == ET_DYN) {
			/* Try and get dynamic programs out of the way of the
			 * default mmap base, as well as whatever program they
			 * might try to exec.  This is because the brk will
			 * follow the loader, and is not movable.  */
#if defined(CONFIG_X86) || defined(CONFIG_ARM)
			/* Memory randomization might have been switched off
			 * in runtime via sysctl.
			 * If that is the case, retain the original non-zero
			 * load_bias value in order to establish proper
			 * non-randomized mappings.
			 */
			if (current->flags & PF_RANDOMIZE)
				load_bias = 0;
			else
				load_bias = POD_PAGESTART(POD_ET_DYN_BASE - vaddr);
#else
			load_bias = POD_PAGESTART(POD_ET_DYN_BASE - vaddr);
#endif
		}

		error = pod_map(bprm->file, load_bias + vaddr, pod_ppnt,
				pod_prot, pod_flags, 0);


		// SS++
	//	POD_ADD_VA(error, podarch_podenter_flag);
		// SS--

		if (BAD_ADDR(error)) {
			send_sig(SIGKILL, current, 0);
			retval = IS_ERR((void *)error) ?
				PTR_ERR((void*)error) : -EINVAL;
			goto out_free_dentry;
		}

		if (!load_addr_set) {
			load_addr_set = 1;
			load_addr = (pod_ppnt->p_vaddr - pod_ppnt->p_offset);
			if (loc->pod_ex.e_type == ET_DYN) {
				load_bias += error -
				             POD_PAGESTART(load_bias + vaddr);
				load_addr += load_bias;
				reloc_func_desc = load_bias;
			}
		}
		k = pod_ppnt->p_vaddr;
		if (k < start_code)
			start_code = k;
		if (start_data < k)
			start_data = k;

		/*
		 * Check to see if the section's size will overflow the
		 * allowed task size. Note that p_filesz must always be
		 * <= p_memsz so it is only necessary to check p_memsz.
		 */
		if (BAD_ADDR(k) || pod_ppnt->p_filesz > pod_ppnt->p_memsz ||
		    pod_ppnt->p_memsz > TASK_SIZE ||
		    TASK_SIZE - pod_ppnt->p_memsz < k) {
			/* set_brk can never work. Avoid overflows. */
			send_sig(SIGKILL, current, 0);
			retval = -EINVAL;
			goto out_free_dentry;
		}

		k = pod_ppnt->p_vaddr + pod_ppnt->p_filesz;

		if (k > pod_bss)
			pod_bss = k;
		if ((pod_ppnt->p_flags & PF_X) && end_code < k)
			end_code = k;
		if (end_data < k)
			end_data = k;
		k = pod_ppnt->p_vaddr + pod_ppnt->p_memsz;
		if (k > pod_brk)
			pod_brk = k;
	}

	loc->pod_ex.e_entry += load_bias;
	pod_bss += load_bias;
	pod_brk += load_bias;
	start_code += load_bias;
	end_code += load_bias;
	start_data += load_bias;
	end_data += load_bias;

	/* Calling set_brk effectively mmaps the pages that we need
	 * for the bss and break sections.  We must do this before
	 * mapping in the interpreter, to make sure it doesn't wind
	 * up getting placed where the bss needs to go.
	 */
	retval = set_brk(pod_bss, pod_brk);
	if (retval) {
		send_sig(SIGKILL, current, 0);
		goto out_free_dentry;
	}
	if (likely(pod_bss != pod_brk) && unlikely(padzero(pod_bss))) {
		send_sig(SIGSEGV, current, 0);
		retval = -EFAULT; /* Nobody gets to see this, but.. */
		goto out_free_dentry;
	}

	if (pod_interpreter) {
		unsigned long uninitialized_var(interp_map_addr);

		pod_entry = load_pod_interp(&loc->interp_pod_ex,
					    interpreter,
					    &interp_map_addr,
					    load_bias);

		if (!IS_ERR((void *)pod_entry)) {
			/*
			 * load_pod_interp() returns relocation
			 * adjustment
			 */
			interp_load_addr = pod_entry;
			pod_entry += loc->interp_pod_ex.e_entry;
		}
		if (BAD_ADDR(pod_entry)) {
			force_sig(SIGSEGV, current);
			retval = IS_ERR((void *)pod_entry) ?
					(int)pod_entry : -EINVAL;
			goto out_free_dentry;
		}
		reloc_func_desc = interp_load_addr;

		allow_write_access(interpreter);
		fput(interpreter);
		kfree(pod_interpreter);
	} else {
		pod_entry = loc->pod_ex.e_entry;
		if (BAD_ADDR(pod_entry)) {
			force_sig(SIGSEGV, current);
			retval = -EINVAL;
			goto out_free_dentry;
		}
	}

	// SS++
//	POD_ADD_VA(pod_entry, podarch_podenter_flag);
	// SS--

	kfree(pod_phdata);

	set_binfmt(&pod_format);

#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
	retval = arch_setup_additional_pages(bprm, !!pod_interpreter);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto out;
	}
#endif /* ARCH_HAS_SETUP_ADDITIONAL_PAGES */

	install_exec_creds(bprm);
	current->flags &= ~PF_FORKNOEXEC;
	retval = create_pod_tables(bprm, &loc->pod_ex,
			  load_addr, interp_load_addr);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto out;
	}
	/* N.B. passed_fileno might not be initialized? */
	current->mm->end_code = end_code;
	current->mm->start_code = start_code;
	current->mm->start_data = start_data;
	current->mm->end_data = end_data;
	current->mm->start_stack = bprm->p;

#ifdef arch_randomize_brk
	if ((current->flags & PF_RANDOMIZE) && (randomize_va_space > 1)) {
		current->mm->brk = current->mm->start_brk =
			arch_randomize_brk(current->mm);
#ifdef CONFIG_COMPAT_BRK
		current->brk_randomized = 1;
#endif
	}
#endif

	if (current->personality & MMAP_PAGE_ZERO) {
		/* Why this, you ask???  Well SVr4 maps page 0 as read-only,
		   and some applications "depend" upon this behavior.
		   Since we do not have the power to recompile these, we
		   emulate the SVr4 behavior. Sigh. */
		down_write(&current->mm->mmap_sem);
		error = do_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_EXEC,
				MAP_FIXED | MAP_PRIVATE, 0);
		up_write(&current->mm->mmap_sem);
	}

#ifdef POD_PLAT_INIT
	/*
	 * The ABI may specify that certain registers be set up in special
	 * ways (on i386 %edx is the address of a DT_FINI function, for
	 * example.  In addition, it may also specify (eg, PowerPC64 POD)
	 * that the e_entry field is the address of the function descriptor
	 * for the startup routine, rather than the address of the startup
	 * routine itspod.  This macro performs whatever initialization to
	 * the regs structure is required as well as any relocations to the
	 * function descriptor entries when executing dynamically links apps.
	 */
	POD_PLAT_INIT(regs, reloc_func_desc);
#endif

	start_thread(regs, pod_entry, bprm->p);
	retval = 0;
out:
	kfree(loc);
out_ret:
	return retval;

	/* error cleanup */
out_free_dentry:
	allow_write_access(interpreter);
	if (interpreter)
		fput(interpreter);
out_free_interp:
	kfree(pod_interpreter);
out_free_ph:
	kfree(pod_phdata);
	goto out;
}

/* This is really simpleminded and specialized - we are loading an
   a.out library that is given an POD header.
   Just keeping for the sake of supportability.
   External library loading is not supported in PodArch
   */
static int load_pod_library(struct file *file)
{
	struct pod_phdr *pod_phdata;
	struct pod_phdr *eppnt;
	unsigned long pod_bss, bss, len;
	int retval, error, i, j;
	struct podhdr pod_ex;

	error = -ENOEXEC;
	retval = kernel_read(file, 0, (char *)&pod_ex, sizeof(pod_ex));
	if (retval != sizeof(pod_ex))
		goto out;

	if (memcmp(pod_ex.e_ident, PODMAG, SELFMAG) != 0)
		goto out;

	/* First of all, some simple consistency checks */
	if (pod_ex.e_type != ET_EXEC || pod_ex.e_phnum > 2 ||
	    !pod_check_arch(&pod_ex) || !file->f_op || !file->f_op->mmap)
		goto out;

	/* Now read in all of the header information */

	j = sizeof(struct pod_phdr) * pod_ex.e_phnum;
	/* j < POD_MIN_ALIGN because pod_ex.e_phnum <= 2 */

	error = -ENOMEM;
	pod_phdata = kmalloc(j, GFP_KERNEL);
	if (!pod_phdata)
		goto out;

	eppnt = pod_phdata;
	error = -ENOEXEC;
	retval = kernel_read(file, pod_ex.e_phoff, (char *)eppnt, j);
	if (retval != j)
		goto out_free_ph;

	for (j = 0, i = 0; i<pod_ex.e_phnum; i++)
		if ((eppnt + i)->p_type == PT_LOAD)
			j++;
	if (j != 1)
		goto out_free_ph;

	while (eppnt->p_type != PT_LOAD)
		eppnt++;

	/* Now use mmap to map the library into memory. */
	down_write(&current->mm->mmap_sem);
	error = do_mmap(file,
			POD_PAGESTART(eppnt->p_vaddr),
			(eppnt->p_filesz +
			 POD_PAGEOFFSET(eppnt->p_vaddr)),
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_FIXED | MAP_PRIVATE | MAP_DENYWRITE,
			(eppnt->p_offset -
			 POD_PAGEOFFSET(eppnt->p_vaddr)));
	up_write(&current->mm->mmap_sem);
	if (error != POD_PAGESTART(eppnt->p_vaddr))
		goto out_free_ph;

	pod_bss = eppnt->p_vaddr + eppnt->p_filesz;
	if (padzero(pod_bss)) {
		error = -EFAULT;
		goto out_free_ph;
	}

	len = POD_PAGESTART(eppnt->p_filesz + eppnt->p_vaddr +
			    POD_MIN_ALIGN - 1);
	bss = eppnt->p_memsz + eppnt->p_vaddr;
	if (bss > len) {
		down_write(&current->mm->mmap_sem);
		do_brk(len, bss - len);
		up_write(&current->mm->mmap_sem);
	}
	error = 0;

out_free_ph:
	kfree(pod_phdata);
out:
	return error;
}

#ifdef CONFIG_POD_CORE
/*
 * POD core dumper
 *
 * Modelled on fs/exec.c:aout_core_dump()
 * Jeremy Fitzhardinge <jeremy@sw.oz.au>
 */

/*
 * Decide what to dump of a segment, part, all or none.
 */
static unsigned long vma_dump_size(struct vm_area_struct *vma,
				   unsigned long mm_flags)
{
#define FILTER(type)	(mm_flags & (1UL << MMF_DUMP_##type))

	/* The vma can be set up to tell us the answer directly.  */
	if (vma->vm_flags & VM_ALWAYSDUMP)
		goto whole;

	/* Hugetlb memory check */
	if (vma->vm_flags & VM_HUGETLB) {
		if ((vma->vm_flags & VM_SHARED) && FILTER(HUGETLB_SHARED))
			goto whole;
		if (!(vma->vm_flags & VM_SHARED) && FILTER(HUGETLB_PRIVATE))
			goto whole;
	}

	/* Do not dump I/O mapped devices or special mappings */
	if (vma->vm_flags & (VM_IO | VM_RESERVED))
		return 0;

	/* By default, dump shared memory if mapped from an anonymous file. */
	if (vma->vm_flags & VM_SHARED) {
		if (vma->vm_file->f_path.dentry->d_inode->i_nlink == 0 ?
		    FILTER(ANON_SHARED) : FILTER(MAPPED_SHARED))
			goto whole;
		return 0;
	}

	/* Dump segments that have been written to.  */
	if (vma->anon_vma && FILTER(ANON_PRIVATE))
		goto whole;
	if (vma->vm_file == NULL)
		return 0;

	if (FILTER(MAPPED_PRIVATE))
		goto whole;

	/*
	 * If this looks like the beginning of a DSO or executable mapping,
	 * check for an POD header.  If we find one, dump the first page to
	 * aid in determining what was mapped here.
	 */
	if (FILTER(POD_HEADERS) &&
	    vma->vm_pgoff == 0 && (vma->vm_flags & VM_READ)) {
		u32 __user *header = (u32 __user *) vma->vm_start;
		u32 word;
		mm_segment_t fs = get_fs();
		/*
		 * Doing it this way gets the constant folded by GCC.
		 */
		union {
			u32 cmp;
			char podmag[SPODMAG];
		} magic;
		BUILD_BUG_ON(SPODMAG != sizeof word);
		magic.podmag[EI_MAG0] = PODMAG0;
		magic.podmag[EI_MAG1] = PODMAG1;
		magic.podmag[EI_MAG2] = PODMAG2;
		magic.podmag[EI_MAG3] = PODMAG3;
		/*
		 * Switch to the user "segment" for get_user(),
		 * then put back what pod_core_dump() had in place.
		 */
		set_fs(USER_DS);
		if (unlikely(get_user(word, header)))
			word = 0;
		set_fs(fs);
		if (word == magic.cmp)
			return PAGE_SIZE;
	}

#undef	FILTER

	return 0;

whole:
	return vma->vm_end - vma->vm_start;
}

/* An POD note in memory */
struct mempodnote
{
	const char *name;
	int type;
	unsigned int datasz;
	void *data;
};

static int notesize(struct mempodnote *en)
{
	int sz;

	sz = sizeof(struct pod_note);
	sz += roundup(strlen(en->name) + 1, 4);
	sz += roundup(en->datasz, 4);

	return sz;
}

#define DUMP_WRITE(addr, nr, foffset)	\
	do { if (!dump_write(file, (addr), (nr))) return 0; *foffset += (nr); } while(0)

static int alignfile(struct file *file, loff_t *foffset)
{
	static const char buf[4] = { 0, };
	DUMP_WRITE(buf, roundup(*foffset, 4) - *foffset, foffset);
	return 1;
}

static int writenote(struct mempodnote *men, struct file *file,
			loff_t *foffset)
{
	struct pod_note en;
	en.n_namesz = strlen(men->name) + 1;
	en.n_descsz = men->datasz;
	en.n_type = men->type;

	DUMP_WRITE(&en, sizeof(en), foffset);
	DUMP_WRITE(men->name, en.n_namesz, foffset);
	if (!alignfile(file, foffset))
		return 0;
	DUMP_WRITE(men->data, men->datasz, foffset);
	if (!alignfile(file, foffset))
		return 0;

	return 1;
}
#undef DUMP_WRITE

static void fill_pod_header(struct podhdr *pod, int segs,
			    u16 machine, u32 flags, u8 osabi)
{
	memset(pod, 0, sizeof(*pod));

	memcpy(pod->e_ident, PODMAG, SELFMAG);
	pod->e_ident[EI_CLASS] = POD_CLASS;
	pod->e_ident[EI_DATA] = POD_DATA;
	pod->e_ident[EI_VERSION] = EV_CURRENT;
	pod->e_ident[EI_OSABI] = POD_OSABI;

	pod->e_type = ET_CORE;
	pod->e_machine = machine;
	pod->e_version = EV_CURRENT;
	pod->e_phoff = sizeof(struct podhdr);
	pod->e_flags = flags;
	pod->e_ehsize = sizeof(struct podhdr);
	pod->e_phentsize = sizeof(struct pod_phdr);
	pod->e_phnum = segs;

	return;
}

static void fill_pod_note_phdr(struct pod_phdr *phdr, int sz, loff_t offset)
{
	phdr->p_type = PT_NOTE;
	phdr->p_offset = offset;
	phdr->p_vaddr = 0;
	phdr->p_paddr = 0;
	phdr->p_filesz = sz;
	phdr->p_memsz = 0;
	phdr->p_flags = 0;
	phdr->p_align = 0;
	return;
}

static void fill_note(struct mempodnote *note, const char *name, int type, 
		unsigned int sz, void *data)
{
	note->name = name;
	note->type = type;
	note->datasz = sz;
	note->data = data;
	return;
}

/*
 * fill up all the fields in prstatus from the given task struct, except
 * registers which need to be filled up separately.
 */
static void fill_prstatus(struct pod_prstatus *prstatus,
		struct task_struct *p, long signr)
{
	prstatus->pr_info.si_signo = prstatus->pr_cursig = signr;
	prstatus->pr_sigpend = p->pending.signal.sig[0];
	prstatus->pr_sighold = p->blocked.sig[0];
	rcu_read_lock();
	prstatus->pr_ppid = task_pid_vnr(rcu_dereference(p->real_parent));
	rcu_read_unlock();
	prstatus->pr_pid = task_pid_vnr(p);
	prstatus->pr_pgrp = task_pgrp_vnr(p);
	prstatus->pr_sid = task_session_vnr(p);
	if (thread_group_leader(p)) {
		struct task_cputime cputime;

		/*
		 * This is the record for the group leader.  It shows the
		 * group-wide total, not its individual thread total.
		 */
		thread_group_cputime(p, &cputime);
		cputime_to_timeval(cputime.utime, &prstatus->pr_utime);
		cputime_to_timeval(cputime.stime, &prstatus->pr_stime);
	} else {
		cputime_to_timeval(p->utime, &prstatus->pr_utime);
		cputime_to_timeval(p->stime, &prstatus->pr_stime);
	}
	cputime_to_timeval(p->signal->cutime, &prstatus->pr_cutime);
	cputime_to_timeval(p->signal->cstime, &prstatus->pr_cstime);
}

static int fill_psinfo(struct pod_prpsinfo *psinfo, struct task_struct *p,
		       struct mm_struct *mm)
{
	const struct cred *cred;
	unsigned int i, len;
	
	/* first copy the parameters from user space */
	memset(psinfo, 0, sizeof(struct pod_prpsinfo));

	len = mm->arg_end - mm->arg_start;
	if (len >= POD_PRARGSZ)
		len = POD_PRARGSZ-1;
	if (copy_from_user(&psinfo->pr_psargs,
		           (const char __user *)mm->arg_start, len))
		return -EFAULT;
	for(i = 0; i < len; i++)
		if (psinfo->pr_psargs[i] == 0)
			psinfo->pr_psargs[i] = ' ';
	psinfo->pr_psargs[len] = 0;

	rcu_read_lock();
	psinfo->pr_ppid = task_pid_vnr(rcu_dereference(p->real_parent));
	rcu_read_unlock();
	psinfo->pr_pid = task_pid_vnr(p);
	psinfo->pr_pgrp = task_pgrp_vnr(p);
	psinfo->pr_sid = task_session_vnr(p);

	i = p->state ? ffz(~p->state) + 1 : 0;
	psinfo->pr_state = i;
	psinfo->pr_sname = (i > 5) ? '.' : "RSDTZW"[i];
	psinfo->pr_zomb = psinfo->pr_sname == 'Z';
	psinfo->pr_nice = task_nice(p);
	psinfo->pr_flag = p->flags;
	rcu_read_lock();
	cred = __task_cred(p);
	SET_UID(psinfo->pr_uid, cred->uid);
	SET_GID(psinfo->pr_gid, cred->gid);
	rcu_read_unlock();
	strncpy(psinfo->pr_fname, p->comm, sizeof(psinfo->pr_fname));
	
	return 0;
}

static void fill_auxv_note(struct mempodnote *note, struct mm_struct *mm)
{
	pod_addr_t *auxv = (pod_addr_t *) mm->saved_auxv;
	int i = 0;
	do
		i += 2;
	while (auxv[i - 2] != AT_NULL);
	fill_note(note, "CORE", NT_AUXV, i * sizeof(pod_addr_t), auxv);
}

#ifdef CORE_DUMP_USE_REGSET
#include <linux/regset.h>

struct pod_thread_core_info {
	struct pod_thread_core_info *next;
	struct task_struct *task;
	struct pod_prstatus prstatus;
	struct mempodnote notes[0];
};

struct pod_note_info {
	struct pod_thread_core_info *thread;
	struct mempodnote psinfo;
	struct mempodnote auxv;
	size_t size;
	int thread_notes;
};

/*
 * When a regset has a writeback hook, we call it on each thread before
 * dumping user memory.  On register window machines, this makes sure the
 * user memory backing the register data is up to date before we read it.
 */
static void do_thread_regset_writeback(struct task_struct *task,
				       const struct user_regset *regset)
{
	if (regset->writeback)
		regset->writeback(task, regset, 1);
}

static int fill_thread_core_info(struct pod_thread_core_info *t,
				 const struct user_regset_view *view,
				 long signr, size_t *total)
{
	unsigned int i;

	/*
	 * NT_PRSTATUS is the one special case, because the regset data
	 * goes into the pr_reg field inside the note contents, rather
	 * than being the whole note contents.  We fill the reset in here.
	 * We assume that regset 0 is NT_PRSTATUS.
	 */
	fill_prstatus(&t->prstatus, t->task, signr);
	(void) view->regsets[0].get(t->task, &view->regsets[0],
				    0, sizeof(t->prstatus.pr_reg),
				    &t->prstatus.pr_reg, NULL);

	fill_note(&t->notes[0], "CORE", NT_PRSTATUS,
		  sizeof(t->prstatus), &t->prstatus);
	*total += notesize(&t->notes[0]);

	do_thread_regset_writeback(t->task, &view->regsets[0]);

	/*
	 * Each other regset might generate a note too.  For each regset
	 * that has no core_note_type or is inactive, we leave t->notes[i]
	 * all zero and we'll know to skip writing it later.
	 */
	for (i = 1; i < view->n; ++i) {
		const struct user_regset *regset = &view->regsets[i];
		do_thread_regset_writeback(t->task, regset);
		if (regset->core_note_type &&
		    (!regset->active || regset->active(t->task, regset))) {
			int ret;
			size_t size = regset->n * regset->size;
			void *data = kmalloc(size, GFP_KERNEL);
			if (unlikely(!data))
				return 0;
			ret = regset->get(t->task, regset,
					  0, size, data, NULL);
			if (unlikely(ret))
				kfree(data);
			else {
				if (regset->core_note_type != NT_PRFPREG)
					fill_note(&t->notes[i], "LINUX",
						  regset->core_note_type,
						  size, data);
				else {
					t->prstatus.pr_fpvalid = 1;
					fill_note(&t->notes[i], "CORE",
						  NT_PRFPREG, size, data);
				}
				*total += notesize(&t->notes[i]);
			}
		}
	}

	return 1;
}

static int fill_note_info(struct podhdr *pod, int phdrs,
			  struct pod_note_info *info,
			  long signr, struct pt_regs *regs)
{
	struct task_struct *dump_task = current;
	const struct user_regset_view *view = task_user_regset_view(dump_task);
	struct pod_thread_core_info *t;
	struct pod_prpsinfo *psinfo;
	struct core_thread *ct;
	unsigned int i;

	info->size = 0;
	info->thread = NULL;

	psinfo = kmalloc(sizeof(*psinfo), GFP_KERNEL);
	if (psinfo == NULL)
		return 0;

	fill_note(&info->psinfo, "CORE", NT_PRPSINFO, sizeof(*psinfo), psinfo);

	/*
	 * Figure out how many notes we're going to need for each thread.
	 */
	info->thread_notes = 0;
	for (i = 0; i < view->n; ++i)
		if (view->regsets[i].core_note_type != 0)
			++info->thread_notes;

	/*
	 * Sanity check.  We rely on regset 0 being in NT_PRSTATUS,
	 * since it is our one special case.
	 */
	if (unlikely(info->thread_notes == 0) ||
	    unlikely(view->regsets[0].core_note_type != NT_PRSTATUS)) {
		WARN_ON(1);
		return 0;
	}

	/*
	 * Initialize the POD file header.
	 */
	fill_pod_header(pod, phdrs,
			view->e_machine, view->e_flags, view->ei_osabi);

	/*
	 * Allocate a structure for each thread.
	 */
	for (ct = &dump_task->mm->core_state->dumper; ct; ct = ct->next) {
		t = kzalloc(offsetof(struct pod_thread_core_info,
				     notes[info->thread_notes]),
			    GFP_KERNEL);
		if (unlikely(!t))
			return 0;

		t->task = ct->task;
		if (ct->task == dump_task || !info->thread) {
			t->next = info->thread;
			info->thread = t;
		} else {
			/*
			 * Make sure to keep the original task at
			 * the head of the list.
			 */
			t->next = info->thread->next;
			info->thread->next = t;
		}
	}

	/*
	 * Now fill in each thread's information.
	 */
	for (t = info->thread; t != NULL; t = t->next)
		if (!fill_thread_core_info(t, view, signr, &info->size))
			return 0;

	/*
	 * Fill in the two process-wide notes.
	 */
	fill_psinfo(psinfo, dump_task->group_leader, dump_task->mm);
	info->size += notesize(&info->psinfo);

	fill_auxv_note(&info->auxv, current->mm);
	info->size += notesize(&info->auxv);

	return 1;
}

static size_t get_note_info_size(struct pod_note_info *info)
{
	return info->size;
}

/*
 * Write all the notes for each thread.  When writing the first thread, the
 * process-wide notes are interleaved after the first thread-specific note.
 */
static int write_note_info(struct pod_note_info *info,
			   struct file *file, loff_t *foffset)
{
	bool first = 1;
	struct pod_thread_core_info *t = info->thread;

	do {
		int i;

		if (!writenote(&t->notes[0], file, foffset))
			return 0;

		if (first && !writenote(&info->psinfo, file, foffset))
			return 0;
		if (first && !writenote(&info->auxv, file, foffset))
			return 0;

		for (i = 1; i < info->thread_notes; ++i)
			if (t->notes[i].data &&
			    !writenote(&t->notes[i], file, foffset))
				return 0;

		first = 0;
		t = t->next;
	} while (t);

	return 1;
}

static void free_note_info(struct pod_note_info *info)
{
	struct pod_thread_core_info *threads = info->thread;
	while (threads) {
		unsigned int i;
		struct pod_thread_core_info *t = threads;
		threads = t->next;
		WARN_ON(t->notes[0].data && t->notes[0].data != &t->prstatus);
		for (i = 1; i < info->thread_notes; ++i)
			kfree(t->notes[i].data);
		kfree(t);
	}
	kfree(info->psinfo.data);
}

#else

/* Here is the structure in which status of each thread is captured. */
struct pod_thread_status
{
	struct list_head list;
	struct pod_prstatus prstatus;	/* NT_PRSTATUS */
	pod_fpregset_t fpu;		/* NT_PRFPREG */
	struct task_struct *thread;
#ifdef POD_CORE_COPY_XFPREGS
	pod_fpxregset_t xfpu;		/* POD_CORE_XFPREG_TYPE */
#endif
	struct mempodnote notes[3];
	int num_notes;
};

/*
 * In order to add the specific thread information for the pod file format,
 * we need to keep a linked list of every threads pr_status and then create
 * a single section for them in the final core file.
 */
static int pod_dump_thread_status(long signr, struct pod_thread_status *t)
{
	int sz = 0;
	struct task_struct *p = t->thread;
	t->num_notes = 0;

	fill_prstatus(&t->prstatus, p, signr);
	pod_core_copy_task_regs(p, &t->prstatus.pr_reg);	
	
	fill_note(&t->notes[0], "CORE", NT_PRSTATUS, sizeof(t->prstatus),
		  &(t->prstatus));
	t->num_notes++;
	sz += notesize(&t->notes[0]);

	if ((t->prstatus.pr_fpvalid = pod_core_copy_task_fpregs(p, NULL,
								&t->fpu))) {
		fill_note(&t->notes[1], "CORE", NT_PRFPREG, sizeof(t->fpu),
			  &(t->fpu));
		t->num_notes++;
		sz += notesize(&t->notes[1]);
	}

#ifdef POD_CORE_COPY_XFPREGS
	if (pod_core_copy_task_xfpregs(p, &t->xfpu)) {
		fill_note(&t->notes[2], "LINUX", POD_CORE_XFPREG_TYPE,
			  sizeof(t->xfpu), &t->xfpu);
		t->num_notes++;
		sz += notesize(&t->notes[2]);
	}
#endif	
	return sz;
}

struct pod_note_info {
	struct mempodnote *notes;
	struct pod_prstatus *prstatus;	/* NT_PRSTATUS */
	struct pod_prpsinfo *psinfo;	/* NT_PRPSINFO */
	struct list_head thread_list;
	pod_fpregset_t *fpu;
#ifdef POD_CORE_COPY_XFPREGS
	pod_fpxregset_t *xfpu;
#endif
	int thread_status_size;
	int numnote;
};

static int pod_note_info_init(struct pod_note_info *info)
{
	memset(info, 0, sizeof(*info));
	INIT_LIST_HEAD(&info->thread_list);

	/* Allocate space for six POD notes */
	info->notes = kmalloc(6 * sizeof(struct mempodnote), GFP_KERNEL);
	if (!info->notes)
		return 0;
	info->psinfo = kmalloc(sizeof(*info->psinfo), GFP_KERNEL);
	if (!info->psinfo)
		goto notes_free;
	info->prstatus = kmalloc(sizeof(*info->prstatus), GFP_KERNEL);
	if (!info->prstatus)
		goto psinfo_free;
	info->fpu = kmalloc(sizeof(*info->fpu), GFP_KERNEL);
	if (!info->fpu)
		goto prstatus_free;
#ifdef POD_CORE_COPY_XFPREGS
	info->xfpu = kmalloc(sizeof(*info->xfpu), GFP_KERNEL);
	if (!info->xfpu)
		goto fpu_free;
#endif
	return 1;
#ifdef POD_CORE_COPY_XFPREGS
 fpu_free:
	kfree(info->fpu);
#endif
 prstatus_free:
	kfree(info->prstatus);
 psinfo_free:
	kfree(info->psinfo);
 notes_free:
	kfree(info->notes);
	return 0;
}

static int fill_note_info(struct podhdr *pod, int phdrs,
			  struct pod_note_info *info,
			  long signr, struct pt_regs *regs)
{
	struct list_head *t;

	if (!pod_note_info_init(info))
		return 0;

	if (signr) {
		struct core_thread *ct;
		struct pod_thread_status *ets;

		for (ct = current->mm->core_state->dumper.next;
						ct; ct = ct->next) {
			ets = kzalloc(sizeof(*ets), GFP_KERNEL);
			if (!ets)
				return 0;

			ets->thread = ct->task;
			list_add(&ets->list, &info->thread_list);
		}

		list_for_each(t, &info->thread_list) {
			int sz;

			ets = list_entry(t, struct pod_thread_status, list);
			sz = pod_dump_thread_status(signr, ets);
			info->thread_status_size += sz;
		}
	}
	/* now collect the dump for the current */
	memset(info->prstatus, 0, sizeof(*info->prstatus));
	fill_prstatus(info->prstatus, current, signr);
	pod_core_copy_regs(&info->prstatus->pr_reg, regs);

	/* Set up header */
	fill_pod_header(pod, phdrs, POD_ARCH, POD_CORE_EFLAGS, POD_OSABI);

	/*
	 * Set up the notes in similar form to SVR4 core dumps made
	 * with info from their /proc.
	 */

	fill_note(info->notes + 0, "CORE", NT_PRSTATUS,
		  sizeof(*info->prstatus), info->prstatus);
	fill_psinfo(info->psinfo, current->group_leader, current->mm);
	fill_note(info->notes + 1, "CORE", NT_PRPSINFO,
		  sizeof(*info->psinfo), info->psinfo);

	info->numnote = 2;

	fill_auxv_note(&info->notes[info->numnote++], current->mm);

	/* Try to dump the FPU. */
	info->prstatus->pr_fpvalid = pod_core_copy_task_fpregs(current, regs,
							       info->fpu);
	if (info->prstatus->pr_fpvalid)
		fill_note(info->notes + info->numnote++,
			  "CORE", NT_PRFPREG, sizeof(*info->fpu), info->fpu);
#ifdef POD_CORE_COPY_XFPREGS
	if (pod_core_copy_task_xfpregs(current, info->xfpu))
		fill_note(info->notes + info->numnote++,
			  "LINUX", POD_CORE_XFPREG_TYPE,
			  sizeof(*info->xfpu), info->xfpu);
#endif

	return 1;
}

static size_t get_note_info_size(struct pod_note_info *info)
{
	int sz = 0;
	int i;

	for (i = 0; i < info->numnote; i++)
		sz += notesize(info->notes + i);

	sz += info->thread_status_size;

	return sz;
}

static int write_note_info(struct pod_note_info *info,
			   struct file *file, loff_t *foffset)
{
	int i;
	struct list_head *t;

	for (i = 0; i < info->numnote; i++)
		if (!writenote(info->notes + i, file, foffset))
			return 0;

	/* write out the thread status notes section */
	list_for_each(t, &info->thread_list) {
		struct pod_thread_status *tmp =
				list_entry(t, struct pod_thread_status, list);

		for (i = 0; i < tmp->num_notes; i++)
			if (!writenote(&tmp->notes[i], file, foffset))
				return 0;
	}

	return 1;
}

static void free_note_info(struct pod_note_info *info)
{
	while (!list_empty(&info->thread_list)) {
		struct list_head *tmp = info->thread_list.next;
		list_del(tmp);
		kfree(list_entry(tmp, struct pod_thread_status, list));
	}

	kfree(info->prstatus);
	kfree(info->psinfo);
	kfree(info->notes);
	kfree(info->fpu);
#ifdef POD_CORE_COPY_XFPREGS
	kfree(info->xfpu);
#endif
}

#endif

static struct vm_area_struct *first_vma(struct task_struct *tsk,
					struct vm_area_struct *gate_vma)
{
	struct vm_area_struct *ret = tsk->mm->mmap;

	if (ret)
		return ret;
	return gate_vma;
}
/*
 * Helper function for iterating across a vma list.  It ensures that the caller
 * will visit `gate_vma' prior to terminating the search.
 */
static struct vm_area_struct *next_vma(struct vm_area_struct *this_vma,
					struct vm_area_struct *gate_vma)
{
	struct vm_area_struct *ret;

	ret = this_vma->vm_next;
	if (ret)
		return ret;
	if (this_vma == gate_vma)
		return NULL;
	return gate_vma;
}

static void fill_extnum_info(struct podhdr *pod, struct pod_shdr *shdr4extnum,
			     pod_addr_t e_shoff, int segs)
{
	pod->e_shoff = e_shoff;
	pod->e_shentsize = sizeof(*shdr4extnum);
	pod->e_shnum = 1;
	pod->e_shstrndx = SHN_UNDEF;

	memset(shdr4extnum, 0, sizeof(*shdr4extnum));

	shdr4extnum->sh_type = SHT_NULL;
	shdr4extnum->sh_size = pod->e_shnum;
	shdr4extnum->sh_link = pod->e_shstrndx;
	shdr4extnum->sh_info = segs;
}

static size_t pod_core_vma_data_size(struct vm_area_struct *gate_vma,
				     unsigned long mm_flags)
{
	struct vm_area_struct *vma;
	size_t size = 0;

	for (vma = first_vma(current, gate_vma); vma != NULL;
	     vma = next_vma(vma, gate_vma))
		size += vma_dump_size(vma, mm_flags);
	return size;
}

/*
 * Actual dumper
 *
 * This is a two-pass process; first we find the offsets of the bits,
 * and then they are actually written out.  If we run out of core limit
 * we just truncate.
 */
static int pod_core_dump(struct coredump_params *cprm)
{
	int has_dumped = 0;
	mm_segment_t fs;
	int segs;
	size_t size = 0;
	struct vm_area_struct *vma, *gate_vma;
	struct podhdr *pod = NULL;
	loff_t offset = 0, dataoff, foffset;
	struct pod_note_info info;
	struct pod_phdr *phdr4note = NULL;
	struct pod_shdr *shdr4extnum = NULL;
	Pod_Half e_phnum;
	pod_addr_t e_shoff;

	/*
	 * We no longer stop all VM operations.
	 * 
	 * This is because those proceses that could possibly change map_count
	 * or the mmap / vma pages are now blocked in do_exit on current
	 * finishing this core dump.
	 *
	 * Only ptrace can touch these memory addresses, but it doesn't change
	 * the map_count or the pages allocated. So no possibility of crashing
	 * exists while dumping the mm->vm_next areas to the core file.
	 */
  
	/* alloc memory for large data structures: too large to be on stack */
	pod = kmalloc(sizeof(*pod), GFP_KERNEL);

	// SS++
//	POD_ADD_VA(pod, podarch_podenter_flag);
	// SS--

	if (!pod)
		goto out;
	/*
	 * The number of segs are recored into POD header as 16bit value.
	 * Please check DEFAULT_MAX_MAP_COUNT definition when you modify here.
	 */
	segs = current->mm->map_count;
	segs += pod_core_extra_phdrs();

	gate_vma = get_gate_vma(current->mm);
	if (gate_vma != NULL)
		segs++;

	/* for notes section */
	segs++;

	/* If segs > PN_XNUM(0xffff), then e_phnum overflows. To avoid
	 * this, kernel supports extended numbering. Have a look at
	 * include/linux/pod.h for further information. */
	e_phnum = segs > PN_XNUM ? PN_XNUM : segs;

	/*
	 * Collect all the non-memory information about the process for the
	 * notes.  This also sets up the file header.
	 */
	if (!fill_note_info(pod, e_phnum, &info, cprm->signr, cprm->regs))
		goto cleanup;

	has_dumped = 1;
	current->flags |= PF_DUMPCORE;
  
	fs = get_fs();
	set_fs(KERNEL_DS);

	offset += sizeof(*pod);				/* Pod header */
	offset += segs * sizeof(struct pod_phdr);	/* Program headers */
	foffset = offset;

	/* Write notes phdr entry */
	{
		size_t sz = get_note_info_size(&info);

		sz += pod_coredump_extra_notes_size();

		phdr4note = kmalloc(sizeof(*phdr4note), GFP_KERNEL);
		if (!phdr4note)
			goto end_coredump;

		fill_pod_note_phdr(phdr4note, sz, offset);
		offset += sz;
	}

	dataoff = offset = roundup(offset, POD_EXEC_PAGESIZE);

	offset += pod_core_vma_data_size(gate_vma, cprm->mm_flags);
	offset += pod_core_extra_data_size();
	e_shoff = offset;

	if (e_phnum == PN_XNUM) {
		shdr4extnum = kmalloc(sizeof(*shdr4extnum), GFP_KERNEL);
		if (!shdr4extnum)
			goto end_coredump;
		fill_extnum_info(pod, shdr4extnum, e_shoff, segs);
	}

	offset = dataoff;

	size += sizeof(*pod);
	if (size > cprm->limit || !dump_write(cprm->file, pod, sizeof(*pod)))
		goto end_coredump;

	size += sizeof(*phdr4note);
	if (size > cprm->limit
	    || !dump_write(cprm->file, phdr4note, sizeof(*phdr4note)))
		goto end_coredump;

	/* Write program headers for segments dump */
	for (vma = first_vma(current, gate_vma); vma != NULL;
			vma = next_vma(vma, gate_vma)) {
		struct pod_phdr phdr;

		phdr.p_type = PT_LOAD;
		phdr.p_offset = offset;
		phdr.p_vaddr = vma->vm_start;
		phdr.p_paddr = 0;
		phdr.p_filesz = vma_dump_size(vma, cprm->mm_flags);
		phdr.p_memsz = vma->vm_end - vma->vm_start;
		offset += phdr.p_filesz;
		phdr.p_flags = vma->vm_flags & VM_READ ? PF_R : 0;
		if (vma->vm_flags & VM_WRITE)
			phdr.p_flags |= PF_W;
		if (vma->vm_flags & VM_EXEC)
			phdr.p_flags |= PF_X;
		phdr.p_align = POD_EXEC_PAGESIZE;

		size += sizeof(phdr);
		if (size > cprm->limit
		    || !dump_write(cprm->file, &phdr, sizeof(phdr)))
			goto end_coredump;
	}

	if (!pod_core_write_extra_phdrs(cprm->file, offset, &size, cprm->limit))
		goto end_coredump;

 	/* write out the notes section */
	if (!write_note_info(&info, cprm->file, &foffset))
		goto end_coredump;

	if (pod_coredump_extra_notes_write(cprm->file, &foffset))
		goto end_coredump;

	/* Align to page */
	if (!dump_seek(cprm->file, dataoff - foffset))
		goto end_coredump;

	for (vma = first_vma(current, gate_vma); vma != NULL;
			vma = next_vma(vma, gate_vma)) {
		unsigned long addr;
		unsigned long end;

		end = vma->vm_start + vma_dump_size(vma, cprm->mm_flags);

		for (addr = vma->vm_start; addr < end; addr += PAGE_SIZE) {
			struct page *page;
			int stop;

			page = get_dump_page(addr);
			if (page) {
				void *kaddr = kmap(page);
				stop = ((size += PAGE_SIZE) > cprm->limit) ||
					!dump_write(cprm->file, kaddr,
						    PAGE_SIZE);
				kunmap(page);
				page_cache_release(page);
			} else
				stop = !dump_seek(cprm->file, PAGE_SIZE);
			if (stop)
				goto end_coredump;
		}
	}

	if (!pod_core_write_extra_data(cprm->file, &size, cprm->limit))
		goto end_coredump;

	if (e_phnum == PN_XNUM) {
		size += sizeof(*shdr4extnum);
		if (size > cprm->limit
		    || !dump_write(cprm->file, shdr4extnum,
				   sizeof(*shdr4extnum)))
			goto end_coredump;
	}

end_coredump:
	set_fs(fs);

cleanup:
	free_note_info(&info);
	kfree(shdr4extnum);
	kfree(phdr4note);
	kfree(pod);
out:
	return has_dumped;
}

#endif		/* CONFIG_POD_CORE */

static int __init init_pod_binfmt(void)
{
	printk("PodArch: registering/init pod binary type \n");
	return register_binfmt(&pod_format);
}

static void __exit exit_pod_binfmt(void)
{
	printk("PodArch: exiting pod binary loader \n");
	/* Remove the COFF and POD loaders. */
	unregister_binfmt(&pod_format);
}

core_initcall(init_pod_binfmt);
module_exit(exit_pod_binfmt);
MODULE_LICENSE("GPL");

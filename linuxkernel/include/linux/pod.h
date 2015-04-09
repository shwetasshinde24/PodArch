/*
 *  Created on: 10 Oct, 2013
 *  Author: Shweta
 *
 * include/linux/pod.h
 *
 * Header file for pod format executables as used by PodArch.
 *
 */

#ifndef _LINUX_POD_H
#define _LINUX_POD_H

#define POD_KEY_SIZE 4

#include <linux/types.h>
#include <linux/pod-em.h>
#ifdef __KERNEL__
#include <asm/pod.h>
#endif

struct file;

#ifndef pod_read_implies_exec
  /* Executables for which pod_read_implies_exec() returns TRUE will
     have the READ_IMPLIES_EXEC personality flag set automatically.
     Override in asm/pod.h as needed.  */
# define pod_read_implies_exec(ex, have_pt_gnu_stack)	0
#endif

/* 32-bit POD base types. */
typedef __u32	Pod32_Addr;
typedef __u16	Pod32_Half;
typedef __u32	Pod32_Off;
typedef __s32	Pod32_Sword;
typedef __u32	Pod32_Word;

/* 64-bit POD base types. */
typedef __u64	Pod64_Addr;
typedef __u16	Pod64_Half;
typedef __s16	Pod64_SHalf;
typedef __u64	Pod64_Off;
typedef __s32	Pod64_Sword;
typedef __u32	Pod64_Word;
typedef __u64	Pod64_Xword;
typedef __s64	Pod64_Sxword;

/* These constants are for the segment types stored in the image headers */
#define PT_NULL    0
#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PT_NOTE    4
#define PT_SHLIB   5
#define PT_PHDR    6
#define PT_TLS     7               /* Thread local storage segment */
#define PT_LOOS    0x60000000      /* OS-specific */
#define PT_HIOS    0x6fffffff      /* OS-specific */
#define PT_LOPROC  0x70000000
#define PT_HIPROC  0x7fffffff
#define PT_GNU_EH_FRAME		0x6474e550

#define PT_GNU_STACK	(PT_LOOS + 0x474e551)

/*
 * Extended Numbering
 *
 * If the real number of program header table entries is larger than
 * or equal to PN_XNUM(0xffff), it is set to sh_info field of the
 * section header at index 0, and PN_XNUM is set to e_phnum
 * field. Otherwise, the section header at index 0 is zero
 * initialized, if it exists.
 *
 * Specifications are available in:
 *
 * - Sun microsystems: Linker and Libraries.
 *   Part No: 817-1984-17, September 2008.
 *   URL: http://docs.sun.com/app/docs/doc/817-1984
 *
 * - System V ABI AMD64 Architecture Processor Supplement
 *   Draft Version 0.99.,
 *   May 11, 2009.
 *   URL: http://www.x86-64.org/
 */
#define PN_XNUM 0xffff

/* These constants define the different pod file types */
#define ET_NONE   0
#define ET_REL    1
#define ET_EXEC   2
#define ET_DYN    3
#define ET_CORE   4
#define ET_LOPROC 0xff00
#define ET_HIPROC 0xffff

/* This is the info that is needed to parse the dynamic section of the file */
#define DT_NULL		0
#define DT_NEEDED	1
#define DT_PLTRELSZ	2
#define DT_PLTGOT	3
#define DT_HASH		4
#define DT_STRTAB	5
#define DT_SYMTAB	6
#define DT_RELA		7
#define DT_RELASZ	8
#define DT_RELAENT	9
#define DT_STRSZ	10
#define DT_SYMENT	11
#define DT_INIT		12
#define DT_FINI		13
#define DT_SONAME	14
#define DT_RPATH 	15
#define DT_SYMBOLIC	16
#define DT_REL	        17
#define DT_RELSZ	18
#define DT_RELENT	19
#define DT_PLTREL	20
#define DT_DEBUG	21
#define DT_TEXTREL	22
#define DT_JMPREL	23
#define DT_ENCODING	32
#define OLD_DT_LOOS	0x60000000
#define DT_LOOS		0x6000000d
#define DT_HIOS		0x6ffff000
#define DT_VALRNGLO	0x6ffffd00
#define DT_VALRNGHI	0x6ffffdff
#define DT_ADDRRNGLO	0x6ffffe00
#define DT_ADDRRNGHI	0x6ffffeff
#define DT_VERSYM	0x6ffffff0
#define DT_RELACOUNT	0x6ffffff9
#define DT_RELCOUNT	0x6ffffffa
#define DT_FLAGS_1	0x6ffffffb
#define DT_VERDEF	0x6ffffffc
#define	DT_VERDEFNUM	0x6ffffffd
#define DT_VERNEED	0x6ffffffe
#define	DT_VERNEEDNUM	0x6fffffff
#define OLD_DT_HIOS     0x6fffffff
#define DT_LOPROC	0x70000000
#define DT_HIPROC	0x7fffffff

/* This info is needed when parsing the symbol table */
#define STB_LOCAL  0
#define STB_GLOBAL 1
#define STB_WEAK   2

#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2
#define STT_SECTION 3
#define STT_FILE    4
#define STT_COMMON  5
#define STT_TLS     6

#define POD_ST_BIND(x)		((x) >> 4)
#define POD_ST_TYPE(x)		(((unsigned int) x) & 0xf)
#define POD32_ST_BIND(x)	POD_ST_BIND(x)
#define POD32_ST_TYPE(x)	POD_ST_TYPE(x)
#define POD64_ST_BIND(x)	POD_ST_BIND(x)
#define POD64_ST_TYPE(x)	POD_ST_TYPE(x)

/*typedef struct dynamic{
  Pod32_Sword d_tag;
  union{
    Pod32_Sword	d_val;
    Pod32_Addr	d_ptr;
  } d_un;
} Pod32_Dyn;*/

typedef struct {
  Pod64_Sxword d_tag;		/* entry tag value */
  union {
    Pod64_Xword d_val;
    Pod64_Addr d_ptr;
  } d_un;
} Pod64_Dyn;

/* The following are used with relocations */
#define POD32_R_SYM(x) ((x) >> 8)
#define POD32_R_TYPE(x) ((x) & 0xff)

#define POD64_R_SYM(i)			((i) >> 32)
#define POD64_R_TYPE(i)			((i) & 0xffffffff)

typedef struct pod32_rel {
  Pod32_Addr	r_offset;
  Pod32_Word	r_info;
} Pod32_Rel;

typedef struct pod64_rel {
  Pod64_Addr r_offset;	/* Location at which to apply the action */
  Pod64_Xword r_info;	/* index and type of relocation */
} Pod64_Rel;

typedef struct pod32_rela{
  Pod32_Addr	r_offset;
  Pod32_Word	r_info;
  Pod32_Sword	r_addend;
} Pod32_Rela;

typedef struct pod64_rela {
  Pod64_Addr r_offset;	/* Location at which to apply the action */
  Pod64_Xword r_info;	/* index and type of relocation */
  Pod64_Sxword r_addend;	/* Constant addend used to compute value */
} Pod64_Rela;

typedef struct pod32_sym{
  Pod32_Word	st_name;
  Pod32_Addr	st_value;
  Pod32_Word	st_size;
  unsigned char	st_info;
  unsigned char	st_other;
  Pod32_Half	st_shndx;
} Pod32_Sym;

typedef struct pod64_sym {
  Pod64_Word st_name;		/* Symbol name, index in string tbl */
  unsigned char	st_info;	/* Type and binding attributes */
  unsigned char	st_other;	/* No defined meaning, 0 */
  Pod64_Half st_shndx;		/* Associated section index */
  Pod64_Addr st_value;		/* Value of the symbol */
  Pod64_Xword st_size;		/* Associated symbol size */
} Pod64_Sym;


#define EI_NIDENT	16

typedef struct pod32_hdr{
  unsigned char	e_ident[EI_NIDENT];
  Pod32_Half	e_type;
  Pod32_Half	e_machine;
  Pod32_Word	e_version;
  Pod32_Addr	e_entry;  /* Entry point */
  Pod32_Off	e_phoff;
  Pod32_Off	e_shoff;
  Pod32_Word	e_flags;
  Pod32_Half	e_ehsize;
  Pod32_Half	e_phentsize;
  Pod32_Half	e_phnum;
  Pod32_Half	e_shentsize;
  Pod32_Half	e_shnum;
  Pod32_Half	e_shstrndx;
} Pod32_Ehdr;

typedef struct pod64_hdr {
  unsigned char	e_ident[EI_NIDENT];	/* POD "magic number" */
  Pod64_Half e_type;
  Pod64_Half e_machine;
  Pod64_Word e_version;
  Pod64_Addr e_entry;		/* Entry point virtual address */
  Pod64_Off e_phoff;		/* Program header table file offset */
  Pod64_Off e_shoff;		/* Section header table file offset */
  Pod64_Word e_flags;
  Pod64_Half e_ehsize;
  Pod64_Half e_phentsize;
  Pod64_Half e_phnum;
  Pod64_Half e_shentsize;
  Pod64_Half e_shnum;
  Pod64_Half e_shstrndx;
} Pod64_Ehdr;

/* These constants define the permissions on sections in the program
   header, p_flags. */
#define PF_R		0x4
#define PF_W		0x2
#define PF_X		0x1

typedef struct pod32_phdr{
  Pod32_Word	p_type;
  Pod32_Off	p_offset;
  Pod32_Addr	p_vaddr;
  Pod32_Addr	p_paddr;
  Pod32_Word	p_filesz;
  Pod32_Word	p_memsz;
  Pod32_Word	p_flags;
  Pod32_Word	p_align;
} Pod32_Phdr;

typedef struct pod64_phdr {
  Pod64_Word p_type;
  Pod64_Word p_flags;
  Pod64_Off p_offset;		/* Segment file offset */
  Pod64_Addr p_vaddr;		/* Segment virtual address */
  Pod64_Addr p_paddr;		/* Segment physical address */
  Pod64_Xword p_filesz;		/* Segment size in file */
  Pod64_Xword p_memsz;		/* Segment size in memory */
  Pod64_Xword p_align;		/* Segment alignment, file & memory */
} Pod64_Phdr;

/* sh_type */
#define SHT_NULL	0
#define SHT_PROGBITS	1
#define SHT_SYMTAB	2
#define SHT_STRTAB	3
#define SHT_RELA	4
#define SHT_HASH	5
#define SHT_DYNAMIC	6
#define SHT_NOTE	7
#define SHT_NOBITS	8
#define SHT_REL		9
#define SHT_SHLIB	10
#define SHT_DYNSYM	11
#define SHT_NUM		12
#define SHT_LOPROC	0x70000000
#define SHT_HIPROC	0x7fffffff
#define SHT_LOUSER	0x80000000
#define SHT_HIUSER	0xffffffff

/* sh_flags */
#define SHF_WRITE	0x1
#define SHF_ALLOC	0x2
#define SHF_EXECINSTR	0x4
#define SHF_MASKPROC	0xf0000000

/* special section indexes */
#define SHN_UNDEF	0
#define SHN_LORESERVE	0xff00
#define SHN_LOPROC	0xff00
#define SHN_HIPROC	0xff1f
#define SHN_ABS		0xfff1
#define SHN_COMMON	0xfff2
#define SHN_HIRESERVE	0xffff
 
typedef struct pod32_shdr {
  Pod32_Word	sh_name;
  Pod32_Word	sh_type;
  Pod32_Word	sh_flags;
  Pod32_Addr	sh_addr;
  Pod32_Off	sh_offset;
  Pod32_Word	sh_size;
  Pod32_Word	sh_link;
  Pod32_Word	sh_info;
  Pod32_Word	sh_addralign;
  Pod32_Word	sh_entsize;
} Pod32_Shdr;

typedef struct pod64_shdr {
  Pod64_Word sh_name;		/* Section name, index in string tbl */
  Pod64_Word sh_type;		/* Type of section */
  Pod64_Xword sh_flags;		/* Miscellaneous section attributes */
  Pod64_Addr sh_addr;		/* Section virtual addr at execution */
  Pod64_Off sh_offset;		/* Section file offset */
  Pod64_Xword sh_size;		/* Size of section in bytes */
  Pod64_Word sh_link;		/* Index of another section */
  Pod64_Word sh_info;		/* Additional section information */
  Pod64_Xword sh_addralign;	/* Section alignment */
  Pod64_Xword sh_entsize;	/* Entry size if section holds table */
} Pod64_Shdr;

#define	EI_MAG0		0		/* e_ident[] indexes */
#define	EI_MAG1		1
#define	EI_MAG2		2
#define	EI_MAG3		3
#define	EI_CLASS	4
#define	EI_DATA		5
#define	EI_VERSION	6
#define	EI_OSABI	7
#define	EI_PAD		8

#define	PODMAG0		0x7f		/* EI_MAG */
#define	PODMAG1		'P'
#define	PODMAG2		'O'
#define	PODMAG3		'D'
#define	PODMAG		"\177POD"
#define	SPODMAG		4

#define	PODCLASSNONE	0		/* EI_CLASS */
#define	PODCLASS32	1
#define	PODCLASS64	2
#define	PODCLASSNUM	3

#define PODDATANONE	0		/* e_ident[EI_DATA] */
#define PODDATA2LSB	1
#define PODDATA2MSB	2

#define EV_NONE		0		/* e_version, EI_VERSION */
#define EV_CURRENT	1
#define EV_NUM		2

#define PODOSABI_NONE	0
#define PODOSABI_LINUX	3

#ifndef POD_OSABI
#define POD_OSABI PODOSABI_NONE
#endif

/*
 * Notes used in ET_CORE. Architectures export some of the arch register sets
 * using the corresponding note types via the PTRACE_GETREGSET and
 * PTRACE_SETREGSET requests.
 */
#define NT_PRSTATUS	1
#define NT_PRFPREG	2
#define NT_PRPSINFO	3
#define NT_TASKSTRUCT	4
#define NT_AUXV		6
#define NT_PRXFPREG     0x46e62b7f      /* copied from gdb5.1/include/elf/common.h */
#define NT_PPC_VMX	0x100		/* PowerPC Altivec/VMX registers */
#define NT_PPC_SPE	0x101		/* PowerPC SPE/EVR registers */
#define NT_PPC_VSX	0x102		/* PowerPC VSX registers */
#define NT_386_TLS	0x200		/* i386 TLS slots (struct user_desc) */
#define NT_386_IOPERM	0x201		/* x86 io permission bitmap (1=deny) */
#define NT_X86_XSTATE	0x202		/* x86 extended state using xsave */
#define NT_S390_HIGH_GPRS	0x300	/* s390 upper register halves */
#define NT_S390_TIMER	0x301		/* s390 timer register */
#define NT_S390_TODCMP	0x302		/* s390 TOD clock comparator register */
#define NT_S390_TODPREG	0x303		/* s390 TOD programmable register */
#define NT_S390_CTRS	0x304		/* s390 control registers */
#define NT_S390_PREFIX	0x305		/* s390 prefix register */
#define NT_S390_LAST_BREAK	0x306	/* s390 breaking event address */
#define NT_S390_SYSTEM_CALL	0x307	/* s390 system call restart data */
#define NT_ARM_VFP	0x400		/* ARM VFP/NEON registers */


/* Note header in a PT_NOTE section */
typedef struct pod32_note {
  Pod32_Word	n_namesz;	/* Name size */
  Pod32_Word	n_descsz;	/* Content size */
  Pod32_Word	n_type;		/* Content type */
} Pod32_Nhdr;

/* Note header in a PT_NOTE section */
typedef struct pod64_note {
  Pod64_Word n_namesz;	/* Name size */
  Pod64_Word n_descsz;	/* Content size */
  Pod64_Word n_type;	/* Content type */
} Pod64_Nhdr;

#ifdef __KERNEL__
#if POD_CLASS == PODCLASS32

extern Pod32_Dyn _DYNAMIC [];
#define podhdr		pod32_hdr
#define pod_phdr	pod32_phdr
#define pod_shdr	pod32_shdr
#define pod_note	pod32_note
#define pod_addr_t	Pod32_Off
#define Pod_Half	Pod32_Half

#else

/*extern Pod64_Dyn _DYNAMIC [];*/
#define podhdr		pod64_hdr
#define pod_phdr	pod64_phdr
#define pod_shdr	pod64_shdr
#define pod_note	pod64_note
#define pod_addr_t	Pod64_Off
#define Pod_Half	Pod64_Half

#endif

/* Optional callbacks to write extra POD notes. */
#ifndef ARCH_HAVE_EXTRA_POD_NOTES
static inline int pod_coredump_extra_notes_size(void) { return 0; }
static inline int pod_coredump_extra_notes_write(struct file *file,
			loff_t *foffset) { return 0; }
#else
extern int pod_coredump_extra_notes_size(void);
extern int pod_coredump_extra_notes_write(struct file *file, loff_t *foffset);
#endif
#endif /* __KERNEL__ */

#define POD_ADD_VA(addr, type) __asm__ __volatile__("movq %0, %%rdx \n movq %0, %%r11 \n movb %1, %%al \n podaddva %%rdx, %%al" \
		    :        /* output */ \
		    :"g"(addr), "m"(type)         /* input */ \
		    :"%al", "%rdx", "%rax", "r10", "r11"        /* clobbered register */ \
		    );

#define PRIVATE_PATTERN 0xAA
#define PUBLIC_PATTERN 0xBB

static int podarch_private_flag  = 0xaa;
static int podarch_public_flag =  0xbb;
static int podarch_podenter_flag = 0xcc;
#endif /* _LINUX_POD_H */

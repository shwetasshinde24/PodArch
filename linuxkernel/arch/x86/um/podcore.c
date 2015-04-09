#include <linux/pod.h>
#include <linux/coredump.h>
#include <linux/fs.h>
#include <linux/mm.h>

#include <asm/pod.h>


Pod32_Half pod_core_extra_phdrs(void)
{
	return vsyscall_ehdr ? (((struct podhdr *)vsyscall_ehdr)->e_phnum) : 0;
}

int pod_core_write_extra_phdrs(struct file *file, loff_t offset, size_t *size,
			       unsigned long limit)
{
	if ( vsyscall_ehdr ) {
		const struct podhdr *const ehdrp =
			(struct podhdr *) vsyscall_ehdr;
		const struct pod_phdr *const phdrp =
			(const struct pod_phdr *) (vsyscall_ehdr + ehdrp->e_phoff);
		int i;
		Elf32_Off ofs = 0;

		for (i = 0; i < ehdrp->e_phnum; ++i) {
			struct pod_phdr phdr = phdrp[i];

			if (phdr.p_type == PT_LOAD) {
				ofs = phdr.p_offset = offset;
				offset += phdr.p_filesz;
			} else {
				phdr.p_offset += ofs;
			}
			phdr.p_paddr = 0; /* match other core phdrs */
			*size += sizeof(phdr);
			if (*size > limit
			    || !dump_write(file, &phdr, sizeof(phdr)))
				return 0;
		}
	}
	return 1;
}

int pod_core_write_extra_data(struct file *file, size_t *size,
			      unsigned long limit)
{
	if ( vsyscall_ehdr ) {
		const struct podhdr *const ehdrp =
			(struct podhdr *) vsyscall_ehdr;
		const struct pod_phdr *const phdrp =
			(const struct pod_phdr *) (vsyscall_ehdr + ehdrp->e_phoff);
		int i;

		for (i = 0; i < ehdrp->e_phnum; ++i) {
			if (phdrp[i].p_type == PT_LOAD) {
				void *addr = (void *) phdrp[i].p_vaddr;
				size_t filesz = phdrp[i].p_filesz;

				*size += filesz;
				if (*size > limit
				    || !dump_write(file, addr, filesz))
					return 0;
			}
		}
	}
	return 1;
}

size_t pod_core_extra_data_size(void)
{
	if ( vsyscall_ehdr ) {
		const struct podhdr *const ehdrp =
			(struct podhdr *)vsyscall_ehdr;
		const struct pod_phdr *const phdrp =
			(const struct pod_phdr *) (vsyscall_ehdr + ehdrp->e_phoff);
		int i;

		for (i = 0; i < ehdrp->e_phnum; ++i)
			if (phdrp[i].p_type == PT_LOAD)
				return (size_t) phdrp[i].p_filesz;
	}
	return 0;
}

#include <linux/pod.h>
#include <linux/fs.h>
#include <linux/mm.h>

#include <asm/pod.h>


Pod_Half __weak pod_core_extra_phdrs(void)
{
	return 0;
}

int __weak pod_core_write_extra_phdrs(struct file *file, loff_t offset, size_t *size,
				      unsigned long limit)
{
	return 1;
}

int __weak pod_core_write_extra_data(struct file *file, size_t *size,
				     unsigned long limit)
{
	return 1;
}

size_t __weak pod_core_extra_data_size(void)
{
	return 0;
}

/*
 * makepod: Make POD executable
 * Use: gcc -o makepod makepod.c -lcrypto
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <byteswap.h>
#include <elf.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include "utstring.h"

#include <endian.h>

struct signelf_info {
	char *in_file, *out_file, *privkey_file, *certificate_file;
	Elf64_Ehdr ehdr;
	Elf64_Phdr *phdr;
	unsigned char *integrity;
//	unsigned char *buf;
//	unsigned int buf_len;
	unsigned int integrity_len;
	unsigned char *pod_key;
	};

/*
 * Contains the pod key which gets into a section (plaintext as of now).
 * objcopy uses it
 */
char *tempkeysection_file = "/tmp/makepod.keysection";

/*
 * Contains the integrity which gets into a section (plaintext, no hash of integrity as of now).
 * objcopy uses it
 */
char *tempintsection_file = "./podintc";

char *tempbufsection_file = "/tmp/makepod.bufsection";


#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ELFDATANATIVE ELFDATA2LSB
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ELFDATANATIVE ELFDATA2MSB
#else
#error "Unknown machine endian"
#endif

static uint16_t file16_to_cpu(struct signelf_info *sinfo, uint16_t val)
{
	if (sinfo->ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
		val = bswap_16(val);
	return val;
}

static uint32_t file32_to_cpu(struct signelf_info *sinfo, uint32_t val)
{
	if (sinfo->ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
		val = bswap_32(val);
	return val;
}

static uint64_t file64_to_cpu(struct signelf_info *sinfo, uint64_t val)
{
	if (sinfo->ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
		val = bswap_64(val);
	return val;
}

static int read_elf32(struct signelf_info *sinfo, int fd)
{
	Elf32_Ehdr ehdr32;
	Elf32_Phdr *phdr32;
	size_t phdrs32_size;
	ssize_t ret = 0, i;

	ret = pread(fd, &ehdr32, sizeof(ehdr32), 0);
	if (ret != sizeof(ehdr32)) {
		fprintf(stdout, "Read of Elf header failed: %s\n",
			strerror(errno));
		return 1;
	}

	sinfo->ehdr.e_type	= file16_to_cpu(sinfo, ehdr32.e_type);
	sinfo->ehdr.e_machine	= file16_to_cpu(sinfo, ehdr32.e_machine);
	sinfo->ehdr.e_version	= file32_to_cpu(sinfo, ehdr32.e_version);
	sinfo->ehdr.e_entry	= file32_to_cpu(sinfo, ehdr32.e_entry);
	sinfo->ehdr.e_phoff	= file32_to_cpu(sinfo, ehdr32.e_phoff);
	sinfo->ehdr.e_shoff	= file32_to_cpu(sinfo, ehdr32.e_shoff);
	sinfo->ehdr.e_flags	= file32_to_cpu(sinfo, ehdr32.e_flags);
	sinfo->ehdr.e_ehsize	= file16_to_cpu(sinfo, ehdr32.e_ehsize);
	sinfo->ehdr.e_phentsize= file16_to_cpu(sinfo, ehdr32.e_phentsize);
	sinfo->ehdr.e_phnum	= file16_to_cpu(sinfo, ehdr32.e_phnum);
	sinfo->ehdr.e_shentsize= file16_to_cpu(sinfo, ehdr32.e_shentsize);
	sinfo->ehdr.e_shnum	= file16_to_cpu(sinfo, ehdr32.e_shnum);
	sinfo->ehdr.e_shstrndx	= file16_to_cpu(sinfo, ehdr32.e_shstrndx);

	if (sinfo->ehdr.e_version != EV_CURRENT) {
		fprintf(stdout, "Bad Elf header version %u\n",
			sinfo->ehdr.e_version);
		return 1;
	}
	if (sinfo->ehdr.e_phentsize != sizeof(Elf32_Phdr)) {
		fprintf(stdout, "Bad Elf program header size %u expected %zu\n",
			sinfo->ehdr.e_phentsize, sizeof(Elf32_Phdr));
		return 1;
	}
	phdrs32_size = sinfo->ehdr.e_phnum * sizeof(Elf32_Phdr);
	phdr32 = calloc(sinfo->ehdr.e_phnum, sizeof(Elf32_Phdr));
	if (!phdr32) {
		fprintf(stdout, "Calloc of %u phdrs32 failed: %s\n",
			sinfo->ehdr.e_phnum, strerror(errno));
		return 1;
	}

	sinfo->phdr = calloc(sinfo->ehdr.e_phnum, sizeof(Elf64_Phdr));
	if (!sinfo->phdr) {
		fprintf(stdout, "Calloc of %u phdrs failed: %s\n",
			sinfo->ehdr.e_phnum, strerror(errno));
		ret = 1;
		goto out_free_phdr32;
	}
	ret = pread(fd, phdr32, phdrs32_size, sinfo->ehdr.e_phoff);
	if (ret < 0 || (size_t)ret != phdrs32_size) {
		fprintf(stdout, "Read of program header  <at>  0x%llu for %zu bytes failed: %s\n",
			(unsigned long long)sinfo->ehdr.e_phoff, phdrs32_size, strerror(errno));
		ret = 1;
		goto out_free_phdr;
	}
	for (i = 0; i < sinfo->ehdr.e_phnum; i++) {
		sinfo->phdr[i].p_type = file32_to_cpu(sinfo, phdr32[i].p_type);
		sinfo->phdr[i].p_offset = file32_to_cpu(sinfo,
						phdr32[i].p_offset);
		sinfo->phdr[i].p_vaddr = file32_to_cpu(sinfo,
						phdr32[i].p_vaddr);
		sinfo->phdr[i].p_paddr = file32_to_cpu(sinfo,
						phdr32[i].p_paddr);
		sinfo->phdr[i].p_filesz = file32_to_cpu(sinfo,
						phdr32[i].p_filesz);
		sinfo->phdr[i].p_memsz = file32_to_cpu(sinfo,
						phdr32[i].p_memsz);
		sinfo->phdr[i].p_flags = file32_to_cpu(sinfo,
						phdr32[i].p_flags);
		sinfo->phdr[i].p_align = file32_to_cpu(sinfo,
						phdr32[i].p_align);
	}
	free(phdr32);
	return ret;

out_free_phdr:
	free(sinfo->phdr);
out_free_phdr32:
	free(phdr32);
	return ret;
}

static int read_elf64(struct signelf_info *sinfo, int fd)
{
	Elf64_Ehdr ehdr64;
	Elf64_Phdr *phdr64;
	size_t phdrs_size;
	ssize_t ret, i;

	ret = pread(fd, &ehdr64, sizeof(ehdr64), 0);
	if (ret < 0 || (size_t)ret != sizeof(sinfo->ehdr)) {
		fprintf(stdout, "Read of Elf header failed: %s\n",
			strerror(errno));
		return 1;
	}

	sinfo->ehdr.e_type	= file16_to_cpu(sinfo, ehdr64.e_type);
	sinfo->ehdr.e_machine	= file16_to_cpu(sinfo, ehdr64.e_machine);
	sinfo->ehdr.e_version	= file32_to_cpu(sinfo, ehdr64.e_version);
	sinfo->ehdr.e_entry	= file64_to_cpu(sinfo, ehdr64.e_entry);
	sinfo->ehdr.e_phoff	= file64_to_cpu(sinfo, ehdr64.e_phoff);
	sinfo->ehdr.e_shoff	= file64_to_cpu(sinfo, ehdr64.e_shoff);
	sinfo->ehdr.e_flags	= file32_to_cpu(sinfo, ehdr64.e_flags);
	sinfo->ehdr.e_ehsize	= file16_to_cpu(sinfo, ehdr64.e_ehsize);
	sinfo->ehdr.e_phentsize	= file16_to_cpu(sinfo, ehdr64.e_phentsize);
	sinfo->ehdr.e_phnum	= file16_to_cpu(sinfo, ehdr64.e_phnum);
	sinfo->ehdr.e_shentsize	= file16_to_cpu(sinfo, ehdr64.e_shentsize);
	sinfo->ehdr.e_shnum	= file16_to_cpu(sinfo, ehdr64.e_shnum);
	sinfo->ehdr.e_shstrndx	= file16_to_cpu(sinfo, ehdr64.e_shstrndx);

	if (sinfo->ehdr.e_version != EV_CURRENT) {
		fprintf(stdout, "Bad Elf header version %u\n",
			sinfo->ehdr.e_version);
		return 1;
	}
	if (sinfo->ehdr.e_phentsize != sizeof(Elf64_Phdr)) {
		fprintf(stdout, "Bad Elf program header size %u expected %zu\n",
			sinfo->ehdr.e_phentsize, sizeof(Elf64_Phdr));
		return 1;
	}
	phdrs_size = sinfo-> ehdr.e_phnum * sizeof(Elf64_Phdr);
	phdr64 = calloc(sinfo->ehdr.e_phnum, sizeof(Elf64_Phdr));
	if (!phdr64) {
		fprintf(stdout, "Calloc of %u phdrs64 failed: %s\n",
			sinfo->ehdr.e_phnum, strerror(errno));
		return 1;
	}
	sinfo->phdr = calloc(sinfo->ehdr.e_phnum, sizeof(Elf64_Phdr));
	if (!sinfo->phdr) {
		fprintf(stdout, "Calloc of %u phdrs failed: %s\n",
			sinfo->ehdr.e_phnum, strerror(errno));
		ret = 1;
		goto out_free_phdr64;
	}
	ret = pread(fd, phdr64, phdrs_size, sinfo->ehdr.e_phoff);
	if (ret < 0 || (size_t)ret != phdrs_size) {
		fprintf(stdout, "Read of program header  <at>  %llu for %zu bytes failed: %s\n",
			(unsigned long long)(sinfo->ehdr.e_phoff), phdrs_size, strerror(errno));
		ret = 1;
		goto out_free_phdr;
	}
	for (i = 0; i < sinfo->ehdr.e_phnum; i++) {
		sinfo->phdr[i].p_type = file32_to_cpu(sinfo, phdr64[i].p_type);
		sinfo->phdr[i].p_flags = file32_to_cpu(sinfo,
						phdr64[i].p_flags);
		sinfo->phdr[i].p_offset = file64_to_cpu(sinfo,
						phdr64[i].p_offset);
		sinfo->phdr[i].p_vaddr = file64_to_cpu(sinfo,
						phdr64[i].p_vaddr);
		sinfo->phdr[i].p_paddr = file64_to_cpu(sinfo,
						phdr64[i].p_paddr);
		sinfo->phdr[i].p_filesz = file64_to_cpu(sinfo,
						phdr64[i].p_filesz);
		sinfo->phdr[i].p_memsz = file64_to_cpu(sinfo,
						phdr64[i].p_memsz);
		sinfo->phdr[i].p_align = file64_to_cpu(sinfo,
						phdr64[i].p_align);
	}
	free(phdr64);
	return ret;

out_free_phdr:
	free(sinfo->phdr);
out_free_phdr64:
	free(phdr64);
	return ret;
}



#define PTLEN 4096
#define TAGLEN 16 
#define IVLEN 12 
#define AADLEN 20
#define KEYLEN 16
#define BUFLEN 4

static const unsigned char AAD[AADLEN] = { 
	0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
	0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
	0xab,0xad,0xda,0xd2
};

static const unsigned char IV[IVLEN] = { 
	0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88
};

static unsigned char* elf_write_binary_podint(struct signelf_info *sinfo){

	int ret, fd;

	fd = open(sinfo->out_file, O_RDWR);
	if (fd < 0) {
		fprintf(stdout, "Cannot open %s: %s\n",
				sinfo->out_file, strerror(errno));
		return NULL;
	}

	ret = pread(fd, sinfo->ehdr.e_ident, EI_NIDENT, 0);
	if (ret != EI_NIDENT) {
		fprintf(stdout, "Read of e_ident from %s failed: %s\n",
				sinfo->out_file, strerror(errno));
		ret = 1;
		goto out;
	}

	if (memcmp(sinfo->ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stdout, "Missing elf signature\n");
		ret = 1;
		goto out;
	}

	if (sinfo->ehdr.e_ident[EI_VERSION] != EV_CURRENT) {
		fprintf(stdout, "Bad elf version\n");
		ret = 1;
		goto out;
	}

	if ((sinfo->ehdr.e_ident[EI_CLASS] != ELFCLASS32) &&
	    (sinfo->ehdr.e_ident[EI_CLASS] != ELFCLASS64))
	{
		fprintf(stdout, "Unknown elf class %u\n",
				sinfo->ehdr.e_ident[EI_CLASS]);
		ret = 1;
		goto out;
	}

	if ((sinfo->ehdr.e_ident[EI_DATA] != ELFDATA2LSB) &&
	    (sinfo->ehdr.e_ident[EI_DATA] != ELFDATA2MSB))
	{
		fprintf(stdout, "Unkown elf data order %u\n",
				sinfo->ehdr.e_ident[EI_DATA]);
		ret = 1;
		goto out;
	}

	if (sinfo->ehdr.e_ident[EI_CLASS] == ELFCLASS32)
		ret = read_elf32(sinfo, fd);
	else
		ret = read_elf64(sinfo, fd);

	fd = open(sinfo->out_file, O_RDWR);
	if (fd < 0) {
		fprintf(stdout, "Cannot open %s: %s\n",
				sinfo->out_file, strerror(errno));
		return NULL;
	}
	Elf64_Ehdr *ehdr = &sinfo->ehdr;
	size_t rem_file_sz, file_sz;
	size_t offset;
	int retval, i;
	unsigned int int_len;
	unsigned int write_len;
	Elf64_Shdr *elf_shtable, *elf_spnt, *elf_shstrpnt;
	unsigned int  shtable_sz;
	uint16_t shstrndx;
	bool found_podid_section = false;

	if (!ehdr->e_shnum){
		printf("Error\n");
		return NULL;
	}
	if (ehdr->e_shstrndx == SHN_UNDEF){
		printf("Error\n");
		return NULL;
	}
	/* Read in elf section table */
//	file_sz = i_size_read(file->f_path.dentry->d_inode);
	shtable_sz = ehdr->e_shnum * sizeof(Elf64_Shdr);
	elf_shtable = malloc(shtable_sz);
	if (!elf_shtable){
		printf("Error\n");
		return NULL;
	}
	retval = pread(fd, elf_shtable,shtable_sz, ehdr->e_shoff);
	if (retval != shtable_sz) {
		if (retval >= 0)
			retval = -EIO;
		printf("Error\n");
		goto out_free_shtable;
	}

	/* if (ehdr->e_shstrndx == 0xffff) */
	/* 	shstrndx = elf_shtable[0]->sh_link; */
	/* else */
		shstrndx = ehdr->e_shstrndx;

	if (shstrndx >= ehdr->e_shnum) {
		retval = -EINVAL;
		printf("Error\n");
		goto out_free_shtable;
	}

	elf_shstrpnt = elf_shtable + shstrndx;
	elf_spnt = elf_shtable;

	/* Scan for section with name ".pod_int" */
	for (i = 0; i < ehdr->e_shnum; i++) {
		char sec_name[9];
		offset = elf_shstrpnt->sh_offset + elf_spnt->sh_name;
		retval = pread(fd, sec_name, 9, offset);
		if (retval != 9) {
			if (retval >= 0)
				retval = -EIO;
			printf("Error\n");
			goto out_free_shtable;
		}

		if(!strcmp(sec_name, ".pod_int")) {
			found_podid_section = true;
			break;
		}
		elf_spnt++;
	}
	
	if (!found_podid_section) {
		/* File is not pod-enabled */
		retval = 0;
		printf("Not found pod_int\n");
		goto out_free_shtable;
	}
	else
		printf("Found pod_int\n");
	

	/* Read in sig info */
//	sig_info_sz = sizeof(struct elf_sig_info);
   	
	int_len = elf_spnt->sh_size;
	if(int_len!=sinfo->integrity_len){
		printf("int_len!=sinfo->integrity_len\n");
		goto out_free_shtable;
	}
	
	offset = elf_spnt->sh_offset;
    
	write_len = pwrite(fd, sinfo->integrity,sinfo->integrity_len, offset);
	if (write_len == -1) {
		fprintf(stdout, "Failed to write:%s\n",
				strerror(errno));
		printf("Error\n");
		goto out_free_shtable;
	}

	if (write_len != int_len) {
		fprintf(stdout, "Failed to write %du bytes."
				" Read %u bytes:%s\n", int_len, write_len, strerror(errno));
		printf("Error\n");
		goto out_free_shtable;
		
	}

	if (write_len == 0){
		printf("write_len=0, Aborting\n");
		goto out_free_shtable;
	}

	/* retval = pread(fd, pod_int_data, int_len, offset); */
	/* if (retval != int_len) { */
	/* 	pod_int_data = NULL; */
	/* 	if (retval >= 0) */
	/* 		retval = -EIO; */
	/* 	goto out_free_key; */
	/* } */
	free(elf_shtable);
	/* int j; */
	/* for(i=0;i<int_len; i+=16){ */
	/* 	for(j=0;j<16;j++) */
	/* 		printf("(%x)",pod_int_data[i+j]); */
	/* 	printf("\n"); */
	/* } */
		
	return sinfo->integrity;

out_free_shtable:
	free(elf_shtable);
out:
	close(fd);
	return NULL;
}

static int encrypt_and_hash_elf(struct signelf_info *sinfo){


	const EVP_CIPHER *gcm = EVP_aes_128_gcm();
	unsigned char *tmp_ptr = NULL;
	unsigned char *integritybuf = NULL; 
	unsigned char* bufbuf = NULL;
	unsigned int currentintsize = 0;
	unsigned int currentbufsize = 0;
	unsigned char *ctbuf; 
	unsigned char tagbuf[TAGLEN]; 
	int page_count = 0;
	unsigned char *CT; 
	unsigned int buf_len;
	unsigned int write_len;
	//unsigned char buf[PTLEN+1000];
	unsigned char *buf;
	
	int i,z,y;
	size_t sz = 0, sz_done = 0, sz_rem = 0;
	int ret;
	int first_segment = 1;

	int fd = open(sinfo->out_file, O_RDWR);
	if (fd < 0) {
		fprintf(stdout, "Cannot open %s: %s\n",
				sinfo->out_file, strerror(errno));
		return 1;
	}

	for (i = 0; i < sinfo->ehdr.e_phnum, first_segment!=0; i++) {

		if (sinfo->phdr[i].p_type != PT_LOAD)
			continue;

        page_count = 0;		
		loff_t offset;
		size_t to_read;
		offset = sinfo->phdr[i].p_offset;
		sz = sinfo->phdr[i].p_filesz;
		unsigned int base = 0x6d1000;
		
	
		if(first_segment){
			first_segment = 0;
			offset = offset + 4096;
			sz = sz - 4096;
			base = 0x401000;
		}
		else{
			offset = 0xd1000;
            sz = 0x2290;
        }


        
		;//	sz = 0x3000;
		/* Calculate hash of PT_LOAD area contents */
		/* Skip if segment size is 0 (bss) */

		sz_rem = sz;
		to_read = PTLEN;
		sz_done = 0;

		while (sz_rem)  {
			if (sz_rem < to_read)
				to_read = sz_rem;
			int howmany, dec_success, len,howmany1;

			buf = (unsigned char*)malloc(PTLEN);	
			memset(buf, 0, PTLEN);
			buf_len = pread(fd,(unsigned char*) buf,to_read, offset);
			if (buf_len == -1) {
				fprintf(stdout, "Failed to read:%s\n",
						strerror(errno));
				return 1;
			}

			
			if (buf_len != to_read) {
				fprintf(stdout, "Failed to read %lu bytes."
						" Read %u bytes:%s\n",
						to_read, buf_len, strerror(errno));
				return 1;
			}

			if (buf_len == 0)
				break;
//			if(((page_count*4096)+base)!=0x446000){ // && ((page_count*4096)+base)!=0x4b4000 && ((page_count*4096)+base)!=0x497000){ // && ((page_count*4096)+base)!=0x40e000){ */
//			if(((page_count*4096)+base)!=0x4b1000 && ((page_count*4096)+base)!=0x4dd000 && ((page_count*4096)+base)!=0x4b3000 && ((page_count*4096)+base)!=0x4de000 && ((page_count*4096)+base)!=0x4b2000 && ((page_count*4096)+base)!=0x4b4000){
			CT = (unsigned char*)malloc(PTLEN);	
			memset(CT, 0, PTLEN);
			EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
			EVP_EncryptInit (ctx, gcm, sinfo->pod_key, IV);
			EVP_EncryptUpdate (ctx, NULL, &howmany, AAD, AADLEN);

			/* Process the plaintext */
			EVP_EncryptUpdate (ctx, CT, &howmany, buf, buf_len);
			
			//if//(((page_count*4096)+base)!=0x495000){
			
/*				Write ciphertext back to file*/
            write_len = pwrite(fd, (unsigned char*)CT, buf_len, offset);
			if (write_len == -1) {
				fprintf(stdout, "Failed to write:%s\n",
						strerror(errno));
				return 1;
			}

			if (write_len != buf_len) {
				fprintf(stdout, "Failed to write %du bytes."
						"Read %u bytes:%s\n", buf_len, write_len, strerror(errno));
				return 1;
			}

			if (write_len == 0){
				printf("write_len=0, Aborting\n");
				break;
			}
			EVP_EncryptFinal (ctx, tagbuf, &howmany);
			EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, TAGLEN, tagbuf);
			EVP_CIPHER_CTX_free(ctx);
			

			tmp_ptr = realloc(integritybuf, currentintsize + TAGLEN + BUFLEN + 12);
			if(tmp_ptr==NULL){
				printf("Failed to catch integrity\n");
				return 1;
			}
			integritybuf = tmp_ptr;
			tmp_ptr = NULL;
			//integritybuf[currentintsize] = ',';
			for(z=0;z<TAGLEN;z++)
				integritybuf[currentintsize+z] = tagbuf[z];

			unsigned char tempbuflen[5];
			int nlen = snprintf(tempbuflen, 5, "%04d", buf_len);
			

			/* tmp_ptr = realloc(bufbuf, currentbufsize + 4); */
			/* if(tmp_ptr==NULL){ */
			/* 	printf("Failed to catch buf\n"); */
			/* 	return 1; */
			/* } */
			/* bufbuf = tmp_ptr; */
			/* tmp_ptr = NULL; */
			for(z=0;z<BUFLEN;z++)
				integritybuf[currentintsize+TAGLEN+z] = tempbuflen[z];
			
			//printf("buf_len=%s\n",tempbuflen);
			printf("START 0x%x: *",(page_count*4096)+base);
			for(z=currentintsize; z<(currentintsize+TAGLEN);z++){
			 	printf("(%x)",(unsigned char)integritybuf[z]);
			}
			printf("*\n");
			/* for(y=0;y<buf_len;y++) */
			/* 	printf("(%x)",(unsigned char)CT[y]); */
			/* printf("\n"); */
			/* printf("END\n"); */
		
			/* printf("%d: START-TAG*",page_count); */
			/*  for(z=0;z<TAGLEN;z++){ */
			/*  	printf("(%x)",tagbuf[z]); */
			/*  } */
			/*  printf("*END-TAG\n"); */ 

			free(CT);
//			}
			currentintsize = currentintsize+TAGLEN+BUFLEN+12;
			//currentbufsize = currentbufsize+4;
			free(buf);			
			sz_rem -= buf_len;
			sz_done += buf_len;
			offset += buf_len;

			to_read = sz_rem;
			if (to_read > PTLEN)
				to_read = PTLEN;

			page_count++;
		}
		 
		//	printf("page_count=%d, currentbufsize=%d, intsize=%d\n",page_count,currentbufsize, currentintsize);
		if (sz_done != sz) {
			fprintf(stdout, "Could not encrypt %lu bytes. Encrypted"
					" only %lu bytes\n", sz, sz_done);
			return 1;
		}
	
	}
	
	sinfo->integrity = (unsigned char*)malloc(currentintsize);
	sinfo->integrity_len = currentintsize;
	
	int j;
	for(j=0;j<currentintsize;j++)
		sinfo->integrity[j]=integritybuf[j];
	
	/* sinfo->buf = (unsigned char*)malloc(currentbufsize); */
	/* sinfo->buf_len = currentbufsize; */
	/* for(j=0;j<currentbufsize;j++) */
	/* 	sinfo->buf[j]=bufbuf[j]; */

	
#ifdef DEBUG
	print_digest(sinfo);
#endif
	return 0;
}


static int read_pod_key(struct signelf_info *sinfo)
{
	/* allocate memory for signature */
	sinfo->pod_key = (unsigned char*)malloc(KEYLEN);

	/* Read pod application key from file */
	FILE *keyfd = fopen(sinfo->privkey_file,"r");
	if(keyfd!=NULL){
		if(fgets(sinfo->pod_key, KEYLEN+1, keyfd ) == NULL){
			printf("Error: Cannot read key from key file\n");
			fclose(keyfd);
			return 1;
		}
	}
//	printf("KEY=%s\n",sinfo->pod_key);
    fclose(keyfd);
	return 0;
}


static int add_podkey_in_a_section(struct signelf_info *sinfo)
{
	FILE *outfp = NULL;
	int ret = 0, exit_code;
	unsigned int written;
	char command[1024];

	outfp = fopen(tempkeysection_file, "w");
	if (!outfp) {
		fprintf(stdout, "Failed to open %s:%s\n", tempkeysection_file,
				strerror(errno));
		return 1;
	}

	/* Write pod key into temp file */
	written = fwrite(sinfo->pod_key, 1, KEYLEN, outfp);
	if (written != KEYLEN) {
		fprintf(stdout, "Failed to write pod key to file %s\n",
				tempkeysection_file);
		ret = 1;
		goto out_close_outfp;
	}

	/* Add pod_id section */
	fclose(outfp);
	snprintf(command, 1024, "objcopy --add-section .pod_id=%s %s %s", tempkeysection_file, sinfo->in_file, sinfo->out_file);
	ret = system(command);
	if (ret == -1) {
		fprintf(stdout, "Failed to execute system(%s)\n", command);
		goto out_close_outfp;
	}

	exit_code = WEXITSTATUS(ret);
	ret = exit_code;
	if (ret)
		goto out_close_outfp;
	return ret;
out_close_outfp:
	fclose(outfp);
	return ret;
}

static int add_integrity_in_a_section(struct signelf_info *sinfo)
{
	FILE *outfp;
	int ret = 0, exit_code;
	unsigned int written;
	char command[1024];

	outfp = fopen(tempintsection_file, "w");
	if (!outfp) {
		fprintf(stdout, "Failed to open %s:%s\n", tempintsection_file,
				strerror(errno));
		return 1;
	}

	/* Write integrity into temp file */
	written = fwrite(sinfo->integrity, 1, sinfo->integrity_len, outfp);
	if (written != sinfo->integrity_len) {
		fprintf(stdout, "Failed to write pod integrity to file %s\n",
				tempintsection_file);
		ret = 1;
		goto out_close_outfp;
	}

	/* Add .pod_int section */
	fclose(outfp);
	/* snprintf(command, 1024, "objcopy --add-section .pod_int=%s %s %s", tempintsection_file, sinfo->out_file, sinfo->out_file); */
	/* ret = system(command); */
	/* if (ret == -1) { */
	/* 	fprintf(stdout, "Failed to execute system(%s)\n", command); */
	/* 	goto out_close_outfp; */
	/* } */

	exit_code = WEXITSTATUS(ret);
	ret = exit_code;
	if (ret)
		goto out_close_outfp;
	return ret;
out_close_outfp:
	fclose(outfp);
	return ret;
}

/* static int add_buflen_in_a_section(struct signelf_info *sinfo) */
/* { */
/* 	FILE *outfp; */
/* 	int ret = 0, exit_code; */
/* 	unsigned int written; */
/* 	char command[1024]; */

/* 	outfp = fopen(tempbufsection_file, "w"); */
/* 	if (!outfp) { */
/* 		fprintf(stdout, "Failed to open %s:%s\n", tempbufsection_file, */
/* 				strerror(errno)); */
/* 		return 1; */
/* 	} */

/* 	/\* Write buf into temp file *\/ */
/* 	written = fwrite(sinfo->buf, 1, sinfo->buf_len, outfp); */
/* 	if (written != sinfo->buf_len) { */
/* 		fprintf(stdout, "Failed to write pod buflen to file %s\n", */
/* 				tempbufsection_file); */
/* 		ret = 1; */
/* 		goto out_close_outfp; */
/* 	} */

/* 	/\* Add .pod_buf section *\/ */
/* 	fclose(outfp); */
/* 	snprintf(command, 1024, "objcopy --add-section .pod_buf=%s %s %s", tempbufsection_file, sinfo->out_file, sinfo->out_file); */
/* 	ret = system(command); */
/* 	if (ret == -1) { */
/* 		fprintf(stdout, "Failed to execute system(%s)\n", command); */
/* 		goto out_close_outfp; */
/* 	} */

/* 	exit_code = WEXITSTATUS(ret); */
/* 	ret = exit_code; */
/* 	if (ret) */
/* 		goto out_close_outfp; */
/* 	return ret; */
/* out_close_outfp: */
/* 	fclose(outfp); */
/* 	return ret; */
/* } */



static int sign_elf_executable(struct signelf_info *sinfo)
{
	int ret, fd;

	fd = open(sinfo->in_file, O_RDONLY);
	if (fd < 0) {
		fprintf(stdout, "Cannot open %s: %s\n",
				sinfo->in_file, strerror(errno));
		return 1;
	}

	ret = pread(fd, sinfo->ehdr.e_ident, EI_NIDENT, 0);
	if (ret != EI_NIDENT) {
		fprintf(stdout, "Read of e_ident from %s failed: %s\n",
				sinfo->in_file, strerror(errno));
		ret = 1;
		goto out;
	}

	if (memcmp(sinfo->ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stdout, "Missing elf signature\n");
		ret = 1;
		goto out;
	}

	if (sinfo->ehdr.e_ident[EI_VERSION] != EV_CURRENT) {
		fprintf(stdout, "Bad elf version\n");
		ret = 1;
		goto out;
	}

	if ((sinfo->ehdr.e_ident[EI_CLASS] != ELFCLASS32) &&
	    (sinfo->ehdr.e_ident[EI_CLASS] != ELFCLASS64))
	{
		fprintf(stdout, "Unknown elf class %u\n",
				sinfo->ehdr.e_ident[EI_CLASS]);
		ret = 1;
		goto out;
	}

	if ((sinfo->ehdr.e_ident[EI_DATA] != ELFDATA2LSB) &&
	    (sinfo->ehdr.e_ident[EI_DATA] != ELFDATA2MSB))
	{
		fprintf(stdout, "Unkown elf data order %u\n",
				sinfo->ehdr.e_ident[EI_DATA]);
		ret = 1;
		goto out;
	}

	if (sinfo->ehdr.e_ident[EI_CLASS] == ELFCLASS32)
		ret = read_elf32(sinfo, fd);
	else
		ret = read_elf64(sinfo, fd);

	if (!ret)
		goto out;

    if(read_pod_key(sinfo)){
		ret = 1;
		goto out;
	}
	
	ret = add_podkey_in_a_section(sinfo);
	if (ret) {
	 	fprintf(stdout, "Error while putting pod key into an elf"
				" section\n");
	 	goto out;
	}
	
	if (encrypt_and_hash_elf(sinfo)) {
		ret = 1;
		goto out;
	}
	
	ret = add_integrity_in_a_section(sinfo);
	if (ret) {
	 	fprintf(stdout, "Error while putting integrity into an elf"
				" section\n");
	 	goto out;
	}

	/* ret = add_buflen_in_a_section(sinfo); */
	/* if (ret) { */
	/*  	fprintf(stdout, "Error while putting buf into an elf" */
	/* 			" section\n"); */
	/*  	goto out; */
	/* } */

	/* if(elf_write_binary_podint(sinfo)==NULL){ */
	/* 	fprintf(stdout, "Error while writing pod_int into the elf\n"); */
	/* 	goto out; */
	/* } */

out:
	close(fd);
	return ret;
}

static void print_help()
{
	printf("Usage: makepod [OPTION...]\n");
	printf(" -i, --in=<infile>\t\t\t\tspecify input file\n");
	printf(" -k, --appkey=<appkeyfile>\t\t\tspecify application key file\n");
	printf(" -c, --cpukey=<cpukeyfile>\t\t\tspecify cpu public key file\n");
	printf(" -o, --out=<outfile>\t\t\t\tspecify output file\n");
}

static void free_sinfo_members(struct signelf_info *sinfo)
{
	free(sinfo->in_file);
	free(sinfo->out_file);
	free(sinfo->privkey_file);
	free(sinfo->certificate_file);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	char *option_string = "hi:k:c:o:", c;
	struct signelf_info *sinfo, signelf_info;

	struct option long_options[] =
		{
			{"help", no_argument, 0, 'h'},
			{"in", required_argument, 0, 'i'},
			{"appkey", required_argument, 0, 'k'},
			{"cpukey", required_argument, 0, 'c'},
			{"out", required_argument, 0, 'o'},
			{ 0, 0, 0, 0}
		};

	if (argc < 2) {
		print_help();
		exit(1);
	}

	sinfo = &signelf_info;
	memset(sinfo, 0, sizeof(struct signelf_info));

	while((c = getopt_long(argc, argv, option_string, &long_options[0],
	       NULL)) != -1) {
		switch(c) {
		case '?':
			/* Unknown option or missing argument*/
			print_help();
			exit(1);
		case 'h':
			print_help();
			exit(0);
		case 'i':
			sinfo->in_file = strdup(optarg);
			if (!sinfo->in_file) {
				fprintf(stdout, "Can't duplicate string:%s\n",
						strerror(errno));
				exit(1);
			}
			break;
		case 'k':
			sinfo->privkey_file = strdup(optarg);
			if (!sinfo->privkey_file) {
				fprintf(stdout, "Can't duplicate string:%s\n",
					strerror(errno));
				exit(1);
			}
			break;
		case 'c':
			sinfo->certificate_file = strdup(optarg);
			if (!sinfo->certificate_file) {
				fprintf(stdout, "Can't duplicate string:%s\n",
					strerror(errno));
				exit(1);
			}
			break;
		case 'o':
			sinfo->out_file = strdup(optarg);
			if (!sinfo->out_file) {
				fprintf(stdout, "Can't duplicate string:%s\n",
					strerror(errno));
				exit(1);
			}
			break;
		default:
			printf("Unexpected option\n");
			exit(1);
		}
	}

	if (!sinfo->in_file || !sinfo->out_file || !sinfo->privkey_file ||
	    !sinfo->certificate_file) {
		print_help();
		exit(1);
	}

	ret = sign_elf_executable(sinfo);

	free_sinfo_members(sinfo);
	//remove(tempintsection_file);
	remove(tempkeysection_file);

	exit(ret);
}

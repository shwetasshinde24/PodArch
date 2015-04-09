/*
 *  Software MMU support
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu-timer.h"
#include <openssl/evp.h>
#include <stdbool.h>
#define DATA_SIZE (1 << SHIFT)

#if DATA_SIZE == 8
#define SUFFIX q
#define USUFFIX q
#define DATA_TYPE uint64_t
#elif DATA_SIZE == 4
#define SUFFIX l
#define USUFFIX l
#define DATA_TYPE uint32_t
#elif DATA_SIZE == 2
#define SUFFIX w
#define USUFFIX uw
#define DATA_TYPE uint16_t
#elif DATA_SIZE == 1
#define SUFFIX b
#define USUFFIX ub
#define DATA_TYPE uint8_t
#else
#error unsupported data size
#endif

#ifdef SOFTMMU_CODE_ACCESS
#define READ_ACCESS_TYPE 2
#define ADDR_READ addr_code
#else
#define READ_ACCESS_TYPE 0
#define ADDR_READ addr_read
#endif

static DATA_TYPE glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                        int mmu_idx,
                                                        void *retaddr);
static inline DATA_TYPE glue(io_read, SUFFIX)(target_phys_addr_t physaddr,
                                              target_ulong addr,
                                              void *retaddr)
{
    DATA_TYPE res;
    int index;
    index = (physaddr >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);
    physaddr = (physaddr & TARGET_PAGE_MASK) + addr;
    env->mem_io_pc = (unsigned long)retaddr;
    if (index > (IO_MEM_NOTDIRTY >> IO_MEM_SHIFT)
            && !can_do_io(env)) {
        cpu_io_recompile(env, retaddr);
    }

    env->mem_io_vaddr = addr;
#if SHIFT <= 2
    res = io_mem_read[index][SHIFT](io_mem_opaque[index], physaddr);
#else
#ifdef TARGET_WORDS_BIGENDIAN
    res = (uint64_t)io_mem_read[index][2](io_mem_opaque[index], physaddr) << 32;
    res |= io_mem_read[index][2](io_mem_opaque[index], physaddr + 4);
#else
    res = io_mem_read[index][2](io_mem_opaque[index], physaddr);
    res |= (uint64_t)io_mem_read[index][2](io_mem_opaque[index], physaddr + 4) << 32;
#endif
#endif /* SHIFT > 2 */
    return res;
}

#define TAGLEN 16 
#define IVLEN 12 
#define AADLEN 20
#define KEY_SIZE 16
#define PAGE_SIZE 4096




#define POD_PAGE_SHIFT      12
#define POD_PAGE_SIZE       (1 << POD_PAGE_SHIFT)
#define POD_PAGE_MASK       (~(POD_PAGE_SIZE-1))

/* handle all cases except unaligned access which span two pages */
DATA_TYPE REGPARM glue(glue(__ld, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                      int mmu_idx)
{
	static const unsigned char AAD[AADLEN] = {
    0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
    0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
    0xab,0xad,0xda,0xd2
};

static const unsigned char IV[IVLEN] = {
    0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88
};  
	

	DATA_TYPE res;
    int index;
    target_ulong tlb_addr;
    target_phys_addr_t ioaddr;
    unsigned long addend;
    void *retaddr;
    int redo_flag=0;

	
    /* test if there is match for unaligned or IO access */
    /* XXX: could done more in memory macro in a non portable way */
	
    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo:

    tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {


	
     		cr3_keyStruct *ccurrent;
			unsigned long *cr3_ptr;
			cr3_ptr = &env->cr[3];
			HASH_FIND(chh, cr3_table, cr3_ptr, sizeof(target_ulong), ccurrent);
			if(ccurrent){ /* check if it's a pod-enabled app */
				//			printf("Found a pod-enabled app:%" PRIu64 " \n", ccurrent->key);

				if(ccurrent->key==Reg_kapp){ /* check the current executing authority */
			
					target_ulong mask_addr = addr & POD_PAGE_MASK;
					if((mask_addr>start_code_address && mask_addr<end_code_address)){//|| (mask_addr>=(brk_start_address) && mask_addr<=(brk_end_address))){// && mask_addr!=0x495000 && mask_addr!=0x497000 && mask_addr!=0x4b4000){ //&& mask_addr!=0x702000
	
						//					printf("Inside podload: 0x%x\n", addr & POD_PAGE_MASK);

						IPACT_struct *item;
						unsigned char *pod_int_host_va;					
						target_ulong temp_ppn = ((addr & TARGET_PAGE_MASK)+env->tlb_table[mmu_idx][index].addend); /* page number */
//						printf("Address translation for vaddr=0x%x, host_va=0x%x\n",addr, temp_ppn);
						HASH_FIND(ghh, pod_table, &temp_ppn, sizeof(target_ulong), item);
						if(item==NULL){ /* page fault, load entry into IPACT */
//				    printf("Item==NULL, adding entry into IPACT: 0x%x\n", temp_ppn);
							item = (IPACT_struct*)malloc(sizeof(IPACT_struct));
							memset(item, 0, sizeof(IPACT_struct));
							item->kapp = Reg_kapp;
							item->ppn = temp_ppn;
							item->vpn = addr & POD_PAGE_MASK; /* page number */
							item->swap_bit = true; /* true=E, false=D */
							item->private_bit = true; /* true=private, false=public - this is obvious*/
							// fixme pod_set_page_permn(item,permn);
//							printf("Calling get_int_addr1\n");
							target_ulong pod_int_address = get_int_address(addr);
							int pod_mmu_idx = get_mmuidx(addr);

							int pod_int_index = (pod_int_address >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
							target_ulong pod_int_tlb_addr = env->tlb_table[pod_mmu_idx][pod_int_index].ADDR_READ;
							//	printf("pod_int_address=0x%x, mmu_idx=%d,  pod_int_index=%d, pod_int_tlb_addr=0x%x\n",pod_int_address, pod_mmu_idx, pod_int_index, pod_int_tlb_addr);
							if ((pod_int_address & TARGET_PAGE_MASK) == (pod_int_tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))){		
						 
								pod_int_host_va = (unsigned char*)((pod_int_address)+env->tlb_table[pod_mmu_idx][pod_int_index].addend);
								int z;
//								printf("pod_int_address START 0x%x: *",pod_int_address);
								for(z=0;z<TAGLEN;z++){
									item->integrity_tag[z] = (unsigned char)*((unsigned char*)pod_int_host_va+(int)z); 
									//	printf("(%x)",item->integrity_tag[z]);
								}
								//	printf("*\n");
								unsigned char pod_buf_var[5];
								for(z=0;z<4;z++){
									pod_buf_var[z] = (unsigned char)*((unsigned char*)pod_int_host_va+TAGLEN+(int)z); 
								}
								pod_buf_var[4] = '\0';
								char *stopstring; 
								item->buflen = strtoull(pod_buf_var, &stopstring, 10);
								//	printf("buflen=%llu\n",item->buflen);
							}
							else{ /* VDF */
								goto VDF_time;
							}
								
						hash_add0:
							HASH_ADD(ghh, pod_table, ppn, sizeof(target_ulong), item);
						}
						else;// printf("Item already in IPACT, now check if we need to decrypt it\n");
//						print_regkapp("Encyption level 1");
//						printf("Found vaddr=0x%x,SB=%d in IPACT\n", item->vpn, item->swap_bit);
						if(item->swap_bit){ /* it's encrypted, so decrypt it */						
//							printf("Encryption level 2\n");
							item->swap_bit = false;
							pod_num_decrypt++;
							int i, dec_success, howmany1;
							unsigned char *pod_host_va;
							unsigned char *CT;
							unsigned char Key[KEY_SIZE];
							EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
							const EVP_CIPHER *gcm = EVP_aes_128_gcm();
							unsigned char *tag;
							unsigned char *ptbuf;
							int thesize = item->buflen; //ensure buflen is fetched
				
							tag = item->integrity_tag;
							pod_host_va = (unsigned char*)((addr & TARGET_PAGE_MASK)+env->tlb_table[mmu_idx][index].addend);
				
//							printf("pod_address START 0x%x: *",addr & POD_PAGE_MASK);
							//	for(i=0;i<TAGLEN;i++)
							//	printf("(%x)",item->integrity_tag[i]);
							//printf("*\n");
							CT = (unsigned char*)malloc(PAGE_SIZE);
							memset(CT, 0, PAGE_SIZE);
							for(i=0;i<thesize;i++){
								*((unsigned char*)CT+(int)i) = (unsigned char)*((unsigned char*)pod_host_va+(int)i);
								//	printf("(%x)",(unsigned char)CT[i]);
							}
							//	printf("\n");
							//printf("END\n");
				
							/* /\* fetching key from Reg_kapp *\/ */
							int nlen = snprintf(NULL, 0, "%"PRIu64, Reg_kapp);
							assert(nlen > 0);
							assert(nlen == KEY_SIZE);
							unsigned char tempkeybuf[nlen+1];
							int clen = snprintf(tempkeybuf, nlen+1, "%"PRIu64, Reg_kapp);
							assert(tempkeybuf[nlen] == '\0');
							assert(clen == nlen);

							for(i=0;i<KEY_SIZE;i++)
								Key[i] = tempkeybuf[i];
							ptbuf = (unsigned char*) malloc(PAGE_SIZE);
							memset(ptbuf, 0, PAGE_SIZE);
//				printf("Encryption starts with KEY:*%s*\n",tempkeybuf);

							ctx = EVP_CIPHER_CTX_new();
							EVP_DecryptInit (ctx, gcm, Key, IV);
							EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, TAGLEN, tag);
							EVP_DecryptInit (ctx, NULL, Key, IV);
							EVP_DecryptUpdate (ctx, NULL, &howmany1, AAD, AADLEN);

							EVP_DecryptUpdate (ctx, ptbuf, &howmany1, CT, thesize);
				
							dec_success = EVP_DecryptFinal (ctx, tag, &howmany1);
							EVP_CIPHER_CTX_free(ctx);

							if(dec_success){
//								printf("\nGCM works!\n");
								for(i=0;i<thesize;i++)
									*((unsigned char*)pod_host_va+(int)i) = (unsigned char)*((unsigned char*)ptbuf + (int)i);
							} else {
//								printf("\nGCM failed at vaddr=0x%x!\n",item->vpn);
							}
							free(CT);
							free(ptbuf);
						}
						else;// printf("Page already decrypted\n");
					}
				}
			}
	out:	
        if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access;
            retaddr = GETPC();
            ioaddr = env->iotlb[mmu_idx][index];
            res = glue(io_read, SUFFIX)(ioaddr, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
            /* slow unaligned access (it spans two pages or IO) */
        do_unaligned_access:
            retaddr = GETPC();
#ifdef ALIGNED_ONLY

            do_unaligned_access(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
#endif
            res = glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(addr,
                                                         mmu_idx, retaddr);
        } else {
            /* unaligned/aligned access in the same page */
#ifdef ALIGNED_ONLY
            if ((addr & (DATA_SIZE - 1)) != 0) {
                retaddr = GETPC();
                do_unaligned_access(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
            }
#endif
            addend = env->tlb_table[mmu_idx][index].addend;
            res = glue(glue(ld, USUFFIX), _raw)((uint8_t *)(long)(addr+addend));

		}
    } else {
        /* the page is not in the TLB : fill it */
        retaddr = GETPC();
#ifdef ALIGNED_ONLY
        if ((addr & (DATA_SIZE - 1)) != 0)
            do_unaligned_access(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
#endif

			VDF_time:
		if(Reg_kapp){
//			printf("Calling get_int_address\n");
			target_ulong pod_int_address = get_int_address(addr);
			if(pod_int_address==0)
				goto out_pod_fill;
			int pod_mmu_idx = get_mmuidx(addr);
                        int temp_index = (pod_int_address >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
                        target_ulong temp_tlb_addr = env->tlb_table[pod_mmu_idx][temp_index].ADDR_READ;
			if ((pod_int_address & TARGET_PAGE_MASK) != (temp_tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))){
		
//				printf("Calling VDF for 0x%x\n", pod_int_address);
				CPUX86State *saved_env;
				saved_env = env;
				env = cpu_single_env;
				//-> mmu_idx=2 for integrity pages
				int ret = VDF_cpu_x86_handle_mmu_fault(env, pod_int_address, 1, 2, 1);
				if(ret){
//					printf("Page fault exception for 0x%x, error=%d\n", pod_int_address, env->error_code);
					raise_exception_err(env->exception_index, env->error_code);
				}
				env = saved_env;
				goto redo;
			}
		 }

	out_pod_fill:
	 tlb_fill(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);   	
	 goto redo;
    }
    return res;
}

/* handle all unaligned cases */
static DATA_TYPE glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                        int mmu_idx,
                                                        void *retaddr)
{

    DATA_TYPE res, res1, res2;
    int index, shift;
    target_phys_addr_t ioaddr;
    unsigned long addend;
    target_ulong tlb_addr, addr1, addr2;

	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo:
    tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {

		
		cr3_keyStruct *ccurrent;
		unsigned long *cr3_ptr;
		cr3_ptr = &env->cr[3];
		HASH_FIND(chh, cr3_table, cr3_ptr, sizeof(target_ulong), ccurrent);
		if(ccurrent){ /* check if it's a pod-enabled app */
			//			printf("Found a pod-enabled app:%" PRIu64 " \n", ccurrent->key);

			if(ccurrent->key==Reg_kapp){ /* check the current executing authority */

				target_ulong mask_addr = addr & POD_PAGE_MASK;
				if((mask_addr>start_code_address && mask_addr<end_code_address)){//|| (mask_addr>=(brk_start_address) && mask_addr<=(brk_end_address))){// && mask_addr!=0x495000 && mask_addr!=0x497000 && mask_addr!=0x4b4000){ //&& mask_addr!=0x702000

//						printf("Inside podload: 0x%x\n", addr & POD_PAGE_MASK);

					IPACT_struct *item;
					unsigned char *pod_int_host_va;					
					target_ulong temp_ppn = ((addr & TARGET_PAGE_MASK)+env->tlb_table[mmu_idx][index].addend); /* page number */
//					printf("Address translation for vaddr=0x%x, host_va=0x%x\n",addr, temp_ppn);
					HASH_FIND(ghh, pod_table, &temp_ppn, sizeof(target_ulong), item);
					if(item==NULL){ /* page fault, load entry into IPACT */
//				    printf("Item==NULL, adding entry into IPACT: 0x%x\n", temp_ppn);
						item = (IPACT_struct*)malloc(sizeof(IPACT_struct));
						memset(item, 0, sizeof(IPACT_struct));
						item->kapp = Reg_kapp;
						item->ppn = temp_ppn;
						item->vpn = addr & POD_PAGE_MASK; /* page number */
						item->swap_bit = true; /* true=E, false=D */
						item->private_bit = true; /* true=private, false=public - this is obvious*/
						// fixme pod_set_page_permn(item,permn);
//							printf("Calling get_int_addr1\n");
						target_ulong pod_int_address = get_int_address(addr);
						int pod_mmu_idx = get_mmuidx(addr);

						int pod_int_index = (pod_int_address >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
						target_ulong pod_int_tlb_addr = env->tlb_table[pod_mmu_idx][pod_int_index].ADDR_READ;
						//	printf("pod_int_address=0x%x, mmu_idx=%d,  pod_int_index=%d, pod_int_tlb_addr=0x%x\n",pod_int_address, pod_mmu_idx, pod_int_index, pod_int_tlb_addr);
						if ((pod_int_address & TARGET_PAGE_MASK) == (pod_int_tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))){		
						 
							pod_int_host_va = (unsigned char*)((pod_int_address)+env->tlb_table[pod_mmu_idx][pod_int_index].addend);
							int z;
//							printf("pod_int_address START 0x%x: *",pod_int_address);
							for(z=0;z<TAGLEN;z++){
								item->integrity_tag[z] = (unsigned char)*((unsigned char*)pod_int_host_va+(int)z); 
								//	printf("(%x)",item->integrity_tag[z]);
							}
							//	printf("*\n");
							unsigned char pod_buf_var[5];
							for(z=0;z<4;z++){
								pod_buf_var[z] = (unsigned char)*((unsigned char*)pod_int_host_va+TAGLEN+(int)z); 
							}
							pod_buf_var[4] = '\0';
							char *stopstring; 
							item->buflen = strtoull(pod_buf_var, &stopstring, 10);
							//	printf("buflen=%llu\n",item->buflen);
						}
						else{ /* VDF */
							goto VDF_time;
						}
								
					hash_add0:
						HASH_ADD(ghh, pod_table, ppn, sizeof(target_ulong), item);
					}
					else;// printf("Item already in IPACT, now check if we need to decrypt it\n");
//						print_regkapp("Encyption level 1");
//						printf("Found vaddr=0x%x,SB=%d in IPACT\n", item->vpn, item->swap_bit);
					if(item->swap_bit){ /* it's encrypted, so decrypt it */						
//							printf("Encryption level 2\n");
						item->swap_bit = false;
						pod_num_decrypt++;
						int i, dec_success, howmany1;
						unsigned char *pod_host_va;
						unsigned char *CT;
						unsigned char Key[KEY_SIZE];
						EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
						const EVP_CIPHER *gcm = EVP_aes_128_gcm();
						unsigned char *tag;
						unsigned char *ptbuf;
						int thesize = item->buflen; //ensure buflen is fetched
				
						tag = item->integrity_tag;
						pod_host_va = (unsigned char*)((addr & TARGET_PAGE_MASK)+env->tlb_table[mmu_idx][index].addend);
				
//						printf("pod_address START 0x%x: *",addr & POD_PAGE_MASK);
						//	for(i=0;i<TAGLEN;i++)
						//	printf("(%x)",item->integrity_tag[i]);
						//printf("*\n");
						CT = (unsigned char*)malloc(PAGE_SIZE);
						memset(CT, 0, PAGE_SIZE);
						for(i=0;i<thesize;i++){
							*((unsigned char*)CT+(int)i) = (unsigned char)*((unsigned char*)pod_host_va+(int)i);
							//	printf("(%x)",(unsigned char)CT[i]);
						}
						//	printf("\n");
						//printf("END\n");
				
						/* /\* fetching key from Reg_kapp *\/ */
						int nlen = snprintf(NULL, 0, "%"PRIu64, Reg_kapp);
						assert(nlen > 0);
						assert(nlen == KEY_SIZE);
						unsigned char tempkeybuf[nlen+1];
						int clen = snprintf(tempkeybuf, nlen+1, "%"PRIu64, Reg_kapp);
						assert(tempkeybuf[nlen] == '\0');
						assert(clen == nlen);

						for(i=0;i<KEY_SIZE;i++)
							Key[i] = tempkeybuf[i];
						ptbuf = (unsigned char*) malloc(PAGE_SIZE);
						memset(ptbuf, 0, PAGE_SIZE);
//				printf("Encryption starts with KEY:*%s*\n",tempkeybuf);

						ctx = EVP_CIPHER_CTX_new();
						EVP_DecryptInit (ctx, gcm, Key, IV);
						EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, TAGLEN, tag);
						EVP_DecryptInit (ctx, NULL, Key, IV);
						EVP_DecryptUpdate (ctx, NULL, &howmany1, AAD, AADLEN);

						EVP_DecryptUpdate (ctx, ptbuf, &howmany1, CT, thesize);
				
						dec_success = EVP_DecryptFinal (ctx, tag, &howmany1);
						EVP_CIPHER_CTX_free(ctx);

						if(dec_success){
//							printf("\nGCM works!\n");
							for(i=0;i<thesize;i++)
								*((unsigned char*)pod_host_va+(int)i) = (unsigned char)*((unsigned char*)ptbuf + (int)i);
						} else {
//							printf("\nGCM failed at vaddr=0x%x!\n",item->vpn);
						}
						free(CT);
						free(ptbuf);
					}
					else;// printf("Page already decrypted\n");
				}

			}
		}
	out:	
        if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access;
            ioaddr = env->iotlb[mmu_idx][index];
            res = glue(io_read, SUFFIX)(ioaddr, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
        do_unaligned_access:
            /* slow unaligned access (it spans two pages) */
addr1 = addr & ~(DATA_SIZE - 1);
            addr2 = addr1 + DATA_SIZE;
            res1 = glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(addr1,
                                                          mmu_idx, retaddr);
            res2 = glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(addr2,
                                                          mmu_idx, retaddr);
            shift = (addr & (DATA_SIZE - 1)) * 8;
#ifdef TARGET_WORDS_BIGENDIAN
            res = (res1 << shift) | (res2 >> ((DATA_SIZE * 8) - shift));
#else
            res = (res1 >> shift) | (res2 << ((DATA_SIZE * 8) - shift));
#endif
            res = (DATA_TYPE)res;
        } else {
            /* unaligned/aligned access in the same page */
            addend = env->tlb_table[mmu_idx][index].addend;
            res = glue(glue(ld, USUFFIX), _raw)((uint8_t *)(long)(addr+addend));
				
	
        }
    } else {
        /* the page is not in the TLB : fill it */

		  	VDF_time:
		if(Reg_kapp){
//			printf("Calling get_int_address\n");
			target_ulong pod_int_address = get_int_address(addr);
			if(pod_int_address==0)
				goto out_pod_fill;
			int pod_mmu_idx = get_mmuidx(addr);
                        int temp_index = (pod_int_address >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
                        target_ulong temp_tlb_addr = env->tlb_table[pod_mmu_idx][temp_index].ADDR_READ;
			if ((pod_int_address & TARGET_PAGE_MASK) != (temp_tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))){
		
//				printf("Calling VDF for 0x%x\n", pod_int_address);
				CPUX86State *saved_env;
				saved_env = env;
				env = cpu_single_env;
				//-> mmu_idx=2 for integrity pages
				int ret = VDF_cpu_x86_handle_mmu_fault(env, pod_int_address, 1, 2, 1);
				if(ret){
//					printf("Page fault exception for 0x%x, error=%d\n", pod_int_address, env->error_code);
					raise_exception_err(env->exception_index, env->error_code);
				}
				env = saved_env;
				goto redo;
			}
		 }

	out_pod_fill:
		tlb_fill(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
        goto redo;
    }
    return res;
}


#ifndef SOFTMMU_CODE_ACCESS

static void glue(glue(slow_st, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                   DATA_TYPE val,
                                                   int mmu_idx,
                                                   void *retaddr);

static inline void glue(io_write, SUFFIX)(target_phys_addr_t physaddr,
                                          DATA_TYPE val,
                                          target_ulong addr,
                                          void *retaddr)
{
    int index;
    index = (physaddr >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);
    physaddr = (physaddr & TARGET_PAGE_MASK) + addr;
    if (index > (IO_MEM_NOTDIRTY >> IO_MEM_SHIFT)
            && !can_do_io(env)) {
        cpu_io_recompile(env, retaddr);
    }

    env->mem_io_vaddr = addr;
    env->mem_io_pc = (unsigned long)retaddr;
#if SHIFT <= 2
    io_mem_write[index][SHIFT](io_mem_opaque[index], physaddr, val);
#else
#ifdef TARGET_WORDS_BIGENDIAN
    io_mem_write[index][2](io_mem_opaque[index], physaddr, val >> 32);
    io_mem_write[index][2](io_mem_opaque[index], physaddr + 4, val);
#else
    io_mem_write[index][2](io_mem_opaque[index], physaddr, val);
    io_mem_write[index][2](io_mem_opaque[index], physaddr + 4, val >> 32);
#endif
#endif /* SHIFT > 2 */
}



void REGPARM glue(glue(__st, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                 DATA_TYPE val,
                                                 int mmu_idx)
{
    target_phys_addr_t ioaddr;
    unsigned long addend;
    target_ulong tlb_addr;
    void *retaddr;
    int index;


	/* if(Reg_kapp){ */
	/* 	printf("inside __st, addr=0x%x\n",addr); */
	/* } */
    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo:
    tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {



		     		cr3_keyStruct *ccurrent;
			unsigned long *cr3_ptr;
			cr3_ptr = &env->cr[3];
			HASH_FIND(chh, cr3_table, cr3_ptr, sizeof(target_ulong), ccurrent);
			if(ccurrent){ /* check if it's a pod-enabled app */
				//			printf("Found a pod-enabled app:%" PRIu64 " \n", ccurrent->key);

				if(ccurrent->key==Reg_kapp){ /* check the current executing authority */

					target_ulong mask_addr = addr & POD_PAGE_MASK;
					if((mask_addr>start_code_address && mask_addr<end_code_address)){//|| (mask_addr>=(brk_start_address) && mask_addr<=(brk_end_address))){// && mask_addr!=0x495000 && mask_addr!=0x497000 && mask_addr!=0x4b4000){ //&& mask_addr!=0x702000

//						printf("Inside podload: 0x%x\n", addr & POD_PAGE_MASK);

						IPACT_struct *item;
						unsigned char *pod_int_host_va;					
						target_ulong temp_ppn = ((addr & TARGET_PAGE_MASK)+env->tlb_table[mmu_idx][index].addend); /* page number */
//						printf("Address translation for vaddr=0x%x, host_va=0x%x\n",addr, temp_ppn);
						HASH_FIND(ghh, pod_table, &temp_ppn, sizeof(target_ulong), item);
						if(item==NULL){ /* page fault, load entry into IPACT */
//				    printf("Item==NULL, adding entry into IPACT: 0x%x\n", temp_ppn);
							item = (IPACT_struct*)malloc(sizeof(IPACT_struct));
							memset(item, 0, sizeof(IPACT_struct));
							item->kapp = Reg_kapp;
							item->ppn = temp_ppn;
							item->vpn = addr & POD_PAGE_MASK; /* page number */
							item->swap_bit = true; /* true=E, false=D */
							item->private_bit = true; /* true=private, false=public - this is obvious*/
							// fixme pod_set_page_permn(item,permn);
//							printf("Calling get_int_addr1\n");
							target_ulong pod_int_address = get_int_address(addr);
							int pod_mmu_idx = get_mmuidx(addr);

							int pod_int_index = (pod_int_address >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
							target_ulong pod_int_tlb_addr = env->tlb_table[pod_mmu_idx][pod_int_index].ADDR_READ;
							//	printf("pod_int_address=0x%x, mmu_idx=%d,  pod_int_index=%d, pod_int_tlb_addr=0x%x\n",pod_int_address, pod_mmu_idx, pod_int_index, pod_int_tlb_addr);
							if ((pod_int_address & TARGET_PAGE_MASK) == (pod_int_tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))){		
						 
								pod_int_host_va = (unsigned char*)((pod_int_address)+env->tlb_table[pod_mmu_idx][pod_int_index].addend);
								int z;
//								printf("pod_int_address START 0x%x: *",pod_int_address);
								for(z=0;z<TAGLEN;z++){
									item->integrity_tag[z] = (unsigned char)*((unsigned char*)pod_int_host_va+(int)z); 
									//	printf("(%x)",item->integrity_tag[z]);
								}
								//	printf("*\n");
								unsigned char pod_buf_var[5];
								for(z=0;z<4;z++){
									pod_buf_var[z] = (unsigned char)*((unsigned char*)pod_int_host_va+TAGLEN+(int)z); 
								}
								pod_buf_var[4] = '\0';
								char *stopstring; 
								item->buflen = strtoull(pod_buf_var, &stopstring, 10);
								//	printf("buflen=%llu\n",item->buflen);
							}
							else{ /* VDF */
								goto VDF_time;
							}
								
						hash_add0:
							HASH_ADD(ghh, pod_table, ppn, sizeof(target_ulong), item);
						}
						else;// printf("Item already in IPACT, now check if we need to decrypt it\n");
//						print_regkapp("Encyption level 1");
//						printf("Found vaddr=0x%x,SB=%d in IPACT\n", item->vpn, item->swap_bit);
						if(item->swap_bit){ /* it's encrypted, so decrypt it */						
//							printf("Encryption level 2\n");
							item->swap_bit = false;
							pod_num_decrypt++;
							int i, dec_success, howmany1;
							unsigned char *pod_host_va;
							unsigned char *CT;
							unsigned char Key[KEY_SIZE];
							EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
							const EVP_CIPHER *gcm = EVP_aes_128_gcm();
							unsigned char *tag;
							unsigned char *ptbuf;
							int thesize = item->buflen; //ensure buflen is fetched
				
							tag = item->integrity_tag;
							pod_host_va = (unsigned char*)((addr & TARGET_PAGE_MASK)+env->tlb_table[mmu_idx][index].addend);
				
//							printf("pod_address START 0x%x: *",addr & POD_PAGE_MASK);
							//	for(i=0;i<TAGLEN;i++)
							//	printf("(%x)",item->integrity_tag[i]);
							//printf("*\n");
							CT = (unsigned char*)malloc(PAGE_SIZE);
							memset(CT, 0, PAGE_SIZE);
							for(i=0;i<thesize;i++){
								*((unsigned char*)CT+(int)i) = (unsigned char)*((unsigned char*)pod_host_va+(int)i);
								//	printf("(%x)",(unsigned char)CT[i]);
							}
							//	printf("\n");
							//printf("END\n");
				
							/* /\* fetching key from Reg_kapp *\/ */
							int nlen = snprintf(NULL, 0, "%"PRIu64, Reg_kapp);
							assert(nlen > 0);
							assert(nlen == KEY_SIZE);
							unsigned char tempkeybuf[nlen+1];
							int clen = snprintf(tempkeybuf, nlen+1, "%"PRIu64, Reg_kapp);
							assert(tempkeybuf[nlen] == '\0');
							assert(clen == nlen);

							for(i=0;i<KEY_SIZE;i++)
								Key[i] = tempkeybuf[i];
							ptbuf = (unsigned char*) malloc(PAGE_SIZE);
							memset(ptbuf, 0, PAGE_SIZE);
//				printf("Encryption starts with KEY:*%s*\n",tempkeybuf);

							ctx = EVP_CIPHER_CTX_new();
							EVP_DecryptInit (ctx, gcm, Key, IV);
							EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, TAGLEN, tag);
							EVP_DecryptInit (ctx, NULL, Key, IV);
							EVP_DecryptUpdate (ctx, NULL, &howmany1, AAD, AADLEN);

							EVP_DecryptUpdate (ctx, ptbuf, &howmany1, CT, thesize);
				
							dec_success = EVP_DecryptFinal (ctx, tag, &howmany1);
							EVP_CIPHER_CTX_free(ctx);

							if(dec_success){
//								printf("\nGCM works!\n");
								for(i=0;i<thesize;i++)
									*((unsigned char*)pod_host_va+(int)i) = (unsigned char)*((unsigned char*)ptbuf + (int)i);
							} else {
//								printf("\nGCM failed at vaddr=0x%x!\n",item->vpn);
							}
							free(CT);
							free(ptbuf);
						}
						else;// printf("Page already decrypted\n");
					}
				}
			}
	out:		
        if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access;
            retaddr = GETPC();
            ioaddr = env->iotlb[mmu_idx][index];
            glue(io_write, SUFFIX)(ioaddr, val, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
        do_unaligned_access:
            retaddr = GETPC();
#ifdef ALIGNED_ONLY
            do_unaligned_access(addr, 1, mmu_idx, retaddr);
#endif
            glue(glue(slow_st, SUFFIX), MMUSUFFIX)(addr, val,
                                                   mmu_idx, retaddr);
        } else {
            /* aligned/unaligned access in the same page */
#ifdef ALIGNED_ONLY
            if ((addr & (DATA_SIZE - 1)) != 0) {
                retaddr = GETPC();
                do_unaligned_access(addr, 1, mmu_idx, retaddr);
            }
#endif
            addend = env->tlb_table[mmu_idx][index].addend;
            glue(glue(st, SUFFIX), _raw)((uint8_t *)(long)(addr+addend), val);
        }
    } else {
        /* the page is not in the TLB : fill it */
        retaddr = GETPC();
#ifdef ALIGNED_ONLY
        if ((addr & (DATA_SIZE - 1)) != 0)
            do_unaligned_access(addr, 1, mmu_idx, retaddr);
#endif

	VDF_time:
		if(Reg_kapp){
//			printf("Calling get_int_address\n");
			target_ulong pod_int_address = get_int_address(addr);
			if(pod_int_address==0)
				goto out_pod_fill;
			int pod_mmu_idx = get_mmuidx(addr);
			int temp_index = (pod_int_address >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
			target_ulong temp_tlb_addr = env->tlb_table[pod_mmu_idx][temp_index].ADDR_READ;
			if ((pod_int_address & TARGET_PAGE_MASK) != (temp_tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))){
		
//				printf("Calling VDF for 0x%x\n", pod_int_address);
				CPUX86State *saved_env;
				saved_env = env;
				env = cpu_single_env;
				//-> mmu_idx=2 for code integrity
				int ret = VDF_cpu_x86_handle_mmu_fault(env, pod_int_address, 1, 2, 1);
				if(ret){
//					printf("Page fault exception for 0x%x, error=%d\n", pod_int_address, env->error_code);					
		
					raise_exception_err(env->exception_index, env->error_code);
				}
				env = saved_env;
				goto redo;
			}
		}
		
	out_pod_fill:
		tlb_fill(addr, 1, mmu_idx, retaddr);
	    goto redo;
	 }
}

/* handles all unaligned cases */
static void glue(glue(slow_st, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                   DATA_TYPE val,
                                                   int mmu_idx,
                                                   void *retaddr)
{
    target_phys_addr_t ioaddr;
    unsigned long addend;
    target_ulong tlb_addr;
    int index, i;

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo:
    tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {

		cr3_keyStruct *ccurrent;
		unsigned long *cr3_ptr;
		cr3_ptr = &env->cr[3];
		HASH_FIND(chh, cr3_table, cr3_ptr, sizeof(target_ulong), ccurrent);
		if(ccurrent){ /* check if it's a pod-enabled app */
			//			printf("Found a pod-enabled app:%" PRIu64 " \n", ccurrent->key);

			if(ccurrent->key==Reg_kapp){ /* check the current executing authority */

				target_ulong mask_addr = addr & POD_PAGE_MASK;
				if((mask_addr>start_code_address && mask_addr<end_code_address)){//|| (mask_addr>=(brk_start_address) && mask_addr<=(brk_end_address))){// && mask_addr!=0x495000 && mask_addr!=0x497000 && mask_addr!=0x4b4000){ //&& mask_addr!=0x702000

//						printf("Inside podload: 0x%x\n", addr & POD_PAGE_MASK);

					IPACT_struct *item;
					unsigned char *pod_int_host_va;					
					target_ulong temp_ppn = ((addr & TARGET_PAGE_MASK)+env->tlb_table[mmu_idx][index].addend); /* page number */
//					printf("Address translation for vaddr=0x%x, host_va=0x%x\n",addr, temp_ppn);
					HASH_FIND(ghh, pod_table, &temp_ppn, sizeof(target_ulong), item);
					if(item==NULL){ /* page fault, load entry into IPACT */
//				    printf("Item==NULL, adding entry into IPACT: 0x%x\n", temp_ppn);
						item = (IPACT_struct*)malloc(sizeof(IPACT_struct));
						memset(item, 0, sizeof(IPACT_struct));
						item->kapp = Reg_kapp;
						item->ppn = temp_ppn;
						item->vpn = addr & POD_PAGE_MASK; /* page number */
						item->swap_bit = true; /* true=E, false=D */
						item->private_bit = true; /* true=private, false=public - this is obvious*/
						// fixme pod_set_page_permn(item,permn);
//							printf("Calling get_int_addr1\n");
						target_ulong pod_int_address = get_int_address(addr);
						int pod_mmu_idx = get_mmuidx(addr);

						int pod_int_index = (pod_int_address >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
						target_ulong pod_int_tlb_addr = env->tlb_table[pod_mmu_idx][pod_int_index].ADDR_READ;
						//	printf("pod_int_address=0x%x, mmu_idx=%d,  pod_int_index=%d, pod_int_tlb_addr=0x%x\n",pod_int_address, pod_mmu_idx, pod_int_index, pod_int_tlb_addr);
						if ((pod_int_address & TARGET_PAGE_MASK) == (pod_int_tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))){		
						 
							pod_int_host_va = (unsigned char*)((pod_int_address)+env->tlb_table[pod_mmu_idx][pod_int_index].addend);
							int z;
//							printf("pod_int_address START 0x%x: *",pod_int_address);
							for(z=0;z<TAGLEN;z++){
								item->integrity_tag[z] = (unsigned char)*((unsigned char*)pod_int_host_va+(int)z); 
								//	printf("(%x)",item->integrity_tag[z]);
							}
							//	printf("*\n");
							unsigned char pod_buf_var[5];
							for(z=0;z<4;z++){
								pod_buf_var[z] = (unsigned char)*((unsigned char*)pod_int_host_va+TAGLEN+(int)z); 
							}
							pod_buf_var[4] = '\0';
							char *stopstring; 
							item->buflen = strtoull(pod_buf_var, &stopstring, 10);
							//	printf("buflen=%llu\n",item->buflen);
						}
						else{ /* VDF */
							goto VDF_time;
						}
								
					hash_add0:
						HASH_ADD(ghh, pod_table, ppn, sizeof(target_ulong), item);
					}
					else;// printf("Item already in IPACT, now check if we need to decrypt it\n");
//						print_regkapp("Encyption level 1");
//						printf("Found vaddr=0x%x,SB=%d in IPACT\n", item->vpn, item->swap_bit);
					if(item->swap_bit){ /* it's encrypted, so decrypt it */						
//							printf("Encryption level 2\n");
						item->swap_bit = false;
						pod_num_decrypt++;
						int i, dec_success, howmany1;
						unsigned char *pod_host_va;
						unsigned char *CT;
						unsigned char Key[KEY_SIZE];
						EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
						const EVP_CIPHER *gcm = EVP_aes_128_gcm();
						unsigned char *tag;
						unsigned char *ptbuf;
						int thesize = item->buflen; //ensure buflen is fetched
				
						tag = item->integrity_tag;
						pod_host_va = (unsigned char*)((addr & TARGET_PAGE_MASK)+env->tlb_table[mmu_idx][index].addend);
				
//						printf("pod_address START 0x%x: *",addr & POD_PAGE_MASK);
						//	for(i=0;i<TAGLEN;i++)
						//	printf("(%x)",item->integrity_tag[i]);
						//printf("*\n");
						CT = (unsigned char*)malloc(PAGE_SIZE);
						memset(CT, 0, PAGE_SIZE);
						for(i=0;i<thesize;i++){
							*((unsigned char*)CT+(int)i) = (unsigned char)*((unsigned char*)pod_host_va+(int)i);
							//	printf("(%x)",(unsigned char)CT[i]);
						}
						//	printf("\n");
						//printf("END\n");
				
						/* /\* fetching key from Reg_kapp *\/ */
						int nlen = snprintf(NULL, 0, "%"PRIu64, Reg_kapp);
						assert(nlen > 0);
						assert(nlen == KEY_SIZE);
						unsigned char tempkeybuf[nlen+1];
						int clen = snprintf(tempkeybuf, nlen+1, "%"PRIu64, Reg_kapp);
						assert(tempkeybuf[nlen] == '\0');
						assert(clen == nlen);

						for(i=0;i<KEY_SIZE;i++)
							Key[i] = tempkeybuf[i];
						ptbuf = (unsigned char*) malloc(PAGE_SIZE);
						memset(ptbuf, 0, PAGE_SIZE);
//				printf("Encryption starts with KEY:*%s*\n",tempkeybuf);

						ctx = EVP_CIPHER_CTX_new();
						EVP_DecryptInit (ctx, gcm, Key, IV);
						EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, TAGLEN, tag);
						EVP_DecryptInit (ctx, NULL, Key, IV);
						EVP_DecryptUpdate (ctx, NULL, &howmany1, AAD, AADLEN);

						EVP_DecryptUpdate (ctx, ptbuf, &howmany1, CT, thesize);
				
						dec_success = EVP_DecryptFinal (ctx, tag, &howmany1);
						EVP_CIPHER_CTX_free(ctx);

						if(dec_success){
//							printf("\nGCM works!\n");
							for(i=0;i<thesize;i++)
								*((unsigned char*)pod_host_va+(int)i) = (unsigned char)*((unsigned char*)ptbuf + (int)i);
						} else {
//							printf("\nGCM failed at vaddr=0x%x!\n",item->vpn);
						}
						free(CT);
						free(ptbuf);
					}
					else;// printf("Page already decrypted\n");
				}

			}
		}
out:		
        if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access;
            ioaddr = env->iotlb[mmu_idx][index];
            glue(io_write, SUFFIX)(ioaddr, val, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
        do_unaligned_access:
            /* XXX: not efficient, but simple */
            /* Note: relies on the fact that tlb_fill() does not remove the
             * previous page from the TLB cache.  */
            for(i = DATA_SIZE - 1; i >= 0; i--) {
#ifdef TARGET_WORDS_BIGENDIAN
                glue(slow_stb, MMUSUFFIX)(addr + i, val >> (((DATA_SIZE - 1) * 8) - (i * 8)),
                                          mmu_idx, retaddr);
#else
                glue(slow_stb, MMUSUFFIX)(addr + i, val >> (i * 8),
                                          mmu_idx, retaddr);
#endif
            }
        } else {
            /* aligned/unaligned access in the same page */
            addend = env->tlb_table[mmu_idx][index].addend;
            glue(glue(st, SUFFIX), _raw)((uint8_t *)(long)(addr+addend), val);
        }
    } else {
        /* the page is not in the TLB : fill it */

			  VDF_time:
		if(Reg_kapp){
//			printf("Calling get_int_address\n");
			target_ulong pod_int_address = get_int_address(addr);
			if(pod_int_address==0)
				goto out_pod_fill;
			int pod_mmu_idx = get_mmuidx(addr);
                        int temp_index = (pod_int_address >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
                        target_ulong temp_tlb_addr = env->tlb_table[pod_mmu_idx][temp_index].ADDR_READ;
			if ((pod_int_address & TARGET_PAGE_MASK) != (temp_tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))){
		
//				printf("Calling VDF for 0x%x\n", pod_int_address);
				CPUX86State *saved_env;
				saved_env = env;
				env = cpu_single_env;
				//-> mmu_idx=2 for code integrity
				int ret = VDF_cpu_x86_handle_mmu_fault(env, pod_int_address, 1, 2, 1);
				if(ret){
//					printf("Page fault exception for 0x%x, error=%d\n", pod_int_address, env->error_code);					
					raise_exception_err(env->exception_index, env->error_code);
				}
				env = saved_env;
				goto redo;
			}
		 }
	out_pod_fill:
		tlb_fill(addr, 1, mmu_idx, retaddr);
        goto redo;
    }
}

#endif /* !defined(SOFTMMU_CODE_ACCESS) */

#undef READ_ACCESS_TYPE
#undef SHIFT
#undef DATA_TYPE
#undef SUFFIX
#undef USUFFIX
#undef DATA_SIZE
#undef ADDR_READ

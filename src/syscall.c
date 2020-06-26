/*
 * PS Vita kernel module manager RE Syacall
 * Copyright (C) 2020, Princess of Sleeping
 */

#include <psp2/types.h>
#include "import_defs.h"
#include "syscall.h"

extern void *SceKernelModulemgr_data;

void *pSyscallTable;

int ReSyscallInit(void *syscall_table_ptr){

	pSyscallTable = syscall_table_ptr;

	return 0;
}

int syscall_stub(){
	return 0x8002710C;
}

/*
 * syacall_init / 0x81008b50
 *
 * @return 0 on success, < 0 on error.
 */
int syacall_init(void){

	int res;
	int dacr;

	void *syscall_table;
	void *syscall_table_end;

	syscall_table = &pSyscallTable;

	res = ksceKernelAllocSyscallTable(0x1000, syscall_table);
	if(res < 0)
		return res;

	asm volatile ("mrc p15, 0, %0, c3, c0, 0" : "=r" (dacr));
	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (0x17450000));

	syscall_table = (void *)(*(uint32_t *)(syscall_table));
	syscall_table_end = (void *)(syscall_table + 0x4000);

loc_81008B84:
	((int *)syscall_table)[0] = (int)syscall_stub;
	syscall_table += 4;
	if(syscall_table != syscall_table_end)
		goto loc_81008B84;

	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (dacr));

	ksceMt19937GlobalUninit((void *)(SceKernelModulemgr_data + 0x338), 4);
	*(uint32_t *)(SceKernelModulemgr_data + 0x334 + 0x4) = (*(uint32_t *)(SceKernelModulemgr_data + 0x334 + 4) & ((1 << 0xC) - 1));
	*(uint32_t *)(SceKernelModulemgr_data + 0x334 + 0x8) = (*(uint32_t *)(SceKernelModulemgr_data + 0x334 + 4) & ((1 << 0xC) - 1)) + 0x1000;

	return 0;
}

/*
 * IsSyscallTableExist / 0x81008d30 (checked)
 *
 * @return 0 or 1
 */
int IsSyscallTableExist(void){
	return (pSyscallTable != NULL) ? 1 : 0;
}

void sceKernelRegisterSyscallForKernel(int syscall_id, const void *func){

	int dacr;

	if((uint32_t)syscall_id >= 0x1000)
		return;

	asm volatile ("mrc p15, 0, %0, c3, c0, 0" : "=r" (dacr));
	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (0x17450000));

	*(uint32_t *)(pSyscallTable + (syscall_id << 0x2)) = (uint32_t)func;

	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (dacr));

	return;
}

// non export
void sceKernelUnregisterSyscallForKernel(int syscall_id){

	int dacr;

	if((uint32_t)syscall_id >= 0x1000)
		return;

	asm volatile ("mrc p15, 0, %0, c3, c0, 0" : "=r" (dacr));
	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (0x17450000));

	*(uint32_t *)(pSyscallTable + (syscall_id << 0x2)) = (uint32_t)&syscall_stub;

	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (dacr));

	return;
}

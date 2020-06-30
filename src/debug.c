/*
 * PS Vita kernel module manager RE My Debug
 * Copyright (C) 2020, Princess of Sleeping
 */

#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/io/fcntl.h>
#include <taihen.h>
#include <string.h>

#include "import_defs.h"
#include "modulemgr_types.h"
#include "modulemgr_internal.h"
#include "modulemgr_common.h"
#include "modulemgr_for_kernel.h"
#include "module_search.h"
#include "module_utility.h"
#include "taihen_macro.h"
#include "debug.h"

extern void *SceKernelModulemgr_data;

/*

	SceUID res;

	res = TAI_CONTINUE(SceUID, module_load_for_pid_ref, pid, path, flags, option);

	ksceDebugPrintf("flags : 0x%08X\n", flags);

	return res;
*/
tai_hook_ref_t module_load_for_pid_ref;
SceUID module_load_for_pid_patch(SceUID pid, const char *path, int flags, SceKernelLMOption *option){
	return module_load_for_pid(pid, path, flags, option);
}

tai_hook_ref_t module_unload_for_pid_ref;
int module_unload_for_pid_patch(SceUID pid, SceUID modid, int flags, SceKernelULMOption *option){

	int res;
	int res_debug;
	char module_name[0x1C];
	SceModuleInfoInternal *pModuleInfo;

	module_name[0x1B] = 0;
	res_debug = sceKernelGetModuleInternalForKernel(modid, &pModuleInfo);
	if(res_debug == 0){
		strncpy(module_name, pModuleInfo->module_name, 0x1B);
		// ksceDebugPrintf("[%-27s] flags:0x%X, shared:0x%X\n", pModuleInfo->module_name, pModuleInfo->flags, sceKernelGetModuleIsSharedByAddrForKernel(pid, pModuleInfo->segments[0].vaddr));
	}

	res = module_unload_for_pid(pid, modid, flags, option);
	if(res_debug == 0){
		// ksceDebugPrintf("Module Unload : [%-27s], modid:0x%X, res:0x%X\n", module_name, modid, res);
	}else{
		ksceDebugPrintf("Module Unload Error : 0x%X, 0x%X\n", res_debug, res);
	}

	return res;
}

tai_hook_ref_t create_new_module_class_ref;
int create_new_module_class_patch(SceUID pid, int flags, SceModuleObject **dst){
	return create_new_module_class(pid, flags, dst);
}

void hex_dump(const void *addr, SceSize len){

	if(addr == NULL)
		return;

	if(len == 0)
		return;

	for(int i=0;i<len;i+=0x10){
		ksceDebugPrintf(
			"%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
			((char *)addr)[i + 0x0], ((char *)addr)[i + 0x1], ((char *)addr)[i + 0x2], ((char *)addr)[i + 0x3],
			((char *)addr)[i + 0x4], ((char *)addr)[i + 0x5], ((char *)addr)[i + 0x6], ((char *)addr)[i + 0x7],
			((char *)addr)[i + 0x8], ((char *)addr)[i + 0x9], ((char *)addr)[i + 0xA], ((char *)addr)[i + 0xB],
			((char *)addr)[i + 0xC], ((char *)addr)[i + 0xD], ((char *)addr)[i + 0xE], ((char *)addr)[i + 0xF]
		);
	}
}

int write_file(const char *path, const void *data, SceSize size){

	if(data == NULL || size == 0)
		return -1;

	SceUID fd = ksceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
	if (fd < 0)
		return fd;

	ksceIoWrite(fd, data, size);
	ksceIoClose(fd);

	return 0;
}

int print_module_flags(SceUID pid){

	int cpu_intr;
	SceKernelProcessModuleInfo *pProcModuleInfo;
	SceModuleInfoInternal *pModuleInfo;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_intr);
	if(pProcModuleInfo == NULL)
		return -1;

	resume_cpu_intr(pProcModuleInfo, cpu_intr);

	pModuleInfo = pProcModuleInfo->pModuleInfo;

	while(pModuleInfo != NULL){
		ksceDebugPrintf("[%-27s] flags:0x%X\n", pModuleInfo->module_name, pModuleInfo->flags);
		pModuleInfo = pModuleInfo->next;
	}

	return 0;
}

int module_testing_thread(SceSize args, void *argp){

	SceUID modid;
	SceUID shell_pid, shell_uid;

	ksceKernelDelayThread(15 * 1000 * 1000);

	shell_pid = ksceKernelSysrootGetShellPid();

	shell_uid = search_module_by_name(shell_pid, "SceShell");

	ksceDebugPrintf("shell_pid : 0x%X\n", shell_pid);
	ksceDebugPrintf("shell_uid : 0x%X\n", shell_uid);

	modid = module_load_for_pid(0x10005, "os0:/kd/enum_wakeup.skprx", 0, NULL);
	ksceDebugPrintf("enum_wakeup.skprx modid : 0x%X\n", modid);

	if(0){
		SceUID SceSysmem_uid = search_module_by_name(0x10005, "SceSysmem");

		SceKernelModuleInfo sce_info;
		memset(&sce_info, 0, sizeof(SceKernelModuleInfo));

		sceKernelGetModuleInfoForKernel(0x10005, SceSysmem_uid, &sce_info);

		uint32_t *sysroot_func_table = *(uint32_t **)(sce_info.segments[1].vaddr + 0x75F8);

		ksceDebugPrintf("SceSysrootForDriver_D75D4F37 : 0x%X\n", sysroot_func_table[0x368 >> 2]);
	}

	ksceDebugPrintf("enum_wakeup.skprx unload res : 0x%X\n", module_unload_for_pid(0x10005, modid, 0, NULL));
	ksceDebugPrintf("\n");



	write_file("uma0:syscall_table.bin", (void *)(*(int *)(SceKernelModulemgr_data + 0x334)), 0x4000);


	ksceDebugPrintf("0x%X\n", *(int *)(SceKernelModulemgr_data + 0x338));


	if(0){
		print_module_flags(0x10005);
		print_module_flags(shell_pid);
	}

	ksceDebugPrintf("Testing Thread Exit\n");

	return ksceKernelExitDeleteThread(0);
}

int my_debug_start(void){

	SceUID modulemgr_uid = search_module_by_name(0x10005, "SceKernelModulemgr");

	HookOffset(modulemgr_uid, 0x5648, 1, create_new_module_class);

	HookOffset(modulemgr_uid, 0x21EC, 1, module_load_for_pid);
	HookOffset(modulemgr_uid, 0x26BC, 1, module_unload_for_pid);

	SceUID thid = ksceKernelCreateThread("SceKernelModuleTestingThread", module_testing_thread, 0x60, 0x4000, 0, 0, NULL);
	if(thid > 0)
		ksceKernelStartThread(thid, 0, NULL);

	return 0;
}
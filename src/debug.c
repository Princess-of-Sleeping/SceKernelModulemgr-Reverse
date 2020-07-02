/*
 * PS Vita kernel module manager RE My Debug
 * Copyright (C) 2020, Princess of Sleeping
 */

#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/io/fcntl.h>
#include <taihen.h>
#include <stdio.h>
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

	if(1){
		SceUID SceSysmem_uid = search_module_by_name(0x10005, "SceSysmem");

		SceKernelModuleInfo sce_info;
		memset(&sce_info, 0, sizeof(SceKernelModuleInfo));

		sceKernelGetModuleInfoForKernel(0x10005, SceSysmem_uid, &sce_info);

		uint32_t *sysroot_func_table = *(uint32_t **)(sce_info.segments[1].vaddr + 0x75F8);

		ksceDebugPrintf("SceSysrootForDriver_D75D4F37 : 0x%X\n", sysroot_func_table[0x3C4 >> 2]);
	}

	ksceDebugPrintf("enum_wakeup.skprx unload res : 0x%X\n", module_unload_for_pid(0x10005, modid, 0, NULL));
	ksceDebugPrintf("\n");

	// write_file("uma0:syscall_table.bin", (void *)(*(int *)(SceKernelModulemgr_data + 0x334)), 0x4000);
	// ksceDebugPrintf("0x%X\n", *(int *)(SceKernelModulemgr_data + 0x338));

	if(0){
		print_module_flags(0x10005);
		print_module_flags(shell_pid);
	}

	ksceDebugPrintf("Testing Thread Exit\n");

	return ksceKernelExitDeleteThread(0);
}


typedef struct SceSysrootProcessHandler_t {
    SceSize size;                                                       //!< sizeof(SceSysrootProcessHandler)
    void (* unk_4)(SceUID pid, SceUID modid, int flags, uint64_t time); //!< process start shared modules
    void (* exit)(SceUID pid, int flags, uint64_t time);
    void (* kill)(SceUID pid);                                          //!< by SceShell
    void (* unk_10)(SceUID pid, SceUID modid, uint64_t time);
    void (* unk_14)(SceUID pid, SceUID modid, uint64_t time);
    void (* unk_18)(SceUID pid, SceUID modid, uint64_t time);
    int (* on_process_created)(int a1, int a2, int a3);                 //!< called when process is created
    void (* unk_20)(SceUID pid, SceUID modid, uint64_t time);
    void (* unk_24)(SceUID pid, SceUID modid, int flags, uint64_t time);
} SceSysrootProcessHandler_t;

void unk_4(SceUID pid, SceUID modid, int flags, uint64_t time){
	ksceDebugPrintf("unk_4(old)  : 0x%X, 0x%X, 0x%X, 0x%llX\n", pid, modid, flags, time);
}

void unk_8(SceUID pid, int flags, uint64_t time){
	ksceDebugPrintf("unk_8(old)  : 0x%X, 0x%X, 0x%llX\n", pid, flags, time);
}

void unk_C(SceUID pid){
	ksceDebugPrintf("unk_C(old)  : 0x%X\n", pid);
}

void unk_10(SceUID pid, SceUID modid, uint64_t time){
	ksceDebugPrintf("unk_10(old) : 0x%X, 0x%X, 0x%llX\n", pid, modid, time);
}

void unk_14(SceUID pid, SceUID modid, uint64_t time){
	ksceDebugPrintf("unk_14(old) : 0x%X, 0x%X, 0x%llX\n", pid, modid, time);
}

void unk_18(SceUID pid, SceUID modid, uint64_t time){
	ksceDebugPrintf("unk_18(old) : 0x%X, 0x%X, 0x%llX\n", pid, modid, time);
}

//!< called when process is created
int  on_process_created(int a1, int a2, int a3){
	ksceDebugPrintf("create(old) : 0x%X, 0x%X, 0x%X\n", a1, a2, a3);
	return 0;
}

void unk_20(SceUID pid, SceUID modid, uint64_t time){
	ksceDebugPrintf("unk_20(old) : 0x%X, 0x%X, 0x%llX\n", pid, modid, time);
}

void unk_24(SceUID pid, SceUID modid, int flags, uint64_t time){
	ksceDebugPrintf("unk_24(old) : 0x%X, 0x%X, 0x%X, 0x%llX\n", pid, modid, flags, time);
}

const SceSysrootProcessHandler_t proc_handler = {
	.size   = sizeof(SceSysrootProcessHandler_t),
	.unk_4  = unk_4,
	.exit   = unk_8,
	.kill   = unk_C,
	.unk_10 = unk_10,
	.unk_14 = unk_14,
	.unk_18 = unk_18,
	.on_process_created = on_process_created,
	.unk_20 = unk_20,
	.unk_24 = unk_24
};


typedef struct SceSysrootDbgpHandler {
    SceSize size; //!< sizeof(SceSysrootDbgpHandler):0x5C
    void (* unk_0x04)(int a1, int a2, int a3, int a4);
    void (* unk_0x08)(int a1, int a2, int a3, int a4);
    void (* unk_0x0C)(int a1);
    void (* unk_0x10)(int a1, int a2, int a3, int a4);
    void (* unk_0x14)(int a1, int a2, int a3, int a4);
    void (* unk_0x18)(SceUID pid, SceUID modid, int flags, uint64_t time);
    void (* unk_0x1C)(int a1, int a2, int a3);
    void (* unk_0x20)(int a1, int a2, int a3);
    void (* unk_0x24)(int a1, int a2, int a3);
    void (* unk_0x28)(SceUID pid, SceUID modid, uint64_t time);
    void (* unk_0x2C)(SceUID pid, SceUID modid, uint64_t time);
    int  (* unk_0x30)(SceUID pid);
    int  (* unk_0x34)(int a1, int a2, int a3);
    int  (* unk_0x38)(int a1, int a2, void *a3);
    int  (* unk_0x3C)(int a1, int a2, int a3);
    int  (* unk_0x40)(SceUID pid, int *some_flag);
    int  (* unk_0x44)(SceUID pid, SceUID modid, int flags, uint64_t time);
    int  (* unk_0x48)(int a1, int a2, int a3);
    void (* unk_0x4C)(void);
    void (* unk_0x50)(void);
    int  (* unk_0x54)(int a1, int a2, int a3, int a4, int a5);
    int  (* unk_0x58)(int a1, int a2, int a3);
} SceSysrootDbgpHandler;


void unk_0x04(int a1, int a2, int a3, int a4){
	ksceDebugPrintf("unk_0x04 : 0x%X, 0x%X, 0x%X, 0x%X\n", a1, a2, a3, a4);
}

void unk_0x08(int a1, int a2, int a3, int a4){
	ksceDebugPrintf("unk_0x08 : 0x%X, 0x%X, 0x%X, 0x%X\n", a1, a2, a3, a4);
}

void unk_0x0C(int a1){
	ksceDebugPrintf("unk_0x0C : 0x%X\n", a1);
}

void unk_0x10(int a1, int a2, int a3, int a4){
	ksceDebugPrintf("unk_0x10 : 0x%X, 0x%X, 0x%X, 0x%X\n", a1, a2, a3, a4);
}

void unk_0x14(int a1, int a2, int a3, int a4){
	ksceDebugPrintf("unk_0x14 : 0x%X, 0x%X, 0x%X, 0x%X\n", a1, a2, a3, a4);
}

void unk_0x18(SceUID pid, SceUID modid, int flags, uint64_t time){
	ksceDebugPrintf("unk_0x18 : 0x%X, 0x%X, 0x%X, 0x%llX\n", pid, modid, flags, time);
}

void unk_0x1C(int a1, int a2, int a3){
	ksceDebugPrintf("unk_0x1C : 0x%X, 0x%X, 0x%X\n", a1, a2, a3);
}

void unk_0x20(int a1, int a2, int a3){
	ksceDebugPrintf("unk_0x20 : 0x%X, 0x%X, 0x%X\n", a1, a2, a3);
}

void unk_0x24(int a1, int a2, int a3){
	ksceDebugPrintf("unk_0x24 : 0x%X, 0x%X, 0x%X\n", a1, a2, a3);
}

void unk_0x28(SceUID pid, SceUID modid, uint64_t time){
	ksceDebugPrintf("unk_0x28 : 0x%X, 0x%X, 0x%llX\n", pid, modid, time);
}

void unk_0x2C(SceUID pid, SceUID modid, uint64_t time){
	ksceDebugPrintf("unk_0x2C : 0x%X, 0x%X, 0x%llX\n", pid, modid, time);
}

int  unk_0x30(SceUID pid){
	ksceDebugPrintf("unk_0x30 : 0x%X\n", pid);
	return 0;
}

int  unk_0x34(int a1, int a2, int a3){
	ksceDebugPrintf("unk_0x34 : 0x%X, 0x%X, 0x%X\n", a1, a2, a3);
	return 0;
}

int  unk_0x38(int a1, int a2, void *a3){
	ksceDebugPrintf("unk_0x38 : 0x%X, 0x%X, 0x%X\n", a1, a2, a3);
	return 0;
}

int  unk_0x3C(int a1, int a2, int a3){
	ksceDebugPrintf("unk_0x3C : 0x%X, 0x%X, 0x%X\n", a1, a2, a3);
	return 0;
}

int  unk_0x40(SceUID pid, int *some_flag){
	ksceDebugPrintf("unk_0x40 : 0x%X, 0x%X\n", pid, some_flag);
	return 0;
}

int  unk_0x44(SceUID pid, SceUID modid, int flags, uint64_t time){
	ksceDebugPrintf("unk_0x44 : 0x%X, 0x%X, 0x%X, 0x%llX\n", pid, modid, flags, time);
	return 0;
}

int  unk_0x48(int a1, int a2, int a3){
	ksceDebugPrintf("unk_0x48 : 0x%X, 0x%X, 0x%X\n", a1, a2, a3);
	return 0;
}

void unk_0x4C(void){
	ksceDebugPrintf("unk_0x4C\n");
}

void unk_0x50(void){
	ksceDebugPrintf("unk_0x50\n");
}

int  unk_0x54(int a1, int a2, int a3, int a4, int a5){
	ksceDebugPrintf("unk_0x54 : 0x%X, 0x%X, 0x%X, 0x%X\n", a1, a2, a3, a4, a5);
	return 0;
}

int  unk_0x58(int a1, int a2, int a3){
	ksceDebugPrintf("unk_0x58 : 0x%X, 0x%X, 0x%X\n", a1, a2, a3);
	return 0;
}

const SceSysrootDbgpHandler dbgp_handler = {
	.size = sizeof(SceSysrootDbgpHandler),
	.unk_0x04 = unk_0x04,
	.unk_0x08 = unk_0x08,
	.unk_0x0C = unk_0x0C,
	.unk_0x10 = unk_0x10,
	.unk_0x14 = unk_0x14,
	.unk_0x18 = unk_0x18,
	.unk_0x1C = unk_0x1C,
	.unk_0x20 = unk_0x20,
	.unk_0x24 = unk_0x24,
	.unk_0x28 = unk_0x28,
	.unk_0x2C = unk_0x2C,
	.unk_0x30 = unk_0x30,
	.unk_0x34 = unk_0x34,
	.unk_0x38 = unk_0x38,
	.unk_0x3C = unk_0x3C,
	.unk_0x40 = unk_0x40,
	.unk_0x44 = unk_0x44,
	.unk_0x48 = unk_0x48,
	.unk_0x4C = unk_0x4C,
	.unk_0x50 = unk_0x50,
	.unk_0x54 = unk_0x54,
	.unk_0x58 = unk_0x58
};

int sceKernelGetModuleExportFunction(const char *module_name, unsigned int libnid, unsigned int func_nid, void *out){

	int res, cpu_intr;
	SceKernelProcessModuleInfo *pProcModuleInfo;
	SceModuleLibraryInfo *pLibraryInfo;

	pProcModuleInfo = getProcModuleInfo(0x10005, &cpu_intr);
	if(pProcModuleInfo == NULL)
		return -1;

	pLibraryInfo = pProcModuleInfo->pLibraryInfo;

	res = -1;

	while(pLibraryInfo != NULL){

		if(pLibraryInfo->pExportInfo->libnid == libnid && strcmp(module_name, pLibraryInfo->pModuleInfo->module_name) == 0){
			for(int i=0;i<pLibraryInfo->pExportInfo->entry_num_function;i++){

				if(pLibraryInfo->pExportInfo->table_nid[i] == func_nid){
					*(int **)(out) = pLibraryInfo->pExportInfo->table_entry[i];
					res = 0;
					goto end;
				}
			}
		}

		pLibraryInfo = pLibraryInfo->next;
	}

end:
	resume_cpu_intr(pProcModuleInfo, cpu_intr);

	return res;
}

int my_debug_start(void){

	SceUID modulemgr_uid = search_module_by_name(0x10005, "SceKernelModulemgr");

	HookOffset(modulemgr_uid, 0x5648, 1, create_new_module_class);

	HookOffset(modulemgr_uid, 0x21EC, 1, module_load_for_pid);
	HookOffset(modulemgr_uid, 0x26BC, 1, module_unload_for_pid);

	SceUID thid = ksceKernelCreateThread("SceKernelModuleTestingThread", module_testing_thread, 0x60, 0x4000, 0, 0, NULL);
	if(thid > 0)
		ksceKernelStartThread(thid, 0, NULL);

/*
	ksceKernelSysrootSetProcessHandler((const SceSysrootProcessHandler *)&proc_handler);

	int res;
	int (* SceSysrootForKernel_3999F917_sceKernelSysrootSetDbgpHandler)(const void *pHandler) = NULL;

	res = sceKernelGetModuleExportFunction("SceSysmem", 0x3691DA45, 0x3999F917, &SceSysrootForKernel_3999F917_sceKernelSysrootSetDbgpHandler);

	ksceDebugPrintf("sceKernelGetModuleExportFunction : 0x%X\n", res);
	ksceDebugPrintf("sceKernelSysrootSetDbgpHandler   : 0x%X\n", SceSysrootForKernel_3999F917_sceKernelSysrootSetDbgpHandler);

	if(SceSysrootForKernel_3999F917_sceKernelSysrootSetDbgpHandler != NULL)
		SceSysrootForKernel_3999F917_sceKernelSysrootSetDbgpHandler(&dbgp_handler);
*/

	return 0;
}

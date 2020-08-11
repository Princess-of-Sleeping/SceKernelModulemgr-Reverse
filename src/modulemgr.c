/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>

#include <string.h>

#include "import_defs.h"
#include "modulemgr.h"
#include "modulemgr_types.h"
#include "modulemgr_for_driver.h"
#include "modulemgr_for_kernel.h"
#include "modulemgr_common.h"

int sceKernelGetAllowedSdkVersionOnSystem(void){

	int res;
	uint32_t state;
	SceKernelFwInfo kdata;

	SceSysrootForDriver_6E0BC27C(); // ???

	ENTER_SYSCALL(state);

	memset(&kdata, 0, sizeof(SceKernelFwInfo));
	kdata.size = sizeof(SceKernelFwInfo);

	res = sceKernelGetSystemSwVersionForDriver(&kdata);
	if(res != 0)
		goto loc_8100A280;

	res = (kdata.version | 0xFF0) | 0xF;

loc_8100A270:
	EXIT_SYSCALL(state);
	return res;

loc_8100A280:
	res = 0;
	goto loc_8100A270;
}

int sceKernelGetSystemSwVersion(SceKernelFwInfo *data){

	int res;
	uint32_t state;
	SceKernelFwInfo kdata;

	ENTER_SYSCALL(state);

	memset(&kdata, 0, sizeof(SceKernelFwInfo));

	res = ksceKernelMemcpyUserToKernel(&kdata, (uintptr_t)data, 4);
	if (res < 0)
		goto loc_8100A214;

	res = sceKernelGetSystemSwVersionForDriver(&kdata);
	if (res < 0)
		goto loc_8100A214;
	res = ksceKernelMemcpyKernelToUser((uintptr_t)data, &kdata, sizeof(SceKernelFwInfo));

loc_8100A214:
	EXIT_SYSCALL(state);

	return res;
}

SceUID sceKernelGetModuleIdByAddr(const void *module_addr){

	SceUID res;
	uint32_t state;

	ENTER_SYSCALL(state);
	res = get_module_id_by_addr(0, module_addr);
	EXIT_SYSCALL(state);

	return res;
}

int sceKernelGetLibraryInfoByNID(SceUID modid, uint32_t libnid, SceKernelLibraryInfo *info){

	int res;
	uint32_t state;
	SceUID pid;
	SceKernelLibraryInfo kinfo;

	ENTER_SYSCALL(state);

	pid = ksceKernelGetProcessId();

	modid = ksceKernelKernelUidForUserUid(pid, modid);
	if (modid < 0)
		goto loc_8100A2F6;

	memset(&kinfo, 0, sizeof(SceKernelLibraryInfo));

	kinfo.size = sizeof(SceKernelLibraryInfo);

	res = get_module_library_info_export(pid, modid, libnid, &kinfo);
	if (res < 0)
		goto loc_8100A2E4;

	res = ksceKernelMemcpyKernelToUser((uintptr_t)info, &kinfo, 0x1C);

loc_8100A2E4:
	EXIT_SYSCALL(state);

loc_8100A2E8:
	return res;

loc_8100A2F6:
	res = modid | 0x40000000;
	EXIT_SYSCALL(state);
	goto loc_8100A2E8;
}

int sceKernelGetModuleList(int flags, SceUID *modids, SceSize *num){

	int res;
	uint32_t state;
	SceSize knum = 0;
	void *klist;

	ENTER_SYSCALL(state);

	if(flags == 0)
		flags = 1;

	if(modids == NULL){
		res = sceKernelGetModuleListForKernel(0, flags, 0, NULL, NULL);
		goto exit_syscall;
	}

	res = ksceKernelMemcpyUserToKernel(&knum, (uintptr_t)num, 4);
	if(res < 0)
		goto exit_syscall;

	klist = ksceKernelAlloc(knum << 2);
	if(klist == NULL){
		res = 0x8002D008;
		goto exit_syscall;
	}

	res = sceKernelGetModuleListForKernel(0, flags, 2, klist, &knum);
	if(res < 0)
		goto free_klist;

	res = ksceKernelMemcpyKernelToUser((uintptr_t)modids, klist, knum << 2);
	if(res < 0)
		goto free_klist;

	res = ksceKernelMemcpyKernelToUser((uintptr_t)num, &knum, 4);

free_klist:
	ksceKernelFree(klist);

exit_syscall:
	EXIT_SYSCALL(state);

	return res;
}

int sceKernelGetModuleInfo(SceUID modid, SceKernelModuleInfo *info){

	int res;
	SceUID kuid;
	uint32_t state;
	SceKernelModuleInfo kinfo;

	ENTER_SYSCALL(state);

	kuid = ksceKernelKernelUidForUserUid(0, modid);
	if (kuid < 0)
		goto loc_8100A194;

	memset(&kinfo, 0, sizeof(SceKernelModuleInfo));
	kinfo.size = sizeof(SceKernelModuleInfo);

	res = get_module_info(ksceKernelGetProcessId(), kuid, (SceKernelModuleInfo_fix_t *)&kinfo);
	if(res < 0)
		goto loc_8100A182;

	res = ksceKernelMemcpyKernelToUser((uintptr_t)info, &kinfo, sizeof(SceKernelModuleInfo));

loc_8100A182:
	EXIT_SYSCALL(state);

loc_8100A186:
	return res;

loc_8100A194:
	res = kuid | 0x40000000;
	EXIT_SYSCALL(state);
	goto loc_8100A186;
}

int sceKernelIsCalledFromSysModule(const void *module_addr){

	int res;
	uint32_t state;

	ENTER_SYSCALL(state);
	res = sceKernelGetModuleIsSharedByAddrForKernel(ksceKernelGetProcessId(), module_addr);
	EXIT_SYSCALL(state);

	return res;
}

SceUID _sceKernelOpenModule(const char *path, SceSize args, void *argp, SceKernelModuleOpen_t *module_open)
{
	// yet not Reversed
	return 0;
}

int _sceKernelCloseModule(SceUID modid, SceSize args, void *argp, SceKernelModuleClose_t *module_close)
{
	// yet not Reversed
	return 0;
}

SceUID _sceKernelLoadModule(const char *path, int flags, SceKernelLMOption *option)
{
	// yet not Reversed
	return 0;
}

int _sceKernelStartModule(SceUID modid, SceSize args, void *argp, SceKernelModuleStart_t *module_start)
{
	// yet not Reversed
	return 0;
}

SceUID _sceKernelLoadStartModule(const char *path, SceSize args, void *argp, SceKernelModuleLoadStart_t *module_load_start)
{
	// yet not Reversed
	return 0;
}

int _sceKernelStopModule(SceUID modid, SceSize args, void *argp, SceKernelModuleStop_t *module_stop)
{
	// yet not Reversed
	return 0;
}

int _sceKernelUnloadModule(SceUID modid, int flags, SceKernelULMOption *option)
{
	// yet not Reversed
	return 0;
}

int _sceKernelStopUnloadModule(SceUID modid, SceSize args, void *argp, SceKernelModuleStopUnload_t *module_stop_unload)
{
	// yet not Reversed
	return 0;
}

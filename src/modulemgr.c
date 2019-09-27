#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>

#include <stdio.h>
#include <string.h>

#include "modulemgr.h"
#include "modulemgr_types.h"
#include "modulemgr_for_driver.h"
#include "modulemgr_for_kernel.h"
#include "modulemgr_common.h"

extern void (* SceSysrootForDriver_6E0BC27C)(void);



int sceKernelGetAllowedSdkVersionOnSystem(void)
{

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

int sceKernelGetSystemSwVersion(SceKernelFwInfo *data)
{

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

int sceKernelGetModuleIdByAddr(const void *addr)
{
	int res;
	uint32_t state;

	ENTER_SYSCALL(state);
	res = get_module_id_by_addr(0, addr);
	EXIT_SYSCALL(state);

	return res;
}

int sceKernelGetLibraryInfoByNID(SceUID uid, int a2, SceKernelLibraryInfo *info)
{

	int res;
	SceUID kuid;
	uint32_t state;
	SceUID pid;
	SceKernelLibraryInfo kinfo;

	ENTER_SYSCALL(state);

	pid = ksceKernelGetProcessId();

	kuid = ksceKernelKernelUidForUserUid(pid, uid);
	if (kuid < 0)
		goto loc_8100A2F6;

	memset(&kinfo, 0, sizeof(SceKernelLibraryInfo));

	kinfo.size = sizeof(SceKernelLibraryInfo);

	res = func_0x810076b0(pid, kuid, a2, &kinfo);
	if (res < 0)
		goto loc_8100A2E4;

	res = ksceKernelMemcpyKernelToUser((uintptr_t)info, &kinfo, 0x1C);

loc_8100A2E4:
	EXIT_SYSCALL(state);

loc_8100A2E8:
	return res;

loc_8100A2F6:
	res = kuid | 0x40000000;
	EXIT_SYSCALL(state);
	goto loc_8100A2E8;
}

int sceKernelGetModuleList(int flags, SceUID *modids, int *num)
{
	// yet not Reversed
	return 0;
}

int sceKernelGetModuleInfo(SceUID modid, SceKernelModuleInfo *info)
{

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

int sceKernelIsCalledFromSysModule(int a1)
{

	int res;
	uint32_t state;

	ENTER_SYSCALL(state);
	res = SceModulemgrForKernel_99890202(ksceKernelGetProcessId(), (const void *)a1);
	EXIT_SYSCALL(state);

	return res;
}

int sceKernelInhibitLoadingModule(uint16_t flag)
{

	int res;
	uint32_t state;

	ENTER_SYSCALL(state);
	res = func_0x81003708(flag);
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





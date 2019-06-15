
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>

#include <stdio.h>
#include <string.h>

#include "modulemgr_common.h"

extern void (* SceSysrootForDriver_6E0BC27C)(void);



int sceKernelGetAllowedSdkVersionOnSystem(){

	int res;
	uint32_t state;
	SceKernelFwInfo kdata;

	SceSysrootForDriver_6E0BC27C(); // ???

	ENTER_SYSCALL(state);

	memset(&kdata, 0, sizeof(SceKernelFwInfo));
	kdata.size = sizeof(SceKernelFwInfo);

	res = ksceKernelGetSystemSwVersion(&kdata);
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

	res = ksceKernelGetSystemSwVersion(&kdata);
	if (res < 0)
		goto loc_8100A214;
	res = ksceKernelMemcpyKernelToUser((uintptr_t)data, &kdata, sizeof(SceKernelFwInfo));

loc_8100A214:
	EXIT_SYSCALL(state);

	return res;
}

int sceKernelGetModuleIdByAddr(const void *some_addr){
	int res;
	uint32_t state;

	ENTER_SYSCALL(state);
	res = func_0x81007c10(0, some_addr);
	EXIT_SYSCALL(state);

	return res;
}

int sceKernelGetLibraryInfoByNID(SceUID uid, int a2, SceKernelLibraryInfo *info){

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

	res = func_0x81007790(ksceKernelGetProcessId(), kuid, (SceKernelModuleInfo_fix_t *)&kinfo);
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

int sceKernelIsCalledFromSysModule(int a1){

	int res;
	uint32_t state;

	ENTER_SYSCALL(state);
	res = SceModulemgrForKernel_99890202(ksceKernelGetProcessId(), a1);
	EXIT_SYSCALL(state);

	return res;
}

int sceKernelInhibitLoadingModule(uint16_t flag){

	int res;
	uint32_t state;

	ENTER_SYSCALL(state);
	res = func_0x81003708(flag);
	EXIT_SYSCALL(state);

	return res;
}

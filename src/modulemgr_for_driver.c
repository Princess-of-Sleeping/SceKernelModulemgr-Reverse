#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>
#include <stdio.h>
#include <string.h>

#include "modulemgr_internal.h"
#include "modulemgr_common.h"

extern void *SceKernelModulemgr_text;
extern void *SceKernelModulemgr_data;

extern int (* SceSysrootForDriver_67AAB627)(void);

// ksceKernelGetModuleInfoByAddr
int SceModulemgrForDriver_1D9E0F7E(const void *addr, SceKernelModuleInfo *info){

	SceUID modid;

	modid = get_module_id_by_addr(0x10005, addr);
	if(modid < 0)
		return modid;

	return get_module_info(0x10005, modid, (SceKernelModuleInfo_fix_t *)info);
}

SceUID sceKernelSearchModuleByNameForDriver(const char *module_name){
	return search_module_by_name(0x10005, module_name);
}

int sceKernelRegisterLibaryForDriver(const void *module_addr){

	int res;
	int some_uid;
	void *arg1;

	some_uid = get_module_id_by_addr(0x10005, module_addr);
	if(some_uid < 0)
		return some_uid;

	arg1 = func_0x81001f0c(some_uid);
	if(arg1 == NULL)
		return 0x8002D011;

	res = func_0x81005fec(arg1 + 8, module_addr);
	if(res < 0)
		goto label_0x81003242;

	res = func_0x81004198(arg1 + 8, res, 1);

label_0x81003242:
	ksceKernelUidRelease(some_uid);
	ksceKernelCpuIcacheInvalidateAll();
	return res;
}

int sceKernelReleaseLibaryForDriver(const void *module_addr){

	int res;
	SceUID modid;
	void *pRes;

	modid = get_module_id_by_addr(0x10005, module_addr);
	if(modid < 0)
		return modid;

	pRes = func_0x81001f0c(modid);
	if(pRes == 0)
		return 0x8002D011;

	res = func_0x81005fec(pRes + 8, module_addr);
	if(res < 0)
		goto label_0x81003296;

	res = func_0x8100428c(pRes + 8, res, 0);

label_0x81003296:
	ksceKernelUidRelease(modid);
	ksceKernelCpuIcacheInvalidateAll();
	return res;
}

int sceKernelGetSystemSwVersionForDriver(SceKernelFwInfo *data){

	int res;
	int sysver;
	SceKernelFwInfo *info_internal = (SceKernelFwInfo *)(SceKernelModulemgr_data + 0x2D0);

	if(data->size != 0x28)
		goto label_0x81003DB2;

	if(*(uint32_t *)(SceKernelModulemgr_data + 0x34) == 0)
		goto label_0x81003D5E;

label_0x81003D28:
	memcpy(data, info_internal, sizeof(SceKernelFwInfo));

	res = 0;

label_0x81003D58:
	return res;

label_0x81003D5E:
	sysver = SceSysrootForDriver_67AAB627();

	info_internal->size    = sizeof(SceKernelFwInfo);
	info_internal->version = sysver;
	info_internal->unk_24  = 0;
	snprintf(info_internal->versionString, 0x1C, "%d.%02d",
		((sysver >> 0x18) & ((1 << 4) - 1)) + (((sysver >> 0x1C) + ((sysver >> 0x1C) << 0x2)) << 0x1),
		(((sysver >> 0x10) & ((1 << 4) - 1)) + ((((sysver >> 0x14) & ((1 << 4) - 1)) + (((sysver >> 0x14) & ((1 << 4) - 1)) << 0x2)) << 0x1))
	);

	*(uint32_t *)(SceKernelModulemgr_data + 0x34) += 1;
	goto label_0x81003D28;

label_0x81003DB2:
	res = 0x80020005;
	goto label_0x81003D58;
}

SceUID ksceKernelLoadModule(const char *path, int flags, SceKernelLMOption *option){

	if(((flags & ~0x7D800) & ~0x1F0) != 0)
		return 0x8002000A;

	return module_load_for_pid(0x10005, path, flags, option);
}

int ksceKernelStartModule(SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){

	if(flags != 0)
		return 0x8002000A;

	return module_start_for_pid(0x10005, modid, args, argp, flags, option, status);
}

SceUID ksceKernelLoadStartModule(const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){

	if(((flags & ~0x7D800) & ~0x1F0) != 0)
		return 0x8002000A;

	return module_load_start_for_pid(0x10005, path, args, argp, flags, option, status);
}

SceUID ksceKernelLoadStartModuleForPid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){

	if(pid == 0)
		return 0x8002D017;

	if(((flags & ~0x7D800) & ~0x1F0) != 0)
		return 0x8002000A;

	return module_load_start_for_pid(pid, path, args, argp, ((flags | 0x8000000) | 2), option, status);
}


int ksceKernelUnloadModule(SceUID modid, int flags, SceKernelULMOption *option){

	if((flags & ~0x40000000) != 0)
		return 0x8002000A;

	return module_unload_for_pid(0x10005, modid, flags, option);
}

int ksceKernelStopModule(SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){

	if(flags != 0)
		return 0x8002000A;

	return module_stop_for_pid(0x10005, modid, args, argp, flags, option, status);
}

int ksceKernelStopUnloadModule(SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){

	if((flags & ~0x40000000) != 0)
		return 0x8002000A;

	return module_stop_unload_for_pid(0x10005, modid, args, argp, flags, option, status);
}

int ksceKernelStopUnloadModuleForPid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){

	if(pid == 0)
		return 0x8002D017;
	
	if((flags & ~0x40000000) != 0)
		return 0x8002000A;

	return module_stop_unload_for_pid(pid, modid, args, argp, flags | 0x8000000, option, status);
}

SceUID ksceKernelLoadStartSharedModuleForPid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){

	if(pid == 0)
		return 0x8002D017;

	return module_load_start_shared_for_pid(pid, path, args, argp, flags | 0x8000000, option, status);
}

int ksceKernelStopUnloadSharedModuleForPid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){

	if(pid == 0)
		return 0x8002D017;

	if(flags != 0)
		return 0x8002000A;

	return module_stop_unload_for_pid(pid, modid, args, argp, 0x8000000, 0, status);
}

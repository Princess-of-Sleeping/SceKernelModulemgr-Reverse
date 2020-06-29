/*
 * PS Vita kernel module manager RE Utility
 * Copyright (C) 2020, Princess of Sleeping
 */

#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/sysmem.h>
#include <string.h>

#include "import_defs.h"
#include "modulemgr_types.h"
#include "modulemgr_internal.h"

extern SceClass *pSceUIDLibraryClass;
extern SceClass *pSceUIDModuleClass;
extern SceClass *pSceUIDLibStubClass;

/*
 * get_module_object / func_0x81001f0c (checked)
 */
SceModuleObject *get_module_object(SceUID modid){

	SceModuleObject *pObj;

	if(ksceKernelGetObjForUid(modid, pSceUIDModuleClass, (SceObjectBase **)&pObj) < 0){
		pObj = NULL;
	}

	return pObj;
}

/*
 * release_obj / func_0x810021b8 (checked)
 */
int release_obj(SceUID uid){
	ksceKernelUidRelease(uid);
	return 0;
}

/*
 * release_obj_for_user / func_0x810021d8 (checked)
 */
int release_obj_for_user(SceUID uid){
	if(uid != 0x10005){
		ksceKernelUidRelease(uid);
	}

	return 0;
}

/*
 * process_check_for_user / func_0x81001ec4 (checked)
 */
int process_check_for_user(SceUID pid){
	return ksceKernelGetObjForUid(pid, sceKernelGetProcessClassForKernel(), 0);
}

/*
 * process_check / func_0x810021c0 (checked)
 */
int process_check(SceUID pid){
	if(pid != 0x10005){
		return process_check_for_user(pid);
	}

	return 0;
}

/*
 * alloc_for_process / func_0x8100498c
 */
void *alloc_for_process(SceUID pid, SceSize len){

	void *res;

	if(pid != 0x10005){
		res = sceKernelAllocRemoteProcessHeapForDriver(pid, len, NULL);
	}else{
		res = ksceKernelAlloc(len);
	}

	return res;
}

/*
 * free_for_process / func_0x810049a8
 */
void free_for_process(SceUID pid, void *ptr){

	if(pid == 0x10005){
		ksceKernelFree(ptr);
	}else{
		sceKernelFreeRemoteProcessHeapForDriver(pid, ptr);
	}

	return;
}

// memcpy_to_kernel / func_0x8100496c
int memcpy_to_kernel(SceUID pid, void *dst, const void *src, SceSize len){
	if(pid == 0x10005){
		memcpy(dst, src, len);
		return 0;
	}

	return ksceKernelMemcpyUserToKernelForPid(pid, dst, (uintptr_t)src, len);
}

/*
 * getProcModuleInfo / 0x81006e60
 *
 * @param[in]  pid              - target pid
 * @param[out] cpu_suspend_intr - ksceKernelCpuSuspendIntr res out
 *
 * @return module tree pointer on success, < 0 on error.
 */
SceKernelProcessModuleInfo *getProcModuleInfo(SceUID pid, int *cpu_suspend_intr){

	int r0;
	SceKernelProcessModuleInfo *res;

	r0 = process_check(pid);
	if(r0 < 0){
		res = NULL;
	}else{
		res = SceProcessmgrForKernel_C1C91BB2(pid);
		if(res != NULL)
			*cpu_suspend_intr = ksceKernelCpuSuspendIntr((int *)(&res->cpu_addr));

		release_obj_for_user(pid);
	}

	return res;
}

/*
 * resume_cpu_intr / func_0x81006e90 (checked)
 */
int resume_cpu_intr(SceKernelProcessModuleInfo *pProcModuleInfo, int cpu_suspend_intr){
	return ksceKernelCpuResumeIntr((int *)(&pProcModuleInfo->cpu_addr), cpu_suspend_intr);
}

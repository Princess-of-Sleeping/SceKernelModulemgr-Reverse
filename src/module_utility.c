/*
 * PS Vita kernel module manager RE Utility
 * Copyright (C) 2020, Princess of Sleeping
 */

#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>

#include "import_defs.h"
#include "modulemgr_types.h"
#include "modulemgr_internal.h"
#include "modulemgr_common.h"

extern SceClass *pSceUIDLibraryClass;
extern SceClass *pSceUIDModuleClass;
extern SceClass *pSceUIDLibStubClass;

extern void *SceKernelModulemgr_data;

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
		res = sceKernelGetProcessModuleInfoForKernel(pid);
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

/*
 * set_module_info_path / func_0x81005a70
 */
int set_module_info_path(SceModuleInfoInternal *pModuleInfo, const char *path, int flags){

	int res = 0;
	int path_len;
	void *pPath;

	if((pModuleInfo->flags & 0x500) != 0){
		pModuleInfo->path = pModuleInfo->pSharedInfo->pModuleInfo->path;
		return 0;
	}

	path_len = strnlen(path, 0xff);
	if(((pModuleInfo->flags & 0x8000) != 0) && (0xfe < path_len)){
		res = 0x8002D01F;
	}else{
		pPath = alloc_for_process(pModuleInfo->pid, path_len + 1);
		pModuleInfo->path = pPath;
		if(pPath == NULL){
			res = 0x8002D008;
		}else{
			memcpy(pPath, path, path_len);
			pModuleInfo->path[path_len] = 0;

			if((flags & 0x800) != 0){
				memcpy(pModuleInfo->path, "bootfs:", 7);
				return 0;
			}
		}
	}

	return res;
}

/*
 * is_process_compiled_new_sdk / func_0x81006da4 (checked)
 */
int is_process_compiled_new_sdk(SceUID pid){

	unsigned int version = 0;

	if(sceKernelGetCompiledSdkVersionByPidForDriver(pid, &version) < 0)
		return 0;

	return (version < 0x1800000) ? 0 : 1;
}

/*
 * search_shared_info_by_path / func_0x81007148 (checked)
 */
SceModuleSharedInfo *search_shared_info_by_path(const char *path){

	int cpu_intr;
	SceModuleSharedInfo *pSharedInfo;

	pSharedInfo = *(SceModuleSharedInfo **)(SceKernelModulemgr_data + 0x30C);

	cpu_intr = ksceKernelCpuSuspendIntr((int *)(SceKernelModulemgr_data + 0x310));

	while(pSharedInfo != NULL){
		if(strncmp(pSharedInfo->pModuleInfo->path, path, 0x100) == 0){
			pSharedInfo->info_linked_number += 1;
			goto end;
		}

		pSharedInfo = pSharedInfo->next;
	}

end:
	ksceKernelCpuResumeIntr((int *)(SceKernelModulemgr_data + 0x310), cpu_intr);

	return pSharedInfo;
}

/*
 * shared_info_decrements / func_0x810071a8
 */
int shared_info_decrements(SceModuleSharedInfo *pSharedInfo){

	int cpu_suspend_intr;
  
	cpu_suspend_intr = ksceKernelCpuSuspendIntr((int *)(SceKernelModulemgr_data + 0x310));
	pSharedInfo->info_linked_number -= 1;
	ksceKernelCpuResumeIntr((int *)(SceKernelModulemgr_data + 0x310), cpu_suspend_intr);

	return 0;
}

/*
 * is_inhibit_shared / func_0x81007f00 (checked)
 */
int is_inhibit_shared(SceUID pid){
	return sceKernelGetProcessModuleInfoForKernel(pid)->inhibit_state & 1;
}

/*
 * update_shared_info_node / func_0x81007f10 (checked)
 */
void update_shared_info_node(SceModuleInfoInternal *pModuleInfo){

	int res, cpu_suspend_intr, cpu_intr;
	SceSize filesz;
	void *ptr, *vaddr;
	SceKernelProcessModuleInfo *pProcModuleInfo;
	SceModuleSharedInfo *pSharedInfo;

	pProcModuleInfo = getProcModuleInfo(pModuleInfo->pid, &cpu_suspend_intr);
	if(pProcModuleInfo == NULL)
		return;

	pModuleInfo->next = pProcModuleInfo->pModuleInfo;
	pProcModuleInfo->process_module_count += 1;
	pProcModuleInfo->pModuleInfo = pModuleInfo;

	if(pProcModuleInfo->data_0x1C != NULL)
		func_0x81006d40(pProcModuleInfo->data_0x1C, pModuleInfo);

	if((pModuleInfo->flags & 0x200) != 0)
		goto loc_81007F64;

loc_81007F4C:
	ksceKernelCpuResumeIntr(&pProcModuleInfo->cpu_addr, cpu_suspend_intr);
	return;

loc_81007F64:
	res = sceKernelGetProcessBudgetTypeForKernel(pModuleInfo->pid);
	if(res == 0x4000000)
		goto loc_81007F80;

loc_81007F72:
	pModuleInfo->flags &= ~0x200;
	goto loc_81007F4C;

loc_81007F80:
	if(is_inhibit_shared(pModuleInfo->pid) != 0)
		goto loc_81007F72;

	pSharedInfo = ksceKernelAlloc(0x10);
	if(pSharedInfo == NULL)
		goto loc_81007F4C;

	pSharedInfo->pModuleInfo = pModuleInfo;

	pSharedInfo->info_linked_number  = 0;
	pSharedInfo->cached_segment_data = NULL;

	if((pModuleInfo->segments[pModuleInfo->segments_num - 1].perms[0] & 2) == 0)
		goto loc_81007FC0;

	vaddr = pModuleInfo->segments[pModuleInfo->segments_num - 1].vaddr;
	if(vaddr == NULL)
		goto loc_81007FC0;

	filesz = pModuleInfo->segments[pModuleInfo->segments_num - 1].filesz;
	if(filesz != 0)
		goto loc_81007FEE;

loc_81007FC0:
	cpu_intr = ksceKernelCpuSuspendIntr((int *)(SceKernelModulemgr_data + 0x310));

	pSharedInfo->next = *(SceModuleSharedInfo **)(SceKernelModulemgr_data + 0x30C);
	*(SceModuleSharedInfo **)(SceKernelModulemgr_data + 0x30C) = pSharedInfo;

	ksceKernelCpuResumeIntr((int *)(SceKernelModulemgr_data + 0x310), cpu_intr);

	goto loc_81007F4C;

loc_81007FEE:
	ptr = ksceKernelAlloc(filesz);
	if(ptr == NULL)
		goto loc_81007F4C;

	res = ksceKernelMemcpyUserToKernelForPid(pModuleInfo->pid, ptr, (uintptr_t)vaddr, filesz);
	if(res >= 0){
		pSharedInfo->cached_segment_data = ptr;
		goto loc_81007FC0;
	}

	ksceKernelFree(ptr);
	goto loc_81007F4C;
}

/*
 * process_lib_is_nonlinked / func_0x810047A4
 */
int process_lib_is_nonlinked(SceUID pid, const char *libname){

	int res, cpu_suspend_intr;
	SceKernelProcessModuleInfo *pProcModuleInfo;
	SceModuleNonlinkedInfo *pNonlinkedInfo;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_suspend_intr);

	pNonlinkedInfo = pProcModuleInfo->pNonlinkedInfo;

	res = 0;

	while(pNonlinkedInfo != NULL){
		if(strncmp(pNonlinkedInfo->pImportInfo->type2.libname, libname, 0x100) == 0){
			res = 1;
			break;
		}
		pNonlinkedInfo = pNonlinkedInfo->next;
	}

	resume_cpu_intr(pProcModuleInfo, cpu_suspend_intr);
	return res;
}

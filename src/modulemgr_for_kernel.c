/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/processmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/cpu.h>

#include "modulemgr_types.h"
#include "modulemgr_internal.h"
#include "module_utility.h"
#include "modulemgr_common.h"
#include "modulemgr_for_driver.h"
#include "modulemgr_for_kernel.h"
#include "module_syscall.h"
#include "import_defs.h"

// return value is previous value
int ksceKernelSetPermission(int value);

// return value is previous value
SceUID ksceKernelSetProcessId(SceUID pid);

extern void *SceKernelModulemgr_text;
extern void *SceKernelModulemgr_data;

SceUID sceKernelGetModuleIdByAddrForKernel(SceUID pid, const void *module_addr){
	return get_module_id_by_addr(pid, module_addr);
}

int sceKernelUnloadProcessModulesForKernel(SceUID pid){

	int cpu_suspend_intr;
	SceKernelProcessModuleInfo *pProcModuleInfo;

	do {

		pProcModuleInfo = getProcModuleInfo(pid, &cpu_suspend_intr);

		if(pProcModuleInfo != NULL && pProcModuleInfo->pModuleInfo != NULL){
			resume_cpu_intr(pProcModuleInfo, cpu_suspend_intr);
			module_stop_unload_for_pid(pid, pProcModuleInfo->pModuleInfo->modid_kernel, 0, 0, 0x40000330, 0, 0);
		}

	} while(pProcModuleInfo != NULL && pProcModuleInfo->pModuleInfo != NULL);

	if(pProcModuleInfo == NULL)
		return 0x8002D080;

	resume_cpu_intr(pProcModuleInfo, cpu_suspend_intr);
	cleanup_process_module_info(pid);

	return 0;
}

int sceKernelModuleUnloadMySelfForKernel(void){

	int res;
	void *lr;
	__asm__ volatile ("mov %0, lr" : "=r" (lr));
	func_0x810014d4();
	*(uint32_t *)(SceKernelModulemgr_data + 0x2F8) = ksceKernelGetThreadId();
	*(uint32_t *)(SceKernelModulemgr_data + 0x2FC) = get_module_id_by_addr(0x10005, lr);

	res = sceKernelEnqueueWorkQueueForDriver(0x10023, "SceKernelUnloadMySelf", (void *)(SceKernelModulemgr_text + 0x3155), (void *)(SceKernelModulemgr_data + 0x2F8));
	if(res < 0)
		goto label_0x81003706;

	res = ksceKernelExitDeleteThread(0);
	if(res > 0)
		res = 0;

label_0x81003706:
	return res;
}

int sceKernelGetModuleInternalByAddrForKernel(SceUID pid, const void *module_addr, SceModuleInfoInternal **ppInfo){

	int res, cpu_intr;
	SceKernelProcessModuleInfo *pProcModuleInfo;

	if(pid == 0)
		pid = ksceKernelGetProcessId();

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_intr);
	if(pProcModuleInfo == NULL)
		return 0x8002D080;

	res = get_module_info_internal_by_addr(pProcModuleInfo, module_addr, ppInfo);
	ksceKernelCpuResumeIntr((int *)(&pProcModuleInfo->cpu_addr), cpu_intr);

	return res;
}

// todo test
int sceKernelGetModuleNonlinkedListForKernel(SceUID pid, SceUID modid, SceKernelModuleNonlinkedInfo *pList, SceSize *num)
{
	return 0;
}

int sceKernelGetModuleInhibitStateForKernel(SceUID pid, int *pState){

	int cpu_intr;
	SceKernelProcessModuleInfo *pProcModuleInfo;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_intr);
	if(pProcModuleInfo == NULL)
		return 0x8002D080;

	*pState = pProcModuleInfo->inhibit_state;

	ksceKernelCpuResumeIntr(&pProcModuleInfo->cpu_addr, cpu_intr);

	return 0;
}

int sceKernelGetModuleInternalForKernel(SceUID modid, SceModuleInfoInternal **ppInfo){

	SceModuleObject *pObj;

	pObj = get_module_object(modid);
	if(pObj == NULL)
		return 0x8002D011;

	if(ppInfo != NULL)
		*ppInfo = &pObj->obj_base;

	ksceKernelUidRelease(modid);

	return 0;
}

// old name is sceKernelGetProcessMainModulePathForKernel
int sceKernelGetModulePathForKernel(SceUID modid, char *path, SceSize pathlen){

	SceModuleObject *pObj;

	pObj = get_module_object(modid);
	if(pObj == NULL)
		return 0x8002D082;

	strncpy(path, pObj->obj_base.path, pathlen);
	release_obj(modid);

	return 0;
}

SceKernelModuleEntry sceKernelGetModuleEntryPointForKernel(SceUID modid){

	SceModuleObject *pObj;

	pObj = get_module_object(modid);
	if(pObj == NULL)
		return NULL;

	ksceKernelUidRelease(modid);

	return pObj->obj_base.module_start;
}

int sceKernelGetModuleEntryPointForUserForKernel(SceUID pid, SceUID UserUid, SceKernelModuleEntry *start, SceKernelModuleEntry *stop){

	SceUID KernelUid;
	SceModuleObject *pObj;

	if(pid == 0x10005)
		return 0x8002D012;

	if(process_check_for_user(pid) < 0)
		return 0x8002D012;

	KernelUid = ksceKernelKernelUidForUserUid(pid, UserUid);
	if(KernelUid < 0){
		ksceKernelUidRelease(pid);
		return KernelUid;
	}

	pObj = get_module_object(KernelUid);
	if(pObj == NULL){
		ksceKernelUidRelease(pid);
		return 0x8002D011;
	}

	*start = pObj->obj_base.module_start;
	*stop  = pObj->obj_base.module_stop;
	ksceKernelUidRelease(KernelUid);
	ksceKernelUidRelease(pid);

	return (*start == NULL) ? 0x8002D01C : 0;
}

SceUID sceKernelGetProcessMainModuleForKernel(SceUID pid){

	SceUID res;
	int cpu_intr;
	SceKernelProcessModuleInfo *pProcModuleInfo;
	SceModuleObject *pObj;

	if(pid == 0x10005)
		return 0x8002D082;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_intr);
	if(pProcModuleInfo == NULL)
		return 0x8002D082;

	pObj = get_module_object(pProcModuleInfo->process_main_module_id);
	if(pObj == NULL){
		ksceKernelCpuResumeIntr(&pProcModuleInfo->cpu_addr, cpu_intr);
		return 0x8002D082;
	}

	if((pObj->obj_base.flags & 0x4000) != 0){
		res = (pObj->obj_base.pid == pid) ? pProcModuleInfo->process_main_module_id : 0x8002D082;
	}else{
		res = 0x8002D082;
	}

	release_obj(pProcModuleInfo->process_main_module_id);
	ksceKernelCpuResumeIntr(&pProcModuleInfo->cpu_addr, cpu_intr);

	return res;
}

/**
 * @brief Get the module fingerprint.
 *
 * @param[in]  modid        - target module id
 * @param[out] pFingerprint - module fingerprint output
 *
 * @return 0 on success, < 0 on error.
 */
int sceKernelGetModuleFingerprintForKernel(SceUID modid, uint32_t *pFingerprint){

	SceModuleObject *pObj;

	pObj = get_module_object(modid);
	if(pObj == NULL)
		return 0x8002D082;

	*pFingerprint = pObj->obj_base.fingerprint;

	release_obj(modid);
	return 0;
}

int sceKernelGetModuleIsSharedByAddrForKernel(SceUID pid, const void *module_addr){

	int res, cpu_intr;
	SceKernelProcessModuleInfo *pProcModuleInfo;
	SceModuleInfoInternal *pModuleInfo;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_intr);
	if(pProcModuleInfo == NULL)
		return 0;

	res = get_module_info_internal_by_addr(pProcModuleInfo, module_addr, &pModuleInfo);

	res = (res < 0) ? 0 : ((pModuleInfo->flags >> 0xC) & 1);

	ksceKernelCpuResumeIntr((int *)(&pProcModuleInfo->cpu_addr), cpu_intr);

	return res;
}

//  sceKernelGetModuleAppInfoForKernel("os0:ue/cui_setupper.self", sp + 0x60, sp + 0x70);
int sceKernelGetModuleAppInfoForKernel(const char *path, uint64_t *pAuthid, SceSelfAppInfo *pInfo){
	// yet not Reversed
	return 0;
}

int sceKernelGetModuleInfoForKernel(SceUID pid, SceUID modid, SceKernelModuleInfo *info){

	if(pid == 0)
		pid = ksceKernelGetProcessId();

	return get_module_info(pid, modid, (SceKernelModuleInfo_fix_t *)info);
}

int sceKernelFinalizeKblForKernel(void){

	SceUID modid;

	modid = *(SceUID *)(*(uint32_t *)(SceKernelModulemgr_data + 0x38) + 0xA8);
	if(modid <= 0){
		return 0;
	}

	return module_stop_unload_for_pid(0x10005, modid, 0, 0, 0, 0, 0);
}

SceUID sceKernelLoadModuleForPidForKernel(SceUID pid, const char *path, int flags, SceKernelLMOption *option){

	SceUID res;
	int OldPermission, OldPid;

	if(pid == 0)
		return 0x8002D017;

	if(((flags & ~0x7D800) & ~0x1F0) != 0)
		return 0x8002000A;

	OldPermission = ksceKernelSetPermission(0x80);
	OldPid = ksceKernelSetProcessId(0x10005);
	res = module_load_for_pid(pid, path, flags | 2, option);
	ksceKernelSetProcessId(OldPid);
	ksceKernelSetPermission(OldPermission);

	return res;
}

int sceKernelStartModuleForPidForKernel(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){

	if(pid == 0)
		return 0x8002D017;

	if(flags != 0)
		return 0x8002000A;

	return module_start_for_pid(pid, modid, args, argp, flags, option, status);
}

int sceKernelUnloadModuleForPidForKernel(SceUID pid, SceUID modid, int flags, SceKernelULMOption *option){

	if(pid == 0)
		return 0x8002D017;

	if((flags & ~0x40000000) != 0)
		return 0x8002000A;

	return module_unload_for_pid(pid, modid, flags, option);
}

int sceKernelStopModuleForPidForKernel(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){

	if(pid == 0)
		return 0x8002D017;

	if(flags != 0)
		return 0x8002000A;

	return module_stop_for_pid(pid, modid, args, argp, flags, option, status);
}

int sceKernelMountBootfsForKernel(const char *bootImagePath){

	int res;
	void *pRes;
	SceUID modid;

	void *pBootfsMountInfo = (void *)(SceKernelModulemgr_data + 0x304);

	if(*(uint32_t *)(pBootfsMountInfo) != 0)
		goto label_0x81004AF6;

	modid = sceKernelLoadStartModuleForDriver(bootImagePath, 0, 0, 0x100, 0, 0);
	if(modid < 0){
		res = modid;
		goto label_0x81004AF2;
	}

	pRes = ksceKernelAlloc(0x10);
	*(uint32_t *)(pBootfsMountInfo) = (uint32_t)pRes;
	*(uint32_t *)(pRes + 0x00) = modid;
	*(uint32_t *)(pRes + 0x04) = 0xFFFFFFFF;
	*(uint32_t *)(pRes + 0x08) = 0;
	*(uint32_t *)(pRes + 0x0C) = 0;
	get_module_object(modid);
	release_obj(modid);
	res = 0;

label_0x81004AF2:

	return res;

label_0x81004AF6:
	return 0x8002D021;
}

int sceKernelUmountBootfsForKernel(void){

	int res;
	SceUID modid;
	void *pBootfsMountInfo = (void *)(SceKernelModulemgr_data + 0x304);

	if(*(uint32_t *)(pBootfsMountInfo) == 0)
		goto label_0x81004B34;

	modid = *(SceUID *)(*(uint32_t *)(pBootfsMountInfo));

	sceKernelStopUnloadModuleForDriver(modid, 0, 0, 0, 0, 0);
	ksceKernelFree((void *)(*(uint32_t *)(pBootfsMountInfo)));
	res = 0;
	*(uint32_t *)(pBootfsMountInfo) = 0;

label_0x81004B30:
	return res;

label_0x81004B34:
	res = 0x8002D001;
	goto label_0x81004B30;
}

SceUID sceKernelLoadProcessImageForKernel(SceUID pid, const char *path, int a3, void *auth_info, SceLoadProcessParam *pParam, int a6)
{
	// yet not Reversed
	return 0;
}

int sceKernelLoadPtLoadSegForFwloaderForKernel(const char *path, int e_phnum, void *buffer, SceSize bufsize, int zero_unk, SceSize *bytes_read)
{
	// yet not Reversed
	return 0;
}

int sceKernelGetModuleListForKernel(SceUID pid, int flags1, int flags2, SceUID *modids, SceSize *num){

	int cpu_intr;
	SceSize count = 0;
	SceModuleInfoInternal *pModuleInfo;
	SceKernelProcessModuleInfo *pProcModuleInfo;

	if(pid == 0)
		pid = ksceKernelGetProcessId();

	if(modids == NULL)
		goto module_count_mode;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_intr);
	if(pProcModuleInfo == NULL)
		return 0x8002D080;

	pModuleInfo = pProcModuleInfo->pModuleInfo;

	while(*num > count){
		if(pModuleInfo == NULL)
			break;

		if((pid != 0x10005) && ((flags1 & 1) != 0) && ((pModuleInfo->flags & 0x1000) == 0)){
			modids[count] = ((flags2 & 1) == 0) ? pModuleInfo->modid_user : pModuleInfo->modid_kernel;
			count++;
		}

		if((pid == 0x10005) || (((flags1 & 0x80) != 0) && ((pModuleInfo->flags & 0x1000) != 0))){
			if((flags2 & 1) == 0){
				if((flags2 & 2) != 0){
					modids[count] = pModuleInfo->modid_user;
					count++;
				}
			}else{
				modids[count] = pModuleInfo->modid_kernel;
				count++;
			}
		}

		pModuleInfo = pModuleInfo->next;
	}

	ksceKernelCpuResumeIntr(&pProcModuleInfo->cpu_addr, cpu_intr);

	*num = count;

	return 0;

module_count_mode:
	pProcModuleInfo = getProcModuleInfo(pid, &cpu_intr);
	if(pProcModuleInfo == NULL)
		return 0;

	pModuleInfo = pProcModuleInfo->pModuleInfo;

	while(pModuleInfo != NULL){
		if (pid == 0x10005){
			count++;
		}else if (((flags1 & 1) != 0) && ((pModuleInfo->flags & 0x1000) == 0)){
			count++;
		}else if (((flags1 & 0x80) != 0) && ((pModuleInfo->flags & 0x1000) != 0)){
			count++;
		}

		pModuleInfo = pModuleInfo->next;
	}

	ksceKernelCpuResumeIntr(&pProcModuleInfo->cpu_addr, cpu_intr);

	return count;
}

int sceKernelGetModuleNonlinkedImportInfoForKernel(SceUID pid, SceKernelModuleImportNID *info, SceSize *num){

	int cpu_intr;
	SceSize count = 0;
	SceModuleNonlinkedInfo *pNonlinkedInfo;
	SceKernelProcessModuleInfo *pProcModuleInfo;

	if(info == NULL){
		pProcModuleInfo = getProcModuleInfo(pid, &cpu_intr);
		ksceKernelCpuResumeIntr(&pProcModuleInfo->cpu_addr, cpu_intr);

		return *(uint16_t *)(((int)pProcModuleInfo) + 0xA);
	}

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_intr);
	if(pProcModuleInfo == NULL)
		return 0x8002D080;

	pNonlinkedInfo = pProcModuleInfo->pNonlinkedInfo;

	while(*num > count && pNonlinkedInfo != NULL){

		info[count].libnid = pNonlinkedInfo->pImportInfo->type2.libnid;
		info[count].modid  = (pid == 0x10005) ? pNonlinkedInfo->pModuleInfo->modid_kernel : pNonlinkedInfo->pModuleInfo->modid_user;

		count++;
		pNonlinkedInfo = pNonlinkedInfo->next;
	}

	ksceKernelCpuResumeIntr(&pProcModuleInfo->cpu_addr, cpu_intr);

	*num = count;

	return 0;
}

int sceKernelGetProcessLibStubIdListForKernel(SceUID pid, SceUID *libstub_ids, SceSize *num)
{
	// yet not Reversed
	return 0;
}

int sceKernelGetProcessLibraryIdListForKernel(SceUID pid, SceUID *library_ids, SceSize *num)
{
	// yet not Reversed
	return 0;
}

int sceKernelGetModuleImportListForKernel(SceUID pid, SceUID modid, SceUID *library_ids, SceSize *num)
{
	// yet not Reversed
	return 0;
}

int sceKernelGetModuleExportListForKernel(SceUID pid, SceUID modid, SceUID *library_ids, SceSize *num)
{
	// yet not Reversed
	return 0;
}

int SceModulemgrForKernel_29CB2771(SceUID pid)
{
	// yet not Reversed
	return 0;
}

void sceKernelSetupForModulemgrForKernel(void)
{
	int cpu_intr;
	void *dat;
	void *lr;

	asm volatile ("mov %0, lr\n" : "=r" (lr));

	syacall_init();
	dat = getProcModuleInfo(0x10005, &cpu_intr);
	if (dat == NULL)
		ksceDebugPrintKernelPanic((void *)(SceKernelModulemgr_text + 0xD84C), lr);

	if (*(uint32_t *)(dat + 4) == 0)
		goto loc_81004152;

loc_81004142:
	if (func_0x810040c8((SceKernelProcessModuleInfo *)(*(uint32_t *)(dat + 4))) < 0)
		ksceDebugPrintKernelPanic((void *)(SceKernelModulemgr_text + 0xD81C), lr);

	if (*(uint32_t *)(*(uint32_t *)(dat + 4)) != 0)
		goto loc_81004142;

loc_81004152:
	func_0x810070b4(dat);
	resume_cpu_intr(dat, cpu_intr);
	return;
}

int sceKernelGetModuleListByImportForKernel(SceUID pid, SceUID library_id, SceUID *modids, SceSize *num, SceSize cpy_skip_num)
{
	// yet not Reversed
	return 0;
}

int sceKernelGetModuleList2ForKernel(SceUID pid, SceKernelModuleListInfo *infolists, size_t *num)
{
	// yet not Reversed
	return 0;
}

int SceModulemgrForKernel_4865C72C(SceUID pid, const char *libname)
{
	// yet not Reversed
	return 0;
}

int sceKernelGetModuleLibraryInfoForKernel(SceUID pid, SceUID library_id, SceKernelModuleLibraryInfo *info){

	int res;
	SceModuleLibraryObject *pObj;
	SceModuleLibraryInfo *pLibraryInfo;

	res = process_check(pid);
	if (res < 0)
		return res;

	pObj = get_library_object(pid, library_id);
	if(pObj == NULL){
		release_obj_for_user(pid);
		return 0x8002D01C;
	}

	pLibraryInfo = pObj->pLibraryInfo;

	info->library_id         = (pLibraryInfo->libid_kernel != library_id) ? pLibraryInfo->libid_user : pLibraryInfo->libid_kernel;
	info->libnid             = pLibraryInfo->pExportInfo->libnid;
	info->version            = pLibraryInfo->pExportInfo->version;
	info->flags              = pLibraryInfo->pExportInfo->flags;
	info->entry_num_function = pLibraryInfo->pExportInfo->entry_num_function;
	info->entry_num_variable = pLibraryInfo->pExportInfo->entry_num_variable;
	info->unk_0x14           = 0;

	info->number_of_imported = pLibraryInfo->number_of_imported;
	info->modid2             = (pid != 0x10005) ? pLibraryInfo->pModuleInfo->modid_user : info->library_id;

	info->library_name[0xFF] = 0;
	strncpy(info->library_name, pLibraryInfo->pExportInfo->libname, 0xFF);

	release_obj(pObj->modid);
	ksceKernelUidRelease(pLibraryInfo->libid_kernel);
	release_obj_for_user(pid);

	return 0;
}

int sceKernelGetModuleInfoMinByAddrForKernel(
	SceUID pid, const void *module_addr, uint32_t *pFingerprint, const void **program_text_addr, SceKernelModuleName_fix *module_name
)
{
	int res;
	int cpu_intr;
	SceKernelProcessModuleInfo *module_proc_info;
	SceModuleInfoInternal *modobj;

	module_proc_info = getProcModuleInfo(pid, &cpu_intr);
	if (module_proc_info == NULL)
		return 0x8002D082;

	res = get_module_info_internal_by_addr(module_proc_info, module_addr, &modobj);
	if (res < 0)
		goto loc_81007ED6;

	if (pFingerprint != NULL)
		*pFingerprint = modobj->fingerprint;

	if (program_text_addr != NULL)
		*program_text_addr = modobj->segments[0].vaddr;

	if (module_name != NULL)
		strncpy(module_name->s, modobj->module_name, 0x1B);

loc_81007ED6:
	ksceKernelCpuResumeIntr(&module_proc_info->cpu_addr, cpu_intr);
	return res;
}

int sceKernelGetModuleKernelExportListForKernel(SceModuleLibraryInfo **list, SceSize *num)
{
	// yet not Reversed
	return 0;
}

int sceKernelGetModuleImportNonlinkedInfoByNIDForKernel(SceUID pid, SceUID modid, uint32_t libnid, SceKernelModuleImportNonlinkedInfo *info)
{
	// yet not Reversed
	return 0;
}

int SceModulemgrForKernel_60E176C8(int a1)
{
	if (*(uint32_t *)(SceKernelModulemgr_data + 0x308) == 0)
		goto loc_81005A30;

	if (*(uint32_t *)(SceKernelModulemgr_data + 0x308) != a1)
		return 0x8002D01D;

loc_81005A30:
	*(uint32_t *)(SceKernelModulemgr_data + 0x308) = a1;
	return 0;
}

int SceModulemgrForKernel_9D20C9BB(int a1)
{
	int res;

	if (*(uint32_t *)(SceKernelModulemgr_data + 0x308) == a1){
		*(uint32_t *)(SceKernelModulemgr_data + 0x308) = 0;
		res = 0;
	}else{
		res = 0x8002D01C;
	}
	return res;
}

int SceModulemgrForKernel_B73BE671(SceUID pid, SceUID libstub_id, void *a3)
{
	// yet not Reversed
	return 0;
}

// SceUID SceSysmemForKernel_libid = get_module_export_library_id(0x10005, search_module_by_name(0x10005, "SceSysmem"), 0x63a519e5);
/*
 * cpy_skip_num is >= 2, 1 == 0
 */
int sceKernelGetModuleLibExportListForKernel(SceUID pid, SceUID libid, SceKernelModuleExportEntry *list, SceSize *num, SceSize cpy_skip_num)
{
	// yet not Reversed
	return 0;
}

void SceModulemgrForKernel_F3CD647F(int a1, int a2)
{
	*(uint32_t *)(SceKernelModulemgr_data + 0x330) = a1;
	*(uint32_t *)(SceKernelModulemgr_data + 0x32C) = a2;
}

int SceModulemgrForKernel_FB251B7A(SceUID pid, SceUID libstub_id, void *a3, SceSize *num, SceSize cpy_skip_num)
{
	// yet not Reversed
	return 0;
}

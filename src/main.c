/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

/*
 * System Version : 3.60
 *
 * text 0x81000000
 * data 0x8100F000
 *
 */

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/processmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/io/fcntl.h>
#include <taihen.h>

#include <stdio.h>
#include <string.h>

#include "import_defs.h"
#include "modulemgr_types.h"
#include "modulemgr_internal.h"
#include "modulemgr_for_driver.h"
#include "modulemgr_for_kernel.h"
#include "modulemgr_common.h"
#include "syscall.h"
#include "search.h"
#include "debug.h"

int write_file(const char *path, const void *data, size_t length){

	SceUID fd = ksceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 6);
	if (fd < 0)
		return fd;

	ksceIoWrite(fd, data, length);
	ksceIoClose(fd);

	return 0;
}

int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

#define HookExport(module_name, library_nid, func_nid, func_name) \
	taiHookFunctionExportForKernel(0x10005, &func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patch)
#define HookImport(module_name, library_nid, func_nid, func_name) \
	taiHookFunctionImportForKernel(0x10005, &func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patch)
#define HookOffset(modid, offset, thumb, func_name) \
	taiHookFunctionOffsetForKernel(0x10005, &func_name ## _ref, modid, 0, offset, thumb, func_name ## _patch)

#define HookRelease(hook_uid, hook_func_name)({ \
	(hook_uid > 0) ? taiHookReleaseForKernel(hook_uid, hook_func_name ## _ref) : -1; \
})

#define GetExport(modname, libnid, funcnid, func) module_get_export_func(0x10005, modname, libnid, funcnid, (uintptr_t *)func)

void *SceKernelModulemgr_text = NULL;
void *SceKernelModulemgr_data = NULL;

int *pThreadSomeInfo;

SceClass *pSceUIDLibraryClass;
SceClass *pSceUIDModuleClass;
SceClass *pSceUIDLibStubClass;

int (* _modulemgr_lock_mutex)(void);
int (* _modulemgr_unlock_mutex)(void);
int (* _set_modobj_type)(SceKernelModuleInfoObjBase_t *objbase, uint8_t type);
void (* _module_unload_some_cleanup)(SceKernelModuleInfoObjBase_t *objbase);

void *(* _func_0x81007148)(const char *path);
void *(* _func_0x81007f00)(SceUID pid);
int (* _func_0x810071a8)(void *a1);
void (* _func_0x810014a8)(void);
SceUID (* _func_0x810049fc)(const char *path);
int (* _func_0x81001518)(SceKernelModuleInfoObj_t *modobj, const char *path, SceUID fd, void *a4, uint32_t flags);

int SceKernelModulemgr_module_start(SceSize args, void *argp){

	SceClass *sysroot_module_cls;

	sysroot_module_cls = (SceClass *)_ksceKernelSysrootGetModulePrivate(9);

	pSceUIDModuleClass  = (SceClass *)(&sysroot_module_cls[0]);
	pSceUIDLibraryClass = (SceClass *)(&sysroot_module_cls[1]);
	pSceUIDLibStubClass = (SceClass *)(&sysroot_module_cls[2]);

	return 0;
}

int get_data(void){

	SceKernelModuleInfo sce_info;
	sce_info.size = sizeof(SceKernelModuleInfo);

	SceUID modid = sceKernelSearchModuleByNameForDriver("SceKernelModulemgr");

	sceKernelGetModuleInfoForKernel(KERNEL_PID, modid, &sce_info);

	ksceDebugPrintf("SceKernelModulemgr modid : 0x%X\n", modid);
	ksceDebugPrintf("%s\n", sce_info.module_name);

	SceKernelModulemgr_text = sce_info.segments[0].vaddr;
	SceKernelModulemgr_data = sce_info.segments[1].vaddr;

	return 0;
}

void func_0x810014a8(void){

	int r0 = 1;
	int r1 = 0;
  
	do{
		if((r0 & *(uint32_t *)(SceKernelModulemgr_data + 0x30)) != 0){
			*(int *)(SceKernelModulemgr_data + r1) += 1;
		}

		r0 <<= 1;
		r1 += 4;
	}while(r1 != 0x30);

	*(uint32_t *)(SceKernelModulemgr_data + 0x30) = 0;

	return;
}

void func_0x810014d4(void){

	void *ptr = (void *)(SceKernelModulemgr_data);
	*(uint32_t *)(ptr + 0x0) = 0;
	*(uint32_t *)(ptr + 0x4) = 0;
	ptr += 8;
	*(uint32_t *)(ptr + 0x0) = 0;
	*(uint32_t *)(ptr + 0x4) = 0;
	ptr += 8;
	*(uint32_t *)(ptr + 0x0) = 0;
	*(uint32_t *)(ptr + 0x4) = 0;
	ptr += 8;
	*(uint32_t *)(ptr + 0x0) = 0;
	*(uint32_t *)(ptr + 0x4) = 0;
	ptr += 8;
	*(uint32_t *)(ptr + 0x0) = 0;
	*(uint32_t *)(ptr + 0x4) = 0;
	ptr += 8;
	*(uint32_t *)(ptr + 0x0) = 0;
	*(uint32_t *)(ptr + 0x4) = 0;
	ptr += 8;
	*(uint32_t *)(ptr + 0x0) = 0;

	return;
}

int func_0x81001ec4(SceUID pid){
	return ksceKernelGetObjForUid(pid, sceKernelGetProcessClassForKernel(), 0);
}

SceKernelModuleInfoObj_t *func_0x81001f0c(SceUID modid){

	SceKernelModuleInfoObj_t *obj_base;

	if(ksceKernelGetObjForUid(modid, pSceUIDModuleClass, (SceObjectBase **)&obj_base) < 0){
		obj_base = NULL;
	}

	return obj_base;
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

int func_0x810021c0(SceUID pid){
	if(pid != 0x10005){
		return func_0x81001ec4(pid);
	}

	return 0;
}

int func_0x810040c8(SceKernelProcessModuleInfo *pProcModuleInfo)
{
	// yet not Reversed
	return 0;
}

int func_0x81004198(void *a1, int a2, int a3)
{
	// yet not Reversed
	return 0;
}

int func_0x8100428c(void *a1, int a2, int a3)
{
	// yet not Reversed
	return 0;
}

// sceKernelAllocProc
void *func_0x8100498c(SceUID pid, SceSize len){

	void *res;

	if(pid != 0x10005){
		res = sceKernelAllocRemoteProcessHeapForDriver(pid, len, NULL);
	}else{
		res = ksceKernelAlloc(len);
	}

	return res;
}

// sceIoOpenBootfs
int func_0x810049fc(const char *path){

	const char **pPath;
	int r0;
	int r1;

	if((*(uint32_t *)(SceKernelModulemgr_data + 0x304) != 0) && (*(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 8) > 0)){
		r0 = 0;
		r1 = 0;
		do{
			pPath = (const char **)(*(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 0xc) + r0);
			r0 += 0xC;
			if(strncmp(path, *pPath, 0xFF) == 0){
				*(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 4) = r1;
				return 0x7f7f7f7f;
			}
			r1 += 1;
		}while(r1 != *(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 8));
	}

	return 0x80010002;
}

// sceIoCloseBootfs
int func_0x81004a54(SceUID fd){
	*(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 4) = 0xffffffff;
	return 0;
}

/*
 * create_new_module_class / 0x81005648 (checked)
 */
int func_0x81005648(SceUID pid, int flags, SceKernelModuleInfoObj_t **dst){

	int res;
	SceKernelModuleInfoObj_t *modobj;
	SceCreateUidObjOpt opt;

	if(pid == 0x10005){
		res = _ksceKernelCreateUidObj(pSceUIDModuleClass, "SceModuleMgrNewModule", 0, (SceObjectBase **)&modobj);
		if (res < 0)
			return res;

		modobj->obj_base.version      = 0xFFFFFFFF;
		modobj->obj_base.modid_kernel = res;
		modobj->obj_base.pid          = 0x10005;
	}else{
		opt.field_10 = ((flags & 0x10) != 0) ? 1 : 0;

		opt.flags    = 8;
		opt.field_4  = 0;
		opt.field_8  = 0;
		opt.pid      = pid;
		opt.field_14 = 0;
		opt.field_18 = 0;

		res = SceProcessmgrForKernel_B75FB970(pid); // wrong arg
		if(res < 0)
			return res;

		res = _ksceKernelCreateUidObj(pSceUIDModuleClass, "SceModuleMgrNewModule", &opt, (SceObjectBase **)&modobj);
		if(res < 0){
			SceProcessmgrForKernel_0A5A2CF1(pid, opt.field_10);
			return res;
		}

		modobj->obj_base.version      = 0x03600011;
		modobj->obj_base.modid_kernel = res;
		modobj->obj_base.pid          = pid;
	}

	if(dst != NULL){
		*dst = modobj;
	}

	return 0;
}

// 0x81001868
int modulemgr_lock_mutex(void){
	return _modulemgr_lock_mutex();
}

// 0x81001884
int modulemgr_unlock_mutex(void){
	return _modulemgr_unlock_mutex();
}

// 0x8100496C
int memcpy_to_kernel(SceUID pid, void *dst, const void *src, SceSize len){
	if(pid == 0x10005){
		memcpy(dst, src, len);
		return 0;
	}
	return ksceKernelMemcpyUserToKernelForPid(pid, dst, (uintptr_t)src, len);
}

// 0x81005A5C
int set_modobj_type(SceKernelModuleInfoObjBase_t *objbase, uint8_t type){
	return _set_modobj_type(objbase, type);
}

// 0x810071CC
void module_unload_some_cleanup(SceKernelModuleInfoObjBase_t *objbase){
	_module_unload_some_cleanup(objbase);
}

int func_0x81005a70(SceKernelModuleInfoObjBase_t *pInfo, const char *path, int flags){

	int res = 0;
	int path_len;
	void *pPath;

	if((pInfo->flags & 0x500) != 0){
		pInfo->path = (char *)(*(uint32_t *)(*(uint32_t *)(pInfo->data_0xD4 + 4) + 0x68));
		return 0;
	}

	path_len = strnlen(path, 0xff);
	if(((pInfo->flags & 0x8000) != 0) && (0xfe < path_len)){
		res = 0x8002D01F;
	}else{
		pPath = func_0x8100498c(pInfo->pid, path_len + 1);
		pInfo->path = pPath;
		if(pPath == NULL){
			res = 0x8002D008;
		}else{
			memcpy(pPath, path, path_len);
			pInfo->path[path_len] = 0;

			if((flags & 0x800) != 0){
				memcpy(pInfo->path, "bootfs:", 7);
				return 0;
			}
		}
	}

	return res;
}

int func_0x81005fec(void *a1, const void *a2)
{
	// yet not Reversed
	return 0;
}

void func_0x81006744(void *a1){

	*(uint32_t *)(a1 + 0x0) = 0;
	*(uint32_t *)(a1 + 0xC) = 0;

	if(*(SceUID *)(a1 + 4) <= 0)
		goto label_0x8100675A;

	ksceKernelDeleteUid(*(SceUID *)(a1 + 4));
	*(SceUID *)(a1 + 0x4) = 0;

label_0x8100675A:
	return;
}

void *func_0x81006cf4(int a1, void *a2, const void *a3, void *a4){

	void *res;

	*(uint32_t *)(a4) = 0;

	res = (void *)(((uint32_t)a3 - 0x200000) >> 0xC);

	if((uint32_t)(res) < 0x8000)
		goto label_0x81006D36;

	res = (void *)(((uint32_t)a3 + -0x8000000) >> 0xC);

	if((uint32_t)(res) < 0x8000)
		goto label_0x81006D32;

	a3 = (const void *)((uint32_t)a3 + 0x7F000000);

	if((uint32_t)a3 < 0x6F000000){
		a2 = (void *)(*(uint32_t *)(a2));
		a3 = (const void *)((uint32_t)a3 >> 0xC);
	}else{
		a1 = 0;
	}

	if((uint32_t)a3 < 0x6F000000){
		a1 = a1 + ((uint32_t)a3 << 2);
		a3 = (const void *)((uint32_t)a2 + ((uint32_t)a3 << 3));
		*(uint32_t *)(a4) = (uint32_t)a3;
	}
	return (void *)a1;

label_0x81006D32:
	res += 0x8000;

label_0x81006D36:
	a1 = a1 + ((uint32_t)res << 2);
	return (void *)a1;
}

int func_0x81006D40(void *a1, void *a2)
{
	// yet not Reversed
	return 0;
}

int func_0x81006da4(SceUID uid){

	int a1 = 0;

	if(SceProcessmgrForDriver_D141C076(uid, &a1) < 0){
		return 0;
	}

	return ((uint32_t)(a1) < 0x1800000) ? 0 : 1;
}

SceModuleLibraryObj_t *func_0x81006de8(SceUID pid, SceUID libid){

	SceModuleLibraryObj_t *SceModuleLibraryObj;

	if((pid != 0x10005) && (func_0x81006da4(pid) == 1))
		libid = ksceKernelKernelUidForUserUid(pid, libid);

	if(libid < 0)
		return NULL;

	if(ksceKernelGetObjForUid(libid, pSceUIDLibraryClass, (SceObjectBase **)&SceModuleLibraryObj) < 0)
		return NULL;

	if(func_0x81001f0c(SceModuleLibraryObj->modid) != NULL)
		return SceModuleLibraryObj;

	ksceKernelUidRelease(libid);
	return NULL;
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

	r0 = func_0x810021c0(pid);
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

int func_0x81006e90(SceKernelProcessModuleInfo *pProcModuleInfo, int cpu_suspend_intr){
	return ksceKernelCpuResumeIntr((int *)(&pProcModuleInfo->cpu_addr), cpu_suspend_intr);
}

int func_0x81006e9c(SceUID pid){

	int cpu_suspend_intr;
	void *pRes;
	char data[0x24];
	void *arg1;

	pRes = getProcModuleInfo(pid, &cpu_suspend_intr);
	if(pRes == 0)
		return 0;

	memcpy(data, pRes, 0x24);

	memset(pRes, 0, 0x20);

	ksceKernelCpuResumeIntr((int *)(pRes + 0x20), cpu_suspend_intr);

	arg1 = (void *)(*(uint32_t *)(&data[0xC]));
	if(arg1 != 0)
		goto label_0x81006EE6;

	goto label_0x81006EF0;

label_0x81006EE6:
	func_0x81006744(arg1);
	arg1 = (void *)(*(uint32_t *)(arg1));
	if(arg1 != 0)
		goto label_0x81006EE6;

label_0x81006EF0:
	arg1 = (void *)(*(uint32_t *)(&data[0x1C]));

	if(arg1 == 0)
		return 0;

	ksceKernelFreeMemBlock(*(uint32_t *)(arg1 + 4));

	if(*(uint32_t *)(arg1 + 0xC) <= 0)
		goto label_0x81006F04;

	ksceKernelFreeMemBlock(*(uint32_t *)(arg1 + 0xC));

label_0x81006F04:
	if(*(uint32_t *)(arg1 + 0x8) <= 0)
		goto label_0x81006F0E;

	ksceKernelFreeMemBlock(*(uint32_t *)(arg1 + 0x8));

label_0x81006F0E:
	return SceProcessmgrForKernel_41815DF2(pid, arg1);
}

int func_0x810070b4(void *a1)
{
	int res;

	/*
	 * allow devkit only
	 */
	if(ksceKernelCheckDipsw(0xD2) != 0)
		goto loc_810070DE;

loc_810070CE:
	res = 0;

loc_810070D0:
	return res;

loc_810070DE:
	*(uint32_t *)(a1 + 0x1C) = (uint32_t)(SceKernelModulemgr_data + 0x318);

	SceKernelAllocMemBlockKernelOpt memblk_opt;

	memset(&memblk_opt, 0, 0x58);

	memblk_opt.size = sizeof(memblk_opt);
	memblk_opt.attr = 0xD0000000;

	res = ksceKernelAllocMemBlock("SceKernelProcess", 0x10F0D006, 0x40000, &memblk_opt);

	*(uint32_t *)(SceKernelModulemgr_data + 0x31C) = res;

	if (res < 0)
		goto loc_810070D0;

	ksceKernelGetMemBlockBase(res, (void **)(SceKernelModulemgr_data + 0x318));
	if ((void *)(*(uint32_t *)(a1 + 0x10)) == NULL)
		goto loc_810070CE;

loc_8100712C:
	func_0x81006D40((void *)(SceKernelModulemgr_data + 0x318), (void *)(*(uint32_t *)(a1 + 0x10)));
	if (*(uint32_t *)(*(uint32_t *)(a1 + 0x10)) != 0)
		goto loc_8100712C;

	goto loc_810070CE;
}

int func_0x81007148(const char *path){

	int cpu_suspend_intr;

	int *piVar3;
  
	cpu_suspend_intr = ksceKernelCpuSuspendIntr((int *)(SceKernelModulemgr_data + 0x310));

	piVar3 = (int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x30C));

	while(1){
		if(piVar3 == (int *)0x0){
			ksceKernelCpuResumeIntr((int *)(SceKernelModulemgr_data + 0x310), cpu_suspend_intr);
			return 0;
		}
		if(strncmp((char *)*(uint32_t *)(piVar3[1] + 0x68), path, 0x100) == 0)
			break;
		piVar3 = (int *)piVar3[0];
	}
	piVar3[2] += 1;
	ksceKernelCpuResumeIntr((int *)(SceKernelModulemgr_data + 0x310), cpu_suspend_intr);
	return (int)piVar3;
}

int func_0x810071a8(void *r0){

	int cpu_suspend_intr;
  
	cpu_suspend_intr = ksceKernelCpuSuspendIntr((int *)(SceKernelModulemgr_data + 0x310));
	*(int *)(r0 + 8) += -1;
	ksceKernelCpuResumeIntr((int *)(SceKernelModulemgr_data + 0x310), cpu_suspend_intr);
	return 0;
}

// 0x810076b0
int get_module_library_info_export(SceUID pid, SceUID modid, uint32_t libnid, SceKernelLibraryInfo *info)
{
	int cpu_intr;
	SceKernelProcessModuleInfo *pProcModuleInfo;
	SceModuleLibraryExportInfo_t *lib_export_info;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_intr);
	if(pProcModuleInfo == NULL)
		return 0x8002D080;

	lib_export_info = pProcModuleInfo->lib_export_info;

	while(lib_export_info != NULL){
		if((lib_export_info->modobj->modid_kernel == modid) && (lib_export_info->info->libnid == libnid)){
			info->libver[0]          = lib_export_info->info->libver[0];
			info->libver[1]          = lib_export_info->info->libver[1];
			info->libnid             = libnid;
			info->libname            = lib_export_info->info->libname;
			info->entry_num_function = lib_export_info->info->entry_num_function;
			info->entry_num_variable = lib_export_info->info->entry_num_variable;
			info->table_nid          = lib_export_info->info->table_nid;
			info->table_entry        = lib_export_info->info->table_entry;

			ksceKernelCpuResumeIntr(&pProcModuleInfo->cpu_addr, cpu_intr);
			return 0;
		}

		lib_export_info = (lib_export_info->data_0x04 != NULL) ? lib_export_info->data_0x04 : lib_export_info->next;
	}

	ksceKernelCpuResumeIntr(&pProcModuleInfo->cpu_addr, cpu_intr);
	return 0x8002D081;
}

/*
 * get_module_info / 0x81007790
 *
 * @param[in]  pid   - target pid
 * @param[in]  modid - target module id
 * @param[out] info  - module info
 *
 * @return 0 on success, < 0 on error.
 */
int get_module_info(SceUID pid, SceUID modid, SceKernelModuleInfo_fix_t *info){

	int res;
	int mod_seg_num;
	int current_seg;
	int cpu_suspend_intr;
	SceKernelProcessModuleInfo *pProcModuleInfo;
	SceKernelModuleInfoObj_t *info_obj;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_suspend_intr);
	if(pProcModuleInfo == NULL){
		res = 0x8002d080;
		goto loc_810077e6;
	}

	info_obj = func_0x81001f0c(modid);
	if(info_obj == NULL){
		res = 0x8002d082;
	}else{
		if(modid == info_obj->obj_base.modid_kernel){

			info->modid = (pid == 0x10005) ? modid : info_obj->obj_base.modid_user;

			info->attr  = info_obj->obj_base.attr;
			info->minor = info_obj->obj_base.minor;
			info->major = info_obj->obj_base.major;

			strncpy(info->module_name, info_obj->obj_base.module_name, 28-1);

			switch(info_obj->obj_base.type){
			case 1:
			case 2:
			case 0x10:
				info->type = 2;
				break;
			case 3:
				info->type = 6;
				break;
			default:
				info->type = 9;
			}

			info->module_start = info_obj->obj_base.module_start;
			info->module_stop  = info_obj->obj_base.module_stop;
			info->module_exit  = info_obj->obj_base.module_exit;

			info->exidxTop = info_obj->obj_base.exidxTop; info->exidxBtm = info_obj->obj_base.exidxBtm;
			info->extabTop = info_obj->obj_base.extabTop; info->extabBtm = info_obj->obj_base.extabBtm;

			info->tlsInit     = info_obj->obj_base.tlsInit;
			info->tlsInitSize = info_obj->obj_base.tlsInitSize;
			info->tlsAreaSize = info_obj->obj_base.tlsAreaSize;

			strncpy(info->path, info_obj->obj_base.path, 0x100-1);
			mod_seg_num = info_obj->obj_base.segments_num;
			current_seg = 0;

			if(mod_seg_num < 1){
				mod_seg_num = 0;
loc_810078fc:

				do {
					info->segments[mod_seg_num].perms  = 0;
					info->segments[mod_seg_num].vaddr  = 0;
					info->segments[mod_seg_num].memsz  = 0;
					info->segments[mod_seg_num].filesz = 0;
					mod_seg_num++;
				} while (mod_seg_num < 4);

			}else{

				do {
					info->segments[current_seg].size   = 0x18;
					info->segments[current_seg].perms  = (info_obj->obj_base.segments[current_seg].perms[0] | (info_obj->obj_base.segments[current_seg].perms[1] << 0x14));
					info->segments[current_seg].vaddr  = info_obj->obj_base.segments[current_seg].vaddr;
					info->segments[current_seg].memsz  = info_obj->obj_base.segments[current_seg].memsz;
					info->segments[current_seg].filesz = info_obj->obj_base.segments[current_seg].filesz;
					current_seg++;
				} while(current_seg < mod_seg_num);

				if(mod_seg_num < 4)
					goto loc_810078fc;
			}
			res = 0;
		}else{
			res = 0x8002d082;
		}
		release_obj(modid);
	}

	ksceKernelCpuResumeIntr((int *)(&pProcModuleInfo->cpu_addr), cpu_suspend_intr);

loc_810077e6:
	return res;
}

// 0x81007a84
int get_module_info_internal_by_addr(SceKernelProcessModuleInfo *pProcModuleInfo, const void *module_addr, SceKernelModuleInfoObjBase_t **dst){

	void *ptr;
	int temp;
	SceKernelModuleInfoObjBase_t *modobj;

	if(pProcModuleInfo->data_0x1C == NULL)
		goto label_0x81007AC2;

	ptr = func_0x81006cf4(*(uint32_t *)(pProcModuleInfo->data_0x1C), pProcModuleInfo->data_0x1C + 0x10, module_addr, &temp);
	if(ptr == NULL)
		goto label_0x81007AC2;

	modobj = (void *)(*(uint32_t *)(ptr));
	if(modobj == NULL)
		goto label_0x81007AC2;

	if((SceSize)(module_addr - modobj->segments[0].vaddr) >= (SceSize)(modobj->segments[0].memsz))
		goto label_0x81007AC2;

	*dst = modobj;
	return 0;


label_0x81007AC2:
	modobj = pProcModuleInfo->module_list;

	while(modobj != NULL){
		for(int i=0;i<modobj->segments_num;i++){
			if((SceSize)(module_addr - modobj->segments[i].vaddr) < (SceSize)(modobj->segments[i].memsz)){
				*dst = modobj;
				return 0;
			}
		}
		modobj = modobj->next;
	}

	return 0x8002D082;
}

/*
 * get_module_id_by_addr_internal / 0x81007bbc
 *
 * @param[in] pid         - target pid
 * @param[in] module_addr - target module addr
 *
 * @return modid on success, < 0 on error.
 */
int get_module_id_by_addr_internal(SceUID pid, const void *module_addr){

	int res;
	int cpu_suspend_intr;
	SceKernelProcessModuleInfo *pProcModuleInfo;
	SceKernelModuleInfoObjBase_t *modobj;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_suspend_intr);
	if(pProcModuleInfo == NULL)
		return 0x8002D080;

	res = get_module_info_internal_by_addr(pProcModuleInfo, module_addr, &modobj);
	if(res == 0)
		res = modobj->modid_kernel;

	ksceKernelCpuResumeIntr(&pProcModuleInfo->cpu_addr, cpu_suspend_intr);
	return res;
}

/*
 * get_module_id_by_addr / 0x81007c10
 *
 * @param[in] pid         - target pid
 * @param[in] module_addr - target module addr
 *
 * @return modid on success, < 0 on error.
 */
SceUID get_module_id_by_addr(SceUID pid, const void *module_addr){

	SceUID res;
	void *pRes;
	SceUID modid;

	if(pid == 0)
		pid = ksceKernelGetProcessId();

	modid = get_module_id_by_addr_internal(pid, module_addr);
	if((pid == 0x10005) && (modid <= 0))
		goto label_0x81007C4A;

	pRes = func_0x81001f0c(modid);
	if(pRes == NULL)
		goto label_0x81007C4E;

	release_obj(modid);
	res = *(uint32_t *)(pRes + 0x18);
	goto label_0x81007C56;

label_0x81007C4A:
	res = modid;
	goto label_0x81007C56;

label_0x81007C4E:
	res = 0x8002D011;

label_0x81007C56:
	return res;
}

int func_0x81007f00(SceUID pid)
{
	return *(uint16_t *)(SceProcessmgrForKernel_C1C91BB2(pid) + 0x1A) & 1;
}

int func_0x81008BB4(int a1)
{
	// yet not Reversed
	return 0;
}

/*
// load flags
#define SCE_KERNEL_MODULE_FLAG_SHARED			(1)
#define SCE_KERNEL_MODULE_FLAG_NORMAL			(2)
#define SCE_KERNEL_MODULE_FLAG_PROCESS_IMAGE		(4)
#define SCE_KERNEL_MODULE_FLAG_UNKNOWN_0x10		(0x10)
#define SCE_KERNEL_MODULE_FLAG_BOOTIMAGE_PATH		(0x800)
#define SCE_KERNEL_MODULE_FLAG_PROC			(0x1000)
#define SCE_KERNEL_MODULE_FLAG_PRELOAD			(0x8000)
#define SCE_KERNEL_MODULE_FLAG_UNKNOWN_0x20000		(0x20000)
#define SCE_KERNEL_MODULE_FLAG_UNKNOWN_0x40000		(0x40000)
#define SCE_KERNEL_MODULE_FLAG_UNKNOWN_0x8000000	(0x8000000)

process image		: 0x4
normal module		: 0x1000
preload module shared	: 0x8001
preload module		: 0x8002
homebrew plugin		: 0x8000002
shared module		: 0x8008001
normal module ?		: 0x8008002
*/

// 0x810021EC
SceUID module_load_for_pid(SceUID pid, const char *path, int flags, SceKernelLMOption *option){

	SceUID res;
	SceUID modid;
	uint64_t time;
	void *thread_ptr;
	int cpu_intr;
	SceKernelProcessModuleInfo *pProcModuleInfo;
	SceKernelModuleInfoObj_t *modobj;
	void *ptr;
	int sysroot_flag;
	SceUID fd;

	if ((option != NULL) && (*(uint32_t *)(option) != 4))
		return 0x80020005;

	if(pid == 0)
		pid = ksceKernelGetProcessId();

	if(((flags & 1) != 0) && (pid == 0x10005))
		return 0x8002D017;	// kernel shared module is not supported

	if((pid != 0x10005) && (func_0x81001ec4(pid) < 0))
		return 0x8002D012;

	if(SceThreadmgrForDriver_20C228E4() != 0)
		goto loc_8100247E;

loc_81002240:
	if(strncmp(path, "host0:", 6) == 0){
		if((pid == 0x10005) && (ksceSblQafMgrIsAllowHost0Access() == 0))
			return 0x8002D01C;

		if(((flags & 1) != 0) && (ksceKernelCheckDipsw(0xFB) == 0)){
			res = 0x8002D01C;
			goto loc_8100239A;
		}
	}

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_intr);
	if(pProcModuleInfo == NULL){
		res = 0x8002D080;
		goto loc_8100239A;
	}

	func_0x81006e90(pProcModuleInfo, cpu_intr);

	if((pProcModuleInfo->inhibit_state & 0x30) == 0x20)
		goto loc_8100238C;

	if((pProcModuleInfo->inhibit_state & 0x30) == 0x30)
		goto loc_81002392;

	if((pProcModuleInfo->inhibit_state & 0x30) == 0x10){
		if((flags & 0x8000) == 0)
			goto loc_81002392;

		if((flags & 1) == 0)
			goto loc_810022B0;

		goto loc_8100229A;
	}

loc_81002298:
	if((flags & 1) == 0)
		goto loc_810022B0;

loc_8100229A:
	ptr = _func_0x81007f00(pid);
	if(ptr == NULL){
		ptr = _func_0x81007148(path);
		if(ptr == NULL)
			goto loc_810022B0;

		res = func_0x81005648(pid, flags, &modobj);
		if(res < 0){
			SceKernelSuspendForDriver_2BB92967(0);
			_func_0x810071a8(ptr);
			goto loc_8100239A;
		}

		*(uint32_t *)(((int)modobj) + 0xDC) = (uint32_t)ptr;
		ksceKernelGetSystemTimeLow();

		res = _func_0x81001518(modobj, path, -1, 0, flags);
		goto loc_8100231A;
	}

	flags = (flags & ~0xF0) | 0x20;

loc_810022B0:
	SceKernelSuspendForDriver_4DF40893(0);

	// open file
	if((flags & 0x1000) != 0){
		fd = ksceIoOpenForPid(pid, path, 1, 0);
	}else if ((flags & 0x800) == 0){
		fd = ksceIoOpen(path, 1, 0);
	}else{
		fd = _func_0x810049fc(path);
	}

	if(fd < 0){
		if((fd & ~0x10000) == 0x8008000A)
			*(uint32_t *)(SceKernelModulemgr_data + 0x300) = 1;
		SceKernelSuspendForDriver_2BB92967(0);

		if(pid != 0x10005)
			ksceKernelUidRelease(pid);

		return fd;
	}

	res = func_0x81005648(pid, flags, &modobj);
	if(res < 0){
		if(fd != 0)
			((flags & 0x800) == 0) ? ksceIoClose(fd) : func_0x81004a54(fd);

		SceKernelSuspendForDriver_2BB92967(0);
		goto loc_8100239A;
	}

	*(uint32_t *)(((int)modobj) + 0xDC) = 0;
	ksceKernelGetSystemTimeLow();

	res = _func_0x81001518(modobj, path, fd, 0, flags);
	if(fd > 0)
		((flags & 0x800) == 0) ? ksceIoClose(fd) : func_0x81004a54(fd);

loc_8100231A:
	SceKernelSuspendForDriver_2BB92967(0);
	if(res < 0){
		if (pid != 0x10005)
			ksceKernelUidRelease(pid);

		return res;
	}

	ksceKernelCpuIcacheInvalidateAll();
	ksceKernelGetSystemTimeLow();
	_func_0x810014a8();
	print_module_load_info(&modobj->obj_base);

	res = modid = modobj->obj_base.modid_kernel;

	sysroot_flag = 0;
	SceSysrootForKernel_73522F65(pid, &sysroot_flag);
	time = ksceKernelGetSystemTimeWide();
	if(pid == 0x10005)
		goto loc_810024A6;

	if((flags & 0x40000) == 0){

		if (SceSysrootForKernel_6050A467(pid) == 1)
			goto loc_81002546;

		if ((flags & 0x20000) == 0)
			goto loc_81002552;

loc_81002546:
		SceSysrootForKernel_C81B7E2B(pid, modid, time);

loc_81002552:
		sysroot_flag = 0;
		SceSysrootForKernel_73522F65(pid, &sysroot_flag);
		goto loc_810024BA;
	}

	sysroot_flag = 0;
	SceSysrootForKernel_73522F65(pid, &sysroot_flag);
	ksceKernelUidRelease(pid);

	return res;

loc_8100238C:
	if((flags & 0x10) != 0)
		goto loc_81002298;

loc_81002392:
	res = 0x8002D0F3;

loc_8100239A:
	if (pid != 0x10005)
		ksceKernelUidRelease(pid);

	return res;

loc_8100247E:
	thread_ptr = SceThreadmgrForDriver_3A72C6D8(*pThreadSomeInfo);
	if((*(uint32_t *)(thread_ptr + 0x10) & 1) == 0){
		if((*(uint32_t *)(thread_ptr + 0x10) & 2) == 0)
			goto loc_81002240;

		res = modid = *(uint32_t *)(thread_ptr + 0xC);
		*(uint32_t *)(thread_ptr + 0x10) &= ~2;
		goto loc_8100239A;
	}

	time = *(uint64_t *)(thread_ptr);
	res = modid = *(uint32_t *)(thread_ptr + 0xC);

	*(uint32_t *)(thread_ptr + 0x10) &= ~1;

loc_810024A6:
	sysroot_flag = 0;
	SceSysrootForKernel_73522F65(pid, &sysroot_flag);
	if ((flags & 0x40000) != 0)
		goto loc_8100239A;

loc_810024BA:
	if((sysroot_flag & 1) != 0){
		thread_ptr = SceThreadmgrForDriver_3A72C6D8(*pThreadSomeInfo);

		res = ksceKernelSysrootDbgpSuspendProcessAndWaitResume(pid, modid, 0x20006, pThreadSomeInfo, time);
		if (res < 0){
			if (res == 0x8002802D){
				*(uint64_t *)(thread_ptr + 0x00) = time;
				*(uint32_t *)(thread_ptr + 0x0C) = modid;
				*(uint32_t *)(thread_ptr + 0x10) = 1;
			}
		}else{
			*(uint32_t *)(thread_ptr + 0x0C) = modid;
			*(uint32_t *)(thread_ptr + 0x10) = 2;
		}
	}else{
		SceSysrootForKernel_CA497324(pid, modid, time);
	}

	res = modid;

	goto loc_8100239A;
}

int module_load_some_work_sysroot(SceUID pid, SceUID modid, uint64_t time, int sysroot_flag)
{
	int res;
	void *thread_ptr;

	if((sysroot_flag & 1) != 0){
		thread_ptr = SceThreadmgrForDriver_3A72C6D8(*pThreadSomeInfo);

		res = ksceKernelSysrootDbgpSuspendProcessAndWaitResume(pid, modid, 0x20006, pThreadSomeInfo, time);
		if(res < 0){
			if(res == 0x8002802D){
				*(uint64_t *)(thread_ptr + 0x00) = time;
				*(uint32_t *)(thread_ptr + 0x0C) = modid;
				*(uint32_t *)(thread_ptr + 0x10) = 1;
			}
		}else{
			*(uint32_t *)(thread_ptr + 0x0C) = modid;
			*(uint32_t *)(thread_ptr + 0x10) = 2;
		}
	}else{
		SceSysrootForKernel_CA497324(pid, modid, time);
	}

	return modid;
}

// 0x8100286C
int module_start_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status)
{
	// yet not Reversed
	return 0;
}

// 0x81002EDC
SceUID module_load_start_for_pid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status)
{

	SceUID res;
	SceUID modid;
	int mod_start_res;

	modid = module_load_for_pid(pid, path, flags, option);

	if(modid < 0)
		goto label_0x81002F4A;

	mod_start_res = module_start_for_pid(pid, modid, args, argp, flags, 0, status);

	if(mod_start_res == 0)
		goto label_0x81002F4A;

	if(mod_start_res == 1){
		res = 0;
		goto label_0x81002F4C;
	}

	/*
	 * 0x8002802C(SCE_KERNEL_ERROR_THREAD_STOPPED)
	 * 0x8002802D(SCE_KERNEL_ERROR_THREAD_SUSPENDED)
	 *
	 * The above error code does not unload module
	 */
	if((uint32_t)(0x7FFD7FD4 + mod_start_res) <= 1){
		res = mod_start_res;
		goto label_0x81002F4C;
	}

	module_stop_unload_for_pid(pid, modid, 0, 0, 0x40000000, 0, 0);

	return mod_start_res;

label_0x81002F4A:
	res = modid;

label_0x81002F4C:
	return res;
}

// 0x81002B40
int module_stop_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status)
{
	// yet not Reversed
	return 0;
}

// 0x810026BC
int module_unload_for_pid(SceUID pid, SceUID modid, int flags, SceKernelULMOption *option)
{
	int res;
	uint64_t time;
	SceKernelModuleInfoObj_t *modobj;

	if((option != NULL) && (option->size != 4))
		return 0x80020005;

	if(pid == 0)
		pid = ksceKernelGetProcessId();

	if((pid != 0x10005) && (func_0x81001ec4(pid) < 0))
		return 0x8002D012;

	modobj = func_0x81001f0c(modid);
	if(modobj == NULL){
		if(pid != 0x10005)
			ksceKernelUidRelease(pid);
		return 0x8002D011;
	}

	if(pid == modobj->obj_base.pid)
		goto loc_8100274C;

	ksceKernelUidRelease(modid);

	if(pid != 0x10005)
		ksceKernelUidRelease(pid);

	return 0x8002D017;

loc_8100274C:
	modulemgr_lock_mutex();

	if(modobj->obj_base.type == 1)
		goto loc_8100275A;

	if(modobj->obj_base.type != 5){
		modulemgr_unlock_mutex();
		res = 0x8002D016;
		goto loc_8100279E;
	}

loc_8100275A:
	set_modobj_type(&modobj->obj_base, 0);
	modulemgr_unlock_mutex();
	if(modobj->obj_base.modid_user > 0){
		ksceKernelDeleteUserUid(pid, modobj->obj_base.modid_user);
		modobj->obj_base.modid_user = 0;
	}

	if(modobj->obj_base.pid == 0x10005)
		goto loc_81002790;

	if((flags & 0x40000000) == 0)
	{
		if(SceSysrootForKernel_6050A467(pid) == 1)
			goto loc_810027F4;

		if((flags & 0x20000) == 0)
			goto loc_81002790;

loc_810027F4:
		time = ksceKernelGetSystemTimeWide();
		SceSysrootForKernel_20D2A0DF(pid, modobj->obj_base.modid_user, time);
		SceSysrootForKernel_AA8D34EE(pid, modobj->obj_base.modid_user, time);
	}

loc_81002790:
	res = 0;
	module_unload_some_cleanup(&modobj->obj_base);
	ksceKernelDeleteUid(modid);

loc_8100279E:
	ksceKernelUidRelease(modid);

	if(pid != 0x10005)
		ksceKernelUidRelease(pid);

	ksceKernelCpuIcacheInvalidateAll();
	return res;
}

// 0x81002EB0
int module_stop_unload_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status)
{
	int res;

	res = module_stop_for_pid(pid, modid, args, argp, flags, NULL, status);
	if(res < 0)
		return res;

	return module_unload_for_pid(pid, modid, flags, option);
}

// 0x81003000
SceUID module_load_start_shared_for_pid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status)
{
	SceUID res;
	SceUID modid;
	int mod_start_res;

	modid = module_load_for_pid(pid, path, flags | 1, NULL);

	if(modid < 0)
		goto label_0x81003022;

	if((flags & 0x100000) == 0) // not set load only flag
		goto label_0x8100302A;

label_0x81003022:
	res = modid;

label_0x81003024:
	return res;

label_0x8100302A:

	mod_start_res = module_start_for_pid(pid, modid, args, argp, flags, NULL, status);

	if(mod_start_res == 0)
		goto label_0x81003022;

	if(mod_start_res == 1){
		res = 0;
		goto label_0x81003024;
	}

	/*
	 * 0x8002D000(SCE_KERNEL_ERROR_MODULEMGR_START_FAILED)
	 */
	if(mod_start_res == 0x8002D000)
		goto label_0x81003082;

	/*
	 * 0x8002802C(SCE_KERNEL_ERROR_THREAD_STOPPED)
	 * 0x8002802D(SCE_KERNEL_ERROR_THREAD_SUSPENDED)
	 *
	 * The above error code does not unload module
	 */
	if((uint32_t)(0x7FFD7FD4 + mod_start_res) <= 1){
		goto label_0x81003082;
	}

	module_stop_unload_for_pid(pid, modid, 0, 0, 0x48000000, 0, 0);

	res = mod_start_res;
	goto label_0x81003024;

label_0x81003082:
	res = mod_start_res;
	goto label_0x81003024;
}

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
	SceKernelModuleInfoObjBase_t *info;

	module_name[0x1B] = 0;
	res_debug = sceKernelGetModuleInternalForKernel(modid, &info);
	if(res_debug == 0){
		strncpy(module_name, info->module_name, 0x1B);
	}

	res = module_unload_for_pid(pid, modid, flags, option);
	if(res_debug == 0){
		ksceDebugPrintf("Module Unload : [%-27s], modid:0x%X, res:0x%X\n", module_name, modid, res);
	}else{
		ksceDebugPrintf("Module Unload Error : 0x%X, 0x%X\n", res_debug, res);
	}

	return res;
}


/*

sceKernelLoadProcessImageForKernel : 0x117BF
a1 : 0x1177F
a2 : 0xA1A5A0
a3 : 0x0
a4 : 0x15500B8
a5 : 0x1550148
a6 : 0x0

shell_pid : 0x1177F
shell_uid : 0x117BF

*/

int dump_flag;

typedef struct SceLoadProcessParam
{
	uint32_t sysver;
	char thread_name[0x20];
	uint32_t unk_0x24;		// ex:0x100000EC
	uint32_t unk_0x28;		// ex:0x6000
	uint32_t unk_0x2C;
	char unk_0x30[0x24];
	char module_name[0x1C];
	uint32_t unk_0x70;
	uint32_t unk_0x74;		// ex:0x790000
	void *unk_0x78;			// ex:0x81600814, data seg vaddr?
	char unk_0x7C[0x20];		// all 0xFF

	// more...
} SceLoadProcessParam;

/**
 * @brief load process image
 *
 * @param[in]    pid    - target pid
 * @param[in]    path   - path
 * @param[in]    a3     - unk, zero
 * @param[out]   auth_info
 * @param[out]   a5
 * @param[in]    a6     - unk, zero
 *
 * @return modid, < 0 on error.
 */
static tai_hook_ref_t sceKernelLoadProcessImageForKernel_ref;
SceUID sceKernelLoadProcessImageForKernel_patch(SceUID pid, const char *path, int a3, void *auth_info, SceLoadProcessParam *a5, int a6)
{
	int res;

	if(dump_flag == 0){
		write_file("sd0:sceKernelLoadProcessImage_auth_info.bin", auth_info, 0x200);
		write_file("sd0:sceKernelLoadProcessImage_a5.bin", a5, 0x200);
	}

	res = TAI_CONTINUE(int, sceKernelLoadProcessImageForKernel_ref, pid, path, a3, auth_info, a5, a6);

	if(dump_flag == 0){
		write_file("sd0:sceKernelLoadProcessImage_auth_info_called.bin", auth_info, 0x200);
		write_file("sd0:sceKernelLoadProcessImage_a5_called.bin", a5, 0x200);
		dump_flag = 1;
	}

	ksceDebugPrintf("sceKernelLoadProcessImageForKernel : 0x%X\n", res);
	ksceDebugPrintf("a1 : 0x%X\n", pid);
	ksceDebugPrintf("a2 : %s\n", path);
	ksceDebugPrintf("a3 : 0x%X\n", a3);
	ksceDebugPrintf("a4 : 0x%X\n", auth_info);
	ksceDebugPrintf("a5 : 0x%X\n", a5);
	ksceDebugPrintf("a6 : 0x%X\n", a6);

	return res;
}

tai_hook_ref_t create_new_module_class_ref;
int create_new_module_class_patch(SceUID pid, int flags, SceKernelModuleInfoObj_t **dst){
	return func_0x81005648(pid, flags, dst);
}

void hex_dump(const void *addr, int len){

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

int threadFunc(SceSize args, void *argp){

	SceUID modid;
	SceUID shell_pid, shell_uid;

	ksceKernelDelayThread(15 * 1000 * 1000);

	shell_pid = ksceKernelSysrootGetShellPid();

	shell_uid = search_module_by_name(shell_pid, "SceShell");

	ksceDebugPrintf("shell_pid : 0x%X\n", shell_pid);
	ksceDebugPrintf("shell_uid : 0x%X\n", shell_uid);

	modid = module_load_for_pid(0x10005, "os0:/kd/enum_wakeup.skprx", 0, NULL);
	ksceDebugPrintf("enum_wakeup.skprx modid : 0x%X\n", modid);

	// int res;

	if(0){
	// print_proc_nonlinked_import(0x10005);
	// print_proc_nonlinked_import(shell_pid);
	}

	if(0){
		SceUID SceSysmem_uid = search_module_by_name(0x10005, "SceSysmem");

		SceKernelModuleInfo sce_info;
		memset(&sce_info, 0, sizeof(SceKernelModuleInfo));

		sceKernelGetModuleInfoForKernel(0x10005, SceSysmem_uid, &sce_info);

		uint32_t *sysroot_func_table = *(uint32_t **)(sce_info.segments[1].vaddr + 0x75F8);

		ksceDebugPrintf("SceSysrootForDriver_D75D4F37 : 0x%X\n", sysroot_func_table[0x368 >> 2]);
	}


	int cpu_intr;
	SceKernelProcessModuleInfo *module_tree_top;

	module_tree_top = getProcModuleInfo(shell_pid, &cpu_intr);
	if(module_tree_top != NULL){
		func_0x81006e90(module_tree_top, cpu_intr);

		// write_file("sd0:/modulemgr_modobj_58.bin", lib_export_info->modobj->data_0x58, 0x400);
	}


	ksceDebugPrintf("enum_wakeup.skprx unload res : 0x%X\n", module_unload_for_pid(0x10005, modid, 0, NULL));
	ksceDebugPrintf("\n");


	modid = search_module_by_name(shell_pid, "SceShell");

	// module_load_unload_test(shell_pid, "os0:/psp2bootconfig.skprx");

	return ksceKernelExitDeleteThread(0);
}

void _start() __attribute__ ((weak, alias("module_start")));
int module_start(SceSize args, void *argp){

	SceKernelModulemgr_module_start(0, NULL); // Real argp : 4, sysroot ptr
	get_data();

	ReSyscallInit((void *)(*(int *)(SceKernelModulemgr_data + 0x334)));

	SceUID modulemgr_uid = search_module_by_name(0x10005, "SceKernelModulemgr");

	uint32_t module_nid = 0;

	sceKernelGetModuleNIDForKernel(modulemgr_uid, &module_nid);

	if(module_nid != 0x726C6635){
		ksceDebugPrintf("3.60 only\n");
		ksceDebugPrintf("nid:0x%08X\n", module_nid);

		return SCE_KERNEL_START_SUCCESS;
	}

	HookOffset(modulemgr_uid, 0x5648, 1, create_new_module_class);

	HookOffset(modulemgr_uid, 0x21EC, 1, module_load_for_pid);
	HookOffset(modulemgr_uid, 0x26BC, 1, module_unload_for_pid);

	// HookExport("SceKernelModulemgr", 0xFFFFFFFF, 0xAC4EABDB, sceKernelLoadProcessImageForKernel);



	SceKernelModuleInfo info;

	sceKernelGetModuleInfoForKernel(0x10005, modulemgr_uid, &info);

	_func_0x81001518 = (void *)(info.segments[0].vaddr + 0x1519);
	_func_0x81007148 = (void *)(info.segments[0].vaddr + 0x7149);
	_func_0x81007f00 = (void *)(info.segments[0].vaddr + 0x7f01);
	_func_0x810071a8 = (void *)(info.segments[0].vaddr + 0x71a9);
	_func_0x810014a8 = (void *)(info.segments[0].vaddr + 0x14a9);
	_func_0x810049fc = (void *)(info.segments[0].vaddr + 0x49fd);

	_modulemgr_lock_mutex       = (void *)(info.segments[0].vaddr + 0x1869);
	_modulemgr_unlock_mutex     = (void *)(info.segments[0].vaddr + 0x1885);
	_set_modobj_type            = (void *)(info.segments[0].vaddr + 0x5A5D);
	_module_unload_some_cleanup = (void *)(info.segments[0].vaddr + 0x71CD);

	pThreadSomeInfo = (int *)(info.segments[1].vaddr + 0x44);

	// module_load_for_pid(0x10005, "os0:/kd/enum_wakeup.skprx", 0, NULL);

	if(0){

	SceUID thid;
	thid = ksceKernelCreateThread("SceKernelModuleTestingThread", threadFunc, 0x10000100, 0x10000, 0, 0, NULL);
	if(thid > 0)
		ksceKernelStartThread(thid, 0, NULL);

	}

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp){
	return SCE_KERNEL_STOP_SUCCESS;
}

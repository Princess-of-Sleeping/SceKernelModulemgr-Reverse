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
#include "module_utility.h"
#include "module_syscall.h"
#include "module_search.h"
#include "module_debug.h"
#include "taihen_macro.h"
#include "debug.h"

void *SceKernelModulemgr_text = NULL;
void *SceKernelModulemgr_data = NULL;

int *pThreadSomeInfo;

SceClass *pSceUIDLibraryClass;
SceClass *pSceUIDModuleClass;
SceClass *pSceUIDLibStubClass;

int (* _modulemgr_lock_mutex)(void);
int (* _modulemgr_unlock_mutex)(void);
int (* _set_module_state)(SceModuleInfoInternal *pModuleInfo, uint8_t state);
void (* _module_unload_some_cleanup)(SceModuleInfoInternal *pModuleInfo);

int SceKernelModulemgr_module_start(SceSize args, void *argp){

	SceClass *sysroot_module_cls;

	sysroot_module_cls = (SceClass *)_ksceKernelSysrootGetModulePrivate(9); // size is 0xAC

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
  
	do {
		if((r0 & *(uint32_t *)(SceKernelModulemgr_data + 0x30)) != 0){
			*(int *)(SceKernelModulemgr_data + r1) += 1;
		}

		r0 <<= 1;
		r1 += 4;
	} while(r1 != 0x30);

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

// related to syscall
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

/*
 * sceIoOpenBootfs / func_0x810049fc
 */
SceUID sceIoOpenBootfs(const char *path){

	const char **pPath;
	int r0;
	int r1;

	if((*(uint32_t *)(SceKernelModulemgr_data + 0x304) != 0) && (*(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 8) > 0)){
		r0 = 0;
		r1 = 0;
		do {
			pPath = (const char **)(*(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 0xc) + r0);
			r0 += 0xC;
			if(strncmp(path, *pPath, 0xFF) == 0){
				*(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 4) = r1;
				return 0x7f7f7f7f;
			}
			r1 += 1;
		} while(r1 != *(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 8));
	}

	return 0x80010002;
}

/*
 * sceIoCloseBootfs / func_0x81004a54
 */
int sceIoCloseBootfs(SceUID fd){
	*(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 4) = 0xffffffff;
	return 0;
}

/*
 * create_new_module_class / func_0x81005648
 */
int create_new_module_class(SceUID pid, int flags, SceModuleObject **dst){

	int res;
	SceModuleObject *pObj;
	SceCreateUidObjOpt opt;

	if(pid == 0x10005){
		res = _ksceKernelCreateUidObj(pSceUIDModuleClass, "SceModuleMgrNewModule", 0, (SceObjectBase **)&pObj);
		if(res < 0)
			return res;

		pObj->obj_base.version      = 0xFFFFFFFF;
		pObj->obj_base.modid_kernel = res;
		pObj->obj_base.pid          = 0x10005;
	}else{
		opt.field_10 = ((flags & 0x10) != 0) ? 1 : 0;

		opt.flags    = 8;
		opt.field_4  = 0;
		opt.field_8  = 0;
		opt.pid      = pid;
		opt.field_14 = 0;
		opt.field_18 = 0;

		res = sceKernelProcessModuleIncForKernel(pid, opt.field_10);
		if(res < 0)
			return res;

		res = _ksceKernelCreateUidObj(pSceUIDModuleClass, "SceModuleMgrNewModule", &opt, (SceObjectBase **)&pObj);
		if(res < 0){
			sceKernelProcessModuleDecForKernel(pid, opt.field_10);
			return res;
		}

		pObj->obj_base.version      = 0x03600011;
		pObj->obj_base.modid_kernel = res;
		pObj->obj_base.pid          = pid;
	}

	if(dst != NULL)
		*dst = pObj;

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

// 0x81005A5C
int set_module_state(SceModuleInfoInternal *pModuleInfo, uint8_t state){
	return _set_module_state(pModuleInfo, state);
}

// 0x810071CC
void module_unload_some_cleanup(SceModuleInfoInternal *pModuleInfo){
	_module_unload_some_cleanup(pModuleInfo);
}

typedef struct SceModuleLoadCtx { // size is 0x44
	SceModuleInfoInternal *pModuleInfo;
	int data_0x04;
	int data_0x08;
	int data_0x0C;
	int data_0x10;
	int data_0x14;
	int data_0x18;
	int data_0x1C;
	void *text_base; // from elf header

	SceUID data_0x24;
	int data_0x28;
	void *data_base; // from elf header

	SceUID data_0x30;
	int data_0x34;
	int data_0x38;

	int data_0x3C;
	int data_0x40;
} SceModuleLoadCtx;

int  (* func_0x81000614)(SceModuleLoadCtx *ctx, SceUID fd, SceSblSmCommContext130 *ctx130, int flags);
int  (* func_0x81005714)(SceModuleLoadCtx *ctx);
int  (* func_0x81005D28)(SceModuleLoadCtx *ctx);
int  (* func_0x810062B4)(SceModuleLoadCtx *ctx);
int  (* func_0x81005E24)(SceModuleLoadCtx *ctx);
int  (* func_0x81005E64)(SceModuleLoadCtx *ctx);
int  (* func_0x81006440)(SceModuleLoadCtx *ctx);
int  (* func_0x81000AEC)(SceModuleLoadCtx *ctx);

int  (* func_0x810047F8)(SceModuleInfoInternal *pModuleInfo);

/*
 * module_load_internal / func_0x81001518
 */
int module_load_internal(SceModuleObject *pModuleObject, const char *path, SceUID fd, SceSelfAuthInfo *pSelfAuthInfo, uint32_t flags){

	int res, self_type;
	SceSblSmCommContext130 ctx130;
	SceModuleLoadCtx load_ctx;

	memset(&load_ctx, 0, sizeof(load_ctx));
	load_ctx.pModuleInfo = &pModuleObject->obj_base;

	if((flags & 4) != 0){
		res = 0x4000;
	}else{
		res = ((flags & 0x8000) != 0) ? 0x1000 : 0;

		if((flags & 0x10) != 0){
			res = (uint16_t)(res | 1);
		}else if((flags & 0x20) != 0){
			res = res | 2;
		}

		if((flags & 1) != 0){
			if(pModuleObject->obj_base.pSharedInfo == NULL){
				res |= 0x200;
			}else if(ksceKernelCheckDipsw(0xD2) == 0){
				res |= 0x100;
			}else{
				res |= 0x400;
			}
		}
	}

	pModuleObject->obj_base.flags |= res;

	res = set_module_info_path(&pModuleObject->obj_base, path, flags);
	if(res < 0)
		goto del_uid;

	memset(&ctx130, 0, sizeof(ctx130));

	self_type = 0;

	if((flags & 0x800) != 0){
		self_type = 0;
	}else if(pModuleObject->obj_base.pSharedInfo == NULL){

		res = ksceKernelGetProcessAuthid(((0x4002 & flags) == 0) ? ksceKernelGetProcessId() : pModuleObject->obj_base.pid, &ctx130.self_auth_info_caller.program_authority_id);
		if(res < 0)
			goto del_uid;

		ctx130.self_auth_info_caller.unk_80 = 0x10;

		if((flags & 4) != 0){
			ctx130.self_type |= 0x10000;
			memcpy(ctx130.self_auth_info_called.klicensee, pSelfAuthInfo->klicensee, 0x10);
		}else if((flags & 0x1000) != 0)
			memcpy(ctx130.self_auth_info_called.klicensee, ctx130.self_auth_info_caller.klicensee, 0x10);

		res = ksceIoGetMediaType(((0x1004 & flags) == 0) ? 0x10005 : pModuleObject->obj_base.pid, path, 1, (int *)&ctx130.path_id);
		if(res < 0)
			goto del_uid;

		self_type = ctx130.self_type;

		if(pModuleObject->obj_base.pid != 0x10005)
			self_type |= 1;
	}

	ctx130.self_type = self_type;

	res = func_0x81000614(&load_ctx, fd, &ctx130, flags);
	if(res < 0)
		goto del_uid;

	res = func_0x81005714(&load_ctx);
	if(res < 0)
		goto del_uid;

	res = func_0x81005D28(&load_ctx);
	if(res < 0)
		goto del_uid;

	res = func_0x810062B4(&load_ctx);
	if(res < 0)
		goto del_uid;

	res = func_0x81005E24(&load_ctx);
	if(res < 0)
		goto del_uid;

	res = func_0x81005E64(&load_ctx);
	if(res < 0)
		goto del_uid;

	res = func_0x81006440(&load_ctx);
	if(res < 0)
		goto del_uid;

	res = func_0x81000AEC(&load_ctx);
	if(res < 0)
		goto del_uid;

	if(pSelfAuthInfo != NULL)
		memcpy(pSelfAuthInfo, &ctx130.self_auth_info_called, 0x90);

	if((pModuleObject->obj_base.attr & 2) != 0){
		if(search_module_by_name(pModuleObject->obj_base.pid, pModuleObject->obj_base.module_name) != 0x8002D082){
			res = 0x8002D021;
			goto del_uid;
		}
	}

	if((pModuleObject->obj_base.flags & 0x500) == 0){

		res = func_0x810047F8(&pModuleObject->obj_base);
		if(res < 0)
			goto del_uid;

		if((flags & 0x100) != 0){
			if(pModuleObject->obj_base.module_start != NULL){
				res = 0x8002D01E;
				goto del_uid;
			}

			if(pModuleObject->obj_base.module_stop != NULL){
				res = 0x8002D01E;
				goto del_uid;
			}

			if(pModuleObject->obj_base.module_exit != NULL){
				res = 0x8002D01E;
				goto del_uid;
			}

			if(pModuleObject->obj_base.data_0xC0 != 0){
				res = 0x8002D01E;
				goto del_uid;
			}
		}
	}

	if(pModuleObject->obj_base.pid != 0x10005){

		if((ksceKernelCheckDipsw(0xD2) == 0) || (pModuleObject->obj_base.exidxBtm <= pModuleObject->obj_base.exidxTop))
			goto loc_81001648;

		if((pModuleObject->obj_base.flags & 0x500) == 0){

			void *ptr;

			ptr = sceKernelProcessAllocKernelBudgetHeapMemoryForKernel(pModuleObject->obj_base.pid, pModuleObject->obj_base.exidxBtm - pModuleObject->obj_base.exidxTop);
			if(ptr == NULL)
				goto loc_81001648;

			res = ksceKernelMemcpyUserToKernelForPid(pModuleObject->obj_base.pid, ptr, (uintptr_t)pModuleObject->obj_base.exidxTop, pModuleObject->obj_base.exidxBtm - pModuleObject->obj_base.exidxTop);
			if(res >= 0){
				pModuleObject->obj_base.data_0xD0 = ptr;
			}else{
				sceKernelFreeRemoteProcessKernelHeapForKernel(pModuleObject->obj_base.pid, ptr);
			}
		}else{
			pModuleObject->obj_base.data_0xD0 = pModuleObject->obj_base.pSharedInfo->pModuleInfo->data_0xD0;
		}
	}else{
		pModuleObject->obj_base.data_0xD0 = pModuleObject->obj_base.exidxTop;
	}

loc_81001648:

	for(int i=0;i<pModuleObject->obj_base.segments_num;i++){
		res = ksceKernelSetObjectForUid(pModuleObject->obj_base.segments[i].memblk_id, pModuleObject->obj_base.module_name);
		if(res < 0)
			break;
	}

	if(res >= 0){
		if(pModuleObject->obj_base.pid != 0x10005){
			res = ksceKernelCreateUserUid(pModuleObject->obj_base.pid, pModuleObject->obj_base.modid_kernel);
			if(res < 0){
				res = 0;
				goto del_uid;
			}

			pModuleObject->obj_base.modid_user = res;
		}

		set_module_state(&pModuleObject->obj_base, 1);
		update_shared_info_node(&pModuleObject->obj_base);
		res = 0;
	}else{
del_uid:
		ksceKernelDeleteUid(pModuleObject->obj_base.modid_kernel);
	}

	return res;
}

/*
 * get_export_index / func_0x81005fec
 */
int get_export_index(SceModuleInfoInternal *pModuleInfo, const void *module_addr){

	if((SceSize)pModuleInfo->libent_top > (SceSize)module_addr)
		return 0x8002D009;

	if((SceSize)module_addr >= (SceSize)pModuleInfo->libent_btm)
		return 0x8002D009;

	if(((module_addr - pModuleInfo->libent_top) & 0x1F) != 0)
		return 0x8002D009;

	// (module_addr - pModuleInfo->libent_top) / sizeof(SceModuleExport)
	return (module_addr - pModuleInfo->libent_top) >> 5;
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

	res = (void *)(((uint32_t)a3 + 0xF8000000) >> 0xC);

	if((uint32_t)(res) < 0x8000)
		goto label_0x81006D32;

	a3 = (const void *)((uint32_t)a3 + 0x7F000000);

	if((uint32_t)a3 < 0x6F000000){
		a3 = (const void *)((uint32_t)a3 >> 0xC);

		a1 = a1 + ((uint32_t)a3 << 2);
		*(uint32_t *)(a4) = *(uint32_t *)(a2) + ((uint32_t)a3 << 3);
	}else{
		a1 = 0;
	}

	return (void *)a1;

label_0x81006D32:
	res += 0x8000;

label_0x81006D36:
	a1 = a1 + ((uint32_t)res << 2);
	return (void *)a1;
}

void func_0x81006d40(void *a1, SceModuleInfoInternal *pModuleInfo){

	void *ptr, *res;
	unsigned int vaddr, size1, size2;

	vaddr = (unsigned int)pModuleInfo->segments[0].vaddr;

	res = func_0x81006cf4(*(uint32_t *)(a1), a1, (const void *)vaddr, &ptr);
	if(res == NULL)
		goto loc_81006D90;

	size1 = (vaddr & 0xFFF);
	size2 = (vaddr + pModuleInfo->segments[0].memsz) & 0xFFF;

	if(size1 >= size2)
		goto loc_81006D90;

loc_81006D74:
	if(ptr == 0)
		goto loc_81006D88;

	*(uint32_t *)(ptr + 0x0) = *(int *)(*(int *)(res) + 0x40);
	*(uint32_t *)(ptr + 0x4) = *(int *)(*(int *)(res) + 0x44);
	res += 4;
	ptr += 8;

loc_81006D88:
	size1 += 0x1000;
	if(size2 > size1)
		goto loc_81006D74;

loc_81006D90:
	return;
}

/*
 * get_library_object / func_0x81006de8
 */
SceModuleLibraryObject *get_library_object(SceUID pid, SceUID library_id){

	SceModuleLibraryObject *pObj;

	if((pid != 0x10005) && (is_process_compiled_new_sdk(pid) == 1))
		library_id = ksceKernelKernelUidForUserUid(pid, library_id);

	if(library_id < 0)
		return NULL;

	if(ksceKernelGetObjForUid(library_id, pSceUIDLibraryClass, (SceObjectBase **)&pObj) < 0)
		return NULL;

	if(get_module_object(pObj->modid) != NULL)
		return pObj;

	ksceKernelUidRelease(library_id);
	return NULL;
}

/*
 * cleanup_process_module_info / func_0x81006e9c
 */
int cleanup_process_module_info(SceUID pid){

	int cpu_suspend_intr;
	char data[0x24];
	void *arg1;
	SceKernelProcessModuleInfo *pProcModuleInfo;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_suspend_intr);
	if(pProcModuleInfo == NULL)
		return 0;

	memcpy(data, pProcModuleInfo, sizeof(SceKernelProcessModuleInfo));
	memset(pProcModuleInfo, 0, 0x20);

	ksceKernelCpuResumeIntr((int *)(&pProcModuleInfo->cpu_addr), cpu_suspend_intr);

	arg1 = (void *)(*(uint32_t *)(&data[0xC]));
	if(arg1 != NULL)
		goto label_0x81006EE6;

	goto label_0x81006EF0;

label_0x81006EE6:
	func_0x81006744(arg1);
	arg1 = (void *)(*(uint32_t *)(arg1));
	if(arg1 != 0)
		goto label_0x81006EE6;

label_0x81006EF0:
	arg1 = (void *)(*(uint32_t *)(&data[0x1C]));
	if(arg1 == NULL)
		return 0;

	ksceKernelFreeMemBlock(*(SceUID *)(arg1 + 4));

	if(*(SceUID *)(arg1 + 0xC) <= 0)
		goto label_0x81006F04;

	ksceKernelFreeMemBlock(*(SceUID *)(arg1 + 0xC));

label_0x81006F04:
	if(*(SceUID *)(arg1 + 0x8) <= 0)
		goto label_0x81006F0E;

	ksceKernelFreeMemBlock(*(SceUID *)(arg1 + 0x8));

label_0x81006F0E:
	return sceKernelFreeRemoteProcessKernelHeapForKernel(pid, arg1);
}

int func_0x810070b4(void *a1){

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
	func_0x81006d40((void *)(SceKernelModulemgr_data + 0x318), (void *)(*(uint32_t *)(a1 + 0x10)));
	if (*(uint32_t *)(*(uint32_t *)(a1 + 0x10)) != 0)
		goto loc_8100712C;

	goto loc_810070CE;
}

/*
 * get_module_library_info_export / func_0x810076b0
 */
int get_module_library_info_export(SceUID pid, SceUID modid, uint32_t libnid, SceKernelLibraryInfo *info){

	int cpu_intr;
	SceKernelProcessModuleInfo *pProcModuleInfo;
	SceModuleLibraryInfo *pLibraryInfo;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_intr);
	if(pProcModuleInfo == NULL)
		return 0x8002D080;

	pLibraryInfo = pProcModuleInfo->pLibraryInfo;

	while(pLibraryInfo != NULL){
		if((pLibraryInfo->pModuleInfo->modid_kernel == modid) && (pLibraryInfo->pExportInfo->libnid == libnid)){
			info->libver[0]          = pLibraryInfo->pExportInfo->libver[0];
			info->libver[1]          = pLibraryInfo->pExportInfo->libver[1];
			info->libnid             = libnid;
			info->libname            = pLibraryInfo->pExportInfo->libname;
			info->entry_num_function = pLibraryInfo->pExportInfo->entry_num_function;
			info->entry_num_variable = pLibraryInfo->pExportInfo->entry_num_variable;
			info->table_nid          = pLibraryInfo->pExportInfo->table_nid;
			info->table_entry        = pLibraryInfo->pExportInfo->table_entry;

			ksceKernelCpuResumeIntr(&pProcModuleInfo->cpu_addr, cpu_intr);
			return 0;
		}

		pLibraryInfo = (pLibraryInfo->data_0x04 != NULL) ? pLibraryInfo->data_0x04 : pLibraryInfo->next;
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
	SceModuleObject *info_obj;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_suspend_intr);
	if(pProcModuleInfo == NULL){
		res = 0x8002d080;
		goto loc_810077e6;
	}

	info_obj = get_module_object(modid);
	if(info_obj == NULL){
		res = 0x8002d082;
	}else{
		if(modid == info_obj->obj_base.modid_kernel){

			info->modid = (pid == 0x10005) ? modid : info_obj->obj_base.modid_user;

			info->attr  = info_obj->obj_base.attr;
			info->minor = info_obj->obj_base.minor;
			info->major = info_obj->obj_base.major;

			strncpy(info->module_name, info_obj->obj_base.module_name, 28-1);

			switch(info_obj->obj_base.state){
			case 1:
			case 2:
			case 0x10:
				info->state = 2;
				break;
			case 3:
				info->state = 6;
				break;
			default:
				info->state = 9;
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
int get_module_info_internal_by_addr(SceKernelProcessModuleInfo *pProcModuleInfo, const void *module_addr, SceModuleInfoInternal **ppInfo){

	void *ptr;
	int temp;
	SceModuleInfoInternal *modobj;

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

	*ppInfo = modobj;

	return 0;


label_0x81007AC2:
	modobj = pProcModuleInfo->pModuleInfo;

	while(modobj != NULL){
		for(int i=0;i<modobj->segments_num;i++){
			if((SceSize)(module_addr - modobj->segments[i].vaddr) < (SceSize)(modobj->segments[i].memsz)){
				*ppInfo = modobj;
				return 0;
			}
		}
		modobj = modobj->next;
	}

	return 0x8002D082;
}

/*
 * get_module_id_by_addr_internal / func_0x81007bbc
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
	SceModuleInfoInternal *pObj;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_suspend_intr);
	if(pProcModuleInfo == NULL)
		return 0x8002D080;

	res = get_module_info_internal_by_addr(pProcModuleInfo, module_addr, &pObj);
	if(res == 0)
		res = pObj->modid_kernel;

	ksceKernelCpuResumeIntr(&pProcModuleInfo->cpu_addr, cpu_suspend_intr);

	return res;
}

/*
 * get_module_id_by_addr / func_0x81007c10
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

	pRes = get_module_object(modid);
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
	SceModuleObject *modobj;
	SceModuleSharedInfo *pSharedInfo;
	// void *ptr;
	int sysroot_flag;
	SceUID fd;

	if((option != NULL) && (*(uint32_t *)(option) != 4))
		return 0x80020005;

	if(pid == 0)
		pid = ksceKernelGetProcessId();

	if(((flags & 1) != 0) && (pid == 0x10005))
		return 0x8002D017;	// kernel shared module is not supported

	if((pid != 0x10005) && (process_check_for_user(pid) < 0))
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

	resume_cpu_intr(pProcModuleInfo, cpu_intr);

	if((pProcModuleInfo->inhibit_state & 0x30) == 0x20){
		if((flags & 0x10) == 0)
			goto loc_81002392;
	}else if((pProcModuleInfo->inhibit_state & 0x30) == 0x30){
		goto loc_81002392;
	}

	if((pProcModuleInfo->inhibit_state & 0x30) == 0x10){
		if((flags & 0x8000) == 0)
			goto loc_81002392;
	}

	if((flags & 1) == 0)
		goto loc_810022B0;

	if(is_inhibit_shared(pid) == 0){
		pSharedInfo = search_shared_info_by_path(path);
		if(pSharedInfo == NULL){
			goto loc_810022B0;
		}

		res = create_new_module_class(pid, flags, &modobj);
		if(res < 0){
			SceKernelSuspendForDriver_2BB92967(0);
			shared_info_decrements(pSharedInfo);
			goto loc_8100239A;
		}

		modobj->obj_base.pSharedInfo = pSharedInfo;

		ksceKernelGetSystemTimeLow();

		res = module_load_internal(modobj, path, -1, 0, flags);
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
		fd = sceIoOpenBootfs(path);
	}

	if(fd < 0){
		if((fd & ~0x10000) == 0x8008000A)
			*(uint32_t *)(SceKernelModulemgr_data + 0x300) = 1;
		SceKernelSuspendForDriver_2BB92967(0);

		if(pid != 0x10005)
			ksceKernelUidRelease(pid);

		return fd;
	}

	res = create_new_module_class(pid, flags, &modobj);
	if(res < 0){
		if(fd != 0)
			((flags & 0x800) == 0) ? ksceIoClose(fd) : sceIoCloseBootfs(fd);

		SceKernelSuspendForDriver_2BB92967(0);
		goto loc_8100239A;
	}

	modobj->obj_base.pSharedInfo = NULL;
	ksceKernelGetSystemTimeLow();

	res = module_load_internal(modobj, path, fd, 0, flags);
	if(fd > 0)
		((flags & 0x800) == 0) ? ksceIoClose(fd) : sceIoCloseBootfs(fd);

loc_8100231A:
	SceKernelSuspendForDriver_2BB92967(0);
	if(res < 0){
		if (pid != 0x10005)
			ksceKernelUidRelease(pid);

		return res;
	}

	ksceKernelCpuIcacheInvalidateAll();
	ksceKernelGetSystemTimeLow();
	func_0x810014a8();
	print_module_load_info(&modobj->obj_base);

	res = modid = modobj->obj_base.modid_kernel;

	sysroot_flag = 0;
	SceSysrootForKernel_73522F65(pid, &sysroot_flag);
	time = ksceKernelGetSystemTimeWide();
	if(pid == 0x10005)
		goto loc_810024A6;

	if((flags & 0x40000) == 0){
		if(SceSysrootForKernel_6050A467(pid) == 1)
			goto loc_81002546;

		if((flags & 0x20000) == 0)
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

		res = ksceKernelSysrootDbgpSuspendProcessAndWaitResume(pid, modid, 0x20006, time);
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

	res = modid;

	goto loc_8100239A;
}

int module_load_some_work_sysroot(SceUID pid, SceUID modid, uint64_t time, int sysroot_flag)
{
	int res;
	void *thread_ptr;

	if((sysroot_flag & 1) != 0){
		thread_ptr = SceThreadmgrForDriver_3A72C6D8(*pThreadSomeInfo);

		res = ksceKernelSysrootDbgpSuspendProcessAndWaitResume(pid, modid, 0x20006, time);
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
SceUID module_load_start_for_pid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){

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

/*
 * module_stop_for_pid / func_0x81002b40
 */
int module_stop_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status)
{
	// yet not Reversed
	return 0;
}

/*
 * module_unload_for_pid / func_0x810026bc
 */
int module_unload_for_pid(SceUID pid, SceUID modid, int flags, SceKernelULMOption *option){

	int res;
	uint64_t time;
	SceModuleObject *modobj;

	if((option != NULL) && (option->size != 4))
		return 0x80020005;

	if(pid == 0)
		pid = ksceKernelGetProcessId();

	if((pid != 0x10005) && (process_check_for_user(pid) < 0))
		return 0x8002D012;

	modobj = get_module_object(modid);
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

	if(modobj->obj_base.state == 1)
		goto loc_8100275A;

	if(modobj->obj_base.state != 5){
		modulemgr_unlock_mutex();
		res = 0x8002D016;
		goto loc_8100279E;
	}

loc_8100275A:
	set_module_state(&modobj->obj_base, 0);
	modulemgr_unlock_mutex();
	if(modobj->obj_base.modid_user > 0){
		ksceKernelDeleteUserUid(pid, modobj->obj_base.modid_user);
		modobj->obj_base.modid_user = 0;
	}

	if(modobj->obj_base.pid == 0x10005)
		goto loc_81002790;

	if((flags & 0x40000000) == 0){
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
int module_stop_unload_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){

	int res;

	res = module_stop_for_pid(pid, modid, args, argp, flags, NULL, status);
	if(res < 0)
		return res;

	return module_unload_for_pid(pid, modid, flags, option);
}

// 0x81003000
SceUID module_load_start_shared_for_pid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){

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

	SceKernelModuleInfo info;

	sceKernelGetModuleInfoForKernel(0x10005, modulemgr_uid, &info);

	func_0x81000614 = (void *)(info.segments[0].vaddr + 0x615);
	func_0x81005714 = (void *)(info.segments[0].vaddr + 0x5715);
	func_0x81005D28 = (void *)(info.segments[0].vaddr + 0x5D29);
	func_0x810062B4 = (void *)(info.segments[0].vaddr + 0x62B5);
	func_0x81005E24 = (void *)(info.segments[0].vaddr + 0x5E25);
	func_0x81005E64 = (void *)(info.segments[0].vaddr + 0x5E65);
	func_0x81006440 = (void *)(info.segments[0].vaddr + 0x6441);
	func_0x81000AEC = (void *)(info.segments[0].vaddr + 0xAED);
	func_0x810047F8 = (void *)(info.segments[0].vaddr + 0x47F9);

	_modulemgr_lock_mutex       = (void *)(info.segments[0].vaddr + 0x1869);
	_modulemgr_unlock_mutex     = (void *)(info.segments[0].vaddr + 0x1885);
	_set_module_state           = (void *)(info.segments[0].vaddr + 0x5A5D);
	_module_unload_some_cleanup = (void *)(info.segments[0].vaddr + 0x71CD);

	pThreadSomeInfo = (int *)(info.segments[1].vaddr + 0x44);

	my_debug_start();

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp){
	return SCE_KERNEL_STOP_SUCCESS;
}

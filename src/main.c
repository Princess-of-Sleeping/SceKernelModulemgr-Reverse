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

#include "modulemgr_internal.h"
#include "modulemgr_common.h"

int write_file(const char *path, const void *data, size_t length){

	SceUID fd = ksceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 6);
	if (fd < 0)
		return fd;

	ksceIoWrite(fd, data, length);
	ksceIoClose(fd);

	return 0;
}

int __stack_chk_fail();

// return value is previous value
int ksceKernelSetPermission(int value);

// return value is previous value
SceUID ksceKernelSetProcessId(SceUID pid);

// SceSysmem
SceClass *ksceKernelGetClassForUid(SceUID uid, SceClass **cls);

int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

#define GetExport(modname, libnid, funcnid, func) module_get_export_func(0x10005, modname, libnid, funcnid, (uintptr_t *)func)

void *(* ksceKernelSysrootAlloc)(int size);
int (* ksceKernelSysrootFree)(void *ptr);
int (* SceQafMgrForDriver_382C71E8)(void);
int (* SceSysrootForDriver_67AAB627)(void); // get sysver
void (* SceSysrootForDriver_6E0BC27C)(void);

void *(* sceKernelAllocRemoteProcessHeapForDriver)(SceUID pid, int size);

void *(* sceKernelGetProcessClassForKernel)(void);
int (* SceProcessmgrForKernel_0A5A2CF1)(SceUID pid, int a2);
int (* SceProcessmgrForKernel_41815DF2)(SceUID pid, void *a2);
int (* SceProcessmgrForKernel_B75FB970)(SceUID pid);
void *(* SceProcessmgrForKernel_C1C91BB2)(SceUID pid);

int (* SceThreadmgrForDriver_E50E1185)(SceUID tid, const char *name, void *some_func, void *some_data);

int (* _ksceKernelGetModuleList)(SceUID pid, int flags1, int flags2, SceUID *modids, size_t *num);
int (* _ksceKernelGetModuleInfo)(SceUID pid, SceUID modid, SceKernelModuleInfo *info);

void *SceKernelModulemgr_text = NULL;
void *SceKernelModulemgr_data = NULL;

int get_function(void){

	GetExport("SceSysmem", 0xFFFFFFFF, 0xC0A4D2F3, &ksceKernelSysrootAlloc);
	GetExport("SceSysmem", 0xFFFFFFFF, 0xABAB0FAB, &ksceKernelSysrootFree);
	GetExport("SceSysmem", 0xFFFFFFFF, 0x382C71E8, &SceQafMgrForDriver_382C71E8);
	GetExport("SceSysmem", 0xFFFFFFFF, 0x67AAB627, &SceSysrootForDriver_67AAB627);
	GetExport("SceSysmem", 0xFFFFFFFF, 0x6E0BC27C, &SceSysrootForDriver_6E0BC27C);

	GetExport("SceKernelThreadMgr", 0xFFFFFFFF, 0xE50E1185, &SceThreadmgrForDriver_E50E1185);

	GetExport("SceProcessmgr", 0xFFFFFFFF, 0x00B1CA0F, &sceKernelAllocRemoteProcessHeapForDriver);
	GetExport("SceProcessmgr", 0xFFFFFFFF, 0x0A5A2CF1, &SceProcessmgrForKernel_0A5A2CF1);
	GetExport("SceProcessmgr", 0xFFFFFFFF, 0x41815DF2, &SceProcessmgrForKernel_41815DF2);
	GetExport("SceProcessmgr", 0xFFFFFFFF, 0xB75FB970, &SceProcessmgrForKernel_B75FB970);
	GetExport("SceProcessmgr", 0xFFFFFFFF, 0xC1C91BB2, &SceProcessmgrForKernel_C1C91BB2);
	GetExport("SceProcessmgr", 0xFFFFFFFF, 0xC6820972, &sceKernelGetProcessClassForKernel);

	if(GetExport("SceKernelModulemgr", 0xC445FA63, 0xD269F915, &_ksceKernelGetModuleInfo) < 0)
	if(GetExport("SceKernelModulemgr", 0x92C9FFC2, 0xDAA90093, &_ksceKernelGetModuleInfo) < 0)
		return 1;

	GetExport("SceKernelModulemgr", 0x92C9FFC2, 0x97CF7B4E, &_ksceKernelGetModuleList);

	return 0;
}

int get_data(void){

	tai_module_info_t tai_info;
	tai_info.size = sizeof(tai_module_info_t);

	SceKernelModuleInfo sce_info;
	sce_info.size = sizeof(SceKernelModuleInfo);

	taiGetModuleInfoForKernel(KERNEL_PID, "SceKernelModulemgr", &tai_info);

	_ksceKernelGetModuleInfo(KERNEL_PID, tai_info.modid, &sce_info);

	SceKernelModulemgr_text = sce_info.segments[0].vaddr;
	SceKernelModulemgr_data = sce_info.segments[1].vaddr;

	return 0;
}

void func_0x810014a8(void){
	int r0 = 1;
	int r1 = 0;
  
	do{
		if ((r0 & *(uint32_t *)(SceKernelModulemgr_data + 0x30)) != 0) {
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

void *func_0x81001f0c(SceUID modid){

	int r0;
	void *obj_base;

	r0 = ksceKernelGetObjForUid(modid, (SceClass *)*(uint32_t *)(SceKernelModulemgr_data + 0x48), (SceObjectBase **)&obj_base);
	if (r0 < 0) {
		obj_base = NULL;
	}

	return obj_base;
}

int func_0x810021b8(SceUID pid){
	ksceKernelUidRelease(pid);
	return 0;
}

int func_0x810021d8(SceUID pid){
	if (pid != 0x10005) {
		ksceKernelUidRelease(pid);
	}
	return 0;
}

int func_0x810021c0(SceUID pid){
	if (pid != 0x10005) {
		return func_0x81001ec4(pid);
	}
	return 0;
}

int func_0x81003708(uint16_t flag){

	int res;
	void *pRes;
	SceUID pid;
	int *cpu_suspend_intr;

	if((flag & ~0x30) != 0)
		goto label_0x8100375C;

	pid = ksceKernelGetProcessId();
	if(pid == 0x10005)
		goto label_0x81003764;

	pRes = get_proc_module_tree_obj_for_pid(pid, (int *)&cpu_suspend_intr);
	if(pRes == NULL)
		goto label_0x8100377C;

	if(flag <= (*(uint16_t *)(pRes + 0x1A) & 0x30))
		goto label_0x8100376E;

	*(uint16_t *)(pRes + 0x1A) = (flag | (*(uint16_t *)(pRes + 0x1A) & ~0x30));
	func_0x81006e90(pRes, (int)cpu_suspend_intr);

	res = 0;

label_0x8100374E:
	return res;

label_0x8100375C:
	res = 0x80020005;
	goto label_0x8100374E;

label_0x81003764:
	res = 0x8002D017;
	goto label_0x8100374E;

label_0x8100376E:
	func_0x81006e90(pRes, (int)cpu_suspend_intr);
	res = 0x80020005;
	goto label_0x8100374E;

label_0x8100377C:
	res = 0x8002D080;
	goto label_0x8100374E;
}

int func_0x81004198(void *a1, int a2, int a3){
	// yet not Reversed
	return 0;
}

int func_0x8100428c(void *a1, int a2, int a3){
	// yet not Reversed
	return 0;
}

void *func_0x8100498c(SceUID pid, int len){
	void *res;

	if (pid != 0x10005) {
		res = sceKernelAllocRemoteProcessHeapForDriver(pid, len);
	}else{
		res = ksceKernelSysrootAlloc(len);
	}
	return res;
}

int func_0x810049fc(const char *path){
	const char **pPath;
	int r0;
	int r1;

	if(
	  (*(uint32_t *)(SceKernelModulemgr_data + 0x304) != 0) && (*(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 8) > 0)
	){
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

int func_0x81004a54(void){
	*(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 4) = 0xffffffff;
	return 0;
}

int func_0x81005648(SceUID pid, int flags, void *dst){
/*
	int res;
	SceObjectBase *local_44;
	SceCreateUidObjOpt local_40;

	if(pid == 0x10005){
		res = ksceKernelCreateUidObj(
			(SceClass *)*(uint32_t *)(SceKernelModulemgr_data + 0x48),
			"SceModuleMgrNewModule",
			0,
			&local_44
		);

		if (res < 0)
			goto loc_810056c8;

		*(uint32_t *)(((char *)local_44) + 0x10) = 0xffffffff;
		*(uint32_t *)(((char *)local_44) + 0x1c) = 0x10005;
		*(uint32_t *)(((char *)local_44) + 0x14) = res;

	}else{

		local_40.field_10 = ((flags & 0x10) != 0) ? 1 : 0;

		local_40.flags = 8;
		local_40.field_4 = 0;
		local_40.field_8 = 0;
		local_40.pid = pid;
		local_40.field_14 = 0;
		local_40.field_18 = 0;

		res = SceProcessmgrForKernel_B75FB970(pid);
		if(res < 0)
			goto loc_810056c8;

		res = ksceKernelCreateUidObj(
			(SceClass *)*(uint32_t *)(SceKernelModulemgr_data + 0x48),
			"SceModuleMgrNewModule",
			&local_40,
			&local_44
		);

		if(res < 0){
			SceProcessmgrForKernel_0A5A2CF1(pid, local_40.field_10);
			goto loc_810056c8;
		}
		*(uint32_t *)(((char *)local_44) + 0x10) = 0x03600011;
		*(uint32_t *)(((char *)local_44) + 0x1c) = pid;
		*(uint32_t *)(((char *)local_44) + 0x14) = res;
	}
	res = (int)dst;
	if(dst != NULL){
		*(uint32_t *)dst = local_44;
		res = 0;
	}
loc_810056c8:

	return res;
*/
	return 0;
}

int func_0x81005a70(void *r0, const char *path, int flags){

	int res = 0;
	int path_len;
	void *pPath;
	uint16_t uVar1;

	uVar1 = *(uint16_t *)(r0 + 4);
	if((uVar1 & 0x500) != 0){
		*(uint32_t *)(r0 + 0x68) = *(uint32_t *)(*(uint32_t *)(*(uint32_t *)(r0 + 0xD4) + 4) + 0x68);
		return 0;
	}

	path_len = strnlen(path, 0xff);
	if(((int)((uint32_t)uVar1 << 0x16) < 0) && (0xfe < path_len)){
		res = 0x8002d01f;
	}else{
		pPath = func_0x8100498c(*(uint32_t *)(r0 + 0x14), path_len + 1);
		*(int *)(r0 + 0x68) = (int)pPath;
		if(pPath == NULL){
			res = 0x8002d008;
		}else{
			memcpy(pPath, path, path_len);
			*(uint8_t *)(*(uint32_t *)(r0 + 0x68) + path_len) = 0;
			if((flags & 0x800) != 0){
				memcpy((void *)*(uint32_t *)(r0 + 0x68), "bootfs:", 7);
			/*
				*(uint32_t *)(*(uint32_t *)(r0 + 0x68) + 0) = 0x746f6f62;
				*(uint16_t *)(*(uint32_t *)(r0 + 0x68) + 4) = 0x7366;
				*(uint8_t  *)(*(uint32_t *)(r0 + 0x68) + 6) = 0x3a;
			*/
				return 0;
			}
		}
	}
	return res;
}

/*
 * print_module_load_info / func_0x81005b04
 *
 * @param[in] r0 - unk, some module info
 */
void print_module_load_info(void *r0){

	if(SceQafMgrForDriver_382C71E8() != 0) {
		if (*(int *)(r0 + 0x6c) < 2) {
			ksceDebugPrintf2(0, (void *)(SceKernelModulemgr_text + 0xD90C), "[%-27s]:text=%p(0x%08x), (no data)\n",
				*(int *)(r0 + 0x1c), *(int *)(r0 + 0x7c), *(int *)(r0 + 0x74)
			);
		}else{
			ksceDebugPrintf2(0, (void *)(SceKernelModulemgr_text + 0xD8F4), "[%-27s]:text=%p(0x%08x), data=%p(0x%08x/0x%08x)\n",
				*(int *)(r0 + 0x1c), *(int *)(r0 + 0x7c), *(int *)(r0 + 0x74),
				*(int *)(r0 + 0x90), *(int *)(r0 + 0x84), *(int *)(r0 + 0x88)
			);
		}
	}
}

int func_0x81005fec(void *a1, void *a2){
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

int _func_0x81006cf4(int a1, int a2, int a3, void *a4){

	int res;

	*(uint32_t *)(a4) = 0;

	res = (a3 - 0x200000) >> 0xC;

	if((uint32_t)(res) < 0x8000)
		goto label_0x81006D36;

	res = (a3 + -0x8000000) >> 0xC;

	if((uint32_t)(res) < 0x8000)
		goto label_0x81006D32;

	a3 += 0x7F000000;

	if((uint32_t)a3 < 0x6F000000){
		a2 = *(uint32_t *)(a2);
		a3 = a3 >> 0xC;
	}else{
		a1 = 0;
	}

	if((uint32_t)a3 < 0x6F000000){
		a1 = a1 + (a3 << 2);
		a3 = a2 + (a3 << 3);
		*(uint32_t *)(a4) = a3;
	}
	return a1;

label_0x81006D32:
	res += 0x8000;

label_0x81006D36:
	a1 = a1 + (res << 2);
	return a1;
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

/*
 * get_proc_module_tree_obj_for_pid / func_0x81006e60
 *
 * @param[in]  pid              - target pid
 * @param[out] cpu_suspend_intr - ksceKernelCpuSuspendIntr res out
 *
 * @return module tree pointer on success, < 0 on error.
 */
module_tree_top_t *get_proc_module_tree_obj_for_pid(SceUID pid, int *cpu_suspend_intr){
	int r0, r1;
	module_tree_top_t *r2;

	r0 = func_0x810021c0(pid);
	if (r0 < 0) {
		r2 = NULL;
	}else{
		r2 = SceProcessmgrForKernel_C1C91BB2(pid);
		if (r2 != NULL) {
			r1 = ksceKernelCpuSuspendIntr((int *)(&r2->cpu_addr));
			*cpu_suspend_intr = r1;
		}

		func_0x810021d8(pid);
	}

	return r2;
}

int func_0x81006e90(module_tree_top_t *module_tree_top, int cpu_suspend_intr){
	return ksceKernelCpuResumeIntr((int *)(&module_tree_top->cpu_addr), cpu_suspend_intr);
}

int func_0x81006e9c(SceUID pid){

	int cpu_suspend_intr;
	void *pRes;
	char data[0x24];
	void *arg1;

	pRes = get_proc_module_tree_obj_for_pid(pid, &cpu_suspend_intr);
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

int func_0x810076b0(SceUID pid, SceUID uid, int a2, SceKernelLibraryInfo *info){
	// yet not Reversed
	return 0;
}

/*
 * get_module_info / func_0x81007790
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
	module_tree_top_t *module_tree_top;
	SceKernelModuleInfoObj_t *info_obj;

	module_tree_top = get_proc_module_tree_obj_for_pid(pid, &cpu_suspend_intr);
	if(module_tree_top == NULL){
		res = 0x8002d080;
		goto loc_810077e6;
	}

	info_obj = func_0x81001f0c(modid);
	if(info_obj == NULL){
		res = 0x8002d082;
	}else{

		if(modid == info_obj->modid_kernel){

			info->handle = (pid == 0x10005) ? modid : info_obj->modid_user;

			info->flags = info_obj->flags;
			info->minor = info_obj->minor;
			info->major = info_obj->major;

			strncpy(info->module_name, info_obj->module_name, 28-1);

			switch(info_obj->type){
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

			info->module_start	= info_obj->module_start;
			info->unk30		= info_obj->unkC0;
			info->module_stop	= info_obj->module_stop;

			info->exidxTop		= info_obj->exidxTop;
			info->exidxBtm		= info_obj->exidxBtm;
			info->unk40		= info_obj->unk50;
			info->unk44		= info_obj->unk54;

			info->tlsInit		= info_obj->tlsInit;
			info->tlsInitSize	= info_obj->tlsInitSize;
			info->tlsAreaSize	= info_obj->tlsAreaSize;

			strncpy(info->path, info_obj->path, 0x100-1);
			mod_seg_num = info_obj->segments_num;
			current_seg = 0;

			if(mod_seg_num < 1){
				mod_seg_num = 0;
loc_810078fc:

				do {
					info->segments[mod_seg_num].perms = 0;
					info->segments[mod_seg_num].vaddr = 0;
					info->segments[mod_seg_num].memsz = 0;
					info->segments[mod_seg_num].flags = 0;
					mod_seg_num++;
				} while (mod_seg_num < 4);

			}else{

				do {
					info->segments[current_seg].size = 0x18;
					info->segments[current_seg].perms = (info_obj->segments[current_seg].perms[0] | (info_obj->segments[current_seg].perms[1] << 0x14));
					info->segments[current_seg].vaddr = info_obj->segments[current_seg].vaddr;
					info->segments[current_seg].memsz = info_obj->segments[current_seg].memsz;
					info->segments[current_seg].flags = info_obj->segments[current_seg].flags;
					current_seg++;
				} while(current_seg < mod_seg_num);

				if(mod_seg_num < 4)
					goto loc_810078fc;
			}
			res = 0;
		}else{
			res = 0x8002d082;
		}
		func_0x810021b8(modid);
	}

	ksceKernelCpuResumeIntr((int *)(&module_tree_top->cpu_addr), cpu_suspend_intr);

loc_810077e6:

	return res;
}

int func_0x81007a84(void *a1, const void *addr, void *out){

	int res;
	int res2;
	void *pRes;
	int count;
	int temp;

	pRes = (void *)(*(uint32_t *)(a1 + 0x1C));
	if(pRes == NULL)
		goto label_0x81007AC2;

	pRes = func_0x81006cf4(*(uint32_t *)(pRes), pRes + 0x10, addr, &temp);
	if(pRes == NULL)
		goto label_0x81007AC2;

	pRes = (void *)(*(uint32_t *)(pRes));
	if(pRes == NULL)
		goto label_0x81007AC2;

	if((uint32_t)((uint32_t)addr - *(uint32_t *)(pRes + 0x7C)) >= (uint32_t)(*(uint32_t *)(pRes + 0x74)))
		goto label_0x81007AC2;

	*(uint32_t *)(out) = (uint32_t)pRes;
	res = 0;
	goto label_0x81007AFA;

label_0x81007AC2:
	pRes = (void *)(*(uint32_t *)(a1 + 0x10));

label_0x81007AC8:
	if(pRes == NULL)
		goto label_0x81007AF2;

	res2 = (int)(*(uint32_t *)(pRes + 0x6C));
	count = 0;

label_0x81007ACE:
	if(count >= res2) // signed
		goto label_0x81007AEE;

	if((uint32_t)((uint32_t)addr - *(uint32_t *)(0x14 * count + pRes + 0x7C)) >= *(uint32_t *)(0x14 * count + pRes + 0x74)) // unsigned
		goto label_0x81007AE8;

	*(uint32_t *)(out) = (uint32_t)pRes;
	res = 0;
	goto label_0x81007AFA;

label_0x81007AE8:
	count += 1;
	//UXTH	R3, R3
	asm volatile(
		"uxth %0, %1\n"
		: "=r"(count)
		: "r"(count)
		:
	);
	goto label_0x81007ACE;

label_0x81007AEE:
	pRes = (void *)(*(uint32_t *)(pRes));
	goto label_0x81007AC8;

label_0x81007AF2:
	res = 0x8002D082;

label_0x81007AFA:

	return res;
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
	void *some_addr;
	void *pRes;

	pRes = get_proc_module_tree_obj_for_pid(pid, &cpu_suspend_intr);
	if(pRes == NULL)
		goto label_0x81007BF8;

	res = func_0x81007a84(pRes, module_addr, &some_addr);
	if(res != 0)
		goto label_0x81007BEA;

	res = *(uint32_t *)(some_addr + 0xC);

label_0x81007BEA:
	ksceKernelCpuResumeIntr((int *)(pRes + 0x20), cpu_suspend_intr);
	goto label_0x81007C00;

label_0x81007BF8:
	res = 0x8002D080;

label_0x81007C00:
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
	if(pid == 0x10005)
		goto label_0x81007C4A;

	if(modid <= 0)
		goto label_0x81007C4A;

	pRes = func_0x81001f0c(modid);
	if(pRes == NULL)
		goto label_0x81007C4E;

	func_0x810021b8(modid);
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

/*
 * search_module_by_name / func_0x81007c5c
 *
 * @param[in] pid         - target pid
 * @param[in] module_name - target module name
 *
 * @return modid on success, < 0 on error.
 */
SceUID search_module_by_name(SceUID pid, const char *module_name){

	SceUID uid;
	int cpu_suspend_intr;
	module_tree_top_t *module_tree_top;
	module_tree_t *module_tree;

	module_tree_top = get_proc_module_tree_obj_for_pid(pid, &cpu_suspend_intr);
	if(module_tree_top == NULL){
		uid = 0x8002d080;
	}else{

		module_tree = module_tree_top->module_tree;
 		while(module_tree != NULL){

			if(strncmp(module_tree->module_name, module_name, 0x1a) == 0){
				uid = module_tree->modid;
				goto loc_81007c9a;
			}
			module_tree = module_tree->next;
		}
		uid = 0x8002d082;
loc_81007c9a:
		ksceKernelCpuResumeIntr((int *)(&module_tree_top->cpu_addr), cpu_suspend_intr);
	}

	return uid;
}

int func_0x81007f00(SceUID pid){
	return *(uint16_t *)(SceProcessmgrForKernel_C1C91BB2(pid) + 0x1A) & 1;
}

// sub_810021EC
SceUID module_load_for_pid(SceUID pid, const char *path, int flags, SceKernelLMOption *option){
	// yet not Reversed
	return 0;
}

// sub_8100286C
int module_start_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){
	// yet not Reversed
	return 0;
}

// sub_81002EDC
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

// sub_81002B40
int module_stop_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){
	// yet not Reversed
	return 0;
}

// sub_810026BC
int module_unload_for_pid(SceUID pid, SceUID modid, int flags, SceKernelULMOption *option){
	// yet not Reversed
	return 0;
}

// sub_81002EB0
int module_stop_unload_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){

	int res;

	res = module_stop_for_pid(pid, modid, args, argp, flags, NULL, status);
	if(res < 0)
		goto end;

	res = module_unload_for_pid(pid, modid, flags, option);

end:
	return res;
}

// sub_81003000
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

SceUID sceKernelSearchModuleByNameForDriver(const char *module_name);
int ksceKernelGetModuleInfo(SceUID pid, SceUID modid, SceKernelModuleInfo *info);

int SceModulemgrForDriver_1D9E0F7E(void *a1, SceKernelModuleInfo *info);

SceUID ksceKernelSysrootGetShellPid(void);



int threadFunc(SceSize args, void *argp){

	int res;
	SceUID shell_pid, shell_uid;
	SceUID t_shell_uid;
	SceKernelModuleInfo info;

	ksceKernelDelayThread(15 * 1000 * 1000);

	shell_pid = ksceKernelSysrootGetShellPid();

	shell_uid = search_module_by_name(shell_pid, "SceShell");

	ksceDebugPrintf("shell_pid : 0x%X\n", shell_pid);
	ksceDebugPrintf("shell_uid : 0x%X\n", shell_uid);


	memset(&info, 0, sizeof(info));

	//SceModulemgrForDriver_1D9E0F7E((void *)(0x81010000), &info);


	// ksceKernelGetModuleIdByAddr
	t_shell_uid = get_module_id_by_addr(shell_pid, (const void *)(0x81010000));
	if(t_shell_uid < 0)
		t_shell_uid = get_module_id_by_addr(shell_pid, (const void *)(0x81080000));

	ksceDebugPrintf("t_shell_uid : 0x%X\n", t_shell_uid);




	t_shell_uid = ksceKernelKernelUidForUserUid(shell_pid, t_shell_uid);

	ksceDebugPrintf("ksceKernelKernelUidForUserUid : 0x%X\n", t_shell_uid);


	res = ksceKernelGetModuleInfo(shell_pid, t_shell_uid, &info); // reverse

	ksceDebugPrintf("ksceKernelGetModuleInfo : 0x%X\n", res);


	write_file("ur0:data/module_rev_SceKernelModulemgr_1D9E0F7E_rev_shell.bin", &info, sizeof(info));


	return ksceKernelExitDeleteThread(0);
}


void _start() __attribute__ ((weak, alias("module_start")));
int module_start(SceSize args, void *argp){

	SceUID uid;

	get_function();
	get_data();

	//uid = sceKernelSearchModuleByNameForDriver("SceSysmem");
	//write_file("ur0:data/module_rev_SceSysmem_uid.bin", &uid, 4);

	uid = sceKernelSearchModuleByNameForDriver("SceKernelModulemgr");
	//write_file("ur0:data/module_rev_SceKernelModulemgr_uid.bin", &uid, 4);

	//void *data = func_0x81001f0c(uid);
	//write_file("ur0:data/module_rev_SceKernelModulemgr_data.bin", data, 0x400);

/*
	// You can check the hash to see if the function is correct :)
	SceKernelModuleInfo info;

	memset(&info, 0, sizeof(info));
	_ksceKernelGetModuleInfo(0x10005, uid, &info);  // original export
	write_file("ur0:data/module_rev_SceKernelModulemgr_Info.bin", &info, sizeof(info));

	memset(&info, 0, sizeof(info));
	ksceKernelGetModuleInfo(0x10005, uid, &info); // reverse
	write_file("ur0:data/module_rev_SceKernelModulemgr_Info_rev.bin", &info, sizeof(info));

	memset(&info, 0, sizeof(info));
	SceModulemgrForDriver_1D9E0F7E(_ksceKernelSearchModuleByName, &info);
	write_file("ur0:data/module_rev_SceKernelModulemgr_1D9E0F7E_rev.bin", &info, sizeof(info));
*/

	SceUID thid;
	thid = ksceKernelCreateThread("my_thread", threadFunc, 0x10000100, 0x10000, 0, 0, NULL);
	if(thid > 0)
		ksceKernelStartThread(thid, 0, NULL);

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp){
	return SCE_KERNEL_STOP_SUCCESS;
}


#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/processmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>
#include <stdio.h>
#include <string.h>

#include "modulemgr_types.h"
#include "modulemgr_internal.h"
#include "modulemgr_common.h"

// return value is previous value
int ksceKernelSetPermission(int value);

// return value is previous value
SceUID ksceKernelSetProcessId(SceUID pid);

extern void *SceKernelModulemgr_text;
extern void *SceKernelModulemgr_data;


extern int (* SceIntrmgrForKernel_B60ACF4B)(int len, void *ptr_dst);
extern void *(* sceKernelGetProcessClassForKernel)(void);
extern int (* SceThreadmgrForDriver_E50E1185)(SceUID tid, const char *name, void *some_func, void *some_data);
extern void *(* ksceKernelSysrootAlloc)(int size);
extern int (* ksceKernelSysrootFree)(void *ptr);
extern int (* _ksceKernelGetModuleList)(SceUID pid, int flags1, int flags2, SceUID *modids, size_t *num);

int sceKernelGetModuleIdByAddrForKernel(SceUID pid, const void *module_addr){
	return get_module_id_by_addr(pid, module_addr);
}

int sceKernelUnloadProcessModulesForKernel(SceUID pid){

	int cpu_suspend_intr;
	void *pRes;
	SceUID modid;

	goto label_0x81003910;

label_0x810038F2:
	if(*(uint32_t *)(pRes + 0x10) == 0)
		goto label_0x81003934;

	modid = *(uint32_t *)(*(uint32_t *)(pRes + 0x10) + 0xC);

	func_0x81006e90(pRes, cpu_suspend_intr);
	module_stop_unload_for_pid(pid, modid, 0, 0, 0x40000330, 0, 0);

label_0x81003910:
	pRes = get_proc_module_tree_obj_for_pid(pid, &cpu_suspend_intr);
	if(pRes != 0)
		goto label_0x810038F2;

	return 0x8002D080;

label_0x81003934:
	func_0x81006e90(pRes, cpu_suspend_intr);
	func_0x81006e9c(pid);
	return 0;
}

int sceKernelModuleUnloadMySelfForKernel(void){

	int res;
	void *lr;
	__asm__ volatile ("mov %0, lr" : "=r" (lr));
	func_0x810014d4();
	*(uint32_t *)(SceKernelModulemgr_data + 0x2F8) = ksceKernelGetThreadId();
	*(uint32_t *)(SceKernelModulemgr_data + 0x2FC) = get_module_id_by_addr(0x10005, lr);

	res = SceThreadmgrForDriver_E50E1185(0x10023, "SceKernelUnloadMySelf", (void *)(SceKernelModulemgr_text + 0x3155), (void *)(SceKernelModulemgr_data + 0x2F8));
	if(res < 0)
		goto label_0x81003706;

	res = ksceKernelExitDeleteThread(0);
	res = res & (res >> 31);

label_0x81003706:
	return res;
}

int SceModulemgrForKernel_2C2618D9(SceUID pid, void *a2, void *a3)
{

	int res;
	int cpu_intr;
	module_tree_top_t *mod_tree;

	if (pid == 0)
		pid = ksceKernelGetProcessId();

	mod_tree = get_proc_module_tree_obj_for_pid(pid, &cpu_intr);
	if (mod_tree == NULL){
		res = 0x8002D080;
	}else{
		res = func_0x81007a84(mod_tree, a2, a3);
		ksceKernelCpuResumeIntr((int *)(&mod_tree->cpu_addr), cpu_intr);
	}

	return res;
}

int SceModulemgrForKernel_FF2264BB(SceUID a1, int a2, int a3, int a4)
{
	return 0;
}

int sceKernelGetProcessMainModulePathForKernel(SceUID pid, char *path, int pathlen)
{
	void *dat;

	dat = func_0x81001f0c(pid);
	if (dat == NULL)
		return 0x8002D082;

	strncpy(path, (const char *)(*(uint32_t *)(dat + 0x70)), pathlen);
	func_0x810021b8(pid); // Release Uid
	return 0;
}

// sceKernelModuleGetProcessMainModuleXXXXXForKernel
int SceModulemgrForKernel_EEA92F1F(SceUID pid, void *a2)
{
	void *dat;

	dat = func_0x81001f0c(pid);
	if (dat == NULL)
		return 0x8002D082;

	*(uint32_t *)(a2) = *(uint32_t *)(dat + 0x38);
	func_0x810021b8(pid);
	return 0;
}

// Bigger function
// https://wiki.henkaku.xyz/vita/SceKernelModulemgr#sceKernelLoadPreloadingModulesForKernel
int sceKernelLoadPreloadingModulesForKernel(SceUID pid, void *unk_buf, int flags){
	// yet not Reversed
	return 0;
}

int sceKernelStartPreloadingModulesForKernel(SceUID pid){

	int res = 0;
	size_t modnum = 0xF;
	SceUID modlist[0x10];
	void *pRes;

	if(_ksceKernelGetModuleList(pid, 0x80, 1, modlist, &modnum) < 0)
		goto label_0x810036A4;

	if(modnum == 0)
		goto label_0x810036A4;

	goto label_0x81003644;

label_0x8100363E:
	if(modnum == 0)
		goto label_0x810036B0;

label_0x81003644:
	modnum -= 1;
	pRes = func_0x81001f0c(modlist[modnum]);
	if(pRes == NULL)
		goto label_0x8100363E;

	res = module_start_for_pid(pid, modlist[modnum], 0, 0, (ksceSysrootUseExternalStorage() != 0) ? 0x4000000 : 0, 0, 0);

	ksceKernelUidRelease(modlist[modnum]);

	if(res >= 0)
		goto label_0x8100363E;

	if(ksceSysrootUseExternalStorage() != 0)
		goto label_0x8100363E;

label_0x810036A4:
	return res;

label_0x810036B0:
	res = 0;
	goto label_0x810036A4;
}

int SceModulemgrForKernel_78DBC027(SceUID pid, SceUID UserUid, void *a3, void *a4){

	SceUID KernelUid;
	void *res1;

	if(pid != 0x10005)
		goto label_0x81003316;

label_0x8100330A:
	return 0x8002D012;

label_0x81003316:
	if(func_0x81001ec4(pid) < 0)
		goto label_0x8100330A;

	KernelUid = ksceKernelKernelUidForUserUid(pid, UserUid);

	if(KernelUid >= 0)
		goto label_0x81003336;

	ksceKernelUidRelease(pid);

	return KernelUid;

label_0x81003336:
	res1 = func_0x81001f0c(KernelUid);
	if(res1 != 0)
		goto label_0x81003350;

	ksceKernelUidRelease(pid);

	return 0x8002D011;

label_0x81003350:
	*(uint32_t *)(a3) = *(uint32_t *)(res1 + 0xB4);
	*(uint32_t *)(a4) = *(uint32_t *)(res1 + 0xB8);
	ksceKernelUidRelease(KernelUid);
	ksceKernelUidRelease(pid);

	if(*(uint32_t *)(a3) == 0){
		return 0x8002D01C;
	}else{
		return 0;
	}
}

int SceModulemgrForKernel_99890202(SceUID pid, const void *module_addr){
	// yet not Reversed
	return 0;
}

//  SceModulemgrForKernel_F95D09C2("os0:ue/cui_setupper.self", sp + 0x60, sp + 0x70);
int SceModulemgrForKernel_F95D09C2(const char *path, void *a2, void *a3){
	// yet not Reversed
	return 0;
}

void sceKernelRegisterSyscallForKernel(int syscall_id, const void *func){

	int dacr;

	if ((uint32_t)syscall_id >= 0x1000)
		return;

	asm volatile ("mrc p15, 0, %0, c3, c0, 0" : "=r" (dacr));
	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (0x17450000));

	*(uint32_t *)((*(uint32_t *)(SceKernelModulemgr_data + 0x334)) + (syscall_id << 0x2)) = (uint32_t)func;

	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (dacr));

	return;
}

// non export
void sceKernelUnregisterSyscallForKernel(int syscall_id){

	int dacr;

	if ((uint32_t)syscall_id >= 0x1000)
		return;

	asm volatile ("mrc p15, 0, %0, c3, c0, 0" : "=r" (dacr));
	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (0x17450000));

	*(uint32_t *)((*(uint32_t *)(SceKernelModulemgr_data + 0x334)) + (syscall_id << 0x2)) = (uint32_t)&syscall_stub;

	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (dacr));

	return;
}

void *SceModulemgrForKernel_66606301(SceUID modid){

	void *res;

	res = func_0x81001f0c(modid);
	if(res == NULL)
		goto label_0x810032CA;

	res = (void *)(*(uint32_t *)(res + 0xBC));
	ksceKernelUidRelease(modid);

label_0x810032CA:
	return res;
}

int sceKernelGetModuleInternalForKernel(SceUID modid, void **module){

	void *r0 = func_0x81001f0c(modid);
	if (r0 == NULL)
		goto loc_810032EA;

	if (module == NULL)
		goto loc_810032E0;

	*(uint32_t *)(module) = (uint32_t)(r0 + 8);

loc_810032E0:
	ksceKernelUidRelease(modid);
	return 0;

loc_810032EA:
	return 0x8002D011;
}

int sceKernelGetModuleInfoForKernel(SceUID pid, SceUID modid, SceKernelModuleInfo *info){
	if(pid == 0){
		pid = ksceKernelGetProcessId();
	}

	return get_module_info(pid, modid, (SceKernelModuleInfo_fix_t *)info);
}

int sceKernelFinalizeKblForKernel(void){

	SceUID modid;
	modid = *(uint32_t *)(*(uint32_t *)(SceKernelModulemgr_data + 0x38) + 0xA8);
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

	modid = ksceKernelLoadStartModule(bootImagePath, 0, 0, 0x100, 0, 0);
	if(modid < 0){
		res = modid;
		goto label_0x81004AF2;
	}

	pRes = ksceKernelSysrootAlloc(0x10);
	*(uint32_t *)(pBootfsMountInfo) = (uint32_t)pRes;
	*(uint32_t *)(pRes + 0x00) = modid;
	*(uint32_t *)(pRes + 0x04) = 0xFFFFFFFF;
	*(uint32_t *)(pRes + 0x08) = 0;
	*(uint32_t *)(pRes + 0x0C) = 0;
	func_0x81001f0c(modid);
	func_0x810021b8(modid);
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

	ksceKernelStopUnloadModule(modid, 0, 0, 0, 0, 0);
	ksceKernelSysrootFree((void *)(*(uint32_t *)(pBootfsMountInfo)));
	res = 0;
	*(uint32_t *)(pBootfsMountInfo) = 0;

label_0x81004B30:
	return res;

label_0x81004B34:
	res = 0x8002D001;
	goto label_0x81004B30;
}

int sceKernelLoadProcessImageForKernel(int a1, int a2, int a3, int a4, int a5, int a6)
{
	// yet not Reversed
	return 0;
}

int sceKernelLoadPtLoadSegForFwloaderForKernel(const char *path, int e_phnum, void *buffer, uint32_t bufsize, int zero_unk, uint32_t *bytes_read)
{
	// yet not Reversed
	return 0;
}

int sceKernelGetModuleListForKernel(SceUID pid, int flags1, int flags2, SceUID *modids, size_t *num)
{
	// yet not Reversed
	return 0;
}

int SceModulemgrForKernel_1BDE2ED2(SceUID pid, void *a2, int *num)
{
	// yet not Reversed
	return 0;
}

int SceModulemgrForKernel_1D341231(SceUID pid, void *a2, int *num)
{
	// yet not Reversed
	return 0;
}

int sceKernelGetModuleUidListForKernel(SceUID pid, SceUID *modids, size_t *num)
{
	// yet not Reversed
	return 0;
}

SceUID sceKernelGetProcessMainModuleForKernel(SceUID pid)
{
	// yet not Reversed
	return 0;
}

int SceModulemgrForKernel_29CB2771(SceUID pid)
{
	// yet not Reversed
	return 0;
}

int SceModulemgrForKernel_2DD3B511(SceUID pid, int a2, int a3, int a4)
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
	dat = get_proc_module_tree_obj_for_pid(0x10005, &cpu_intr);
	if (dat == NULL)
		ksceDebugPrintKernelPanic((void *)(SceKernelModulemgr_text + 0xD84C), lr);

	if (*(uint32_t *)(dat + 4) == 0)
		goto loc_81004152;

loc_81004142:
	if (func_0x810040c8((module_tree_top_t *)(*(uint32_t *)(dat + 4))) < 0)
		ksceDebugPrintKernelPanic((void *)(SceKernelModulemgr_text + 0xD81C), lr);

	if (*(uint32_t *)(*(uint32_t *)(dat + 4)) != 0)
		goto loc_81004142;

loc_81004152:
	func_0x810070b4(dat);
	func_0x81006e90(dat, cpu_intr);
	return;
}

int sceKernelGetModuleUidForKernel(SceUID pid, SceUID modid, SceUID *modid_out, const void *unk1, int unk2)
{
	// yet not Reversed
	return 0;
}

int sceKernelGetModuleList2ForKernel(SceUID pid, SceKernelModuleListInfo *infolists, size_t *num)
{
	// yet not Reversed
	return 0;
}

int SceModulemgrForKernel_4865C72C(int a1, int a2)
{
	// yet not Reversed
	return 0;
}

int SceModulemgrForKernel_619925F1(SceUID pid, int a2, int a3, int a4)
{
	// yet not Reversed
	return 0;
}

int sceKernelGetModuleInfo2ForKernel(SceUID pid, SceUID modid, SceKernelModuleInfo2_fix *info)
{
	int res;
	int a1;
	void *dat;

	res = func_0x810021c0(pid);
	if (res < 0)
		goto loc_81008952;

	dat = func_0x81006de8(pid, modid);
	if (dat == NULL)
		goto loc_81008940;

	a1 = *(uint32_t *)(*(uint32_t *)(dat + 8) + 0x18);
	if (a1 != modid)
		a1 = *(uint32_t *)(*(uint32_t *)(dat + 8) + 0x1C);

	info->modid1    = a1;
	info->unk_0x08  = *(uint32_t *)(*(uint32_t *)(*(uint32_t *)(dat + 8) + 8) + 0x10);
	info->unk_0x0C  = *(uint16_t *)(*(uint32_t *)(*(uint32_t *)(dat + 8) + 8) + 2);
	info->unk_0x0E  = *(uint16_t *)(*(uint32_t *)(*(uint32_t *)(dat + 8) + 8) + 4);
	info->unk_0x10  = *(uint16_t *)(*(uint32_t *)(*(uint32_t *)(dat + 8) + 8) + 6);
	info->unk_0x12  = *(uint16_t *)(*(uint32_t *)(*(uint32_t *)(dat + 8) + 8) + 8);
	info->unk_0x14  = 0;
	info->unk_0x118 = *(uint32_t *)(*(uint32_t *)(dat + 8) + 0x10);
	info->modid2    = (pid != 0x10005) ? *(uint32_t *)(*(uint32_t *)(*(uint32_t *)(dat + 8) + 0x20) + 0x10) : info->modid1;

	info->module_name[0xFF] = 0;
	strncpy(info->module_name, (const char *)(*(uint32_t *)(*(uint32_t *)(*(uint32_t *)(dat + 8) + 8) + 0x14)), 0xFF);

	func_0x810021b8(*(uint32_t *)(dat + 0xC));
	ksceKernelUidRelease(*(uint32_t *)(*(uint32_t *)(dat + 8) + 0x18));
	res = 0;
	goto loc_81008948;

loc_81008940:
	res = 0x8002D01C;

loc_81008948:
	func_0x810021d8(pid);

loc_81008952:
	return res;
}

int SceModulemgrForKernel_7A1E882D(SceUID pid, int *a2)
{
	int cpu_intr;
	void *dat;

	dat = get_proc_module_tree_obj_for_pid(pid, &cpu_intr);
	if (dat == NULL)
		return 0x8002D080;

	*(uint32_t *)(a2) = (uint32_t)(*(uint16_t *)(dat + 0x1A));

	ksceKernelCpuResumeIntr(&((module_tree_top_t *)dat)->cpu_addr, cpu_intr);

	return 0;
}

int sceKernelGetModuleInfoMinByAddrForKernel(SceUID pid, const void *module_addr, int *a3, int *a4, SceKernelModuleName *module_name)
{
	int res;
	int cpu_intr;
	void *dat, *some_addr;

	dat = get_proc_module_tree_obj_for_pid(pid, &cpu_intr);
	if (dat == NULL)
		return 0x8002D082;

	res = func_0x81007a84(dat, module_addr, &some_addr);
	if (res < 0)
		goto loc_81007ED6;

	if (a3 != NULL)
		*(uint32_t *)(a3) = *(uint32_t *)(some_addr + 0x30);

	if (a4 != NULL)
		*(uint32_t *)(a4) = *(uint32_t *)(some_addr + 0x7C);

	if (module_name != NULL)
		strncpy(module_name->module_name, (const char *)(*(uint32_t *)(some_addr + 0x1C)), 0x1B);

loc_81007ED6:
	ksceKernelCpuResumeIntr(&((module_tree_top_t *)dat)->cpu_addr, cpu_intr);

	return res;
}

int SceModulemgrForKernel_8D1AA624(void *a1, void *a2)
{
	// yet not Reversed
	return 0;
}

int SceModulemgrForKernel_952535A3(SceUID a1, int a2, int a3, int a4)
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
		*(uint32_t *)(SceKernelModulemgr_data + 0x308) = a1;
		res = 0;
	}else{
		res = 0x8002D01C;
	}
	return res;
}

int SceModulemgrForKernel_B73BE671(int a1, int a2, int a3)
{
	// yet not Reversed
	return 0;
}

int sceKernelGetModuleLibraryInfoForKernel(SceUID pid, SceUID modid, void *unk1, const void *unk2, int unk3)
{
	// yet not Reversed
	return 0;
}

void SceModulemgrForKernel_F3CD647F(int a1, int a2)
{
	*(uint32_t *)(SceKernelModulemgr_data + 0x330) = a1;
	*(uint32_t *)(SceKernelModulemgr_data + 0x32C) = a2;
}

int SceModulemgrForKernel_FB251B7A(SceUID pid, SceUID a2, int a3, int a4, int a5)
{
	// yet not Reversed
	return 0;
}






#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/processmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <stdio.h>
#include <string.h>

#include "modulemgr_internal.h"
#include "modulemgr_common.h"

// return value is previous value
int ksceKernelSetPermission(int value);

// return value is previous value
SceUID ksceKernelSetProcessId(SceUID pid);

extern void *SceKernelModulemgr_text;
extern void *SceKernelModulemgr_data;

extern void *(* sceKernelGetProcessClassForKernel)(void);
extern int (* SceThreadmgrForDriver_E50E1185)(SceUID tid, const char *name, void *some_func, void *some_data);
extern void *(* ksceKernelSysrootAlloc)(int size);
extern int (* ksceKernelSysrootFree)(void *ptr);
extern int (* _ksceKernelGetModuleList)(SceUID pid, int flags1, int flags2, SceUID *modids, size_t *num);



int SceModulemgrForKernel_0053BA4A(SceUID pid, void *a2){
	return func_0x81007c10(pid, a2);
}

int SceModulemgrForKernel_0E33258E(SceUID pid){

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
	pRes = func_0x81006e60(pid, &cpu_suspend_intr);
	if(pRes != 0)
		goto label_0x810038F2;

	return 0x8002D080;

label_0x81003934:
	func_0x81006e90(pRes, cpu_suspend_intr);
	func_0x81006e9c(pid);
	return 0;
}

int SceModulemgrForKernel_2A69385E(void){

	int res;
	void *lr;
	__asm__ volatile ("mov %0, lr" : "=r" (lr));
	func_0x810014d4();
	*(uint32_t *)(SceKernelModulemgr_data + 0x2F8) = ksceKernelGetThreadId();
	*(uint32_t *)(SceKernelModulemgr_data + 0x2FC) = func_0x81007c10(0x10005, lr);

	res = SceThreadmgrForDriver_E50E1185(0x10023, "SceKernelUnloadMySelf", (void *)(SceKernelModulemgr_text + 0x3155), (void *)(SceKernelModulemgr_data + 0x2F8));
	if(res < 0)
		goto label_0x81003706;

	res = ksceKernelExitDeleteThread(0);
	res = res & (res >> 31);

label_0x81003706:
	return res;
}

// Bigger function
// sceKernelLoadPreloadingModulesForKernel
// https://wiki.henkaku.xyz/vita/SceKernelModulemgr#sceKernelLoadPreloadingModulesForKernel
int SceModulemgrForKernel_3AD26B43(SceUID pid, void *unk_buf, int flags){
	// yet not Reversed
	return 0;
}

// maybe sceKernelStartPreloadingModulesForKernel
int SceModulemgrForKernel_432DCC7A(SceUID pid){

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

// sceKernelDecryptSelfByPathForKernel
int SceModulemgrForKernel_448810D5(int a1, int a2, int a3, int a4, int a5, int a6){
	// yet not Reversed
	return 0;
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

int SceModulemgrForKernel_99890202(SceUID pid, int a1){
	// yet not Reversed
	return 0;
}

// sceKernelLoadProcessImageForKernel
int SceModulemgrForKernel_AC4EABDB(SceUID pid, void *a2, int a3, void *a4, void *a5, int a6){
	// yet not Reversed
	return 0;
}

//  SceModulemgrForKernel_F95D09C2("os0:ue/cui_setupper.self", sp + 0x60, sp + 0x70);
int SceModulemgrForKernel_F95D09C2(const char *path, void *a2, void *a3){
	// yet not Reversed
	return 0;
}

int syscall_stub(){
	return 0x8002710C;
}

// ksceKernelRegisterSyscall
void SceModulemgrForKernel_B427025E(int syscall_id, const void *func){

	int dacr;

	if (syscall_id >= 0x1000)
		return;

	asm volatile ("mrc p15, 0, %0, c3, c0, 0" : "=r" (dacr));
	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (0x17450000));

	*(uint32_t *)((*(uint32_t *)(SceKernelModulemgr_data + 0x334)) + (syscall_id << 0x2)) = (uint32_t)func;

	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (dacr));

	return;
}

// non export
void ksceKernelUnregisterSyscall(int syscall_id){

	int dacr;

	if (syscall_id >= 0x1000)
		return;

	asm volatile ("mrc p15, 0, %0, c3, c0, 0" : "=r" (dacr));
	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (0x17450000));

	*(uint32_t *)((*(uint32_t *)(SceKernelModulemgr_data + 0x334)) + (syscall_id << 0x2)) = (uint32_t)&syscall_stub;

	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (dacr));

	return;
}

int ksceKernelGetModuleInternal(SceUID modid, void **module){

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

int ksceKernelGetModuleInfo(SceUID pid, SceUID modid, SceKernelModuleInfo *info){
	if(pid == 0){
		pid = ksceKernelGetProcessId();
	}

	return func_0x81007790(pid, modid, (SceKernelModuleInfo_fix_t *)info);
}

// sceKernelFinalizeKblForKernel
int SceModulemgrForKernel_FDD7F646(void){

	SceUID modid;
	modid = *(uint32_t *)(*(uint32_t *)(SceKernelModulemgr_data + 0x38) + 0xA8);
	if(modid <= 0){
		return 0;
	}

	return module_stop_unload_for_pid(0x10005, modid, 0, 0, 0, 0, 0);
}

SceUID ksceKernelLoadModuleForPid(SceUID pid, const char *path, int flags, SceKernelLMOption *option){

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

int ksceKernelStartModuleForPid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){

	if(pid == 0)
		return 0x8002D017;

	if(flags != 0)
		return 0x8002000A;

	return module_start_for_pid(pid, modid, args, argp, flags, option, status);
}

int ksceKernelUnloadModuleForPid(SceUID pid, SceUID modid, int flags, SceKernelULMOption *option){

	if(pid == 0)
		return 0x8002D017;

	if((flags & ~0x40000000) != 0)
		return 0x8002000A;

	return module_unload_for_pid(pid, modid, flags, option);
}

int ksceKernelStopModuleForPid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){

	if(pid == 0)
		return 0x8002D017;

	if(flags != 0)
		return 0x8002000A;

	return module_stop_for_pid(pid, modid, args, argp, flags, option, status);
}

int ksceKernelMountBootfs(const char *bootImagePath){

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

int ksceKernelUmountBootfs(void){

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







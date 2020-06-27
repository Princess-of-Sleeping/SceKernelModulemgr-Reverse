/*
 * PS Vita kernel module manager import defs header
 * Copyright (C) 2020, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULE_MGR_IMPORT_H_
#define _PSP2_KERNEL_MODULE_MGR_IMPORT_H_

#include <psp2kern/kernel/sysmem.h>

int __stack_chk_fail();

SceUID ksceIoOpenForPid(SceUID pid, const char *path, int flags, int mode);

int ksceKernelGetSystemTimeLow(void);
int ksceKernelSetPermission(int value);		// return value is previous value
SceUID ksceKernelSetProcessId(SceUID pid);	// return value is previous value

int ksceKernelCheckDipsw(int bit);
int ksceMt19937GlobalUninit(void *a1, int a2);
int ksceSblQafMgrIsAllowHost0Access(void);
SceUID ksceKernelSysrootGetShellPid(void);
int ksceKernelSysrootDbgpSuspendProcessAndWaitResume(SceUID pid, SceUID modid, int flags, int *a4, uint64_t time);

// SceSysmem
SceClass *ksceKernelGetClassForUid(SceUID uid, SceClass **cls);
int ksceKernelStrnlenUser(uintptr_t path, SceSize len);


int sceKernelEnqueueWorkQueueForDriver(SceUID tid, const char *name, void *some_func, void *some_data);
int SceThreadmgrForDriver_20C228E4(void);
void *SceThreadmgrForDriver_3A72C6D8(int a1);



int ksceKernelAllocSyscallTable(SceSize len, void *ptr_dst);



void *sceKernelAllocRemoteProcessHeapForDriver(SceUID pid, int size, void *pOpt);
void sceKernelFreeRemoteProcessHeapForDriver(SceUID pid, void *ptr);
void *sceKernelGetProcessClassForKernel(void);
int SceProcessmgrForKernel_0A5A2CF1(SceUID pid, int a2);
int SceProcessmgrForKernel_41815DF2(SceUID pid, void *a2);
int SceProcessmgrForKernel_B75FB970(SceUID pid);
int SceProcessmgrForDriver_D141C076(SceUID uid, void *a2);
void *SceProcessmgrForKernel_C1C91BB2(SceUID pid);



void *ksceKernelAlloc(int size);
int ksceKernelFree(void *ptr);
int _ksceKernelCreateUidObj(SceClass *class, const char *name, SceCreateUidObjOpt *opt, SceObjectBase **obj_base);

int SceQafMgrForDriver_382C71E8(void);

int SceKernelSuspendForDriver_4DF40893(int a1);
int SceKernelSuspendForDriver_2BB92967(int a1);

void *_ksceKernelSysrootGetModulePrivate(int idx);
int SceSysrootForKernel_20D2A0DF(SceUID pid, SceUID modid, uint64_t time);
int SceSysrootForKernel_AA8D34EE(SceUID pid, SceUID modid, uint64_t time);
int SceSysrootForKernel_CA497324(SceUID pid, SceUID modid, uint64_t time);
int SceSysrootForKernel_C81B7E2B(SceUID pid, SceUID modid, uint64_t time);
int SceSysrootForKernel_73522F65(SceUID pid, int *some_flag);
int SceSysrootForKernel_6050A467(SceUID pid);
void SceSysrootForDriver_6E0BC27C(void);

int ksceKernelSysrootGetSystemSwVersion(void);

#endif /* _PSP2_KERNEL_MODULE_MGR_IMPORT_H_ */

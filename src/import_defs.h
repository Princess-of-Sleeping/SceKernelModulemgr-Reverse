/*
 * PS Vita kernel module manager import defs header
 * Copyright (C) 2020, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULE_MGR_IMPORT_H_
#define _PSP2_KERNEL_MODULE_MGR_IMPORT_H_

#include <psp2kern/kernel/sysmem.h>
#include "modulemgr_internal.h"

typedef struct SceSelfAuthInfo { // size is 0x90
	SceUInt64 program_authority_id;
	SceUInt64 padding1;
	char capability[0x20];
	char attributes[0x20];
	uint8_t padding2[0x10];
	uint8_t klicensee[0x10]; // offset 0x60
	uint32_t unk_70;
	uint32_t unk_74;
	uint32_t unk_78;
	uint32_t unk_7C;
	uint32_t unk_80;
	uint32_t unk_84;
	uint32_t unk_88;
	uint32_t unk_8C;
} SceSelfAuthInfo;

typedef struct SceSblSmCommContext130 { // size is 0x130 as its name indicates.
	uint32_t unk_0;
	uint32_t self_type;                    // kernel : 0 / user : 1 / main process : 0x10001

	// offset:0x8
	SceSelfAuthInfo self_auth_info_caller; // size is 0x90 - can be obtained with sceKernelGetSelfAuthInfoForKernel

	// offset:0x98
	SceSelfAuthInfo self_auth_info_called; // size is 0x90

	// 0x128
	uint32_t path_id;                      // can be obtained with sceSblACMgrGetPathIdForKernel or sceIoGetPathIdExForDriver
	uint32_t unk_12C;
} SceSblSmCommContext130;

int ksceIoGetMediaType(SceUID pid, const char *path, int ignored, int *media_type);
SceUID ksceIoOpenForPid(SceUID pid, const char *path, int flags, int mode);

int ksceMt19937GlobalUninit(void *a1, int a2);
int ksceSblQafMgrIsAllowHost0Access(void);
SceUID ksceKernelSysrootGetShellPid(void);
int ksceKernelSysrootDbgpSuspendProcessAndWaitResume(SceUID pid, SceUID modid, int flags, uint64_t time);

// SceSysmem
SceClass *ksceKernelGetClassForUid(SceUID uid, SceClass **cls);
int ksceKernelStrnlenUser(uintptr_t path, SceSize len);


int sceKernelEnqueueWorkQueueForDriver(SceUID tid, const char *name, const void *func, void *argp);
int SceThreadmgrForDriver_20C228E4(void);
void *SceThreadmgrForDriver_3A72C6D8(int a1);



int ksceKernelAllocSyscallTable(SceSize len, void *ptr_dst);


int sceKernelGetProcessBudgetTypeForKernel(SceUID pid);

int ksceKernelGetProcessAuthid(SceUID pid, uint64_t *pAuthid);

void *sceKernelAllocRemoteProcessHeapForDriver(SceUID pid, int size, void *pOpt);
void sceKernelFreeRemoteProcessHeapForDriver(SceUID pid, void *ptr);
void *sceKernelGetProcessClassForKernel(void);

/*
 * sceKernelProcessModuleInc
 *
 * a2 - if one, max 0x20 count increments, else max 0x7F count increments
 */
int sceKernelProcessModuleIncForKernel(SceUID pid, int a2);

/*
 * sceKernelProcessModuleDec
 *
 * a2 - if one, max 0x20 count decrements, else max 0x7F count decrements
 */
int sceKernelProcessModuleDecForKernel(SceUID pid, int a2);

void *sceKernelProcessAllocKernelBudgetHeapMemoryForKernel(SceUID pid, SceSize len);
int sceKernelFreeRemoteProcessKernelHeapForKernel(SceUID pid, void *ptr);
SceKernelProcessModuleInfo *sceKernelGetProcessModuleInfoForKernel(SceUID pid);

int sceKernelGetCompiledSdkVersionByPidForDriver(SceUID pid, unsigned int *pVersion);


int _ksceKernelCreateUidObj(SceClass *class, const char *name, SceCreateUidObjOpt *opt, SceObjectBase **obj_base);

int ksceKernelSetObjectForUid(SceUID uid, const char *name);

int SceQafMgrForDriver_B9770A13(void);
int sceSblQafMgrIsAllowKernelDebugForDriver(void);

int SceKernelSuspendForDriver_4DF40893(int a1);
int SceKernelSuspendForDriver_2BB92967(int a1);

void *_ksceKernelSysrootGetModulePrivate(int idx);

// SceSysrootProcessHandler
int SceSysrootForKernel_20D2A0DF(SceUID pid, SceUID modid, uint64_t time);
int SceSysrootForKernel_C81B7E2B(SceUID pid, SceUID modid, uint64_t time);

// SceSysrootDbgpHandler
int SceSysrootForKernel_AA8D34EE(SceUID pid, SceUID modid, uint64_t time);
int SceSysrootForKernel_CA497324(SceUID pid, SceUID modid, uint64_t time);
int SceSysrootForKernel_73522F65(SceUID pid, int *some_flag);
int SceSysrootForKernel_6050A467(SceUID pid);

// set state 2 to thread some storage
void SceSysrootForDriver_6E0BC27C(void);

int ksceKernelSysrootGetSystemSwVersion(void);

#endif /* _PSP2_KERNEL_MODULE_MGR_IMPORT_H_ */

/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULEMGR_FOR_KERNEL_H_
#define _PSP2_KERNEL_MODULEMGR_FOR_KERNEL_H_

#include "modulemgr_types.h"
#include "modulemgr_internal.h"

int sceKernelLoadProcessImageForKernel(int a1, int a2, int a3, int a4, int a5, int a6);
int sceKernelLoadPreloadingModulesForKernel(SceUID pid, void *unk_buf, int flags);
int sceKernelStartPreloadingModulesForKernel(SceUID pid);
int sceKernelStopUnloadProcessModulesForKernel(SceUID pid);

void sceKernelRegisterSyscallForKernel(int syscall_id, const void *func);

int sceKernelFinalizeKblForKernel(void);

SceUID sceKernelLoadModuleForPidForKernel(SceUID pid, const char *path, int flags, SceKernelLMOption *option);
int sceKernelStartModuleForPidForKernel(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);

int sceKernelStopModuleForPidForKernel(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);
int sceKernelUnloadModuleForPidForKernel(SceUID pid, SceUID modid, int flags, SceKernelULMOption *option);

int sceKernelMountBootfsForKernel(const char *bootImagePath);
int sceKernelUmountBootfsForKernel(void);

void sceKernelSetupForModulemgrForKernel(void);

int sceKernelGetModuleNIDForKernel(SceUID modid, uint32_t *module_nid);
int sceKernelGetModulePathForKernel(SceUID modid, char *path, int pathlen);
SceKernelModuleEntry sceKernelGetModuleEntryPointForKernel(SceUID modid);
int sceKernelGetModuleEntryPointForUserForKernel(SceUID pid, SceUID UserUid, SceKernelModuleEntry *start, SceKernelModuleEntry *stop);

int sceKernelGetModuleIdByAddrForKernel(SceUID pid, const void *module_addr);

int sceKernelGetModuleInfoForKernel(SceUID pid, SceUID modid, SceKernelModuleInfo *info);

int sceKernelGetModuleLibraryInfoForKernel(SceUID pid, SceUID libid, SceKernelModuleLibraryInfo *info);

int sceKernelGetModuleInfoMinByAddrForKernel(
	SceUID pid,
	const void *module_addr,
	uint32_t *module_nid,
	const void **program_text_addr,
	SceKernelModuleName_fix *module_name);
int sceKernelGetModuleInternalForKernel(SceUID modid, SceKernelModuleInfoObjBase_t **info);
int sceKernelGetModuleInternalByAddrForKernel(SceUID pid, const void *module_addr, SceKernelModuleInfoObjBase_t **info);

int sceKernelGetModuleLibExportListForKernel(SceUID pid, SceUID libid, SceKernelModuleExportEntry *list, SceSize *num, SceSize cpy_skip_num);
int sceKernelGetModuleListForKernel(SceUID pid, int flags1, int flags2, SceUID *modids, size_t *num);
int sceKernelGetModuleList2ForKernel(SceUID pid, SceKernelModuleListInfo *infolists, size_t *num);
int sceKernelGetModuleUidForKernel(SceUID pid, SceUID libid, SceUID *dst, SceSize *num, SceSize cpy_skip_num);
int sceKernelGetModuleUidListForKernel(SceUID pid, SceUID *modids, size_t *num);

int sceKernelGetModuleInhibitStateForKernel(SceUID pid, int *a2);

int sceKernelGetModuleNonlinkedImportInfoForKernel(SceUID pid, SceKernelModuleImportNID *a2, SceSize *num);

SceUID sceKernelGetProcessMainModuleForKernel(SceUID pid);

int sceKernelLoadPtLoadSegForFwloaderForKernel(const char *path, int e_phnum, void *buffer, uint32_t bufsize, int zero_unk, uint32_t *bytes_read);

int sceKernelGetModuleImportNonlinkedInfoByNIDForKernel(SceUID pid, SceUID modid, uint32_t libnid, SceKernelModuleImportNonlinkedInfo *info);

int sceKernelGetModuleIsSharedByAddrForKernel(SceUID pid, const void *module_addr);
int sceKernelGetModuleLibStubIdListForKernel(SceUID pid, SceUID *stubid, SceSize *num);
int sceKernelGetModuleLibraryIdListForKernel(SceUID pid, SceUID modid, SceUID *libid, SceSize *num);
int sceKernelGetModuleKernelExportListForKernel(SceModuleLibraryExportInfo_t **list, SceSize *num);

int sceKernelModuleUnloadMySelfForKernel(void);

int SceModulemgrForKernel_29CB2771(SceUID pid);
int SceModulemgrForKernel_2DD3B511(SceUID pid, int a2, int a3, int a4);
int SceModulemgrForKernel_4865C72C(int a1, int a2);
int SceModulemgrForKernel_60E176C8(int a1);

int SceModulemgrForKernel_9D20C9BB(int a1);
int SceModulemgrForKernel_B73BE671(int a1, int a2, int a3);
void SceModulemgrForKernel_F3CD647F(int a1, int a2);
int SceModulemgrForKernel_F95D09C2(const char *path, void *a2, void *a3);
int SceModulemgrForKernel_FB251B7A(SceUID pid, SceUID a2, int a3, int a4, int a5);

int SceModulemgrForKernel_FF2264BB(SceUID a1, int a2, int a3, int a4);

#endif /* _PSP2_KERNEL_MODULEMGR_FOR_KERNEL_H_ */

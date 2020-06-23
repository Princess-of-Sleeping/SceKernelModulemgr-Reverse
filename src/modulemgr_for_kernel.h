/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULEMGR_FOR_KERNEL_H_
#define _PSP2_KERNEL_MODULEMGR_FOR_KERNEL_H_

#include "modulemgr_types.h"
#include "modulemgr_internal.h"

/*
 * Module load, start, stop, unload
 */
int sceKernelLoadProcessImageForKernel(int a1, int a2, int a3, int a4, int a5, int a6);
int sceKernelLoadPreloadingModulesForKernel(SceUID pid, void *unk_buf, int flags);
int sceKernelStartPreloadingModulesForKernel(SceUID pid);
int sceKernelStopUnloadProcessModulesForKernel(SceUID pid);

SceUID sceKernelLoadModuleForPidForKernel(SceUID pid, const char *path, int flags, SceKernelLMOption *option);
int sceKernelStartModuleForPidForKernel(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);

int sceKernelStopModuleForPidForKernel(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);
int sceKernelUnloadModuleForPidForKernel(SceUID pid, SceUID modid, int flags, SceKernelULMOption *option);

int sceKernelModuleUnloadMySelfForKernel(void);

int sceKernelMountBootfsForKernel(const char *bootImagePath);
int sceKernelUmountBootfsForKernel(void);

int sceKernelLoadPtLoadSegForFwloaderForKernel(const char *path, int e_phnum, void *buffer, uint32_t bufsize, int zero_unk, uint32_t *bytes_read);

/*
 * Syscall
 */
void sceKernelRegisterSyscallForKernel(int syscall_id, const void *func);

/*
 * Init
 */
int sceKernelFinalizeKblForKernel(void);

void sceKernelSetupForModulemgrForKernel(void);

/*
 * get list
 */
int sceKernelGetModuleLibExportListForKernel(SceUID pid, SceUID libid, SceKernelModuleExportEntry *list, SceSize *num, SceSize cpy_skip_num);

int sceKernelGetModuleImportListForKernel(SceUID pid, SceUID modid, SceUID *libids, SceSize *num);

int sceKernelGetModuleNonlinkedListForKernel(SceUID pid, SceUID modid, SceKernelModuleNonlinkedInfo *pList, SceSize *num);
int sceKernelGetModuleKernelExportListForKernel(SceModuleLibraryExportInfo_t **list, SceSize *num);
int sceKernelGetModuleLibStubIdListForKernel(SceUID pid, SceUID *stubid, SceSize *num);
int sceKernelGetModuleLibraryIdListForKernel(SceUID pid, SceUID modid, SceUID *libid, SceSize *num);

int sceKernelGetModuleListForKernel(SceUID pid, int flags1, int flags2, SceUID *modids, size_t *num);
int sceKernelGetModuleList2ForKernel(SceUID pid, SceKernelModuleListInfo *infolists, size_t *num);

int sceKernelGetModuleListByImportForKernel(SceUID pid, SceUID libid, SceUID *modids, SceSize *num, SceSize cpy_skip_num);
int sceKernelGetModuleExportLibraryListForKernel(SceUID pid, SceUID *libids, SceSize *num);

/*
 * get info(Big structure)
 */
int sceKernelGetModuleInfoForKernel(SceUID pid, SceUID modid, SceKernelModuleInfo *info);
int sceKernelGetModuleInfoMinByAddrForKernel(SceUID pid, const void *module_addr, uint32_t *module_nid, const void **program_text_addr, SceKernelModuleName_fix *module_name);

int sceKernelGetModuleLibraryInfoForKernel(SceUID pid, SceUID libid, SceKernelModuleLibraryInfo *info);

int sceKernelGetModuleNonlinkedImportInfoForKernel(SceUID pid, SceKernelModuleImportNID *a2, SceSize *num);
int sceKernelGetModuleImportNonlinkedInfoByNIDForKernel(SceUID pid, SceUID modid, uint32_t libnid, SceKernelModuleImportNonlinkedInfo *info);

/*
 * get info
 */
int sceKernelGetModuleAppInfoForKernel(const char *path, uint64_t *pAuthid, SceSelfAppInfo *pInfo);

int sceKernelGetModuleInternalForKernel(SceUID modid, SceKernelModuleInfoObjBase_t **info);
int sceKernelGetModuleInternalByAddrForKernel(SceUID pid, const void *module_addr, SceKernelModuleInfoObjBase_t **info);

int sceKernelGetModuleNIDForKernel(SceUID modid, uint32_t *module_nid);
int sceKernelGetModulePathForKernel(SceUID modid, char *path, int pathlen);
int sceKernelGetModuleEntryPointForUserForKernel(SceUID pid, SceUID UserUid, SceKernelModuleEntry *start, SceKernelModuleEntry *stop);

int sceKernelGetModuleInhibitStateForKernel(SceUID pid, int *a2);
int sceKernelGetModuleIsSharedByAddrForKernel(SceUID pid, const void *module_addr);
SceUID sceKernelGetProcessMainModuleForKernel(SceUID pid);
SceUID sceKernelGetModuleIdByAddrForKernel(SceUID pid, const void *module_addr);

SceKernelModuleEntry sceKernelGetModuleEntryPointForKernel(SceUID modid);

/*
 * unknown
 */
int SceModulemgrForKernel_29CB2771(SceUID pid);
int SceModulemgrForKernel_4865C72C(int a1, int a2);
int SceModulemgrForKernel_60E176C8(int a1);

int SceModulemgrForKernel_9D20C9BB(int a1);
int SceModulemgrForKernel_B73BE671(int a1, int a2, int a3);
void SceModulemgrForKernel_F3CD647F(int a1, int a2);
int SceModulemgrForKernel_FB251B7A(SceUID pid, SceUID a2, int a3, int a4, int a5);

#endif /* _PSP2_KERNEL_MODULEMGR_FOR_KERNEL_H_ */

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
SceUID sceKernelLoadProcessImageForKernel(SceUID pid, const char *path, int a3, void *auth_info, SceLoadProcessParam *pParam, int a6);
int sceKernelStopUnloadProcessModulesForKernel(SceUID pid);

SceUID sceKernelLoadModuleForPidForKernel(SceUID pid, const char *path, int flags, SceKernelLMOption *option);
int sceKernelStartModuleForPidForKernel(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);

int sceKernelStopModuleForPidForKernel(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);
int sceKernelUnloadModuleForPidForKernel(SceUID pid, SceUID modid, int flags, SceKernelULMOption *option);

int sceKernelModuleUnloadMySelfForKernel(void);

int sceKernelMountBootfsForKernel(const char *bootImagePath);
int sceKernelUmountBootfsForKernel(void);

int sceKernelLoadPtLoadSegForFwloaderForKernel(const char *path, int e_phnum, void *buffer, SceSize bufsize, int zero_unk, SceSize *bytes_read);

/*
 * Init
 */
int sceKernelFinalizeKblForKernel(void);

void sceKernelSetupForModulemgrForKernel(void);

// register module debug cb
int SceModulemgrForKernel_60E176C8(int a1);
int SceModulemgrForKernel_9D20C9BB(int a1);

/*
 * get list
 */
int sceKernelGetModuleNonlinkedListForKernel(SceUID pid, SceUID modid, SceKernelModuleNonlinkedInfo *pList, SceSize *num);
int sceKernelGetModuleKernelExportListForKernel(SceModuleLibraryInfo **list, SceSize *num);

int sceKernelGetProcessLibStubIdListForKernel(SceUID pid, SceUID *libstub_ids, SceSize *num);
int sceKernelGetProcessLibraryIdListForKernel(SceUID pid, SceUID *library_ids, SceSize *num);

int sceKernelGetModuleImportListForKernel(SceUID pid, SceUID modid, SceUID *library_ids, SceSize *num);
int sceKernelGetModuleExportListForKernel(SceUID pid, SceUID modid, SceUID *library_ids, SceSize *num);

int sceKernelGetModuleListByImportForKernel(SceUID pid, SceUID library_id, SceUID *modids, SceSize *num, SceSize cpy_skip_num);

int sceKernelGetModuleLibExportListForKernel(SceUID pid, SceUID libid, SceKernelModuleExportEntry *list, SceSize *num, SceSize cpy_skip_num);

int sceKernelGetModuleListForKernel(SceUID pid, int flags1, int flags2, SceUID *modids, size_t *num);
int sceKernelGetModuleList2ForKernel(SceUID pid, SceKernelModuleListInfo *infolists, size_t *num);

// a3 size is 8 * num
int SceModulemgrForKernel_FB251B7A(SceUID pid, SceUID libstub_id, void *a3, SceSize *num, SceSize cpy_skip_num);

/*
 * get info(Big structure)
 */
int sceKernelGetModuleInfoForKernel(SceUID pid, SceUID modid, SceKernelModuleInfo *info);
int sceKernelGetModuleInfoMinByAddrForKernel(SceUID pid, const void *module_addr, uint32_t *pFingerprint, const void **program_text_addr, SceKernelModuleName_fix *module_name);

int sceKernelGetModuleLibraryInfoForKernel(SceUID pid, SceUID library_id, SceKernelModuleLibraryInfo *info);

// a3 size is 0x128
int SceModulemgrForKernel_B73BE671(SceUID pid, SceUID libstub_id, void *a3);

int sceKernelGetModuleNonlinkedImportInfoForKernel(SceUID pid, SceKernelModuleImportNID *a2, SceSize *num);
int sceKernelGetModuleImportNonlinkedInfoByNIDForKernel(SceUID pid, SceUID modid, uint32_t libnid, SceKernelModuleImportNonlinkedInfo *info);

/*
 * get info
 */
int sceKernelGetModuleAppInfoForKernel(const char *path, uint64_t *pAuthid, SceSelfAppInfo *pInfo);

int sceKernelGetModuleInternalForKernel(SceUID modid, SceModuleInfoInternal **info);
int sceKernelGetModuleInternalByAddrForKernel(SceUID pid, const void *module_addr, SceModuleInfoInternal **info);

int sceKernelGetModuleFingerprintForKernel(SceUID modid, uint32_t *pFingerprint);
int sceKernelGetModulePathForKernel(SceUID modid, char *path, SceSize pathlen);
int sceKernelGetModuleEntryPointForUserForKernel(SceUID pid, SceUID UserUid, SceKernelModuleEntry *start, SceKernelModuleEntry *stop);

int sceKernelGetModuleInhibitStateForKernel(SceUID pid, int *a2);
int sceKernelGetModuleIsSharedByAddrForKernel(SceUID pid, const void *module_addr);
SceUID sceKernelGetProcessMainModuleForKernel(SceUID pid);
SceUID sceKernelGetModuleIdByAddrForKernel(SceUID pid, const void *module_addr);

SceKernelModuleEntry sceKernelGetModuleEntryPointForKernel(SceUID modid);

/*
 * unknown
 */
// Related to process switch?
int SceModulemgrForKernel_29CB2771(SceUID pid);

// Related to non-linked?
int SceModulemgrForKernel_4865C72C(SceUID pid, const char *libname);

// set two param
void SceModulemgrForKernel_F3CD647F(int a1, int a2);

#endif /* _PSP2_KERNEL_MODULEMGR_FOR_KERNEL_H_ */

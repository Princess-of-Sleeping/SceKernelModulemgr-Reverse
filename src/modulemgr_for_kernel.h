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
int SceModulemgrForKernel_78DBC027(SceUID pid, SceUID UserUid, uint32_t *a3, uint32_t *a4);
void *SceModulemgrForKernel_66606301(SceUID modid);

int sceKernelGetModuleIdByAddrForKernel(SceUID pid, const void *module_addr);

int sceKernelGetModuleInfoForKernel(SceUID pid, SceUID modid, SceKernelModuleInfo *info);
int sceKernelGetModuleInfo2ForKernel(SceUID pid, SceUID modid, SceKernelModuleInfo2_fix *info);
int sceKernelGetModuleInfoMinByAddrForKernel(
	SceUID pid,
	const void *module_addr,
	uint32_t *module_nid,
	const void **program_text_addr,
	SceKernelModuleName_fix *module_name);
int sceKernelGetModuleInternalForKernel(SceUID modid, SceKernelModuleInfoObjBase_t **info);

int sceKernelGetModuleLibraryInfoForKernel(SceUID pid, SceUID modid, void *unk1, const void *unk2, int unk3);
int sceKernelGetModuleListForKernel(SceUID pid, int flags1, int flags2, SceUID *modids, size_t *num);
int sceKernelGetModuleList2ForKernel(SceUID pid, SceKernelModuleListInfo *infolists, size_t *num);
int sceKernelGetModuleUidForKernel(SceUID pid, SceUID modid, SceUID *modid_out, const void *unk1, int unk2);
int sceKernelGetModuleUidListForKernel(SceUID pid, SceUID *modids, size_t *num);

int SceModulemgrForKernel_2C2618D9(SceUID pid, const void *module_addr, int *dst);

int SceModulemgrForKernel_1BDE2ED2(SceUID pid, SceKernelModuleImportNID *a2, SceSize *num);

SceUID sceKernelGetProcessMainModuleForKernel(SceUID pid);

int sceKernelLoadPtLoadSegForFwloaderForKernel(const char *path, int e_phnum, void *buffer, uint32_t bufsize, int zero_unk, uint32_t *bytes_read);



int SceModulemgrForKernel_2A69385E(void);

int SceModulemgrForKernel_FF2264BB(SceUID a1, int a2, int a3, int a4);

int SceModulemgrForKernel_99890202(SceUID pid, const void *module_addr);

int SceModulemgrForKernel_F95D09C2(const char *path, void *a2, void *a3);

int SceModulemgrForKernel_1D341231(SceUID pid, void *a2, int *num);

int SceModulemgrForKernel_29CB2771(SceUID pid);

int SceModulemgrForKernel_2DD3B511(SceUID pid, int a2, int a3, int a4);

int SceModulemgrForKernel_4865C72C(int a1, int a2);

int SceModulemgrForKernel_619925F1(SceUID pid, int a2, int a3, int a4);

int SceModulemgrForKernel_7A1E882D(SceUID pid, int *a2);

int SceModulemgrForKernel_8D1AA624(void *a1, void *a2);

int SceModulemgrForKernel_952535A3(SceUID a1, int a2, int a3, int a4);

int SceModulemgrForKernel_60E176C8(int a1);

int SceModulemgrForKernel_9D20C9BB(int a1);

int SceModulemgrForKernel_B73BE671(int a1, int a2, int a3);

void SceModulemgrForKernel_F3CD647F(int a1, int a2);

int SceModulemgrForKernel_FB251B7A(SceUID pid, SceUID a2, int a3, int a4, int a5);

#endif /* _PSP2_KERNEL_MODULEMGR_FOR_KERNEL_H_ */

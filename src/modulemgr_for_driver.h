#ifndef _PSP2_KERNEL_MODULEMGR_FOR_DRIVER_H_
#define _PSP2_KERNEL_MODULEMGR_FOR_DRIVER_H_

#include <psp2kern/types.h>

SceUID sceKernelSearchModuleByNameForDriver(const char *module_name);

// ksceKernelGetModuleInfoByAddr
int SceModulemgrForDriver_1D9E0F7E(const void *addr, SceKernelModuleInfo *info);

int sceKernelRegisterLibaryForDriver(const void *module_addr);
int sceKernelReleaseLibaryForDriver(const void *module_addr);

SceUID sceKernelSearchModuleByNameForDriver(const char *module_name);

int sceKernelGetSystemSwVersionForDriver(SceKernelFwInfo *data);

SceUID ksceKernelLoadModule(const char *path, int flags, SceKernelLMOption *option);
int ksceKernelStartModule(SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);
SceUID ksceKernelLoadStartModule(const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);

int ksceKernelUnloadModule(SceUID modid, int flags, SceKernelULMOption *option);
int ksceKernelStopModule(SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);
int ksceKernelStopUnloadModule(SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);

SceUID ksceKernelLoadStartModuleForPid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);
int ksceKernelStopUnloadModuleForPid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);

SceUID ksceKernelLoadStartSharedModuleForPid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);
int ksceKernelStopUnloadSharedModuleForPid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);



#endif /* _PSP2_KERNEL_MODULEMGR_FOR_DRIVER_H_ */

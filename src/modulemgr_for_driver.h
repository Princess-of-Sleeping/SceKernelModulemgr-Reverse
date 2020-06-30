/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULEMGR_FOR_DRIVER_H_
#define _PSP2_KERNEL_MODULEMGR_FOR_DRIVER_H_

#include <psp2kern/types.h>

SceUID sceKernelSearchModuleByNameForDriver(const char *module_name);

int sceKernelGetModuleInfoByAddrForDriver(const void *addr, SceKernelModuleInfo *info);

int sceKernelRegisterLibaryForDriver(const void *module_addr);
int sceKernelReleaseLibaryForDriver(const void *module_addr);

SceUID sceKernelSearchModuleByNameForDriver(const char *module_name);

int sceKernelGetSystemSwVersionForDriver(SceKernelFwInfo *data);

SceUID sceKernelLoadModuleForDriver(const char *path, int flags, SceKernelLMOption *option);
int sceKernelStartModuleForDriver(SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);
SceUID sceKernelLoadStartModuleForDriver(const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);

int sceKernelUnloadModuleForDriver(SceUID modid, int flags, SceKernelULMOption *option);
int sceKernelStopModuleForDriver(SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);
int sceKernelStopUnloadModuleForDriver(SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);

SceUID sceKernelLoadStartModuleForPidForDriver(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);
int sceKernelStopUnloadModuleForPidForDriver(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);

SceUID sceKernelLoadStartSharedModuleForPidForDriver(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);
int sceKernelStopUnloadSharedModuleForPidForDriver(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);

#endif /* _PSP2_KERNEL_MODULEMGR_FOR_DRIVER_H_ */

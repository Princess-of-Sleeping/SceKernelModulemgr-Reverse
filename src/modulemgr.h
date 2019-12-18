/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#ifndef _PSP2_MODULEMGR_H_
#define _PSP2_MODULEMGR_H_

#include "modulemgr_types.h"

SceUID _sceKernelOpenModule(const char *path, SceSize args, void *argp, SceKernelModuleOpen_t *module_open);

int _sceKernelCloseModule(SceUID modid, SceSize args, void *argp, SceKernelModuleClose_t *module_close);

SceUID _sceKernelLoadModule(const char *path, int flags, SceKernelLMOption *option);

int _sceKernelStartModule(SceUID modid, SceSize args, void *argp, SceKernelModuleStart_t *module_start);

SceUID _sceKernelLoadStartModule(const char *path, SceSize args, void *argp, SceKernelModuleLoadStart_t *module_load_start);

int _sceKernelStopModule(SceUID modid, SceSize args, void *argp, SceKernelModuleStop_t *module_stop);

int _sceKernelUnloadModule(SceUID modid, int flags, SceKernelULMOption *option);

int _sceKernelStopUnloadModule(SceUID modid, SceSize args, void *argp, SceKernelModuleStopUnload_t *module_stop_unload);

#endif /* _PSP2_MODULEMGR_H_ */

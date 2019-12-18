/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#include <psp2/types.h>
#include "modulemgr.h"

SceUID sceKernelOpenModule(const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status)
{
	SceKernelModuleOpen_t module_open;

	module_open.flags  = flags;
	module_open.status = status;
	module_open.option = option;

	return _sceKernelOpenModule(path, args, argp, &module_open);
}

int sceKernelCloseModule(SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status)
{
	SceKernelModuleClose_t module_close;

	module_close.flags  = flags;
	module_close.status = status;
	module_close.option = option;

	return _sceKernelCloseModule(modid, args, argp, &module_close);
}

SceUID sceKernelLoadModule(const char *path, int flags, SceKernelLMOption *option)
{
	return _sceKernelLoadModule(path, flags, option);
}

int sceKernelStartModule(SceUID modid, SceSize args, void *argp, int flags, void *option, int *status)
{
	SceKernelModuleStart_t module_start;

	module_start.flags  = flags;
	module_start.status = status;
	module_start.option = option;

	return _sceKernelStartModule(modid, args, argp, &module_start);
}

SceUID sceKernelLoadStartModule(const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status)
{
	SceKernelModuleLoadStart_t module_load_start;

	module_load_start.flags  = flags;
	module_load_start.status = status;
	module_load_start.option = option;

	return _sceKernelLoadStartModule(path, args, argp, &module_load_start);
}

int sceKernelStopModule(SceUID modid, SceSize args, void *argp, int flags, void *option, int *status)
{
	SceKernelModuleStop_t module_stop;

	module_stop.flags  = flags;
	module_stop.status = status;
	module_stop.option = option;

	return _sceKernelStopModule(modid, args, argp, &module_stop);
}

int sceKernelUnloadModule(SceUID modid, int flags, SceKernelULMOption *option)
{
	return _sceKernelUnloadModule(modid, flags, option);
}

int sceKernelStopUnloadModule(SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status)
{
	SceKernelModuleStopUnload_t module_stop_unload;

	module_stop_unload.flags  = flags;
	module_stop_unload.status = status;
	module_stop_unload.option = option;

	return _sceKernelStopUnloadModule(modid, args, argp, &module_stop_unload);
}

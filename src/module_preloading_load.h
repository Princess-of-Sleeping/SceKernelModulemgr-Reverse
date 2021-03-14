/*
 * PS Vita kernel module manager RE Preloading
 * Copyright (C) 2020, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULE_PRELOADING_H_
#define _PSP2_KERNEL_MODULE_PRELOADING_H_

#include "modulemgr_internal.h"

int sceKernelLoadPreloadingModules(SceUID pid, SceLoadProcessParam *pParam, int flags);

#endif /* _PSP2_KERNEL_MODULE_PRELOADING_H_ */

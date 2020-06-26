/*
 * PS Vita kernel module manager RE Search header
 * Copyright (C) 2020, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULE_MGR_SEARCH_H_
#define _PSP2_KERNEL_MODULE_MGR_SEARCH_H_

#include <psp2/types.h>

SceUID search_module_by_name(SceUID pid, const char *module_name);

SceUID sceKernelSearchModuleByNameForDriver(const char *module_name);

#endif /* _PSP2_KERNEL_MODULE_MGR_SEARCH_H_ */

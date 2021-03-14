/*
 * PS Vita kernel module manager RE Utility header
 * Copyright (C) 2020, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULE_MGR_UTILITY_H_
#define _PSP2_KERNEL_MODULE_MGR_UTILITY_H_

#include "modulemgr_internal.h"

SceModuleObject *get_module_object(SceUID modid);

void *alloc_for_process(SceUID pid, SceSize len);
void free_for_process(SceUID pid, void *ptr);

int process_check(SceUID pid);
int process_check_for_user(SceUID pid);

int release_obj(SceUID uid);
int release_obj_for_user(SceUID uid);

int memcpy_to_kernel(SceUID pid, void *dst, const void *src, SceSize len);

SceKernelProcessModuleInfo *getProcModuleInfo(SceUID pid, int *cpu_suspend_intr);
int resume_cpu_intr(SceKernelProcessModuleInfo *pProcModuleInfo, int cpu_suspend_intr);

int set_module_info_path(SceModuleInfoInternal *pModuleInfo, const char *path, int flags);

int is_process_compiled_new_sdk(SceUID pid);

SceModuleSharedInfo *search_shared_info_by_path(const char *path);
int shared_info_decrements(SceModuleSharedInfo *pSharedInfo);

int is_inhibit_shared(SceUID pid);

void update_shared_info_node(SceModuleInfoInternal *pModuleInfo);

int process_lib_is_nonlinked(SceUID pid, const char *libname);

#endif /* _PSP2_KERNEL_MODULE_MGR_UTILITY_H_ */

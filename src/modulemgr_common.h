/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULEMGR_COMMON_H_
#define _PSP2_KERNEL_MODULEMGR_COMMON_H_

#include "modulemgr_types.h"
#include "modulemgr_internal.h"

SceUID module_load_for_pid(SceUID pid, const char *path, int flags, SceKernelLMOption *option);
int module_start_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);
SceUID module_load_start_for_pid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);
int module_stop_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);
int module_unload_for_pid(SceUID pid, SceUID modid, int flags, SceKernelULMOption *option);
int module_stop_unload_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);
SceUID module_load_start_shared_for_pid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);

int syscall_stub();

void func_0x810014a8(void);
void func_0x810014d4(void);
SceModuleObject *get_module_object(SceUID modid);

int release_obj(SceUID uid);
int release_obj_for_user(SceUID uid);

int process_check(SceUID pid);
int process_check_for_user(SceUID pid);

int inhibit_loading_module(uint16_t flag);

int func_0x810040c8(SceKernelProcessModuleInfo *a1);
int func_0x81004198(void *a1, int a2, int a3);			// yet not Reversed
int func_0x8100428c(void *a1, int a2, int a3);			// yet not Reversed

void *alloc_for_process(SceUID pid, SceSize len);
void free_for_process(SceUID pid, void *ptr);

int func_0x810049fc(const char *path);
int func_0x81004a54(SceUID fd);

// int func_0x81005648(SceUID pid, int flags, void *dst);
int func_0x81005648(SceUID pid, int flags, SceModuleObject **dst);
int func_0x81005a70(SceModuleInfoInternal *pInfo, const char *path, int flags);
int get_export_index(SceModuleInfoInternal *pModuleInfo, const void *module_addr);

//int func_0x81006cf4(int a1, int a2, int a3, void *a4);
void *func_0x81006cf4(int a1, void *a2, const void *a3, void *a4);
SceModuleLibraryObject *func_0x81006de8(SceUID pid, SceUID libid);
SceKernelProcessModuleInfo *getProcModuleInfo(SceUID pid, int *cpu_suspend_intr);
int resume_cpu_intr(SceKernelProcessModuleInfo *pProcModuleInfo, int cpu_suspend_intr);
int cleanup_process_module_info(SceUID pid);

int func_0x810070b4(void *a1);
int func_0x81007148(const char *path);
int func_0x810071a8(void *r0);
int get_module_library_info_export(SceUID pid, SceUID modid, uint32_t libnid, SceKernelLibraryInfo *info);
int get_module_info(SceUID pid, SceUID modid, SceKernelModuleInfo_fix_t *info);
int get_module_info_internal_by_addr(SceKernelProcessModuleInfo *module_proc_info, const void *module_addr, SceModuleInfoInternal **dst);

int syacall_init(void);

SceUID get_module_id_by_addr_internal(SceUID pid, const void *module_addr);
SceUID get_module_id_by_addr(SceUID pid, const void *module_addr);
SceUID search_module_by_name(SceUID pid, const char *module_name);

#endif /* _PSP2_KERNEL_MODULEMGR_COMMON_H_ */

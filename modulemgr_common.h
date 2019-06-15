
#ifndef _PSP2_KERNEL_MODULEMGR_COMMON_H_
#define _PSP2_KERNEL_MODULEMGR_COMMON_H_

#include "modulemgr_internal.h"

typedef struct SceKernelLibraryInfo {
	SceSize size;
	uint32_t unk_04;
	uint32_t unk_08;
	uint32_t unk_0C;
	uint32_t unk_10;
	uint32_t unk_14;
	uint32_t unk_18;
} SceKernelLibraryInfo;  // size is 0x1C

SceUID module_load_for_pid(SceUID pid, const char *path, int flags, SceKernelLMOption *option);
int module_start_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);
SceUID module_load_start_for_pid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);
int module_stop_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);
int module_unload_for_pid(SceUID pid, SceUID modid, int flags, SceKernelULMOption *option);
int module_stop_unload_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status);
SceUID module_load_start_shared_for_pid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status);

void func_0x810014a8(void);
void func_0x810014d4(void);
int func_0x81001ec4(SceUID pid);
void *func_0x81001f0c(SceUID modid);

int func_0x810021b8(SceUID pid);
int func_0x810021c0(SceUID pid);
int func_0x810021d8(SceUID pid);

int func_0x81003708(uint16_t flag);

int func_0x81004198(void *a1, int a2, int a3); // yet not Reversed
int func_0x8100428c(void *a1, int a2, int a3); // yet not Reversed
void *func_0x8100498c(SceUID pid, int len);
int func_0x810049fc(const char *path);
int func_0x81004a54(void);

int func_0x81005648(SceUID pid, int flags, void *dst);
int func_0x81005a70(void *r0, const char *path, int flags);
void func_0x81005b04(void *r0); // print module load info
int func_0x81005fec(void *a1, void *a2); // yet not Reversed

int func_0x81006cf4(int a1, int a2, int a3, void *a4);
module_tree_top_t *func_0x81006e60(SceUID pid, int *cpu_suspend_intr);
int func_0x81006e90(module_tree_top_t *module_tree_top, int cpu_suspend_intr);
int func_0x81006e9c(SceUID pid);

int func_0x81007148(const char *path);
int func_0x810071a8(void *r0);
int func_0x810076b0(SceUID pid, SceUID uid, int a2, SceKernelLibraryInfo *info); // yet not Reversed
int func_0x81007790(SceUID pid, SceUID modid, SceKernelModuleInfo_fix_t *info);
int func_0x81007A84(void *a1, const void *a2, void *a3); // yet not Reversed
int func_0x81007bbc(SceUID pid, const void *lr);
int func_0x81007c10(SceUID pid, const void *lr);
SceUID func_0x81007c5c(SceUID pid, const char *module_name);

#endif /* _PSP2_KERNEL_MODULEMGR_COMMON_H_ */

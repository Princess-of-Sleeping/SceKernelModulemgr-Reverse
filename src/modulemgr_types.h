/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#ifndef _PSP2_MODULEMGR_USER_TYPE_H_
#define _PSP2_MODULEMGR_USER_TYPE_H_

#include <psp2kern/kernel/modulemgr.h>

/*
 * flags for sceKernelGetModuleList
 */
#define SCE_KERNEL_MODULE_LIST_FLAG1_GET_NORMAL           0x1
#define SCE_KERNEL_MODULE_LIST_FLAG1_GET_SHARED           0x80

/*
 * flags2 |= SCE_KERNEL_MODULE_LIST_FLAG2_CPY_KERNEL_MODULE_ID; -> cpy kernel modid
 * If this flag is not set, the user modid will be copied
 */
#define SCE_KERNEL_MODULE_LIST_FLAG2_CPY_KERNEL_MODULE_ID 0x1

/*
 * If the modid to be copied is user, whether to copy the modid of the shared module
 */
#define SCE_KERNEL_MODULE_LIST_FLAG2_CPY_SHARED_MODULE_ID 0x2

typedef struct SceSelfAppInfo {
	int vendor_id;
	int self_type;
} SceSelfAppInfo;

typedef struct SceKernelModuleNonlinkedInfo {
	SceUID modid;
	uint32_t libnid;
} SceKernelModuleNonlinkedInfo;

typedef struct SceKernelModuleImportNonlinkedInfo {
	SceSize size; // 0x124
	SceUID modid;
	uint32_t libnid;
	char libname[0x100];
	uint32_t data_0x10C;
	uint32_t data_0x110;
	uint32_t data_0x114;
	uint32_t data_0x118;
	uint32_t data_0x11C;
	uint32_t data_0x120;
} SceKernelModuleImportNonlinkedInfo;

typedef struct {
  SceSize size;   //!< this structure size (0x18)
  SceUInt perms;  //!< probably rwx in low bits
  void *vaddr;    //!< address in memory
  SceSize memsz;  //!< size in memory
  SceSize filesz; //!< original size of memsz
  SceUInt res;    //!< unused
} SceKernelSegmentInfo_fix;

typedef struct {
	SceUInt size;    //!< 0x1B8 for Vita 1.x
	SceUID modid;
	uint16_t attr;
	uint8_t minor;
	uint8_t major;

	// 0xC
	char module_name[0x1C];

	// 0x28
	SceUInt unk28;
	void *module_start;

	// 0x30
	void *module_stop;
	void *module_exit;

	void *exidxTop;
	void *exidxBtm;
	void *extabTop;
	void *extabBtm;

	void *tlsInit;
	SceSize tlsInitSize;
	SceSize tlsAreaSize;
	char path[0x100];
	SceKernelSegmentInfo_fix segments[4];
	SceUInt type;   //!< 6 = user-mode PRX?
} SceKernelModuleInfo_fix_t;

typedef struct {
	SceSize size;
	uint16_t libver[2];
	uint32_t libnid;
	const char *libname;
	uint16_t entry_num_function;
	uint16_t entry_num_variable;
	uint32_t *table_nid;
	void    **table_entry;
} SceKernelLibraryInfo;  // size is 0x1C

typedef struct {
  char s[0x1C];
} SceKernelModuleName_fix;

typedef struct {
	SceUID modid;
	uint32_t libnid;
} SceKernelModuleImportNID;

typedef struct {
	int flags;
	int *status;
	SceKernelLMOption *option;
	int a4; // not used
} SceKernelModuleOpen_t;

typedef struct {
	int flags;
	int *status;
	SceKernelULMOption *option;
	int a4; // not used
} SceKernelModuleClose_t;

typedef struct {
	int flags;
	int *status;
	void *option;
	int a4; // not used
} SceKernelModuleStart_t;

typedef struct {
	int flags;
	int *status;
	SceKernelLMOption *option;
	int a4; // not used
} SceKernelModuleLoadStart_t;

typedef struct {
	int flags;
	int *status;
	void *option;
	int a4; // not used
} SceKernelModuleStop_t;

typedef struct {
	int flags;
	int *status;
	SceKernelULMOption *option;
	int a4; // not used
} SceKernelModuleStopUnload_t;

#endif /* _PSP2_MODULEMGR_USER_TYPE_H_ */

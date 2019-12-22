/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#ifndef _PSP2_MODULEMGR_USER_TYPE_H_
#define _PSP2_MODULEMGR_USER_TYPE_H_

#include <psp2kern/kernel/modulemgr.h>

typedef struct SceKernelModuleExportEntry {
	uint32_t libnid;
	const void *entry; // function ptr. or vars?
} SceKernelModuleExportEntry;

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
	uint32_t *table_entry;
} SceKernelLibraryInfo;  // size is 0x1C

typedef struct SceKernelModuleLibraryInfo {
  SceSize size; //!< sizeof(SceKernelModuleLibraryInfo) : 0x120
  SceUID libid;
  uint32_t libnid;
  uint16_t libver[2];
  uint16_t entry_num_function;
  uint16_t entry_num_variable;
  uint16_t unk_0x14;
  uint16_t unk_0x16;
  char library_name[0x100]; // offset : 0x18
  uint32_t unk_0x118;
  SceUID modid2;
} SceKernelModuleLibraryInfo;

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

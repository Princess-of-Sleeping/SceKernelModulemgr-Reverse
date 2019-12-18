/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#ifndef _PSP2_MODULEMGR_USER_TYPE_H_
#define _PSP2_MODULEMGR_USER_TYPE_H_

#include <psp2kern/kernel/modulemgr.h>

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

typedef struct {
  char s[0x1C];
} SceKernelModuleName_fix;

typedef struct {
	SceUID modid;
	uint32_t libnid;
} SceKernelModuleImportNID;

typedef struct {
  SceSize size; //!< sizeof(SceKernelModuleInfo2) : 0x120
  SceUID modid1;
  uint32_t unk_0x08;
  uint16_t unk_0x0C;
  uint16_t unk_0x0E;
  uint16_t unk_0x10;
  uint16_t unk_0x12;
  uint16_t unk_0x14;
  uint16_t unk_0x16;
  char module_name[0x100]; // offset : 0x18
  uint32_t unk_0x118;
  SceUID modid2;
} SceKernelModuleInfo2_fix;

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

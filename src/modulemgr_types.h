#ifndef _PSP2_MODULEMGR_USER_TYPE_H_
#define _PSP2_MODULEMGR_USER_TYPE_H_

#include <psp2kern/kernel/modulemgr.h>

typedef struct {
  char module_name[0x1C];
} SceKernelModuleName;

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

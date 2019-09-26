#ifndef _PSP2_MODULEMGR_USER_TYPE_H_
#define _PSP2_MODULEMGR_USER_TYPE_H_

#include <psp2kern/kernel/modulemgr.h>

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

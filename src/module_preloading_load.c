/*
 * PS Vita kernel module manager RE Preloading Load
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>

#include "import_defs.h"
#include "modulemgr_types.h"
#include "modulemgr_internal.h"

extern void *SceKernelModulemgr_data;

/*
 * preloading_inhibit_shared / 0x8100801c (checked)
 *
 * @param[in] pid - target process id
 *
 * @return none.
 */
void preloading_inhibit_shared(SceUID pid){

	SceKernelProcessModuleInfo *pProcessModuleInfo = sceKernelGetProcessModuleInfoForKernel(pid);

	pProcessModuleInfo->inhibit_state |= 1;

	if(sceKernelGetProcessBudgetTypeForKernel(pid) == 0x4000000)
		*(uint32_t *)(SceKernelModulemgr_data + 0x314) = 1;

	return;
}

// TODO:add sceKernelLoadPreloadingModules

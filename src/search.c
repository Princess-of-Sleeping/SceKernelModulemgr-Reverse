/*
 * PS Vita kernel module manager RE Search
 * Copyright (C) 2020, Princess of Sleeping
 */

#include <psp2/types.h>
#include <psp2kern/kernel/cpu.h>
#include <string.h>

#include "import_defs.h"
#include "modulemgr_types.h"
#include "modulemgr_internal.h"
#include "modulemgr_common.h"

/*
 * search_module_by_name / 0x81007c5c (checked)
 *
 * @param[in] pid         - target pid
 * @param[in] module_name - target module name
 *
 * @return modid on success, < 0 on error.
 */
SceUID search_module_by_name(SceUID pid, const char *module_name){

	SceUID uid;
	int cpu_suspend_intr;
	SceKernelProcessModuleInfo *pProcModuleInfo;
	SceModuleInfoInternal *pModuleInfo;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_suspend_intr);
	if(pProcModuleInfo == NULL){
		uid = 0x8002d080;
	}else{
		pModuleInfo = pProcModuleInfo->pModuleInfo;
 		while(pModuleInfo != NULL){
			if(strncmp(pModuleInfo->module_name, module_name, 0x1A) == 0){
				uid = pModuleInfo->modid_kernel;
				goto loc_81007c9a;
			}
			pModuleInfo = pModuleInfo->next;
		}
		uid = 0x8002d082;
loc_81007c9a:
		ksceKernelCpuResumeIntr((int *)(&pProcModuleInfo->cpu_addr), cpu_suspend_intr);
	}

	return uid;
}

SceUID sceKernelSearchModuleByNameForDriver(const char *module_name){
	return search_module_by_name(0x10005, module_name);
}

/*
 * PS Vita kernel module manager RE Inhibit Loading
 * Copyright (C) 2020, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/cpu.h>

#include "modulemgr_types.h"
#include "modulemgr_internal.h"
#include "module_utility.h"
#include "modulemgr_common.h"

/*
 * inhibit_loading_module / func_0x81003708
 */
int inhibit_loading_module(uint16_t flag){

	SceKernelProcessModuleInfo *pProcModuleInfo;
	SceUID pid;
	int cpu_suspend_intr;

	if((flag & ~0x30) != 0)
		return 0x80020005;

	pid = ksceKernelGetProcessId();
	if(pid == 0x10005)
		return 0x8002D017;

	pProcModuleInfo = getProcModuleInfo(pid, &cpu_suspend_intr);
	if(pProcModuleInfo == NULL)
		return 0x8002D080;

	if(flag <= (pProcModuleInfo->inhibit_state & 0x30)){
		resume_cpu_intr(pProcModuleInfo, cpu_suspend_intr);
		return 0x80020005;
	}

	pProcModuleInfo->inhibit_state &= ~0x30;
	pProcModuleInfo->inhibit_state |= flag;

	resume_cpu_intr(pProcModuleInfo, (int)cpu_suspend_intr);

	return 0;
}

int sceKernelInhibitLoadingModule(uint16_t flag){

	int res;
	uint32_t state;

	ENTER_SYSCALL(state);
	res = inhibit_loading_module(flag);
	EXIT_SYSCALL(state);

	return res;
}

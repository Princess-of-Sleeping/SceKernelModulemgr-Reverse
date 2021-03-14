/*
 * PS Vita kernel module manager RE LoadModule
 * Copyright (C) 2020, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/threadmgr.h>

#include "modulemgr_types.h"
#include "modulemgr_internal.h"
#include "module_utility.h"
#include "modulemgr_common.h"
#include "module_load.h"

/*
 * module_load_for_pid_as_shared / func_0x8100266C
 */
SceUID module_load_for_pid_as_shared(SceUID pid, const char *path, int flags){

	SceUID res, prev_pid;
	int prev_perm;

	if(pid == 0)
		return 0x8002D017;

	prev_perm = ksceKernelSetPermission(0x80);
	prev_pid  = ksceKernelSetProcessId(0x10005);
	res = module_load_for_pid(pid, path, flags | 1, NULL);
	ksceKernelSetProcessId(prev_pid);
	ksceKernelSetPermission(prev_perm);

	return res;
}

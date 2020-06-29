/*
 * PS Vita kernel module manager RE User
 * Copyright (C) 2020, Princess of Sleeping
 */

#include <psp2/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <string.h>

#include "import_defs.h"
#include "modulemgr_types.h"
#include "modulemgr_internal.h"
#include "module_utility.h"
#include "modulemgr_common.h"

/*
 * cpy_path_from_user / func_0x81009bc4
 */
int cpy_path_from_user(const char *path_for_user, char **dst){

	int res;
	char *path;

	res = ksceKernelStrnlenUser((uintptr_t)path_for_user, 0x400);
	if(res < 0)
		return res;

	if(res >= 0x400)
		return 0x8002D01F;

	path = alloc_for_process(0, res + 1);
	if(path == NULL)
		return 0x8002D008;

	path[res] = 0;

	if(res != 0){
		res = ksceKernelMemcpyUserToKernel(path, (uintptr_t)path_for_user, res);
		if(res < 0){
			free_for_process(0, path);
			goto loc_81009BF4;
		}
	}

	res = 0;
	*dst = path;

loc_81009BF4:
	return res;
}

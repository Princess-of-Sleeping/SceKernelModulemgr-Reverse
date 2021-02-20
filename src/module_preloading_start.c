/*
 * PS Vita kernel module manager RE Preloading Start
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysroot.h>

#include "import_defs.h"
#include "modulemgr_types.h"
#include "modulemgr_internal.h"
#include "modulemgr_common.h"
#include "modulemgr_for_kernel.h"
#include "module_utility.h"

int sceKernelStartPreloadingModulesForKernel(SceUID pid){

	int res = 0;
	size_t modnum = 0xF;
	SceUID modlist[0x10];
	void *pRes;

	res = sceKernelGetModuleListForKernel(pid, 0x80, 1, modlist, &modnum);
	if(res < 0)
		goto label_0x810036A4;

	if(modnum == 0)
		goto label_0x810036A4;

	goto label_0x81003644;

label_0x8100363E:
	if(modnum == 0)
		goto label_0x810036B0;

label_0x81003644:
	modnum -= 1;
	pRes = get_module_object(modlist[modnum]);
	if(pRes == NULL)
		goto label_0x8100363E;

	res = module_start_for_pid(pid, modlist[modnum], 0, 0, (ksceSysrootUseExternalStorage() != 0) ? 0x4000000 : 0, 0, 0);

	ksceKernelUidRelease(modlist[modnum]);

	if(res >= 0)
		goto label_0x8100363E;

	if(ksceSysrootUseExternalStorage() != 0)
		goto label_0x8100363E;

label_0x810036A4:
	return res;

label_0x810036B0:
	res = 0;
	goto label_0x810036A4;
}

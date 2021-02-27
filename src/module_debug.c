/*
 * PS Vita kernel module manager RE Debug
 * Copyright (C) 2020, Princess of Sleeping
 */

#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>

#include "import_defs.h"
#include "modulemgr_types.h"
#include "modulemgr_internal.h"

const SceKernelDebugMessageContext load_param = {
	.hex_value0_hi = 0x6C6D2F8B,
	.hex_value0_lo = 0x6DE580FF,
	.hex_value1    = 0xFFAC508A,
	.func          = NULL,
	.line          = 0,
	.file          = NULL
};

const SceKernelDebugMessageContext load_param_one_seg = {
	.hex_value0_hi = 0x6C6D2F8B,
	.hex_value0_lo = 0x669C9853,
	.hex_value1    = 0xFFAC508A,
	.func          = NULL,
	.line          = 0,
	.file          = NULL
};

/*
 * print_module_load_info / 0x81005b04 (checked)
 */
void print_module_load_info(SceModuleInfoInternal *pModuleInfo){
	if(sceSblQafMgrIsAllowKernelDebugForDriver() != 0){
		if(pModuleInfo->segments_num < 2){
			ksceDebugPrintf2(0, &load_param_one_seg, "[%-27s]:text=%p(0x%08x), (no data)\n",
				pModuleInfo->module_name, pModuleInfo->segments[0].vaddr, pModuleInfo->segments[0].memsz
			);
		}else{
			ksceDebugPrintf2(0, &load_param, "[%-27s]:text=%p(0x%08x), data=%p(0x%08x/0x%08x)\n",
				pModuleInfo->module_name,
				pModuleInfo->segments[0].vaddr, pModuleInfo->segments[0].memsz,
				pModuleInfo->segments[1].vaddr, pModuleInfo->segments[1].filesz, pModuleInfo->segments[1].memsz
			);
		}
	}
}

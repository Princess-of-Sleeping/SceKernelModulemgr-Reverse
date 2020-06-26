/*
 * PS Vita kernel module manager RE Debug
 * Copyright (C) 2020, Princess of Sleeping
 */

#include <psp2/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <string.h>

#include "import_defs.h"
#include "modulemgr_types.h"
#include "modulemgr_internal.h"

const kernel_message_ctx load_param = {
	.hex_value0_hi = 0x6C6D2F8B,
	.hex_value0_lo = 0x6DE580FF,
	.hex_value1    = 0xFFAC508A,
	.msg0          = NULL,
	.num           = 0,
	.msg1          = NULL
};

const kernel_message_ctx load_param_one_seg = {
	.hex_value0_hi = 0x6C6D2F8B,
	.hex_value0_lo = 0x669C9853,
	.hex_value1    = 0xFFAC508A,
	.msg0          = NULL,
	.num           = 0,
	.msg1          = NULL
};

/*
 * print_module_load_info / 0x81005b04 (checked)
 */
void print_module_load_info(SceKernelModuleInfoObjBase_t *pObj){
	if(SceQafMgrForDriver_382C71E8() != 0){
		if(pObj->segments_num < 2){
			ksceDebugPrintf2(0, (kernel_message_ctx *)&load_param_one_seg, "[%-27s]:text=%p(0x%08x), (no data)\n",
				pObj->module_name, pObj->segments[0].vaddr, pObj->segments[0].memsz
			);
		}else{
			ksceDebugPrintf2(0, (kernel_message_ctx *)&load_param, "[%-27s]:text=%p(0x%08x), data=%p(0x%08x/0x%08x)\n",
				pObj->module_name,
				pObj->segments[0].vaddr, pObj->segments[0].memsz,
				pObj->segments[1].vaddr, pObj->segments[1].filesz, pObj->segments[1].memsz
			);
		}
	}
}

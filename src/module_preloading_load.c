/*
 * PS Vita kernel module manager RE Preloading Load
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/types.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/sblacmgr.h>

#include "import_defs.h"
#include "modulemgr_types.h"
#include "modulemgr_internal.h"
#include "modulemgr_common.h"
#include "modulemgr_for_kernel.h"
#include "module_utility.h"
#include "module_load.h"
#include "module_preloading_load.h"

extern void *SceKernelModulemgr_data;

const SceKernelPreloadModuleInfo preloading_list[0xF] = {
	{
		.module_name = NULL,
		.path = {
			"host0:module/libkernel.suprx",
			NULL,
			"os0:us/libkernel.suprx",
			NULL,
			"sd0:us/libkernel.suprx",
			"os0:us/libkernel.suprx",
		},
		.inhibit = 0x0,
		.flags   = 0x32
	},
	{
		.module_name = NULL,
		.path = {
			"host0:module/driver_us.suprx",
			NULL,
			"os0:us/driver_us.suprx",
			NULL,
			"sd0:us/driver_us.suprx",
			"os0:us/driver_us.suprx",
		},
		.inhibit = 0x0,
		.flags   = 0x32
	},
	{
		.module_name = NULL,
		.path = {
			"host0:module/avcodec_us.suprx",
			NULL,
			"os0:us/avcodec_us.suprx",
			NULL,
			"sd0:us/avcodec_us.suprx",
			"os0:us/avcodec_us.suprx",
		},
		.inhibit = 0x0,
		.flags   = 0x32
	},
	{
		.module_name = NULL,
		.path = {
			"host0:module/libgpu_es4.suprx",
			NULL,
			"os0:us/libgpu_es4.suprx",
			NULL,
			"sd0:us/libgpu_es4.suprx",
			"os0:us/libgpu_es4.suprx",
		},
		.inhibit = 0x0,
		.flags   = 0x32
	},
	{
		.module_name = NULL,
		.path = {
			"host0:module/libgxm_es4.suprx",
			NULL,
			"os0:us/libgxm_es4.suprx",
			NULL,
			"sd0:us/libgxm_es4.suprx",
			"os0:us/libgxm_es4.suprx",
		},
		.inhibit = 0x0,
		.flags   = 0x22
	},
	{
		.module_name = NULL,
		.path = {
			"host0:module/libgxm_dbg_es4.suprx",
			NULL,
			"vs0:sys/external/libgxm_dbg_es4.suprx",
			NULL,
			"sd0:us/libgxm_dbg_es4.suprx",
			"os0:us/libgxm_dbg_es4.suprx",
		},
		.inhibit = 0x0,
		.flags   = 0x18
	},
	{
		.module_name = "SceFios2",
		.path = {
			"host0:module/libfios2.suprx",
			NULL,
			"vs0:sys/external/libfios2.suprx",
			"app0:sce_module/libfios2.suprx",
			"sd0:us/libfios2.suprx",
			"os0:us/libfios2.suprx",
		},
		.inhibit = 0x200000,
		.flags   = 0x20000030
	},
	{
		.module_name = "SceLibc",
		.path = {
			"host0:module/libc.suprx",
			NULL,
			"vs0:sys/external/libc.suprx",
			"app0:sce_module/libc.suprx",
			"sd0:us/libc.suprx",
			"os0:us/libc.suprx",
		},
		.inhibit = 0x10000,
		.flags   = 0x10000030
	},
	{
		.module_name = NULL,
		.path = {
			"host0:module/libshellsvc.suprx",
			"host0:vs0/sys/external/libshellsvc.suprx",
			"vs0:sys/external/libshellsvc.suprx",
			NULL,
			"sd0:us/libshellsvc.suprx",
			"os0:us/libshellsvc.suprx",
		},
		.inhibit = 0x80000,
		.flags   = 0x32
	},
	{
		.module_name = NULL,
		.path = {
			"host0:module/libcdlg.suprx",
			"host0:vs0/sys/external/libcdlg.suprx",
			"vs0:sys/external/libcdlg.suprx",
			NULL,
			"sd0:us/libcdlg.suprx",
			"os0:us/libcdlg.suprx",
		},
		.inhibit = 0x100000,
		.flags   = 0x32
	},
	{
		.module_name = NULL,
		.path = {
			"host0:module/libdbg.suprx",
			NULL,
			"vs0:sys/external/libdbg.suprx",
			NULL,
			"sd0:us/libdbg.suprx",
			"os0:us/libdbg.suprx",
		},
		.inhibit = 0x20000,
		.flags   = 0x32
	},
	{
		.module_name = NULL,
		.path = {
			"host0:module/libSceFt2.suprx",
			"host0:vs0/sys/external/libSceFt2.suprx",
			"vs0:sys/external/libSceFt2.suprx",
			NULL,
			"sd0:us/libSceFt2.suprx",
			"os0:us/libSceFt2.suprx",
		},
		.inhibit = 0x800000,
		.flags   = 0x32
	},
	{
		.module_name = NULL,
		.path = {
			"host0:module/libpvf.suprx",
			"host0:vs0/sys/external/libpvf.suprx",
			"vs0:sys/external/libpvf.suprx",
			NULL,
			"sd0:us/libpvf.suprx",
			"os0:us/libpvf.suprx",
		},
		.inhibit = 0x1000000,
		.flags   = 0x32
	},
	{
		.module_name = NULL,
		.path = {
			"host0:module/apputil.suprx",
			"host0:vs0/sys/external/apputil.suprx",
			"vs0:sys/external/apputil.suprx",
			NULL,
			"sd0:us/apputil.suprx",
			"os0:us/apputil.suprx",
		},
		.inhibit = 0x400000,
		.flags   = 0x30
	},
	{
		.module_name = NULL,
		.path = {
			"host0:module/libperf.suprx",
			"host0:vs0/sys/external/libperf.suprx",
			"vs0:sys/external/libperf.suprx",
			NULL,
			"sd0:us/libperf.suprx",
			"os0:us/libperf.suprx",
		},
		.inhibit = 0x2000000,
		.flags   = 0xB8
	}
};

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

const SceKernelDebugMessageContext dbg_msg_ctx_preloading = {
	.hex_value0_hi = 0x48D9AE98,
	.hex_value0_lo = 0x8104FBF7,
	.hex_value1    = 0x9865A59C,
	.func = NULL,
	.line = 0,
	.file = NULL
};

int sceKernelLoadPreloadingModules(SceUID pid, SceLoadProcessParam *pParam, int flags){

	if((flags & 1) != 0)
		preloading_inhibit_shared(pid);

	int sl = 0x8000, sb;
	const char *fp;
	int load_res, count = 0;
	char path_tmp[0x40];

	if(1){
		char _titleid[0x20]; // for log
		ksceKernelGetProcessTitleId(pid, _titleid, sizeof(_titleid));

		ksceDebugPrintf("sceKernelLoadPreloadingModules:[%-9s] pid(0x%08X) flags(0x%08X)\n", _titleid, pid, flags);
		ksceDebugPrintf("preload_inhibit(0x%08X)\n", pParam->preload_inhibit);
	}

	goto load_start;

load_next:

	count++;
	if(count == 0xF){
		func_0x810014d4();
		return 0;
	}

load_start:
	if((preloading_list[count].inhibit & pParam->preload_inhibit) != 0)
		goto load_next;

	if(preloading_list[count].module_name != NULL){
		if(process_lib_is_nonlinked(pid, preloading_list[count].module_name) == 0){

			if(strncmp(preloading_list[count].module_name, "SceFios2", 0x1F) != 0)
				goto load_next;

			if(process_lib_is_nonlinked(pid, "SceLibc") == 0)
				goto load_next;
		}
	}

	if((preloading_list[count].flags & 0x40) != 0){
		if(ksceSblACMgrIsDevelopmentMode2() == 0)
			goto load_next;

		if((preloading_list[count].flags & 0x80) == 0)
			goto loc_81003412;
	}

	if((preloading_list[count].flags & 0x80) != 0 && ksceKernelCheckDipsw(0xD4) == 0){
		goto load_next;
	}

loc_81003412:
	if((flags & 1) != 0){
		if((preloading_list[count].flags & 0x10) != 0)
			goto loc_8100341C;

		goto load_next;
	}

	if((preloading_list[count].flags & 0x20) == 0)
		goto load_next;

loc_8100341C:
	if(ksceKernelCheckDipsw(0xD2) != 0)
		sl |= (((preloading_list[count].flags & 8) != 0) ? 0x20 : 0);

	sb = 1;

	for(int i=0;i<2;i++){
		if(ksceSysrootUseExternalStorage() == 0){

			if(SceQafMgrForDriver_B9770A13() == 0)
				continue;

			if(*(uint32_t *)(SceKernelModulemgr_data + 0x300) != 0)
				continue;

			if(ksceKernelCheckDipsw(0xFB) == 0)
				continue;

			fp = preloading_list[count].path[i];
		}else{
			if(i == 0){
				fp = preloading_list[count].path[4];
			}else{
				fp = path_tmp;
				snprintf(path_tmp, sizeof(path_tmp), "ux0:%s", &(preloading_list[count].path[4][4]));
			}

			if(ksceSysrootIsExternalBootMode() != 0)
				sb = 0;
		}

		if(fp != NULL){

			if((preloading_list[count].flags & 2) == 0){
				load_res = sceKernelLoadModuleForPidForKernel(pid, fp, sl, 0);
			}else{
				load_res = module_load_for_pid_as_shared(pid, fp, sl);
			}

			ksceDebugPrintf("load:0x%08X:%s\n", load_res, fp);

			if(load_res >= 0)
				goto load_next;
		}
	}

	if(sb == 0)
		goto app0_path_check;

	if((preloading_list[count].flags & 2) != 0){
		load_res = module_load_for_pid_as_shared(pid, preloading_list[count].path[2], sl);

		ksceDebugPrintf("load:0x%08X:%s\n", load_res, preloading_list[count].path[2]);
		goto load_res_check;
	}

	if(preloading_list[count].path[3] == NULL)
		goto loc_810034B6;

	if(ksceSblACMgrIsGameProgram2(pid) == 0 && ksceSblACMgrIsNonGameProgram2(pid) == 0){

		char titleid[0x20];
		ksceKernelGetProcessTitleId(pid, titleid, sizeof(titleid));
		if(strncmp(titleid, "NPXS10007", 0x20) != 0)
			goto loc_810034B6;
	}

	load_res = sceKernelLoadModuleForPidForKernel(pid, preloading_list[count].path[3], sl | 0x1000, 0);

		ksceDebugPrintf("load:0x%08X:%s\n", load_res, preloading_list[count].path[3]);
	if(load_res >= 0)
		goto load_next;

loc_810034B6:
	if(ksceSblACMgrIsGameProgram2(pid) == 0 && ksceSblACMgrIsNonGameProgram2(pid) == 0){
		load_res = sceKernelLoadModuleForPidForKernel(pid, preloading_list[count].path[2], sl, 0);
		ksceDebugPrintf("load:0x%08X:%s\n", load_res, preloading_list[count].path[2]);
		goto load_res_check;
	}

	if(preloading_list[count].path[3] == NULL){
		load_res = sceKernelLoadModuleForPidForKernel(pid, preloading_list[count].path[2], sl, 0);
		ksceDebugPrintf("load:0x%08X:%s\n", load_res, preloading_list[count].path[2]);
		goto load_res_check;
	}

	if((flags & 2) != 0)
		goto app0_path_check;

	load_res = sceKernelLoadModuleForPidForKernel(pid, preloading_list[count].path[2], sl, 0);
		ksceDebugPrintf("load:0x%08X:%s\n", load_res, preloading_list[count].path[2]);

load_res_check:
	if(load_res >= 0)
		goto load_next;

app0_path_check:
	if(preloading_list[count].path[3] == NULL)
		goto load_next;

	int res = 0x8002D0F0 | ((preloading_list[count].flags >> 0x1C) & 0xF);
	ksceDebugPrintf2(0, &dbg_msg_ctx_preloading, "not found %s (0x%08x)\n", preloading_list[count].path[3], res);
	ksceDebugPrintf("load:not found %s (0x%08x)\n", preloading_list[count].path[3], res);

	return res;
}



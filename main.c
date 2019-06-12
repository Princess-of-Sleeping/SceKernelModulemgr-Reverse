/*
 * System Version : 3.60
 * text 0x81000000
 * data 0x8100F000
 */

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/io/fcntl.h>
#include <taihen.h>

#include <stdio.h>
#include <string.h>

typedef struct{
	SceUInt flags;
	SceUInt memsz;
	uint8_t perms[4];
	void *vaddr;
	int unk10;
} SceKernelSegmentInfoObj_t; // size (0x14)

typedef struct SceKernelModuleInfoObj_t {
	// 0x00
	int data_0x00;
	int data_0x04;		// ex : 0x900860
	struct SceKernelModuleInfoObj_t *next;
	uint16_t data_0x0C;	// ex : 0xA000
	uint16_t type;

	// 0x10
	uint32_t version;	// ex : 0x03600011
	SceUID modid_kernel;	// This is only used by kernel modules
	SceUID modid_user;	// This is only used by user modules
	SceUID pid;

	// 0x20
	uint16_t flags;
	uint8_t minor;
	uint8_t major;
	const char *module_name;
	int data_0x28;
	int data_0x2C;

	// 0x30
	int data_0x30;
	int data_0x34;
	int data_0x38;
	void *tlsInit;

	// 0x40
	SceSize tlsInitSize;
	SceSize tlsAreaSize;
	void *exidxTop;
	void *exidxBtm;

	// 0x50
	SceUInt unk50;
	SceUInt unk54;
	int data_0x58;		// ex : 0x190006
	int data_0x5C;		// ex : 0x9020D8

	// 0x60
	int data_0x60;
	int data_0x64;		// ex : 0x9020D8
	int data_0x68;
	int data_0x6C;		// ex : 0x9021E0

	// 0x70
	const char *path;
	int segments_num;

	SceKernelSegmentInfoObj_t segments[3];

	int data_0xB4;
	int data_0xB8;
	void *module_start;

	// 0xC0
	SceUInt unkC0;
	void *module_stop;

	// more

} SceKernelModuleInfoObj_t; // sizeof == 0x100

typedef struct{
	SceUInt size;   //!< 0x1B8 for Vita 1.x
	SceUID handle; //!< kernel module handle?
	uint16_t flags;  //!< some bits. could be priority or whatnot
	uint8_t minor;
	uint8_t major;

	// 0xC
	char module_name[0x1C];

	// 0x28
	SceUInt unk28;
	void *module_start;

	// 0x30
	SceUInt unk30;
	void *module_stop;

	void *exidxTop;
	void *exidxBtm;
	SceUInt unk40;
	SceUInt unk44;

	void *tlsInit;
	SceSize tlsInitSize;
	SceSize tlsAreaSize;
	char path[256];
	SceKernelSegmentInfo segments[4];
	SceUInt type;   //!< 6 = user-mode PRX?
} SceKernelModuleInfo_fix_t;

typedef struct module_tree_t{
	struct module_tree_t *next;
	int data_0x04;		// ex : 0x28000 (flags?)
	uint32_t version;	// ex : 0x03600011, -1, etc...
	SceUID modid;
	int data_0x10;
	SceUID pid;
	int data_0x18;		// ex : 0x1
	const char *module_name;

	// maybe more
} module_tree_t;

typedef struct module_tree_top_t{
	SceUID pid;
	void *data_0x04;
	int data_0x08;
	void *data_0x0C;
	module_tree_t *module_tree;
	int data_0x14;
	int data_0x18;		// ex : 0x52
	int data_0x1C;
	int cpu_addr;
	int data_0x24;		// ex : 0x1009B(modid?)
	int data_0x28;
	int data_0x2C;		// ex : 0x19D42EA0(void* ?)

	// maybe more
} module_tree_top_t;

int write_file(const char *path, const void *data, size_t length){

	SceUID fd = ksceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 6);
	if (fd < 0)
		return fd;

	ksceIoWrite(fd, data, length);
	ksceIoClose(fd);

	return 0;
}

int __stack_chk_fail();

// return value is previous value
int ksceKernelSetPermission(int value);

// return value is previous value
SceUID ksceKernelSetProcessId(SceUID pid);

// SceSysmem
SceClass *ksceKernelGetClassForUid(SceUID uid, SceClass **cls);

int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

#define GetExport(modname, libnid, funcnid, func) module_get_export_func(0x10005, modname, libnid, funcnid, (uintptr_t *)func)


void *(* sceKernelGetProcessClassForKernel)(void);
void *(* SceProcessmgrForKernel_C1C91BB2)(SceUID pid);
int (* _ksceKernelGetModuleInfo)(SceUID pid, SceUID modid, SceKernelModuleInfo *info) = NULL;



void *SceKernelModulemgr_text = NULL;
void *SceKernelModulemgr_data = NULL;



int get_function(void){

	GetExport("SceProcessmgr", 0xFFFFFFFF, 0xC1C91BB2, &SceProcessmgrForKernel_C1C91BB2);
	GetExport("SceProcessmgr", 0xFFFFFFFF, 0xC6820972, &sceKernelGetProcessClassForKernel);

	if(GetExport("SceKernelModulemgr", 0xC445FA63, 0xD269F915, &_ksceKernelGetModuleInfo) < 0)
	if(GetExport("SceKernelModulemgr", 0x92C9FFC2, 0xDAA90093, &_ksceKernelGetModuleInfo) < 0)
		return 1;

	return 0;
}

int get_data(void){

	tai_module_info_t tai_info;
	tai_info.size = sizeof(tai_module_info_t);

	SceKernelModuleInfo sce_info;
	sce_info.size = sizeof(SceKernelModuleInfo);

	taiGetModuleInfoForKernel(KERNEL_PID, "SceKernelModulemgr", &tai_info);

	_ksceKernelGetModuleInfo(KERNEL_PID, tai_info.modid, &sce_info);

	SceKernelModulemgr_text = sce_info.segments[0].vaddr;
	SceKernelModulemgr_data = sce_info.segments[1].vaddr;

	return 0;
}





void func_0x810014a8(void){
	int r0 = 1;
	int r1 = 0;
  
	do{
		if ((r0 & *(uint32_t *)(SceKernelModulemgr_data + 0x30)) != 0) {
			*(int *)(SceKernelModulemgr_data + r1) += 1;
		}
		r0 <<= 1;
		r1 += 4;
	}while(r1 != 0x30);
	*(uint32_t *)(SceKernelModulemgr_data + 0x30) = 0;
	return;
}

int func_0x81001ec4(SceUID pid){
	return ksceKernelGetObjForUid(pid, sceKernelGetProcessClassForKernel(), 0);
}

void *func_0x81001f0c(SceUID modid){

	int r0;
	void *obj_base;
	int stack_check;
  
	stack_check = 0;
	r0 = ksceKernelGetObjForUid(modid, (SceClass *)*(uint32_t *)(SceKernelModulemgr_data + 0x48), (SceObjectBase **)&obj_base);
	if (r0 < 0) {
		obj_base = NULL;
	}
	if (stack_check != 0) {
		__stack_chk_fail();
	}

	return obj_base;
}

int func_0x810021b8(SceUID pid){
	ksceKernelUidRelease(pid);
	return 0;
}

int func_0x810021d8(SceUID pid){
	if (pid != 0x10005) {
		ksceKernelUidRelease(pid);
	}
	return 0;
}

int func_0x810021c0(SceUID pid){
	if (pid != 0x10005) {
		return func_0x81001ec4(pid);
	}
	return 0;
}

void *func_0x8100498c(SceUID pid, int len){
	void *res;

	if (pid != 0x10005) {
		res = SceProcessmgrForDriver_00B1CA0F(pid, len);
	}else{
		res = ksceKernelSysrootAlloc(len);
	}
	return res;
}

int func_0x810049fc(const char *path){
	const char **pPath;
	int r0;
	int r1;

	if(
	  (*(uint32_t *)(SceKernelModulemgr_data + 0x304) != 0) && (*(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 8) > 0)
	){
		r0 = 0;
		r1 = 0;
		do{
			pPath = (const char **)(*(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 0xc) + r0);
			r0 += 0xC;
			if(strncmp(path, *pPath, 0xFF) == 0){
				*(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 4) = r1;
				return 0x7f7f7f7f;
			}
			r1 += 1;
		}while(r1 != *(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 8));
	}
	return 0x80010002;
}

int func_0x81004a54(void){
	*(int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x304) + 4) = 0xffffffff;
	return 0;
}

int func_0x81005648(SceUID pid, int flags, void *dst){

	int res;
	int stack_check;
	SceObjectBase *local_44;
	SceCreateUidObjOpt local_40;

	stack_check = 0;

	if(pid == 0x10005){
		res = ksceKernelCreateUidObj(
			(SceClass *)*(uint32_t *)(SceKernelModulemgr_data + 0x48),
			"SceModuleMgrNewModule",
			0,
			&local_44
		);

		if (res < 0)
			goto loc_810056c8;

		*(uint32_t *)(((char *)local_44) + 0x10) = 0xffffffff;
		*(uint32_t *)(((char *)local_44) + 0x1c) = 0x10005;
		*(uint32_t *)(((char *)local_44) + 0x14) = res;

	}else{

		local_40.field_10 = ((flags & 0x10) != 0) ? 1 : 0;

		local_40.flags = 8;
		local_40.field_4 = 0;
		local_40.field_8 = 0;
		local_40.pid = pid;
		local_40.field_14 = 0;
		local_40.field_18 = 0;

		res = SceProcessmgrForKernel_B75FB970(pid);
		if(res < 0)
			goto loc_810056c8;

		res = ksceKernelCreateUidObj(
			(SceClass *)*(uint32_t *)(SceKernelModulemgr_data + 0x48),
			"SceModuleMgrNewModule",
			&local_40,
			&local_44
		);

		if(res < 0){
			SceProcessmgrForKernel_0A5A2CF1(pid, local_40.field_10);
			goto loc_810056c8;
		}
		*(uint32_t *)(((char *)local_44) + 0x10) = 0x03600011;
		*(uint32_t *)(((char *)local_44) + 0x1c) = pid;
		*(uint32_t *)(((char *)local_44) + 0x14) = res;
	}
	res = (int)dst;
	if(dst != NULL){
		*(uint32_t *)dst = local_44;
		res = 0;
	}
loc_810056c8:
	if(stack_check != 0){
		__stack_chk_fail();
	}

	return res;
}

int func_0x81005a70(void *r0, const char *path, int flags){

	int res = 0;
	int path_len;
	void *pPath;
	uint16_t uVar1;

	uVar1 = *(uint16_t *)(r0 + 4);
	if((uVar1 & 0x500) != 0){
		*(uint32_t *)(r0 + 0x68) = *(uint32_t *)(*(uint32_t *)(*(uint32_t *)(r0 + 0xD4) + 4) + 0x68);
		return 0;
	}

	path_len = strnlen(path, 0xff);
	if(((int)((uint32_t)uVar1 << 0x16) < 0) && (0xfe < path_len)){
		res = 0x8002d01f;
	}else{
		pPath = func_0x8100498c(*(uint32_t *)(r0 + 0x14), path_len + 1);
		*(int *)(r0 + 0x68) = pPath;
		if(pPath == NULL){
			res = 0x8002d008;
		}else{
			memcpy(pPath, path, path_len);
			*(uint8_t *)(*(uint32_t *)(r0 + 0x68) + path_len) = 0;
			if((flags & 0x800) != 0){
				memcpy((void *)*(uint32_t *)(r0 + 0x68), "bootfs:", 7);
			/*
				*(uint32_t *)(*(uint32_t *)(r0 + 0x68) + 0) = 0x746f6f62;
				*(uint16_t *)(*(uint32_t *)(r0 + 0x68) + 4) = 0x7366;
				*(uint8_t  *)(*(uint32_t *)(r0 + 0x68) + 6) = 0x3a;
			*/
				return 0;
			}
		}
	}
	return res;
}

void func_0x81005b04(void *r0){

	if(SceQafMgrForDriver_382C71E8() != 0) {
		if (*(int *)(r0 + 0x6c) < 2) {
			ksceDebugPrintf2(0, (void *)(SceKernelModulemgr_text + 0xD90C), "[%-27s]:text=%p(0x%08x), (no data)\n",
				*(int *)(r0 + 0x1c), *(int *)(r0 + 0x7c), *(int *)(r0 + 0x74)
			);
		}else{
			ksceDebugPrintf2(0, (void *)(SceKernelModulemgr_text + 0xD8F4), "[%-27s]:text=%p(0x%08x), data=%p(0x%08x/0x%08x)\n",
				*(int *)(r0 + 0x1c), *(int *)(r0 + 0x7c), *(int *)(r0 + 0x74),
				*(int *)(r0 + 0x90), *(int *)(r0 + 0x84), *(int *)(r0 + 0x88)
			);
		}
	}
}

/*
 * get_module_obj_for_pid
 *
 * pid			[in]
 * cpu_suspend_intr	[out]
 */
module_tree_top_t *func_0x81006e60(SceUID pid, int *cpu_suspend_intr){
	int r0, r1;
	module_tree_top_t *r2;

	r0 = func_0x810021c0(pid);
	if (r0 < 0) {
		r2 = NULL;
	}else{
		r2 = SceProcessmgrForKernel_C1C91BB2(pid);
		if (r2 != NULL) {
			r1 = ksceKernelCpuSuspendIntr((int *)(&r2->cpu_addr));
			*cpu_suspend_intr = r1;
		}

		func_0x810021d8(pid);
	}

	return r2;
}

int func_0x81006e90(module_tree_top_t *module_tree_top, int cpu_suspend_intr){
	return ksceKernelCpuResumeIntr((int *)(&module_tree_top->cpu_addr), cpu_suspend_intr);
}

int func_0x81007148(const char *path){

	int cpu_suspend_intr;

	int *piVar3;
  
	cpu_suspend_intr = ksceKernelCpuSuspendIntr((int *)(SceKernelModulemgr_data + 0x310));

	piVar3 = (int *)(*(uint32_t *)(SceKernelModulemgr_data + 0x30C));

	while(1){
		if(piVar3 == (int *)0x0){
			ksceKernelCpuResumeIntr((int *)(SceKernelModulemgr_data + 0x310), cpu_suspend_intr);
			return 0;
		}
		if(strncmp(*(uint32_t *)(piVar3[1] + 0x68), path, 0x100) == 0)
			break;
		piVar3 = (int *)piVar3[0];
	}
	piVar3[2] += 1;
	ksceKernelCpuResumeIntr((int *)(SceKernelModulemgr_data + 0x310), cpu_suspend_intr);
	return (int)piVar3;
}

int func_0x810071a8(void *r0){
	int cpu_suspend_intr;
  
	cpu_suspend_intr = ksceKernelCpuSuspendIntr((int *)(SceKernelModulemgr_data + 0x310));
	*(int *)(r0 + 8) += -1;
	ksceKernelCpuResumeIntr((int *)(SceKernelModulemgr_data + 0x310), cpu_suspend_intr);
	return 0;
}

int func_0x81007790(SceUID pid, SceUID modid, SceKernelModuleInfo_fix_t *info){

	int res;
	int mod_seg_num;
	int current_seg;
	int cpu_suspend_intr;
	int stack_check;
	module_tree_top_t *module_tree_top;
	SceKernelModuleInfoObj_t *info_obj;
  
	stack_check = 0;

	module_tree_top = func_0x81006e60(pid, &cpu_suspend_intr);
	if(module_tree_top == NULL){
		res = 0x8002d080;
		goto loc_810077e6;
	}

	info_obj = func_0x81001f0c(modid);
	if(info_obj == NULL){
		res = 0x8002d082;
	}else{

		if(modid == info_obj->modid_kernel){

			info->handle = (pid == 0x10005) ? modid : info_obj->modid_user;

			info->flags = info_obj->flags;
			info->minor = info_obj->minor;
			info->major = info_obj->major;

			strncpy(info->module_name, info_obj->module_name, 28-1);

			switch(info_obj->type){
			case 1:
			case 2:
			case 0x10:
				info->type = 2;
				break;
			case 3:
				info->type = 6;
				break;
			default:
				info->type = 9;
			}

			info->module_start	= info_obj->module_start;
			info->unk30		= info_obj->unkC0;
			info->module_stop	= info_obj->module_stop;

			info->exidxTop		= info_obj->exidxTop;
			info->exidxBtm		= info_obj->exidxBtm;
			info->unk40		= info_obj->unk50;
			info->unk44		= info_obj->unk54;

			info->tlsInit		= info_obj->tlsInit;
			info->tlsInitSize	= info_obj->tlsInitSize;
			info->tlsAreaSize	= info_obj->tlsAreaSize;

			strncpy(info->path, info_obj->path, 0x100-1);
			mod_seg_num = info_obj->segments_num;
			current_seg = 0;

			if(mod_seg_num < 1){
				mod_seg_num = 0;
loc_810078fc:

				do {
					info->segments[mod_seg_num].perms = 0;
					info->segments[mod_seg_num].vaddr = 0;
					info->segments[mod_seg_num].memsz = 0;
					info->segments[mod_seg_num].flags = 0;
					mod_seg_num++;
				} while (mod_seg_num < 4);

			}else{

				do {
					info->segments[current_seg].size = 0x18;
					info->segments[current_seg].perms = (info_obj->segments[current_seg].perms[0] | (info_obj->segments[current_seg].perms[1] << 0x14));
					info->segments[current_seg].vaddr = info_obj->segments[current_seg].vaddr;
					info->segments[current_seg].memsz = info_obj->segments[current_seg].memsz;
					info->segments[current_seg].flags = info_obj->segments[current_seg].flags;
					current_seg++;
				} while(current_seg < mod_seg_num);

				if(mod_seg_num < 4)
					goto loc_810078fc;
			}
			res = 0;
		}else{
			res = 0x8002d082;
		}
		func_0x810021b8(modid);
	}

	ksceKernelCpuResumeIntr((int *)(&module_tree_top->cpu_addr), cpu_suspend_intr);

loc_810077e6:
	if(stack_check != 0){
		__stack_chk_fail();
	}

	return res;
}

SceUID func_0x81007c5c(SceUID pid, const char *module_name){
	module_tree_top_t *module_tree_top;
	module_tree_t *module_tree;
	SceUID uid;
	int cpu_suspend_intr;
	int stack_check;

	stack_check = 0;

	module_tree_top = func_0x81006e60(pid, &cpu_suspend_intr);
	if(module_tree_top == NULL){
		uid = 0x8002d080;
	}else{

		module_tree = module_tree_top->module_tree;
 		while(module_tree != NULL){

			if(strncmp(module_tree->module_name, module_name, 0x1a) == 0){
				uid = module_tree->modid;
				goto loc_81007c9a;
			}
			module_tree = module_tree->next;
		}
		uid = 0x8002d082;
loc_81007c9a:
		ksceKernelCpuResumeIntr((int *)(&module_tree_top->cpu_addr), cpu_suspend_intr);
	}

	if(stack_check != 0){
		__stack_chk_fail();
	}

	return uid;
}

int func_0x81007f00(SceUID pid){
	return *(uint16_t *)(SceProcessmgrForKernel_C1C91BB2(pid) + 0x1A) & 1;
}

SceUID _ksceKernelSearchModuleByName(const char *module_name){
	return func_0x81007c5c(0x10005, module_name);
}

int _ksceKernelGetModuleInternal(SceUID modid, void **module){

	void *r0 = func_0x81001f0c(modid);
	if (r0 == NULL)
		goto loc_810032EA;

	if (module == NULL)
		goto loc_810032E0;

	*(uint32_t *)(module) = (uint32_t)(r0 + 8);

loc_810032E0:
	ksceKernelUidRelease(modid);
	return 0;

loc_810032EA:
	return 0x8002D011;
}

int __ksceKernelGetModuleInfo(SceUID pid, SceUID modid, SceKernelModuleInfo *info){
	if(pid == 0){
		pid = ksceKernelGetProcessId();
	}

	return func_0x81007790(pid, modid, (SceKernelModuleInfo_fix_t *)info);
}

// sub_810021EC
SceUID module_load_for_pid(SceUID pid, const char *path, int flags, SceKernelLMOption *option){
	// yet not Reversed
	return 0;
}

// sub_8100286C
int module_start_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){
	// yet not Reversed
	return 0;
}

// sub_81002EDC
SceUID module_load_start_for_pid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){

	SceUID res;
	SceUID modid;
	int mod_start_res;

	modid = module_load_for_pid(pid, path, flags, option);

	if(modid < 0)
		goto label_0x81002F4A;

	mod_start_res = module_start_for_pid(pid, modid, args, argp, flags, 0, status);

	if(mod_start_res == 0)
		goto label_0x81002F4A;

	if(mod_start_res == 1){
		res = 0;
		goto label_0x81002F4C;
	}

	/*
	 * 0x8002802C(SCE_KERNEL_ERROR_THREAD_STOPPED)
	 * 0x8002802D(SCE_KERNEL_ERROR_THREAD_SUSPENDED)
	 *
	 * The above error code does not unload module
	 */
	if((uint32_t)(0x7FFD7FD4 + mod_start_res) <= 1){
		res = mod_start_res;
		goto label_0x81002F4C;
	}

	module_stop_unload_for_pid(pid, modid, 0, 0, 0x40000000, 0, 0);

	return mod_start_res;

label_0x81002F4A:
	res = modid;

label_0x81002F4C:
	return res;
}

// sub_81002B40
int module_stop_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){
	// yet not Reversed
	return 0;
}

// sub_810026BC
int module_unload_for_pid(SceUID pid, SceUID modid, int flags, SceKernelULMOption *option){
	// yet not Reversed
	return 0;
}

// sub_81002EB0
int module_stop_unload_for_pid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){

	int res;

	res = module_stop_for_pid(pid, modid, args, argp, flags, NULL, status);
	if(res < 0)
		goto end;

	res = module_unload_for_pid(pid, modid, flags, option);

end:
	return res;
}

// sub_81003000
SceUID module_load_start_shared_for_pid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){
	SceUID res;
	SceUID modid;
	int mod_start_res;

	modid = module_load_for_pid(pid, path, flags | 1, NULL);

	if(modid < 0)
		goto label_0x81003022;

	if((flags & 0x100000) == 0) // not set load only flag
		goto label_0x8100302A;

label_0x81003022:
	res = modid;

label_0x81003024:
	return res;

label_0x8100302A:

	mod_start_res = module_start_for_pid(pid, modid, args, argp, flags, NULL, status);

	if(mod_start_res == 0)
		goto label_0x81003022;

	if(mod_start_res == 1){
		res = 0;
		goto label_0x81003024;
	}

	/*
	 * 0x8002D000(SCE_KERNEL_ERROR_MODULEMGR_START_FAILED)
	 */
	if(mod_start_res == 0x8002D000)
		goto label_0x81003082;

	/*
	 * 0x8002802C(SCE_KERNEL_ERROR_THREAD_STOPPED)
	 * 0x8002802D(SCE_KERNEL_ERROR_THREAD_SUSPENDED)
	 *
	 * The above error code does not unload module
	 */
	if((uint32_t)(0x7FFD7FD4 + mod_start_res) <= 1){
		goto label_0x81003082;
	}

	module_stop_unload_for_pid(pid, modid, 0, 0, 0x48000000, 0, 0);

	res = mod_start_res;
	goto label_0x81003024;

label_0x81003082:
	res = mod_start_res;
	goto label_0x81003024;
}

// sceKernelFinalizeKblForKernel
int SceModulemgrForKernel_FDD7F646(void){

	SceUID modid;
	modid = *(uint32_t *)(*(uint32_t *)(SceKernelModulemgr_data + 0x38) + 0xA8);
	if(modid <= 0){
		return 0;
	}

	return module_stop_unload_for_pid(0x10005, modid, 0, 0, 0, 0, 0);
}

SceUID ksceKernelLoadModule(const char *path, int flags, SceKernelLMOption *option){

	if(((flags & ~0x7D800) & ~0x1F0) != 0)
		return 0x8002000A;

	return module_load_for_pid(0x10005, path, flags, option);
}

SceUID ksceKernelLoadModuleForPid(SceUID pid, const char *path, int flags, SceKernelLMOption *option){

	SceUID res;
	int OldPermission, OldPid;

	if(pid == 0)
		return 0x8002D017;

	if(((flags & ~0x7D800) & ~0x1F0) != 0)
		return 0x8002000A;

	OldPermission = ksceKernelSetPermission(0x80);
	OldPid = ksceKernelSetProcessId(0x10005);
	res = module_load_for_pid(pid, path, flags | 2, option);
	ksceKernelSetProcessId(OldPid);
	ksceKernelSetPermission(OldPermission);

	return res;
}

int ksceKernelStartModule(SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){

	if(flags != 0)
		return 0x8002000A;

	return module_start_for_pid(0x10005, modid, args, argp, flags, option, status);
}

int ksceKernelStartModuleForPid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){

	if(pid == 0)
		return 0x8002D017;

	if(flags != 0)
		return 0x8002000A;

	return module_start_for_pid(pid, modid, args, argp, flags, option, status);
}

SceUID ksceKernelLoadStartModule(const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){

	if(((flags & ~0x7D800) & ~0x1F0) != 0)
		return 0x8002000A;

	return module_load_start_for_pid(0x10005, path, args, argp, flags, option, status);
}

SceUID ksceKernelLoadStartModuleForPid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){

	if(pid == 0)
		return 0x8002D017;

	if(((flags & ~0x7D800) & ~0x1F0) != 0)
		return 0x8002000A;

	return module_load_start_for_pid(pid, path, args, argp, ((flags | 0x8000000) | 2), option, status);
}


int ksceKernelUnloadModule(SceUID modid, int flags, SceKernelULMOption *option){

	if((flags & ~0x40000000) != 0)
		return 0x8002000A;

	return module_unload_for_pid(0x10005, modid, flags, option);
}

int ksceKernelUnloadModuleForPid(SceUID pid, SceUID modid, int flags, SceKernelULMOption *option){

	if(pid == 0)
		return 0x8002D017;

	if((flags & ~0x40000000) != 0)
		return 0x8002000A;

	return module_unload_for_pid(pid, modid, flags, option);
}

int ksceKernelStopModule(SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){

	if(flags != 0)
		return 0x8002000A;

	return module_stop_for_pid(0x10005, modid, args, argp, flags, option, status);
}

int ksceKernelStopModuleForPid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){

	if(pid == 0)
		return 0x8002D017;

	if(flags != 0)
		return 0x8002000A;

	return module_stop_for_pid(pid, modid, args, argp, flags, option, status);
}

int ksceKernelStopUnloadModule(SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){

	if((flags & ~0x40000000) != 0)
		return 0x8002000A;

	return module_stop_unload_for_pid(0x10005, modid, args, argp, flags, option, status);
}

int ksceKernelStopUnloadModuleForPid(SceUID pid, SceUID modid, SceSize args, void *argp, int flags, SceKernelULMOption *option, int *status){

	if(pid == 0)
		return 0x8002D017;
	
	if((flags & ~0x40000000) != 0)
		return 0x8002000A;

	return module_stop_unload_for_pid(pid, modid, args, argp, flags | 0x8000000, option, status);
}

SceUID ksceKernelLoadStartSharedModuleForPid(SceUID pid, const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){

	if(pid == 0)
		return 0x8002D017;

	return module_load_start_shared_for_pid(pid, path, args, argp, flags | 0x8000000, option, status);
}

int syscall_stub(){
	return 0x8002710C;
}

// ksceKernelRegisterSyscall
void SceModulemgrForKernel_B427025E(int syscall_id, const void *func){

	int dacr;

	if (syscall_id >= 0x1000)
		return;

	asm volatile ("mrc p15, 0, %0, c3, c0, 0" : "=r" (dacr));
	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (0x17450000));

	*(uint32_t *)((*(uint32_t *)(SceKernelModulemgr_data + 0x334)) + (syscall_id << 0x2)) = (uint32_t)func;

	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (dacr));

	return;
}

// non export
void ksceKernelUnregisterSyscall(int syscall_id){

	int dacr;

	if (syscall_id >= 0x1000)
		return;

	asm volatile ("mrc p15, 0, %0, c3, c0, 0" : "=r" (dacr));
	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (0x17450000));

	*(uint32_t *)((*(uint32_t *)(SceKernelModulemgr_data + 0x334)) + (syscall_id << 0x2)) = (uint32_t)&syscall_stub;

	asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (dacr));

	return;
}


/*
int sub_81006CF4(int a1, int a2, int a3, void *a4){
	// yet not Reversed
	return 0;
}

int sub_81007A84(void *a1, int a2, void *a3){

	int res, v1, v4, lr, a4;

	v1 = a1;
	sp = sp - 0xC;
	if (*(uint32_t *)(a1 + 0x1C) == 0)
		goto loc_81007AC2;

	res = sub_81006CF4(*(uint32_t *)(*(uint32_t *)(a1 + 0x1C)), *(uint32_t *)(a1 + 0x1C) + 0x10, a2, sp);
	if(res == 0)
		goto loc_81007AC2;

	if(*(uint32_t *)(a1) == 0)
		goto loc_81007AC2;

	if((a2 - *(uint32_t *)(*(uint32_t *)(a1) + 0x7C)) >= *(uint32_t *)(*(uint32_t *)(a1) + 0x74)) // unsigned >=
		goto loc_81007AC2;

	*(uint32_t *)(a3) = *(uint32_t *)(a1);
	res = 0;
	goto loc_81007AFA;

loc_81007AC2:
	a3 = *(uint32_t *)(v1 + 0x10);
	lr = 0x14;

loc_81007AC8:
	if (a3 == NULL)
		goto loc_81007AF2;
	a2 = *(uint32_t *)(a3 + 0x6C);
	a4 = 0;

loc_81007ACE:
	if(a4 >= a2)
		goto loc_81007AEE;

	if((uint32_t)(v2 - *(uint32_t *)(lr * a4 + a3 + 0x7C)) >= (uint32_t)*(uint32_t *)(a1 + 0x74))
		goto loc_81007AE8;

	*(uint32_t *)(v4) = a3;
	res = 0;
	goto loc_81007AFA;

loc_81007AE8:
	a4 = (uint16_t)(a4 + 1);
	goto loc_81007ACE;

loc_81007AEE:
	a3 = *(uint32_t *)(a3);
	goto loc_81007AC8;

loc_81007AF2:
	res = 0x8002D082;

loc_81007AFA:

loc_81007B06:
	return res;
}

int sub_81007BBC(SceUID pid, int a2){

	int res;
	char data[0x10];
	module_tree_top_t *module_tree_top;

	v1 = 0;
	*(uint32_t *)(&data[0xC]) = 0;

	module_tree_top = func_0x81006e60(pid, (int *)&data[0x4]);
	if(module_tree_top == NULL)
		goto loc_81007BF8;

	res = sub_81007A84(module_tree_top, a2, &data[0x8]);
	if(res == 0)
		res = *(uint32_t *)(*(uint32_t *)(&data[0x8]) + 0xC);

	ksceKernelCpuResumeIntr((int *)(&module_tree_top->cpu_addr), *(uint32_t *)(&data[0x4]));
	goto loc_81007C00;

loc_81007BF8:
	res = 0x8002D080;

loc_81007C00:
	if (*(uint32_t *)(&data[0xC]) != v1)
		__stack_chk_fail();

loc_81007C0C:
	return res;
}


int sub_81007C10(SceUID pid, int a2){

	int res, a2, v1, v2, r4;
	char data[0xC];
	v1 = pid;

	if(pid == 0){
		*(uint32_t *)(&data[0x4]) = a2;
		pid = ksceKernelGetProcessId();
		a2 = *(uint32_t *)(&data[0x4]);
		v1 = pid;
	}

	res = sub_81007BBC(v1, a2);
	v2 = a1;
	if(v1 == 0x10005)
		goto loc_81007C4A;

	if(res <= 0)
		goto loc_81007C4A;

	res = sub_81001F0C(res);
	if(res == 0)
		return 0x8002D011;

	res = sub_810021B8(res);
	r4 = *(uint32_t *)(res + 0x18);
	res = v2;
	goto loc_81007C56;

loc_81007C46:
	res = r4
	goto loc_81007C56;

loc_81007C4A:
	res = v2;

loc_81007C56:
	return res;
}


int SceModulemgrForKernel_0053BA4A(SceUID pid, int a2){
	return sub_81007C10(pid, a2);
}
*/

//  SceModulemgrForKernel_F95D09C2("os0:ue/cui_setupper.self", sp + 0x60, sp + 0x70);
int SceModulemgrForKernel_F95D09C2(const char *path, void *a2, void *a3){
	// yet not Reversed
	return 0;
}

int SceModulemgrForDriver_861638AD(int a1){

	int res;
	int some_uid;
	void *arg1;

	some_uid = func_0x81007C10(0x10005, a1);
	if(some_uid < 0)
		return some_uid;

	arg1 = func_0x81001F0C(some_uid);
	if(arg1 == NULL)
		return 0x8002D011;

	res = func_0x81005FEC(arg1 + 8, a1);
	if(res < 0)
		goto label_0x81003242;

	res = func_0x81004198(arg1 + 8, res, 1);

label_0x81003242:
	ksceKernelUidRelease(some_uid);
	ksceKernelCpuIcacheInvalidateAll();
	return res;
}

void *SceModulemgrForKernel_66606301(int a1){

	void *res;

	res = func_0x81001F0C(a1);
	if(res == NULL)
		goto label_0x810032CA;

	res = *(uint32_t *)(res + 0xBC);
	ksceKernelUidRelease(a1);

label_0x810032CA:
	return res;
}

int SceModulemgrForKernel_78DBC027(SceUID pid, SceUID UserUid, void *a3, void *a4){

	void *res1;

	if(pid != 0x10005)
		goto label_0x81003316;

label_0x8100330A:
	return 0x8002D012;

label_0x81003316:
	if(func_0x81001EC4(pid) < 0)
		goto label_0x8100330A;

	KernelUid = ksceKernelKernelUidForUserUid(pid, UserUid);

	if(KernelUid >= 0)
		goto label_0x81003336;

	ksceKernelUidRelease(pid);

	return KernelUid;

label_0x81003336:
	res1 = func_0x81001F0C(KernelUid);
	if(res1 != 0)
		goto label_0x81003350;

	ksceKernelUidRelease(pid);

	return 0x8002D011;

label_0x81003350:
	*(uint32_t *)(a3) = *(uint32_t *)(res1 + 0xB4);
	*(uint32_t *)(a4) = *(uint32_t *)(res1 + 0xB8);
	ksceKernelUidRelease(KernelUid);
	ksceKernelUidRelease(pid);

	if(*(uint32_t *)(a3) == 0){
		return 0x8002D01C;
	}else{
		return 0;
	}
}

// Bigger function
// sceKernelLoadPreloadingModulesForKernel
// https://wiki.henkaku.xyz/vita/SceKernelModulemgr#sceKernelLoadPreloadingModulesForKernel
int SceModulemgrForKernel_3AD26B43(int a1, int a2, int a3){
	// yet not Reversed
	return 0;
}

void _start() __attribute__ ((weak, alias("module_start")));
int module_start(SceSize args, void *argp){

	SceUID uid;

	get_function();
	get_data();

	uid = _ksceKernelSearchModuleByName("SceSysmem");
	write_file("ur0:data/module_rev_SceSysmem_uid.bin", &uid, 4);

	uid = _ksceKernelSearchModuleByName("SceKernelModulemgr");
	write_file("ur0:data/module_rev_SceKernelModulemgr_uid.bin", &uid, 4);

	void *data = func_0x81001f0c(uid);
	write_file("ur0:data/module_rev_SceKernelModulemgr_data.bin", data, 0x400);

	// You can check the hash to see if the function is correct :)
	SceKernelModuleInfo info;

	memset(&info, 0, sizeof(info));
	_ksceKernelGetModuleInfo(0x10005, uid, &info);  // original export
	write_file("ur0:data/module_rev_SceKernelModulemgr_Info.bin", &info, sizeof(info));

	memset(&info, 0, sizeof(info));
	__ksceKernelGetModuleInfo(0x10005, uid, &info); // reverse
	write_file("ur0:data/module_rev_SceKernelModulemgr_Info_rev.bin", &info, sizeof(info));

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp){
	return SCE_KERNEL_STOP_SUCCESS;
}

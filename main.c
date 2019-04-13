/*
 * System Version : 3.60
 */

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/io/fcntl.h>
#include <taihen.h>

#include <stdio.h>
#include <string.h>

int write_file(const char *path, const void *data, size_t length){

	SceUID fd = ksceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 6);
	if (fd < 0)
		return fd;

	ksceIoWrite(fd, data, length);
	ksceIoClose(fd);

	return 0;
}

int __stack_chk_fail();

SceClass *ksceKernelGetClassForUid(SceUID uid, SceClass **cls);

int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

#define GetExport(modname, libnid, funcnid, func) module_get_export_func(0x10005, modname, libnid, funcnid, (uintptr_t *)func)



void *(* SceProcessmgrForKernel_C1C91BB2)(SceUID pid);
int (* _ksceKernelGetModuleInfo)(SceUID pid, SceUID modid, SceKernelModuleInfo *info) = NULL;



void *SceKernelModulemgr_data = NULL;



int get_function(void){

	GetExport("SceProcessmgr", 0xFFFFFFFF, 0xC1C91BB2, &SceProcessmgrForKernel_C1C91BB2);

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

	SceKernelModulemgr_data = sce_info.segments[1].vaddr;

	return 0;
}

int func_0x81001ec4(SceUID pid){
	SceClass *cls;
  
	cls = ksceKernelGetClassForUid(pid, NULL);
	return ksceKernelGetObjForUid(pid, cls, 0);
}

int func_0x810021c0(SceUID pid){
  
	if (pid != 0x10005) {
		return func_0x81001ec4(pid);
	}

	return 0;
}

int func_0x810021d8(SceUID pid){
	if (pid != 0x10005) {
		ksceKernelUidRelease(pid);
	}
	return 0;
}

int func_0x810021b8(SceUID pid){
	ksceKernelUidRelease(pid);
	return 0;
}

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

			if (strncmp(module_tree->module_name, module_name, 0x1a) == 0) {
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

SceUID _ksceKernelSearchModuleByName(const char *module_name){
	return func_0x81007c5c(0x10005, module_name);
}

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

int __ksceKernelGetModuleInfo(SceUID pid, SceUID modid, SceKernelModuleInfo *info){
	if(pid == 0){
		pid = ksceKernelGetProcessId();
	}

	return func_0x81007790(pid, modid, (SceKernelModuleInfo_fix_t *)info);
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

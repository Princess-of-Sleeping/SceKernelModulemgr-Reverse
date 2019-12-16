
#ifndef _PSP2_KERNEL_MODULEMGR_INTERNAL_H_
#define _PSP2_KERNEL_MODULEMGR_INTERNAL_H_

#include <psp2kern/types.h>

typedef struct {
  SceSize size;   //!< this structure size (0x18)
  SceUInt perms;  //!< probably rwx in low bits
  void *vaddr;    //!< address in memory
  SceSize memsz;  //!< size in memory
  SceSize filesz; //!< original size of memsz
  SceUInt res;    //!< unused
} SceKernelSegmentInfo_fix;

typedef struct {
	SceSize filesz;
	SceSize memsz;
	uint8_t perms[4];
	void *vaddr;
	SceUID unk_0x10;
} SceKernelSegmentInfoObj_t; // size (0x14)

typedef struct SceKernelModuleInfoObjBase_t {

	struct SceKernelModuleInfoObjBase_t *next;
	uint16_t flags;		// ex : 0xA000
	uint8_t type;
	uint8_t data_0x07;
	uint32_t version;	// ex : 0x03600011
	SceUID modid_kernel;	// This is only used by kernel modules

	// 0x10
	SceUID modid_user;	// This is only used by   user modules
	SceUID pid;
	uint16_t attr;
	uint8_t minor;
	uint8_t major;
	const char *module_name;

	// 0x20
	void *libent_top;
	void *libent_btm;
	void *libstub_top;
	void *libstub_btm;

	// 0x30
	uint32_t module_nid;
	void *tlsInit;
	SceSize tlsInitSize;
	SceSize tlsAreaSize;

	// 0x40
	void *exidxTop;
	void *exidxBtm;
	void *extabTop;
	void *extabBtm;

	// 0x50
	int data_0x58;		// ex : 0x190006
	int data_0x5C;		// ex : 0x9020D8
	int data_0x60;
	int data_0x64;		// ex : 0x9020D8

	// 0x60
	int data_0x68;
	int data_0x6C;		// ex : 0x9021E0
	const char *path;
	int segments_num;

	// 0x70
	SceKernelSegmentInfoObj_t segments[3]; // 0x14 * 3 : 0x3C

	int data_0xB4;

	// 0xB0
	int data_0xB8;
	void *module_start;
	void *module_stop;
	void *module_exit;

	// more
} SceKernelModuleInfoObjBase_t;

typedef struct SceKernelModuleInfoObj_t {
	// 0x00
	uint32_t sce_reserved[2];
	SceKernelModuleInfoObjBase_t obj_base;
} SceKernelModuleInfoObj_t; // sizeof == 0x100

typedef struct {
	SceUInt size;    //!< 0x1B8 for Vita 1.x
	SceUID modid;
	uint16_t attr;
	uint8_t minor;
	uint8_t major;

	// 0xC
	char module_name[0x1C];

	// 0x28
	SceUInt unk28;
	void *module_start;

	// 0x30
	void *module_stop;
	void *module_exit;

	void *exidxTop;
	void *exidxBtm;
	void *extabTop;
	void *extabBtm;

	void *tlsInit;
	SceSize tlsInitSize;
	SceSize tlsAreaSize;
	char path[0x100];
	SceKernelSegmentInfo_fix segments[4];
	SceUInt type;   //!< 6 = user-mode PRX?
} SceKernelModuleInfo_fix_t;

typedef struct module_tree_t {
	// 0x00
	struct module_tree_t *next;
	int data_0x04;		// ex : 0x28000 (flags?)
	uint32_t version;	// ex : 0x03600011, -1, etc...
	SceUID modid;

	// 0x10
	int data_0x10;
	SceUID pid;
	int data_0x18;		// ex : 0x1
	const char *module_name;

	// maybe more
} module_tree_t;

typedef struct module_library_info_t {
	int data_0x00; // 0x10024
	int data_0x04; // 0x10008
	int data_0x08;
	uint32_t library_nid;

	// maybe more
} module_library_info_t;

typedef struct module_info_tree_t {
	struct module_info_tree_t *next;
	SceUID data_0x04;
	module_library_info_t *data_0x08;
	int data_0x0C;
	SceKernelModuleInfoObjBase_t *pObjBase;

	// maybe more
} module_info_tree_t;

typedef struct module_tree_top_t {
	SceUID pid;
	void *data_0x04;	// export info?
	int data_0x08;		// uid?
	module_info_tree_t *module_info_tree; // non linked import info?
	module_tree_t *module_tree;
	int data_0x14;
	uint16_t data_0x18;	// ex : 0x52
	uint16_t inhibit_state;
	void *data_0x1C;
	int cpu_addr;
	int data_0x24;		// ex : 0x1009B(modid?)
	int data_0x28;
	int data_0x2C;		// ex : 0x19D42EA0(void* ?)

	// maybe more
} module_tree_top_t;

#endif /* _PSP2_KERNEL_MODULEMGR_INTERNAL_H_ */

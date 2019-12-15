
#ifndef _PSP2_KERNEL_MODULEMGR_INTERNAL_H_
#define _PSP2_KERNEL_MODULEMGR_INTERNAL_H_

#include <psp2kern/types.h>

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
	SceUID modid_user;	// This is only used by   user modules
	SceUID pid;

	// 0x20
	uint16_t attr;
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
	void *extabTop;
	void *extabBtm;
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
	void *module_stop;
	void *module_exit;

	// more

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
	SceKernelSegmentInfo segments[4];
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

typedef struct module_tree_top_t {
	SceUID pid;
	void *data_0x04;
	int data_0x08;
	void *data_0x0C;
	module_tree_t *module_tree;
	int data_0x14;
	uint16_t data_0x18;		// ex : 0x52
	uint16_t data_0x1A;
	int data_0x1C;
	int cpu_addr;
	int data_0x24;		// ex : 0x1009B(modid?)
	int data_0x28;
	int data_0x2C;		// ex : 0x19D42EA0(void* ?)

	// maybe more
} module_tree_top_t;

#endif /* _PSP2_KERNEL_MODULEMGR_INTERNAL_H_ */

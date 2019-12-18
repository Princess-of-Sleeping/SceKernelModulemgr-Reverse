/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULEMGR_INTERNAL_H_
#define _PSP2_KERNEL_MODULEMGR_INTERNAL_H_

#include <psp2kern/types.h>

typedef struct SceKernelModuleInfoObjBase_t SceKernelModuleInfoObjBase_t;

typedef int (* SceKernelModuleEntry)(SceSize args, void *argp);

typedef struct SceModuleLibImport_t {

	uint16_t size; // 0x24
	uint16_t libver[2];
	uint16_t entry_num_function;
	uint16_t entry_num_variable;
	uint16_t data_0x0A; // unused?
	uint32_t libnid;

	const char *libname;
	void *ent1;
	void *ent2;
	void *ent3;

	void *ent4;

/*
	int data_0x00; // 0x10024
	int data_0x04; // 0x10008
	int data_0x08;
	uint32_t library_nid;
*/
} SceModuleLibImport_t;
// } module_library_info_t;

typedef struct SceModuleLibExport_t {
	uint16_t size; // 0x20
	uint16_t libver[2];
	uint16_t entry_num_function;
	uint16_t entry_num_variable;
	uint16_t data_0x0A; // unused?
	uint32_t data_0x0C; // unused?
	uint32_t libnid;
	const char *libname;
	void *table_nid;
	void *table_entry;
} SceModuleLibExport_t;

typedef struct SceModuleLibraryExportInfo_t {
	struct SceModuleLibraryExportInfo_t *next;
	void *data_0x04;
	SceModuleLibExport_t *nid_info;
	int data_0x0C; // flags?
	int data_0x10; // ex:1
	int data_0x14; // zero?
	SceUID libid_kernel;
	SceUID libid_user;
	SceKernelModuleInfoObjBase_t *modobj;
	int data_0x24[3]; // zero?
	int data_0x30; // zero?
	SceModuleLibExport_t *data_0x34; // maybe noname export
	int data_0x38; // ex:0x40000

	// maybe more
} SceModuleLibraryExportInfo_t;

typedef struct {
	SceSize filesz;
	SceSize memsz;
	uint8_t perms[4];
	void *vaddr;
	SceUID unk_0x10;
} SceKernelSegmentInfoObj_t; // size (0x14)

typedef struct module_tree_t {
	struct module_tree_t *next;
	int data_0x04;		// ex : 0x28000 (flags?)
	uint32_t version;	// ex : 0x03600011, -1, etc...
	SceUID modid_kernel;

	// 0x10
	int data_0x10;
	SceUID pid;
	int data_0x18;		// ex : 0x1
	const char *module_name;

	// maybe more
} module_tree_t;

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
	void *data_0x58;			// unk
	SceModuleLibExport_t *data_0x5C;
	SceModuleLibExport_t *data_0x60;	// export relation
	SceModuleLibraryExportInfo_t *data_0x64;

	// 0x60
	void *data_0x68;			// import relation
	void *data_0x6C;			// unk, function table?
	const char *path;
	int segments_num;

	// 0x70
	SceKernelSegmentInfoObj_t segments[3]; // 0x14 * 3 : 0x3C

	int data_0xB4;

	// 0xB0
	int data_0xB8;
	SceKernelModuleEntry module_start;
	SceKernelModuleEntry module_stop;
	SceKernelModuleEntry module_exit;

	// more
} SceKernelModuleInfoObjBase_t;

typedef struct SceKernelModuleImportNonlinkedInfo_t {
	struct SceKernelModuleImportNonlinkedInfo_t *next;
	SceUID stubid;
	SceModuleLibImport_t *lib_import_info;
	int data_0x0C;
	SceKernelModuleInfoObjBase_t *pObjBase;
	int data_0x14;
} SceKernelModuleImportNonlinkedInfo_t;

typedef struct SceKernelModuleInfoObj_t {
	uint32_t sce_reserved[2];
	SceKernelModuleInfoObjBase_t obj_base;
} SceKernelModuleInfoObj_t; // sizeof == 0x100

typedef struct SceModuleLibraryObj_t {
	uint32_t sce_reserved[2];
	SceModuleLibraryExportInfo_t *library_info;
	SceUID modid;
} SceModuleLibraryObj_t;

typedef struct SceModuleLibStubObj_t {
	uint32_t sce_reserved[2];
	SceUID modid;
	SceSize num; // maybe non linked import num
} SceModuleLibStubObj_t;

typedef struct SceKernelModuleProcInfo_t {
	SceUID pid;
	SceModuleLibraryExportInfo_t *lib_export_info;
	SceUID data_0x08;			// uid?
	SceKernelModuleImportNonlinkedInfo_t *import_nonlinked_list;	// non linked import info?, allocated by sceKernelAlloc
	SceKernelModuleInfoObjBase_t *module_list;
	SceUID proc_main_module_id;
	uint16_t proc_module_count;
	uint16_t inhibit_state;
	void *data_0x1C;
	int cpu_addr;
	int data_0x24;				// ex:0x1009B(modid?)
} SceKernelModuleProcInfo_t;

#endif /* _PSP2_KERNEL_MODULEMGR_INTERNAL_H_ */

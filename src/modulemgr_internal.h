/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULEMGR_INTERNAL_H_
#define _PSP2_KERNEL_MODULEMGR_INTERNAL_H_

#include <psp2kern/types.h>

typedef struct SceModuleInfoInternal SceModuleInfoInternal;
typedef struct SceModuleLibraryExportInfo_t SceModuleLibraryExportInfo_t;

typedef int (* SceKernelModuleEntry)(SceSize args, void *argp);

typedef struct SceModuleLibImport1_t {
	uint16_t size;               // 0x34
	uint16_t version;
	uint16_t flags;
	uint16_t entry_num_function;
	uint16_t entry_num_variable;
	uint16_t entry_num_tls;
	uint32_t rsvd1;
	uint32_t libnid;
	const char *libname;
	uint32_t rsvd2;
	uint32_t *table_func_nid;
	void    **table_function;
	uint32_t *table_vars_nid;
	void    **table_variable;
	uint32_t *table_tls_nid;
	void    **table_tls;
} SceModuleLibImport1_t;

typedef struct SceModuleLibImport2_t {
	uint16_t size; // 0x24
	uint16_t libver[2];
	uint16_t entry_num_function;
	uint16_t entry_num_variable;
	uint16_t data_0x0A; // unused?
	uint32_t libnid;
	const char *libname;
	uint32_t *table_func_nid;
	void    **table_function;
	uint32_t *table_vars_nid;
	void    **table_variable;
} SceModuleLibImport2_t;

typedef union SceModuleLibImport_t {
	uint16_t size;
	SceModuleLibImport1_t type1;
	SceModuleLibImport2_t type2;
} SceModuleLibImport_t;

typedef struct SceModuleLibExport_t {
	uint16_t size; // 0x20

	uint16_t libver[2];
/*
	uint16_t libver_minor;
	uint8_t  libver_major;
	uint8_t  flags; // 0x40:user export
*/
	uint16_t entry_num_function;
	uint16_t entry_num_variable;
	uint16_t data_0x0A; // unused?
	uint32_t data_0x0C; // unused?
	uint32_t libnid;
	const char *libname;
	void  *table_nid;
	void **table_entry;
} SceModuleLibExport_t;

typedef struct SceModuleProcImportInfo_t {
	struct SceModuleProcImportInfo_t *next;
	SceUID data_0x04;
	SceModuleLibImport_t *data_0x08;
	SceModuleLibraryExportInfo_t *data_0x0C;
	SceModuleInfoInternal *data_0x10;
	int data_0x14; // zero?
} SceModuleProcImportInfo_t;

typedef struct SceModuleLibraryExportInfo_t { // size is 0x2C
	struct SceModuleLibraryExportInfo_t *next;
	void *data_0x04;
	SceModuleLibExport_t *info;
	int data_0x0C; // flags?
	int data_0x10; // ex:1
	SceModuleProcImportInfo_t *data_0x14;
	SceUID libid_kernel;
	SceUID libid_user;
	SceModuleInfoInternal *modobj;
	int data_0x24; // zero?
	int data_0x28; // zero?
} SceModuleLibraryExportInfo_t;

typedef struct SceModuleLibraryImportInfo {
	SceUID stubid;
	SceModuleLibImport_t *info;
	SceModuleLibraryExportInfo_t *lib_export_info;
	SceModuleInfoInternal *modobj;
	int data_0x14;
	void *data_0x18; // size is 0x30
} SceModuleLibraryImportInfo;

typedef struct SceModuleImportList { // size is 0x48
	struct SceModuleImportList *next;
	SceModuleLibraryImportInfo list[];
} SceModuleImportList;

typedef struct SceSegmentInfoInternal {
	SceSize filesz;
	SceSize memsz;
	uint8_t perms[4];
	void *vaddr;
	SceUID memblk_id;
} SceSegmentInfoInternal; // size (0x14)

typedef struct SceModuleInfoInternal {
	struct SceModuleInfoInternal *next;
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
	uint16_t lib_export_num;                 // Includes noname library
	uint16_t lib_import_num;
	SceModuleLibExport_t *data_0x54;
	SceModuleLibExport_t *data_0x58;         // export relation

	/*
	 * export list
	 * maybe this kernel only
	 * allocated by sceKernelAlloc
	 *
	 * if you using this data, need call get_module_object
	 */
	SceModuleLibraryExportInfo_t *data_0x5C;

	// 0x60
	SceModuleLibImport_t *data_0x60;         // first_import?
	SceModuleImportList *imports;            // allocated by sceKernelAlloc
	char *path;
	SceSize segments_num;

	// 0x70
	SceSegmentInfoInternal segments[3]; // 0x14 * 3 : 0x3C
	int data_0xAC;

	// 0xB0
	int data_0xB0;
	SceKernelModuleEntry module_start;
	SceKernelModuleEntry module_stop;
	SceKernelModuleEntry module_exit;

	int data_0xC0;
	void *data_0xC4; // module import/export data?
	int data_0xC8;
	int data_0xCC;

	void *data_0xD0; // elf data
	void *data_0xD4; // for shared module data
	int data_0xD8;
	int data_0xDC;

	int data_0xE0;
	int data_0xE4;
	int data_0xE8;
} SceModuleInfoInternal; // size is 0xEC

typedef struct SceModuleNonlinkedInfo {
	struct SceModuleNonlinkedInfo *next;
	SceUID stubid;
	SceModuleLibImport_t *lib_import_info;
	int data_0x0C;
	SceModuleInfoInternal *pModuleInfo;
	int data_0x14;
} SceModuleNonlinkedInfo;

typedef struct SceModuleObject {
	uint32_t sce_reserved[2];
	SceModuleInfoInternal obj_base;
} SceModuleObject; // sizeof == 0xF4

typedef struct SceModuleLibraryObject {
	uint32_t sce_reserved[2];
	SceModuleLibraryExportInfo_t *library_info;
	SceUID modid;
} SceModuleLibraryObject;

typedef struct SceModuleLibStubObject {
	uint32_t sce_reserved[2];
	SceUID modid;
	SceSize num; // maybe non linked import num
} SceModuleLibStubObject;

typedef struct SceKernelProcessModuleInfo {
	SceUID pid;
	SceModuleLibraryExportInfo_t *lib_export_info;
	SceUID data_0x08;                              // uid?
	SceModuleNonlinkedInfo *nonlinked_info;        // allocated by sceKernelAlloc

	// offset:0x10
	SceModuleInfoInternal *pModuleInfo;
	SceUID process_main_module_id;
	uint16_t process_module_count;
	uint16_t inhibit_state;
	void *data_0x1C;

	int cpu_addr;
	SceUID ScePsp2BootConfig_modid;                // kernel only
} SceKernelProcessModuleInfo;

#endif /* _PSP2_KERNEL_MODULEMGR_INTERNAL_H_ */

/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2019, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULEMGR_INTERNAL_H_
#define _PSP2_KERNEL_MODULEMGR_INTERNAL_H_

#include <psp2kern/types.h>

typedef struct SceModuleInfoInternal SceModuleInfoInternal;
typedef struct SceModuleLibraryInfo SceModuleLibraryInfo;

typedef int (* SceKernelModuleEntry)(SceSize args, void *argp);
typedef int (* SceKernelModuleDebugCallback)(SceModuleInfoInternal *pModuleInfo);

typedef struct SceModuleImport1 {
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
} SceModuleImport1;

typedef struct SceModuleImport2 {
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
} SceModuleImport2;

typedef union SceModuleImport {
	uint16_t size;
	SceModuleImport1 type1;
	SceModuleImport2 type2;
} SceModuleImport;

typedef struct SceModuleExport {
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
} SceModuleExport;

typedef struct SceModuleImportedInfo {
	struct SceModuleImportedInfo *next;
	SceUID data_0x04;
	SceModuleImport *pImportInfo;
	SceModuleLibraryInfo *pLibraryInfo;
	SceModuleInfoInternal *pModuleInfo;
	int data_0x14; // zero?
} SceModuleImportedInfo;

typedef struct SceModuleLibraryImportInfo {
	SceUID stubid;
	SceModuleImport *pImportInfo;
	SceModuleLibraryInfo *pLibraryInfo;
	SceModuleInfoInternal *pModuleInfo;
	int data_0x14;
	void *data_0x18; // size is 0x30
} SceModuleLibraryImportInfo;

typedef struct SceModuleImportList { // size is 0x48
	struct SceModuleImportList *next;
	SceModuleLibraryImportInfo list[];
} SceModuleImportList;

typedef struct SceModuleLibraryInfo { // size is 0x2C
	struct SceModuleLibraryInfo *next;
	struct SceModuleLibraryInfo *data_0x04; // maybe
	SceModuleExport *pExportInfo;

	/*
	 * (syscall_idx &  0xFFF):syscall idx
	 * (syscall_idx & 0x1000):has syscall flag?
	 * (syscall_idx == 0) -> kernel export
	 */
	uint16_t syscall_info;
	uint16_t data_0x0E;

	/*
	 * Number of times this export was imported into another module
	 */
	SceSize number_of_imported;
	SceModuleImportedInfo *pImportedInfo;
	SceUID libid_kernel;
	SceUID libid_user;
	SceModuleInfoInternal *pModuleInfo;
	int data_0x24; // zero?
	int data_0x28; // zero?
} SceModuleLibraryInfo;

typedef struct SceSegmentInfoInternal { // size is 0x14
	SceSize filesz;
	SceSize memsz;
	uint8_t perms[4];
	void *vaddr;
	SceUID memblk_id;
} SceSegmentInfoInternal;

typedef struct SceModuleSharedInfo { // size is 0x10
	struct SceModuleSharedInfo *next;
	SceModuleInfoInternal *pModuleInfo;
	int data_0x08; // ex:1
	int data_0x0C;
} SceModuleSharedInfo;

typedef struct SceModuleInfoInternal {
	struct SceModuleInfoInternal *next;
	uint16_t flags;
	uint8_t state;
	uint8_t data_0x07;
	uint32_t version;	// ex : 0x03600011
	SceUID modid_kernel;	// This is only used by kernel modules

	// 0x10
	SceUID modid_user;	// This is only used by   user modules
	SceUID pid;
	uint16_t attr;
	uint8_t minor;
	uint8_t major;
	char *module_name;

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
	uint16_t lib_export_num;            // Includes noname library
	uint16_t lib_import_num;
	SceModuleExport *data_0x54;
	SceModuleExport *data_0x58;         // export relation

	/*
	 * export list
	 * maybe this kernel only
	 *
	 * if you using this data, need call get_module_object
	 */
	SceModuleLibraryInfo *pLibraryInfo;

	// 0x60
	SceModuleImport *data_0x60;         // first_import?
	SceModuleImportList *imports;       // allocated by sceKernelAlloc
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
	void *module_proc_param;
	int data_0xC8;
	int data_0xCC;

	/*
	 * hb  : elf data
	 * sce : some data
	 */
	void *data_0xD0;
	SceModuleSharedInfo *pSharedInfo; // allocated by sceKernelAlloc
	int data_0xD8;
	int data_0xDC;

	int data_0xE0;
	int data_0xE4;
	int data_0xE8;
} SceModuleInfoInternal; // size is 0xEC

typedef struct SceModuleObject { // size is 0xF4
	uint32_t sce_reserved[2];
	SceModuleInfoInternal obj_base;
} SceModuleObject;

typedef struct SceModuleLibraryObject {
	uint32_t sce_reserved[2];
	SceModuleLibraryInfo *pLibraryInfo;
	SceUID modid;
} SceModuleLibraryObject;

typedef struct SceModuleLibStubObject {
	uint32_t sce_reserved[2];
	SceUID modid;
	SceSize num; // maybe nonlinked import num
} SceModuleLibStubObject;

typedef struct SceModuleNonlinkedInfo {
	struct SceModuleNonlinkedInfo *next;
	SceUID stubid;
	SceModuleImport *pImportInfo;
	int data_0x0C;
	SceModuleInfoInternal *pModuleInfo;
	int data_0x14;
} SceModuleNonlinkedInfo;

typedef struct SceKernelProcessModuleInfo {
	SceUID pid;
	SceModuleLibraryInfo *pLibraryInfo;
	SceUID data_0x08;                              // uid?
	SceModuleNonlinkedInfo *pNonlinkedInfo;        // allocated by sceKernelAlloc

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

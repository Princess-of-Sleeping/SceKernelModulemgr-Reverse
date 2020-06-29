/*
 * PS Vita kernel module manager RE Syscall header
 * Copyright (C) 2020, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULE_MGR_SYSCALL_H_
#define _PSP2_KERNEL_MODULE_MGR_SYSCALL_H_

int ReSyscallInit(void *syscall_table_ptr);

int syacall_init(void);

int IsSyscallTableExist(void);

void sceKernelRegisterSyscallForKernel(int syscall_id, const void *func);
void sceKernelUnregisterSyscallForKernel(int syscall_id);

#endif /* _PSP2_KERNEL_MODULE_MGR_SYSCALL_H_ */

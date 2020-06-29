/*
 * PS Vita kernel module manager RE Inhibit Loading header
 * Copyright (C) 2020, Princess of Sleeping
 */

#ifndef _PSP2_KERNEL_MODULE_MGR_INHIBIT_LOADING_H_
#define _PSP2_KERNEL_MODULE_MGR_INHIBIT_LOADING_H_

int inhibit_loading_module(uint16_t flag);

int sceKernelInhibitLoadingModule(uint16_t flag);

#endif /* _PSP2_KERNEL_MODULE_MGR_INHIBIT_LOADING_H_ */

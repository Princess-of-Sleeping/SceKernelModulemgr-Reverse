/*
 * PS Vita kernel module manager RE
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _PSP2_MODULE_LOAD_H_
#define _PSP2_MODULE_LOAD_H_

#include <psp2kern/types.h>

SceUID module_load_for_pid_as_shared(SceUID pid, const char *path, int flags);

#endif /* _PSP2_MODULE_LOAD_H_ */

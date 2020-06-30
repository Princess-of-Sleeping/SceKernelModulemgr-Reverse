/*
 * PS Vita kernel module manager RE My Debug header
 * Copyright (C) 2020, Princess of Sleeping
 */

#ifndef _MY_DEBUG_H_
#define _MY_DEBUG_H_

#include "modulemgr_internal.h"

void hex_dump(const void *addr, SceSize len);
int write_file(const char *path, const void *data, SceSize size);

int my_debug_start(void);

#endif /* _MY_DEBUG_H_ */

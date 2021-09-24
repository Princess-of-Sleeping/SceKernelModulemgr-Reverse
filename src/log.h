/*
 * log.h
 * Copyright (C) 2020, Princess of Sleeping
 */

#ifndef _FAPS_LOG_H_
#define _FAPS_LOG_H_

int LogIsOpened(void);
int LogOpen(const char *path);
int LogWrite(const char *fmt, ...);
int LogClose(void);

#endif /* _FAPS_LOG_H_ */

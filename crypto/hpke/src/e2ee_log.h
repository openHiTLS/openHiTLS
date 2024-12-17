#ifndef E2EE_LOG_H
#define E2EE_LOG_H

#include <stdarg.h>

void E2EE_LogPrint(const char *format, ...);

#define E2EE_LOG_ERROR(fmt, ...) E2EE_LogPrint(fmt, ##__VA_ARGS__)

#endif

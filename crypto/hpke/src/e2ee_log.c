#include <stdarg.h>
#include <stdio.h>
#include "securec.h"
#include "e2ee_key_exch.h"
#include "e2ee_log.h"

#define E2EE_LOG_BUF_SIZE 128

static void DefaultLogPrint(const char *buff, uint32_t len)
{
    (void)len;
    printf("%s", buff);
}

E2EE_logCallbackFunc g_logCallback = DefaultLogPrint;

void E2EE_RegisterLogCallback(E2EE_logCallbackFunc logCallbackFunc)
{
    g_logCallback = logCallbackFunc;
}

void E2EE_LogPrint(const char *format, ...)
{
    if (g_logCallback == NULL) {
        return;
    }
    char logBuf[E2EE_LOG_BUF_SIZE] = {0};

    va_list args;
    va_start(args, format);
    int32_t ret = vsnprintf_s(logBuf, E2EE_LOG_BUF_SIZE, E2EE_LOG_BUF_SIZE - 2, format, args); // -2 for '\n' and '\0'
    va_end(args);
    if (ret <= 0) {
        ret = strlen("Log buffer overflow");
        (void)memcpy_s(logBuf, E2EE_LOG_BUF_SIZE, "Log buffer overflow", ret);
    }
    logBuf[ret] = '\n';
    logBuf[ret + 1] = '\0';

    g_logCallback(logBuf, ret + 1);
}

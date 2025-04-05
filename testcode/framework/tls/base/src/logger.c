/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <unistd.h>
#include "logger.h"

LogLevel GetLogLevel(void)
{
#ifdef TLS_DEBUG
    return ENUM_LOG_LEVEL_TRACE;
#else
    return ENUM_LOG_LEVEL_FATAL;
#endif
}

static const char *ConvertLevel2Str(LogLevel level)
{
    switch (level) {
        case ENUM_LOG_LEVEL_TRACE:
            return "TRACE";
        case ENUM_LOG_LEVEL_DEBUG:
            return "DEBUG";
        case ENUM_LOG_LEVEL_WARNING:
            return "WARNING";
        case ENUM_LOG_LEVEL_ERROR:
            return "ERROR";
        case ENUM_LOG_LEVEL_FATAL:
            return "FATAL";
        default:
            return "UNKNOWN";
    }
}

int LogWrite(LogLevel level, const char *file, int line, const char *fmt, ...)
{
    int len, ilen;
    LogLevel curLevel;
    va_list vargs;
    int tmpLevel = level;
    char logBuf[LOG_MAX_SIZE] = {0};

    if ((tmpLevel < ENUM_LOG_LEVEL_TRACE) || (tmpLevel > ENUM_LOG_LEVEL_FATAL)) {
        return 0;
    }

    // Print logs whose levels are higher than or equal to the current level.
    curLevel = GetLogLevel();
    if (level < curLevel) {
        return 0;
    }

    // Process the log header
    if (file == NULL || line == 0) {
        len = snprintf_s(logBuf, LOG_MAX_SIZE, (size_t)(LOG_MAX_SIZE - 1), "[%d_TEST_%s]",
            getpid(), ConvertLevel2Str((LogLevel)tmpLevel));
    } else {
        len = snprintf_s(logBuf, LOG_MAX_SIZE, (size_t)(LOG_MAX_SIZE - 1), "[%d_TEST_%s][%s:%d]",
            getpid(), ConvertLevel2Str((LogLevel)tmpLevel), file, line);
    }

    if (len < 0 || len > LOG_MAX_SIZE - 1) {
        return 0;
    }

    va_start(vargs, fmt);
    ilen = vsnprintf_s(logBuf + len, (size_t)(LOG_MAX_SIZE - len), (size_t)(LOG_MAX_SIZE - len - 1), fmt, vargs);
    if (ilen < 0 || ilen > LOG_MAX_SIZE - len - 1) {
        // In the case of overflow truncation, the maximum value is used
        len = LOG_MAX_SIZE;
        logBuf[len - 1] = '\0';
        goto EXIT;
    }

    len += ilen;
    logBuf[len] = '\n';
    logBuf[len + 1] = '\0';
EXIT:
    va_end(vargs);
#ifdef TLS_DEBUG
    printf("%s", logBuf);
#endif
    return 0;
}

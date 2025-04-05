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

#ifndef BSL_LOG_INTERNAL_H
#define BSL_LOG_INTERNAL_H

#include <stdint.h>
#include "hitls_build.h"
#include "bsl_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HITLS_BSL_LOG
#ifdef HITLS_BSL_LOG_NO_FORMAT_STRING
#define LOG_STR(str) NULL
#else
#define LOG_STR(str) (str)
#endif

#define BSL_LOG_BUF_SIZE            1024U

/**
 * @ingroup bsl_log
 * @brief four-parameter dotting log function
 * @attention A maximum of four parameters can be contained in the formatted string.
 *            If the number of parameters is less than four, 0s or NULL must be added.
 *            If the number of parameters exceeds four, multiple invoking is required.
 *            Only the LOG_BINLOG_FIXLEN macro can be invoked. This macro cannot be redefined.
 * @param logId [IN] Log ID
 * @param logLevel [IN] Log level
 * @param logType [IN] String label
 * @param format [IN] Format string. Only literal strings are allowed. Variables are not allowed.
 * @param para1 [IN] Parameter 1
 * @param para2 [IN] Parameter 2
 * @param para3 [IN] Parameter 3
 * @param para4 [IN] Parameter 4
 */
void BSL_LOG_BinLogFixLen(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para1, void *para2, void *para3, void *para4);

/**
 * @ingroup bsl_log
 * @brief one-parameter dotting log function
 * @attention The formatted character string contains only one parameter, which is %s.
 *            For a pure character string, use LOG_BinLogFixLen
 *            Only the LOG_BINLOG_VARLEN macro can be invoked. This macro cannot be redefined.
 * @param logId [IN] Log ID
 * @param logLevel [IN] Log level
 * @param logType [IN] String label
 * @param format [IN] Format string. Only literal strings are allowed. Variables are not allowed.
 * @param para [IN] Parameter
 */
void BSL_LOG_BinLogVarLen(uint32_t logId, uint32_t logLevel, uint32_t logType, void *format, void *para);

/**
 * @ingroup bsl_log
 * @brief four-parameter dotting log macro
 * @attention A maximum of four parameters can be contained in the formatted string.
 *            If the number of parameters is less than four, 0s or NULL must be added.
 *            If the number of parameters exceeds four, multiple invoking is required.
 * @param logId [IN] Log ID
 * @param logLevel [IN] Log level
 * @param logType [IN] String label
 * @param format [IN] Format string. Only literal strings are allowed. Variables are not allowed.
 * @param para1 [IN] Parameter 1
 * @param para2 [IN] Parameter 2
 * @param para3 [IN] Parameter 3
 * @param para4 [IN] Parameter 4
 */
#define BSL_LOG_BINLOG_FIXLEN(logId, logLevel, logType, format, para1, para2, para3, para4) \
    BSL_LOG_BinLogFixLen(logId, logLevel, logType, \
        (void *)(uintptr_t)(const void *)(LOG_STR(format)), (void *)(uintptr_t)(para1), (void *)(uintptr_t)(para2), \
        (void *)(uintptr_t)(para3), (void *)(uintptr_t)(para4))

/**
 * @ingroup bsl_log
 * @brief one-parameter dotting log macro
 * @attention The formatted character string contains only one parameter, which is %s.
 *            For a pure character string, use LOG_BinLogFixLen
 * @param logId [IN] Log ID
 * @param logLevel [IN] Log level
 * @param logType [IN] String label
 * @param format [IN] Format string. Only literal strings are allowed. Variables are not allowed.
 * @param para [IN] Parameter
 */
#define BSL_LOG_BINLOG_VARLEN(logId, logLevel, logType, format, para) \
    BSL_LOG_BinLogVarLen(logId, logLevel, logType, \
        (void *)(uintptr_t)(const void *)(LOG_STR(format)), (void *)(uintptr_t)(const void *)(para))

#else

#define BSL_LOG_BINLOG_FIXLEN(logId, logLevel, logType, format, para1, para2, para3, para4)
#define BSL_LOG_BINLOG_VARLEN(logId, logLevel, logType, format, para)

#endif /* HITLS_BSL_LOG */

#ifdef __cplusplus
}
#endif

#endif // BSL_LOG_INTERNAL_H

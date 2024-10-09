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

#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <stdio.h>
#include <stdint.h>
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_MAX_SIZE 1024

typedef enum {
    ENUM_LOG_LEVEL_TRACE,      /* Basic level */
    ENUM_LOG_LEVEL_DEBUG,      /* Debugging level */
    ENUM_LOG_LEVEL_WARNING,    /* Warning level */
    ENUM_LOG_LEVEL_ERROR,      /* Error level */
    ENUM_LOG_LEVEL_FATAL       /* Fatal level */
} LogLevel;

/**
* @ingroup log
* @brief Record error information based on the log level
*
* @par
* Record error information based on the log level
*
* @attention
*
* @param[in] level Log level
* @param[in] file File where the error information is stored
* @param[in] line Number of the line where the error information is stored
* @param[in] fmt Format character string for printing
*
* @retval 0 Success
* @retval others failure
*/
int LogWrite(LogLevel level, const char *file, int line, const char *fmt, ...);

#define LOG_DEBUG(...) LogWrite(ENUM_LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) LogWrite(ENUM_LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __LOGGER_H__

/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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

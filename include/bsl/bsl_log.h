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

/**
 * @defgroup bsl_log
 * @ingroup bsl
 * @brief log module
 */

#ifndef BSL_LOG_H
#define BSL_LOG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_log
 *
 * Audit log level
 */
#define BSL_LOG_LEVEL_SEC         0U

/**
 * @ingroup bsl_log
 *
 * Emergency log level
 */
#define BSL_LOG_LEVEL_FATAL       1U

/**
 * @ingroup bsl_log
 *
 * Error log level
 */
#define BSL_LOG_LEVEL_ERR         2U

/**
 * @ingroup bsl_log
 *
 * Warning log level
 */
#define BSL_LOG_LEVEL_WARN        3U

/**
 * @ingroup bsl_log
 *
 * Information log level
 */
#define BSL_LOG_LEVEL_INFO        4U

/**
 * @ingroup bsl_log
 *
 * Debug log level
 */
#define BSL_LOG_LEVEL_DEBUG       5U

/**
 * @ingroup bsl_log
 *
 * HiTLS version string
 */
#ifndef OPENHITLS_VERSION_S
#define OPENHITLS_VERSION_S "openHiTLS 0.3.0 12 Feb 2026"
#endif

#ifndef OPENHITLS_VERSION_I
#define OPENHITLS_VERSION_I 0x0030000fULL
#endif

#define HITLS_VERSION_LEN 150

/**
 * @ingroup bsl_log
 * @brief   Obtain the openHiTLS version string.
 *
 * @attention The length of the received version string must be greater than or equal to HITLS_VERSION_LEN.
 * @param   version [OUT] openHiTLS current version string.
 * @param   versionLen [IN/OUT] String length of the current openHiTLS version.
 * @retval  #BSL_SUCCESS, if success.
 * @retval  #BSL_LOG_ERR_MEMCPY, memory copy failure.
 */
int32_t BSL_LOG_GetVersion(char *version, uint32_t *versionLen);

/**
 * @ingroup bsl_log
 * @brief   Obtain the openHiTLS version number.
 *
 * @retval  openHiTLS version number.
 */
uint64_t BSL_LOG_GetVersionNum(void);

/**
 * @ingroup bsl_log
 * @brief   Binlog type, other types can be extended.
 */
#define BSL_LOG_BINLOG_TYPE_RUN 0x01

/**
 * @ingroup bsl_log
 * @brief   Fixed-length callback type of binlogs.
 *
 * The function format of this type cannot contain %s, the number of parameters is less than four, add 0s.
 * More than four parameters must be called multiple times.
 */
typedef void (*BSL_LOG_BinLogFixLenFunc)(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para1, void *para2, void *para3, void *para4);

/**
 * @ingroup bsl_log
 * @brief   Callback type for variable-length binlogs.
 *
 * This type function format contains only one %s, If no %s exists, use BSL_LOG_BinLogFixLenFunc type.
 * If there are more than one %s, call the interface multiple times.
 */
typedef void (*BSL_LOG_BinLogVarLenFunc)(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para);

/**
 * @ingroup bsl_log
 * @brief   Register the parameter type of the binlog callback function.
 */
typedef struct {
    BSL_LOG_BinLogFixLenFunc fixLenFunc; /**< 4 parameter callback */
    BSL_LOG_BinLogVarLenFunc varLenFunc; /**< 1 parameter callback */
} BSL_LOG_BinLogFuncs;

/**
 * @ingroup bsl_log
 * @brief   Set the fixed-length and variable-length callback function for binlogs.
 *
 * @attention The input parameter can be NULL.
 * @param   funcs [IN] Callback function pointer collection of the binlog.
 *          The parameter cannot be null, but the member of the structure can be null.
 * @retval  #BSL_SUCCESS.
 */
int32_t BSL_LOG_RegBinLogFunc(const BSL_LOG_BinLogFuncs *funcs);

/**
 * @ingroup bsl_log
 * @brief   Set the level of binlogs.
 *
 * @attention The level must be valid.
 * @param   level [IN] Level of the binlogs. The valid values are BSL_LOG_LEVEL_SEC, BSL_LOG_LEVEL_FATAL,
 *          BSL_LOG_LEVEL_ERR, BSL_LOG_LEVEL_WARN, BSL_LOG_LEVEL_INFO, BSL_LOG_LEVEL_DEBUG
 * @retval  #BSL_SUCCESS.
 * @retval  #BSL_LOG_ERR_BAD_PARAM, invalid input parameter.
 */
int32_t BSL_LOG_SetBinLogLevel(uint32_t level);

/**
 * @ingroup bsl_log
 * @brief   Obtain the level of binlogs.
 *
 * @retval  Level of the binlog. The value can be BSL_LOG_LEVEL_SEC, BSL_LOG_LEVEL_FATAL, BSL_LOG_LEVEL_ERR,
 *          BSL_LOG_LEVEL_WARN, BSL_LOG_LEVEL_INFO, BSL_LOG_LEVEL_DEBUG
 */
uint32_t BSL_LOG_GetBinLogLevel(void);

#ifdef __cplusplus
}
#endif

#endif // BSL_LOG_H

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

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include "bsl_log_internal.h"
#include "bsl_binlog_id.h"
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PROCESS_PARAM_INT32(tmpParam, paramObj, params, paramName, destField) \
    do { \
        (tmpParam) = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)(params), (paramName)); \
        if ((tmpParam) == NULL || (tmpParam)->valueType != BSL_PARAM_TYPE_INT32) { \
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05075, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, \
            "tls config: not found int32 param %s", #paramName, 0, 0, 0); \
            goto ERR; \
        } \
        (paramObj)->destField = *(int32_t *)(tmpParam)->value; \
    } while (0)

#define PROCESS_PARAM_UINT16(tmpParam, paramObj, params, paramName, destField) \
    do { \
        (tmpParam) = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)(params), (paramName)); \
        if ((tmpParam) == NULL || (tmpParam)->valueType != BSL_PARAM_TYPE_UINT16) { \
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05076, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, \
            "tls config: not found uint16 param %s", #paramName, 0, 0, 0); \
            goto ERR; \
        } \
        (paramObj)->destField = *(uint16_t *)(tmpParam)->value; \
    } while (0)

#define PROCESS_PARAM_UINT32(tmpParam, paramObj, params, paramName, destField) \
    do { \
        (tmpParam) = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)(params), (paramName)); \
        if ((tmpParam) == NULL || (tmpParam)->valueType != BSL_PARAM_TYPE_UINT32) { \
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05077, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, \
            "tls config: not found uint32 param %s", #paramName, 0, 0, 0); \
            goto ERR; \
        } \
        (paramObj)->destField = *(uint32_t *)(tmpParam)->value; \
    } while (0)

#define PROCESS_PARAM_BOOL(tmpParam, paramObj, params, paramName, destField) \
    do { \
        (tmpParam) = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)(params), (paramName)); \
        if ((tmpParam) == NULL || (tmpParam)->valueType != BSL_PARAM_TYPE_BOOL) { \
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05078, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, \
            "tls config: not found bool param %s", #paramName, 0, 0, 0); \
            goto ERR; \
        } \
        (paramObj)->destField = *(bool *)(tmpParam)->value; \
    } while (0)

#define PROCESS_STRING_PARAM(tmpParam, paramObj, params, paramName, destField) \
    do { \
        (tmpParam) = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)(params), (paramName)); \
        if ((tmpParam) == NULL || (tmpParam)->valueType != BSL_PARAM_TYPE_OCTETS_PTR) { \
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05079, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, \
            "tls config: not found string param %s", #paramName, 0, 0, 0); \
            goto ERR; \
        } \
        (paramObj)->destField = BSL_SAL_Calloc((tmpParam)->valueLen + 1, sizeof(char)); \
        if ((paramObj)->destField == NULL) { \
            goto ERR; \
        } \
        memcpy((paramObj)->destField, (tmpParam)->value, (tmpParam)->valueLen); \
    } while (0)

#define PROCESS_OPTIONAL_STRING_PARAM(tmpParam, params, paramName, outString, outStringLen, nameParamName, outName) \
    do { \
        (tmpParam) = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)(params), (paramName)); \
        if ((tmpParam) == NULL) { \
            (outString) = NULL; \
        } else if ((tmpParam)->valueType == BSL_PARAM_TYPE_OCTETS_PTR) { \
            (outString) = (const char *)(tmpParam)->value; \
            (outStringLen) = (tmpParam)->valueLen; \
            (tmpParam) = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)(params), (nameParamName)); \
            if ((tmpParam) == NULL || (tmpParam)->valueType != BSL_PARAM_TYPE_OCTETS_PTR) { \
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05080, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, \
                "tls config: not found optional string param %s", #nameParamName, 0, 0, 0); \
                goto ERR; \
            } \
            (outName) = (const char *)(tmpParam)->value; \
        } else { \
            goto ERR; \
        } \
    } while (0)

/** clear the TLS configuration */
void CFG_CleanConfig(HITLS_Config *config);

/** copy the TLS configuration */
int32_t DumpConfig(HITLS_Ctx *ctx, const HITLS_Config *srcConfig);

#ifdef __cplusplus
}
#endif

#endif
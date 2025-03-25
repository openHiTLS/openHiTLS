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
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PROCESS_PARAM_INT32(tmpParam, paramObj, params, paramName, destField) \
    do { \
        (tmpParam) = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)(params), (paramName)); \
        if ((tmpParam) == NULL || (tmpParam)->valueType != BSL_PARAM_TYPE_INT32) { \
            goto ERR; \
        } \
        (paramObj)->destField = *(int32_t *)(tmpParam)->value; \
    } while (0)

#define PROCESS_PARAM_UINT16(tmpParam, paramObj, params, paramName, destField) \
    do { \
        (tmpParam) = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)(params), (paramName)); \
        if ((tmpParam) == NULL || (tmpParam)->valueType != BSL_PARAM_TYPE_UINT16) { \
            goto ERR; \
        } \
        (paramObj)->destField = *(uint16_t *)(tmpParam)->value; \
    } while (0)

#define PROCESS_PARAM_UINT32(tmpParam, paramObj, params, paramName, destField) \
    do { \
        (tmpParam) = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)(params), (paramName)); \
        if ((tmpParam) == NULL || (tmpParam)->valueType != BSL_PARAM_TYPE_UINT32) { \
            goto ERR; \
        } \
        (paramObj)->destField = *(uint32_t *)(tmpParam)->value; \
    } while (0)

#define PROCESS_PARAM_BOOL(tmpParam, paramObj, params, paramName, destField) \
    do { \
        (tmpParam) = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)(params), (paramName)); \
        if ((tmpParam) == NULL || (tmpParam)->valueType != BSL_PARAM_TYPE_BOOL) { \
            goto ERR; \
        } \
        (paramObj)->destField = *(bool *)(tmpParam)->value; \
    } while (0)

#define PROCESS_STRING_PARAM(tmpParam, paramObj, params, paramName, destField) \
    do { \
        (tmpParam) = BSL_PARAM_FindParam((BSL_Param *)(uintptr_t)(params), (paramName)); \
        if ((tmpParam) == NULL || (tmpParam)->valueType != BSL_PARAM_TYPE_OCTETS_PTR) { \
            goto ERR; \
        } \
        (paramObj)->destField = BSL_SAL_Calloc((tmpParam)->valueLen + 1, sizeof(char)); \
        if ((paramObj)->destField == NULL) { \
            goto ERR; \
        } \
        (void)memcpy_s((paramObj)->destField, (tmpParam)->valueLen + 1, (tmpParam)->value, (tmpParam)->valueLen); \
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

/**
 * @brief Common function to update config arrays
 */
int32_t ConfigUpdateTlsConfigArray(uint16_t **destArray, uint32_t *destSize, const void *sourceArray,
    uint32_t sourceLen, uint32_t versionBits, uint32_t (*getVersionBitsFn)(const void *, uint32_t),
    uint16_t (*getItemIdFn)(const void *, uint32_t));

#ifdef __cplusplus
}
#endif

#endif
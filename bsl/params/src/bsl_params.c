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

#include "hitls_build.h"
#ifdef HITLS_BSL_PARAMS
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_params.h"

#define BSL_PARAM_MAX_NUMBER 1000

int32_t BSL_PARAM_InitValue(BSL_Param *param, int32_t key, uint32_t type, void *val, uint32_t valueLen)
{
    if (key == 0) {
        BSL_ERR_PUSH_ERROR(BSL_PARAMS_INVALID_KEY);
        return BSL_PARAMS_INVALID_KEY;
    }
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    if (type != BSL_PARAM_TYPE_FUNC_PTR && type != BSL_PARAM_TYPE_CTX_PTR) {
        /* Parameter validation: param cannot be NULL, if val is NULL, valueLen must be 0 */
        if (val == NULL && valueLen != 0) {
            BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
            return BSL_INVALID_ARG;
        }
    }

    switch (type) {
        case BSL_PARAM_TYPE_UINT8:
        case BSL_PARAM_TYPE_UINT16:
        case BSL_PARAM_TYPE_UINT32:
        case BSL_PARAM_TYPE_UINT64:
        case BSL_PARAM_TYPE_OCTETS:
        case BSL_PARAM_TYPE_BOOL:
        case BSL_PARAM_TYPE_UINT32_PTR:
        case BSL_PARAM_TYPE_FUNC_PTR:
        case BSL_PARAM_TYPE_CTX_PTR:
        case BSL_PARAM_TYPE_INT32:
        case BSL_PARAM_TYPE_OCTETS_PTR:
        case BSL_PARAM_TYPE_UTF8_STR:
        case BSL_PARAM_TYPE_SIZE_T:
        case BSL_PARAM_TYPE_SIZE_T_PTR:
            param->value = val;
            param->valueLen = valueLen;
            param->valueType = type;
            param->key = key;
            param->useLen = 0;
            return BSL_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(BSL_PARAMS_INVALID_TYPE);
            return BSL_PARAMS_INVALID_TYPE;
    }
}

static int32_t ParamCheck(BSL_Param *param, int32_t key, uint32_t type)
{
    if (key == 0) {
        BSL_ERR_PUSH_ERROR(BSL_PARAMS_INVALID_KEY);
        return BSL_PARAMS_INVALID_KEY;
    }
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    if (param->key != key || param->valueType != type) {
        BSL_ERR_PUSH_ERROR(BSL_PARAMS_MISMATCH);
        return BSL_PARAMS_MISMATCH;
    }
    return BSL_SUCCESS;
}

static int32_t SetOtherValues(BSL_Param *param, uint32_t type, void *val, uint32_t len)
{
    if (param->valueLen != len || val == NULL || param->value == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    switch (type) {
        case BSL_PARAM_TYPE_UINT8:
            *(uint8_t *)param->value = *(uint8_t *)val;
            param->useLen = len;
            return BSL_SUCCESS;
        case BSL_PARAM_TYPE_UINT16:
            *(uint16_t *)param->value = *(uint16_t *)val;
            param->useLen = len;
            return BSL_SUCCESS;
        case BSL_PARAM_TYPE_UINT32:
            *(uint32_t *)param->value = *(uint32_t *)val;
            param->useLen = len;
            return BSL_SUCCESS;
        case BSL_PARAM_TYPE_UINT64:
            *(uint64_t *)param->value = *(uint64_t *)val;
            param->useLen = len;
            return BSL_SUCCESS;
        case BSL_PARAM_TYPE_OCTETS:
            (void)memcpy_s(param->value, len, val, len);
            param->useLen = len;
            return BSL_SUCCESS;
        case BSL_PARAM_TYPE_BOOL:
            *(bool *)param->value = *(bool *)val;
            param->useLen = len;
            return BSL_SUCCESS;
        case BSL_PARAM_TYPE_SIZE_T:
            *(size_t *)param->value = *(size_t *)val;
            param->useLen = len;
            return BSL_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(BSL_PARAMS_INVALID_TYPE);
            return BSL_PARAMS_INVALID_TYPE;
    }
}

int32_t BSL_PARAM_SetValue(BSL_Param *param, int32_t key, uint32_t type, void *val, uint32_t len)
{
    int32_t ret = ParamCheck(param, key, type);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    switch (type) {
        case BSL_PARAM_TYPE_OCTETS_PTR:
        case BSL_PARAM_TYPE_FUNC_PTR:
        case BSL_PARAM_TYPE_CTX_PTR:
        case BSL_PARAM_TYPE_SIZE_T_PTR:
            param->value = val;
            param->useLen = len;
            return BSL_SUCCESS;
        default:
            return SetOtherValues(param, type, val, len);
    }
}

int32_t BSL_PARAM_GetPtrValue(const BSL_Param *param, int32_t key, uint32_t type, void **val, uint32_t *valueLen)
{
    if (key == 0) {
        BSL_ERR_PUSH_ERROR(BSL_PARAMS_INVALID_KEY);
        return BSL_PARAMS_INVALID_KEY;
    }
    if (param == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    if (type != BSL_PARAM_TYPE_FUNC_PTR && type != BSL_PARAM_TYPE_CTX_PTR) {
        if (valueLen == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
            return BSL_INVALID_ARG;
        }
    }
    if (param->key != key || param->valueType != type) {
        BSL_ERR_PUSH_ERROR(BSL_PARAMS_MISMATCH);
        return BSL_PARAMS_MISMATCH;
    }
    switch (type) {
        case BSL_PARAM_TYPE_UINT32_PTR:
        case BSL_PARAM_TYPE_OCTETS_PTR:
        case BSL_PARAM_TYPE_SIZE_T_PTR:
            *val = param->value;
            *valueLen = param->valueLen;
            return BSL_SUCCESS;
        case BSL_PARAM_TYPE_FUNC_PTR:
        case BSL_PARAM_TYPE_CTX_PTR:
            *val = param->value;
            return BSL_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(BSL_PARAMS_INVALID_TYPE);
            return BSL_PARAMS_INVALID_TYPE;
    }
}

int32_t BSL_PARAM_GetValue(const BSL_Param *param, int32_t key, uint32_t type, void *val, uint32_t *valueLen)
{
    if (key == 0) {
        BSL_ERR_PUSH_ERROR(BSL_PARAMS_INVALID_KEY);
        return BSL_PARAMS_INVALID_KEY;
    }
    if (param == NULL || val == NULL || valueLen == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    if (param->key != key || param->valueType != type) {
        BSL_ERR_PUSH_ERROR(BSL_PARAMS_MISMATCH);
        return BSL_PARAMS_MISMATCH;
    }
    switch (type) {
        case BSL_PARAM_TYPE_UINT16:
        case BSL_PARAM_TYPE_UINT32:
        case BSL_PARAM_TYPE_UINT64:
        case BSL_PARAM_TYPE_OCTETS:
        case BSL_PARAM_TYPE_BOOL:
        case BSL_PARAM_TYPE_INT32:
        case BSL_PARAM_TYPE_SIZE_T:
            if (*valueLen < param->valueLen) {
                BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
                return BSL_INVALID_ARG;
            }
            (void)memcpy_s(val, param->valueLen, param->value, param->valueLen);
            *valueLen = param->valueLen;
            return BSL_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(BSL_PARAMS_INVALID_TYPE);
            return BSL_PARAMS_INVALID_TYPE;
    }
}

const BSL_Param *BSL_PARAM_FindConstParam(const BSL_Param *param, int32_t key)
{
    if (key == 0) {
        BSL_ERR_PUSH_ERROR(BSL_PARAMS_INVALID_KEY);
        return NULL;
    }
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return NULL;
    }
    int32_t index = 0;
    while (param[index].key != 0 && index < BSL_PARAM_MAX_NUMBER) {
        if (param[index].key == key) {
            return &param[index];
        }
        index++;
    }
    BSL_ERR_PUSH_ERROR(BSL_PARAMS_MISMATCH);
    return NULL;
}

BSL_Param *BSL_PARAM_FindParam(BSL_Param *param, int32_t key)
{
    if (key == 0) {
        BSL_ERR_PUSH_ERROR(BSL_PARAMS_INVALID_KEY);
        return NULL;
    }
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return NULL;
    }
    int32_t index = 0;
    while (param[index].key != 0 && index < BSL_PARAM_MAX_NUMBER) {
        if (param[index].key == key) {
            return &param[index];
        }
        index++;
    }
    BSL_ERR_PUSH_ERROR(BSL_PARAMS_MISMATCH);
    return NULL;
}

void BSL_PARAM_Free(BSL_Param *param)
{
    if (param != NULL) {
        BSL_SAL_Free(param);
    }
}

#endif

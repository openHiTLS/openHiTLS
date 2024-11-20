#include "hitls_build.h"
#ifdef HITLS_BSL_PARAMS
#include "bsl_params_internal.h"
#include "bsl_errno.h"
#include "securec.h"

int32_t BSL_Param_InitValue(BSL_Param *param, int32_t key, int32_t type, void *val, uint32_t len)
{
    if (key == 0) {
        return BSL_INVALID_ARG;
    }
    
    switch (type)
    {
        case BSL_PARAM_TYPE_UINT32_PTR:
        case BSL_PARAM_TYPE_OCTETS_PTR:
            param->value = val;
            param->valueLen = len;
            param->valueType = type;
            param->key = key;
            param->useLen = -1;
            return BSL_SUCCESS;
        default:
            return BSL_INVALID_ARG;
    }
}

int32_t BSL_Param_SetValue(BSL_Param *param, int32_t key, int32_t type, void *val, uint32_t len)
{
    if (key == 0) {
        return BSL_INVALID_ARG;
    }
    switch (type)
    {
        case BSL_PARAM_TYPE_UINT32_PTR:
        case BSL_PARAM_TYPE_OCTETS_PTR:
            param->value = val;
            param->useLen = len;
            return BSL_SUCCESS;
        case BSL_PARAM_TYPE_UINT32:
            if (param->valueLen != len) {
                return BSL_INVALID_ARG;
            }
            *(uint32_t *)param->value = *(uint32_t *)val;
            param->useLen = len;
            return BSL_SUCCESS;
        case BSL_PARAM_TYPE_OCTETS:
            if (param->valueLen < len) {
                return BSL_INVALID_ARG;
            }
            memcpy_s(param->value, len, val, len);
            param->useLen = len;
            return BSL_SUCCESS;
        default:
            return BSL_INVALID_ARG;
    }
}

int32_t BSL_Param_GetPtrValue(BSL_Param *param, int32_t key, int32_t type, void **val, uint32_t *len)
{
    if (key == 0) {
        return BSL_INVALID_ARG;
    }
    switch (type)
    {
        case BSL_PARAM_TYPE_UINT32_PTR:
        case BSL_PARAM_TYPE_OCTETS_PTR:
            if (val == NULL) {
                return BSL_INVALID_ARG;
            }
            *val = param->value;
            *len = param->valueLen;
            return BSL_SUCCESS;
        default:
            return BSL_INVALID_ARG;
    }
}

int32_t BSL_Param_GetValue(BSL_Param *param, int32_t key, int32_t type, void *val, uint32_t *len)
{
    if (key == 0) {
        return BSL_INVALID_ARG;
    }
    switch (type)
    {
        case BSL_PARAM_TYPE_UINT32:
        case BSL_PARAM_TYPE_OCTETS:
            if (val == NULL || *len < param->valueLen) {
                return BSL_INVALID_ARG;
            }
            memcpy_s(val, param->valueLen, param->value, param->valueLen);
            *len = param->valueLen;
            return BSL_SUCCESS;
        default:
            return BSL_INVALID_ARG;
    }
}

BSL_Param *BSL_Param_FindParam(BSL_Param *param, int32_t key)
{
    int32_t index = 0;
    while (param[index].key != 0) {
        if (param[index].key == key) {
            return &param[index];
        }
    }
    return NULL;
}

#endif
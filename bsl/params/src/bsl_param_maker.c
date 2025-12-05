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
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_params.h"
#include "bsl_list.h"

typedef struct {
    int32_t key;
    uint32_t type;
    void *value;
    uint32_t len;
    uint32_t allocLen;
    union {
        bool flag;
        int32_t i32;
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
    } num;
    uint32_t flag;
} BSL_PARAM_MAKER_DEF;

#define PARAM_MAKER_MALLOCED_VALUE 1

struct BslParamMaker {
    uint32_t valueLen;
    BslList *params;
};

static void PARAM_MAKER_DEF_Free(BSL_PARAM_MAKER_DEF *paramMakerDef)
{
    if (paramMakerDef == NULL) {
        return;
    }
    if ((paramMakerDef->flag & PARAM_MAKER_MALLOCED_VALUE) != 0) {
        BSL_SAL_FREE(paramMakerDef->value);
    }
    BSL_SAL_Free(paramMakerDef);
}

BSL_ParamMaker *BSL_PARAM_MAKER_New(void)
{
    BSL_ParamMaker *maker = BSL_SAL_Calloc(1, sizeof(BSL_ParamMaker));
    if (maker == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    maker->params = BSL_LIST_New(sizeof(BSL_PARAM_MAKER_DEF));
    if (maker->params == NULL) {
        BSL_SAL_Free(maker);
        BSL_ERR_PUSH_ERROR(BSL_LIST_MALLOC_FAIL);
        return NULL;
    }
    return maker;
}

static int32_t BSL_PARAM_MAKER_CheckNumberLen(uint32_t type, uint32_t len)
{
    switch (type) {
        case BSL_PARAM_TYPE_UINT8:
            if (len < sizeof(uint8_t)) {
                return BSL_INVALID_ARG;
            }
            break;
        case BSL_PARAM_TYPE_UINT16:
            if (len < sizeof(uint16_t)) {
                return BSL_INVALID_ARG;
            }
            break;
        case BSL_PARAM_TYPE_UINT32:
            if (len < sizeof(uint32_t)) {
                return BSL_INVALID_ARG;
            }
            break;
        case BSL_PARAM_TYPE_INT32:
            if (len < sizeof(int32_t)) {
                return BSL_INVALID_ARG;
            }
            break;
        case BSL_PARAM_TYPE_BOOL:
            if (len < sizeof(bool)) {
                return BSL_INVALID_ARG;
            }
            break;
        default:
            return BSL_PARAMS_INVALID_TYPE;
    }
    return BSL_SUCCESS;
}

static int32_t BSL_PARAM_MAKER_CheckInput(const BSL_ParamMaker *maker, int32_t key, const void *value, uint32_t len)
{
    if (key == 0) {
        BSL_ERR_PUSH_ERROR(BSL_PARAMS_INVALID_KEY);
        return BSL_PARAMS_INVALID_KEY;
    }
    if (maker == NULL || maker->params == NULL || (value == NULL && len != 0)) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (((uint32_t)maker->params->count + 1) > UINT32_MAX / sizeof(BSL_Param)) {
        return BSL_PARAMS_OUT_LIMIT;
    }
    return BSL_SUCCESS;
}

int32_t BSL_PARAM_MAKER_PushValue(BSL_ParamMaker *maker, int32_t key, uint32_t type, void *value, uint32_t len)
{
    int32_t ret = BSL_PARAM_MAKER_CheckInput(maker, key, value, len);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    BSL_PARAM_MAKER_DEF *paramMakerDef = BSL_SAL_Calloc(1, sizeof(BSL_PARAM_MAKER_DEF));
    if (paramMakerDef == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    paramMakerDef->key = key;
    paramMakerDef->type = type;
    paramMakerDef->len = len;
    switch (type) {
        case BSL_PARAM_TYPE_UINT8:
        case BSL_PARAM_TYPE_UINT16:
        case BSL_PARAM_TYPE_UINT32:
        case BSL_PARAM_TYPE_INT32:
        case BSL_PARAM_TYPE_BOOL:
            ret = BSL_PARAM_MAKER_CheckNumberLen(type, len);
            if (ret != BSL_SUCCESS) {
                goto EXIT;
            }
            (void)memcpy_s(&paramMakerDef->num, len, value, len);
            paramMakerDef->allocLen = len;
            break;
        case BSL_PARAM_TYPE_UINT32_PTR:
        case BSL_PARAM_TYPE_OCTETS_PTR:
        case BSL_PARAM_TYPE_FUNC_PTR:
        case BSL_PARAM_TYPE_CTX_PTR:
            paramMakerDef->value = value;
            paramMakerDef->allocLen = 0;
            break;
        case BSL_PARAM_TYPE_UTF8_STR:
            paramMakerDef->value = value;
            paramMakerDef->allocLen = len + 1;
            break;
        case BSL_PARAM_TYPE_OCTETS:
            paramMakerDef->value = value;
            paramMakerDef->allocLen = len;
            break;
        default:
            ret = BSL_PARAMS_INVALID_TYPE;
            goto EXIT;
    }
    maker->valueLen += paramMakerDef->allocLen;
    ret = BSL_LIST_AddElement(maker->params, paramMakerDef, BSL_LIST_POS_END);
EXIT:
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        PARAM_MAKER_DEF_Free(paramMakerDef);
    }
    return ret;
}

int32_t BSL_PARAM_MAKER_DeepPushValue(BSL_ParamMaker *maker, int32_t key, uint32_t type, void *value, uint32_t len)
{
    int32_t ret = BSL_PARAM_MAKER_CheckInput(maker, key, value, len);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    BSL_PARAM_MAKER_DEF *paramMakerDef = BSL_SAL_Calloc(1, sizeof(BSL_PARAM_MAKER_DEF));
    if (paramMakerDef == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    paramMakerDef->key = key;
    paramMakerDef->type = type;
    paramMakerDef->len = len;
    uint32_t allocLen = 0;
    switch (type) {
        case BSL_PARAM_TYPE_UTF8_STR:
            allocLen = len + 1;
            break;
        case BSL_PARAM_TYPE_OCTETS:
            allocLen = len;
            break;
        default:
            ret = BSL_PARAMS_INVALID_TYPE;
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
    }
    paramMakerDef->value = BSL_SAL_Malloc(len);
    if (paramMakerDef->value == NULL && value != NULL) {
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    paramMakerDef->flag |= PARAM_MAKER_MALLOCED_VALUE;
    (void)memcpy_s(paramMakerDef->value, len, value, len);
    paramMakerDef->allocLen = allocLen;
    maker->valueLen += paramMakerDef->allocLen;
    ret = BSL_LIST_AddElement(maker->params, paramMakerDef, BSL_LIST_POS_END);
EXIT:
    if (ret != BSL_SUCCESS) {
        PARAM_MAKER_DEF_Free(paramMakerDef);
    }
    return ret;
}

static int32_t BSL_PARAM_MAKER_NumberConvert(BSL_PARAM_MAKER_DEF *paramMakerDef, BSL_Param *params,
    int32_t i, uint8_t **valueIndex)
{
    uint8_t *value = *valueIndex;
    (void)memcpy_s(value, paramMakerDef->len, &paramMakerDef->num, paramMakerDef->len);
    *valueIndex += paramMakerDef->allocLen;
    return BSL_PARAM_InitValue(&params[i], paramMakerDef->key, paramMakerDef->type, value, paramMakerDef->len);
}

static int32_t BSL_PARAM_MAKER_PointerConvert(BSL_PARAM_MAKER_DEF *paramMakerDef, BSL_Param *params, int32_t i)
{
    void *value = paramMakerDef->value;
    return BSL_PARAM_InitValue(&params[i], paramMakerDef->key, paramMakerDef->type, value, paramMakerDef->len);
}

static int32_t BSL_PARAM_MAKER_StringConvert(BSL_PARAM_MAKER_DEF *paramMakerDef, BSL_Param *params,
    int32_t i, uint8_t **valueIndex)
{
    uint8_t *value = *valueIndex;
    if (paramMakerDef->value != NULL) {
        (void)memcpy_s(value, paramMakerDef->len, paramMakerDef->value, paramMakerDef->len);
    } else {
        (void)memset_s(value, paramMakerDef->len, 0, paramMakerDef->len);
    }
    if (paramMakerDef->type == BSL_PARAM_TYPE_UTF8_STR) {
        ((char *)(value))[paramMakerDef->len] = '\0';
    }
    *valueIndex += paramMakerDef->allocLen;
    return BSL_PARAM_InitValue(&params[i], paramMakerDef->key, paramMakerDef->type, value, paramMakerDef->len);
}

static int32_t BSL_PARAM_MAKER_CalculateSize(BSL_ParamMaker *maker, uint32_t *paramSize)
{
    if (maker == NULL || maker->params == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    BslList *list = maker->params;
    *paramSize = ((uint32_t)list->count + 1) * sizeof(BSL_Param);
    if (*paramSize > UINT32_MAX - maker->valueLen) {
        return BSL_PARAMS_OUT_LIMIT;
    } else {
        *paramSize += maker->valueLen;
    }

    return BSL_SUCCESS;
}

BSL_Param *BSL_PARAM_MAKER_ToParam(BSL_ParamMaker *maker)
{
    uint32_t paramSize = 0;
    if (BSL_PARAM_MAKER_CalculateSize(maker, &paramSize) != BSL_SUCCESS) {
        return NULL;
    }
    
    BSL_Param *params = BSL_SAL_Calloc(1, paramSize);
    if (params == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    
    BslList *list = maker->params;
    uint8_t *valueIndex = (uint8_t *)(list->count + 1 + params);
    BSL_PARAM_MAKER_DEF **paramMakerDef = BSL_LIST_First(list);
    int i = 0;

    while (paramMakerDef != NULL) {
        int32_t ret;
        switch ((*paramMakerDef)->type) {
            case BSL_PARAM_TYPE_UINT8:
            case BSL_PARAM_TYPE_UINT16:
            case BSL_PARAM_TYPE_UINT32:
            case BSL_PARAM_TYPE_INT32:
            case BSL_PARAM_TYPE_BOOL:
                ret = BSL_PARAM_MAKER_NumberConvert(*paramMakerDef, params, i++, &valueIndex);
                break;
            case BSL_PARAM_TYPE_UINT32_PTR:
            case BSL_PARAM_TYPE_FUNC_PTR:
            case BSL_PARAM_TYPE_CTX_PTR:
            case BSL_PARAM_TYPE_OCTETS_PTR:
                ret = BSL_PARAM_MAKER_PointerConvert(*paramMakerDef, params, i++);
                break;
            case BSL_PARAM_TYPE_OCTETS:
            case BSL_PARAM_TYPE_UTF8_STR:
            default:
                ret = BSL_PARAM_MAKER_StringConvert(*paramMakerDef, params, i++, &valueIndex);
                break;
        }

        if (ret != BSL_SUCCESS) {
            BSL_SAL_Free(params);
            return NULL;
        }
        paramMakerDef = BSL_LIST_Next(list);
    }
    return params;
}

void BSL_PARAM_MAKER_Free(BSL_ParamMaker *maker)
{
    if (maker == NULL) {
        return;
    }
    BSL_LIST_FREE(maker->params, (BSL_LIST_PFUNC_FREE)PARAM_MAKER_DEF_Free);
    BSL_SAL_Free(maker);
    maker = NULL;
}

#endif
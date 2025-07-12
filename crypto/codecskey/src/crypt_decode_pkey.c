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

#if defined(HITLS_CRYPTO_CODECSKEY)
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "sal_file.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_codecs.h"
#include "crypt_provider.h"
#include "crypt_eal_pkey.h"
#include "bsl_types.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "eal_pkey.h"
#include "crypt_encode_decode_local.h"
#include "crypt_encode_decode_key.h"

#if defined(HITLS_CRYPTO_PROVIDER)
static int32_t SetDecodePoolParamForKey(CRYPT_DECODER_PoolCtx *poolCtx, char *targetType, char *targetFormat)
{
    int32_t ret = CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_TARGET_FORMAT, targetFormat,
        strlen(targetFormat));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_TARGET_TYPE, targetType, strlen(targetType));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return ret;
}

static int32_t GetObjectFromOutData(BSL_Param *outData, void **object)
{
    if (outData == NULL || object == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_Param *param = BSL_PARAM_FindParam(outData, CRYPT_PARAM_DECODE_OBJECT_DATA);
    if (param == NULL || param->valueType != BSL_PARAM_TYPE_CTX_PTR || param->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *object = param->value;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_ProviderDecodeBuffKeyInner(CRYPT_EAL_LibCtx *libCtx, const char *attrName, int32_t keyType,
    const char *format, const char *type, BSL_Buffer *encode, const BSL_Buffer *pwd, CRYPT_EAL_PkeyCtx **ealPKey)
{
    char *targetType = "HIGH_KEY";
    char *targetFormat = "OBJECT";
    uint32_t index = 0;
    BSL_Param *outParam = NULL;
    bool isFreeOutData = false;
    BSL_Param input[3] = {{0}, {0}, BSL_PARAM_END};
    CRYPT_EAL_PkeyCtx *tmpPKey = NULL;
    if (encode == NULL || encode->data == NULL || encode->dataLen == 0 || ealPKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_DECODER_PoolCtx *poolCtx = CRYPT_DECODE_PoolNewCtx(libCtx, attrName, keyType, format, type);
    if (poolCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = SetDecodePoolParamForKey(poolCtx, targetType, targetFormat);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    (void)BSL_PARAM_InitValue(&input[index++], CRYPT_PARAM_DECODE_BUFFER_DATA, BSL_PARAM_TYPE_OCTETS, encode->data,
        encode->dataLen);
    if (pwd != NULL) {
        (void)BSL_PARAM_InitValue(&input[index++], CRYPT_PARAM_DECODE_PASSWORD, BSL_PARAM_TYPE_OCTETS, pwd->data,
            pwd->dataLen);
    }
    ret = CRYPT_DECODE_PoolDecode(poolCtx, input, &outParam);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ret = GetObjectFromOutData(outParam, (void **)(&tmpPKey));
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    int32_t algId = CRYPT_EAL_PkeyGetId(tmpPKey);
    if (keyType != BSL_CID_UNKNOWN && algId != keyType) {
        ret = CRYPT_EAL_ERR_ALGID;
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        goto EXIT;
    }
    ret = CRYPT_DECODE_PoolCtrl(poolCtx, CRYPT_DECODE_POOL_CMD_SET_FLAG_FREE_OUT_DATA, &isFreeOutData, sizeof(bool));
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    *ealPKey = tmpPKey;
    BSL_SAL_Free(outParam);
EXIT:
    CRYPT_DECODE_PoolFreeCtx(poolCtx);
    return ret;
}


#endif /* HITLS_CRYPTO_PROVIDER */

int32_t CRYPT_EAL_ProviderDecodeBuffKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, int32_t keyType,
    const char *format, const char *type, BSL_Buffer *encode, const BSL_Buffer *pwd, CRYPT_EAL_PkeyCtx **ealPKey)
{
#ifdef HITLS_CRYPTO_PROVIDER
    return CRYPT_EAL_ProviderDecodeBuffKeyInner(libCtx, attrName, keyType, format, type, encode, pwd, ealPKey);
#else
    (void)libCtx;
    (void)attrName;
    (void)keyType;
    int32_t encodeType = CRYPT_EAL_GetEncodeType(type);
    int32_t encodeFormat = CRYPT_EAL_GetEncodeFormat(format);
    if (pwd == NULL) {
        return CRYPT_EAL_DecodeBuffKey(encodeFormat, encodeType, encode, NULL, 0, ealPKey);
    } else {
        return CRYPT_EAL_DecodeBuffKey(encodeFormat, encodeType, encode, pwd->data, pwd->dataLen, ealPKey);
    }
#endif
}

#ifdef HITLS_BSL_SAL_FILE
int32_t CRYPT_EAL_ProviderDecodeFileKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, int32_t keyType,
    const char *format, const char *type, const char *path, const BSL_Buffer *pwd, CRYPT_EAL_PkeyCtx **ealPKey)
{
    if (path == NULL || strlen(path) > PATH_MAX_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_Buffer encode = {data, dataLen};
    ret = CRYPT_EAL_ProviderDecodeBuffKey(libCtx, attrName, keyType, format, type, &encode, pwd, ealPKey);
    BSL_SAL_Free(data);
    return ret;
}
#endif /* HITLS_BSL_SAL_FILE */

#endif /* HITLS_CRYPTO_CODECSKEY */

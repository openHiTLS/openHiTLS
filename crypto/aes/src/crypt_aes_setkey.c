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
#ifdef HITLS_CRYPTO_AES

#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "crypt_aes_local.h"
#include "bsl_sal.h"

int32_t CRYPT_AES_SetEncryptKey128(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != 16) {
        BSL_ERR_PUSH_ERROR(CRYPT_AES_ERR_KEYLEN);
        return CRYPT_AES_ERR_KEYLEN;
    }
    SetEncryptKey128(ctx, key);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_AES_SetEncryptKey192(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != 24) {
        BSL_ERR_PUSH_ERROR(CRYPT_AES_ERR_KEYLEN);
        return CRYPT_AES_ERR_KEYLEN;
    }
    SetEncryptKey192(ctx, key);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_AES_SetEncryptKey256(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != 32) {
        BSL_ERR_PUSH_ERROR(CRYPT_AES_ERR_KEYLEN);
        return CRYPT_AES_ERR_KEYLEN;
    }
    SetEncryptKey256(ctx, key);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_AES_SetDecryptKey128(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != 16) {
        BSL_ERR_PUSH_ERROR(CRYPT_AES_ERR_KEYLEN);
        return CRYPT_AES_ERR_KEYLEN;
    }
    SetDecryptKey128(ctx, key);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_AES_SetDecryptKey192(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != 24) {
        BSL_ERR_PUSH_ERROR(CRYPT_AES_ERR_KEYLEN);
        return CRYPT_AES_ERR_KEYLEN;
    }
    SetDecryptKey192(ctx, key);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_AES_SetDecryptKey256(CRYPT_AES_Key *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != 32) {
        BSL_ERR_PUSH_ERROR(CRYPT_AES_ERR_KEYLEN);
        return CRYPT_AES_ERR_KEYLEN;
    }
    SetDecryptKey256(ctx, key);
    return CRYPT_SUCCESS;
}

void CRYPT_AES_Clean(CRYPT_AES_Key *ctx)
{
    BSL_SAL_CleanseData((void *)(ctx), sizeof(CRYPT_AES_Key));
}
#endif /* HITLS_CRYPTO_AES */

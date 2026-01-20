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
#if defined(HITLS_CRYPTO_CBC_MAC) || defined(HITLS_CRYPTO_CMAC)
#include <stdlib.h>
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "crypt_local_types.h"
#include "cipher_mac_common.h"

int32_t CipherMacInitCtx(Cipher_MAC_Common_Ctx *ctx, const EAL_SymMethod *method)
{
    if (ctx == NULL || method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    void *key = (void *)BSL_SAL_Calloc(1u, method->ctxSize);
    if (key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    // set key and set method
    ctx->key = key;
    ctx->method = method;
    return CRYPT_SUCCESS;
}

void CipherMacDeinitCtx(Cipher_MAC_Common_Ctx *ctx)
{
    if (ctx == NULL || ctx->method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return;
    }
    const EAL_SymMethod *method = ctx->method;
    BSL_SAL_CleanseData((void *)(ctx->key), method->ctxSize);
    BSL_SAL_FREE(ctx->key);
}

int32_t CipherMacInit(Cipher_MAC_Common_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL || ctx->method == NULL || (key == NULL && len != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = ctx->method->setEncryptKey(ctx->key, key, len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memset_s(ctx->data, CIPHER_MAC_MAXBLOCKSIZE, 0, CIPHER_MAC_MAXBLOCKSIZE);
    ctx->len = 0;
    return CRYPT_SUCCESS;
}

int32_t CipherMacUpdate(Cipher_MAC_Common_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    if (ctx == NULL || ctx->method == NULL || (in == NULL && len != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const EAL_SymMethod *method = ctx->method;
    int32_t ret;
    uint32_t blockSize = method->blockSize;
    const uint8_t *inTmp = in;
    uint32_t lenTmp = len;
    if (ctx->len > 0) {
        if (ctx->len > (UINT32_MAX - lenTmp)) {
            BSL_ERR_PUSH_ERROR(CRYPT_CMAC_INPUT_OVERFLOW);
            return CRYPT_CMAC_INPUT_OVERFLOW;
        }
        uint32_t end = (ctx->len + lenTmp) > (blockSize) ? (blockSize) : (ctx->len + lenTmp);
        for (uint32_t i = ctx->len; i < end; i++) {
            ctx->left[i] = (*inTmp);
            inTmp++;
        }
        lenTmp -= (end - ctx->len);
        if (lenTmp == 0) {
            ctx->len = end;
            return CRYPT_SUCCESS;
        }
        DATA_XOR(ctx->left, ctx->data, ctx->left, blockSize);
        ret = method->encryptBlock(ctx->key, ctx->left, ctx->data, blockSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    while (lenTmp > blockSize) {
        DATA_XOR(inTmp, ctx->data, ctx->left, blockSize);
        ret = method->encryptBlock(ctx->key, ctx->left, ctx->data, blockSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        lenTmp -= blockSize;
        inTmp += blockSize;
    }
    for (uint32_t i = 0; i < lenTmp; i++) {
        ctx->left[i] = inTmp[i];
    }
    ctx->len = lenTmp;
    return CRYPT_SUCCESS;
}

int32_t CipherMacReinit(Cipher_MAC_Common_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    (void)memset_s(ctx->data, CIPHER_MAC_MAXBLOCKSIZE, 0, CIPHER_MAC_MAXBLOCKSIZE);
    ctx->len = 0;
    return CRYPT_SUCCESS;
}

int32_t CipherMacDeinit(Cipher_MAC_Common_Ctx *ctx)
{
    if (ctx == NULL || ctx->method == NULL) {
        return CRYPT_NULL_INPUT;
    }

    const uint32_t ctxSize = ctx->method->ctxSize;
    BSL_SAL_CleanseData(ctx->key, ctxSize);
    (void)memset_s(ctx->data, CIPHER_MAC_MAXBLOCKSIZE, 0, CIPHER_MAC_MAXBLOCKSIZE);
    (void)memset_s(ctx->left, CIPHER_MAC_MAXBLOCKSIZE, 0, CIPHER_MAC_MAXBLOCKSIZE);
    ctx->len = 0;
    return CRYPT_SUCCESS;
}

int32_t CipherMacGetMacLen(const Cipher_MAC_Common_Ctx *ctx, void *val, uint32_t len)
{
    if (ctx == NULL || ctx->method == NULL || val == NULL || len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    *(uint32_t *)val = ctx->method->blockSize;
    return CRYPT_SUCCESS;
}
#endif // #if defined(HITLS_CRYPTO_CBC_MAC) || defined(HITLS_CRYPTO_CMAC)

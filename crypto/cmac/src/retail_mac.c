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
#ifdef HITLS_CRYPTO_RETAIL_MAC

#include <stdint.h>
#include "bsl_sal.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "cipher_mac_common.h"
#include "crypt_errno.h"
#include "crypt_retail_mac.h"
#include "eal_mac_local.h"
#include "securec.h"

#define RETAIL_MAC_KEY_LEN 16
#define RETAIL_MAC_KEY_PART_LEN 8

CRYPT_RETAIL_MAC_Ctx *CRYPT_RETAIL_MAC_NewCtx(CRYPT_MAC_AlgId id)
{
    EAL_MacDepMethod method = {0};
    int32_t ret = EAL_MacFindDepMethod(id, NULL, NULL, &method, NULL, false);
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }

    CRYPT_RETAIL_MAC_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_RETAIL_MAC_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    ret = CipherMacInitCtx(&ctx->common, method.method.sym);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(ctx);
        return NULL;
    }

    ctx->key2 = BSL_SAL_Calloc(1, method.method.sym->ctxSize);
    if (ctx->key2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        CipherMacDeinitCtx(&ctx->common);
        BSL_SAL_Free(ctx);
        return NULL;
    }
    return ctx;
}

CRYPT_RETAIL_MAC_Ctx *CRYPT_RETAIL_MAC_NewCtxEx(void *libCtx, CRYPT_MAC_AlgId id)
{
    (void)libCtx;
    return CRYPT_RETAIL_MAC_NewCtx(id);
}

int32_t CRYPT_RETAIL_MAC_InitEx(CRYPT_RETAIL_MAC_Ctx *ctx, const uint8_t *key, uint32_t len, void *param)
{
    (void)param;
    if (len != RETAIL_MAC_KEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_RETAIL_MAC_ERR_KEYLEN);
        return CRYPT_RETAIL_MAC_ERR_KEYLEN;
    }

    int32_t ret = CipherMacInit(&ctx->common, key, RETAIL_MAC_KEY_PART_LEN);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    const EAL_SymMethod *method = ctx->common.method;
    ret = method->setDecryptKey(ctx->key2, key + RETAIL_MAC_KEY_PART_LEN, RETAIL_MAC_KEY_PART_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

int32_t CRYPT_RETAIL_MAC_Init(CRYPT_RETAIL_MAC_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    return CRYPT_RETAIL_MAC_InitEx(ctx, key, len, NULL);
}

int32_t CRYPT_RETAIL_MAC_Update(CRYPT_RETAIL_MAC_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CipherMacUpdate(&ctx->common, in, len);
}

static int32_t RetailMacProcessBlock(CRYPT_RETAIL_MAC_Ctx *ctx)
{
    const EAL_SymMethod *method = ctx->common.method;
    uint32_t blockSize = method->blockSize;
    DATA_XOR(ctx->common.left, ctx->common.data, ctx->common.left, blockSize);
    int32_t ret = method->encryptBlock(ctx->common.key, ctx->common.left, ctx->common.data, blockSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_RETAIL_MAC_Final(CRYPT_RETAIL_MAC_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    if (ctx == NULL || ctx->common.method == NULL || len == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const EAL_SymMethod *method = ctx->common.method;
    uint32_t blockSize = method->blockSize;
    if (*len < blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_RETAIL_MAC_OUT_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_RETAIL_MAC_OUT_BUFF_LEN_NOT_ENOUGH;
    }

    int32_t ret;
    uint32_t length = ctx->common.len;
    if (length == blockSize) {
        ret = RetailMacProcessBlock(ctx);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        length = 0;
    }
    ctx->common.left[length++] = 0x80; // 0x80: The high bit is filled with 1
    if (length < blockSize) {
        (void)memset_s(ctx->common.left + length, blockSize - length, 0, blockSize - length);
    }

    ret = RetailMacProcessBlock(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // common.left is reused
    ret = method->decryptBlock(ctx->key2, ctx->common.data, ctx->common.left, blockSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = method->encryptBlock(ctx->common.key, ctx->common.left, out, blockSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *len = blockSize;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RETAIL_MAC_Reinit(CRYPT_RETAIL_MAC_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CipherMacReinit(&ctx->common);
}

int32_t CRYPT_RETAIL_MAC_Deinit(CRYPT_RETAIL_MAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->common.method == NULL || ctx->key2 == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CipherMacDeinit(&ctx->common);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    const uint32_t ctxSize = ctx->common.method->ctxSize;
    BSL_SAL_CleanseData(ctx->key2, ctxSize);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_RETAIL_MAC_Ctrl(CRYPT_RETAIL_MAC_Ctx *ctx, uint32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_GET_MACLEN:
            return CipherMacGetMacLen(&ctx->common, val, len);
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(CRYPT_RETAIL_MAC_ERR_UNSUPPORTED_CTRL_OPTION);
    return CRYPT_RETAIL_MAC_ERR_UNSUPPORTED_CTRL_OPTION;
}

void CRYPT_RETAIL_MAC_FreeCtx(CRYPT_RETAIL_MAC_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return;
    }
    if (ctx->key2 != NULL && ctx->common.method != NULL) {
        BSL_SAL_CleanseData(ctx->key2, ctx->common.method->ctxSize);
        BSL_SAL_Free(ctx->key2);
    }
    CipherMacDeinitCtx(&ctx->common);
    BSL_SAL_Free(ctx);
}

CRYPT_RETAIL_MAC_Ctx *CRYPT_RETAIL_MAC_DupCtx(const CRYPT_RETAIL_MAC_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    CRYPT_RETAIL_MAC_Ctx *newCtx = BSL_SAL_Dump(ctx, sizeof(CRYPT_RETAIL_MAC_Ctx));
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    void *key = BSL_SAL_Dump(ctx->common.key, ctx->common.method->ctxSize);
    if (key == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(newCtx);
        return NULL;
    }

    void *key2 = BSL_SAL_Dump(ctx->key2, ctx->common.method->ctxSize);
    if (key2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_ClearFree(key, ctx->common.method->ctxSize);
        BSL_SAL_Free(newCtx);
        return NULL;
    }

    newCtx->common.key = key;
    newCtx->key2 = key2;
    return newCtx;
}

#endif
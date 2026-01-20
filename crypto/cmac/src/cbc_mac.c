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
#ifdef HITLS_CRYPTO_CBC_MAC
#include <stdint.h>
#include "bsl_sal.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "cipher_mac_common.h"
#include "crypt_errno.h"
#include "crypt_cbc_mac.h"
#include "eal_mac_local.h"

CRYPT_CBC_MAC_Ctx *CRYPT_CBC_MAC_NewCtx(CRYPT_MAC_AlgId id)
{
    EAL_MacDepMethod method = {0};
    int32_t ret = EAL_MacFindDepMethod(id, NULL, NULL, &method, NULL, false);
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }
    CRYPT_CBC_MAC_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_CBC_MAC_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ret = CipherMacInitCtx(&ctx->common, method.method.sym);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(ctx);
        return NULL;
    }
    ctx->paddingType = CRYPT_PADDING_MAX_COUNT;
    return ctx;
}

CRYPT_CBC_MAC_Ctx *CRYPT_CBC_MAC_NewCtxEx(void *libCtx, CRYPT_MAC_AlgId id)
{
    (void)libCtx;
    return CRYPT_CBC_MAC_NewCtx(id);
}

int32_t CRYPT_CBC_MAC_Init(CRYPT_CBC_MAC_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CipherMacInit(&ctx->common, key, len);
}

int32_t CRYPT_CBC_MAC_InitEx(CRYPT_CBC_MAC_Ctx *ctx, const uint8_t *key, uint32_t len, void *param)
{
    (void)param;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CipherMacInit(&ctx->common, key, len);
}

int32_t CRYPT_CBC_MAC_Update(CRYPT_CBC_MAC_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->paddingType == CRYPT_PADDING_MAX_COUNT) {
        BSL_ERR_PUSH_ERROR(CRYPT_CBC_MAC_PADDING_NOT_SET);
        return CRYPT_CBC_MAC_PADDING_NOT_SET;
    }
    return CipherMacUpdate(&ctx->common, in, len);
}

static int32_t CbcMacPadding(CRYPT_CBC_MAC_Ctx *ctx)
{
    const EAL_SymMethod *method = ctx->common.method;
    uint32_t length = ctx->common.len;
    uint32_t padLen = method->blockSize - length;
    switch (ctx->paddingType) {
        case CRYPT_PADDING_ZEROS:
            for (uint32_t i = 0; i < padLen; i++) {
                ctx->common.left[length++] = 0;
            }
            ctx->common.len = length;
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_CBC_MAC_PADDING_NOT_SUPPORT);
            return CRYPT_CBC_MAC_PADDING_NOT_SUPPORT;
    }
}

int32_t CRYPT_CBC_MAC_Final(CRYPT_CBC_MAC_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    if (ctx == NULL || ctx->common.method == NULL || len == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const EAL_SymMethod *method = ctx->common.method;
    uint32_t blockSize = method->blockSize;
    if (*len < blockSize) {
        BSL_ERR_PUSH_ERROR(CRYPT_CBC_MAC_OUT_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_CBC_MAC_OUT_BUFF_LEN_NOT_ENOUGH;
    }

    int32_t ret = CbcMacPadding(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    DATA_XOR(ctx->common.left, ctx->common.data, ctx->common.left, blockSize);
    ret = method->encryptBlock(ctx->common.key, ctx->common.left, out, blockSize);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *len = blockSize;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CBC_MAC_Reinit(CRYPT_CBC_MAC_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CipherMacReinit(&ctx->common);
}

int32_t CRYPT_CBC_MAC_Deinit(CRYPT_CBC_MAC_Ctx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    return CipherMacDeinit(&ctx->common);
}

int32_t CRYPT_CBC_MAC_Ctrl(CRYPT_CBC_MAC_Ctx *ctx, uint32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_SET_CBC_MAC_PADDING:
            if (len != sizeof(CRYPT_PaddingType)) {
                BSL_ERR_PUSH_ERROR(CRYPT_CBC_MAC_ERR_CTRL_LEN);
                return CRYPT_CBC_MAC_ERR_CTRL_LEN;
            }
            ctx->paddingType = *(CRYPT_PaddingType*)val;
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_GET_MACLEN:
            return CipherMacGetMacLen(&ctx->common, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_CBC_MAC_ERR_UNSUPPORTED_CTRL_OPTION);
            return CRYPT_CBC_MAC_ERR_UNSUPPORTED_CTRL_OPTION;
    }
}

void CRYPT_CBC_MAC_FreeCtx(CRYPT_CBC_MAC_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return;
    }
    CipherMacDeinitCtx(&ctx->common);
    BSL_SAL_Free(ctx);
}

CRYPT_CBC_MAC_Ctx *CRYPT_CBC_MAC_DupCtx(const CRYPT_CBC_MAC_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    CRYPT_CBC_MAC_Ctx *newCtx = BSL_SAL_Dump(ctx, sizeof(CRYPT_CBC_MAC_Ctx));
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
    newCtx->common.key = key;
    return newCtx;
}
#endif

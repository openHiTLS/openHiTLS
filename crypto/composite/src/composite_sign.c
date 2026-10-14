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
#ifdef HITLS_CRYPTO_COMPOSITE_SIGN
#include <string.h>
#include "composite_local.h"
#include "crypt_utils.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"

static const uint8_t PREFIX[] = {0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x65, 0x41, 0x6C,
                                 0x67, 0x6F, 0x72, 0x69, 0x74, 0x68, 0x6D, 0x53, 0x69, 0x67, 0x6E,
                                 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x32, 0x30, 0x32, 0x35};

static int32_t CompositeGetPreHashLen(CRYPT_MD_AlgId hashId, uint32_t *digestLen)
{
    uint32_t len = CRYPT_EAL_MdGetDigestSize(hashId);
    RETURN_RET_IF(len == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
    *digestLen = len;
    return CRYPT_SUCCESS;
}

static int32_t CompositeMsgEncodeDigest(CRYPT_CompositeCtx *ctx, const uint8_t *digest, uint32_t digestLen,
                                        CRYPT_Data *msg)
{
    const char *label = ctx->info->label;
    uint32_t prefixLen = COMPOSITE_SIGNATURE_PREFIX_LEN;
    uint32_t labelLen = (uint32_t)strlen(label);
    msg->len = prefixLen + labelLen + 1 + ctx->ctxLen + digestLen;
    msg->data = (uint8_t *)BSL_SAL_Malloc(msg->len);
    RETURN_RET_IF(msg->data == NULL, CRYPT_MEM_ALLOC_FAIL);
    uint8_t *ptr = msg->data;
    memcpy(ptr, PREFIX, prefixLen);
    ptr += prefixLen;
    memcpy(ptr, label, labelLen);
    ptr += labelLen;
    *ptr = ctx->ctxLen;
    ptr++;
    if (ctx->ctxInfo != NULL && ctx->ctxLen > 0) {
        memcpy(ptr, ctx->ctxInfo, ctx->ctxLen);
        ptr += ctx->ctxLen;
    }
    memcpy(ptr, digest, digestLen);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_COMPOSITE_SignData(CRYPT_CompositeCtx *ctx, const uint8_t *data, uint32_t dataLen,
                                 uint8_t *sign, uint32_t *signLen)
{
    uint32_t expectedDigestLen = 0;
    uint32_t requiredSignLen = 0;
    int32_t ret;

    RETURN_RET_IF(ctx == NULL || sign == NULL || signLen == NULL || (data == NULL && dataLen != 0), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(ctx->info->kind != CRYPT_COMPOSITE_KIND_SIGN, CRYPT_NOT_SUPPORT);
    RETURN_RET_IF_ERR(CompositeGetPreHashLen(ctx->info->alg.sign.hashId, &expectedDigestLen), ret);
    RETURN_RET_IF(dataLen != expectedDigestLen, CRYPT_INVALID_ARG);
    RETURN_RET_IF_ERR_EX(CRYPT_COMPOSITE_Ctrl(ctx, CRYPT_CTRL_GET_SIGNLEN,
        &requiredSignLen, sizeof(requiredSignLen)), ret);
    RETURN_RET_IF(*signLen < requiredSignLen, CRYPT_COMPOSITE_INVALID_SIG_LEN);

    CRYPT_Data msg = {0};
    uint8_t *tmpSign = NULL;
    uint32_t pqcSigLen = ctx->info->alg.sign.pqcSigLen;
    uint32_t tradSigLen = requiredSignLen - pqcSigLen;
    RETURN_RET_IF_ERR(CompositeMsgEncodeDigest(ctx, data, dataLen, &msg), ret);
    tmpSign = (uint8_t *)BSL_SAL_Malloc(requiredSignLen);
    ret = CRYPT_MEM_ALLOC_FAIL;
    GOTO_ERR_IF_TRUE(tmpSign == NULL, ret);
    GOTO_ERR_IF(CRYPT_EAL_PkeyCtrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctx->info->label,
        (uint32_t)strlen(ctx->info->label)), ret);
    GOTO_ERR_IF(CRYPT_EAL_PkeySign(ctx->pqcCtx, CRYPT_MD_MAX, msg.data, msg.len, tmpSign, &pqcSigLen), ret);
    GOTO_ERR_IF(CRYPT_EAL_PkeySign(ctx->tradCtx, ctx->info->alg.sign.tradHashId, msg.data, msg.len, tmpSign + pqcSigLen,
        &tradSigLen), ret);
    memcpy(sign, tmpSign, pqcSigLen + tradSigLen);
    *signLen = pqcSigLen + tradSigLen;
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_ClearFree(tmpSign, requiredSignLen);
    BSL_SAL_ClearFree(msg.data, msg.len);
    return ret;
}

int32_t CRYPT_COMPOSITE_Sign(CRYPT_CompositeCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                             uint8_t *sign, uint32_t *signLen)
{
    int32_t ret;
    uint8_t digest[64];
    uint32_t digestLen = sizeof(digest);

    RETURN_RET_IF(ctx == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(ctx->info->kind != CRYPT_COMPOSITE_KIND_SIGN, CRYPT_NOT_SUPPORT);
    RETURN_RET_IF((CRYPT_MD_AlgId)algId != ctx->info->alg.sign.hashId, CRYPT_INVALID_ARG);
    RETURN_RET_IF_ERR(CRYPT_EAL_ProviderMd(ctx->libCtx, ctx->info->alg.sign.hashId, NULL, data, dataLen, digest, &digestLen),
        ret);
    return CRYPT_COMPOSITE_SignData(ctx, digest, digestLen, sign, signLen);
}

int32_t CRYPT_COMPOSITE_VerifyData(CRYPT_CompositeCtx *ctx, const uint8_t *data, uint32_t dataLen,
                                   const uint8_t *sign, uint32_t signLen)
{
    int32_t ret;
    uint32_t expectedDigestLen = 0;

    RETURN_RET_IF(ctx == NULL || sign == NULL || (data == NULL && dataLen != 0), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(ctx->info->kind != CRYPT_COMPOSITE_KIND_SIGN, CRYPT_NOT_SUPPORT);
    RETURN_RET_IF(signLen < ctx->info->alg.sign.pqcSigLen, CRYPT_COMPOSITE_INVALID_SIG_LEN);
    RETURN_RET_IF_ERR(CompositeGetPreHashLen(ctx->info->alg.sign.hashId, &expectedDigestLen), ret);
    RETURN_RET_IF(dataLen != expectedDigestLen, CRYPT_INVALID_ARG);

    CRYPT_Data msg = {0};
    uint32_t pqcSigLen = ctx->info->alg.sign.pqcSigLen;
    uint32_t tradSigLen = signLen - pqcSigLen;
    RETURN_RET_IF_ERR(CompositeMsgEncodeDigest(ctx, data, dataLen, &msg), ret);
    GOTO_ERR_IF(CRYPT_EAL_PkeyCtrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctx->info->label,
        (uint32_t)strlen(ctx->info->label)), ret);
    GOTO_ERR_IF(CRYPT_EAL_PkeyVerify(ctx->pqcCtx, CRYPT_MD_MAX, msg.data, msg.len, sign, pqcSigLen), ret);
    GOTO_ERR_IF(CRYPT_EAL_PkeyVerify(ctx->tradCtx, ctx->info->alg.sign.tradHashId, msg.data, msg.len, sign + pqcSigLen,
        tradSigLen), ret);
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_ClearFree(msg.data, msg.len);
    return ret;
}

int32_t CRYPT_COMPOSITE_Verify(CRYPT_CompositeCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                               const uint8_t *sign, uint32_t signLen)
{
    int32_t ret;
    uint8_t digest[64];
    uint32_t digestLen = sizeof(digest);

    RETURN_RET_IF(ctx == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(ctx->info->kind != CRYPT_COMPOSITE_KIND_SIGN, CRYPT_NOT_SUPPORT);
    RETURN_RET_IF((CRYPT_MD_AlgId)algId != ctx->info->alg.sign.hashId, CRYPT_INVALID_ARG);
    RETURN_RET_IF_ERR(CRYPT_EAL_ProviderMd(ctx->libCtx, ctx->info->alg.sign.hashId, NULL, data, dataLen, digest, &digestLen),
        ret);
    return CRYPT_COMPOSITE_VerifyData(ctx, digest, digestLen, sign, signLen);
}

#endif /* HITLS_CRYPTO_COMPOSITE_SIGN */
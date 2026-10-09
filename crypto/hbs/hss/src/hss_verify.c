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
#if defined(HITLS_CRYPTO_HSS_LMS)

#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "hss_local.h"
#include "lms_internal.h"
#include "crypt_params_key.h"

int32_t CRYPT_HSS_SetPubKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *pub = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_HSS_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    if (pub->valueLen != CRYPT_HSS_PUBKEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_KEY_LEN);
        return CRYPT_HSS_INVALID_KEY_LEN;
    }

    uint32_t levels = HSS_MIN_LEVELS;
    const BSL_Param *level = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_HSS_LEVEL);
    if (level != NULL) {
        uint32_t valLen = sizeof(levels);
        if (BSL_PARAM_GetValue(level, CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32,
            &levels, &valLen) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
        }
        if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_VERIFY_LEVELS) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_LEVEL);
            return CRYPT_HSS_INVALID_LEVEL;
        }
    }

    const uint8_t *keyData = (const uint8_t *)pub->value;
    uint32_t lmsType = BSL_ByteToUint32(keyData + LMS_PUBKEY_LMS_TYPE_OFFSET);
    uint32_t otsType = BSL_ByteToUint32(keyData + LMS_PUBKEY_OTS_TYPE_OFFSET);
    LMS_Para topPara = {0};
    int32_t ret = LmsParaInit(&topPara, lmsType, otsType);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    uint8_t *tmpPubKey = BSL_SAL_Dump(pub->value, pub->valueLen);
    if (tmpPubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    HSS_Para para = {0};
    para.levels = levels;
    para.lmsType[0] = lmsType;
    para.otsType[0] = otsType;
    para.pubKeyLen = topPara.pubKeyLen;
    para.levelPara[0] = topPara;
    if (ctx->publicKey != NULL) {
        BSL_SAL_Free(ctx->publicKey);
    }
    ctx->para = para;
    ctx->publicKey = tmpPubKey;
    ctx->publicLen = pub->valueLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HSS_GetPubKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->publicKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }

    BSL_Param *pub = BSL_PARAM_FindParam(param, CRYPT_PARAM_HSS_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->publicLen == 0 || pub->valueLen < ctx->publicLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_KEY_LEN);
        return CRYPT_HSS_INVALID_KEY_LEN;
    }

    BSL_Param *levelParam = BSL_PARAM_FindParam(param, CRYPT_PARAM_HSS_LEVEL);
    if (levelParam != NULL && BSL_PARAM_SetValue(levelParam, CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32,
        &ctx->para.levels, sizeof(ctx->para.levels)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    memcpy(pub->value, ctx->publicKey, ctx->publicLen);
    pub->useLen = ctx->publicLen;
    return CRYPT_SUCCESS;
}

int32_t HssTreeVerify(const HSS_Para *para, const uint8_t *publicKey, const uint8_t *message,
    uint32_t messageLen, const uint8_t *signature, uint32_t signatureLen)
{
    if (signatureLen < HSS_SIG_NSPK_LEN ||
        BSL_ByteToUint32(signature) != para->levels - 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    const uint8_t *currentPubKey = publicKey;
    const uint8_t *currentSig = signature + HSS_SIG_NSPK_LEN;
    uint32_t remaining = signatureLen - HSS_SIG_NSPK_LEN;
    LMS_Para currentPara = para->levelPara[0];

    for (uint32_t i = 1; i < para->levels; i++) {
        uint32_t lmsSigLen = LMS_Q_LEN + LmOtsGetSigLen(currentPara.otsType) + LMS_TYPE_LEN +
            currentPara.height * currentPara.n;
        if (remaining < lmsSigLen + LMS_PUBKEY_ROOT_OFFSET) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
            return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
        }

        const uint8_t *childPubKey = currentSig + lmsSigLen;
        LMS_Para childPara = {0};
        int32_t ret = LmsParaInit(&childPara, BSL_ByteToUint32(childPubKey + LMS_PUBKEY_LMS_TYPE_OFFSET),
            BSL_ByteToUint32(childPubKey + LMS_PUBKEY_OTS_TYPE_OFFSET));
        if (ret != CRYPT_SUCCESS || remaining < lmsSigLen + childPara.pubKeyLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
            return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
        }

        ret = LmsValidateSignature(currentPubKey, childPubKey, childPara.pubKeyLen, currentSig, lmsSigLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_VERIFY_FAIL);
            return CRYPT_HSS_VERIFY_FAIL;
        }

        currentPubKey = childPubKey;
        currentPara = childPara;
        currentSig = childPubKey + childPara.pubKeyLen;
        remaining -= lmsSigLen + childPara.pubKeyLen;
    }

    int32_t ret = LmsValidateSignature(currentPubKey, message, messageLen, currentSig, remaining);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_VERIFY_FAIL);
        return CRYPT_HSS_VERIFY_FAIL;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_HSS_Verify(const CRYPT_HSS_Ctx *ctx, int32_t algId, const uint8_t *msg, uint32_t msgLen,
    const uint8_t *sig, uint32_t sigLen)
{
    (void)algId;
    if (ctx == NULL || msg == NULL || sig == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->publicKey == NULL || ctx->para.levels == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }

    return HssTreeVerify(&ctx->para, ctx->publicKey, msg, msgLen, sig, sigLen);
}

#endif /* HITLS_CRYPTO_HSS_LMS */

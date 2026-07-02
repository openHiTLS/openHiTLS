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

typedef struct {
    uint32_t nspk;
    const uint8_t *bottomSig;
    uint32_t bottomSigLen;
    const uint8_t *signedPubKeys[HSS_LEVELS_ARRAY_SIZE];
    uint32_t signedPubKeyLens[HSS_LEVELS_ARRAY_SIZE];
    uint32_t lmsSigLens[HSS_LEVELS_ARRAY_SIZE];
} HSS_ParsedSig;

int32_t CRYPT_HSS_SetPubKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para.pubKeyLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }

    const BSL_Param *pubKeyParam = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_HSS_PUBKEY);
    if (pubKeyParam == NULL || pubKeyParam->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }
    if (pubKeyParam->valueLen < HSS_PUBKEY_ROOT_OFFSET || pubKeyParam->valueLen != ctx->para.pubKeyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_KEY_LEN);
        return CRYPT_HSS_INVALID_KEY_LEN;
    }

    const uint8_t *keyData = (const uint8_t *)pubKeyParam->value;
    uint32_t levels = BSL_ByteToUint32(keyData + HSS_PUBKEY_LEVELS_OFFSET);
    uint32_t lmsType = BSL_ByteToUint32(keyData + HSS_PUBKEY_LMS_TYPE_OFFSET);
    uint32_t otsType = BSL_ByteToUint32(keyData + HSS_PUBKEY_OTS_TYPE_OFFSET);
    if (ctx->para.levels != levels || ctx->para.lmsType[0] != lmsType || ctx->para.otsType[0] != otsType) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }

    void *tmpPubKey = BSL_SAL_Dump(pubKeyParam->value, pubKeyParam->valueLen);
    if (tmpPubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (ctx->publicKey != NULL) {
        BSL_SAL_Free(ctx->publicKey);
    }
    ctx->publicKey = tmpPubKey;
    ctx->publicLen = pubKeyParam->valueLen;
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

    memcpy(pub->value, ctx->publicKey, ctx->publicLen);
    pub->useLen = ctx->publicLen;
    return CRYPT_SUCCESS;
}

static int32_t HssGetLmsSigLenFromBytes(const uint8_t *sig, uint32_t remaining, uint32_t *lmsSigLen)
{
    if (remaining < LMS_Q_LEN + LMS_TYPE_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    uint32_t otsType = BSL_ByteToUint32(sig + LMS_Q_LEN);
    LmOtsParams ots;
    if (LmOtsLookupParamSet(otsType, &ots) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    uint32_t otsSigLen = LMS_TYPE_LEN + ots.n + ots.p * ots.n;

    if (remaining < LMS_Q_LEN + otsSigLen + LMS_TYPE_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    uint32_t lmsType = BSL_ByteToUint32(sig + LMS_Q_LEN + otsSigLen);
    uint32_t h, n, height;
    if (LmsLookupParamSet(lmsType, &h, &n, &height) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    *lmsSigLen = LMS_Q_LEN + otsSigLen + LMS_TYPE_LEN + height * n;
    if (*lmsSigLen > remaining) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    return CRYPT_SUCCESS;
}

static int32_t HssParseSignedPubKeys(HSS_ParsedSig *parsed, const HSS_Para *para, const uint8_t **sigPtr,
    uint32_t *remaining)
{
    for (uint32_t i = 0; i < parsed->nspk; i++) {
        if (i >= HSS_LEVELS_ARRAY_SIZE) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
            return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
        }

        uint32_t lmsSigLen = 0;
        int32_t ret = HssGetLmsSigLenFromBytes(*sigPtr, *remaining, &lmsSigLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        uint32_t totalLen = lmsSigLen + para->levelPara[i + 1].pubKeyLen;
        if (*remaining < totalLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
            return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
        }

        parsed->lmsSigLens[i] = lmsSigLen;
        parsed->signedPubKeys[i] = *sigPtr;
        parsed->signedPubKeyLens[i] = totalLen;

        *sigPtr += totalLen;
        *remaining -= totalLen;
    }
    return CRYPT_SUCCESS;
}

static int32_t HssParseSignature(HSS_ParsedSig *parsed, const HSS_Para *para, const uint8_t *signature,
    uint32_t signatureLen)
{
    if (signatureLen < HSS_SIG_NSPK_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    const uint8_t *sigPtr = signature;
    uint32_t remaining = signatureLen;

    parsed->nspk = BSL_ByteToUint32(sigPtr);
    sigPtr += HSS_SIG_NSPK_LEN;
    remaining -= HSS_SIG_NSPK_LEN;

    if (parsed->nspk != para->levels - 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    int32_t ret = HssParseSignedPubKeys(parsed, para, &sigPtr, &remaining);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t bottomSigLen = 0;
    int32_t lenRet = HssGetLmsSigLenFromBytes(sigPtr, remaining, &bottomSigLen);
    if (lenRet != CRYPT_SUCCESS || bottomSigLen != remaining) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }
    parsed->bottomSigLen = bottomSigLen;

    parsed->bottomSig = sigPtr;
    return CRYPT_SUCCESS;
}

int32_t HssTreeVerify(const HSS_Para *para, const uint8_t *publicKey, const uint8_t *message,
    uint32_t messageLen, const uint8_t *signature, uint32_t signatureLen)
{
    HSS_ParsedSig parsed = {0};
    int32_t ret = HssParseSignature(&parsed, para, signature, signatureLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t topPubKeyLen = para->levelPara[0].pubKeyLen;
    uint8_t currentPubKey[LMS_PUBKEY_MAX_LEN];
    memcpy(currentPubKey, publicKey + HSS_PUBKEY_LMS_TYPE_OFFSET, topPubKeyLen);

    for (uint32_t i = 0; i < parsed.nspk; i++) {
        const uint8_t *signedPubKey = parsed.signedPubKeys[i];
        uint32_t lmsSigLen = parsed.lmsSigLens[i];
        const uint8_t *lmsSig = signedPubKey;
        const uint8_t *childPubKey = signedPubKey + lmsSigLen;

        uint32_t childLmsType = BSL_ByteToUint32(childPubKey + LMS_PUBKEY_LMS_TYPE_OFFSET);
        uint32_t childOtsType = BSL_ByteToUint32(childPubKey + LMS_PUBKEY_OTS_TYPE_OFFSET);
        if (childLmsType != para->levelPara[i + 1].lmsType || childOtsType != para->levelPara[i + 1].otsType) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_VERIFY_FAIL);
            return CRYPT_HSS_VERIFY_FAIL;
        }

        uint32_t childPubKeyLen = para->levelPara[i + 1].pubKeyLen;
        ret = LmsValidateSignature(currentPubKey, childPubKey, childPubKeyLen, lmsSig, lmsSigLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_VERIFY_FAIL);
            return CRYPT_HSS_VERIFY_FAIL;
        }

        memcpy(currentPubKey, childPubKey, childPubKeyLen);
    }

    ret = LmsValidateSignature(currentPubKey, message, messageLen, parsed.bottomSig, parsed.bottomSigLen);
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

    int32_t ret = HssTreeVerify(&ctx->para, ctx->publicKey, msg, msgLen, sig, sigLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#endif /* HITLS_CRYPTO_HSS_LMS */

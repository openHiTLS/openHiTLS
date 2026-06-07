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
#ifdef HITLS_CRYPTO_LMS

#include <string.h>
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_local_types.h"
#include "crypt_params_key.h"
#include "lms_local.h"

CRYPT_LMS_Ctx *CRYPT_LMS_NewCtx(void)
{
    CRYPT_LMS_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_LMS_Ctx));
    if (ctx == NULL) {
        return NULL;
    }

    /* All fields are already zero from Calloc (including embedded para). */
    return ctx;
}

CRYPT_LMS_Ctx *CRYPT_LMS_NewCtxEx(void *libCtx)
{
    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

void CRYPT_LMS_FreeCtx(CRYPT_LMS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    BSL_SAL_ClearFree(ctx->publicKey, LMS_PUBKEY_LEN);
    BSL_SAL_ClearFree(ctx->privateKey, LMS_PRVKEY_LEN);
    BSL_SAL_ClearFree(ctx->cachedTree, ctx->cachedTreeSize);
    BSL_SAL_ClearFree(ctx, sizeof(CRYPT_LMS_Ctx));
}

CRYPT_LMS_Ctx *CRYPT_LMS_DupCtx(CRYPT_LMS_Ctx *srcCtx)
{
    if (srcCtx == NULL) {
        return NULL;
    }

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }

    ctx->para = srcCtx->para;

    if (srcCtx->publicKey != NULL && srcCtx->para.lmsType != 0) {
        ctx->publicKey = BSL_SAL_Calloc(srcCtx->para.pubKeyLen, 1);
        if (ctx->publicKey == NULL) {
            CRYPT_LMS_FreeCtx(ctx);
            return NULL;
        }
        memcpy(ctx->publicKey, srcCtx->publicKey, srcCtx->para.pubKeyLen);
    }

    ctx->signatureIndex = 0;
    return ctx;
}

int32_t CRYPT_LMS_Cmp(CRYPT_LMS_Ctx *ctx1, CRYPT_LMS_Ctx *ctx2)
{
    if (ctx1 == NULL || ctx2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx1->para.lmsType == 0 && ctx2->para.lmsType == 0) {
        return CRYPT_SUCCESS;
    }
    if (ctx1->para.lmsType == 0 || ctx2->para.lmsType == 0) {
        return CRYPT_LMS_CMP_FALSE;
    }

    /* Compare parameters */
    if (ctx1->para.lmsType != ctx2->para.lmsType || ctx1->para.otsType != ctx2->para.otsType) {
        return CRYPT_LMS_CMP_FALSE;
    }

    /* Compare public keys */
    if ((ctx1->publicKey == NULL) != (ctx2->publicKey == NULL)) {
        return CRYPT_LMS_CMP_FALSE;
    }
    if (ctx1->publicKey != NULL &&
        ConstTimeMemcmp(ctx1->publicKey, ctx2->publicKey, (uint32_t)ctx1->para.pubKeyLen) == 0) {
        return CRYPT_LMS_CMP_FALSE;
    }

    /* Compare private keys -- use constant-time comparison to prevent timing side-channel */
    if ((ctx1->privateKey == NULL) != (ctx2->privateKey == NULL)) {
        return CRYPT_LMS_CMP_FALSE;
    }
    if (ctx1->privateKey != NULL &&
        ConstTimeMemcmp(ctx1->privateKey, ctx2->privateKey, (uint32_t)ctx1->para.prvKeyLen) == 0) {
        return CRYPT_LMS_CMP_FALSE;
    }

    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Set LMS type parameter
 * @param ctx    [IN/OUT] LMS context
 * @param val    [IN]     LMS type value
 * @param valLen [IN]     Value length (must be sizeof(uint32_t))
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsCtrlSetLmsType(CRYPT_LMS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint32_t lmsType = *(uint32_t *)val;

    if (LmsLookupParamSet(lmsType, NULL, NULL, NULL) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    ctx->para.lmsType = lmsType;

    if (ctx->para.otsType != 0) {
        return LmsParaInit(&ctx->para, lmsType, ctx->para.otsType);
    }
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Set OTS type parameter
 * @param ctx    [IN/OUT] LMS context
 * @param val    [IN]     OTS type value
 * @param valLen [IN]     Value length (must be sizeof(uint32_t))
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsCtrlSetOtsType(CRYPT_LMS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint32_t otsType = *(uint32_t *)val;

    LmOtsParams otsParams;
    if (LmOtsLookupParamSet(otsType, &otsParams) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    ctx->para.otsType = otsType;

    if (ctx->para.lmsType != 0) {
        return LmsParaInit(&ctx->para, ctx->para.lmsType, otsType);
    }
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Set LMS parameters by algorithm ID
 * @param ctx    [IN/OUT] LMS context
 * @param val    [IN]     Algorithm ID value
 * @param valLen [IN]     Value length (must be sizeof(int32_t))
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsCtrlSetParaById(CRYPT_LMS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (ctx->para.lmsType != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_CTRL_INIT_REPEATED);
        return CRYPT_LMS_CTRL_INIT_REPEATED;
    }
    if (valLen != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t algId = *(int32_t *)val;
    uint32_t lmsType;
    uint32_t otsType;
    switch (algId) {
        case CRYPT_LMS_SHA256_H5_W4:
            lmsType = LMS_SHA256_M32_H5;
            otsType = LMOTS_SHA256_N32_W4;
            break;
        case CRYPT_LMS_SHA256_H10_W4:
            lmsType = LMS_SHA256_M32_H10;
            otsType = LMOTS_SHA256_N32_W4;
            break;
        case CRYPT_LMS_SHA256_H15_W4:
            lmsType = LMS_SHA256_M32_H15;
            otsType = LMOTS_SHA256_N32_W4;
            break;
        case CRYPT_LMS_SHA256_H20_W4:
            lmsType = LMS_SHA256_M32_H20;
            otsType = LMOTS_SHA256_N32_W4;
            break;
        case CRYPT_LMS_SHA256_H25_W4:
            lmsType = LMS_SHA256_M32_H25;
            otsType = LMOTS_SHA256_N32_W4;
            break;
        case CRYPT_LMS_SHA256_H10_W2:
            lmsType = LMS_SHA256_M32_H10;
            otsType = LMOTS_SHA256_N32_W2;
            break;
        case CRYPT_LMS_SHA256_H15_W2:
            lmsType = LMS_SHA256_M32_H15;
            otsType = LMOTS_SHA256_N32_W2;
            break;
        case CRYPT_LMS_SHA256_H20_W2:
            lmsType = LMS_SHA256_M32_H20;
            otsType = LMOTS_SHA256_N32_W2;
            break;
        case CRYPT_LMS_SHA256_H10_W8:
            lmsType = LMS_SHA256_M32_H10;
            otsType = LMOTS_SHA256_N32_W8;
            break;
        case CRYPT_LMS_SHA256_H15_W8:
            lmsType = LMS_SHA256_M32_H15;
            otsType = LMOTS_SHA256_N32_W8;
            break;
        case CRYPT_LMS_SHA256_H20_W8:
            lmsType = LMS_SHA256_M32_H20;
            otsType = LMOTS_SHA256_N32_W8;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
            return CRYPT_LMS_INVALID_PARAM;
    }
    return LmsParaInit(&ctx->para, lmsType, otsType);
}

/**
 * @ingroup lms
 * @brief Get public key length
 * @param ctx    [IN]  LMS context
 * @param val    [OUT] Public key length
 * @param valLen [IN]  Value buffer length (must be sizeof(uint32_t))
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsCtrlGetPubKeyLen(CRYPT_LMS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (ctx->para.lmsType == 0 || valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *(uint32_t *)val = (uint32_t)ctx->para.pubKeyLen;
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Get private key length
 * @param ctx    [IN]  LMS context
 * @param val    [OUT] Private key length
 * @param valLen [IN]  Value buffer length (must be sizeof(uint32_t))
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsCtrlGetPrvKeyLen(CRYPT_LMS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (ctx->para.lmsType == 0 || valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *(uint32_t *)val = (uint32_t)ctx->para.prvKeyLen;
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Get signature length
 * @param ctx    [IN]  LMS context
 * @param val    [OUT] Signature length
 * @param valLen [IN]  Value buffer length (must be sizeof(uint32_t))
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsCtrlGetSigLen(CRYPT_LMS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (ctx->para.lmsType == 0 || valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *(uint32_t *)val = (uint32_t)ctx->para.sigLen;
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Get remaining signature capacity
 * @param ctx    [IN]  LMS context
 * @param val    [OUT] Remaining signatures
 * @param valLen [IN]  Value buffer length (must be sizeof(uint64_t))
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsCtrlGetRemaining(CRYPT_LMS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (ctx->para.lmsType == 0 || ctx->privateKey == NULL || valLen != sizeof(uint64_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *(uint64_t *)val = LmsGetRemainingSignatures(ctx->privateKey, ctx->para.height);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_Ctrl(CRYPT_LMS_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    switch (cmd) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            return LmsCtrlSetParaById(ctx, val, valLen);
        case CRYPT_CTRL_LMS_SET_TYPE:
            return LmsCtrlSetLmsType(ctx, val, valLen);
        case CRYPT_CTRL_LMS_SET_OTS_TYPE:
            return LmsCtrlSetOtsType(ctx, val, valLen);
        case CRYPT_CTRL_LMS_GET_PUBKEY_LEN:
            return LmsCtrlGetPubKeyLen(ctx, val, valLen);
        case CRYPT_CTRL_LMS_GET_PRVKEY_LEN:
            return LmsCtrlGetPrvKeyLen(ctx, val, valLen);
        case CRYPT_CTRL_LMS_GET_SIG_LEN:
            return LmsCtrlGetSigLen(ctx, val, valLen);
        case CRYPT_CTRL_LMS_GET_REMAINING:
            return LmsCtrlGetRemaining(ctx, val, valLen);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_CMD);
            return CRYPT_LMS_INVALID_CMD;
    }
}

int32_t CRYPT_LMS_Gen(CRYPT_LMS_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    /* Validate parameters are fully configured */
    if (ctx->para.lmsType == 0 || ctx->para.otsType == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    /* Free existing keys */
    BSL_SAL_ClearFree(ctx->publicKey, ctx->para.pubKeyLen);
    ctx->publicKey = NULL;
    BSL_SAL_ClearFree(ctx->privateKey, ctx->para.prvKeyLen);
    ctx->privateKey = NULL;

    /* Allocate new key buffers */
    ctx->publicKey = BSL_SAL_Calloc(ctx->para.pubKeyLen, 1);
    if (ctx->publicKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ctx->privateKey = BSL_SAL_Calloc(ctx->para.prvKeyLen, 1);
    if (ctx->privateKey == NULL) {
        BSL_SAL_FREE(ctx->publicKey);
        ctx->publicKey = NULL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    /* Generate key pair */
    int32_t ret = LmsKeyGen(ctx->libCtx, &ctx->para, ctx->publicKey, ctx->privateKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(ctx->publicKey, ctx->para.pubKeyLen);
        BSL_SAL_ClearFree(ctx->privateKey, ctx->para.prvKeyLen);
        ctx->publicKey = NULL;
        ctx->privateKey = NULL;
        return ret;
    }

    ctx->signatureIndex = 0;
    ctx->treeCacheValid = false;
    return CRYPT_SUCCESS;
}

/* Validate key-encoded types and ensure context parameters are consistent and initialized. */
static int32_t LmsValidateAndInitKeyTypes(CRYPT_LMS_Ctx *ctx, uint32_t keyLmsType, uint32_t keyOtsType,
                                          uint32_t requiredKeyLen)
{
    if (LmsLookupParamSet(keyLmsType, NULL, NULL, NULL) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }
    LmOtsParams otsCheck;
    if (LmOtsLookupParamSet(keyOtsType, &otsCheck) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }
    if (ctx->para.lmsType != 0 && ctx->para.lmsType != keyLmsType) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }
    if (ctx->para.otsType != 0 && ctx->para.otsType != keyOtsType) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }
    if (requiredKeyLen == 0) {
        return CRYPT_SUCCESS;
    }
    /* Initialize if not yet configured (check by whether the relevant key length field is zero) */
    if ((requiredKeyLen == LMS_PRVKEY_LEN && ctx->para.prvKeyLen == 0) ||
        (requiredKeyLen == LMS_PUBKEY_LEN && ctx->para.pubKeyLen == 0)) {
        int32_t ret = LmsParaInit(&ctx->para, keyLmsType, keyOtsType);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_SetPrvKey(CRYPT_LMS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *prv = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_LMS_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prv->valueLen != LMS_PRVKEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_KEY_LEN);
        return CRYPT_LMS_INVALID_KEY_LEN;
    }

    const uint8_t *keyData = (const uint8_t *)prv->value;
    uint32_t keyLmsType = (uint32_t)LmsGetBigendian(keyData + LMS_PRVKEY_LMS_TYPE_OFFSET, LMS_TYPE_LEN);
    uint32_t keyOtsType = (uint32_t)LmsGetBigendian(keyData + LMS_PRVKEY_OTS_TYPE_OFFSET, LMS_TYPE_LEN);

    int32_t ret = LmsValidateAndInitKeyTypes(ctx, keyLmsType, keyOtsType, LMS_PRVKEY_LEN);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (ctx->privateKey == NULL) {
        ctx->privateKey = BSL_SAL_Calloc(ctx->para.prvKeyLen, 1);
        if (ctx->privateKey == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    memcpy(ctx->privateKey, prv->value, ctx->para.prvKeyLen);
    ctx->signatureIndex = LmsGetBigendian(ctx->privateKey + LMS_PRVKEY_INDEX_OFFSET, LMS_PRVKEY_INDEX_LEN);
    ctx->treeCacheValid = false;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_SetPubKey(CRYPT_LMS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *pub = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_LMS_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pub->valueLen != LMS_PUBKEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_KEY_LEN);
        return CRYPT_LMS_INVALID_KEY_LEN;
    }

    const uint8_t *keyData = (const uint8_t *)pub->value;
    uint32_t keyLmsType = (uint32_t)LmsGetBigendian(keyData + LMS_PUBKEY_LMS_TYPE_OFFSET, LMS_TYPE_LEN);
    uint32_t keyOtsType = (uint32_t)LmsGetBigendian(keyData + LMS_PUBKEY_OTS_TYPE_OFFSET, LMS_TYPE_LEN);

    int32_t ret = LmsValidateAndInitKeyTypes(ctx, keyLmsType, keyOtsType, LMS_PUBKEY_LEN);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (ctx->publicKey == NULL) {
        ctx->publicKey = BSL_SAL_Calloc(ctx->para.pubKeyLen, 1);
        if (ctx->publicKey == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    memcpy(ctx->publicKey, pub->value, ctx->para.pubKeyLen);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_GetPrvKey(CRYPT_LMS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->para.lmsType == 0 || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_NO_KEY);
        return CRYPT_LMS_NO_KEY;
    }

    BSL_Param *prv = BSL_PARAM_FindParam(param, CRYPT_PARAM_LMS_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (prv->valueLen < ctx->para.prvKeyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_KEY_LEN);
        return CRYPT_LMS_INVALID_KEY_LEN;
    }

    memcpy(prv->value, ctx->privateKey, ctx->para.prvKeyLen);
    prv->useLen = ctx->para.prvKeyLen;

    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_GetPubKey(CRYPT_LMS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->para.lmsType == 0 || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->publicKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_NO_KEY);
        return CRYPT_LMS_NO_KEY;
    }

    BSL_Param *pub = BSL_PARAM_FindParam(param, CRYPT_PARAM_LMS_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pub->valueLen < ctx->para.pubKeyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_KEY_LEN);
        return CRYPT_LMS_INVALID_KEY_LEN;
    }

    memcpy(pub->value, ctx->publicKey, ctx->para.pubKeyLen);
    pub->useLen = ctx->para.pubKeyLen;

    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_Sign(CRYPT_LMS_Ctx *ctx, int32_t algId, const uint8_t *msg, uint32_t msgLen, uint8_t *sig,
                       uint32_t *sigLen)
{
    (void)algId;
    if (ctx == NULL || msg == NULL || sig == NULL || sigLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->para.lmsType == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_NO_KEY);
        return CRYPT_LMS_NO_KEY;
    }

    /* Check if key is exhausted */
    uint64_t remaining = LmsGetRemainingSignatures(ctx->privateKey, ctx->para.height);
    if (remaining == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_KEY_EXHAUSTED);
        return CRYPT_LMS_KEY_EXHAUSTED;
    }

    size_t actualSigLen = *sigLen;
    LMS_InputBuffer msgBuf = {msg, msgLen};
    LMS_SignatureBuffer sigBuf = {sig, &actualSigLen};
    LMS_TreeCache cache = {&ctx->cachedTree, &ctx->cachedTreeSize, &ctx->treeCacheValid};
    int32_t ret = LmsSignCached(&ctx->para, ctx->privateKey, &msgBuf, &sigBuf, &cache);

    /* LmsSignCached advances privateKey's q before signing (fail-closed against
     * one-time-key reuse), so the cached index must mirror privateKey on every
     * path — including failure — to stay consistent with the source of truth. */
    ctx->signatureIndex = LmsGetBigendian(ctx->privateKey + LMS_PRVKEY_INDEX_OFFSET, LMS_PRVKEY_INDEX_LEN);

    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    *sigLen = (uint32_t)actualSigLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_Verify(const CRYPT_LMS_Ctx *ctx, int32_t algId, const uint8_t *msg, uint32_t msgLen,
                         const uint8_t *sig, uint32_t sigLen)
{
    (void)algId;
    if (ctx == NULL || msg == NULL || sig == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->para.lmsType == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->publicKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_NO_KEY);
        return CRYPT_LMS_NO_KEY;
    }

    int32_t ret = LmsValidateSignature(ctx->publicKey, msg, msgLen, sig, sigLen);
    if (ret != CRYPT_SUCCESS) {
        return CRYPT_LMS_VERIFY_FAIL;
    }
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_LMS_CHECK
/**
 * @ingroup lms
 * @brief Verify LMS key pair consistency
 * @param pubKey [IN] Public key context
 * @param prvKey [IN] Private key context
 * @return CRYPT_SUCCESS if keys match, error code otherwise
 */
static int32_t LMSKeyPairCheck(const CRYPT_LMS_Ctx *pubKey, const CRYPT_LMS_Ctx *prvKey)
{
    if (pubKey == NULL || prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->para.lmsType == 0 || prvKey->para.lmsType == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->publicKey == NULL || prvKey->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_NO_KEY);
        return CRYPT_LMS_NO_KEY;
    }

    // Compare LMS and OTS types
    uint32_t pubLmsType = (uint32_t)LmsGetBigendian(pubKey->publicKey + LMS_PUBKEY_LMS_TYPE_OFFSET, LMS_TYPE_LEN);
    uint32_t pubOtsType = (uint32_t)LmsGetBigendian(pubKey->publicKey + LMS_PUBKEY_OTS_TYPE_OFFSET, LMS_TYPE_LEN);
    uint32_t prvLmsType = (uint32_t)LmsGetBigendian(prvKey->privateKey + LMS_PRVKEY_LMS_TYPE_OFFSET, LMS_TYPE_LEN);
    uint32_t prvOtsType = (uint32_t)LmsGetBigendian(prvKey->privateKey + LMS_PRVKEY_OTS_TYPE_OFFSET, LMS_TYPE_LEN);
    if (pubLmsType != prvLmsType || pubOtsType != prvOtsType) {
        return CRYPT_LMS_PAIRWISE_CHECK_FAIL;
    }

    // Compare I values
    if (ConstTimeMemcmp(pubKey->publicKey + LMS_PUBKEY_I_OFFSET, prvKey->privateKey + LMS_PRVKEY_I_OFFSET, LMS_I_LEN) ==
        0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_PAIRWISE_CHECK_FAIL);
        return CRYPT_LMS_PAIRWISE_CHECK_FAIL;
    }

    // Recalculate root from private key and compare with public key root
    uint8_t computedRoot[LMS_SHA256_N];
    const uint8_t *I = prvKey->privateKey + LMS_PRVKEY_I_OFFSET;
    const uint8_t *seed = prvKey->privateKey + LMS_PRVKEY_SEED_OFFSET;

    int32_t ret = LmsComputeRoot(computedRoot, &prvKey->para, I, seed);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    int32_t cmpRet = ConstTimeMemcmp(computedRoot, pubKey->publicKey + LMS_PUBKEY_ROOT_OFFSET, LMS_SHA256_N);
    BSL_SAL_CleanseData(computedRoot, sizeof(computedRoot));
    if (cmpRet == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_PAIRWISE_CHECK_FAIL);
        return CRYPT_LMS_PAIRWISE_CHECK_FAIL;
    }

    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Verify private key validity
 * @param prvKey [IN] Private key context
 * @return CRYPT_SUCCESS if valid, error code otherwise
 */
static int32_t LMSPrvKeyCheck(const CRYPT_LMS_Ctx *prvKey)
{
    if (prvKey == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (prvKey->para.lmsType == 0) {
        return CRYPT_NULL_INPUT;
    }
    if (prvKey->privateKey == NULL) {
        return CRYPT_LMS_NO_KEY;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_Check(uint32_t checkType, const CRYPT_LMS_Ctx *pkey1, const CRYPT_LMS_Ctx *pkey2)
{
    switch (checkType) {
        case CRYPT_PKEY_CHECK_KEYPAIR:
            return LMSKeyPairCheck(pkey1, pkey2);
        case CRYPT_PKEY_CHECK_PRVKEY:
            return LMSPrvKeyCheck(pkey1);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
}
#endif

#endif /* HITLS_CRYPTO_LMS */

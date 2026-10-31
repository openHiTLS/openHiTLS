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
#ifdef HITLS_CRYPTO_ECC_LITE

#include <stdbool.h>
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "crypt_util_rand.h"
#include "crypt_util_ctrl.h"
#include <string.h>
#include "sal_atomic.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_ecc.h"
#include "ecc_local.h"
#include "crypt_ecc_pkey.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

void ECC_FreeCtx(ECC_Pkey *ctx)
{
    if (ctx == NULL) {
        return;
    }
    EccLiteBnFree(ctx->prvkey);
    ECC_FreePoint(ctx->pubkey);
    ECC_FreePara(ctx->para);
    BSL_SAL_Free(ctx);
}

ECC_Pkey *ECC_DupCtx(ECC_Pkey *ctx)
{
    (void)ctx;
    BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
    return NULL;
}

uint32_t ECC_PkeyGetBits(const ECC_Pkey *ctx)
{
    (void)ctx;
    BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
    return 0;
}

int32_t ECC_GenPublicKey(ECC_Pkey *ctx)
{
    (void)ctx;
    BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
    return CRYPT_ECC_NOT_SUPPORT;
}

int32_t ECC_PkeyGetPrvKey(const ECC_Pkey *ctx, CRYPT_EccPrv *prv)
{
    (void)ctx;
    (void)prv;
    BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
    return CRYPT_ECC_NOT_SUPPORT;
}

int32_t ECC_PkeyGetPubKey(const ECC_Pkey *ctx, CRYPT_EccPub *pub)
{
    (void)ctx;
    (void)pub;
    BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
    return CRYPT_ECC_NOT_SUPPORT;
}

ECC_Pkey *ECC_PkeyNewCtx(CRYPT_PKEY_ParaId id)
{
    (void)id;
    BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
    return NULL;
}

int32_t ECC_PkeySetPrvKey(ECC_Pkey *ctx, const CRYPT_EccPrv *prv)
{
    if ((ctx == NULL) || (ctx->para == NULL) || (prv == NULL) || (prv->data == NULL) || (prv->len == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret;
    ECC_LiteBn *newPrvKey = BSL_SAL_Calloc(1u, sizeof(ECC_LiteBn));
    if (newPrvKey == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = EccLiteBnBin2Bn(newPrvKey, prv->data, prv->len, ctx->para->bytes);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    if (EccLiteBnIsZero(newPrvKey) ||
        !EccLiteBnLessThan(newPrvKey, EccLiteParaData(ctx->para, ECC_LITE_N), ctx->para->words)) {
        ret = CRYPT_ECC_PKEY_ERR_INVALID_PRIVATE_KEY;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    EccLiteBnFree(ctx->prvkey);
    ctx->prvkey = newPrvKey;
    return CRYPT_SUCCESS;

ERR:
    EccLiteBnFree(newPrvKey);
    return ret;
}

/**
 * In NIST.SP.800-56 Ar3, the FFC Full Public-Key Validation Routine needs to check nQ = Ø.
 * For performance considerations, we perform Partial public-key Validation (Section 5.6.2.3.4) when
 * setting the Public Key.
*/
int32_t ECC_PkeySetPubKey(ECC_Pkey *ctx, const CRYPT_EccPub *pub)
{
    if ((ctx == NULL) || (ctx->para == NULL) || (pub == NULL) || (pub->data == NULL) || (pub->len == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    ECC_Point *newPubKey = ECC_NewPoint(ctx->para);
    if (newPubKey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = ECC_DecodePoint(ctx->para, newPubKey, pub->data, pub->len);
    if (ret == CRYPT_SUCCESS) {
        ECC_FreePoint(ctx->pubkey);
        ctx->pubkey = newPubKey;
        return ret;
    }
    ECC_FreePoint(newPubKey);
    return ret;
}

#ifdef HITLS_BSL_PARAMS
int32_t ECC_PkeySetPrvKeyEx(ECC_Pkey *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_EccPrv prv = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_EC_PRVKEY, &prv.data, &prv.len);
    return ECC_PkeySetPrvKey(ctx, &prv);
}

int32_t ECC_PkeySetPubKeyEx(ECC_Pkey *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_EccPub pub = {0};
    if (GetConstParamValue(para, CRYPT_PARAM_EC_PUBKEY, &pub.data, &pub.len) == NULL) {
        (void)GetConstParamValue(para, CRYPT_PARAM_PKEY_ENCODE_PUBKEY, (uint8_t **)&pub.data, &pub.len);
    }
    return ECC_PkeySetPubKey(ctx, &pub);
}

int32_t ECC_PkeyGetPrvKeyEx(const ECC_Pkey *ctx, BSL_Param *para)
{
    (void)ctx;
    (void)para;
    BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
    return CRYPT_ECC_NOT_SUPPORT;
}

int32_t ECC_PkeyGetPubKeyEx(const ECC_Pkey *ctx, BSL_Param *para)
{
    (void)ctx;
    (void)para;
    BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
    return CRYPT_ECC_NOT_SUPPORT;
}

#endif

static int32_t GenPublicKey(ECC_Pkey *ctx)
{
    if (ctx->para == NULL || ctx->prvkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->pubkey == NULL) {
        ctx->pubkey = ECC_NewPoint(ctx->para);
        if (ctx->pubkey == NULL) {
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }

    return ECC_PointMul(ctx->para, ctx->pubkey, ctx->prvkey, NULL);
}

int32_t ECC_PkeyGen(ECC_Pkey *ctx)
{
    if (ctx == NULL || ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint8_t bytes[ECC_LITE_MAX_BYTES] = {0};
    ECC_LiteBn candidate = {0};
    int32_t ret = CRYPT_SUCCESS;
    for (uint32_t i = 0; i < CRYPT_ECC_TRY_MAX_CNT; i++) {
        GOTO_ERR_IF_EX(CRYPT_RandEx(NULL, bytes, ctx->para->bytes), ret);
        GOTO_ERR_IF_EX(EccLiteBnBin2Bn(&candidate, bytes, ctx->para->bytes, ctx->para->bytes), ret);
        /* Rejection sampling discards invalid draws; it does not reduce modulo n. */
        if (EccLiteBnIsZero(&candidate) ||
            !EccLiteBnLessThan(&candidate, EccLiteParaData(ctx->para, ECC_LITE_N), ctx->para->words)) {
            continue;
        }
        if (ctx->prvkey == NULL) {
            ctx->prvkey = BSL_SAL_Calloc(1, sizeof(ECC_LiteBn));
            if (ctx->prvkey == NULL) {
                ret = CRYPT_MEM_ALLOC_FAIL;
                BSL_ERR_PUSH_ERROR(ret);
                goto ERR;
            }
        }
        EccLiteBnCopy(ctx->prvkey, &candidate);
        ret = GenPublicKey(ctx);
        goto ERR;
    }
    ret = CRYPT_ECC_PKEY_ERR_TRY_CNT;
    BSL_ERR_PUSH_ERROR(ret);
ERR:
    BSL_SAL_CleanseData(bytes, sizeof(bytes));
    BSL_SAL_CleanseData(&candidate, sizeof(candidate));
    if (ret != CRYPT_SUCCESS) {
        EccLiteBnFree(ctx->prvkey);
        ctx->prvkey = NULL;
        ECC_FreePoint(ctx->pubkey);
        ctx->pubkey = NULL;
    }
    return ret;
}

int32_t ECC_PkeyCtrl(ECC_Pkey *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL || (val == NULL && opt != CRYPT_CTRL_GEN_ECC_PUBLICKEY && opt != CRYPT_CTRL_CLR_FLAG)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_GEN_ECC_PUBLICKEY:
            return GenPublicKey(ctx);
        case CRYPT_CTRL_GET_ECC_ORDER_BITS:
        case CRYPT_CTRL_GET_PUB_KEY_BITS:
            return CRYPT_CTRL_GetNum32(ctx->para == NULL ? 0 : ctx->para->bytes * 8u, val, len);
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            return CRYPT_CTRL_GetNum32(ctx->para == NULL ? 0 : ((ctx->para->bytes * 2u) + 1u), val, len);
        case CRYPT_CTRL_GET_PRVKEY_LEN:
        case CRYPT_CTRL_GET_SHARED_KEY_LEN:
            return CRYPT_CTRL_GetNum32(ctx->para == NULL ? 0 : ctx->para->bytes, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_PKEY_ERR_UNSUPPORTED_CTRL_OPTION);
            return CRYPT_ECC_PKEY_ERR_UNSUPPORTED_CTRL_OPTION;
    }
}

#endif /* HITLS_CRYPTO_ECC_LITE */

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
#ifdef HITLS_CRYPTO_CMVP_ISO19790

#include "crypt_eal_implprovider.h"
#include "crypt_dsa.h"
#include "crypt_rsa.h"
#include "crypt_ecdsa.h"
#include "crypt_sm2.h"
#include "crypt_curve25519.h"
#include "crypt_slh_dsa.h"
#include "crypt_mldsa.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_cmvp.h"
#include "cmvp_iso19790.h"
#include "crypt_iso_selftest.h"
#include "crypt_iso_provderimpl.h"

static int32_t CheckSignVerifyMdAlgId(CRYPT_Iso_Pkey_Ctx *ctx, int32_t algId, bool isSign)
{
    CRYPT_EVENT_TYPE event = isSign ? CRYPT_EVENT_SIGN : CRYPT_EVENT_VERIFY;
    CRYPT_EAL_PkeyC2Data data = {NULL, NULL, NULL, algId, CRYPT_PKEY_PARAID_MAX, event, NULL, NULL, NULL};
    if (!CMVP_Iso19790PkeyC2(ctx->algId, &data)) {
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_PARAM_CHECK, CRYPT_ALGO_PKEY, ctx->algId);
        return CRYPT_CMVP_ERR_PARAM_CHECK;
    }
    return CRYPT_SUCCESS;
}

#define PKEY_SIGN_FUNC(name)                                                                                        \
    static int32_t CRYPT_##name##_SignWrapper(CRYPT_Iso_Pkey_Ctx *ctx, int32_t algId, const uint8_t *data,          \
        uint32_t dataLen, uint8_t *sign, uint32_t *signLen)                                                         \
    {                                                                                                               \
        if (ctx == NULL) {                                                                                          \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                                   \
            return CRYPT_NULL_INPUT;                                                                                \
        }                                                                                                           \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_SIGN, CRYPT_ALGO_PKEY, ctx->algId);                   \
        if (ret != CRYPT_SUCCESS) {                                                                                 \
            return ret;                                                                                             \
        }                                                                                                           \
        ret = CheckSignVerifyMdAlgId(ctx, algId, true);                                                             \
        if (ret != CRYPT_SUCCESS) {                                                                                 \
            return ret;                                                                                             \
        }                                                                                                           \
        return CRYPT_##name##_Sign(ctx->ctx, algId, data, dataLen, sign, signLen);                                  \
    }                                                                                                               \
                                                                                                                    \
    static int32_t CRYPT_##name##_VerifyWrapper(CRYPT_Iso_Pkey_Ctx *ctx, int32_t algId, const uint8_t *msg,         \
        uint32_t msgLen, uint8_t *sign, uint32_t signLen)                                                           \
    {                                                                                                               \
        if (ctx == NULL) {                                                                                          \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                                   \
            return CRYPT_NULL_INPUT;                                                                                \
        }                                                                                                           \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_VERIFY, CRYPT_ALGO_PKEY, ctx->algId);                 \
        if (ret != CRYPT_SUCCESS) {                                                                                 \
            return ret;                                                                                             \
        }                                                                                                           \
        ret = CheckSignVerifyMdAlgId(ctx, algId, false);                                                            \
        if (ret != CRYPT_SUCCESS) {                                                                                 \
            return ret;                                                                                             \
        }                                                                                                           \
        return CRYPT_##name##_Verify(ctx->ctx, algId, msg, msgLen, sign, signLen);                                  \
    }

#define PKEY_SIGN_DATA_FUNC(name)                                                                                   \
    static int32_t CRYPT_##name##_SignDataWrapper(CRYPT_Iso_Pkey_Ctx *ctx, const uint8_t *data, uint32_t dataLen,   \
        uint8_t *sign, uint32_t *signLen)                                                                           \
    {                                                                                                               \
        if (ctx == NULL) {                                                                                          \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                                   \
            return CRYPT_NULL_INPUT;                                                                                \
        }                                                                                                           \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_SIGN, CRYPT_ALGO_PKEY, ctx->algId);                   \
        if (ret != CRYPT_SUCCESS) {                                                                                 \
            return ret;                                                                                             \
        }                                                                                                           \
        return CRYPT_##name##_SignData(ctx->ctx, data, dataLen, sign, signLen);                                     \
    }                                                                                                               \
                                                                                                                    \
    static int32_t CRYPT_##name##_VerifyDataWrapper(CRYPT_Iso_Pkey_Ctx *ctx, const uint8_t *data, uint32_t dataLen, \
        uint8_t *sign, uint32_t signLen)                                                                            \
    {                                                                                                               \
        if (ctx == NULL) {                                                                                          \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                                   \
            return CRYPT_NULL_INPUT;                                                                                \
        }                                                                                                           \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_VERIFY, CRYPT_ALGO_PKEY, ctx->algId);                 \
        if (ret != CRYPT_SUCCESS) {                                                                                 \
            return ret;                                                                                             \
        }                                                                                                           \
        return CRYPT_##name##_VerifyData(ctx->ctx, data, dataLen, sign, signLen);                                   \
    }

static int32_t CRYPT_RSA_RecoverWrapper(CRYPT_Iso_Pkey_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *out,
    uint32_t *outLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_RSA_Recover(ctx->ctx, data, dataLen, out, outLen);
}

static int32_t CRYPT_RSA_BlindWrapper(CRYPT_Iso_Pkey_Ctx *ctx, int32_t algId, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_BLIND, CRYPT_ALGO_PKEY, ctx->algId);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_RSA_Blind(ctx->ctx, algId, input, inputLen, out, outLen);
}

static int32_t CRYPT_RSA_UnBlindWrapper(CRYPT_Iso_Pkey_Ctx *ctx, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_UNBLIND, CRYPT_ALGO_PKEY, ctx->algId);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_RSA_UnBlind(ctx->ctx, input, inputLen, out, outLen);
}

PKEY_SIGN_FUNC(CURVE25519)

PKEY_SIGN_FUNC(DSA)
PKEY_SIGN_DATA_FUNC(DSA)

PKEY_SIGN_FUNC(RSA)
PKEY_SIGN_DATA_FUNC(RSA)

PKEY_SIGN_FUNC(ECDSA)
PKEY_SIGN_DATA_FUNC(ECDSA)

PKEY_SIGN_FUNC(SM2)

const CRYPT_EAL_Func g_isoSignDsa[] = {
#ifdef HITLS_CRYPTO_DSA
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_DSA_SignWrapper},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, (CRYPT_EAL_ImplPkeySignData)CRYPT_DSA_SignDataWrapper},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_DSA_VerifyWrapper},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, (CRYPT_EAL_ImplPkeyVerifyData)CRYPT_DSA_VerifyDataWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoSignEd25519[] = {
#ifdef HITLS_CRYPTO_ED25519
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_CURVE25519_SignWrapper},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_CURVE25519_VerifyWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoSignRsa[] = {
#ifdef HITLS_CRYPTO_RSA_SIGN
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_RSA_SignWrapper},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, (CRYPT_EAL_ImplPkeySignData)CRYPT_RSA_SignDataWrapper},
#endif
#ifdef HITLS_CRYPTO_RSA_VERIFY
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_RSA_VerifyWrapper},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, (CRYPT_EAL_ImplPkeyVerifyData)CRYPT_RSA_VerifyDataWrapper},
    {CRYPT_EAL_IMPLPKEYSIGN_RECOVER, (CRYPT_EAL_ImplPkeyRecover)CRYPT_RSA_RecoverWrapper},
#endif
#ifdef HITLS_CRYPTO_RSA_BSSA
#ifdef HITLS_CRYPTO_RSA_SIGN
    {CRYPT_EAL_IMPLPKEYSIGN_BLIND, (CRYPT_EAL_ImplPkeyBlind)CRYPT_RSA_BlindWrapper},
#endif
#ifdef HITLS_CRYPTO_RSA_VERIFY
    {CRYPT_EAL_IMPLPKEYSIGN_UNBLIND, (CRYPT_EAL_ImplPkeyUnBlind)CRYPT_RSA_UnBlindWrapper},
#endif
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoSignEcdsa[] = {
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_ECDSA_SignWrapper},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, (CRYPT_EAL_ImplPkeySignData)CRYPT_ECDSA_SignDataWrapper},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_ECDSA_VerifyWrapper},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, (CRYPT_EAL_ImplPkeyVerifyData)CRYPT_ECDSA_VerifyDataWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoSignSm2[] = {
#ifdef HITLS_CRYPTO_SM2_SIGN
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_SM2_SignWrapper},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_SM2_VerifyWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */
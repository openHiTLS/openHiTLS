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
#ifdef HITLS_CRYPTO_DSA
#include "crypt_dsa.h"
#endif
#ifdef HITLS_CRYPTO_CURVE25519
#include "crypt_curve25519.h"
#endif
#ifdef HITLS_CRYPTO_RSA
#include "crypt_rsa.h"
#endif
#ifdef HITLS_CRYPTO_DH
#include "crypt_dh.h"
#endif
#ifdef HITLS_CRYPTO_ECDSA
#include "crypt_ecdsa.h"
#endif
#ifdef HITLS_CRYPTO_ECDH
#include "crypt_ecdh.h"
#endif
#ifdef HITLS_CRYPTO_SM2
#include "crypt_sm2.h"
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
#include "crypt_slh_dsa.h"
#endif
#ifdef HITLS_CRYPTO_MLKEM
#include "crypt_mlkem.h"
#endif
#ifdef HITLS_CRYPTO_MLDSA
#include "crypt_mldsa.h"
#endif
#include "crypt_params_key.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "crypt_ealinit.h"
#include "crypt_iso_provider.h"
#include "crypt_eal_pkey.h"
#include "crypt_cmvp.h"
#include "crypt_iso_selftest.h"
#include "crypt_iso_provderimpl.h"
#include "cmvp_iso19790.h"

#define PKEY_PCT_PARAM_COUNT 4

static int32_t ParaCheckAndLog(const CRYPT_Iso_Pkey_Ctx *ctx, const CRYPT_EAL_PkeyPara *para)
{
    CRYPT_EAL_PkeyC2Data data = {para, NULL, NULL, CRYPT_MD_MAX, CRYPT_PKEY_PARAID_MAX, CRYPT_EVENT_MAX,
        NULL, NULL, NULL};
    if (!CMVP_Iso19790PkeyC2(ctx->algId, &data)) {
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_PARAM_CHECK, CRYPT_ALGO_PKEY, ctx->algId);
        return CRYPT_CMVP_ERR_PARAM_CHECK;
    }
    return CRYPT_SUCCESS;
}

static int32_t GetParamValue(const BSL_Param *params, int32_t paramId, uint8_t **value, uint32_t *valueLen)
{
    const BSL_Param *param = BSL_PARAM_FindConstParam(params, paramId);
    if (param == NULL || (param->value == NULL && param->valueLen != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *value = param->value;
    *valueLen = param->valueLen;
    return CRYPT_SUCCESS;
}

static int32_t CheckDsaPara(const CRYPT_Iso_Pkey_Ctx *ctx, const BSL_Param *params)
{
    CRYPT_EAL_PkeyPara para = {0};
    int32_t ret = GetParamValue(params, CRYPT_PARAM_DSA_P, &para.para.dsaPara.p, &para.para.dsaPara.pLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = GetParamValue(params, CRYPT_PARAM_DSA_Q, &para.para.dsaPara.q, &para.para.dsaPara.qLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = GetParamValue(params, CRYPT_PARAM_DSA_G, &para.para.dsaPara.g, &para.para.dsaPara.gLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return ParaCheckAndLog(ctx, &para);
}

static int32_t GetRsaBits(const BSL_Param *params, uint32_t *bits)
{
    uint32_t bitsLen = sizeof(*bits);
    const BSL_Param *temp = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_RSA_BITS);
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    int32_t ret = BSL_PARAM_GetValue(temp, CRYPT_PARAM_RSA_BITS, BSL_PARAM_TYPE_UINT32, bits, &bitsLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_SUCCESS;
}

static int32_t CheckRsaPara(const CRYPT_Iso_Pkey_Ctx *ctx, const BSL_Param *params)
{
    uint32_t bits = 0;
    int32_t ret = GetRsaBits(params, &bits);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_EAL_PkeyPara para = {0};
    para.para.rsaPara.bits = bits;
    return ParaCheckAndLog(ctx, &para);
}

static int32_t CheckDhPara(const CRYPT_Iso_Pkey_Ctx *ctx, const BSL_Param *params)
{
    CRYPT_EAL_PkeyPara para = {0};
    int32_t ret = GetParamValue(params, CRYPT_PARAM_DH_P, &para.para.dhPara.p, &para.para.dhPara.pLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = GetParamValue(params, CRYPT_PARAM_DH_Q, &para.para.dhPara.q, &para.para.dhPara.qLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return ParaCheckAndLog(ctx, &para);
}

static int32_t CheckPkeyParam(const CRYPT_Iso_Pkey_Ctx *ctx, const BSL_Param *params)
{
    switch (ctx->algId) {
        case CRYPT_PKEY_DH:
            return CheckDhPara(ctx, params);
        case CRYPT_PKEY_DSA:
            return CheckDsaPara(ctx, params);
        case CRYPT_PKEY_RSA:
            return CheckRsaPara(ctx, params);
        default:
            return CRYPT_SUCCESS;
    }
}

static int32_t CheckSetRsaPrvKey(CRYPT_Iso_Pkey_Ctx *ctx, const BSL_Param *params)
{
    CRYPT_EAL_PkeyPrv prv = {0};
    int32_t ret = GetParamValue(params, CRYPT_PARAM_RSA_N, &prv.key.rsaPrv.n, &prv.key.rsaPrv.nLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = GetParamValue(params, CRYPT_PARAM_RSA_D, &prv.key.rsaPrv.d, &prv.key.rsaPrv.dLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_EAL_PkeyC2Data data = {NULL, NULL, &prv, CRYPT_MD_MAX, CRYPT_PKEY_PARAID_MAX, CRYPT_EVENT_MAX,
        NULL, NULL, NULL};
    if (!CMVP_Iso19790PkeyC2(ctx->algId, &data)) {
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_PARAM_CHECK, CRYPT_ALGO_PKEY, ctx->algId);
        return CRYPT_CMVP_ERR_PARAM_CHECK;
    }
    return CRYPT_SUCCESS;
}

static int32_t CheckSetPrvKey(CRYPT_Iso_Pkey_Ctx *ctx, const BSL_Param *params)
{
    if (ctx->algId == CRYPT_PKEY_RSA) {
        return CheckSetRsaPrvKey(ctx, params);
    }
    return CRYPT_SUCCESS;
}

static int32_t CheckSetRsaPubKey(CRYPT_Iso_Pkey_Ctx *ctx, const BSL_Param *params)
{
    CRYPT_EAL_PkeyPub pub = {0};
    int32_t ret = GetParamValue(params, CRYPT_PARAM_RSA_N, &pub.key.rsaPub.n, &pub.key.rsaPub.nLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_EAL_PkeyC2Data data = {NULL, &pub, NULL, CRYPT_MD_MAX, CRYPT_PKEY_PARAID_MAX, CRYPT_EVENT_MAX,
        NULL, NULL, NULL};
    if (!CMVP_Iso19790PkeyC2(ctx->algId, &data)) {
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_PARAM_CHECK, CRYPT_ALGO_PKEY, ctx->algId);
        return CRYPT_CMVP_ERR_PARAM_CHECK;
    }
    return CRYPT_SUCCESS;
}

static int32_t CheckSetPubKey(CRYPT_Iso_Pkey_Ctx *ctx, const BSL_Param *params)
{
    if (ctx->algId == CRYPT_PKEY_RSA) {
        return CheckSetRsaPubKey(ctx, params);
    }
    return CRYPT_SUCCESS;
}

static int32_t CheckParaId(CRYPT_Iso_Pkey_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (opt != CRYPT_CTRL_SET_PARA_BY_ID) {
        return CRYPT_SUCCESS;
    }
    if (val == NULL || len != sizeof(CRYPT_PKEY_ParaId)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    CRYPT_EAL_PkeyC2Data data = {NULL, NULL, NULL, CRYPT_MD_MAX, *(CRYPT_PKEY_ParaId *)val, CRYPT_EVENT_MAX,
        NULL, NULL, NULL};
    if (!CMVP_Iso19790PkeyC2(ctx->algId, &data)) {
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_PARAM_CHECK, CRYPT_ALGO_PKEY, ctx->algId);
        return CRYPT_CMVP_ERR_PARAM_CHECK;
    }
    return CRYPT_SUCCESS;
}

static int32_t CheckRsaPadding(CRYPT_Iso_Pkey_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx->algId != CRYPT_PKEY_RSA) {
        return CRYPT_SUCCESS;
    }
    int32_t ret = CRYPT_SUCCESS;
    do {
        if (opt == CRYPT_CTRL_SET_RSA_RSAES_PKCSV15 || opt == CRYPT_CTRL_SET_RSA_RSAES_PKCSV15_TLS ||
            opt == CRYPT_CTRL_SET_NO_PADDING) {
            ret = CRYPT_CMVP_ERR_PARAM_CHECK;
            break;
        }
        if (opt == CRYPT_CTRL_SET_RSA_PADDING) {
            if (val == NULL || len != sizeof(int32_t)) {
                ret = CRYPT_NULL_INPUT;
                break;
            }
            int32_t padType = *(int32_t *)val;
            if (padType != CRYPT_EMSA_PKCSV15 && padType != CRYPT_EMSA_PSS && padType != CRYPT_RSAES_OAEP) {
                ret = CRYPT_CMVP_ERR_PARAM_CHECK;
                break;
            }
        }
    } while (0);
    if (ret != CRYPT_SUCCESS) {
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_PARAM_CHECK, CRYPT_ALGO_PKEY, ctx->algId);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t CheckRsaMdId(CRYPT_Iso_Pkey_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    CRYPT_RSA_PkcsV15Para pkcsv15 = {0};
    CRYPT_EAL_PkeyC2Data data = {NULL, NULL, NULL, CRYPT_MD_MAX, CRYPT_PKEY_PARAID_MAX, CRYPT_EVENT_MAX,
        NULL, NULL, NULL};

    switch (opt) {
        case CRYPT_CTRL_SET_RSA_EMSA_PKCSV15:
            if (val == NULL || len != sizeof(int32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            pkcsv15.mdId = *(int32_t *)val;
            data.pkcsv15 = &pkcsv15;
            break;
        case CRYPT_CTRL_SET_RSA_EMSA_PSS:
            data.pss = (BSL_Param *)val;
            break;
        case CRYPT_CTRL_SET_RSA_RSAES_OAEP:
            data.oaep = (BSL_Param *)val;
            break;
        default:
            return CRYPT_SUCCESS;
    }

    if (!CMVP_Iso19790PkeyC2(ctx->algId, &data)) {
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_PARAM_CHECK, CRYPT_ALGO_PKEY, ctx->algId);
        return CRYPT_CMVP_ERR_PARAM_CHECK;
    }
    return CRYPT_SUCCESS;
}

static int32_t PkeyCtrlCheck(CRYPT_Iso_Pkey_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret = CheckParaId(ctx, opt, val, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CheckRsaPadding(ctx, opt, val, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return CheckRsaMdId(ctx, opt, val, len);
}

static int32_t CRYPT_ASMCAP_PkeyCheck(int32_t algId)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Pkey(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#else
    (void)algId;
#endif
    return CRYPT_SUCCESS;
}

#define PKEY_NEW_Ctx_FUNC(name)                                                                              \
    static void *CRYPT_##name##_NewCtxExWrapper(CRYPT_EAL_IsoProvCtx *provCtx, int32_t algId)                \
    {                                                                                                        \
        if (CRYPT_ASMCAP_PkeyCheck(algId) != CRYPT_SUCCESS) {                                                \
            return NULL;                                                                                     \
        }                                                                                                    \
        if (provCtx == NULL || provCtx->libCtx == NULL) {                                                    \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                            \
            return NULL;                                                                                     \
        }                                                                                                    \
        CRYPT_Iso_Pkey_Ctx *ctx = (CRYPT_Iso_Pkey_Ctx *)BSL_SAL_Calloc(1, sizeof(CRYPT_Iso_Pkey_Ctx));       \
        if (ctx == NULL) {                                                                                   \
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);                                                        \
            return NULL;                                                                                     \
        }                                                                                                    \
        void *pkeyCtx = CRYPT_##name##_NewCtxEx(provCtx->libCtx);                                            \
        if (pkeyCtx == NULL) {                                                                               \
            BSL_SAL_Free(ctx);                                                                               \
            return NULL;                                                                                     \
        }                                                                                                    \
        ctx->algId = algId;                                                                                  \
        ctx->ctx = pkeyCtx;                                                                                  \
        ctx->provCtx = provCtx;                                                                              \
        return ctx;                                                                                          \
    }

#define PKEY_SET_PARA_FUNC(name)                                                                             \
    static int32_t CRYPT_##name##_SetParaWrapper(CRYPT_Iso_Pkey_Ctx *ctx, const BSL_Param *param)            \
    {                                                                                                        \
        if (ctx == NULL || param == NULL) {                                                                  \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                            \
            return CRYPT_NULL_INPUT;                                                                         \
        }                                                                                                    \
        int32_t ret = CheckPkeyParam(ctx, param);                                                            \
        if (ret != CRYPT_SUCCESS) {                                                                          \
            return ret;                                                                                      \
        }                                                                                                    \
        return CRYPT_##name##_SetParaEx(ctx->ctx, param);                                                    \
    }

#define PKEY_GET_PARA_FUNC(name)                                                                             \
    static int32_t CRYPT_##name##_GetParaWrapper(const CRYPT_Iso_Pkey_Ctx *ctx, BSL_Param *param)            \
    {                                                                                                        \
        if (ctx == NULL || param == NULL) {                                                                  \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                            \
            return CRYPT_NULL_INPUT;                                                                         \
        }                                                                                                    \
        int32_t ret = CheckPkeyParam(ctx, param);                                                            \
        if (ret != CRYPT_SUCCESS) {                                                                          \
            return ret;                                                                                      \
        }                                                                                                    \
        return CRYPT_##name##_GetParaEx(ctx->ctx, param);                                                    \
    }

#define PKEY_GEN_KEY_FUNC(name)                                                                              \
    static int32_t name##Wrapper(CRYPT_Iso_Pkey_Ctx *ctx)                                                    \
    {                                                                                                        \
        if (ctx == NULL) {                                                                                   \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                            \
            return CRYPT_NULL_INPUT;                                                                         \
        }                                                                                                    \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_GEN, CRYPT_ALGO_PKEY, ctx->algId);             \
        if (ret != CRYPT_SUCCESS) {                                                                          \
            return ret;                                                                                      \
        }                                                                                                    \
        ret = (name)(ctx->ctx);                                                                              \
        if (ret != CRYPT_SUCCESS) {                                                                          \
            return ret;                                                                                      \
        }                                                                                                    \
        ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_PCT_TEST, CRYPT_ALGO_PKEY, ctx->algId);                \
        if (ret != CRYPT_SUCCESS) {                                                                          \
            return ret;                                                                                      \
        }                                                                                                    \
        if (!CMVP_Iso19790PkeyPct(ctx)) {                                                                    \
            return CRYPT_CMVP_ERR_PAIRWISETEST;                                                              \
        }                                                                                                    \
        return CRYPT_SUCCESS;                                                                                \
    }

#define PKEY_SET_KEY_FUNC(setPrvFunc, setPubFunc)                                                            \
    static int32_t setPrvFunc##Wrapper(CRYPT_Iso_Pkey_Ctx *ctx, const BSL_Param *para)                       \
    {                                                                                                        \
        if (ctx == NULL || para == NULL) {                                                                   \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                            \
            return CRYPT_NULL_INPUT;                                                                         \
        }                                                                                                    \
        int32_t ret = CheckSetPrvKey(ctx, para);                                                             \
        if (ret != CRYPT_SUCCESS) {                                                                          \
            return ret;                                                                                      \
        }                                                                                                    \
        ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_SETSSP, CRYPT_ALGO_PKEY, ctx->algId);                  \
        if (ret != CRYPT_SUCCESS) {                                                                          \
            return ret;                                                                                      \
        }                                                                                                    \
        return (setPrvFunc)(ctx->ctx, para);                                                                 \
    }                                                                                                        \
                                                                                                             \
    static int32_t setPubFunc##Wrapper(CRYPT_Iso_Pkey_Ctx *ctx, const BSL_Param *para)                       \
    {                                                                                                        \
        if (ctx == NULL || para == NULL) {                                                                   \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                            \
            return CRYPT_NULL_INPUT;                                                                         \
        }                                                                                                    \
        int32_t ret = CheckSetPubKey(ctx, para);                                                             \
        if (ret != CRYPT_SUCCESS) {                                                                          \
            return ret;                                                                                      \
        }                                                                                                    \
        ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_SETSSP, CRYPT_ALGO_PKEY, ctx->algId);                  \
        if (ret != CRYPT_SUCCESS) {                                                                          \
            return ret;                                                                                      \
        }                                                                                                    \
        return (setPubFunc)(ctx->ctx, para);                                                                 \
    }

#define PKEY_GET_KEY_FUNC(getPrvFunc, getPubFunc)                                                            \
    static int32_t getPrvFunc##Wrapper(const CRYPT_Iso_Pkey_Ctx *ctx, BSL_Param *para)                       \
    {                                                                                                        \
        if (ctx == NULL || para == NULL) {                                                                   \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                            \
            return CRYPT_NULL_INPUT;                                                                         \
        }                                                                                                    \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_GETSSP, CRYPT_ALGO_PKEY, ctx->algId);          \
        if (ret != CRYPT_SUCCESS) {                                                                          \
            return ret;                                                                                      \
        }                                                                                                    \
        return (getPrvFunc)(ctx->ctx, para);                                                                 \
    }                                                                                                        \
                                                                                                             \
    static int32_t getPubFunc##Wrapper(const CRYPT_Iso_Pkey_Ctx *ctx, BSL_Param *para)                       \
    {                                                                                                        \
        if (ctx == NULL || para == NULL) {                                                                   \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                            \
            return CRYPT_NULL_INPUT;                                                                         \
        }                                                                                                    \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_GETSSP, CRYPT_ALGO_PKEY, ctx->algId);          \
        if (ret != CRYPT_SUCCESS) {                                                                          \
            return ret;                                                                                      \
        }                                                                                                    \
        return (getPubFunc)(ctx->ctx, para);                                                                 \
    }

#define PKEY_DUP_CTX_FUNC(name)                                                                              \
    static CRYPT_Iso_Pkey_Ctx *CRYPT_##name##_DupCtxWrapper(CRYPT_Iso_Pkey_Ctx *ctx)                         \
    {                                                                                                        \
        if (ctx == NULL) {                                                                                   \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                            \
            return NULL;                                                                                     \
        }                                                                                                    \
        CRYPT_Iso_Pkey_Ctx *newCtx = (CRYPT_Iso_Pkey_Ctx *)BSL_SAL_Calloc(1, sizeof(CRYPT_Iso_Pkey_Ctx));    \
        if (newCtx == NULL) {                                                                                \
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);                                                        \
            return NULL;                                                                                     \
        }                                                                                                    \
        void *pkeyCtx = CRYPT_##name##_DupCtx(ctx->ctx);                                                     \
        if (pkeyCtx == NULL) {                                                                               \
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);                                                        \
            BSL_SAL_Free(newCtx);                                                                            \
            return NULL;                                                                                     \
        }                                                                                                    \
        newCtx->algId = ctx->algId;                                                                          \
        newCtx->ctx = pkeyCtx;                                                                               \
        newCtx->provCtx = ctx->provCtx;                                                                      \
        return newCtx;                                                                                       \
    }

#define PKEY_CMP_FUNC(name)                                                                                  \
    static int32_t CRYPT_##name##_CmpWrapper(const CRYPT_Iso_Pkey_Ctx *a, const CRYPT_Iso_Pkey_Ctx *b)       \
    {                                                                                                        \
        if (a == NULL || b == NULL) {                                                                        \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                            \
            return CRYPT_NULL_INPUT;                                                                         \
        }                                                                                                    \
        return CRYPT_##name##_Cmp(a->ctx, b->ctx);                                                           \
    }

#define PKEY_CTRL_FUNC(name)                                                                                 \
    static int32_t CRYPT_##name##_CtrlWrapper(CRYPT_Iso_Pkey_Ctx *ctx, int32_t opt, void *val, uint32_t len) \
    {                                                                                                        \
        if (ctx == NULL) {                                                                                   \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                            \
            return CRYPT_NULL_INPUT;                                                                         \
        }                                                                                                    \
        int32_t ret = PkeyCtrlCheck(ctx, opt, val, len);                                                     \
        if (ret != CRYPT_SUCCESS) {                                                                          \
            return ret;                                                                                      \
        }                                                                                                    \
        return CRYPT_##name##_Ctrl(ctx->ctx, opt, val, len);                                                 \
    }

#define PKEY_FREE_CTX_FUNC(name)                                                                             \
    static void CRYPT_##name##_FreeCtxWrapper(CRYPT_Iso_Pkey_Ctx *ctx)                                       \
    {                                                                                                        \
        if (ctx == NULL) {                                                                                   \
            return;                                                                                          \
        }                                                                                                    \
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_ZERO, CRYPT_ALGO_PKEY, ctx->algId);                    \
        if (ctx->algId == CRYPT_PKEY_SLH_DSA || ctx->algId == CRYPT_PKEY_ML_DSA ||                           \
            ctx->algId == CRYPT_PKEY_ML_KEM) {                                                               \
            CRYPT_##name##_Ctrl(ctx->ctx, CRYPT_CTRL_CLEAN_PUB_KEY, NULL, 0);                                \
        }                                                                                                    \
        if (ctx->ctx != NULL) {                                                                              \
            CRYPT_##name##_FreeCtx(ctx->ctx);                                                                \
        }                                                                                                    \
        BSL_SAL_Free(ctx);                                                                                   \
    }

#define PKEY_IMPORT_EXPORT_FUNC(name)                                                                        \
    static int32_t CRYPT_##name##_ImportWrapper(CRYPT_Iso_Pkey_Ctx *ctx, const BSL_Param *params)            \
    {                                                                                                        \
        if (ctx == NULL || params == NULL) {                                                                 \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                            \
            return CRYPT_NULL_INPUT;                                                                         \
        }                                                                                                    \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_SETSSP, CRYPT_ALGO_PKEY, ctx->algId);          \
        if (ret != CRYPT_SUCCESS) {                                                                          \
            return ret;                                                                                      \
        }                                                                                                    \
        return CRYPT_##name##_Import(ctx->ctx, params);                                                      \
    }                                                                                                        \
                                                                                                             \
    static int32_t CRYPT_##name##_ExportWrapper(const CRYPT_Iso_Pkey_Ctx *ctx, BSL_Param *params)            \
    {                                                                                                        \
        if (ctx == NULL || params == NULL) {                                                                 \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                            \
            return CRYPT_NULL_INPUT;                                                                         \
        }                                                                                                    \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_GETSSP, CRYPT_ALGO_PKEY, ctx->algId);          \
        if (ret != CRYPT_SUCCESS) {                                                                          \
            return ret;                                                                                      \
        }                                                                                                    \
        return CRYPT_##name##_Export(ctx->ctx, params);                                                      \
    }

#define PKEY_CHECK_FUNC(name)                                                                                \
    static int32_t CRYPT_##name##_CheckWrapper(uint32_t checkType, const CRYPT_Iso_Pkey_Ctx *ctx1,           \
        const CRYPT_Iso_Pkey_Ctx *ctx2)                                                                      \
    {                                                                                                        \
        return CRYPT_##name##_Check(checkType, ctx1 != NULL ? ctx1->ctx : NULL,                              \
            ctx2 != NULL ? ctx2->ctx : NULL);                                                                \
    }

PKEY_NEW_Ctx_FUNC(DSA)
PKEY_SET_PARA_FUNC(DSA)
PKEY_GET_PARA_FUNC(DSA)
PKEY_GEN_KEY_FUNC(CRYPT_DSA_Gen)
PKEY_SET_KEY_FUNC(CRYPT_DSA_SetPrvKeyEx, CRYPT_DSA_SetPubKeyEx)
PKEY_GET_KEY_FUNC(CRYPT_DSA_GetPrvKeyEx, CRYPT_DSA_GetPubKeyEx)
PKEY_DUP_CTX_FUNC(DSA)
PKEY_CMP_FUNC(DSA)
PKEY_CTRL_FUNC(DSA)
PKEY_FREE_CTX_FUNC(DSA)
PKEY_CHECK_FUNC(DSA)

PKEY_NEW_Ctx_FUNC(ED25519)
PKEY_GEN_KEY_FUNC(CRYPT_ED25519_GenKey)
PKEY_CHECK_FUNC(ED25519)

PKEY_NEW_Ctx_FUNC(X25519)
PKEY_GEN_KEY_FUNC(CRYPT_X25519_GenKey)
PKEY_CHECK_FUNC(X25519)

PKEY_SET_KEY_FUNC(CRYPT_CURVE25519_SetPrvKeyEx, CRYPT_CURVE25519_SetPubKeyEx)
PKEY_GET_KEY_FUNC(CRYPT_CURVE25519_GetPrvKeyEx, CRYPT_CURVE25519_GetPubKeyEx)
PKEY_DUP_CTX_FUNC(CURVE25519)
PKEY_CMP_FUNC(CURVE25519)
PKEY_CTRL_FUNC(CURVE25519)
PKEY_FREE_CTX_FUNC(CURVE25519)
PKEY_IMPORT_EXPORT_FUNC(CURVE25519)

PKEY_NEW_Ctx_FUNC(RSA)
PKEY_SET_PARA_FUNC(RSA)
PKEY_GEN_KEY_FUNC(CRYPT_RSA_Gen)
PKEY_SET_KEY_FUNC(CRYPT_RSA_SetPrvKeyEx, CRYPT_RSA_SetPubKeyEx)
PKEY_GET_KEY_FUNC(CRYPT_RSA_GetPrvKeyEx, CRYPT_RSA_GetPubKeyEx)
PKEY_DUP_CTX_FUNC(RSA)
PKEY_CMP_FUNC(RSA)
PKEY_CTRL_FUNC(RSA)
PKEY_FREE_CTX_FUNC(RSA)
PKEY_IMPORT_EXPORT_FUNC(RSA)
PKEY_CHECK_FUNC(RSA)

PKEY_NEW_Ctx_FUNC(DH)
PKEY_SET_PARA_FUNC(DH)
PKEY_GET_PARA_FUNC(DH)
PKEY_GEN_KEY_FUNC(CRYPT_DH_Gen)
PKEY_SET_KEY_FUNC(CRYPT_DH_SetPrvKeyEx, CRYPT_DH_SetPubKeyEx)
PKEY_GET_KEY_FUNC(CRYPT_DH_GetPrvKeyEx, CRYPT_DH_GetPubKeyEx)
PKEY_DUP_CTX_FUNC(DH)
PKEY_CMP_FUNC(DH)
PKEY_CTRL_FUNC(DH)
PKEY_FREE_CTX_FUNC(DH)
PKEY_CHECK_FUNC(DH)

PKEY_NEW_Ctx_FUNC(ECDSA)
PKEY_SET_PARA_FUNC(ECDSA)
PKEY_GET_PARA_FUNC(ECDSA)
PKEY_GEN_KEY_FUNC(CRYPT_ECDSA_Gen)
PKEY_SET_KEY_FUNC(CRYPT_ECDSA_SetPrvKeyEx, CRYPT_ECDSA_SetPubKeyEx)
PKEY_GET_KEY_FUNC(CRYPT_ECDSA_GetPrvKeyEx, CRYPT_ECDSA_GetPubKeyEx)
PKEY_DUP_CTX_FUNC(ECDSA)
PKEY_CMP_FUNC(ECDSA)
PKEY_CTRL_FUNC(ECDSA)
PKEY_FREE_CTX_FUNC(ECDSA)
PKEY_IMPORT_EXPORT_FUNC(ECDSA)
PKEY_CHECK_FUNC(ECDSA)

PKEY_NEW_Ctx_FUNC(ECDH)
PKEY_SET_PARA_FUNC(ECDH)
PKEY_GET_PARA_FUNC(ECDH)
PKEY_GEN_KEY_FUNC(CRYPT_ECDH_Gen)
PKEY_SET_KEY_FUNC(CRYPT_ECDH_SetPrvKeyEx, CRYPT_ECDH_SetPubKeyEx)
PKEY_GET_KEY_FUNC(CRYPT_ECDH_GetPrvKeyEx, CRYPT_ECDH_GetPubKeyEx)
PKEY_DUP_CTX_FUNC(ECDH)
PKEY_CMP_FUNC(ECDH)
PKEY_CTRL_FUNC(ECDH)
PKEY_FREE_CTX_FUNC(ECDH)
PKEY_CHECK_FUNC(ECDH)

PKEY_NEW_Ctx_FUNC(SM2)
PKEY_GEN_KEY_FUNC(CRYPT_SM2_Gen)
PKEY_SET_KEY_FUNC(CRYPT_SM2_SetPrvKeyEx, CRYPT_SM2_SetPubKeyEx)
PKEY_GET_KEY_FUNC(CRYPT_SM2_GetPrvKeyEx, CRYPT_SM2_GetPubKeyEx)
PKEY_DUP_CTX_FUNC(SM2)
PKEY_CMP_FUNC(SM2)
PKEY_CTRL_FUNC(SM2)
PKEY_FREE_CTX_FUNC(SM2)
PKEY_IMPORT_EXPORT_FUNC(SM2)
PKEY_CHECK_FUNC(SM2)

PKEY_NEW_Ctx_FUNC(SLH_DSA)
PKEY_GEN_KEY_FUNC(CRYPT_SLH_DSA_Gen)
PKEY_SET_KEY_FUNC(CRYPT_SLH_DSA_SetPrvKeyEx, CRYPT_SLH_DSA_SetPubKeyEx)
PKEY_GET_KEY_FUNC(CRYPT_SLH_DSA_GetPrvKeyEx, CRYPT_SLH_DSA_GetPubKeyEx)
PKEY_CTRL_FUNC(SLH_DSA)
PKEY_FREE_CTX_FUNC(SLH_DSA)
PKEY_CHECK_FUNC(SLH_DSA)

PKEY_NEW_Ctx_FUNC(ML_KEM)
PKEY_GEN_KEY_FUNC(CRYPT_ML_KEM_GenKey)
PKEY_SET_KEY_FUNC(CRYPT_ML_KEM_SetDecapsKeyEx, CRYPT_ML_KEM_SetEncapsKeyEx)
PKEY_GET_KEY_FUNC(CRYPT_ML_KEM_GetDecapsKeyEx, CRYPT_ML_KEM_GetEncapsKeyEx)
PKEY_DUP_CTX_FUNC(ML_KEM)
PKEY_CMP_FUNC(ML_KEM)
PKEY_CTRL_FUNC(ML_KEM)
PKEY_FREE_CTX_FUNC(ML_KEM)
PKEY_CHECK_FUNC(ML_KEM)

PKEY_NEW_Ctx_FUNC(ML_DSA)
PKEY_GEN_KEY_FUNC(CRYPT_ML_DSA_GenKey)
PKEY_SET_KEY_FUNC(CRYPT_ML_DSA_SetPrvKeyEx, CRYPT_ML_DSA_SetPubKeyEx)
PKEY_GET_KEY_FUNC(CRYPT_ML_DSA_GetPrvKeyEx, CRYPT_ML_DSA_GetPubKeyEx)
PKEY_DUP_CTX_FUNC(ML_DSA)
PKEY_CMP_FUNC(ML_DSA)
PKEY_CTRL_FUNC(ML_DSA)
PKEY_FREE_CTX_FUNC(ML_DSA)
PKEY_CHECK_FUNC(ML_DSA)

const CRYPT_EAL_Func g_isoKeyMgmtDsa[] = {
#ifdef HITLS_CRYPTO_DSA
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_DSA_NewCtxExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, (CRYPT_EAL_ImplPkeyMgmtSetParam)CRYPT_DSA_SetParaWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPARAM, (CRYPT_EAL_ImplPkeyMgmtGetParam)CRYPT_DSA_GetParaWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_DSA_GenWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_DSA_SetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_DSA_SetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_DSA_GetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_DSA_GetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_DSA_DupCtxWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (CRYPT_EAL_ImplPkeyMgmtCheck)CRYPT_DSA_CheckWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)CRYPT_DSA_CmpWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_DSA_CtrlWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_DSA_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoKeyMgmtEd25519[] = {
#ifdef HITLS_CRYPTO_ED25519
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_ED25519_NewCtxExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_ED25519_GenKeyWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_CURVE25519_SetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_CURVE25519_SetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_CURVE25519_GetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_CURVE25519_GetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_CURVE25519_DupCtxWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (CRYPT_EAL_ImplPkeyMgmtCheck)CRYPT_ED25519_CheckWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)CRYPT_CURVE25519_CmpWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_CURVE25519_CtrlWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_CURVE25519_FreeCtxWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_IMPORT, (CRYPT_EAL_ImplPkeyMgmtImport)CRYPT_CURVE25519_ImportWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_EXPORT, (CRYPT_EAL_ImplPkeyMgmtExport)CRYPT_CURVE25519_ExportWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoKeyMgmtX25519[] = {
#ifdef HITLS_CRYPTO_X25519
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_X25519_NewCtxExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_X25519_GenKeyWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_CURVE25519_SetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_CURVE25519_SetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_CURVE25519_GetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_CURVE25519_GetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_CURVE25519_DupCtxWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (CRYPT_EAL_ImplPkeyMgmtCheck)CRYPT_X25519_CheckWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)CRYPT_CURVE25519_CmpWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_CURVE25519_CtrlWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_CURVE25519_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoKeyMgmtRsa[] = {
#ifdef HITLS_CRYPTO_RSA
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_RSA_NewCtxExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, (CRYPT_EAL_ImplPkeyMgmtSetParam)CRYPT_RSA_SetParaWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_RSA_GenWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_RSA_SetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_RSA_SetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_RSA_GetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_RSA_GetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_RSA_DupCtxWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (CRYPT_EAL_ImplPkeyMgmtCheck)CRYPT_RSA_CheckWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)CRYPT_RSA_CmpWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_RSA_CtrlWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_RSA_FreeCtxWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_IMPORT, (CRYPT_EAL_ImplPkeyMgmtImport)CRYPT_RSA_ImportWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_EXPORT, (CRYPT_EAL_ImplPkeyMgmtExport)CRYPT_RSA_ExportWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoKeyMgmtDh[] = {
#ifdef HITLS_CRYPTO_DH
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_DH_NewCtxExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, (CRYPT_EAL_ImplPkeyMgmtSetParam)CRYPT_DH_SetParaWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPARAM, (CRYPT_EAL_ImplPkeyMgmtGetParam)CRYPT_DH_GetParaWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_DH_GenWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_DH_SetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_DH_SetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_DH_GetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_DH_GetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_DH_DupCtxWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (CRYPT_EAL_ImplPkeyMgmtCheck)CRYPT_DH_CheckWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)CRYPT_DH_CmpWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_DH_CtrlWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_DH_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoKeyMgmtEcdsa[] = {
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_ECDSA_NewCtxExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, (CRYPT_EAL_ImplPkeyMgmtSetParam)CRYPT_ECDSA_SetParaWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPARAM, (CRYPT_EAL_ImplPkeyMgmtGetParam)CRYPT_ECDSA_GetParaWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_ECDSA_GenWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_ECDSA_SetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_ECDSA_SetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_ECDSA_GetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_ECDSA_GetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_ECDSA_DupCtxWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (CRYPT_EAL_ImplPkeyMgmtCheck)CRYPT_ECDSA_CheckWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)CRYPT_ECDSA_CmpWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_ECDSA_CtrlWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_ECDSA_FreeCtxWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_IMPORT, (CRYPT_EAL_ImplPkeyMgmtImport)CRYPT_ECDSA_ImportWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_EXPORT, (CRYPT_EAL_ImplPkeyMgmtExport)CRYPT_ECDSA_ExportWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoKeyMgmtEcdh[] = {
#ifdef HITLS_CRYPTO_ECDH
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_ECDH_NewCtxExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPARAM, (CRYPT_EAL_ImplPkeyMgmtSetParam)CRYPT_ECDH_SetParaWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPARAM, (CRYPT_EAL_ImplPkeyMgmtGetParam)CRYPT_ECDH_GetParaWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_ECDH_GenWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_ECDH_SetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_ECDH_SetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_ECDH_GetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_ECDH_GetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_ECDH_DupCtxWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (CRYPT_EAL_ImplPkeyMgmtCheck)CRYPT_ECDH_CheckWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)CRYPT_ECDH_CmpWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_ECDH_CtrlWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_ECDH_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoKeyMgmtSm2[] = {
#ifdef HITLS_CRYPTO_SM2
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_SM2_NewCtxExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_SM2_GenWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_SM2_SetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_SM2_SetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_SM2_GetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_SM2_GetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_SM2_DupCtxWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (CRYPT_EAL_ImplPkeyMgmtCheck)CRYPT_SM2_CheckWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)CRYPT_SM2_CmpWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_SM2_CtrlWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_SM2_FreeCtxWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_IMPORT, (CRYPT_EAL_ImplPkeyMgmtImport)CRYPT_SM2_ImportWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_EXPORT, (CRYPT_EAL_ImplPkeyMgmtExport)CRYPT_SM2_ExportWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoKeyMgmtMlKem[] = {
#ifdef HITLS_CRYPTO_MLKEM
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_ML_KEM_NewCtxExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_ML_KEM_GenKeyWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_ML_KEM_SetDecapsKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_ML_KEM_SetEncapsKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_ML_KEM_GetDecapsKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_ML_KEM_GetEncapsKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_ML_KEM_DupCtxWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (CRYPT_EAL_ImplPkeyMgmtCheck)CRYPT_ML_KEM_CheckWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)CRYPT_ML_KEM_CmpWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_ML_KEM_CtrlWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_ML_KEM_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoKeyMgmtMlDsa[] = {
#ifdef HITLS_CRYPTO_MLDSA
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_ML_DSA_NewCtxExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_ML_DSA_GenKeyWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_ML_DSA_SetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_ML_DSA_SetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_ML_DSA_GetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_ML_DSA_GetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_ML_DSA_DupCtxWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (CRYPT_EAL_ImplPkeyMgmtCheck)CRYPT_ML_DSA_CheckWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)CRYPT_ML_DSA_CmpWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_ML_DSA_CtrlWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_ML_DSA_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoKeyMgmtSlhDsa[] = {
#ifdef HITLS_CRYPTO_SLH_DSA
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_SLH_DSA_NewCtxExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_SLH_DSA_GenWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_SLH_DSA_SetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_SLH_DSA_SetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_SLH_DSA_GetPrvKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_SLH_DSA_GetPubKeyExWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (CRYPT_EAL_ImplPkeyMgmtCheck)CRYPT_SLH_DSA_CheckWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_SLH_DSA_CtrlWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_SLH_DSA_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */
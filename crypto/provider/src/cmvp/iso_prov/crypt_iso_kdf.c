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
#include "crypt_params_key.h"
#include "crypt_pbkdf2.h"
#include "crypt_kdf_tls12.h"
#include "crypt_hkdf.h"
#include "crypt_scrypt.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "crypt_cmvp.h"
#include "cmvp_iso19790.h"
#include "crypt_iso_selftest.h"
#include "crypt_iso_provider.h"

typedef struct {
    int32_t algId;
    void *ctx;
    void *provCtx;
} IsoKdfCtx;

/* Constants for parameter validation */
#define KDF_DEF_MAC_ALGID   CRYPT_MAC_HMAC_SHA256
#define KDF_DEF_SALT_LEN    16
#define KDF_DEF_PBKDF2_ITER 1024
#define KDF_DEF_KEY_LEN     16

static int32_t GetMacId(const BSL_Param *param, CRYPT_MAC_AlgId *macId)
{
    int32_t id;
    uint32_t len = sizeof(id);
    const BSL_Param *temp = NULL;

    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_MAC_ID)) == NULL) {
        return CRYPT_SUCCESS;
    }

    int32_t ret = BSL_PARAM_GetValue(temp, CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &id, &len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *macId = (CRYPT_MAC_AlgId)id;
    return CRYPT_SUCCESS;
}

static int32_t GetPbkdf2Params(const BSL_Param *param, CRYPT_EAL_Pbkdf2Param *pbkdf2Param)
{
    uint32_t iter = 0;
    uint32_t len = 0;
    const BSL_Param *temp = NULL;

    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_SALT)) != NULL) {
        pbkdf2Param->saltLen = temp->valueLen;
    }

    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_ITER)) != NULL) {
        len = sizeof(iter);
        int32_t ret = BSL_PARAM_GetValue(temp, CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &iter, &len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        pbkdf2Param->iter = iter;
    }
    return GetMacId(param, &pbkdf2Param->macId);
}

static int32_t GetHkdfAndTlskdfParam(const BSL_Param *param, CRYPT_EAL_HkdfParam *hkdf)
{
    const BSL_Param *temp = NULL;
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_KEY)) != NULL) {
        hkdf->keyLen = temp->valueLen;
    }
    return GetMacId(param, &hkdf->macId);
}

static int32_t CheckKdfParam(IsoKdfCtx *ctx, const BSL_Param *param)
{
    int32_t ret = CRYPT_SUCCESS;
    CRYPT_EAL_Pbkdf2Param pbkdf2 = {KDF_DEF_MAC_ALGID, KDF_DEF_SALT_LEN, KDF_DEF_PBKDF2_ITER, KDF_DEF_KEY_LEN};
    CRYPT_EAL_HkdfParam hkdf = {KDF_DEF_MAC_ALGID, KDF_DEF_KEY_LEN};
    CRYPT_EAL_KdfC2Data data = {&pbkdf2, &hkdf};
    switch (ctx->algId) {
        case CRYPT_KDF_HKDF:
        case CRYPT_KDF_KDFTLS12:
            ret = GetHkdfAndTlskdfParam(param, &hkdf);
            break;
        case CRYPT_KDF_PBKDF2:
            ret = GetPbkdf2Params(param, &pbkdf2);
            break;
        case CRYPT_KDF_SCRYPT:
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
    if (ret != CRYPT_SUCCESS) {
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_PARAM_CHECK, CRYPT_ALGO_KDF, ctx->algId);
        return ret;
    }
    if (!CMVP_Iso19790KdfC2(ctx->algId, &data)) {
        BSL_ERR_PUSH_ERROR(CRYPT_CMVP_ERR_PARAM_CHECK);
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_PARAM_CHECK, CRYPT_ALGO_KDF, ctx->algId);
        return CRYPT_CMVP_ERR_PARAM_CHECK;
    }
    return ret;
}

/* Algorithm-specific parameter check functions */
static int32_t SSPLog(IsoKdfCtx *ctx, const BSL_Param *param, const int32_t *sspParam, uint32_t paramCount)
{
    for (uint32_t i = 0; i < paramCount; i++) {
        if (BSL_PARAM_FindConstParam(param, sspParam[i]) != NULL) {
            return CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_SETSSP, CRYPT_ALGO_KDF, ctx->algId);
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t CheckDeriveKeyLen(IsoKdfCtx *ctx, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->algId != CRYPT_KDF_PBKDF2) {
        return CRYPT_SUCCESS;
    }
    CRYPT_EAL_Pbkdf2Param pbkdf2Param = {KDF_DEF_MAC_ALGID, KDF_DEF_SALT_LEN, KDF_DEF_PBKDF2_ITER, len};
    CRYPT_EAL_KdfC2Data data = {&pbkdf2Param, NULL};
    if (!CMVP_Iso19790KdfC2(CRYPT_KDF_PBKDF2, &data)) {
        BSL_ERR_PUSH_ERROR(CRYPT_CMVP_ERR_PARAM_CHECK);
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_PARAM_CHECK, CRYPT_ALGO_KDF, ctx->algId);
        return CRYPT_CMVP_ERR_PARAM_CHECK;
    }
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_SCRYPT
static int32_t CheckSCRYPTParamAndLog(IsoKdfCtx *ctx, const BSL_Param *param)
{
    int32_t ret = CheckKdfParam(ctx, param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    int32_t sspParam[] = {CRYPT_PARAM_KDF_PASSWORD};
    return SSPLog(ctx, param, sspParam, sizeof(sspParam)/sizeof(sspParam[0]));
}
#endif

#ifdef HITLS_CRYPTO_KDFTLS12
static int32_t CheckKDFTLS12ParamAndLog(IsoKdfCtx *ctx, const BSL_Param *param)
{
    int32_t ret = CheckKdfParam(ctx, param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    int32_t sspParam[] = {CRYPT_PARAM_KDF_KEY, CRYPT_PARAM_KDF_SEED};
    return SSPLog(ctx, param, sspParam, sizeof(sspParam)/sizeof(sspParam[0]));
}
#endif

#ifdef HITLS_CRYPTO_HKDF
static int32_t CheckHKDFParamAndLog(IsoKdfCtx *ctx, const BSL_Param *param)
{
    int32_t ret = CheckKdfParam(ctx, param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    int32_t sspParam[] = {
        CRYPT_PARAM_KDF_KEY, CRYPT_PARAM_KDF_PRK, CRYPT_PARAM_KDF_INFO
    };
    return SSPLog(ctx, param, sspParam, sizeof(sspParam)/sizeof(sspParam[0]));
}
#endif

static int32_t CheckPBKDF2ParamAndLog(IsoKdfCtx *ctx, const BSL_Param *param)
{
    int32_t ret = CheckKdfParam(ctx, param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    int32_t sspParam[] = {CRYPT_PARAM_KDF_PASSWORD};
    return SSPLog(ctx, param, sspParam, sizeof(sspParam)/sizeof(sspParam[0]));
}

#define KDF_METHOD_FUNC(name)                                                                                  \
    static void *CRYPT_##name##_NewCtxExWrapper(CRYPT_EAL_IsoProvCtx *provCtx, int32_t algId)                  \
    {                                                                                                          \
        if (provCtx == NULL) {                                                                                 \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return NULL;                                                                                       \
        }                                                                                                      \
        void *kdfCtx = CRYPT_##name##_NewCtxEx(provCtx->libCtx, algId);                                        \
        if (kdfCtx == NULL) {                                                                                  \
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);                                                          \
            return NULL;                                                                                       \
        }                                                                                                      \
        IsoKdfCtx *ctx = BSL_SAL_Calloc(1, sizeof(IsoKdfCtx));                                                 \
        if (ctx == NULL) {                                                                                     \
            CRYPT_##name##_FreeCtx(kdfCtx);                                                                    \
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);                                                          \
            return NULL;                                                                                       \
        }                                                                                                      \
        ctx->algId = algId;                                                                                    \
        ctx->ctx = kdfCtx;                                                                                     \
        ctx->provCtx = provCtx;                                                                                \
        return ctx;                                                                                            \
    }                                                                                                          \
                                                                                                               \
    static int32_t CRYPT_##name##_SetParamWrapper(IsoKdfCtx *ctx, const BSL_Param *param)                      \
    {                                                                                                          \
        if (ctx == NULL || param == NULL) {                                                                    \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return CRYPT_NULL_INPUT;                                                                           \
        }                                                                                                      \
        int32_t ret = Check##name##ParamAndLog(ctx, param);                                                    \
        if (ret != CRYPT_SUCCESS) {                                                                            \
            return ret;                                                                                        \
        }                                                                                                      \
        return CRYPT_##name##_SetParam(ctx->ctx, param);                                                       \
    }                                                                                                          \
                                                                                                               \
    static int32_t CRYPT_##name##_DeriveWrapper(IsoKdfCtx *ctx, uint8_t *out, uint32_t len)                    \
    {                                                                                                          \
        int32_t ret = CheckDeriveKeyLen(ctx, len);                                                             \
        if (ret != CRYPT_SUCCESS) {                                                                            \
            return ret;                                                                                        \
        }                                                                                                      \
        ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_KDF, CRYPT_ALGO_KDF, ctx->algId);                        \
        if (ret != CRYPT_SUCCESS) {                                                                            \
            return ret;                                                                                        \
        }                                                                                                      \
        return CRYPT_##name##_Derive(ctx->ctx, out, len);                                                      \
    }                                                                                                          \
                                                                                                               \
    static int32_t CRYPT_##name##_DeinitWrapper(IsoKdfCtx *ctx)                                                \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return CRYPT_NULL_INPUT;                                                                           \
        }                                                                                                      \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_ZERO, CRYPT_ALGO_KDF, ctx->algId);               \
        if (ret != CRYPT_SUCCESS) {                                                                            \
            return ret;                                                                                        \
        }                                                                                                      \
        return CRYPT_##name##_Deinit(ctx->ctx);                                                                \
    }                                                                                                          \
                                                                                                               \
    static void CRYPT_##name##_FreeCtxWrapper(IsoKdfCtx *ctx)                                                  \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            return;                                                                                            \
        }                                                                                                      \
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_ZERO, CRYPT_ALGO_KDF, ctx->algId);                       \
        if (ctx->ctx != NULL) {                                                                                \
            CRYPT_##name##_FreeCtx(ctx->ctx);                                                                  \
        }                                                                                                      \
        BSL_SAL_Free(ctx);                                                                                     \
    }

#ifdef HITLS_CRYPTO_SCRYPT
KDF_METHOD_FUNC(SCRYPT);
#endif
#ifdef HITLS_CRYPTO_PBKDF2
KDF_METHOD_FUNC(PBKDF2);
#endif
#ifdef HITLS_CRYPTO_KDFTLS12
KDF_METHOD_FUNC(KDFTLS12);
#endif
#ifdef HITLS_CRYPTO_HKDF
KDF_METHOD_FUNC(HKDF);
#endif

const CRYPT_EAL_Func g_isoKdfScrypt[] = {
#ifdef HITLS_CRYPTO_SCRYPT
    {CRYPT_EAL_IMPLKDF_NEWCTX, (CRYPT_EAL_ImplKdfNewCtx)CRYPT_SCRYPT_NewCtxExWrapper},
    {CRYPT_EAL_IMPLKDF_SETPARAM, (CRYPT_EAL_ImplKdfSetParam)CRYPT_SCRYPT_SetParamWrapper},
    {CRYPT_EAL_IMPLKDF_DERIVE, (CRYPT_EAL_ImplKdfDerive)CRYPT_SCRYPT_DeriveWrapper},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, (CRYPT_EAL_ImplKdfDeInitCtx)CRYPT_SCRYPT_DeinitWrapper},
    {CRYPT_EAL_IMPLKDF_FREECTX, (CRYPT_EAL_ImplKdfFreeCtx)CRYPT_SCRYPT_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoKdfPBKdf2[] = {
#ifdef HITLS_CRYPTO_PBKDF2
    {CRYPT_EAL_IMPLKDF_NEWCTX, (CRYPT_EAL_ImplKdfNewCtx)CRYPT_PBKDF2_NewCtxExWrapper},
    {CRYPT_EAL_IMPLKDF_SETPARAM, (CRYPT_EAL_ImplKdfSetParam)CRYPT_PBKDF2_SetParamWrapper},
    {CRYPT_EAL_IMPLKDF_DERIVE, (CRYPT_EAL_ImplKdfDerive)CRYPT_PBKDF2_DeriveWrapper},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, (CRYPT_EAL_ImplKdfDeInitCtx)CRYPT_PBKDF2_DeinitWrapper},
    {CRYPT_EAL_IMPLKDF_FREECTX, (CRYPT_EAL_ImplKdfFreeCtx)CRYPT_PBKDF2_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoKdfKdfTLS12[] = {
#ifdef HITLS_CRYPTO_KDFTLS12
    {CRYPT_EAL_IMPLKDF_NEWCTX, (CRYPT_EAL_ImplKdfNewCtx)CRYPT_KDFTLS12_NewCtxExWrapper},
    {CRYPT_EAL_IMPLKDF_SETPARAM, (CRYPT_EAL_ImplKdfSetParam)CRYPT_KDFTLS12_SetParamWrapper},
    {CRYPT_EAL_IMPLKDF_DERIVE, (CRYPT_EAL_ImplKdfDerive)CRYPT_KDFTLS12_DeriveWrapper},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, (CRYPT_EAL_ImplKdfDeInitCtx)CRYPT_KDFTLS12_DeinitWrapper},
    {CRYPT_EAL_IMPLKDF_FREECTX, (CRYPT_EAL_ImplKdfFreeCtx)CRYPT_KDFTLS12_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoKdfHkdf[] = {
#ifdef HITLS_CRYPTO_HKDF
    {CRYPT_EAL_IMPLKDF_NEWCTX, (CRYPT_EAL_ImplKdfNewCtx)CRYPT_HKDF_NewCtxExWrapper},
    {CRYPT_EAL_IMPLKDF_SETPARAM, (CRYPT_EAL_ImplKdfSetParam)CRYPT_HKDF_SetParamWrapper},
    {CRYPT_EAL_IMPLKDF_DERIVE, (CRYPT_EAL_ImplKdfDerive)CRYPT_HKDF_DeriveWrapper},
    {CRYPT_EAL_IMPLKDF_DEINITCTX, (CRYPT_EAL_ImplKdfDeInitCtx)CRYPT_HKDF_DeinitWrapper},
    {CRYPT_EAL_IMPLKDF_FREECTX, (CRYPT_EAL_ImplKdfFreeCtx)CRYPT_HKDF_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */
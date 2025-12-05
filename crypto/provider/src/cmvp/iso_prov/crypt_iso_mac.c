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
#include "crypt_hmac.h"
#include "crypt_cmac.h"
#include "crypt_cbc_mac.h"
#include "crypt_gmac.h"
#include "crypt_siphash.h"
#include "crypt_ealinit.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "cmvp_iso19790.h"
#include "crypt_iso_selftest.h"
#include "crypt_iso_provider.h"

#define MAC_KEY_LEN_MIN 14

typedef struct {
    int32_t algId;
    void *ctx;
    void *provCtx;
} IsoMacCtx;

static int32_t CRYPT_ASMCAP_MacCheck(int32_t algId)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Mac(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#else
    (void)algId;
#endif
    return CRYPT_SUCCESS;
}

static int32_t CheckMacKeyLen(IsoMacCtx *ctx, uint32_t keyLen)
{
    if (!CMVP_Iso19790MacC2(ctx->algId, keyLen)) {
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_PARAM_CHECK, CRYPT_ALGO_MAC, ctx->algId);
        BSL_ERR_PUSH_ERROR(CRYPT_CMVP_ERR_PARAM_CHECK);
        return CRYPT_CMVP_ERR_PARAM_CHECK;
    }
    return CRYPT_SUCCESS;
}

#define MAC_NewCtx_FUNC(name)                                                                                  \
    static void *CRYPT_##name##_NewCtxExWrapper(CRYPT_EAL_IsoProvCtx *provCtx, int32_t algId)                  \
    {                                                                                                          \
        if (CRYPT_ASMCAP_MacCheck(algId) != CRYPT_SUCCESS) {                                                   \
            return NULL;                                                                                       \
        }                                                                                                      \
        if (provCtx == NULL) {                                                                                 \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return NULL;                                                                                       \
        }                                                                                                      \
        void *macCtx = CRYPT_##name##_NewCtxEx(provCtx->libCtx, algId);                                        \
        if (macCtx == NULL) {                                                                                  \
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);                                                          \
            return NULL;                                                                                       \
        }                                                                                                      \
        IsoMacCtx *ctx = BSL_SAL_Calloc(1, sizeof(IsoMacCtx));                                                 \
        if (ctx == NULL) {                                                                                     \
            CRYPT_##name##_FreeCtx(macCtx);                                                                    \
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);                                                          \
            return NULL;                                                                                       \
        }                                                                                                      \
        ctx->algId = algId;                                                                                    \
        ctx->ctx = macCtx;                                                                                     \
        ctx->provCtx = provCtx;                                                                                \
        return ctx;                                                                                            \
    }

#define MAC_INIT_FUNC(name)                                                                                    \
    static int32_t CRYPT_##name##_InitWrapper(IsoMacCtx *ctx, const uint8_t *key, uint32_t len, void *param)   \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return CRYPT_NULL_INPUT;                                                                           \
        }                                                                                                      \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_MAC, CRYPT_ALGO_MAC, ctx->algId);                \
        if (ret != CRYPT_SUCCESS) {                                                                            \
            return ret;                                                                                        \
        }                                                                                                      \
        ret = CheckMacKeyLen(ctx, len);                                                                        \
        if (ret != CRYPT_SUCCESS) {                                                                            \
            return ret;                                                                                        \
        }                                                                                                      \
        ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_SETSSP, CRYPT_ALGO_MAC, ctx->algId);                     \
        if (ret != CRYPT_SUCCESS) {                                                                            \
            return ret;                                                                                        \
        }                                                                                                      \
        return CRYPT_##name##_InitEx(ctx->ctx, key, len, param);                                                 \
    }

#define MAC_Update_FUNC(name)                                                                                  \
    static int32_t CRYPT_##name##_UpdateWrapper(IsoMacCtx *ctx, const uint8_t *in, uint32_t len)               \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return CRYPT_NULL_INPUT;                                                                           \
        }                                                                                                      \
        return CRYPT_##name##_Update(ctx->ctx, in, len);                                                       \
    }

#define MAC_Final_FUNC(name)                                                                                   \
    static int32_t CRYPT_##name##_FinalWrapper(IsoMacCtx *ctx, uint8_t *out, uint32_t *len)                    \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return CRYPT_NULL_INPUT;                                                                           \
        }                                                                                                      \
        return CRYPT_##name##_Final(ctx->ctx, out, len);                                                       \
    }

#define MAC_Ctrl_FUNC(name)                                                                                    \
    static int32_t CRYPT_##name##_CtrlWrapper(IsoMacCtx *ctx, CRYPT_MacCtrl opt, void *val, uint32_t len)      \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return CRYPT_NULL_INPUT;                                                                           \
        }                                                                                                      \
        return CRYPT_##name##_Ctrl(ctx->ctx, opt, val, len);                                                   \
    }

#define MAC_FreeCtx_FUNC(name)                                                                                 \
    static void CRYPT_##name##_FreeCtxWrapper(IsoMacCtx *ctx)                                                  \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            return;                                                                                            \
        }                                                                                                      \
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_ZERO, CRYPT_ALGO_MAC, ctx->algId);                       \
        if (ctx->ctx != NULL) {                                                                                \
            CRYPT_##name##_FreeCtx(ctx->ctx);                                                                  \
        }                                                                                                      \
        BSL_SAL_Free(ctx);                                                                                     \
    }

#define MAC_DEINIT_FUNC(name)                                                                                  \
    static int32_t CRYPT_##name##_DeinitWrapper(IsoMacCtx *ctx)                                                \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return CRYPT_NULL_INPUT;                                                                           \
        }                                                                                                      \
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_ZERO, CRYPT_ALGO_MAC, ctx->algId);                       \
        return CRYPT_##name##_Deinit(ctx->ctx);                                                                \
    }

#define MAC_REINIT_FUNC(name)                                                                                  \
    static int32_t CRYPT_##name##_ReinitWrapper(IsoMacCtx *ctx)                                                \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return CRYPT_NULL_INPUT;                                                                           \
        }                                                                                                      \
        return CRYPT_##name##_Reinit(ctx->ctx);                                                                \
    }

#define MAC_SET_PARAM_FUNC(name)                                                                               \
    static int32_t CRYPT_##name##_SetParamWrapper(IsoMacCtx *ctx, const BSL_Param *param)                      \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return CRYPT_NULL_INPUT;                                                                           \
        }                                                                                                      \
        return CRYPT_##name##_SetParam(ctx->ctx, param);                                                       \
    }

#define MAC_FUNCS(name)     \
    MAC_NewCtx_FUNC(name)   \
    MAC_INIT_FUNC(name)     \
    MAC_Update_FUNC(name)   \
    MAC_Final_FUNC(name)    \
    MAC_DEINIT_FUNC(name)   \
    MAC_Ctrl_FUNC(name)     \
    MAC_FreeCtx_FUNC(name)

#ifdef HITLS_CRYPTO_HMAC
MAC_FUNCS(HMAC)
MAC_REINIT_FUNC(HMAC)
MAC_SET_PARAM_FUNC(HMAC)
#endif

#ifdef HITLS_CRYPTO_CMAC
MAC_FUNCS(CMAC)
MAC_REINIT_FUNC(CMAC)
#endif

#ifdef HITLS_CRYPTO_GMAC
MAC_FUNCS(GMAC)
#endif

const CRYPT_EAL_Func g_isoMacHmac[] = {
#ifdef HITLS_CRYPTO_HMAC
    {CRYPT_EAL_IMPLMAC_NEWCTX, (CRYPT_EAL_ImplMacNewCtx)CRYPT_HMAC_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMAC_INIT, (CRYPT_EAL_ImplMacInit)CRYPT_HMAC_InitWrapper},
    {CRYPT_EAL_IMPLMAC_UPDATE, (CRYPT_EAL_ImplMacUpdate)CRYPT_HMAC_UpdateWrapper},
    {CRYPT_EAL_IMPLMAC_FINAL, (CRYPT_EAL_ImplMacFinal)CRYPT_HMAC_FinalWrapper},
    {CRYPT_EAL_IMPLMAC_DEINITCTX, (CRYPT_EAL_ImplMacDeInitCtx)CRYPT_HMAC_DeinitWrapper},
    {CRYPT_EAL_IMPLMAC_REINITCTX, (CRYPT_EAL_ImplMacReInitCtx)CRYPT_HMAC_ReinitWrapper},
    {CRYPT_EAL_IMPLMAC_CTRL, (CRYPT_EAL_ImplMacCtrl)CRYPT_HMAC_CtrlWrapper},
    {CRYPT_EAL_IMPLMAC_FREECTX, (CRYPT_EAL_ImplMacFreeCtx)CRYPT_HMAC_FreeCtxWrapper},
    {CRYPT_EAL_IMPLMAC_SETPARAM, (CRYPT_EAL_ImplMacSetParam)CRYPT_HMAC_SetParamWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoMacCmac[] = {
#ifdef HITLS_CRYPTO_CMAC
    {CRYPT_EAL_IMPLMAC_NEWCTX, (CRYPT_EAL_ImplMacNewCtx)CRYPT_CMAC_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMAC_INIT, (CRYPT_EAL_ImplMacInit)CRYPT_CMAC_InitWrapper},
    {CRYPT_EAL_IMPLMAC_UPDATE, (CRYPT_EAL_ImplMacUpdate)CRYPT_CMAC_UpdateWrapper},
    {CRYPT_EAL_IMPLMAC_FINAL, (CRYPT_EAL_ImplMacFinal)CRYPT_CMAC_FinalWrapper},
    {CRYPT_EAL_IMPLMAC_DEINITCTX, (CRYPT_EAL_ImplMacDeInitCtx)CRYPT_CMAC_DeinitWrapper},
    {CRYPT_EAL_IMPLMAC_REINITCTX, (CRYPT_EAL_ImplMacReInitCtx)CRYPT_CMAC_ReinitWrapper},
    {CRYPT_EAL_IMPLMAC_CTRL, (CRYPT_EAL_ImplMacCtrl)CRYPT_CMAC_CtrlWrapper},
    {CRYPT_EAL_IMPLMAC_FREECTX, (CRYPT_EAL_ImplMacFreeCtx)CRYPT_CMAC_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoMacGmac[] = {
#ifdef HITLS_CRYPTO_GMAC
    {CRYPT_EAL_IMPLMAC_NEWCTX, (CRYPT_EAL_ImplMacNewCtx)CRYPT_GMAC_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMAC_INIT, (CRYPT_EAL_ImplMacInit)CRYPT_GMAC_InitWrapper},
    {CRYPT_EAL_IMPLMAC_UPDATE, (CRYPT_EAL_ImplMacUpdate)CRYPT_GMAC_UpdateWrapper},
    {CRYPT_EAL_IMPLMAC_FINAL, (CRYPT_EAL_ImplMacFinal)CRYPT_GMAC_FinalWrapper},
    {CRYPT_EAL_IMPLMAC_DEINITCTX, (CRYPT_EAL_ImplMacDeInitCtx)CRYPT_GMAC_DeinitWrapper},
    {CRYPT_EAL_IMPLMAC_REINITCTX, NULL},
    {CRYPT_EAL_IMPLMAC_CTRL, (CRYPT_EAL_ImplMacCtrl)CRYPT_GMAC_CtrlWrapper},
    {CRYPT_EAL_IMPLMAC_FREECTX, (CRYPT_EAL_ImplMacFreeCtx)CRYPT_GMAC_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */
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
#include "crypt_modes_cbc.h"
#include "crypt_modes_ccm.h"
#include "crypt_modes_chacha20poly1305.h"
#include "crypt_modes_ctr.h"
#include "crypt_modes_ecb.h"
#include "crypt_modes_gcm.h"
#include "crypt_modes_ofb.h"
#include "crypt_modes_cfb.h"
#include "crypt_modes_xts.h"
#include "crypt_local_types.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "crypt_ealinit.h"
#include "crypt_iso_selftest.h"
#include "crypt_iso_provider.h"

typedef struct {
    int32_t algId;
    void *ctx;
    void *provCtx;
} IsoCipherCtx;

static int32_t CRYPT_ASMCAP_CipherCheck(int32_t algId)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Cipher(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#else
    (void)algId;
#endif
    return CRYPT_SUCCESS;
}

#define CIPHER_NewCtx_FUNC(name)                                                                               \
    static void *MODES_##name##_NewCtxWrapper(CRYPT_EAL_IsoProvCtx *provCtx, int32_t algId)                    \
    {                                                                                                          \
        if (CRYPT_ASMCAP_CipherCheck(algId) != CRYPT_SUCCESS) {                                                \
            return NULL;                                                                                       \
        }                                                                                                      \
        if (provCtx == NULL) {                                                                                 \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return NULL;                                                                                       \
        }                                                                                                      \
        void *cipherCtx = MODES_##name##_NewCtx(algId);                                                        \
        if (cipherCtx == NULL) {                                                                               \
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);                                                          \
            return NULL;                                                                                       \
        }                                                                                                      \
        IsoCipherCtx *ctx = BSL_SAL_Calloc(1, sizeof(IsoCipherCtx));                                           \
        if (ctx == NULL) {                                                                                     \
            MODES_##name##_FreeCtx(cipherCtx);                                                                 \
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);                                                          \
            return NULL;                                                                                       \
        }                                                                                                      \
        ctx->algId = algId;                                                                                    \
        ctx->ctx = cipherCtx;                                                                                  \
        ctx->provCtx = provCtx;                                                                                \
        return ctx;                                                                                            \
    }                                                                                                          \
                                                                                                               \
    static int32_t MODES_##name##_CtrlWrapper(IsoCipherCtx *ctx, int32_t cmd, void *val, uint32_t valLen)      \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return CRYPT_NULL_INPUT;                                                                           \
        }                                                                                                      \
        return MODES_##name##_Ctrl(ctx->ctx, cmd, val, valLen);                                                \
    }                                                                                                          \
                                                                                                               \
    static void MODES_##name##_FreeCtxWrapper(IsoCipherCtx *ctx)                                               \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            return;                                                                                            \
        }                                                                                                      \
        (void)CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_ZERO, CRYPT_ALGO_CIPHER, ctx->algId);                    \
        if (ctx->ctx != NULL) {                                                                                \
            MODES_##name##_FreeCtx(ctx->ctx);                                                                  \
        }                                                                                                      \
        BSL_SAL_Free(ctx);                                                                                     \
    }

#define CIPHER_INIT_FUNC(initFunc, updateFunc, finalFunc, deinitFunc)                                          \
    static int32_t initFunc##Wrapper(IsoCipherCtx *ctx, const uint8_t *key, uint32_t keyLen,                   \
        const uint8_t *iv, uint32_t ivLen, void *param, bool enc)                                              \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return CRYPT_NULL_INPUT;                                                                           \
        }                                                                                                      \
        int32_t event = enc ? CRYPT_EVENT_ENC : CRYPT_EVENT_DEC;                                               \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, event, CRYPT_ALGO_CIPHER, ctx->algId);                       \
        if (ret != CRYPT_SUCCESS) {                                                                            \
            return ret;                                                                                        \
        }                                                                                                      \
        ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_SETSSP, CRYPT_ALGO_CIPHER, ctx->algId);                  \
        if (ret != CRYPT_SUCCESS) {                                                                            \
            return ret;                                                                                        \
        }                                                                                                      \
        return (initFunc)(ctx->ctx, key, keyLen, iv, ivLen, param, enc);                                       \
    }                                                                                                          \
                                                                                                               \
    static int32_t updateFunc##Wrapper(IsoCipherCtx *ctx, const uint8_t *in, uint32_t inLen,                   \
        uint8_t *out, uint32_t *outLen)                                                                        \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return CRYPT_NULL_INPUT;                                                                           \
        }                                                                                                      \
        return (updateFunc)(ctx->ctx, in, inLen, out, outLen);                                                 \
    }                                                                                                          \
                                                                                                               \
    static int32_t finalFunc##Wrapper(IsoCipherCtx *ctx, uint8_t *out, uint32_t *outLen)                       \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return CRYPT_NULL_INPUT;                                                                           \
        }                                                                                                      \
        return (finalFunc)(ctx->ctx, out, outLen);                                                             \
    }                                                                                                          \
                                                                                                               \
    static int32_t deinitFunc##Wrapper(IsoCipherCtx *ctx)                                                      \
    {                                                                                                          \
        if (ctx == NULL) {                                                                                     \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                              \
            return CRYPT_NULL_INPUT;                                                                           \
        }                                                                                                      \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_ZERO, CRYPT_ALGO_CIPHER, ctx->algId);            \
        if (ret != CRYPT_SUCCESS) {                                                                            \
            return ret;                                                                                        \
        }                                                                                                      \
        return (deinitFunc)(ctx->ctx);                                                                         \
    }                                                                                                          \

CIPHER_NewCtx_FUNC(CBC)
CIPHER_INIT_FUNC(MODES_CBC_InitCtxEx, MODES_CBC_UpdateEx, MODES_CBC_FinalEx, MODES_CBC_DeInitCtx)

CIPHER_NewCtx_FUNC(CCM)
CIPHER_INIT_FUNC(MODES_CCM_InitCtx,   MODES_CCM_UpdateEx, MODES_CCM_Final,   MODES_CCM_DeInitCtx)

CIPHER_NewCtx_FUNC(CFB)
CIPHER_INIT_FUNC(MODES_CFB_InitCtxEx, MODES_CFB_UpdateEx, MODES_CFB_Final,   MODES_CFB_DeInitCtx)

CIPHER_NewCtx_FUNC(CTR)
CIPHER_INIT_FUNC(MODES_CTR_InitCtxEx, MODES_CTR_UpdateEx, MODES_CTR_Final,   MODES_CTR_DeInitCtx)

CIPHER_NewCtx_FUNC(ECB)
CIPHER_INIT_FUNC(MODES_ECB_InitCtxEx, MODES_ECB_UpdateEx, MODES_ECB_Final,   MODES_ECB_DeinitCtx)

CIPHER_NewCtx_FUNC(GCM)
CIPHER_INIT_FUNC(MODES_GCM_InitCtxEx, MODES_GCM_UpdateEx, MODES_GCM_Final,   MODES_GCM_DeInitCtx)

CIPHER_NewCtx_FUNC(OFB)
CIPHER_INIT_FUNC(MODES_OFB_InitCtxEx, MODES_OFB_UpdateEx, MODES_OFB_Final,   MODES_OFB_DeInitCtx)

CIPHER_NewCtx_FUNC(XTS)
CIPHER_INIT_FUNC(MODES_XTS_InitCtxEx, MODES_XTS_UpdateEx, MODES_XTS_Final,   MODES_XTS_DeInitCtx)

CIPHER_NewCtx_FUNC(CHACHA20POLY1305)
CIPHER_INIT_FUNC(MODES_CHACHA20POLY1305_InitCtx, MODES_CHACHA20POLY1305_Update, MODES_CHACHA20POLY1305_Final,
    MODES_CHACHA20POLY1305_DeInitCtx)

const CRYPT_EAL_Func g_isoCbc[] = {
#ifdef HITLS_CRYPTO_CBC
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)MODES_CBC_NewCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_CBC_InitCtxExWrapper},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_CBC_UpdateExWrapper},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_CBC_FinalExWrapper},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_CBC_DeInitCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_CBC_CtrlWrapper},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_CBC_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoCcm[] = {
#ifdef HITLS_CRYPTO_CCM
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)MODES_CCM_NewCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_CCM_InitCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_CCM_UpdateExWrapper},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_CCM_FinalWrapper},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_CCM_DeInitCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_CCM_CtrlWrapper},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_CCM_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoCfb[] = {
#ifdef HITLS_CRYPTO_CFB
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)MODES_CFB_NewCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_CFB_InitCtxExWrapper},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_CFB_UpdateExWrapper},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_CFB_FinalWrapper},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_CFB_DeInitCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_CFB_CtrlWrapper},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_CFB_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoChaCha[] = {
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)MODES_CHACHA20POLY1305_NewCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_CHACHA20POLY1305_InitCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_CHACHA20POLY1305_UpdateWrapper},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_CHACHA20POLY1305_FinalWrapper},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_CHACHA20POLY1305_DeInitCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_CHACHA20POLY1305_CtrlWrapper},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_CHACHA20POLY1305_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoCtr[] = {
#ifdef HITLS_CRYPTO_CTR
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)MODES_CTR_NewCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_CTR_InitCtxExWrapper},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_CTR_UpdateExWrapper},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_CTR_FinalWrapper},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_CTR_DeInitCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_CTR_CtrlWrapper},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_CTR_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoEcb[] = {
#ifdef HITLS_CRYPTO_ECB
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)MODES_ECB_NewCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_ECB_InitCtxExWrapper},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_ECB_UpdateExWrapper},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_ECB_FinalWrapper},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_ECB_DeinitCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_ECB_CtrlWrapper},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_ECB_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoGcm[] = {
#ifdef HITLS_CRYPTO_GCM
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)MODES_GCM_NewCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_GCM_InitCtxExWrapper},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_GCM_UpdateExWrapper},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_GCM_FinalWrapper},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_GCM_DeInitCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_GCM_CtrlWrapper},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_GCM_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoOfb[] = {
#ifdef HITLS_CRYPTO_OFB
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)MODES_OFB_NewCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_OFB_InitCtxExWrapper},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_OFB_UpdateExWrapper},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_OFB_FinalWrapper},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_OFB_DeInitCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_OFB_CtrlWrapper},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_OFB_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoXts[] = {
#ifdef HITLS_CRYPTO_XTS
    {CRYPT_EAL_IMPLCIPHER_NEWCTX, (CRYPT_EAL_ImplCipherNewCtx)MODES_XTS_NewCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_INITCTX, (CRYPT_EAL_ImplCipherInitCtx)MODES_XTS_InitCtxExWrapper},
    {CRYPT_EAL_IMPLCIPHER_UPDATE, (CRYPT_EAL_ImplCipherUpdate)MODES_XTS_UpdateExWrapper},
    {CRYPT_EAL_IMPLCIPHER_FINAL, (CRYPT_EAL_ImplCipherFinal)MODES_XTS_FinalWrapper},
    {CRYPT_EAL_IMPLCIPHER_DEINITCTX, (CRYPT_EAL_ImplCipherDeinitCtx)MODES_XTS_DeInitCtxWrapper},
    {CRYPT_EAL_IMPLCIPHER_CTRL, (CRYPT_EAL_ImplCipherCtrl)MODES_XTS_CtrlWrapper},
    {CRYPT_EAL_IMPLCIPHER_FREECTX, (CRYPT_EAL_ImplCipherFreeCtx)MODES_XTS_FreeCtxWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */
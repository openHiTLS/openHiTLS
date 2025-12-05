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
#include "crypt_md5.h"
#include "crypt_sha1.h"
#include "crypt_sha2.h"
#include "crypt_sha3.h"
#include "crypt_sm3.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "crypt_ealinit.h"
#include "crypt_iso_selftest.h"
#include "crypt_iso_provider.h"

typedef struct {
    int32_t algId;
    void *ctx;
    void *provCtx;
} IsoMdCtx;

static uint32_t CRYPT_ASMCAP_Test(int32_t algId)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Md(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#else
    (void)algId;
#endif
    return CRYPT_SUCCESS;
}

#define MD_METHOD_FUNC(name)                                                                            \
    static IsoMdCtx *CRYPT_##name##_NewCtxExWrapper(CRYPT_EAL_IsoProvCtx *provCtx, int32_t algId)       \
    {                                                                                                   \
        int32_t ret = CRYPT_ASMCAP_Test(algId);                                                         \
        if (ret != CRYPT_SUCCESS) {                                                                     \
            return NULL;                                                                                \
        }                                                                                               \
        if (provCtx == NULL) {                                                                          \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                       \
            return NULL;                                                                                \
        }                                                                                               \
        void *mdCtx = CRYPT_##name##_NewCtxEx(provCtx->libCtx, algId);                                  \
        if (mdCtx == NULL) {                                                                            \
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);                                                   \
            return NULL;                                                                                \
        }                                                                                               \
        IsoMdCtx *ctx = BSL_SAL_Calloc(1, sizeof(IsoMdCtx));                                            \
        if (ctx == NULL) {                                                                              \
            CRYPT_##name##_FreeCtx(mdCtx);                                                              \
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);                                                   \
            return NULL;                                                                                \
        }                                                                                               \
        ctx->algId = algId;                                                                             \
        ctx->ctx = mdCtx;                                                                               \
        ctx->provCtx = provCtx;                                                                         \
        return ctx;                                                                                     \
    }                                                                                                   \
                                                                                                        \
    static int32_t CRYPT_##name##_InitWrapper(IsoMdCtx *ctx, BSL_Param *param)                          \
    {                                                                                                   \
        if (ctx == NULL) {                                                                              \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                       \
            return CRYPT_NULL_INPUT;                                                                    \
        }                                                                                               \
        int32_t ret = CRYPT_Iso_Log(ctx->provCtx, CRYPT_EVENT_MD, CRYPT_ALGO_MD, ctx->algId);           \
        if (ret != CRYPT_SUCCESS) {                                                                     \
            return ret;                                                                                 \
        }                                                                                               \
        return CRYPT_##name##_InitEx(ctx->ctx, param);                                                    \
    }                                                                                                   \
                                                                                                        \
    static int32_t CRYPT_##name##_UpdateWrapper(IsoMdCtx *ctx, const uint8_t *data, uint32_t nbytes)    \
    {                                                                                                   \
        if (ctx == NULL) {                                                                              \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                       \
            return CRYPT_NULL_INPUT;                                                                    \
        }                                                                                               \
        return CRYPT_##name##_Update(ctx->ctx, data, nbytes);                                           \
    }                                                                                                   \
                                                                                                        \
    static int32_t CRYPT_##name##_FinalWrapper(IsoMdCtx *ctx, uint8_t *digest, uint32_t *len)           \
    {                                                                                                   \
        if (ctx == NULL) {                                                                              \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                       \
            return CRYPT_NULL_INPUT;                                                                    \
        }                                                                                               \
        return CRYPT_##name##_Final(ctx->ctx, digest, len);                                             \
    }                                                                                                   \
                                                                                                        \
    static int32_t CRYPT_##name##_DeinitWrapper(IsoMdCtx *ctx)                                          \
    {                                                                                                   \
        if (ctx == NULL) {                                                                              \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                       \
            return CRYPT_NULL_INPUT;                                                                    \
        }                                                                                               \
        return CRYPT_##name##_Deinit(ctx->ctx);                                                         \
    }                                                                                                   \
                                                                                                        \
    static IsoMdCtx *CRYPT_##name##_DupCtxWrapper(const IsoMdCtx *src)                                  \
    {                                                                                                   \
        if (src == NULL) {                                                                              \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                       \
            return NULL;                                                                                \
        }                                                                                               \
        void *mdCtx = CRYPT_##name##_DupCtx(src->ctx);                                                  \
        if (mdCtx == NULL) {                                                                            \
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);                                                   \
            return NULL;                                                                                \
        }                                                                                               \
        IsoMdCtx *dupCtx = BSL_SAL_Calloc(1, sizeof(IsoMdCtx));                                         \
        if (dupCtx == NULL) {                                                                           \
            CRYPT_##name##_FreeCtx(mdCtx);                                                              \
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);                                                   \
            return NULL;                                                                                \
        }                                                                                               \
        dupCtx->algId = src->algId;                                                                     \
        dupCtx->ctx = mdCtx;                                                                            \
        dupCtx->provCtx = src->provCtx;                                                                 \
        return dupCtx;                                                                                  \
    }                                                                                                   \
                                                                                                        \
    static void CRYPT_##name##_FreeCtxWrapper(IsoMdCtx *ctx)                                            \
    {                                                                                                   \
        if (ctx == NULL) {                                                                              \
            return;                                                                                     \
        }                                                                                               \
        if (ctx->ctx != NULL) {                                                                         \
            CRYPT_##name##_FreeCtx(ctx->ctx);                                                           \
        }                                                                                               \
        BSL_SAL_Free(ctx);                                                                              \
    }                                                                                                   \
                                                                                                        \
    static int32_t CRYPT_##name##_GetParamWrapper(IsoMdCtx *ctx, BSL_Param *param)                      \
    {                                                                                                   \
        (void)ctx;                                                                                      \
        return CRYPT_##name##_GetParam(NULL, param);                                                    \
    }                                                                                                   \
                                                                                                        \
    static int32_t CRYPT_##name##_CopyCtxWrapper(IsoMdCtx *dst, const IsoMdCtx *src)                    \
    {                                                                                                   \
        if (dst == NULL || src == NULL) {                                                               \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                       \
            return CRYPT_NULL_INPUT;                                                                    \
        }                                                                                               \
        dst->algId = src->algId;                                                                        \
        dst->provCtx = src->provCtx;                                                                    \
        return CRYPT_##name##_CopyCtx(dst->ctx, src->ctx);                                              \
    }

#define MD_SQUEEZE_FUNC(name)                                                                           \
    static int32_t CRYPT_##name##_SqueezeWrapper(IsoMdCtx *ctx, uint8_t *out, uint32_t len)             \
    {                                                                                                   \
        if (ctx == NULL) {                                                                              \
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);                                                       \
            return CRYPT_NULL_INPUT;                                                                    \
        }                                                                                               \
        return CRYPT_##name##_Squeeze(ctx->ctx, out, len);                                              \
    }

MD_METHOD_FUNC(SHA1)
MD_METHOD_FUNC(SHA2_224)
MD_METHOD_FUNC(SHA2_256)
MD_METHOD_FUNC(SHA2_384)
MD_METHOD_FUNC(SHA2_512)
MD_METHOD_FUNC(SHA3_224)
MD_METHOD_FUNC(SHA3_256)
MD_METHOD_FUNC(SHA3_384)
MD_METHOD_FUNC(SHA3_512)
MD_METHOD_FUNC(SHAKE128)
MD_SQUEEZE_FUNC(SHAKE128)
MD_METHOD_FUNC(SHAKE256)
MD_SQUEEZE_FUNC(SHAKE256)
MD_METHOD_FUNC(SM3)

const CRYPT_EAL_Func g_isoMdSha1[] = {
#ifdef HITLS_CRYPTO_SHA1
    {CRYPT_EAL_IMPLMD_NEWCTX, (CRYPT_EAL_ImplMdNewCtx)CRYPT_SHA1_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMD_INITCTX, (CRYPT_EAL_ImplMdInitCtx)CRYPT_SHA1_InitWrapper},
    {CRYPT_EAL_IMPLMD_UPDATE, (CRYPT_EAL_ImplMdUpdate)CRYPT_SHA1_UpdateWrapper},
    {CRYPT_EAL_IMPLMD_FINAL, (CRYPT_EAL_ImplMdFinal)CRYPT_SHA1_FinalWrapper},
    {CRYPT_EAL_IMPLMD_DEINITCTX, (CRYPT_EAL_ImplMdDeInitCtx)CRYPT_SHA1_DeinitWrapper},
    {CRYPT_EAL_IMPLMD_DUPCTX, (CRYPT_EAL_ImplMdDupCtx)CRYPT_SHA1_DupCtxWrapper},
    {CRYPT_EAL_IMPLMD_FREECTX, (CRYPT_EAL_ImplMdFreeCtx)CRYPT_SHA1_FreeCtxWrapper},
    {CRYPT_EAL_IMPLMD_COPYCTX, (CRYPT_EAL_ImplMdCopyCtx)CRYPT_SHA1_CopyCtxWrapper},
    {CRYPT_EAL_IMPLMD_GETPARAM, (CRYPT_EAL_ImplMdGetParam)CRYPT_SHA1_GetParamWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoMdSha224[] = {
#ifdef HITLS_CRYPTO_SHA224
    {CRYPT_EAL_IMPLMD_NEWCTX, (CRYPT_EAL_ImplMdNewCtx)CRYPT_SHA2_224_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMD_INITCTX, (CRYPT_EAL_ImplMdInitCtx)CRYPT_SHA2_224_InitWrapper},
    {CRYPT_EAL_IMPLMD_UPDATE, (CRYPT_EAL_ImplMdUpdate)CRYPT_SHA2_224_UpdateWrapper},
    {CRYPT_EAL_IMPLMD_FINAL, (CRYPT_EAL_ImplMdFinal)CRYPT_SHA2_224_FinalWrapper},
    {CRYPT_EAL_IMPLMD_DEINITCTX, (CRYPT_EAL_ImplMdDeInitCtx)CRYPT_SHA2_224_DeinitWrapper},
    {CRYPT_EAL_IMPLMD_DUPCTX, (CRYPT_EAL_ImplMdDupCtx)CRYPT_SHA2_224_DupCtxWrapper},
    {CRYPT_EAL_IMPLMD_FREECTX, (CRYPT_EAL_ImplMdFreeCtx)CRYPT_SHA2_224_FreeCtxWrapper},
    {CRYPT_EAL_IMPLMD_COPYCTX, (CRYPT_EAL_ImplMdCopyCtx)CRYPT_SHA2_224_CopyCtxWrapper},
    {CRYPT_EAL_IMPLMD_GETPARAM, (CRYPT_EAL_ImplMdGetParam)CRYPT_SHA2_224_GetParamWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoMdSha256[] = {
#ifdef HITLS_CRYPTO_SHA256
    {CRYPT_EAL_IMPLMD_NEWCTX, (CRYPT_EAL_ImplMdNewCtx)CRYPT_SHA2_256_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMD_INITCTX, (CRYPT_EAL_ImplMdInitCtx)CRYPT_SHA2_256_InitWrapper},
    {CRYPT_EAL_IMPLMD_UPDATE, (CRYPT_EAL_ImplMdUpdate)CRYPT_SHA2_256_UpdateWrapper},
    {CRYPT_EAL_IMPLMD_FINAL, (CRYPT_EAL_ImplMdFinal)CRYPT_SHA2_256_FinalWrapper},
    {CRYPT_EAL_IMPLMD_DEINITCTX, (CRYPT_EAL_ImplMdDeInitCtx)CRYPT_SHA2_256_DeinitWrapper},
    {CRYPT_EAL_IMPLMD_DUPCTX, (CRYPT_EAL_ImplMdDupCtx)CRYPT_SHA2_256_DupCtxWrapper},
    {CRYPT_EAL_IMPLMD_FREECTX, (CRYPT_EAL_ImplMdFreeCtx)CRYPT_SHA2_256_FreeCtxWrapper},
    {CRYPT_EAL_IMPLMD_COPYCTX, (CRYPT_EAL_ImplMdCopyCtx)CRYPT_SHA2_256_CopyCtxWrapper},
    {CRYPT_EAL_IMPLMD_GETPARAM, (CRYPT_EAL_ImplMdGetParam)CRYPT_SHA2_256_GetParamWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoMdSha384[] = {
#ifdef HITLS_CRYPTO_SHA384
    {CRYPT_EAL_IMPLMD_NEWCTX, (CRYPT_EAL_ImplMdNewCtx)CRYPT_SHA2_384_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMD_INITCTX, (CRYPT_EAL_ImplMdInitCtx)CRYPT_SHA2_384_InitWrapper},
    {CRYPT_EAL_IMPLMD_UPDATE, (CRYPT_EAL_ImplMdUpdate)CRYPT_SHA2_384_UpdateWrapper},
    {CRYPT_EAL_IMPLMD_FINAL, (CRYPT_EAL_ImplMdFinal)CRYPT_SHA2_384_FinalWrapper},
    {CRYPT_EAL_IMPLMD_DEINITCTX, (CRYPT_EAL_ImplMdDeInitCtx)CRYPT_SHA2_384_DeinitWrapper},
    {CRYPT_EAL_IMPLMD_DUPCTX, (CRYPT_EAL_ImplMdDupCtx)CRYPT_SHA2_384_DupCtxWrapper},
    {CRYPT_EAL_IMPLMD_FREECTX, (CRYPT_EAL_ImplMdFreeCtx)CRYPT_SHA2_384_FreeCtxWrapper},
    {CRYPT_EAL_IMPLMD_COPYCTX, (CRYPT_EAL_ImplMdCopyCtx)CRYPT_SHA2_384_CopyCtxWrapper},
    {CRYPT_EAL_IMPLMD_GETPARAM, (CRYPT_EAL_ImplMdGetParam)CRYPT_SHA2_384_GetParamWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoMdSha512[] = {
#ifdef HITLS_CRYPTO_SHA512
    {CRYPT_EAL_IMPLMD_NEWCTX, (CRYPT_EAL_ImplMdNewCtx)CRYPT_SHA2_512_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMD_INITCTX, (CRYPT_EAL_ImplMdInitCtx)CRYPT_SHA2_512_InitWrapper},
    {CRYPT_EAL_IMPLMD_UPDATE, (CRYPT_EAL_ImplMdUpdate)CRYPT_SHA2_512_UpdateWrapper},
    {CRYPT_EAL_IMPLMD_FINAL, (CRYPT_EAL_ImplMdFinal)CRYPT_SHA2_512_FinalWrapper},
    {CRYPT_EAL_IMPLMD_DEINITCTX, (CRYPT_EAL_ImplMdDeInitCtx)CRYPT_SHA2_512_DeinitWrapper},
    {CRYPT_EAL_IMPLMD_DUPCTX, (CRYPT_EAL_ImplMdDupCtx)CRYPT_SHA2_512_DupCtxWrapper},
    {CRYPT_EAL_IMPLMD_FREECTX, (CRYPT_EAL_ImplMdFreeCtx)CRYPT_SHA2_512_FreeCtxWrapper},
    {CRYPT_EAL_IMPLMD_COPYCTX, (CRYPT_EAL_ImplMdCopyCtx)CRYPT_SHA2_512_CopyCtxWrapper},
    {CRYPT_EAL_IMPLMD_GETPARAM, (CRYPT_EAL_ImplMdGetParam)CRYPT_SHA2_512_GetParamWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoMdSha3224[] = {
#ifdef HITLS_CRYPTO_SHA3
    {CRYPT_EAL_IMPLMD_NEWCTX, (CRYPT_EAL_ImplMdNewCtx)CRYPT_SHA3_224_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMD_INITCTX, (CRYPT_EAL_ImplMdInitCtx)CRYPT_SHA3_224_InitWrapper},
    {CRYPT_EAL_IMPLMD_UPDATE, (CRYPT_EAL_ImplMdUpdate)CRYPT_SHA3_224_UpdateWrapper},
    {CRYPT_EAL_IMPLMD_FINAL, (CRYPT_EAL_ImplMdFinal)CRYPT_SHA3_224_FinalWrapper},
    {CRYPT_EAL_IMPLMD_DEINITCTX, (CRYPT_EAL_ImplMdDeInitCtx)CRYPT_SHA3_224_DeinitWrapper},
    {CRYPT_EAL_IMPLMD_DUPCTX, (CRYPT_EAL_ImplMdDupCtx)CRYPT_SHA3_224_DupCtxWrapper},
    {CRYPT_EAL_IMPLMD_FREECTX, (CRYPT_EAL_ImplMdFreeCtx)CRYPT_SHA3_224_FreeCtxWrapper},
    {CRYPT_EAL_IMPLMD_COPYCTX, (CRYPT_EAL_ImplMdCopyCtx)CRYPT_SHA3_224_CopyCtxWrapper},
    {CRYPT_EAL_IMPLMD_GETPARAM, (CRYPT_EAL_ImplMdGetParam)CRYPT_SHA3_224_GetParamWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoMdSha3256[] = {
#ifdef HITLS_CRYPTO_SHA3
    {CRYPT_EAL_IMPLMD_NEWCTX, (CRYPT_EAL_ImplMdNewCtx)CRYPT_SHA3_256_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMD_INITCTX, (CRYPT_EAL_ImplMdInitCtx)CRYPT_SHA3_256_InitWrapper},
    {CRYPT_EAL_IMPLMD_UPDATE, (CRYPT_EAL_ImplMdUpdate)CRYPT_SHA3_256_UpdateWrapper},
    {CRYPT_EAL_IMPLMD_FINAL, (CRYPT_EAL_ImplMdFinal)CRYPT_SHA3_256_FinalWrapper},
    {CRYPT_EAL_IMPLMD_DEINITCTX, (CRYPT_EAL_ImplMdDeInitCtx)CRYPT_SHA3_256_DeinitWrapper},
    {CRYPT_EAL_IMPLMD_DUPCTX, (CRYPT_EAL_ImplMdDupCtx)CRYPT_SHA3_256_DupCtxWrapper},
    {CRYPT_EAL_IMPLMD_FREECTX, (CRYPT_EAL_ImplMdFreeCtx)CRYPT_SHA3_256_FreeCtxWrapper},
    {CRYPT_EAL_IMPLMD_COPYCTX, (CRYPT_EAL_ImplMdCopyCtx)CRYPT_SHA3_256_CopyCtxWrapper},
    {CRYPT_EAL_IMPLMD_GETPARAM, (CRYPT_EAL_ImplMdGetParam)CRYPT_SHA3_256_GetParamWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoMdSha3384[] = {
#ifdef HITLS_CRYPTO_SHA3
    {CRYPT_EAL_IMPLMD_NEWCTX, (CRYPT_EAL_ImplMdNewCtx)CRYPT_SHA3_384_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMD_INITCTX, (CRYPT_EAL_ImplMdInitCtx)CRYPT_SHA3_384_InitWrapper},
    {CRYPT_EAL_IMPLMD_UPDATE, (CRYPT_EAL_ImplMdUpdate)CRYPT_SHA3_384_UpdateWrapper},
    {CRYPT_EAL_IMPLMD_FINAL, (CRYPT_EAL_ImplMdFinal)CRYPT_SHA3_384_FinalWrapper},
    {CRYPT_EAL_IMPLMD_DEINITCTX, (CRYPT_EAL_ImplMdDeInitCtx)CRYPT_SHA3_384_DeinitWrapper},
    {CRYPT_EAL_IMPLMD_DUPCTX, (CRYPT_EAL_ImplMdDupCtx)CRYPT_SHA3_384_DupCtxWrapper},
    {CRYPT_EAL_IMPLMD_FREECTX, (CRYPT_EAL_ImplMdFreeCtx)CRYPT_SHA3_384_FreeCtxWrapper},
    {CRYPT_EAL_IMPLMD_COPYCTX, (CRYPT_EAL_ImplMdCopyCtx)CRYPT_SHA3_384_CopyCtxWrapper},
    {CRYPT_EAL_IMPLMD_GETPARAM, (CRYPT_EAL_ImplMdGetParam)CRYPT_SHA3_384_GetParamWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoMdSha3512[] = {
#ifdef HITLS_CRYPTO_SHA3
    {CRYPT_EAL_IMPLMD_NEWCTX, (CRYPT_EAL_ImplMdNewCtx)CRYPT_SHA3_512_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMD_INITCTX, (CRYPT_EAL_ImplMdInitCtx)CRYPT_SHA3_512_InitWrapper},
    {CRYPT_EAL_IMPLMD_UPDATE, (CRYPT_EAL_ImplMdUpdate)CRYPT_SHA3_512_UpdateWrapper},
    {CRYPT_EAL_IMPLMD_FINAL, (CRYPT_EAL_ImplMdFinal)CRYPT_SHA3_512_FinalWrapper},
    {CRYPT_EAL_IMPLMD_DEINITCTX, (CRYPT_EAL_ImplMdDeInitCtx)CRYPT_SHA3_512_DeinitWrapper},
    {CRYPT_EAL_IMPLMD_DUPCTX, (CRYPT_EAL_ImplMdDupCtx)CRYPT_SHA3_512_DupCtxWrapper},
    {CRYPT_EAL_IMPLMD_FREECTX, (CRYPT_EAL_ImplMdFreeCtx)CRYPT_SHA3_512_FreeCtxWrapper},
    {CRYPT_EAL_IMPLMD_COPYCTX, (CRYPT_EAL_ImplMdCopyCtx)CRYPT_SHA3_512_CopyCtxWrapper},
    {CRYPT_EAL_IMPLMD_GETPARAM, (CRYPT_EAL_ImplMdGetParam)CRYPT_SHA3_512_GetParamWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoMdShake128[] = {
#ifdef HITLS_CRYPTO_SHA3
    {CRYPT_EAL_IMPLMD_NEWCTX, (CRYPT_EAL_ImplMdNewCtx)CRYPT_SHAKE128_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMD_INITCTX, (CRYPT_EAL_ImplMdInitCtx)CRYPT_SHAKE128_InitWrapper},
    {CRYPT_EAL_IMPLMD_UPDATE, (CRYPT_EAL_ImplMdUpdate)CRYPT_SHAKE128_UpdateWrapper},
    {CRYPT_EAL_IMPLMD_FINAL, (CRYPT_EAL_ImplMdFinal)CRYPT_SHAKE128_FinalWrapper},
    {CRYPT_EAL_IMPLMD_DEINITCTX, (CRYPT_EAL_ImplMdDeInitCtx)CRYPT_SHAKE128_DeinitWrapper},
    {CRYPT_EAL_IMPLMD_DUPCTX, (CRYPT_EAL_ImplMdDupCtx)CRYPT_SHAKE128_DupCtxWrapper},
    {CRYPT_EAL_IMPLMD_FREECTX, (CRYPT_EAL_ImplMdFreeCtx)CRYPT_SHAKE128_FreeCtxWrapper},
    {CRYPT_EAL_IMPLMD_SQUEEZE, (CRYPT_EAL_ImplMdSqueeze)CRYPT_SHAKE128_SqueezeWrapper},
    {CRYPT_EAL_IMPLMD_COPYCTX, (CRYPT_EAL_ImplMdCopyCtx)CRYPT_SHAKE128_CopyCtxWrapper},
    {CRYPT_EAL_IMPLMD_GETPARAM, (CRYPT_EAL_ImplMdGetParam)CRYPT_SHAKE128_GetParamWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoMdShake256[] = {
#ifdef HITLS_CRYPTO_SHA3
    {CRYPT_EAL_IMPLMD_NEWCTX, (CRYPT_EAL_ImplMdNewCtx)CRYPT_SHAKE256_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMD_INITCTX, (CRYPT_EAL_ImplMdInitCtx)CRYPT_SHAKE256_InitWrapper},
    {CRYPT_EAL_IMPLMD_UPDATE, (CRYPT_EAL_ImplMdUpdate)CRYPT_SHAKE256_UpdateWrapper},
    {CRYPT_EAL_IMPLMD_FINAL, (CRYPT_EAL_ImplMdFinal)CRYPT_SHAKE256_FinalWrapper},
    {CRYPT_EAL_IMPLMD_DEINITCTX, (CRYPT_EAL_ImplMdDeInitCtx)CRYPT_SHAKE256_DeinitWrapper},
    {CRYPT_EAL_IMPLMD_DUPCTX, (CRYPT_EAL_ImplMdDupCtx)CRYPT_SHAKE256_DupCtxWrapper},
    {CRYPT_EAL_IMPLMD_FREECTX, (CRYPT_EAL_ImplMdFreeCtx)CRYPT_SHAKE256_FreeCtxWrapper},
    {CRYPT_EAL_IMPLMD_SQUEEZE, (CRYPT_EAL_ImplMdSqueeze)CRYPT_SHAKE256_SqueezeWrapper},
    {CRYPT_EAL_IMPLMD_COPYCTX, (CRYPT_EAL_ImplMdCopyCtx)CRYPT_SHAKE256_CopyCtxWrapper},
    {CRYPT_EAL_IMPLMD_GETPARAM, (CRYPT_EAL_ImplMdGetParam)CRYPT_SHAKE256_GetParamWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_isoMdSm3[] = {
#ifdef HITLS_CRYPTO_SM3
    {CRYPT_EAL_IMPLMD_NEWCTX, (CRYPT_EAL_ImplMdNewCtx)CRYPT_SM3_NewCtxExWrapper},
    {CRYPT_EAL_IMPLMD_INITCTX, (CRYPT_EAL_ImplMdInitCtx)CRYPT_SM3_InitWrapper},
    {CRYPT_EAL_IMPLMD_UPDATE, (CRYPT_EAL_ImplMdUpdate)CRYPT_SM3_UpdateWrapper},
    {CRYPT_EAL_IMPLMD_FINAL, (CRYPT_EAL_ImplMdFinal)CRYPT_SM3_FinalWrapper},
    {CRYPT_EAL_IMPLMD_DEINITCTX, (CRYPT_EAL_ImplMdDeInitCtx)CRYPT_SM3_DeinitWrapper},
    {CRYPT_EAL_IMPLMD_DUPCTX, (CRYPT_EAL_ImplMdDupCtx)CRYPT_SM3_DupCtxWrapper},
    {CRYPT_EAL_IMPLMD_FREECTX, (CRYPT_EAL_ImplMdFreeCtx)CRYPT_SM3_FreeCtxWrapper},
    {CRYPT_EAL_IMPLMD_COPYCTX, (CRYPT_EAL_ImplMdCopyCtx)CRYPT_SM3_CopyCtxWrapper},
    {CRYPT_EAL_IMPLMD_GETPARAM, (CRYPT_EAL_ImplMdGetParam)CRYPT_SM3_GetParamWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */
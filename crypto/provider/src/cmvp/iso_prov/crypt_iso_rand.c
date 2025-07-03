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
#include "crypt_drbg.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "crypt_ealinit.h"
#include "bsl_params.h"
#include "crypt_iso_selftest.h"
#include "crypt_iso_provider.h"

#if defined(HITLS_CRYPTO_DRBG)
typedef struct {
    int32_t algId;
    void *ctx;
    void *mgrCtx;
} IsoRandCtx;

static void *CRYPT_EAL_IsoRandNewCtx(int32_t algId, BSL_Param *param)
{
    void *randCtx = NULL;
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Drbg(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    BSL_Param *getEnt = BSL_PARAM_FindParam(param, CRYPT_PARAM_RAND_SEED_GETENTROPY);
    if (param == NULL || getEnt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }
    randCtx = DRBG_New(algId, param);
    if (randCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
    return randCtx;
}

static void *CRYPT_EAL_IsoRandNewCtxWrapper(CRYPT_EAL_IsoProvCtx *provCtx, int32_t algId, BSL_Param *param)
{
    if (provCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    void *randCtx = CRYPT_EAL_IsoRandNewCtx(algId, param);
    if (randCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    IsoRandCtx *ctx = BSL_SAL_Calloc(1, sizeof(IsoRandCtx));
    if (ctx == NULL) {
        DRBG_Free(randCtx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->algId = algId;
    ctx->ctx = randCtx;
    ctx->mgrCtx = provCtx->mgrCtx;
    return ctx;
}

static int32_t DRBG_InstantiateWrapper(IsoRandCtx *ctx, const uint8_t *person, uint32_t persLen, BSL_Param *param)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_Iso_Log(ctx->mgrCtx, CRYPT_EVENT_SETSSP, CRYPT_ALGO_RAND, ctx->algId);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return DRBG_Instantiate(ctx->ctx, person, persLen, param);
}

static int32_t DRBG_UninstantiateWrapper(IsoRandCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_Iso_Log(ctx->mgrCtx, CRYPT_EVENT_ZERO, CRYPT_ALGO_RAND, ctx->algId);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return DRBG_Uninstantiate(ctx->ctx);
}

static int32_t DRBG_GenerateBytesWrapper(IsoRandCtx *ctx, uint8_t *out, uint32_t outLen, const uint8_t *adin,
    uint32_t adinLen, BSL_Param *param)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_Iso_Log(ctx->mgrCtx, CRYPT_EVENT_RANDGEN, CRYPT_ALGO_RAND, ctx->algId);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return DRBG_GenerateBytes(ctx->ctx, out, outLen, adin, adinLen, param);
}

static int32_t DRBG_ReseedWrapper(IsoRandCtx *ctx, const uint8_t *adin, uint32_t adinLen, BSL_Param *param)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_Iso_Log(ctx->mgrCtx, CRYPT_EVENT_SETSSP, CRYPT_ALGO_RAND, ctx->algId);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return DRBG_Reseed(ctx->ctx, adin, adinLen, param);
}

static int32_t DRBG_CtrlWrapper(IsoRandCtx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return DRBG_Ctrl(ctx->ctx, opt, val, len);
}

static void DRBG_FreeWrapper(IsoRandCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    (void)CRYPT_Iso_Log(ctx->mgrCtx, CRYPT_EVENT_ZERO, CRYPT_ALGO_RAND, ctx->algId);
    if (ctx->ctx != NULL) {
        DRBG_Free(ctx->ctx);
    }
    BSL_SAL_Free(ctx);
}
#endif

const CRYPT_EAL_Func g_isoRand[] = {
#if defined(HITLS_CRYPTO_DRBG)
    {CRYPT_EAL_IMPLRAND_DRBGNEWCTX, (CRYPT_EAL_ImplRandDrbgNewCtx)CRYPT_EAL_IsoRandNewCtxWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGINST, (CRYPT_EAL_ImplRandDrbgInst)DRBG_InstantiateWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGUNINST, (CRYPT_EAL_ImplRandDrbgUnInst)DRBG_UninstantiateWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGGEN, (CRYPT_EAL_ImplRandDrbgGen)DRBG_GenerateBytesWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGRESEED, (CRYPT_EAL_ImplRandDrbgReSeed)DRBG_ReseedWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGCTRL, (CRYPT_EAL_ImplRandDrbgCtrl)DRBG_CtrlWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGFREECTX, (CRYPT_EAL_ImplRandDrbgFreeCtx)DRBG_FreeWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */
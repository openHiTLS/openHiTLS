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
#ifdef HITLS_CRYPTO_CMVP_SM

#include "securec.h"
#include "crypt_eal_implprovider.h"
#include "crypt_drbg.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "crypt_ealinit.h"
#include "crypt_cmvp_selftest.h"
#include "bsl_params.h"
#include "eal_entropy.h"
#include "crypt_sm_provider.h"

#ifdef HITLS_CRYPTO_ENTROPY
#define SM_RANDOM_MIN_LEN 32

typedef struct {
    void *ctx;
    int32_t isSelfTest;
} SmRandCtx;

static int32_t GetDefaultSeed(CRYPT_EAL_SmProvCtx *provCtx, BSL_Param *param)
{
    CRYPT_RandSeedMethod seedMethod = {0};
    int32_t ret = EAL_SetDefaultEntropyMeth(&seedMethod);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    int32_t index = 0;
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR,
        provCtx->pool, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR,
        seedMethod.getEntropy, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR,
        seedMethod.cleanEntropy, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR,
        seedMethod.getNonce, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR,
        seedMethod.cleanNonce, 0);
    return CRYPT_SUCCESS;
}
#endif

static void *CRYPT_EAL_SmRandNewCtx(CRYPT_EAL_SmProvCtx *provCtx, int32_t algId, BSL_Param *param)
{
    void *randCtx = NULL;
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Drbg(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    BSL_Param *getEnt = BSL_PARAM_FindParam(param, CRYPT_PARAM_RAND_SEED_GETENTROPY);
    BSL_Param *cleanEnt = BSL_PARAM_FindParam(param, CRYPT_PARAM_RAND_SEED_CLEANENTROPY);
    BSL_Param *getNonce = BSL_PARAM_FindParam(param, CRYPT_PARAM_RAND_SEED_GETNONCE);
    BSL_Param *cleanNonce = BSL_PARAM_FindParam(param, CRYPT_PARAM_RAND_SEED_CLEANNONCE);
    BSL_Param *ctx = BSL_PARAM_FindParam(param, CRYPT_PARAM_RAND_SEEDCTX);
    /**
     * If you use a registered entropy source, the getEntropy callback cannot be NULL,
     * and if getEntropy is NULL, cleanEntropy, getNonce, cleanNonce, etc. must be NULL
     */
    if (getEnt == NULL && ((cleanEnt != NULL && cleanEnt->value != NULL) ||
        (getNonce != NULL && getNonce->value != NULL) || (cleanNonce != NULL && cleanNonce->value != NULL) ||
        (ctx != NULL && ctx->value != NULL))) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }
    if (param == NULL || getEnt == NULL) {
#ifdef HITLS_CRYPTO_ENTROPY
        BSL_Param defaultParam[6] = {BSL_PARAM_END};
        if (GetDefaultSeed(provCtx, defaultParam) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return NULL;
        }
        return DRBG_NewEx(provCtx->libCtx, algId, defaultParam);
#else
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
#endif
    }
    randCtx = DRBG_NewEx(provCtx->libCtx, algId, param);
    if (randCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
    return randCtx;
}

void *CRYPT_EAL_SmRandNewCtxWrapper(CRYPT_EAL_SmProvCtx *provCtx, int32_t algId, BSL_Param *param)
{
    if (provCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    SmRandCtx *ctx = BSL_SAL_Calloc(1, sizeof(SmRandCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    void *randCtx = CRYPT_EAL_SmRandNewCtx(provCtx, algId, param);
    if (randCtx == NULL) {
        BSL_SAL_FREE(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->ctx = randCtx;
    ctx->isSelfTest = 1;
    return ctx;
}

static int32_t DRBG_InstantiateWrapper(SmRandCtx *ctx, const uint8_t *person, uint32_t persLen, BSL_Param *param)
{
    (void)param;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return DRBG_Instantiate(ctx->ctx, person, persLen);
}

static int32_t DRBG_UninstantiateWrapper(SmRandCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return DRBG_Uninstantiate(ctx->ctx);
}

static int32_t GenerateBytesAndTest(void *ctx, uint8_t *out, uint32_t outLen,
    const uint8_t *adin, uint32_t adinLen, BSL_Param *param)
{
    // 2: GM/T 0062-2018 Table 8, retry 2 times
    (void)param;
    for (uint32_t attempt = 0; attempt < 2; attempt++) {
        int32_t ret = DRBG_GenerateBytes(ctx, out, outLen, adin, adinLen);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        ret = CRYPT_CMVP_RandomnessTest(out, outLen);
        if (ret != CRYPT_SUCCESS) {
            continue;
        }
        return CRYPT_SUCCESS;
    }
    return CRYPT_CMVP_RANDOMNESS_ERR;
}

static int32_t DRBG_GenerateBytesWrapper(SmRandCtx *ctx, uint8_t *out, uint32_t outLen,
    const uint8_t *adin, uint32_t adinLen, BSL_Param *param)
{
    (void)param;
    if (ctx == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->isSelfTest == 0) {
        return DRBG_GenerateBytes(ctx->ctx, out, outLen, adin, adinLen);
    }

    /*
     * To satisfy the minimum 256-bit test length requirement:
     * - If outLen < 256 bits, internally generate and test 256 bits (SM_RANDOM_MIN_LEN),
     *   then copy only the requested length back to the caller upon success.
     * - If outLen >= 256 bits, test directly on the target output buffer.
     */
    uint8_t randomData[SM_RANDOM_MIN_LEN] = {0};
    uint32_t dataLen = outLen < SM_RANDOM_MIN_LEN ? SM_RANDOM_MIN_LEN : outLen;
    uint8_t *data = outLen < SM_RANDOM_MIN_LEN ? randomData : out;

    int32_t ret = GenerateBytesAndTest(ctx->ctx, data, dataLen, adin, adinLen, param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (outLen < SM_RANDOM_MIN_LEN) {
        (void)memcpy_s(out, outLen, randomData, outLen);
    }
    return CRYPT_SUCCESS;
}

static int32_t DRBG_ReseedWrapper(SmRandCtx *ctx, const uint8_t *adin, uint32_t adinLen, BSL_Param *param)
{
    (void)param;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return DRBG_Reseed(ctx->ctx, adin, adinLen);
}

static int32_t DRBG_CtrlWrapper(SmRandCtx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (opt == CRYPT_CTRL_SET_SELFTEST_FLAG) {
        if (val == NULL || len != sizeof(int32_t) || (*(int32_t*)val != 0 && *(int32_t*)val != 1)) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        ctx->isSelfTest = *(int32_t*)val;
        return CRYPT_SUCCESS;
    }
    return DRBG_Ctrl(ctx->ctx, opt, val, len);
}

static void DRBG_FreeWrapper(SmRandCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    DRBG_Free(ctx->ctx);
    BSL_SAL_FREE(ctx);
}

const CRYPT_EAL_Func g_smRand[] = {
#if defined(HITLS_CRYPTO_DRBG)
    {CRYPT_EAL_IMPLRAND_DRBGNEWCTX, (CRYPT_EAL_ImplRandDrbgNewCtx)CRYPT_EAL_SmRandNewCtxWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGINST, (CRYPT_EAL_ImplRandDrbgInst)DRBG_InstantiateWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGUNINST, (CRYPT_EAL_ImplRandDrbgUnInst)DRBG_UninstantiateWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGGEN, (CRYPT_EAL_ImplRandDrbgGen)DRBG_GenerateBytesWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGRESEED, (CRYPT_EAL_ImplRandDrbgReSeed)DRBG_ReseedWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGCTRL, (CRYPT_EAL_ImplRandDrbgCtrl)DRBG_CtrlWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGFREECTX, (CRYPT_EAL_ImplRandDrbgFreeCtx)DRBG_FreeWrapper},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_CMVP_SM */
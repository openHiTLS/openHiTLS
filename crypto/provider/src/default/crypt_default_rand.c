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
#ifdef HITLS_CRYPTO_PROVIDER

#include "crypt_eal_implprovider.h"
#include "crypt_drbg.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "crypt_ealinit.h"
#include "bsl_params.h"
#include "crypt_default_provider.h"

#ifdef HITLS_CRYPTO_ENTROPY
static int32_t GetDefaultSeed(BSL_Param *param)
{
    void *defaultSeedCtx = NULL;
    CRYPT_RandSeedMethod *defaultSeedMethod = NULL;
    int32_t ret = CRYPT_EAL_ProviderGetSeed(&defaultSeedMethod, &defaultSeedCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, defaultSeedCtx, 0);
    (void)BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR,
        defaultSeedMethod->getEntropy, 0);
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR,
        defaultSeedMethod->cleanEntropy, 0);
    (void)BSL_PARAM_InitValue(&param[3], CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR,
        defaultSeedMethod->getNonce, 0);
    (void)BSL_PARAM_InitValue(&param[4], CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR,
        defaultSeedMethod->cleanNonce, 0);
    return CRYPT_SUCCESS;
}
#endif

void *CRYPT_EAL_DefRandNewCtx(void *provCtx, int32_t algId, BSL_Param *param)
{
    (void) provCtx;
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
        if (GetDefaultSeed(defaultParam) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return NULL;
        }
        return DRBG_New(algId, defaultParam);
#else
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
#endif
    }
    randCtx = DRBG_New(algId, param);
    if (randCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
    return randCtx;
}

const CRYPT_EAL_Func g_defRand[] = {
#if defined(HITLS_CRYPTO_DRBG)
    {CRYPT_EAL_IMPLRAND_DRBGNEWCTX, (CRYPT_EAL_ImplRandDrbgNewCtx)CRYPT_EAL_DefRandNewCtx},
    {CRYPT_EAL_IMPLRAND_DRBGINST, (CRYPT_EAL_ImplRandDrbgInst)DRBG_Instantiate},
    {CRYPT_EAL_IMPLRAND_DRBGUNINST, (CRYPT_EAL_ImplRandDrbgUnInst)DRBG_Uninstantiate},
    {CRYPT_EAL_IMPLRAND_DRBGGEN, (CRYPT_EAL_ImplRandDrbgGen)DRBG_GenerateBytes},
    {CRYPT_EAL_IMPLRAND_DRBGRESEED, (CRYPT_EAL_ImplRandDrbgReSeed)DRBG_Reseed},
    {CRYPT_EAL_IMPLRAND_DRBGCTRL, (CRYPT_EAL_ImplRandDrbgCtrl)DRBG_Ctrl},
    {CRYPT_EAL_IMPLRAND_DRBGFREECTX, (CRYPT_EAL_ImplRandDrbgFreeCtx)DRBG_Free},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_PROVIDER */
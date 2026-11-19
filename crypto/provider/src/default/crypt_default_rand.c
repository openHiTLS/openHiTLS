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
#if defined(HITLS_CRYPTO_DRBG) && defined(HITLS_CRYPTO_PROVIDER)

#include "crypt_eal_implprovider.h"
#include "crypt_drbg.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "eal_rand_local.h"
#include "crypt_ealinit.h"
#include "crypt_params_key.h"
#include "crypt_default_provider.h"

#ifdef HITLS_CRYPTO_ENTROPY
static void GetDefaultSeed(const CRYPT_EAL_DefProvCtx *provCtx, BSL_Param *param)
{
    (void)BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, provCtx->seedCtx, 0);
    (void)BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR,
        provCtx->seedMethod.getEntropy, 0);
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR,
        provCtx->seedMethod.cleanEntropy, 0);
    (void)BSL_PARAM_InitValue(&param[3], CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR,
        provCtx->seedMethod.getNonce, 0);
    (void)BSL_PARAM_InitValue(&param[4], CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR,
        provCtx->seedMethod.cleanNonce, 0);
}
#endif

static void *DRBG_DefRandNewCtx(CRYPT_EAL_DefProvCtx *provCtx, int32_t algId, BSL_Param *param)
{
    void *libCtx = provCtx == NULL ? NULL : provCtx->libCtx;
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
    bool nullInput = getEnt == NULL && ((cleanEnt != NULL && cleanEnt->value != NULL) ||
        (getNonce != NULL && getNonce->value != NULL) || (cleanNonce != NULL && cleanNonce->value != NULL) ||
        (ctx != NULL && ctx->value != NULL));
    if (nullInput == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }
    if (param == NULL || getEnt == NULL) {
#ifdef HITLS_CRYPTO_ENTROPY
        if (provCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return NULL;
        }
        BSL_Param defaultParam[6] = {BSL_PARAM_END};
        GetDefaultSeed(provCtx, defaultParam);
        return DRBG_NewEx(libCtx, algId, defaultParam);
#else
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
#endif
    }
    randCtx = DRBG_NewEx(libCtx, algId, param);
    if (randCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
    return randCtx;
}

const CRYPT_EAL_Func g_defEalRand[] = {
    {CRYPT_EAL_IMPLRAND_DRBGNEWCTX, (CRYPT_EAL_ImplRandDrbgNewCtx)DRBG_DefRandNewCtx},
    {CRYPT_EAL_IMPLRAND_DRBGINST, (CRYPT_EAL_ImplRandDrbgInst)DRBG_InstantiateWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGUNINST, (CRYPT_EAL_ImplRandDrbgUnInst)DRBG_Uninstantiate},
    {CRYPT_EAL_IMPLRAND_DRBGGEN, (CRYPT_EAL_ImplRandDrbgGen)DRBG_GenerateBytesWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGRESEED, (CRYPT_EAL_ImplRandDrbgReSeed)DRBG_ReSeedWrapper},
    {CRYPT_EAL_IMPLRAND_DRBGCTRL, (CRYPT_EAL_ImplRandDrbgCtrl)DRBG_Ctrl},
    {CRYPT_EAL_IMPLRAND_DRBGFREECTX, (CRYPT_EAL_ImplRandDrbgFreeCtx)DRBG_Free},
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_DRBG && HITLS_CRYPTO_PROVIDER */

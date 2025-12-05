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

#include "crypt_eal_implprovider.h"
#include "crypt_sm_provider.h"
#include "crypt_sm3.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "crypt_ealinit.h"

static void *CRYPT_EAL_SmMdNewCtxEx(CRYPT_EAL_SmProvCtx *provCtx, int32_t algId)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Md(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    if (provCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    switch (algId) {
#ifdef HITLS_CRYPTO_SM3
        case CRYPT_MD_SM3:
            return CRYPT_SM3_NewCtxEx(provCtx->libCtx, algId);
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
            return NULL;
    }
}

const CRYPT_EAL_Func g_smMdSm3[] = {
#ifdef HITLS_CRYPTO_SM3
    {CRYPT_EAL_IMPLMD_NEWCTX, (CRYPT_EAL_ImplMdNewCtx)CRYPT_EAL_SmMdNewCtxEx},
    {CRYPT_EAL_IMPLMD_INITCTX, (CRYPT_EAL_ImplMdInitCtx)CRYPT_SM3_InitEx},
    {CRYPT_EAL_IMPLMD_UPDATE, (CRYPT_EAL_ImplMdUpdate)CRYPT_SM3_Update},
    {CRYPT_EAL_IMPLMD_FINAL, (CRYPT_EAL_ImplMdFinal)CRYPT_SM3_Final},
    {CRYPT_EAL_IMPLMD_DEINITCTX, (CRYPT_EAL_ImplMdDeInitCtx)CRYPT_SM3_Deinit},
    {CRYPT_EAL_IMPLMD_DUPCTX, (CRYPT_EAL_ImplMdDupCtx)CRYPT_SM3_DupCtx},
    {CRYPT_EAL_IMPLMD_FREECTX, (CRYPT_EAL_ImplMdFreeCtx)CRYPT_SM3_FreeCtx},
    {CRYPT_EAL_IMPLMD_COPYCTX, (CRYPT_EAL_ImplMdCopyCtx)CRYPT_SM3_CopyCtx},
    {CRYPT_EAL_IMPLMD_GETPARAM, (CRYPT_EAL_ImplMdGetParam)CRYPT_SM3_GetParam},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_CMVP_SM */

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
#ifdef HITLS_CRYPTO_SM2
#include "crypt_sm2.h"
#endif
#include "crypt_errno.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "crypt_ealinit.h"
#include "cmvp_sm.h"
#include "crypt_sm_provider.h"

void *CRYPT_EAL_SmPkeyMgmtNewCtx(CRYPT_EAL_SmProvCtx *provCtx, int32_t algId)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Pkey(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    if (provCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    switch (algId) {
#ifdef HITLS_CRYPTO_SM2
        case CRYPT_PKEY_SM2:
            return CRYPT_SM2_NewCtxEx(provCtx->libCtx);
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
            return NULL;
    }
};

static int32_t CRYPT_SM2_GenWrapper(CRYPT_SM2_Ctx *ctx)
{
    int32_t ret = CRYPT_SM2_Gen(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (!CMVP_SmPkeyPct(ctx, CRYPT_PKEY_SM2)) {
        return CRYPT_CMVP_ERR_PAIRWISETEST;
    }
    return CRYPT_SUCCESS;
}

const CRYPT_EAL_Func g_smKeyMgmtSm2[] = {
#ifdef HITLS_CRYPTO_SM2
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_EAL_SmPkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)CRYPT_SM2_GenWrapper},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)CRYPT_SM2_SetPrvKeyEx},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)CRYPT_SM2_SetPubKeyEx},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)CRYPT_SM2_GetPrvKeyEx},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)CRYPT_SM2_GetPubKeyEx},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)CRYPT_SM2_DupCtx},
#ifdef HITLS_CRYPTO_SM2_CHECK
    {CRYPT_EAL_IMPLPKEYMGMT_CHECK, (CRYPT_EAL_ImplPkeyMgmtCheck)CRYPT_SM2_Check},
#endif
#ifdef HITLS_CRYPTO_SM2_CMP
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)CRYPT_SM2_Cmp},
#endif
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)CRYPT_SM2_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)CRYPT_SM2_FreeCtx},
#ifdef HITLS_CRYPTO_KEY_DECODE_CHAIN
    {CRYPT_EAL_IMPLPKEYMGMT_IMPORT, (CRYPT_EAL_ImplPkeyMgmtImport)CRYPT_SM2_Import},
    {CRYPT_EAL_IMPLPKEYMGMT_EXPORT, (CRYPT_EAL_ImplPkeyMgmtExport)CRYPT_SM2_Export},
#endif // HITLS_CRYPTO_KEY_DECODE_CHAIN
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_CMVP_SM */

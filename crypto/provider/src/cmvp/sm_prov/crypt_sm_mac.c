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
#include "crypt_hmac.h"
#include "crypt_cbc_mac.h"
#include "crypt_ealinit.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"

void *CRYPT_EAL_SmMacNewCtxEx(CRYPT_EAL_SmProvCtx *provCtx, int32_t algId)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Mac(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    if (provCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    switch (algId) {
#ifdef HITLS_CRYPTO_HMAC
        case CRYPT_MAC_HMAC_SM3:
            return CRYPT_HMAC_NewCtxEx(provCtx->libCtx, algId);
#endif
#ifdef HITLS_CRYPTO_CBC_MAC
        case CRYPT_MAC_CBC_MAC_SM4:
            return CRYPT_CBC_MAC_NewCtxEx(provCtx->libCtx, algId);
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
            return NULL;
    }
}

const CRYPT_EAL_Func g_smMacHmac[] = {
#ifdef HITLS_CRYPTO_HMAC
    {CRYPT_EAL_IMPLMAC_NEWCTX, (CRYPT_EAL_ImplMacNewCtx)CRYPT_EAL_SmMacNewCtxEx},
    {CRYPT_EAL_IMPLMAC_INIT, (CRYPT_EAL_ImplMacInit)CRYPT_HMAC_InitEx},
    {CRYPT_EAL_IMPLMAC_UPDATE, (CRYPT_EAL_ImplMacUpdate)CRYPT_HMAC_Update},
    {CRYPT_EAL_IMPLMAC_FINAL, (CRYPT_EAL_ImplMacFinal)CRYPT_HMAC_Final},
    {CRYPT_EAL_IMPLMAC_DEINITCTX, (CRYPT_EAL_ImplMacDeInitCtx)CRYPT_HMAC_Deinit},
    {CRYPT_EAL_IMPLMAC_REINITCTX, (CRYPT_EAL_ImplMacReInitCtx)CRYPT_HMAC_Reinit},
    {CRYPT_EAL_IMPLMAC_CTRL, (CRYPT_EAL_ImplMacCtrl)CRYPT_HMAC_Ctrl},
    {CRYPT_EAL_IMPLMAC_FREECTX, (CRYPT_EAL_ImplMacFreeCtx)CRYPT_HMAC_FreeCtx},
    {CRYPT_EAL_IMPLMAC_SETPARAM, (CRYPT_EAL_ImplMacSetParam)CRYPT_HMAC_SetParam},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_smMacCbcMac[] = {
#ifdef HITLS_CRYPTO_CBC_MAC
    {CRYPT_EAL_IMPLMAC_NEWCTX, (CRYPT_EAL_ImplMacNewCtx)CRYPT_EAL_SmMacNewCtxEx},
    {CRYPT_EAL_IMPLMAC_INIT, (CRYPT_EAL_ImplMacInit)CRYPT_CBC_MAC_InitEx},
    {CRYPT_EAL_IMPLMAC_UPDATE, (CRYPT_EAL_ImplMacUpdate)CRYPT_CBC_MAC_Update},
    {CRYPT_EAL_IMPLMAC_FINAL, (CRYPT_EAL_ImplMacFinal)CRYPT_CBC_MAC_Final},
    {CRYPT_EAL_IMPLMAC_DEINITCTX, (CRYPT_EAL_ImplMacDeInitCtx)CRYPT_CBC_MAC_Deinit},
    {CRYPT_EAL_IMPLMAC_REINITCTX, (CRYPT_EAL_ImplMacReInitCtx)CRYPT_CBC_MAC_Reinit},
    {CRYPT_EAL_IMPLMAC_CTRL, (CRYPT_EAL_ImplMacCtrl)CRYPT_CBC_MAC_Ctrl},
    {CRYPT_EAL_IMPLMAC_FREECTX, (CRYPT_EAL_ImplMacFreeCtx)CRYPT_CBC_MAC_FreeCtx},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_CMVP_SM */

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
#if defined(HITLS_CRYPTO_MAC) && defined(HITLS_CRYPTO_PROVIDER)

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
#include "crypt_default_provider.h"

void *CRYPT_EAL_DefMacNewCtx(CRYPT_EAL_DefProvCtx *provCtx, int32_t algId)
{
    void *libCtx = provCtx == NULL ? NULL : provCtx->libCtx;
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Mac(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif

    switch (algId) {
#ifdef HITLS_CRYPTO_HMAC
        case CRYPT_MAC_HMAC_MD5:
        case CRYPT_MAC_HMAC_SHA1:
        case CRYPT_MAC_HMAC_SHA224:
        case CRYPT_MAC_HMAC_SHA256:
        case CRYPT_MAC_HMAC_SHA384:
        case CRYPT_MAC_HMAC_SHA512:
        case CRYPT_MAC_HMAC_SHA3_224:
        case CRYPT_MAC_HMAC_SHA3_256:
        case CRYPT_MAC_HMAC_SHA3_384:
        case CRYPT_MAC_HMAC_SHA3_512:
        case CRYPT_MAC_HMAC_SM3:
            return CRYPT_HMAC_NewCtxEx(libCtx, algId);
#endif
#ifdef HITLS_CRYPTO_CMAC
        case CRYPT_MAC_CMAC_AES128:
        case CRYPT_MAC_CMAC_AES192:
        case CRYPT_MAC_CMAC_AES256:
        case CRYPT_MAC_CMAC_SM4:
            return CRYPT_CMAC_NewCtxEx(libCtx, algId);
#endif
#ifdef HITLS_CRYPTO_CBC_MAC
        case CRYPT_MAC_CBC_MAC_SM4:
            return CRYPT_CBC_MAC_NewCtxEx(libCtx, algId);
#endif
#ifdef HITLS_CRYPTO_SIPHASH
        case CRYPT_MAC_SIPHASH64:
        case CRYPT_MAC_SIPHASH128:
            return CRYPT_SIPHASH_NewCtxEx(libCtx, algId);
#endif
#ifdef HITLS_CRYPTO_GMAC
        case CRYPT_MAC_GMAC_AES128:
        case CRYPT_MAC_GMAC_AES192:
        case CRYPT_MAC_GMAC_AES256:
            return CRYPT_GMAC_NewCtxEx(libCtx, algId);
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
            return NULL;
    }
}

#ifdef HITLS_CRYPTO_HMAC
const CRYPT_EAL_Func g_defEalMacHmac[] = {
    {CRYPT_EAL_IMPLMAC_NEWCTX, (CRYPT_EAL_ImplMacNewCtx)CRYPT_EAL_DefMacNewCtx},
    {CRYPT_EAL_IMPLMAC_INIT, (CRYPT_EAL_ImplMacInit)CRYPT_HMAC_InitEx},
    {CRYPT_EAL_IMPLMAC_UPDATE, (CRYPT_EAL_ImplMacUpdate)CRYPT_HMAC_Update},
    {CRYPT_EAL_IMPLMAC_FINAL, (CRYPT_EAL_ImplMacFinal)CRYPT_HMAC_Final},
    {CRYPT_EAL_IMPLMAC_DEINITCTX, (CRYPT_EAL_ImplMacDeInitCtx)CRYPT_HMAC_Deinit},
    {CRYPT_EAL_IMPLMAC_REINITCTX, (CRYPT_EAL_ImplMacReInitCtx)CRYPT_HMAC_Reinit},
    {CRYPT_EAL_IMPLMAC_CTRL, (CRYPT_EAL_ImplMacCtrl)CRYPT_HMAC_Ctrl},
    {CRYPT_EAL_IMPLMAC_FREECTX, (CRYPT_EAL_ImplMacFreeCtx)CRYPT_HMAC_FreeCtx},
    {CRYPT_EAL_IMPLMAC_SETPARAM, (CRYPT_EAL_ImplMacSetParam)CRYPT_HMAC_SetParam},
    {CRYPT_EAL_IMPLMAC_DUPCTX, (CRYPT_EAL_ImplMacDupCtx)CRYPT_HMAC_DupCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_CMAC
const CRYPT_EAL_Func g_defEalMacCmac[] = {
    {CRYPT_EAL_IMPLMAC_NEWCTX, (CRYPT_EAL_ImplMacNewCtx)CRYPT_EAL_DefMacNewCtx},
    {CRYPT_EAL_IMPLMAC_INIT, (CRYPT_EAL_ImplMacInit)CRYPT_CMAC_InitEx},
    {CRYPT_EAL_IMPLMAC_UPDATE, (CRYPT_EAL_ImplMacUpdate)CRYPT_CMAC_Update},
    {CRYPT_EAL_IMPLMAC_FINAL, (CRYPT_EAL_ImplMacFinal)CRYPT_CMAC_Final},
    {CRYPT_EAL_IMPLMAC_DEINITCTX, (CRYPT_EAL_ImplMacDeInitCtx)CRYPT_CMAC_Deinit},
    {CRYPT_EAL_IMPLMAC_REINITCTX, (CRYPT_EAL_ImplMacReInitCtx)CRYPT_CMAC_Reinit},
    {CRYPT_EAL_IMPLMAC_CTRL, (CRYPT_EAL_ImplMacCtrl)CRYPT_CMAC_Ctrl},
    {CRYPT_EAL_IMPLMAC_FREECTX, (CRYPT_EAL_ImplMacFreeCtx)CRYPT_CMAC_FreeCtx},
    {CRYPT_EAL_IMPLMAC_DUPCTX, (CRYPT_EAL_ImplMacDupCtx)CRYPT_CMAC_DupCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_CBC_MAC
const CRYPT_EAL_Func g_defEalMacCbcMac[] = {
    {CRYPT_EAL_IMPLMAC_NEWCTX, (CRYPT_EAL_ImplMacNewCtx)CRYPT_EAL_DefMacNewCtx},
    {CRYPT_EAL_IMPLMAC_INIT, (CRYPT_EAL_ImplMacInit)CRYPT_CBC_MAC_InitEx},
    {CRYPT_EAL_IMPLMAC_UPDATE, (CRYPT_EAL_ImplMacUpdate)CRYPT_CBC_MAC_Update},
    {CRYPT_EAL_IMPLMAC_FINAL, (CRYPT_EAL_ImplMacFinal)CRYPT_CBC_MAC_Final},
    {CRYPT_EAL_IMPLMAC_DEINITCTX, (CRYPT_EAL_ImplMacDeInitCtx)CRYPT_CBC_MAC_Deinit},
    {CRYPT_EAL_IMPLMAC_REINITCTX, (CRYPT_EAL_ImplMacReInitCtx)CRYPT_CBC_MAC_Reinit},
    {CRYPT_EAL_IMPLMAC_CTRL, (CRYPT_EAL_ImplMacCtrl)CRYPT_CBC_MAC_Ctrl},
    {CRYPT_EAL_IMPLMAC_FREECTX, (CRYPT_EAL_ImplMacFreeCtx)CRYPT_CBC_MAC_FreeCtx},
    {CRYPT_EAL_IMPLMAC_DUPCTX, (CRYPT_EAL_ImplMacDupCtx)CRYPT_CBC_MAC_DupCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_GMAC
const CRYPT_EAL_Func g_defEalMacGmac[] = {
    {CRYPT_EAL_IMPLMAC_NEWCTX, (CRYPT_EAL_ImplMacNewCtx)CRYPT_EAL_DefMacNewCtx},
    {CRYPT_EAL_IMPLMAC_INIT, (CRYPT_EAL_ImplMacInit)CRYPT_GMAC_InitEx},
    {CRYPT_EAL_IMPLMAC_UPDATE, (CRYPT_EAL_ImplMacUpdate)CRYPT_GMAC_Update},
    {CRYPT_EAL_IMPLMAC_FINAL, (CRYPT_EAL_ImplMacFinal)CRYPT_GMAC_Final},
    {CRYPT_EAL_IMPLMAC_DEINITCTX, (CRYPT_EAL_ImplMacDeInitCtx)CRYPT_GMAC_Deinit},
    {CRYPT_EAL_IMPLMAC_CTRL, (CRYPT_EAL_ImplMacCtrl)CRYPT_GMAC_Ctrl},
    {CRYPT_EAL_IMPLMAC_FREECTX, (CRYPT_EAL_ImplMacFreeCtx)CRYPT_GMAC_FreeCtx},
    {CRYPT_EAL_IMPLMAC_DUPCTX, (CRYPT_EAL_ImplMacDupCtx)CRYPT_GMAC_DupCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#ifdef HITLS_CRYPTO_SIPHASH
const CRYPT_EAL_Func g_defEalMacSiphash[] = {
    {CRYPT_EAL_IMPLMAC_NEWCTX, (CRYPT_EAL_ImplMacNewCtx)CRYPT_EAL_DefMacNewCtx},
    {CRYPT_EAL_IMPLMAC_INIT, (CRYPT_EAL_ImplMacInit)CRYPT_SIPHASH_InitEx},
    {CRYPT_EAL_IMPLMAC_UPDATE, (CRYPT_EAL_ImplMacUpdate)CRYPT_SIPHASH_Update},
    {CRYPT_EAL_IMPLMAC_FINAL, (CRYPT_EAL_ImplMacFinal)CRYPT_SIPHASH_Final},
    {CRYPT_EAL_IMPLMAC_DEINITCTX, (CRYPT_EAL_ImplMacDeInitCtx)CRYPT_SIPHASH_Deinit},
    {CRYPT_EAL_IMPLMAC_REINITCTX, (CRYPT_EAL_ImplMacReInitCtx)CRYPT_SIPHASH_Reinit},
    {CRYPT_EAL_IMPLMAC_CTRL, (CRYPT_EAL_ImplMacCtrl)CRYPT_SIPHASH_Ctrl},
    {CRYPT_EAL_IMPLMAC_FREECTX, (CRYPT_EAL_ImplMacFreeCtx)CRYPT_SIPHASH_FreeCtx},
    {CRYPT_EAL_IMPLMAC_DUPCTX, (CRYPT_EAL_ImplMacDupCtx)CRYPT_SIPHASH_DupCtx},
    CRYPT_EAL_FUNC_END,
};
#endif

#endif
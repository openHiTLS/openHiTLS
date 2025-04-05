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
#include "crypt_hmac.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "crypt_ealinit.h"

#define MAC_DEINIT_FUNC(name) \
    static int32_t CRYPT_##name##_DeinitWrapper(void *ctx) \
    { \
        CRYPT_##name##_Deinit(ctx); \
        return CRYPT_SUCCESS; \
    }

#define MAC_REINIT_FUNC(name) \
    static int32_t CRYPT_##name##_ReinitWrapper(void *ctx) \
    { \
        CRYPT_##name##_Reinit(ctx); \
        return CRYPT_SUCCESS; \
    }

#define MAC_FUNCS(name) \
    MAC_DEINIT_FUNC(name) \
    MAC_REINIT_FUNC(name)

MAC_FUNCS(HMAC)

void *CRYPT_EAL_DefMacNewCtx(void *provCtx, int32_t algId)
{
    (void) provCtx;
    void *macCtx = NULL;
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Mac(algId) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    switch (algId) {
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
            macCtx = CRYPT_HMAC_NewCtx(algId);
            break;
    }
    if (macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
    return macCtx;
}

const CRYPT_EAL_Func g_defMacHmac[] = {
    {CRYPT_EAL_IMPLMAC_NEWCTX, (CRYPT_EAL_ImplMacNewCtx)CRYPT_EAL_DefMacNewCtx},
    {CRYPT_EAL_IMPLMAC_INIT, (CRYPT_EAL_ImplMacInit)CRYPT_HMAC_Init},
    {CRYPT_EAL_IMPLMAC_UPDATE, (CRYPT_EAL_ImplMacUpdate)CRYPT_HMAC_Update},
    {CRYPT_EAL_IMPLMAC_FINAL, (CRYPT_EAL_ImplMacFinal)CRYPT_HMAC_Final},
    {CRYPT_EAL_IMPLMAC_DEINITCTX, (CRYPT_EAL_ImplMacDeInitCtx)CRYPT_HMAC_DeinitWrapper},
    {CRYPT_EAL_IMPLMAC_REINITCTX, (CRYPT_EAL_ImplMacReInitCtx)CRYPT_HMAC_ReinitWrapper},
    {CRYPT_EAL_IMPLMAC_CTRL, (CRYPT_EAL_ImplMacCtrl)CRYPT_HMAC_Ctrl},
    {CRYPT_EAL_IMPLMAC_FREECTX, (CRYPT_EAL_ImplMacFreeCtx)CRYPT_HMAC_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_PROVIDER */
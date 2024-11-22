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

void *CRYPT_EAL_DefMacNewCtx(void *provCtx, int32_t algId)
{
    (void) provCtx;
    void *macCtx = NULL;

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
    {CRYPT_EAL_IMPLMAC_NEWCTX, CRYPT_EAL_DefMacNewCtx},
    {CRYPT_EAL_IMPLMAC_INIT, CRYPT_HMAC_Init},
    {CRYPT_EAL_IMPLMAC_UPDATE, CRYPT_HMAC_Update},
    {CRYPT_EAL_IMPLMAC_FINAL, CRYPT_HMAC_Final},
    {CRYPT_EAL_IMPLMAC_DEINITCTX, CRYPT_HMAC_Deinit},
    {CRYPT_EAL_IMPLMAC_REINITCTX, CRYPT_HMAC_Reinit},
    {CRYPT_EAL_IMPLMAC_CTRL, CRYPT_HMAC_Ctrl},
    {CRYPT_EAL_IMPLMAC_FREECTX, CRYPT_HMAC_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_PROVIDER */
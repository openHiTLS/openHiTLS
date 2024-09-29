/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
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

int32_t CRYPT_EAL_DefMacCtrl(void *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    (void) ctx;
    (void) cmd;
    (void) val;
    (void) valLen;
    BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
    return CRYPT_NOT_SUPPORT;
}

const CRYPT_EAL_Func defMacHmac[] = {
    {CRYPT_EAL_IMPLMAC_NEWCTX, CRYPT_EAL_DefMacNewCtx},
    {CRYPT_EAL_IMPLMAC_INIT, CRYPT_HMAC_Init},
    {CRYPT_EAL_IMPLMAC_UPDATE, CRYPT_HMAC_Update},
    {CRYPT_EAL_IMPLMAC_FINAL, CRYPT_HMAC_Final},
    {CRYPT_EAL_IMPLMAC_REINITCTX, CRYPT_HMAC_Reinit},
    {CRYPT_EAL_IMPLMAC_CTRL, CRYPT_EAL_DefMacCtrl},
    {CRYPT_EAL_IMPLMAC_FREECTX, CRYPT_HMAC_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

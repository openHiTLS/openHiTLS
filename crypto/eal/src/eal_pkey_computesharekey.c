/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_PKEY)

#include <securec.h>
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "eal_pkey_local.h"
#include "crypt_eal_pkey.h"
#include "eal_common.h"

int32_t CRYPT_EAL_PkeyComputeShareKey(const CRYPT_EAL_PkeyCtx *pkey, const CRYPT_EAL_PkeyCtx *pubKey,
    uint8_t *share, uint32_t *shareLen)
{
    if (pkey == NULL || pubKey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->id != pubKey->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    if (pkey->method == NULL || pkey->method->computeShareKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    int32_t ret = pkey->method->computeShareKey(pkey->key, pubKey->key, share, shareLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    EAL_EventReport(CRYPT_EVENT_KEYAGGREMENT, CRYPT_ALGO_PKEY, pkey->id, CRYPT_SUCCESS);
    return ret;
}
#endif

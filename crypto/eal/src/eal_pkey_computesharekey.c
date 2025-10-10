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
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    if (pkey->method.computeShareKey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = pkey->method.computeShareKey(pkey->key, pubKey->key, share, shareLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, ret);
    }
    return ret;
}
#endif

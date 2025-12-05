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
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_PKEY_KEM)
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "eal_pkey_local.h"
#include "eal_common.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_md.h"
#include "crypt_mlkem.h"

int32_t CRYPT_EAL_PkeyEncapsInit(CRYPT_EAL_PkeyCtx *pkey, const BSL_Param *params)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_SUCCESS;
#ifdef HITLS_CRYPTO_PROVIDER
    if (pkey->isProvider && pkey->method.encapsInit != NULL) {
        ret = pkey->method.encapsInit(pkey->key, params);
        if (ret != CRYPT_SUCCESS) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
        }
    }
#else
    (void)params;
#endif
    return ret;
}

int32_t CRYPT_EAL_PkeyDecapsInit(CRYPT_EAL_PkeyCtx *pkey, const BSL_Param *params)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_SUCCESS;
#ifdef HITLS_CRYPTO_PROVIDER
    if (pkey->isProvider && pkey->method.decapsInit != NULL) {
        ret = pkey->method.decapsInit(pkey->key, params);
        if (ret != CRYPT_SUCCESS) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
        }
    }
#else
    (void)params;
#endif
    return ret;
}

int32_t CRYPT_EAL_PkeyEncaps(const CRYPT_EAL_PkeyCtx *pkey, uint8_t *cipher, uint32_t *cipherLen,
    uint8_t *sharekey, uint32_t *shareLen)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pkey->method.pkeyEncaps == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    int32_t ret = pkey->method.pkeyEncaps(pkey->key, cipher, cipherLen, sharekey, shareLen);
    EAL_ERR_REPORT((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_ENCAPS : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

int32_t CRYPT_EAL_PkeyDecaps(const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *cipher, uint32_t cipherLen,
    uint8_t *sharekey, uint32_t *shareLen)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pkey->method.pkeyDecaps == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    int32_t ret = pkey->method.pkeyDecaps(pkey->key, cipher, cipherLen, sharekey, shareLen);
    EAL_ERR_REPORT((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_DECAPS : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

#endif

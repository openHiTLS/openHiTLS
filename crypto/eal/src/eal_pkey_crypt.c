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

#include <stdbool.h>
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "eal_pkey_local.h"
#include "crypt_algid.h"
#include "bsl_err_internal.h"
#include "eal_common.h"
#include "crypt_eal_pkey.h"

int32_t CRYPT_EAL_PkeyEncrypt(const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method.encrypt == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    return pkey->method.encrypt(pkey->key, data, dataLen, out, outLen);
}

int32_t CRYPT_EAL_PkeyDecrypt(const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method.decrypt == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    return pkey->method.decrypt(pkey->key, data, dataLen, out, outLen);
}

int32_t CRYPT_EAL_PkeyPairCheck(CRYPT_EAL_PkeyCtx *pubKey, CRYPT_EAL_PkeyCtx *prvKey)
{
    if ((pubKey == NULL) || (prvKey == NULL)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->method.check == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pubKey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    return pubKey->method.check(CRYPT_PKEY_CHECK_KEYPAIR, pubKey->key, prvKey->key);
}

int32_t CRYPT_EAL_PkeyPrvCheck(CRYPT_EAL_PkeyCtx *prvKey)
{
    if (prvKey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prvKey->method.check == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, prvKey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_NULL_INPUT;
    }
    return prvKey->method.check(CRYPT_PKEY_CHECK_PRVKEY, prvKey->key, NULL);
}

int32_t CRYPT_EAL_PkeyHEAdd(const CRYPT_EAL_PkeyCtx *pkey, const BSL_Param *input, uint8_t *out, uint32_t *outLen)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (pkey->method.headd == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    return pkey->method.headd(pkey->key, input, out, outLen);
}

int32_t CRYPT_EAL_PkeyHEMul(const CRYPT_EAL_PkeyCtx *pkey, const BSL_Param *input, uint8_t *out, uint32_t *outLen)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (pkey->method.hemul == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    return pkey->method.hemul(pkey->key, input, out, outLen);
}

#endif

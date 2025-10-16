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
#include "crypt_eal_pkey.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#include "eal_md_local.h"
#include "eal_pkey_local.h"
#include "crypt_eal_rand.h"
#include "crypt_algid.h"
#include "bsl_err_internal.h"
#include "eal_common.h"
#include "crypt_utils.h"

int32_t CRYPT_EAL_PkeySignData(const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *hash,
    uint32_t hashLen, uint8_t *sign, uint32_t *signLen)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method.signData == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    if ((hash == NULL && hashLen != 0) || (hash != NULL && hashLen == 0)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    int32_t ret = pkey->method.signData(pkey->key, hash, hashLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeySign(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_MD_AlgId id,
    const uint8_t *data, uint32_t dataLen, uint8_t *sign, uint32_t *signLen)
{
    // 1. Check the input parameter
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method.sign == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = pkey->method.sign(pkey->key, id, data, dataLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}


int32_t CRYPT_EAL_PkeyVerify(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_MD_AlgId id,
    const uint8_t *data, uint32_t dataLen, const uint8_t *sign, uint32_t signLen)
{
    // 1. Check the input parameter
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method.verify == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    // 2. Hash the plaintext data and verify the hash value.
    int32_t ret = pkey->method.verify(pkey->key, id, data, dataLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
        return ret;
    }
    return ret;
}

int32_t CRYPT_EAL_PkeyVerifyData(const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *hash,
    uint32_t hashLen, const uint8_t *sign, uint32_t signLen)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method.verifyData == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    if ((hash == NULL && hashLen != 0) || (hash != NULL && hashLen == 0)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret = pkey->method.verifyData(pkey->key, hash, hashLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeyBlind(CRYPT_EAL_PkeyCtx *pkey, CRYPT_MD_AlgId id, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method.blind == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    int32_t ret = pkey->method.blind(pkey->key, id, input, inputLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeyUnBlind(CRYPT_EAL_PkeyCtx *pkey, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method.unBlind == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    int32_t ret = pkey->method.unBlind(pkey->key, input, inputLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    }
    return ret;
}

#endif

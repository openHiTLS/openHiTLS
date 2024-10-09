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
#include <securec.h>
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

#define VERIFY_MAXDIGESTSIZE           64       // Maximum signature length

static const uint32_t SIGN_MD_ID_LIST[] = {
    CRYPT_MD_MD5,
    CRYPT_MD_SHA1,
    CRYPT_MD_SHA224,
    CRYPT_MD_SHA256,
    CRYPT_MD_SHA384,
    CRYPT_MD_SHA512,
    CRYPT_MD_SM3
};

int32_t SignVerifySimpleHash(CRYPT_MD_AlgId id, const uint8_t *data,
    uint32_t dataLen, uint8_t *hash, uint32_t *hashLen)
{
    if (ParamIdIsValid(id, SIGN_MD_ID_LIST, sizeof(SIGN_MD_ID_LIST) / sizeof(SIGN_MD_ID_LIST[0])) == false) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    int32_t ret = CRYPT_EAL_Md(id, data, dataLen, hash, hashLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_EAL_PkeySignData(const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *hash,
    uint32_t hashLen, uint8_t *sign, uint32_t *signLen)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method == NULL || pkey->method->sign == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    // ed25519/sm2/sm9 does not support signing hash data
    if (pkey->id == CRYPT_PKEY_ED25519 || pkey->id == CRYPT_PKEY_SM2) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    // There is no 0-length hash data. ed25519 signs the plaintext instead of the hash data.
    if (hash == NULL || hashLen == 0) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = pkey->method->sign(pkey->key, hash, hashLen, sign, signLen);
    EAL_EventReport((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_SIGN : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

static int32_t PkeySignCore(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_MD_AlgId id,
    const uint8_t *data, uint32_t dataLen, uint8_t *sign, uint32_t *signLen)
{
    int32_t ret;
    // ed25519 directly sign the plaintext data.
    if (pkey->id == CRYPT_PKEY_ED25519) {
        if (id != CRYPT_MD_SHA512) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_CURVE25519_HASH_METH_ERROR);
            return CRYPT_CURVE25519_HASH_METH_ERROR;
        }
        ret = pkey->method->sign(pkey->key, data, dataLen, sign, signLen);
    } else if (pkey->id == CRYPT_PKEY_SM2) { // sm2: directly verify the plaintext data.
        if (id != CRYPT_MD_SM3) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ERR_ALGID);
            return CRYPT_EAL_ERR_ALGID;
        }
        ret = pkey->method->sign(pkey->key, data, dataLen, sign, signLen);
    } else { // For others, hash then sign the plaintext data.
        uint8_t hash[VERIFY_MAXDIGESTSIZE];
        uint32_t hashLen = VERIFY_MAXDIGESTSIZE;
        ret = SignVerifySimpleHash(id, data, dataLen, hash, &hashLen);
        if (ret != CRYPT_SUCCESS) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
            return ret;
        }
        // Sign the hash.
        ret = pkey->method->sign(pkey->key, hash, hashLen, sign, signLen);
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
    if (pkey->method == NULL || pkey->method->sign == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = PkeySignCore(pkey, id, data, dataLen, sign, signLen);
    EAL_EventReport((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_SIGN : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

static int32_t PkeyVerifyCore(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_MD_AlgId id,
    const uint8_t *data, uint32_t dataLen, const uint8_t *sign, uint32_t signLen)
{
    // ed25519/sm2: directly verify the plaintext data.
    int32_t ret;
    if (pkey->id == CRYPT_PKEY_ED25519) {
        if (id != CRYPT_MD_SHA512) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_CURVE25519_HASH_METH_ERROR);
            return CRYPT_CURVE25519_HASH_METH_ERROR;
        }
        ret = pkey->method->verify(pkey->key, data, dataLen, sign, signLen);
    } else if (pkey->id == CRYPT_PKEY_SM2) { // sm2: directly verify the plaintext.
        if (id != CRYPT_MD_SM3) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ERR_ALGID);
            return CRYPT_EAL_ERR_ALGID;
        }
        ret = pkey->method->verify(pkey->key, data, dataLen, sign, signLen);
    } else { // Hash the plaintext data and verify the hash value.
        uint8_t hash[VERIFY_MAXDIGESTSIZE];
        uint32_t hashLen = VERIFY_MAXDIGESTSIZE;
        ret = SignVerifySimpleHash(id, data, dataLen, hash, &hashLen);
        if (ret != CRYPT_SUCCESS) {
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
            return ret;
        }
        ret = pkey->method->verify(pkey->key, hash, hashLen, sign, signLen);
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
    if (pkey->method == NULL || pkey->method->verify == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    // 2. Hash the plaintext data and verify the hash value.
    int32_t ret = PkeyVerifyCore(pkey, id, data, dataLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
        return ret;
    }
    EAL_EventReport(CRYPT_EVENT_VERIFY, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}

int32_t CRYPT_EAL_PkeyVerifyData(const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *hash,
    uint32_t hashLen, const uint8_t *sign, uint32_t signLen)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method == NULL || pkey->method->verify == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    // ed25519: does not support signing hash data
    if (pkey->id == CRYPT_PKEY_ED25519) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    if (hash == NULL || hashLen == 0) { // Hash data with length 0 does not exist
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // 3. Verify the hash value.
    int32_t ret = pkey->method->verify(pkey->key, hash, hashLen, sign, signLen);
    EAL_EventReport((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_VERIFY : CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, ret);
    return ret;
}
#endif

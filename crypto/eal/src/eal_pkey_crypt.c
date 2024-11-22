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
#include "crypt_errno.h"
#include "eal_pkey_local.h"
#include "crypt_algid.h"
#include "bsl_err_internal.h"
#include "eal_common.h"

int32_t CRYPT_EAL_PkeyEncrypt(const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method == NULL || pkey->method->encrypt == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    return pkey->method->encrypt(pkey->key, data, dataLen, out, outLen);
}

int32_t CRYPT_EAL_PkeyDecrypt(const CRYPT_EAL_PkeyCtx *pkey, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen)
{
    if (pkey == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey->method == NULL || pkey->method->decrypt == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, pkey->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    return pkey->method->decrypt(pkey->key, data, dataLen, out, outLen);
}

static int32_t CryptRsaEmsaPairSet(CRYPT_EAL_PkeyCtx *pubKey, CRYPT_EAL_PkeyCtx *prvKey, CRYPT_MD_AlgId hashId)
{
    int32_t mdId = hashId;
    int32_t ret = CRYPT_EAL_PkeyCtrl(pubKey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &mdId, sizeof(mdId));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_EAL_PkeyCtrl(prvKey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &mdId, sizeof(mdId));
}

static int32_t CryptSm2PairSet(CRYPT_EAL_PkeyCtx *pubKey, CRYPT_EAL_PkeyCtx *prvKey)
{
    char *userId = "1234567812345678";
    int32_t ret = CRYPT_EAL_PkeyCtrl(pubKey, CRYPT_CTRL_SET_SM2_USER_ID, (void *)userId, strlen(userId));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_EAL_PkeyCtrl(prvKey, CRYPT_CTRL_SET_SM2_USER_ID, (void *)userId, strlen(userId));
}

int32_t CRYPT_EAL_PkeyPairCheck(CRYPT_EAL_PkeyCtx *pubKey, CRYPT_EAL_PkeyCtx *prvKey)
{
    if ((pubKey == NULL) || (prvKey == NULL)) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_PKEY, CRYPT_PKEY_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = CRYPT_SUCCESS;
    uint8_t *signedData = NULL;
    
    CRYPT_EAL_PkeyCtx *tempPubKey = CRYPT_EAL_PkeyDupCtx(pubKey);
    CRYPT_EAL_PkeyCtx *tempPrivKey = CRYPT_EAL_PkeyDupCtx(prvKey);
    if (tempPubKey == NULL || tempPrivKey == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    CRYPT_MD_AlgId hashId;
    CRYPT_PKEY_AlgId algId = CRYPT_EAL_PkeyGetId(tempPubKey);
    switch (algId) {
        case CRYPT_PKEY_DSA:
        case CRYPT_PKEY_ED25519:
        case CRYPT_PKEY_ECDSA:
            /* RFC8032 5.1.6: ECDSA supports only sha512 as the hash algorithm for signatures.
             * Other signature algorithms support sha512. Therefore, sha512 is always used here. */
            hashId = CRYPT_MD_SHA512;
            break;
        case CRYPT_PKEY_RSA:
            hashId = CRYPT_MD_SHA512;
            ret = CryptRsaEmsaPairSet(tempPubKey, tempPrivKey, hashId);
            break;
        case CRYPT_PKEY_SM2:
            hashId = CRYPT_MD_SM3;
            ret = CryptSm2PairSet(tempPubKey, tempPrivKey);
            break;
        default:
            ret = CRYPT_NOT_SUPPORT;
            break;
    }

    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    uint8_t toBeSig[] = {1};
    uint32_t signedLen = CRYPT_EAL_PkeyGetSignLen(tempPrivKey);
    if (signedLen == 0) {
        ret = CRYPT_ECC_PKEY_ERR_SIGN_LEN;
        goto ERR;
    }
    signedData = BSL_SAL_Malloc(signedLen);
    if (signedData == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    ret = CRYPT_EAL_PkeySign(tempPrivKey, hashId, toBeSig, sizeof(toBeSig), signedData, &signedLen);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    ret = CRYPT_EAL_PkeyVerify(tempPubKey, hashId, toBeSig, sizeof(toBeSig), signedData, signedLen);
ERR:
    BSL_SAL_FREE(signedData);
    CRYPT_EAL_PkeyFreeCtx(tempPubKey);
    CRYPT_EAL_PkeyFreeCtx(tempPrivKey);
    return ret;
}
#endif

/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
    CRYPT_RSA_PkcsV15Para pkcsv15 = {hashId};
    int32_t ret = CRYPT_EAL_PkeyCtrl(pubKey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(CRYPT_RSA_PkcsV15Para));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_EAL_PkeyCtrl(prvKey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(CRYPT_RSA_PkcsV15Para));
}

int32_t CRYPT_EAL_PkeyPairCheck(CRYPT_EAL_PkeyCtx *pubKey, CRYPT_EAL_PkeyCtx *prvKey)
{
    if ((pubKey == NULL) || (prvKey == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    CRYPT_MD_AlgId hashId;
    CRYPT_PKEY_AlgId algId = CRYPT_EAL_PkeyGetId(pubKey);
    int32_t ret;
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
            ret = CryptRsaEmsaPairSet(pubKey, prvKey, hashId);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            break;
        case CRYPT_PKEY_SM2:
            hashId = CRYPT_MD_SM3;
            break;
        default:
            return CRYPT_NOT_SUPPORT;
    }

    uint8_t toBeSig[] = {1};
    uint32_t signedLen = CRYPT_EAL_PkeyGetSignLen(prvKey);
    if (signedLen == 0) {
        return CRYPT_ECC_PKEY_ERR_SIGN_LEN;
    }
    uint8_t *signedData = BSL_SAL_Malloc(signedLen);
    if (signedData == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeySign(prvKey, hashId, toBeSig, sizeof(toBeSig), signedData, &signedLen);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    ret = CRYPT_EAL_PkeyVerify(pubKey, hashId, toBeSig, sizeof(toBeSig), signedData, signedLen);
ERR:
    BSL_SAL_FREE(signedData);
    return ret;
}
#endif

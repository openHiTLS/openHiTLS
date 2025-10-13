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

#ifndef CRYPT_ENCODE_INTERNAL_H
#define CRYPT_ENCODE_INTERNAL_H

#include "hitls_build.h"
#include "bsl_types.h"
#include "bsl_asn1_internal.h"
#include "crypt_bn.h"
#include "crypt_eal_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */


#if defined(HITLS_CRYPTO_SM2_SIGN) || defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_ECDSA)
/**
 * Get the maximum length of the signature data.
 *
 * @param rLen [in] The length of r.
 * @param sLen [in] The length of s.
 * @param maxLen [out] The maximum length of the signature data.
 * @return: CRYPT_SUCCESS: Success, other: Error.
 */
int32_t CRYPT_EAL_GetSignEncodeLen(uint32_t rLen, uint32_t sLen, uint32_t *maxLen);

/**
 * Encode the signature data by big number.
 *
 * @param r [in] The r value.
 * @param s [in] The s value.
 * @param encode [out] The encoded data.
 * @param encodeLen [out] The length of the encoded data.
 * @return: CRYPT_SUCCESS: Success, other: Error.
 */
int32_t CRYPT_EAL_EncodeSign(const BN_BigNum *r, const BN_BigNum *s, uint8_t *encode, uint32_t *encodeLen);

/**
 * Decode the signature data to big number.
 *
 * @param encode [in] The encoded data.
 * @param encodeLen [in] The length of the encoded data.
 * @param r [out] The r value.
 * @param s [out] The s value.
 * @return: CRYPT_SUCCESS: Success, other: Error.
 */
int32_t CRYPT_EAL_DecodeSign(const uint8_t *encode, uint32_t encodeLen, BN_BigNum *r, BN_BigNum *s);
#endif

#ifdef HITLS_CRYPTO_SM2_CRYPT
typedef struct {
    uint8_t *x;         // XCoordinate
    uint8_t *y;         // YCoordinate
    uint8_t *hash;      // HASH
    uint8_t *cipher;    // CipherText
    uint32_t xLen;
    uint32_t yLen;
    uint32_t hashLen;
    uint32_t cipherLen;
} CRYPT_SM2_EncryptData;

/**
 * Get the length of the SM2 encoded data.
 *
 * @param xLen [in] The length of the x coordinate.
 * @param yLen [in] The length of the y coordinate.
 * @param hashLen [in] The length of the hash.
 * @param dataLen [in] The length of the data.
 * @param maxLen [out] The length of the SM2 encoded data.
 * @return: CRYPT_SUCCESS: Success, other: Error.
 */
int32_t CRYPT_EAL_GetSm2EncryptDataEncodeLen(uint32_t xLen, uint32_t yLen, uint32_t hashLen, uint32_t dataLen,
    uint32_t *maxLen);

/**
 * Encode the SM2 encrypt data.
 *
 * @param data [in] The SM2 encrypt data.
 * @param encode [out] The encoded data.
 * @param encodeLen [out] The length of the encoded data.
 * @return: CRYPT_SUCCESS: Success, other: Error.
 */
int32_t CRYPT_EAL_EncodeSm2EncryptData(const CRYPT_SM2_EncryptData *data, uint8_t *encode, uint32_t *encodeLen);

/**
 * Decode the SM2 encrypt data.
 *
 * @param encode [in] The encoded data.
 * @param encodeLen [in] The length of the encoded data.
 * @param data [out] The SM2 encrypt data.
 * @return: CRYPT_SUCCESS: Success, other: Error.
 */
int32_t CRYPT_EAL_DecodeSm2EncryptData(const uint8_t *encode, uint32_t encodeLen, CRYPT_SM2_EncryptData *data);
#endif

#ifdef __cplusplus
}
#endif

#endif // CRYPT_ENCODE_INTERNAL_H

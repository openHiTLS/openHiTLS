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

#ifndef CRYPT_ENCODE_H
#define CRYPT_ENCODE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ENCODE

#include "crypt_bn.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef struct {
    BN_BigNum *r;
    BN_BigNum *s;
} DSA_Sign;
// encode signature data
int32_t ASN1_SignDataEncode(const DSA_Sign *s, uint8_t *sign, uint32_t *signLen);

// decode signature data
int32_t ASN1_SignDataDecode(DSA_Sign *s, const uint8_t *sign, uint32_t signLen);

// Obtain the required length of the signature data.
uint32_t ASN1_SignEnCodeLen(uint32_t rLen, uint32_t sLen);

// Stream length for encoding a BigNum.
uint32_t ASN1_SignStringLenOfBn(const BN_BigNum *num);

int32_t ASN1_Sm2EncryptDataEncode(const uint8_t *input, uint32_t inputLen, uint8_t *encode, uint32_t *encodeLen);

int32_t ASN1_Sm2EncryptDataDecode(const uint8_t *eData, uint32_t eLen, uint8_t *decode, uint32_t *decodeLen);

uint64_t ASN1_Sm2GetEnCodeLen(uint32_t dataLen);

int32_t CRYPT_EAL_ParseAsn1SubPubkey(uint8_t *buff, uint32_t buffLen, void **ealPubKey, bool isComplete);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_ENCODE

#endif // CRYPT_ENCODE_H

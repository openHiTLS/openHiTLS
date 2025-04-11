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
#ifdef HITLS_CRYPTO_ENCODE_DECODE

#include "bsl_types.h"
#include "bsl_asn1.h"
#include "crypt_eal_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */


#ifdef HITLS_CRYPTO_KEY_DECODE
int32_t CRYPT_EAL_ParseRsaPssAlgParam(BSL_ASN1_Buffer *param, CRYPT_RSA_PssPara *para);

int32_t CRYPT_EAL_PriKeyParseFile(CRYPT_EAL_LibCtx *libctx, const char *attrName, BSL_ParseFormat format, int32_t type,
    const char *path, const BSL_Buffer *pwd, CRYPT_EAL_PkeyCtx **ealPriKey);
#endif

#ifdef HITLS_CRYPTO_KEY_ENCODE

int32_t CRYPT_EAL_EncodePubKeyBuffInternal(CRYPT_EAL_PkeyCtx *ealPubKey,
    BSL_ParseFormat format, int32_t type, bool isComplete, BSL_Buffer *encode);

#ifdef HITLS_CRYPTO_RSA
int32_t CRYPT_EAL_EncodeRsaPssAlgParam(const CRYPT_RSA_PssPara *rsaPssParam, uint8_t **buf, uint32_t *bufLen);
#endif

#endif // HITLS_CRYPTO_KEY_ENCODE

#ifdef HITLS_PKI_PKCS12_PARSE
// parse PKCS7-EncryptData：only support PBES2 + PBKDF2.
int32_t CRYPT_EAL_ParseAsn1PKCS7EncryptedData(CRYPT_EAL_LibCtx *libCtx, const char *attrName, BSL_Buffer *encode,
    const uint8_t *pwd, uint32_t pwdlen, BSL_Buffer *output);
#endif

#ifdef HITLS_PKI_PKCS12_GEN
// encode PKCS7-EncryptData：only support PBES2 + PBKDF2.
int32_t CRYPT_EAL_EncodePKCS7EncryptDataBuff(CRYPT_EAL_LibCtx *libCtx, const char *attrName, BSL_Buffer *data,
    const void *encodeParam, BSL_Buffer *encode);
#endif


#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_ENCODE_DECODE

#endif // CRYPT_ENCODE_H

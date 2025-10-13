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

#ifndef CRYPT_CODECSKEY_H
#define CRYPT_CODECSKEY_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CODECSKEY

#include "bsl_types.h"
#include "bsl_asn1_internal.h"
#include "crypt_eal_pkey.h"
#ifdef HITLS_CRYPTO_KEY_INFO
#include "bsl_uio.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef struct {
    int32_t version;
    BslCid keyType;
    BSL_ASN1_Buffer keyParam;
    uint8_t *pkeyRawKey;
    uint32_t pkeyRawKeyLen;
    void *attrs; // HITLS_X509_Attrs *
} CRYPT_ENCODE_DECODE_Pk8PrikeyInfo;

#ifdef HITLS_CRYPTO_KEY_DECODE

typedef struct {
    BslCid keyType;
    BSL_ASN1_Buffer keyParam;
    BSL_ASN1_BitString pubKey;
} CRYPT_DECODE_SubPubkeyInfo;

int32_t CRYPT_DECODE_SubPubkey(uint8_t *buff, uint32_t buffLen, BSL_ASN1_DecTemplCallBack keyInfoCb,
    CRYPT_DECODE_SubPubkeyInfo *subPubkeyInfo, bool isComplete);

int32_t CRYPT_DECODE_Pkcs8Info(uint8_t *buff, uint32_t buffLen, BSL_ASN1_DecTemplCallBack keyInfoCb,
    CRYPT_ENCODE_DECODE_Pk8PrikeyInfo *pk8PrikeyInfo);

#ifdef HITLS_CRYPTO_RSA
int32_t CRYPT_EAL_ParseRsaPssAlgParam(BSL_ASN1_Buffer *param, CRYPT_RSA_PssPara *para);
#endif

#endif // HITLS_CRYPTO_KEY_DECODE

#ifdef HITLS_CRYPTO_KEY_ENCODE

int32_t CRYPT_ENCODE_Pkcs8Info(CRYPT_ENCODE_DECODE_Pk8PrikeyInfo *pk8PrikeyInfo, BSL_Buffer *asn1);

int32_t CRYPT_EAL_EncodePubKeyBuffInternal(CRYPT_EAL_PkeyCtx *ealPubKey,
    BSL_ParseFormat format, int32_t type, bool isComplete, BSL_Buffer *encode);

#ifdef HITLS_CRYPTO_RSA
int32_t CRYPT_EAL_EncodeRsaPssAlgParam(const CRYPT_RSA_PssPara *rsaPssParam, uint8_t **buf, uint32_t *bufLen);
#endif

#endif // HITLS_CRYPTO_KEY_ENCODE

#if defined(HITLS_CRYPTO_RSA) && (defined(HITLS_CRYPTO_KEY_ENCODE) || defined(HITLS_CRYPTO_KEY_INFO))
int32_t CRYPT_EAL_InitRsaPrv(const CRYPT_EAL_PkeyCtx *ealPriKey, CRYPT_PKEY_AlgId cid, CRYPT_EAL_PkeyPrv *rsaPrv);
void CRYPT_EAL_DeinitRsaPrv(CRYPT_EAL_PkeyPrv *rsaPrv);
int32_t CRYPT_EAL_GetRsaPssPara(CRYPT_EAL_PkeyCtx *key, CRYPT_RSA_PssPara *para);
#endif

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

#ifdef HITLS_CRYPTO_KEY_INFO
int32_t CRYPT_EAL_PrintPubkey(uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio);

int32_t CRYPT_EAL_PrintPrikey(uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio);

#ifdef HITLS_CRYPTO_RSA
int32_t CRYPT_EAL_PrintRsaPssPara(uint32_t layer, CRYPT_RSA_PssPara *para, BSL_UIO *uio);
#endif
#endif // HITLS_CRYPTO_KEY_INFO

int32_t CRYPT_EAL_GetEncodeFormat(const char *format);

int32_t CRYPT_EAL_GetEncodeType(const char *type);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_CODECSKEY

#endif // CRYPT_CODECSKEY_H

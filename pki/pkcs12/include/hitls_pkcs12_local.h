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

#ifndef HITLS_PKCS12_LOCAL_H
#define HITLS_PKCS12_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_PKI_PKCS12
#include <stdint.h>
#include "bsl_asn1.h"
#include "bsl_obj.h"
#include "sal_atomic.h"
#include "hitls_x509_local.h"
#include "hitls_pki_cert.h"
#include "crypt_eal_codecs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    BslCid contentType;
    BSL_Buffer *contentValue;
} HITLS_PKCS12_ContentInfo;

typedef struct {
    BslCid alg;
    BSL_Buffer *mac;
    BSL_Buffer *macSalt;
    uint32_t iteration;
} HITLS_PKCS12_MacData;

/* This struct is provided for users to create related bags and add them to the p12-ctx. */
typedef struct _HITLS_PKCS12_Bag {
    uint32_t type;
    union {
        CRYPT_EAL_PkeyCtx *key;
        HITLS_X509_Cert *cert;
    } value;
    HITLS_X509_Attrs *attributes; // localKeyId, friendlyName, ect. Item is HITLS_PKCS12_SafeBagAttr.
} HITLS_PKCS12_Bag;

/*
 * The Top-Level p12-ctx, which can store certificates and pkey required by a .p12 file.
 * Note that the entity-cert and entity-pkey are unique.
 */
typedef struct _HITLS_PKCS12 {
    uint32_t version;
    HITLS_PKCS12_Bag *key;
    HITLS_PKCS12_Bag *entityCert;
    BSL_ASN1_List *certList;
    HITLS_PKCS12_MacData *macData;
    HITLS_PKI_LibCtx *libCtx;
    const char *attrName;
    CRYPT_EAL_PkeyCtx *recipientPkeyCtx; // For EnvelopedData parsing
} HITLS_PKCS12;

/* A common bag, could store a crl-bag, or a cert-bag, or a secret-bag... */
typedef struct {
    BslCid bagId;
    BSL_Buffer *bagValue; // encode data
} HITLS_PKCS12_CommonSafeBag;

/* SafeBag Attributes. */
typedef struct {
    BslCid attrId;
    BSL_Buffer attrValue;
} HITLS_PKCS12_SafeBagAttr;

/* A safeBag defined in RFC 7292, which storing intermediate data in our decoding process. */
typedef struct {
    BslCid bagId;
    BSL_Buffer *bag; // encode data
    HITLS_X509_Attrs *attributes; // Currently, only support localKeyId, friendlyName. Item is HITLS_PKCS12_SafeBagAttr.
} HITLS_PKCS12_SafeBag;

void HITLS_PKCS12_SafeBagFree(HITLS_PKCS12_SafeBag *safeBag);

HITLS_PKCS12_MacData *HITLS_PKCS12_MacDataNew(void);

void HITLS_PKCS12_MacDataFree(HITLS_PKCS12_MacData *macData);

void HITLS_PKCS12_AttributesFree(void *attribute);

typedef enum {
    HITLS_PKCS12_KDF_ENCKEY_ID = 1,
    HITLS_PKCS12_KDF_ENCIV_ID = 2,
    HITLS_PKCS12_KDF_MACKEY_ID = 3,
} HITLS_PKCS12_KDF_IDX;

/*
 * A method of obtaining the mac key in key-integrity protection mode.
 * The method implementation follows standards RFC 7292
*/
int32_t HITLS_PKCS12_KDF(BSL_Buffer *output, const uint8_t *pwd, uint32_t pwdLen, HITLS_PKCS12_KDF_IDX type,
    HITLS_PKCS12_MacData *macData);

/*
 * To cal mac data in key-integrity protection mode, we use the way of Hmac + PKCS12_KDF.
*/
int32_t HITLS_PKCS12_CalMac(BSL_Buffer *output, BSL_Buffer *pwd, BSL_Buffer *initData, HITLS_PKCS12_MacData *macData);

#ifdef HITLS_PKI_PKCS12_PARSE
/*
 * Parse the outermost layer of contentInfo, provide two functions
 *    1. AuthSafe -> pkcs7 package format
 *    2. contentInfo_i  -> safeContents
*/
int32_t HITLS_PKCS12_ParseContentInfo(HITLS_PKI_LibCtx *libCtx, const char *attrName,
    CRYPT_EAL_PkeyCtx *recipientPkeyCtx, BSL_Buffer *encode, const uint8_t *password, uint32_t passLen,
    BSL_Buffer *data);

/*
 * Parse the 'sequences of' of p12, provide two functions
 *    1. contentInfo -> contentInfo_i
 *    2. safeContent -> safeBag_i
 * Both of the above parsing only resolves to BER encoding format, and requiring further conversion.
*/
int32_t HITLS_PKCS12_ParseAsn1AddList(BSL_Buffer *encode, BSL_ASN1_List *list, uint32_t parseType);

/*
 * Parse each safeBag of list, and convert decode data to the cert or key.
*/
int32_t HITLS_PKCS12_ParseSafeBagList(BSL_ASN1_List *bagList, const uint8_t *password, uint32_t passLen,
    HITLS_PKCS12 *p12);

/*
 * Parse attributes of a safeBag, and convert decode data to the real data.
*/
int32_t HITLS_PKCS12_ParseSafeBagAttr(BSL_ASN1_Buffer *attrBuff, HITLS_X509_Attrs *attrList);

/*
 * Parse AuthSafeData of a p12, and convert decode data to the real data.
*/
int32_t HITLS_PKCS12_ParseAuthSafeData(BSL_Buffer *encode, const HITLS_PKCS12_PwdParam *pwdParam, HITLS_PKCS12 *p12);

/*
 * Parse MacData of a p12, and convert decode data to the real data.
*/
int32_t HITLS_PKCS12_ParseMacData(BSL_Buffer *encode, HITLS_PKCS12_MacData *macData);
#endif

#ifdef HITLS_PKI_PKCS12_GEN
/*
 * Encode MacData of a p12.
*/
int32_t HITLS_PKCS12_EncodeMacData(BSL_Buffer *initData, const HITLS_PKCS12_MacParam *macParam,
    HITLS_PKCS12_MacData *p12Mac, BSL_Buffer *encode);

/*
 * Encode contentInfo.
*/
int32_t HITLS_PKCS12_EncodeContentInfo(HITLS_PKI_LibCtx *libCtx, const char *attrName, BSL_Buffer *input,
    uint32_t encodeType, const CRYPT_EncodeParam *encryptParam, BSL_Buffer *encode);

/*
 * Encode list, including contentInfo-list, safeContent-list.
*/
int32_t HITLS_PKCS12_EncodeAsn1List(BSL_ASN1_List *list, uint32_t encodeType, const CRYPT_EncodeParam *encryptParam,
    BSL_Buffer *encode);
#endif

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_PKCS12

#endif // HITLS_CRL_LOCAL_H
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

#include <stdint.h>
#include "bsl_asn1.h"
#include "bsl_obj.h"
#include "sal_atomic.h"
#include "hitls_x509_local.h"
#include "crypt_eal_encode.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    BslCid contentType;
    BSL_Buffer *contentValue;
} HTILS_PKCS12_ContentInfo;

typedef struct {
    BslCid alg;
    BSL_Buffer *mac;
    BSL_Buffer *macSalt;
    uint32_t interation;
} HTILS_PKCS12_MacData;

typedef struct {
    union {
        CRYPT_EAL_PkeyCtx *key;
        HITLS_X509_Cert *cert;
    } value;
    BSL_ASN1_List *attributes; // localKeyId, friendlyname, ...
} HTILS_PKCS12_Bag;

typedef struct _HTILS_PKCS12_P12Info {
    uint32_t version;
    HTILS_PKCS12_Bag *key;
    HTILS_PKCS12_Bag *entityCert;
    BSL_ASN1_List *certList;
    HTILS_PKCS12_MacData *macData;
} HTILS_PKCS12_P12Info;

typedef struct {
    BslCid bagId;
    BSL_Buffer *bagValue; // encode data
} HTILS_PKCS12_CommonSafeBag;

typedef struct {
    BslCid attrId;
    BSL_Buffer *attrValue;
} HTILS_PKCS12_SafeBagAttr;

typedef struct {
    BslCid bagId;
    BSL_Buffer *bag; // encode data
    BSL_ASN1_List *attributes; // Currently, only support localKeyId, friendlyname,.
} HTILS_PKCS12_SafeBag;

typedef struct _HTILS_PKCS12_PwdParam {
    BSL_Buffer *macPwd;
    BSL_Buffer *encPwd;
} HTILS_PKCS12_PwdParam;

typedef struct _HTILS_PKCS12_HmacParam {
    uint32_t saltLen;
    uint32_t itCnt;
    uint32_t macId;
    uint8_t *pwd;
    uint32_t pwdLen;
} HTILS_PKCS12_HmacParam;

typedef struct _HTILS_PKCS12_EncodeParam {
    CRYPT_EncodeParam certEncParam;
    CRYPT_EncodeParam keyEncParam;
    HTILS_PKCS12_HmacParam macParam;
} HTILS_PKCS12_EncodeParam;

HTILS_PKCS12_SafeBag *HTILS_PKCS12_SafeBagNew();

void HTILS_PKCS12_SafeBagFree(HTILS_PKCS12_SafeBag *safeBag);

HTILS_PKCS12_P12Info *HTILS_PKCS12_P12_InfoNew(void);

void HTILS_PKCS12_P12_InfoFree(HTILS_PKCS12_P12Info *p12);

HTILS_PKCS12_MacData *HTILS_PKCS12_P12_MacDataNew(void);

void HTILS_PKCS12_p12_MacDataFree(HTILS_PKCS12_MacData *macData);

void HTILS_PKCS12_AttributesFree(void *attribute);
typedef enum {
    HITLS_PKCS12_KDF_ENCKEY_ID = 1,
    HITLS_PKCS12_KDF_ENCIV_ID = 2,
    HITLS_PKCS12_KDF_MACKEY_ID = 3,
} HITLS_PKCS12_KDF_IDX;

/*
 * A method of obtaining the mac key in key-integrity protection mode.
 * The method implementation follows standards RFC 7292
*/
int32_t HTILS_PKCS12_KDF(BSL_Buffer *output, const uint8_t *pwd, uint32_t pwdLen, HITLS_PKCS12_KDF_IDX type,
    HTILS_PKCS12_MacData *macData);

/*
 * To cal mac data in key-integrity protection mode, we use the way of Hmac + PKCS12_KDF.
*/
int32_t HTILS_PKCS12_CalMac(BSL_Buffer *output, BSL_Buffer *pwd, BSL_Buffer *initData, HTILS_PKCS12_MacData *macData);
;

/*
 * Parse the outermost layer of contentInfo, provide two functions
 *    1. AuthSafe -> pkcs7 package format
 *    2. contentInfo_i  -> safeContents
*/
int32_t HITLS_PKCS12_ParseContentInfo(BSL_Buffer *encode, const uint8_t *password, uint32_t passLen, BSL_Buffer *data);

/*
 * Parse the 'sequences of' of p12, provide two functions
 *    1. contentInfo -> contentInfo_i
 *    2. safeContent -> safeBag_i
 * Both of the above parsing only resolves to BER encoding format, and requiring further conversion.
*/
int32_t HITLS_PKCS12_ParseAsn1AddList(BSL_Buffer *encode, BSL_ASN1_List *list, uint32_t parseType);

/*
 * Parse each safeBags of list, and convert decode data to the cert or key.
*/
int32_t HITLS_PKCS12_ParseSafeBagList(BSL_ASN1_List *bagList, const uint8_t *password, uint32_t passLen,
    HTILS_PKCS12_P12Info *p12);

/*
 * Parse attributes of a safeBag, and convert decode data to the real data.
*/
int32_t HITLS_PKCS12_ParseSafeBagAttr(BSL_ASN1_Buffer *attribute, BSL_ASN1_List *attriList);

/*
 * Parse AuthSafeData of a p12, and convert decode data to the real data.
*/
int32_t HITLS_PKCS12_ParseAuthSafeData(BSL_Buffer *encode, const uint8_t *password, uint32_t passLen,
    HTILS_PKCS12_P12Info *p12);

/*
 * Parse MacData of a p12, and convert decode data to the real data.
*/
int32_t HITLS_PKCS12_ParseMacData(BSL_Buffer *encode, HTILS_PKCS12_MacData *macData);

/*
 * Encode MacData of a p12.
*/
int32_t HITLS_PKCS12_EncodeMacData(BSL_Buffer *initData, const HTILS_PKCS12_HmacParam *macParam,
    HTILS_PKCS12_MacData *p12Mac, BSL_Buffer *encode);

/*
 * Encode contentInfo.
*/
int32_t HITLS_PKCS12_EncodeContentInfo(BSL_Buffer *input, uint32_t encodeType, const CRYPT_EncodeParam *encryptParam,
    BSL_Buffer *encode);

/*
 * Encode list, including contentInfo-list, safeContent-list.
*/
int32_t HITLS_PKCS12_EncodeAsn1List(BSL_ASN1_List *list, uint32_t encodeType, const CRYPT_EncodeParam *encryptParam,
    BSL_Buffer *encode);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRL_LOCAL_H
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

#ifndef HITLS_CMS_RECIPIENT_H
#define HITLS_CMS_RECIPIENT_H

#include <stdbool.h>
#include <stdint.h>
#include "hitls_build.h"
#ifdef HITLS_PKI_CMS
#include "bsl_asn1.h"
#include "bsl_params.h"
#include "bsl_sal.h"
#include "crypt_eal_pkey.h"
#include "hitls_pki_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if defined(HITLS_PKI_CMS_ENVELOPEDDATA) || defined(HITLS_PKI_CMS_AUTHENTICATEDDATA)
/**
 * @brief KeyTransRecipientInfo structure
 * Reference: RFC 5652 Section 6.2.1
 * KeyTransRecipientInfo ::= SEQUENCE {
 *      version CMSVersion,  -- always set to 0 or 2
 *      rid RecipientIdentifier,
 *      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *      encryptedKey EncryptedKey }
 */
typedef struct {
    uint32_t version; /* According to RFC 5652:
                         If the RecipientIdentifier is the CHOICE issuerAndSerialNumber, then the version MUST be 0.
                         If the RecipientIdentifier is subjectKeyIdentifier, then the version MUST be 2. */
    BSL_ASN1_List *issuerName;
    BSL_Buffer serialNumber;
    HITLS_X509_ExtSki subjectKeyId;
    BslCid keyEncryAlg;
    BSL_Buffer algParams;
    BSL_Buffer encryptedKey;
    /* Runtime context - not encoded into ASN.1 */
    uint32_t flag; // Used to mark EnvelopedData parsing or generation, indicating resource release behavior.
    CRYPT_EAL_PkeyCtx *pkey;
    CRYPT_EAL_LibCtx *libCtx;
    const char *attrName; // Provider attribute name
} CMS_KeyTransRecipientInfo;

typedef struct {
    BslCid algorithm;
    BSL_Buffer algParams;
    BSL_ASN1_BitString publicKey;
} CMS_OriginatorPublicKey;

typedef struct {
    BSL_ASN1_List *issuer; // Issuer DN
    BSL_Buffer serialNumber;
} CMS_IssuerAndSerialNumber;

typedef struct {
    uint32_t type; // 0: issuerAndSerialNumber, 1: subjectKeyIdentifier, 2: originatorKey
    union {
        CMS_IssuerAndSerialNumber *issuerAndSerialNumber;
        HITLS_X509_ExtSki *subjectKeyIdentifier;
        CMS_OriginatorPublicKey *originatorKey;
    } d;
} CMS_OriginatorIdentifierOrKey;

typedef struct {
    HITLS_X509_ExtSki subjectKeyIdentifier;
    BSL_TIME *date;
    BslCid otherKeyAttrId;
    BSL_Buffer otherKeyAttr;
} CMS_RecipientKeyIdentifier;

typedef struct {
    uint32_t type; // 0: issuer and serialnumber, 1: recipient key identifier
    union {
        CMS_IssuerAndSerialNumber *issuerAndSerialNumber;
        CMS_RecipientKeyIdentifier *recipientKeyIdentifier;
    } d;
} CMS_KeyAgreeRecipientIdentifier;

typedef struct {
    CMS_KeyAgreeRecipientIdentifier rid;
    BSL_Buffer encryptedKey;
} CMS_RecipientEncryptedKey;

/**
 * @brief KeyAgreeRecipientInfo structure
 * Reference: RFC 5652 Section 6.2.2
 * KeyAgreeRecipientInfo ::= SEQUENCE {
 *      version CMSVersion,  -- always set to 3
 *      originator [0] EXPLICIT OriginatorIdentifierOrKey,
 *      ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
 *      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *      recipientEncryptedKeys RecipientEncryptedKeys }
 */
typedef struct {
    uint32_t version; // Must be 3
    CMS_OriginatorIdentifierOrKey originator;
    BSL_Buffer ukm; // User Keying Material (Optional)
    BslCid keyEncryAlg;
    BSL_Buffer algParams;
    BSL_ASN1_List *recipientEncryptedKeys;
    /* Runtime context - not encoded into ASN.1 */
    CRYPT_EAL_PkeyCtx *pkey;
    CRYPT_EAL_LibCtx *libCtx;
    const char *attrName;
} CMS_KeyAgreeRecipientInfo;

/**
 * @brief KEKRecipientInfo structure
 * Reference: RFC 5652 Section 6.2.3
 * KEKRecipientInfo ::= SEQUENCE {
 *      version CMSVersion,  -- always set to 4
 *      kekid KEKIdentifier,
 *      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *      encryptedKey EncryptedKey }
 *
 * KEKIdentifier ::= SEQUENCE {
 *      keyIdentifier OCTET STRING,
 *      date GeneralizedTime OPTIONAL,
 *      other OtherKeyAttribute OPTIONAL }
 */
typedef struct {
    uint32_t version; // Must be 4
    CMS_RecipientKeyIdentifier kekid;
    BslCid keyEncryAlg;
    BSL_Buffer algParams;
    BSL_Buffer encryptedKey;
    /* Runtime context - not encoded into ASN.1 */
    BSL_Buffer *kek;
    CRYPT_EAL_LibCtx *libCtx;
    const char *attrName;
} CMS_KEKRecipientInfo;

/**
 * @brief PasswordRecipientInfo structure
 * Reference: RFC 5652 Section 6.2.4
 *  PasswordRecipientInfo ::= SEQUENCE {
 *      version CMSVersion,   -- Always set to 0
 *      keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
 *                                   OPTIONAL,
 *      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *      encryptedKey EncryptedKey }
 */
typedef struct {
    uint32_t version; // Must be 0
    BslCid keyDerivationAlg; // Optional
    BSL_Buffer kdfParams;
    BslCid keyEncryAlg;
    BSL_Buffer keyEncAlgParams;
    BSL_Buffer encryptedKey;
    /* Runtime context - not encoded into ASN.1 */
    BSL_Buffer *password;
    CRYPT_EAL_LibCtx *libCtx;
    const char *attrName;
} CMS_PasswordRecipientInfo;

/**
 * @brief OtherRecipientInfo structure
 * Reference: RFC 5652 Section 6.2.5
 *  OtherRecipientInfo ::= SEQUENCE {
 *      oriType OBJECT IDENTIFIER,
 *      oriValue ANY DEFINED BY oriType }
 */
typedef struct {
    BslCid oriType;
    BSL_Buffer oriValue;
} CMS_OtherRecipientInfo;

/**
 * @brief RecipientInfo structure
 * Reference: RFC 5652 Section 6.2
 * RecipientInfo ::= CHOICE {
 *      ktri KeyTransRecipientInfo,
 *      kari [1] KeyAgreeRecipientInfo,
 *      kekri [2] KEKRecipientInfo,
 *      pwri [3] PasswordRecipientinfo,
 *      ori [4] OtherRecipientInfo }
 */
typedef enum {
    CMS_RECIPIENT_TYPE_KTRI = 0,
    CMS_RECIPIENT_TYPE_KARI = 1,
    CMS_RECIPIENT_TYPE_KEKRI = 2,
    CMS_RECIPIENT_TYPE_PWRI = 3,
    CMS_RECIPIENT_TYPE_ORI = 4
} CMS_RecipientType;
typedef struct {
    CMS_RecipientType type;
    union {
        CMS_KeyTransRecipientInfo *ktri;
        CMS_KeyAgreeRecipientInfo *kari;
        CMS_KEKRecipientInfo *kekri;
        CMS_PasswordRecipientInfo *pwri;
        CMS_OtherRecipientInfo *ori;
    } d;
} CMS_RecipientInfo;

/**
 * @brief Originator structure
 * Reference: RFC 5652 Section 6.1
 * OriginatorInfo ::= SEQUENCE {
 *     certs [0] IMPLICIT CertificateSet OPTIONAL,
 *     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
 */
typedef struct {
    HITLS_X509_List *certs;
    HITLS_X509_List *crls;
} CMS_OriginatorInfo;

#define CMS_RecipientInfos BslList

bool CMS_OriginatorInfoIsEmpty(const CMS_OriginatorInfo *originatorInfo);
void CMS_OriginatorInfoFree(CMS_OriginatorInfo *originatorInfo);
int32_t CMS_ParseOriginatorInfo(BSL_ASN1_Buffer *asn, CMS_OriginatorInfo *orig);
int32_t CMS_EncodeOriginatorInfo(CMS_OriginatorInfo *originator, BSL_ASN1_Buffer *encode);

/**
 * @brief Create a new CMS_RecipientInfo structure
 * @param type [IN] Specifies the type of recipient information to create
 *                  (e.g., CMS_RECIPIENT_TYPE_KTRI, CMS_RECIPIENT_TYPE_KARI, etc.)
 * @param flag [IN] Flags used to control creation behavior (reserved or implementation-specific)
 * @return Returns a pointer to the CMS_RecipientInfo structure on success, or NULL on failure
 */
CMS_RecipientInfo *CMS_RecipientInfoNew(CMS_RecipientType type, uint32_t flag);

void CMS_RecipientInfoFree(CMS_RecipientInfo *recipInfo);
int32_t CMS_ParseRecipientList(BSL_ASN1_Buffer *recipSet, CMS_RecipientInfos *list);
int32_t CMS_EncodeRecipientList(CMS_RecipientInfos *list, BSL_ASN1_Buffer *encode);
int32_t CMS_DecryptCekForRecipient(CMS_RecipientInfos *recips, const BSL_Param *param, uint8_t **cek, uint32_t *cekLen);
int32_t CMS_AddRecipientAndWrapCek(CMS_RecipientInfos *recips, BSL_Buffer *key, const BSL_Param *param);
int32_t CMS_CheckRecipientsNotEmpty(CMS_RecipientInfos *recips);

#endif // HITLS_PKI_CMS_ENVELOPEDDATA || HITLS_PKI_CMS_AUTHENTICATEDDATA

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_CMS

#endif // HITLS_CMS_RECIPIENT_H

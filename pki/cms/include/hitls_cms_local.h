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

#ifndef HITLS_CMS_LOCAL_H
#define HITLS_CMS_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_PKI_CMS
#include "hitls_x509_local.h"
#include "crypt_eal_md.h"
#include "hitls_cert_local.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_cms.h"
#include "crypt_eal_cipher.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if defined(HITLS_PKI_CMS_SIGNEDDATA) || defined(HITLS_PKI_CMS_ENVELOPEDDATA)

#define HITLS_CMS_FLAG_GEN               0x01
#define HITLS_CMS_FLAG_PARSE             0x02
#define HITLS_CMS_FLAG_NO_SIGNEDATTR     0x08

#define HITLS_CMS_UNINIT                      0
#define HITLS_CMS_SIGN_INIT                   1
#define HITLS_CMS_VERIFY_INIT                 2
#define HITLS_CMS_SIGN_FINISHED               3
#define HITLS_CMS_VERIFY_FINISHED             4
#define HITLS_CMS_ENCRYPT_INIT                5
#define HITLS_CMS_DECRYPT_INIT                6
#define HITLS_CMS_ENCRYPT_FINISHED            7
#define HITLS_CMS_DECRYPT_FINISHED            8
#endif /* HITLS_PKI_CMS_SIGNEDDATA || HITLS_PKI_CMS_ENVELOPEDDATA */

#ifdef HITLS_PKI_CMS_ENVELOPEDDATA

/**
 * Reference: RFC 5652 Section 6.1
 * EncryptedContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *      encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
 */
typedef struct {
    BslCid contentType;
    BslCid contentEncryAlg;
    BSL_Buffer encryptedContent;
    BSL_Buffer algParams;
    /* Runtime encryption context - not encoded into ASN.1 */
    CRYPT_EAL_CipherCtx *cipherCtx;
    uint8_t *key; // Content encryption key
    uint32_t keyLen;
} CMS_EncryptedContentInfo;

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

/**
 * @brief EnvelopedData structure
 * Reference: RFC 5652 Section 6.1
 * EnvelopedData ::= SEQUENCE {
 *      version CMSVersion,
 *      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *      recipientInfos RecipientInfos,
 *      encryptedContentInfo EncryptedContentInfo,
 *      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
 */
typedef struct {
    uint32_t version;
    CMS_OriginatorInfo *originatorInfo; // optional
    CMS_RecipientInfos *recipientInfos;
    CMS_EncryptedContentInfo encryptedContentInfo;
    HITLS_X509_Attrs *unprotectedAttrs; // optional

    // Streaming operation support fields
    uint32_t flag; // Used to mark EnvelopedData parsing or generation, indicating resource release behavior.
    uint32_t state;  // Operation state: UNINIT, ENCRYPT_INIT, DECRYPT_INIT, etc.
    CRYPT_EAL_CipherCtx *streamCipherCtx;  // Streaming encryption/decryption context
    BSL_Buffer key; // Content encrypt key
    uint8_t *initData; /* Parsed input snapshot kept alive for ASN.1-backed fields */
    HITLS_PKI_LibCtx *libCtx;
    const char *attrName;
} CMS_EnvelopedData;

void CMS_EnvelopedDataFree(CMS_EnvelopedData *envData);

/**
 * @brief Create a new CMS_RecipientInfo structure
 * @param type [IN] Specifies the type of recipient information to create
 *                  (e.g., CMS_RECIPIENT_TYPE_KTRI, CMS_RECIPIENT_TYPE_KARI, etc.)
 * @param flag [IN] Flags used to control creation behavior (reserved or implementation-specific)
 * @return Returns a pointer to the CMS_RecipientInfo structure on success, or NULL on failure
 */
CMS_RecipientInfo *CMS_RecipientInfoNew(CMS_RecipientType type, uint32_t flag);

void RecipientInfoFree(CMS_RecipientInfo *recipInfo);

/**
 * @brief Initialize streaming operation for EnvelopedData
 */
int32_t HITLS_CMS_EnvelopedDataInit(HITLS_CMS *cms, int32_t option, const BSL_Param *param);

/**
 * @brief Update streaming operation for EnvelopedData
 */
int32_t HITLS_CMS_EnvelopedDataUpdate(HITLS_CMS *cms, const BSL_Buffer *input, BSL_Buffer *output);

/**
 * @brief Finalize streaming operation for EnvelopedData
 */
int32_t HITLS_CMS_EnvelopedDataFinal(HITLS_CMS *cms, const BSL_Param *param, BSL_Buffer *output);

/**
 * @brief Control EnvelopedData structure
 */
int32_t HITLS_CMS_EnvelopedDataCtrl(HITLS_CMS *cms, int32_t cmd, void *val, uint32_t valLen);

/**
 * @brief Generate EnvelopedData buffer (wrapper for encoding)
 */
int32_t HITLS_CMS_GenEnvelopedDataBuff(int32_t format, HITLS_CMS *cms, BSL_Buffer *encode);

/**
 * @brief Parse EnvelopedData from buffer (wrapper for unified framework)
 */
int32_t HITLS_CMS_ParseEnvelopedData(HITLS_PKI_LibCtx *libCtx, const char *attrName, const BSL_Buffer *encode,
    HITLS_CMS **cms);

#endif // HITLS_PKI_CMS_ENVELOPEDDATA

#ifdef HITLS_PKI_CMS_SIGNEDDATA

#define HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1    0x01  /** v1 signerinfo. */
#define HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3    0x03  /** v3 signerinfo. */

/**
 * @brief AlgorithmIdentifier structure
 * Reference: RFC 5652 Section 5.1.1
 */
typedef struct {
    int32_t id;     /**< Algorithm OID */
    BSL_Buffer param; /**< Algorithm parameters (optional) */
    CRYPT_EAL_MdCtx *mdCtx; /**< Message digest context for streaming signature */
} CMS_AlgId;

/**
 * @brief Attribute structure
 * Reference: RFC 5652 Section 5.3
 */
#define CMS_SignerInfos BslList

/**
 * @brief EncapsulatedContentInfo structure
 * Reference: RFC 5652 Section 5.2
 */
typedef struct {
    int32_t contentType;   /**< Content type */
    BSL_Buffer content;   /**< Encapsulated content (optional) */
} CMS_EncapContentInfo;

/**
 * @brief SignerInfo structure
 * Reference: RFC 5652 Section 5.3
 */
typedef struct {
    int32_t version;                            /**< CMS version */
    BSL_ASN1_List *issuerName;
    BSL_Buffer certSerialNum;
    HITLS_X509_ExtSki subjectKeyId;
    CMS_AlgId digestAlg;                         /**< Digest algorithm */
    HITLS_X509_Attrs *signedAttrs;               /**< Signed attributes (optional) */
    HITLS_X509_Asn1AlgId sigAlg;                 /**< Signature algorithm */
    HITLS_X509_Attrs *unsignedAttrs;             /**< Unsigned attributes (optional) */
    BSL_Buffer sigValue;                         /**< Signature value */
    BSL_Buffer signData;      /**< Sign data of the signerInfo, used to verify the signature, in parse mode,
                                    it cannot be free, in generate mode, it can be free. */
    uint32_t flag;            /**< Used to mark signData parsing or generation, indicating resource release behavior. */
} CMS_SignerInfo;

/**
 * @brief SignedData structure
 * Reference: RFC 5652 Section 5.1
 */
typedef struct {
    int32_t version;                     /**< CMS version */
    HITLS_X509_List *digestAlg;                     /**< List of CMS_AlgId */
    CMS_EncapContentInfo encapCont; /**< Encapsulated content info */
    HITLS_X509_List *certs;                         /**< List of HITLS_X509_Cert (optional) */
    HITLS_X509_List *crls;                                 /**< List of HITLS_X509_Crl (optional) */
    CMS_SignerInfos *signerInfos;                          /**< List of CMS_SignerInfo */
    uint32_t flag; // Used to mark signData parsing or generation, indicating resource release behavior.
    uint8_t *initData;
    bool detached;
    uint32_t state;  /**< Operation state: HITLS_CMS_UNINIT, HITLS_CMS_SIGN_INIT... */
    HITLS_PKI_LibCtx *libCtx;
    const char *attrName;
} CMS_SignedData;

/**
 * @brief Parse SignedData from ASN.1 encoded buffer
 * @param encode ASN.1 encoded buffer
 * @param signedData Output SignedData structure
 * @return HITLS_PKI_SUCCESS on success, error code on failure
 */
int32_t HITLS_CMS_ParseSignedData(HITLS_PKI_LibCtx *libCtx, const char *attrName, const BSL_Buffer *encode,
    HITLS_CMS **signedData);

/**
 * @brief Create a new CMS_SignerInfo structure
 * @return CMS_SignerInfo structure
 */
CMS_SignerInfo *CMS_SignerInfoNew(uint32_t flag);

void CMS_AlgIdFree(void *algId);

/**
 * @brief encode PKCS7-SignedDataa
 * @param format encoding format
 * @param cms CMS SignedData structure
 * @param encode encode data
 * @return HITLS_PKI_SUCCESS on success, error code on failure
 */
int32_t HITLS_CMS_GenSignedDataBuff(int32_t format, HITLS_CMS *cms, BSL_Buffer *encode);

/**
 * @brief Free CMS_SignerInfo structure
 * @param signerInfo CMS_SignerInfo structure to free
 */
void HITLS_CMS_SignerInfoFree(void *signerInfo);

/**
 * @brief add message digest algorithm to list, if duplicate, do not add.
 */
int32_t HITLS_CMS_AddMd(HITLS_X509_List *list, int32_t mdId);

/**
 * @brief Control SignedData structure
 */
int32_t HITLS_CMS_SignedDataCtrl(HITLS_CMS *cms, int32_t cmd, void *val, uint32_t valLen);

/**
 * @brief Add certificate to list
 */
int32_t HITLS_CMS_AddCert(HITLS_X509_List **list, HITLS_X509_Cert *cert);

/**
 * @brief Add CRL to list
 */
int32_t HITLS_CMS_AddCrl(HITLS_X509_List **list, HITLS_X509_Crl *crl);

/**
 * @brief Initialize streaming operation for SignedData
 */
int32_t HITLS_CMS_SignedDataInit(HITLS_CMS *cms, int32_t option, const BSL_Param *param);

/**
 * @brief Update streaming operation for SignedData
 */
int32_t HITLS_CMS_SignedDataUpdate(HITLS_CMS *cms, const BSL_Buffer *input);

/**
 * @brief Finalize streaming operation for SignedData
 */
int32_t HITLS_CMS_SignedDataFinal(HITLS_CMS *cms, const BSL_Param *param);

#endif

#ifdef HITLS_PKI_CMS_DATA
// parse PKCS7-Data
int32_t HITLS_CMS_ParseAsn1Data(BSL_Buffer *encode, BSL_Buffer *dataValue);
#endif

#ifdef HITLS_PKI_CMS_DIGESTINFO

// parse PKCS7-DigestInfo：only support hash.
int32_t HITLS_CMS_ParseDigestInfo(BSL_Buffer *encode, BslCid *cid, BSL_Buffer *digest);

// encode PKCS7-DigestInfo：only support hash.
int32_t HITLS_CMS_EncodeDigestInfoBuff(BslCid cid, BSL_Buffer *in, BSL_Buffer *encode);

#endif

#if defined(HITLS_PKI_CMS_SIGNEDDATA) || defined(HITLS_PKI_CMS_ENVELOPEDDATA)
/**
 * @brief CMS ContentInfo structure
 * Reference: RFC 5652 Section 3
 */
typedef struct {
    int32_t contentType;   /**< Content type */
    BSL_Buffer content;   /**< Content (optional) */
} CMS_ContentInfo;

struct _HITLS_CMS {
    int32_t dataType;                     /**< CMS data type */
    union {
#ifdef HITLS_PKI_CMS_SIGNEDDATA
        CMS_SignedData *signedData;
#endif
#ifdef HITLS_PKI_CMS_ENVELOPEDDATA
        CMS_EnvelopedData *envelopedData;
#endif
    } ctx;
};

void HITLS_CMS_FreeAsnList(BSL_ASN1_Buffer *list, uint32_t count);

int32_t EncodeCertList(HITLS_X509_List *certs, BSL_ASN1_Buffer *encode);

int32_t EncodeCrlList(HITLS_X509_List *crls, BSL_ASN1_Buffer *encode);

/**
 * @ingroup cms
 * @brief cms generate
 * @par Description: generate cms buffer. Now only support to generate signeddata, envelopeddata.
 *
 * @attention Only support to generate cms buffer.
 * @param format         [IN] format
 * @param cms            [IN] the cms struct.
 * @param optionalParam  [IN] optional parameters (can be NULL).
 * @param encode         [OUT] encode data
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_GenBuff(int32_t format, HITLS_CMS *cms, const BSL_Param *optionalParam, BSL_Buffer *encode);

/**
 * @ingroup cms
 * @par Description: Generate cms to store in file
 *
 * @attention Generate a .cms file based on the existing information.
 * @param format          [IN] Encoding format: BSL_FORMAT_ASN1.
 * @param cms             [IN] cms struct.
 * @param optionalParam   [IN] optional parameters (can be NULL).
 * @param path            [IN] The path of the generated cms-file.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_GenFile(int32_t format, HITLS_CMS *cms, const BSL_Param *optionalParam, const char *path);

#endif // HITLS_PKI_CMS_SIGNEDDATA || HITLS_PKI_CMS_ENVELOPEDDATA

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_CMS

#endif // HITLS_CMS_LOCAL_H

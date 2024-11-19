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

#ifndef HITLS_PKI_H
#define HITLS_PKI_H

#include <stdint.h>
#include <stdbool.h>
#include "bsl_list.h"
#include "bsl_type.h"
#include "bsl_uio.h"
#include "bsl_obj.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_encode.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HITLS_X509_List BslList

typedef struct _HITLS_X509_Cert HITLS_X509_Cert;

typedef struct _HITLS_X509_Ext HITLS_X509_Ext;

typedef struct _HITLS_X509_Crl HITLS_X509_Crl;

typedef struct _HITLS_X509_CrlEntry HITLS_X509_CrlEntry;

typedef struct _HITLS_X509_StoreCtx HITLS_X509_StoreCtx;

typedef struct _HITLS_X509_Csr HITLS_X509_Csr;

typedef struct _HITLS_PKCS12 HITLS_PKCS12;

typedef struct _HITLS_PKCS12_Bag HITLS_PKCS12_Bag;

#define HITLS_CERT_VERSION_1 0
#define HITLS_CERT_VERSION_2 1
#define HITLS_CERT_VERSION_3 2

#define HITLS_CSR_VERSION 0

/* Key usage */
#define HITLS_X509_EXT_KU_DIGITAL_SIGN          0x0080
#define HITLS_X509_EXT_KU_NON_REPUDIATION       0x0040
#define HITLS_X509_EXT_KU_KEY_ENCIPHERMENT      0x0020
#define HITLS_X509_EXT_KU_DATA_ENCIPHERMENT     0x0010
#define HITLS_X509_EXT_KU_KEY_AGREEMENT         0x0008
#define HITLS_X509_EXT_KU_KEY_CERT_SIGN         0x0004
#define HITLS_X509_EXT_KU_CRL_SIGN              0x0002
#define HITLS_X509_EXT_KU_ENCIPHER_ONLY         0x0001
#define HITLS_X509_EXT_KU_DECIPHER_ONLY         0x8000

typedef enum {
    HITLS_X509_REF_UP = 0,             /** Increase the reference count of the object */

    HITLS_X509_GET_ENCODELEN = 0x0100, /** Get the length in bytes of the ASN.1 DER encoded cert/csr */
    HITLS_X509_GET_ENCODE,             /** Get the ASN.1 DER encoded cert/csr data */
    HITLS_X509_GET_PUBKEY,             /** Get the public key contained in the cert/csr */
    HITLS_X509_GET_SIGNALG,            /** Get the signature algorithm used to sign the cert/csr */
    HITLS_X509_GET_SUBJECT_DNNAME_STR, /** Get the subject distinguished name as a formatted string */
    HITLS_X509_GET_ISSUER_DNNAME_STR,  /** Get the issuer distinguished name as a formatted string */
    HITLS_X509_GET_SERIALNUM_STR,      /** Get the serial number as a string */
    HITLS_X509_GET_BEFORE_TIME,        /** Get the validity start time as a string */
    HITLS_X509_GET_AFTER_TIME,         /** Get the validity end time as a string */
    HITLS_X509_GET_SUBJECT_DNNAME,     /** Get the list of subject distinguished name components.
                                           Note: The list is read-only and should not be modified. */
    HITLS_X509_GET_ISSUER_DNNAME,      /** Get the list of issuer distinguished name components.
                                           Note: The list is read-only and should not be modified. */
    HITLS_X509_GET_VERSION,            /** Get the version from cert or crl. */
    HITLS_X509_GET_REVOKELIST,         /** Get the certficate revoke list from the crl. */
    HITLS_X509_GET_SERIALNUM,          /** Get the serial number of the cert. */

    HITLS_X509_SET_VERSION = 0x0200,   /** Set the version for the cert. */
    HITLS_X509_SET_SERIALNUM,          /** Set the serial number for the cert, the length range is 1 to 20. */
    HITLS_X509_SET_BEFORE_TIME,        /** Set the before time for the cert. */
    HITLS_X509_SET_AFTER_TIME,         /** Set the after time for the cert. */
    HITLS_X509_SET_PUBKEY,             /** Set the public key for the cert/csr. */
    HITLS_X509_SET_SUBJECT_DNNAME,     /** Set the subject name list. */
    HITLS_X509_SET_ISSUER_DNNAME,      /** Set the issuer name list. */
    HITLS_X509_SET_CSR_EXT,            /** Replace the cert's ext with csr's */
    HITLS_X509_ADD_SUBJECT_NAME,       /** Add the subject name for the cert/csr. */
    HITLS_X509_CRL_ADD_REVOKED_CERT,   /** Add the revoke cert to crl. */

    HITLS_X509_EXT_KU_KEYENC = 0x0300,          /** Check if key encipherment usage is set in key usage extension */
    HITLS_X509_EXT_KU_DIGITALSIGN,              /** Check if digital signature usage is set in key usage extension */
    HITLS_X509_EXT_KU_CERTSIGN,                 /** Check if certificate signing usage is set in key usage extension */
    HITLS_X509_EXT_KU_KEYAGREEMENT,             /** Check if key agreement usage is set in key usage extension */

    HITLS_X509_EXT_SET_SKI = 0x0400,             /** Set the subject key identifier extension. */
    HITLS_X509_EXT_SET_AKI,                      /** Set the authority key identifier extension. */
    HITLS_X509_EXT_SET_KUSAGE,                   /** Set the key usage extension. */
    HITLS_X509_EXT_SET_SAN,                      /** Set the subject alternative name extension. */
    HITLS_X509_EXT_SET_BCONS,                    /** Set the basic constraints extension. */
    HITLS_X509_EXT_SET_EXKUSAGE,                 /** Set the extended key usage extension. */
    HITLS_X509_EXT_SET_CRLNUMBER,                /** Set the crlnumber extension. */

    HITLS_X509_EXT_GET_SKI = 0x0500,            /** Get Subject Key Identifier from extensions.
                                                    Note: Kid is a shallow copy. */
    HITLS_X509_EXT_GET_CRLNUMBER,               /** get the crlnumber form the crl. */
    HITLS_X509_EXT_GET_AKI,                     /** get the Authority Key Identifier form the crl/cert/csr. */

    HITLS_X509_EXT_CHECK_SKI = 0x0600,          /** Check if ski is exists. */

    HITLS_X509_CSR_GET_ATTRIBUTES = 0x0700,     /** Get the attributes from the csr. */
} HITLS_X509_Cmd;

/**
 * GeneralName types defined in RFC 5280 Section 4.2.1.6
 * Reference: https://tools.ietf.org/html/rfc5280#section-4.2.1.6
 * GeneralName ::= CHOICE {
 *   otherName                       [0]     OtherName,
 *   rfc822Name                      [1]     IA5String,
 *   dNSName                         [2]     IA5String,
 *   x400Address                     [3]     ORAddress,
 *   directoryName                   [4]     Name,
 *   ediPartyName                    [5]     EDIPartyName,
 *   uniformResourceIdentifier       [6]     IA5String,
 *   iPAddress                       [7]     OCTET STRING,
 *   registeredID                    [8]     OBJECT IDENTIFIER }
 */
typedef enum {
    HITLS_X509_GN_EMAIL,  // rfc822Name                [1] IA5String
    HITLS_X509_GN_DNS,    // dNSName                   [2] IA5String
    HITLS_X509_GN_DNNAME, // directoryName             [4] Name
    HITLS_X509_GN_URI,    // uniformResourceIdentifier [6] IA5String
    HITLS_X509_GN_IP,     // iPAddress                 [7] Octet String

    // Other types are not supported yet
    HITLS_X509_GN_MAX
} HITLS_X509_GeneralNameType;

/* Distinguish name */
typedef struct {
    BslCid cid;
    uint8_t *data;
    uint32_t dataLen;
} HITLS_X509_DN;

/**
 * GenernalName
 */
typedef struct {
    HITLS_X509_GeneralNameType type;
    BSL_Buffer value;
} HITLS_X509_GeneralName;

/**
 * Authority Key identifier
 */
typedef struct {
    bool critical;
    BSL_Buffer kid;       // keyIdentifier: optional
    BslList *issuerName;  // Not supported. authorityCertIssuer: optional, List of HITLS_X509_GeneralName
    BSL_Buffer serialNum; // Not supported. authorityCertSerialNumber: optional
} HITLS_X509_ExtAki;

/**
 * Subject Key identifier
 */
typedef struct {
    bool critical;
    BSL_Buffer kid;
} HITLS_X509_ExtSki;

/**
 * Key Usage
 */
typedef struct {
    bool critical;
    uint32_t keyUsage;
} HITLS_X509_ExtKeyUsage;

/**
 * Extended Key Usage
 */
typedef struct {
    bool critical;
    BslList *oidList; // Object Identifier: list of BSL_Buffer
} HITLS_X509_ExtExKeyUsage;

/**
 * Subject Alternatiive Name
 */
typedef struct {
    bool critical;
    BslList *names; // List of HITLS_X509_GeneralName
} HITLS_X509_ExtSan;

/**
 * Basic Constraints
 */
typedef struct {
    bool critical;
    bool isCa;          // Default to false.
    int32_t maxPathLen; // Greater than or equal to 0. -1: no check, 0: no intermediate certificate
} HITLS_X509_ExtBCons;

/**
 * @brief Signature algorithm parameters.
 */
typedef struct {
    uint32_t algId;    /**< Algorithm identifier */
    union {
        CRYPT_RSA_PssPara rsaPss;       /**< RSA PSS padding parameters */
    };
} HITLS_X509_SignAlgParam;

/**
 * Crl number
 */
typedef struct {
    bool critical;        // Default to false.
    BSL_Buffer crlNumber; // crlNumber
} HITLS_X509_ExtCrlNumber;

typedef struct {
    bool critical;
    BSL_TIME time;
} HITLS_X509_RevokeExtTime;

typedef enum {
    HITLS_X509_CRL_SET_REVOKED_SERIALNUM = 0,    /** Set the revoked serial number. */
    HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME,      /** Set the revoke time. */
    HITLS_X509_CRL_SET_REVOKED_INVAILD_TIME,     /** Set the invalid time extension. */
    HITLS_X509_CRL_SET_REVOKED_REASON,           /** Set the revoke reason extension. */
    HITLS_X509_CRL_SET_REVOKED_CERTISSUER,       /** Set the revoke cert issuer extension. */

    HITLS_X509_CRL_GET_REVOKED_SERIALNUM,        /** Get the revoked serial number. */
    HITLS_X509_CRL_GET_REVOKED_REVOKE_TIME,      /** Get the revoke time. */
    HITLS_X509_CRL_GET_REVOKED_INVAILD_TIME,     /** Get the invalid time extension. */
    HITLS_X509_CRL_GET_REVOKED_REASON,           /** Get the revoke reason extension. */
    HITLS_X509_CRL_GET_REVOKED_CERTISSUER,       /** Get the revoke cert issuer extension. */
} HITLS_X509_RevokeCmd;

typedef enum {
    HITLS_X509_REVOKED_REASON_UNSPECIFIED = 0,         /** CRLReason: Unspecified. */
    HITLS_X509_REVOKED_REASON_KEY_COMPROMISE,          /** CRLReason: Key compromise. */
    HITLS_X509_REVOKED_REASON_CA_COMPROMISE,           /** CRLReason: CA compromise. */
    HITLS_X509_REVOKED_REASON_AFFILIATION_CHANGED,     /** CRLReason: Affiliation changed. */
    HITLS_X509_REVOKED_REASON_SUPERSEDED,              /** CRLReason: Superseded. */
    HITLS_X509_REVOKED_REASON_CESSATION_OF_OPERATION,  /** CRLReason: Cessation of operation. */
    HITLS_X509_REVOKED_REASON_CERTIFICATE_HOLD,        /** CRLReason: Certificate hold. */
    HITLS_X509_REVOKED_REASON_REMOVE_FROM_CRL,         /** CRLReason: Remove from CRL. */
    HITLS_X509_REVOKED_REASON_PRIVILEGE_WITHDRAWN,     /** CRLReason: Privilege withdrawn. */
    HITLS_X509_REVOKED_REASON_AA_COMPROMISE,           /** CRLReason: aA compromise. */
} HITLS_X509_RevokeReason;

typedef struct {
    bool critical;
    int32_t reason;
} HITLS_X509_RevokeExtReason;

typedef struct {
    bool critical;
    BslList *issuerName;
} HITLS_X509_RevokeExtCertIssuer;

typedef enum {
    HITLS_X509_EXT_TYPE_CSR,
} HITLS_X509_ExtType;

/**
 * @ingroup pki
 * @brief Allocate a certificate.
 *
 * @retval HITLS_X509_Cert *
 */
HITLS_X509_Cert *HITLS_X509_CertNew(void);

/**
 * @ingroup pki
 * @brief Unallocate a certificate.
 *
 * @param cert [IN] The certificate.
 */
void HITLS_X509_CertFree(HITLS_X509_Cert *cert);

/**
 * @ingroup pki
 * @brief Duplicate a certificate.
 *
 * @param src  [IN] Source certificate.
 * @param dest [OUT] Destination certificate.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertDup(HITLS_X509_Cert *src, HITLS_X509_Cert **dest);

/**
 * @ingroup pki
 * @brief Sign a certificate.
 *
 * @attention 1. This function can only be used when generating a new certificate.
 *            2. You need to first call interfaces HITLS_X509_CertCtrl to set cert information.
 *
 * @param mdId     [IN] The message digest algorithm ID.
 * @param prvKey   [IN] The private key context used for signing.
 * @param algParam [IN] The signature algorithm parameters.
 * @param cert     [IN] The certificate to be signed.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertSign(uint32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam,
    HITLS_X509_Cert *cert);

/**
 * @ingroup pki
 * @brief Compute the digest of the certificate.
 *
 * @attention This function must be called after generating or parsing a certificate.
 *
 * @param cert  [IN] The certificate.
 * @param mdId [IN] Digest algorithm.
 * @param data [IN/OUT] The digest result.
 * @param dataLen [IN/OUT] The length of the digest.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertDigest(HITLS_X509_Cert *cert, CRYPT_MD_AlgId mdId, uint8_t *data, uint32_t *dataLen);

/**
 * @ingroup pki
 * @brief Generic function to process certificate.
 *
 * @param cert   [IN] The certificate.
 * @param cmd    [IN] HITLS_X509_Cmd
 * @param val    [IN/OUT] input and output value
 * @param valLen [In] value length
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertCtrl(HITLS_X509_Cert *cert, int32_t cmd, void *val, int32_t valLen);

/**
 * @ingroup pki
 * @brief Generic function to set/get an extension.
 *
 * @param ext    [IN] extensions
 * @param cmd    [IN] HITLS_X509_EXT_SET_XXX
 *        cmd                               data type
 *        HITLS_X509_EXT_GET|SET_KUSAGE         HITLS_X509_ExtKeyUsage
 *        HITLS_X509_EXT_GET|SET_BCONS          HITLS_X509_ExtBCons
 *        HITLS_X509_EXT_GET|SET_AKI            HITLS_X509_ExtAki
 *        HITLS_X509_EXT_GET|SET_SKI            HITLS_X509_ExtSki
 *        HITLS_X509_EXT_GET|SET_SAN            HITLS_X509_ExtSan
 *        HITLS_X509_EXT_GET|SET_EXKUSAGE       HITLS_X509_ExtExKeyUsage
 *        HITLS_X509_EXT_CHECK_SKI              bool
 * @param val    [IN/OUT] input and output value
 * @param valLen [In] value length
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_ExtCtrl(HITLS_X509_Ext *ext, int32_t cmd, void *val, int32_t valLen);

/**
 * @ingroup pki
 * @brief Allocate a extension.
 *
 * @retval HITLS_X509_Ext *
 */
HITLS_X509_Ext *HITLS_X509_ExtNew(int32_t type);

/**
 * @ingroup pki
 * @brief Unallocate a extension.
 *
 * @param ext [IN] The extension.
 */
void HITLS_X509_ExtFree(HITLS_X509_Ext *ext);

/**
 * @ingroup pki
 * @brief clear the HITLS_X509_ExtAki structure.
 * @par Description: This interface needs to be called to clean up memory when obtaining AKI extensions from
 *  certificates, CRLs, or CSRs using the macro HITLS_X509_EXT_GET_AKI.
 *
 * @param aki [IN] The HITLS_X509_ExtAki aki
 */
void HITLS_X509_ClearAuthorityKeyId(HITLS_X509_ExtAki *aki);

/**
 * @ingroup pki
 * @brief Parse the CERT in the buffer.
 * @par Description: Parse the CERT in the buffer.
 *  If the encoding is successful, the memory for the crl is requested from within the function,
 *  and the user needs to free it after using it. When the parameter is BSL_FORMAT_PEM and
 *  BSL_FORMAT_UNKNOWN, the buff of encode needs to end with '\0'
 * @attention None
 * @param format [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param encode [IN] CERT data.
 * @param cert   [OUT] CERT after parse.
 * @return #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertParseBuff(int32_t format, BSL_Buffer *encode, HITLS_X509_Cert **cert);

/**
 * @ingroup pki
 * @brief Parse the CERT in the file.
 * @par Description: Parse the CERT in the file.
 *  If the encoding is successful, the memory for the crl is requested from within the function,
 *  and the user needs to free it after using it.
 * @attention None
 * @param format [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param path   [IN] CERT file path.
 * @param cert   [OUT] CERT after parse.
 * @return #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertParseFile(int32_t format, const char *path, HITLS_X509_Cert **cert);

/**
 * @ingroup pki
 * @brief Parse the CERTs in the file.
 * @par Description: Parse multiple CERTs in the file.
 *  If the encoding is successful, the memory for the certlist is requested from within the function,
 *  and the user needs to free it after using it.
 * @attention None
 * @param format  [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param path    [IN] CRL file path.
 * @param crllist [OUT] CRL list after parse.
 * @return #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertMulParseFile(int32_t format, const char *path, HITLS_X509_List **certlist);

/**
 * @ingroup pki
 * @brief Generates an encoded certificate.
 *
 * @attention This function is used after parsing the certificate or after signing.
 *
 * @param format [IN] Encoding format: BSL_FORMAT_ASN1 or BSL_FORMAT_PEM
 * @param cert   [IN] cert
 * @param buff   [OUT] encode result
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertGenBuff(int32_t format, HITLS_X509_Cert *cert, BSL_Buffer *buff);

/**
 * @ingroup pki
 * @brief Generate a certificate file.
 *
 * @attention This function is used after parsing the certificate or after signing.
 *
 * @param format [IN] Encoding format: BSL_FORMAT_ASN1 or BSL_FORMAT_PEM
 * @param cert   [IN] cert
 * @param path   [IN] file path
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertGenFile(int32_t format, HITLS_X509_Cert *cert, const char *path);

/**
 * @ingroup pki
 * @brief Add a distinguish name array to list.
 *
 * @param list [IN] The name list
 * @param dnNames   [IN] dnName array
 * @param size   [IN] The count of dnName array
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_AddDnName(BslList *list, HITLS_X509_DN *dnNames, int32_t size);

/**
 * @ingroup pki
 * @brief Allocate a crl.
 *
 * @retval HITLS_X509_Crl *
 */
HITLS_X509_Crl *HITLS_X509_CrlNew(void);
/**
 * @ingroup pki
 * @brief Release the CRL.
 * @par Description: Release the memory of the CRL.
 *
 * @attention None
 * @param crl           [IN] CRL after parse.
 * @return Error code
 */
void HITLS_X509_CrlFree(HITLS_X509_Crl *crl);

/**
 * @ingroup pki
 * @brief Crl setting interface.
 * @par Description: Set CRL information.
 *         parameter           data type         Length(len):number of data bytes
 * HITLS_X509_REF_UP       int           The length is sizeof(int), which is used to increase the
 *                                       number of CRL references.
 * @attention None
 * @param crl            [IN] CRL data
 * @param cmd            [IN] Set type.
 * @param val           [OUT] Set data.
 * @param valLen         [IN] The length of val.
 * @return Error code
 */
int32_t HITLS_X509_CrlCtrl(HITLS_X509_Crl *crl, int32_t cmd, void *val, int32_t valLen);

/**
 * @ingroup pki
 * @brief Parse the CRL in the buffer.
 * @par Description: Parse the CRL in the buffer.
 *  If the encoding is successful, the memory for the crl is requested from within the function,
 *  and the user needs to free it after using it. When the parameter is BSL_FORMAT_PEM and
 *  BSL_FORMAT_UNKNOWN, the buff of encode needs to end with '\0'
 * @attention None
 * @param format         [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/
 *                            BSL_FORMAT_UNKNOWN.
 * @param encode         [IN] CRL data.
 * @param crl           [OUT] CRL after parse.
 * @return Error code
 */
int32_t HITLS_X509_CrlParseBuff(int32_t format, BSL_Buffer *encode, HITLS_X509_Crl **crl);

/**
 * @ingroup pki
 * @brief Parse the CRL in the file.
 * @par Description: Parse the CRL in the file.
 *  If the encoding is successful, the memory for the crl is requested from within the function,
 *  and the user needs to free it after using it.
 * @attention None
 * @param format         [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/
 *                            BSL_FORMAT_UNKNOWN.
 * @param path           [IN] CRL file path.
 * @param crl           [OUT] CRL after parse.
 * @return Error code
 */
int32_t HITLS_X509_CrlParseFile(int32_t format, const char *path, HITLS_X509_Crl **crl);

/**
 * @ingroup pki
 * @brief Parse the CRLs in the file.
 * @par Description: Parse multiple CRLs in the file.
 *  If the encoding is successful, the memory for the crllist is requested from within the function,
 *  and the user needs to free it after using it.
 * @attention None
 * @param format         [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/
 *                            BSL_FORMAT_UNKNOWN.
 * @param path           [IN] CRL file path.
 * @param crllist       [OUT] CRL list after parse.
 * @return Error code
 */
int32_t HITLS_X509_CrlMulParseFile(int32_t format, const char *path, HITLS_X509_List **crllist);

/**
 * @ingroup pki
 * @brief Generate a CRL and encode it.
 * @par Description: This function encodes the CRL into the specified format.
 *  If the encoding is successful, the memory for the encode data is requested from within the function,
 *  and the user needs to free it after using it.
 *
 * @attention This function is used after parsing the crl or after signing.
 *
 * @attention None
 * @param format        [IN] Encoding format: BSL_FORMAT_PEM or BSL_FORMAT_ASN1.
 * @param crl           [IN] CRL raw data.
 * @param buff          [OUT] Encode data.
 * @return Error code
 */
int32_t HITLS_X509_CrlGenBuff(int32_t format, HITLS_X509_Crl *crl, BSL_Buffer *buff);

/**
 * @ingroup pki
 * @brief Generate a CRL and encode it to specific file.
 * @par Description: This function encodes the CRL into the specified format.
 *  If the encoding is successful, the memory for the encode data is requested from within the function,
 *  and the user needs to free it after using it.
 *
 * @attention This function is used after parsing the crl or after signing.
 *
 * @attention None
 * @param format         [IN] Encoding format: BSL_FORMAT_PEM or BSL_FORMAT_ASN1.
 * @param crl            [IN] CRL raw data.
 * @param path          [OUT] Encoding data file path.
 * @return Error code
 */
int32_t HITLS_X509_CrlGenFile(int32_t format, HITLS_X509_Crl *crl, const char *path);

/**
 * @ingroup pki
 * @brief Verify the integrity of the CRL.
 * @par Description: This function verifies the integrity of the CRL
 *
 * @attention For generated CRLs, must be called after signing.
 *
 * @attention None
 * @param pubkey         [IN] pubkey.
 * @param crl            [IN] CRL info.
 * @return Error code
 */
int32_t HITLS_X509_CrlVerify(void *pubkey, HITLS_X509_Crl *crl);

/**
 * @ingroup pki
 * @brief Signing a CRL.
 * @par Description: This function is used to sign the CRL.
 *
 * @attention 1. This function can only be used when generating a new crl.
 *            2. Before signing, you need to call the HITLS_X509_CrlCtrl interface to set the CRL information.
 *
 * @attention The interface can be called multiple times, and the signature is regenerated on each call.
 * @param mdId           [IN] hash algorithm.
 * @param prvKey         [IN] private key.
 * @param algParam       [IN] signature parameter, for example, rsa-pss parameter.
 * @param crl            [IN/OUT] CRL info.
 * @return Error code
 */
int32_t HITLS_X509_CrlSign(uint32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam,
    HITLS_X509_Crl *crl);

/**
 * @ingroup pki crl
 * @brief Allocate a revoked certificate.
 *
 * @attention None
 * @return HITLS_X509_CrlEntry *
 */
HITLS_X509_CrlEntry *HITLS_X509_CrlRevokedNew(void);

/**
 * @ingroup pki
 * @brief Release the CRL certificateRevoke struct .
 * @par Description: Release the memory of the CRL certificateRevoke struct.
 *
 * @attention None
 * @param entry            [IN] entry info.
 * @return Error code
 */
void HITLS_X509_CrlRevokedFree(HITLS_X509_CrlEntry *entry);

/**
 * @ingroup pki
 * @brief Generate a CRL and encode it to specific file.
 * @par Description: This function encodes the CRL into the specified format.
 *  If the encoding is successful, the memory for the encode data is requested from within the function,
 *  and the user needs to free it after using it.
 * @attention None
 * @param pubkey         [IN] pubkey.
 * @param crl            [IN] CRL info.
 * @return Error code
 */
int32_t HITLS_X509_CrlRevokedCtrl(HITLS_X509_CrlEntry *revoked, int32_t cmd, void *val, int32_t valLen);

typedef enum {
    HITLS_X509_VFY_FLAG_CRL_ALL = 1,
    HITLS_X509_VFY_FLAG_CRL_DEV = 2
} HITLS_X509_VFY_FLAGS;

typedef enum {
    HITLS_X509_STORECTX_SET_PARAM_DEPTH,
    HITLS_X509_STORECTX_SET_PARAM_FLAGS,
    HITLS_X509_STORECTX_SET_TIME,
    HITLS_X509_STORECTX_SET_SECBITS,
    /* clear flag */
    HITLS_X509_STORECTX_CLR_PARAM_FLAGS,
    HITLS_X509_STORECTX_DEEP_COPY_SET_CA,
    HITLS_X509_STORECTX_SHALLOW_COPY_SET_CA,
    HITLS_X509_STORECTX_SET_CRL,
    HITLS_X509_STORECTX_REF_UP,
    HITLS_X509_STORECTX_MAX
} HITLS_X509_StoreCtxCmd;

/**
 * @ingroup pki
 * @brief Allocate a StoreCtx.
 *
 * @retval HITLS_X509_StoreCtx *
 */
HITLS_X509_StoreCtx *HITLS_X509_StoreCtxNew(void);

/**
 * @ingroup pki
 * @brief Release the StoreCtx.
 *
 * @param storeCtx    [IN] StoreCtx.
 * @retval void
 */
void HITLS_X509_StoreCtxFree(HITLS_X509_StoreCtx *storeCtx);

/**
 * @ingroup pki
 * @brief Generic function to process StoreCtx.
 *
 * @param storeCtx [IN] StoreCtx.
 * @param cmd [IN] HITLS_X509_Cmd                       data type
 *        HITLS_X509_STORECTX_SET_PARAM_DEPTH           int32_t
 *        HITLS_X509_STORECTX_SET_PARAM_FLAGS           int64_t
 *        HITLS_X509_STORECTX_SET_TIME                  int64_t
 *        HITLS_X509_STORECTX_SET_SECBITS               uint32_t
 *        HITLS_X509_STORECTX_CLR_PARAM_FLAGS           int64_t
 *        HITLS_X509_STORECTX_DEEP_COPY_SET_CA          HITLS_X509_Cert
 *        HITLS_X509_STORECTX_SHALLOW_COPY_SET_CA       HITLS_X509_Cert
 *        HITLS_X509_STORECTX_SET_CRL                   HITLS_X509_Crl
 *        HITLS_X509_STORECTX_REF_UP                    int
 * @param val [IN/OUT] input and output value.
 * @param valLen [IN] value length.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_StoreCtxCtrl(HITLS_X509_StoreCtx *storeCtx, int32_t cmd, void *val, int32_t valLen);

/**
 * @ingroup pki
 * @brief Certificate chain verify function.
 *
 * @param storeCtx [IN] StoreCtx.
 * @param chain [IN] certificate chain.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertVerify(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain);

/**
 * @ingroup pki
 * @brief Certificate chain build function.
 *
 * @param storeCtx [IN] StoreCtx.
 * @param isWithRoot [IN] whether the root cert is included.
 * @param cert [IN] certificate.
 * @param chain [OUT] certificate chain.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CertChainBuild(HITLS_X509_StoreCtx *storeCtx, bool isWithRoot, HITLS_X509_Cert *cert,
    HITLS_X509_List **chain);

typedef struct _HITLS_X509_Attr {
    BslCid cid;
    void *value;
} HITLS_X509_Attr;

/**
 * @ingroup pki
 * @brief Allocate a pkcs10 csr.
 *
 * @retval HITLS_X509_Csr *
 */
HITLS_X509_Csr *HITLS_X509_CsrNew(void);

/**
 * @ingroup pki
 * @brief Release the pkcs10 csr.
 *
 * @param csr    [IN] CSR context.
 * @retval void
 */
void HITLS_X509_CsrFree(HITLS_X509_Csr *csr);

/**
 * @ingroup pki
 * @brief Sign a CSR (Certificate Signing Request).
 *
* @attention 1. This function can only be used when generating a new csr.
 *            2. You need to first call interfaces HITLS_X509_CsrCtrl and HITLS_X509_AttrCtrl to set csr information.
 *
 * @param mdId     [IN] The message digest algorithm ID.
 * @param prvKey   [IN] The private key context used for signing.
 * @param algParam [IN] The signature algorithm parameters.
 * @param csr      [IN] The CSR to be signed.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CsrSign(uint32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam,
    HITLS_X509_Csr *csr);

/**
 * @ingroup pki
 * @brief Generate csr to store in buffer
 *
 * @attention This function is used after parsing the csr or after signing.
 *
 * @param format [IN] The format of the generated csr.
 * @param csr    [IN] The csr context
 * @param buff   [OUT] The buffer of the generated csr.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CsrGenBuff(int32_t format, HITLS_X509_Csr *csr, BSL_Buffer *buff);

/**
 * @ingroup pki
 * @brief Generate csr to store in file
 *
 * @attention This function is used after parsing the csr or after signing.
 *
 * @param format [IN] The format of the generated csr.
 * @param csr    [IN] The csr context
 * @param path   [IN] The path of the generated csr.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CsrGenFile(int32_t format, HITLS_X509_Csr *csr, const char *path);

/**
 * @ingroup pki
 * @brief Generic function to process csr function
 *
 * @param csr [IN] The csr context
 * @param cmd [IN] HITLS_X509_Cmd
 * @param val [IN/OUT] input and output value.
 * @param valLen [IN] value length.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CsrCtrl(HITLS_X509_Csr *csr, int32_t cmd, void *val, int32_t valLen);

/**
 * @ingroup pki
 * @brief Parse the csr in the buffer.When the parameter is BSL_FORMAT_PEM and
 *  BSL_FORMAT_UNKNOWN, the buff of encode needs to end with '\0'
 *
 * @param format [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1
 * @param encode [IN] The csr data
 * @param csr [OUT] The csr context after parsing
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CsrParseBuff(int32_t format, BSL_Buffer *encode, HITLS_X509_Csr **csr);

/**
 * @ingroup pki
 * @brief Parse the csr in the file
 *
 * @param format [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1
 * @param path [IN] The csr file path
 * @param csr [OUT] The csr context after parsing
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CsrParseFile(int32_t format, const char *path, HITLS_X509_Csr **csr);

/**
 * @ingroup pki
 * @brief Csr verify function
 *
 * @param csr [OUT] The csr context
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_CsrVerify(HITLS_X509_Csr *csr);

typedef enum {
    HITLS_X509_ATTR_SET_REQUESTED_EXTENSIONS = 0x01,
    HITLS_X509_ATTR_GET_REQUESTED_EXTENSIONS,
} HITLS_X509_Attr_Cmd;

/**
 * @ingroup pki
 * @brief Generic function to process attribute function
 *
 * @param attributes [IN] The attribute list
 * @param cmd [IN] HITLS_X509_AttrCmd
 * @param val                                               data type
 *        HITLS_X509_ATTR_XX_REQUESTED_EXTENSIONS         HITLS_X509_Ext
 * @param valLen  The length of value.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_AttrCtrl(BslList *attributes, int32_t cmd, void *val, int32_t valLen);

typedef struct {
    BSL_Buffer *macPwd;
    BSL_Buffer *encPwd;
} HITLS_PKCS12_PwdParam;

/**
 * While the standard imposes no constraints on password length, (pwdLen + saltLen) should be kept below 2^31
 * to avoid integer overflow in internal calculations.
*/
typedef struct {
    uint32_t saltLen;
    uint32_t itCnt;
    uint32_t macId;
    uint8_t *pwd;
    uint32_t pwdLen;
} HITLS_PKCS12_KdfParam;

typedef struct {
    void *para;
    int32_t algId;
} HITLS_PKCS12_MacParam;

/**
 * Parameters for p12 file generation.
 * Only PBES2 is supported, but different symmetric encryption algorithms can be used within certificates and keys.
 * Additionally, the encryption key must be the same for both certificates and private keys.
 */
typedef struct {
    CRYPT_EncodeParam certEncParam;
    CRYPT_EncodeParam keyEncParam;
    HITLS_PKCS12_MacParam macParam;
} HITLS_PKCS12_EncodeParam;

typedef enum {
    HITLS_PKCS12_GEN_LOCALKEYID = 0x01,          /** Gen and set localKeyId of entity-key and entity-cert in p12-ctx. */
    HITLS_PKCS12_SET_ENTITY_KEYBAG,             /** Set entity key-Bag to p12-ctx. */
    HITLS_PKCS12_SET_ENTITY_CERTBAG,            /** Set entity cert-Bag to p12-ctx. */
    HITLS_PKCS12_ADD_CERTBAG,                   /** Set other cert-Bag to p12-ctx. */
    HITLS_PKCS12_GET_ENTITY_CERT,               /** Obtain entity cert from p12-ctx. */
    HITLS_PKCS12_GET_ENTITY_KEY,                /** Obtain entity pkey from p12-ctx. */
} HITLS_PKCS12_Cmd;

/**
 * @ingroup pkcs12
 * @brief Allocate a pkcs12 struct.
 *
 * @retval HITLS_PKCS12 *
 */
HITLS_PKCS12 *HITLS_PKCS12_New(void);

/**
 * @ingroup pkcs12
 * @brief Release the pkcs12 context.
 *
 * @param csr    [IN] p12 context.
 * @retval void
 */
void HITLS_PKCS12_Free(HITLS_PKCS12 *p12);

/**
 * @ingroup pkcs12
 * @brief Allocate a bag struct, which could store a cert or key and its attributes.
 *
 * @param bagType          [IN] BagType, BSL_CID_PKCS8SHROUDEDKEYBAG/BSL_CID_CERTBAG
 * @param bagValue         [IN] bagValue, the bagValue must match the bag-type. Each Bag only holds one piece of
 *                              information -- a key or a certificate...
 * @retval HITLS_PKCS12_Bag *
 */
HITLS_PKCS12_Bag *HITLS_PKCS12_BagNew(uint32_t bagType, void *bagValue);

/**
 * @ingroup pkcs12
 * @brief Release the bag context.
 *
 * @param bag    [IN] bag context.
 * @retval void
 */
void HITLS_PKCS12_BagFree(HITLS_PKCS12_Bag *bag);

/**
 * @ingroup pkcs12
 * @brief Add attributes to a bag.
 *
 * @attention A bag can have multiple properties, but each property only contains one value.
 * @param bag          [IN] bag
 * @param type         [IN] BSL_CID_LOCALKEYID/BSL_CID_FRIENDLYNAME
 * @param attrValue    [IN] the attr buffer
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_PKCS12_BagAddAttr(HITLS_PKCS12_Bag *bag, uint32_t type, const BSL_Buffer *attrValue);

/**
 * @ingroup pkcs12
 * @brief Generic function to set a p12 context.
 *
 * @param p12    [IN] p12 context.
 * @param cmd    [IN] HITLS_PKCS12_XXX
 *        cmd                                   val type
 *        HITLS_PKCS12_GEN_LOCALKEYID           AlgId of MD
 *        HITLS_PKCS12_SET_ENTITY_KEYBAG        a pkey bag
 *        HITLS_PKCS12_SET_ENTITY_CERTBAG       a cert bag
 *        HITLS_PKCS12_ADD_CERTBAG              a cert bag
 *        HITLS_PKCS12_GET_ENTITY_CERT          HITLS_X509_Cert**
 *        HITLS_PKCS12_GET_ENTITY_KEY           CRYPT_EAL_PkeyCtx**
 * @param val    [IN/OUT] input and output value
 * @param valLen [In] value length
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_PKCS12_Ctrl(HITLS_PKCS12 *p12, int32_t cmd, void *val, int32_t valLen);

/**
 * @ingroup pkcs12
 * @brief pkcs12 parse
 * @par Description: parse p12 buffer, and set the p12 struct. When the parameter is
 *  BSL_FORMAT_PEM and BSL_FORMAT_UNKNOWN, the buff of encode needs to end with '\0'
 *
 * @attention Only support to parse p12 buffer in key-integrity and key-privacy protection mode.
 * @param format         [IN] Decoding format: BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param encode         [IN] encode data
 * @param pwdParam       [IN] include MAC-pwd, enc-pwd, they can be different.
 * @param p12            [OUT] the p12 struct.
 * @param needMacVerify  [IN] true, need verify mac; false, skip mac check.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_PKCS12_ParseBuff(int32_t format, BSL_Buffer *encode, const HITLS_PKCS12_PwdParam *pwdParam,
    HITLS_PKCS12 **p12, bool needMacVerify);

/**
 * @ingroup pkcs12
 * @par Description: parse p12 file, and set the p12 struct.
 *
 * @attention Only support to parse p12 files in key-integrity and key-privacy protection mode.
 * @param format         [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1
 * @param path           [IN] p12 file path.
 * @param pwdParam       [IN] include MAC-pwd, enc-pwd, they can be different.
 * @param p12            [OUT] the p12 struct.
 * @param needMacVerify  [IN] true, need verify mac; false, skip mac check.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_PKCS12_ParseFile(int32_t format, const char *path, const HITLS_PKCS12_PwdParam *pwdParam,
    HITLS_PKCS12 **p12, bool needMacVerify);

/**
 * @ingroup pkcs12
 * @brief pkcs12 gen
 * @par Description: gen p12 buffer.
 *
 * @attention Generate a p12 buffer based on the existing information.
 * @param format          [IN] Encoding format: BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param p12             [IN] p12 struct, including entityCert, CA-cert, prvkey, and so on.
 * @param encodeParam     [IN] encode data
 * @param isNeedMac       [IN] Identifies whether macData is required.
 * @param encode          [OUT] result.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_PKCS12_GenBuff(int32_t format, HITLS_PKCS12 *p12, const HITLS_PKCS12_EncodeParam *encodeParam,
    bool isNeedMac, BSL_Buffer *encode);

/**
 * @ingroup pkcs12
 * @par Description: Generate p12 to store in file
 *
 * @attention Generate a .p12 file based on the existing information.
 * @param format          [IN] Encoding format: BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param p12             [IN] p12 struct, including entityCert, CA-cert, prvkey, and so on.
 * @param encodeParam     [IN] encode data
 * @param isNeedMac       [IN] Identifies whether macData is required.
 * @param path            [IN] The path of the generated p12-file.
 * @retval #HITLS_X509_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_PKCS12_GenFile(int32_t format, HITLS_PKCS12 *p12, const HITLS_PKCS12_EncodeParam *encodeParam,
    bool isNeedMac, const char *path);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_H

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

#ifndef HITLS_PKI_TYPES_H
#define HITLS_PKI_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include "bsl_obj.h"
#include "bsl_types.h"
#include "bsl_list.h"
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void HITLS_PKI_LibCtx;

#define HITLS_X509_List BslList

#define HITLS_X509_VERSION_1 0
#define HITLS_X509_VERSION_2 1
#define HITLS_X509_VERSION_3 2

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
    HITLS_X509_GET_SUBJECT_DN_STR,     /** Get the subject distinguished name as a formatted string */
    HITLS_X509_GET_ISSUER_DN_STR,      /** Get the issuer distinguished name as a formatted string */
    HITLS_X509_GET_SERIALNUM_STR,      /** Get the serial number as a string */
    HITLS_X509_GET_BEFORE_TIME_STR,    /** Get the validity start time as a string */
    HITLS_X509_GET_AFTER_TIME_STR,     /** Get the validity end time as a string */
    HITLS_X509_GET_SUBJECT_DN,         /** Get the list of subject distinguished name components.
                                           Note: The list is read-only and should not be modified. */
    HITLS_X509_GET_ISSUER_DN,          /** Get the list of issuer distinguished name components.
                                           Note: The list is read-only and should not be modified. */
    HITLS_X509_GET_VERSION,            /** Get the version from cert or crl. */
    HITLS_X509_GET_REVOKELIST,         /** Get the certificate revoke list from the crl. */
    HITLS_X509_GET_SERIALNUM,          /** Get the serial number of the cert. */
    HITLS_X509_GET_BEFORE_TIME,        /** Get the validity start time */
    HITLS_X509_GET_AFTER_TIME,         /** Get the validity end time */
    HITLS_X509_GET_SIGN_MDALG,         /** Get the hash algorithm of signature algorithm used to sign the cert/ */

    HITLS_X509_SET_VERSION = 0x0200,   /** Set the version for the cert. */
    HITLS_X509_SET_SERIALNUM,          /** Set the serial number for the cert, the length range is 1 to 20. */
    HITLS_X509_SET_BEFORE_TIME,        /** Set the before time for the cert. */
    HITLS_X509_SET_AFTER_TIME,         /** Set the after time for the cert. */
    HITLS_X509_SET_PUBKEY,             /** Set the public key for the cert/csr. */
    HITLS_X509_SET_SUBJECT_DN,         /** Set the subject name list. */
    HITLS_X509_SET_ISSUER_DN,          /** Set the issuer name list. */
    HITLS_X509_SET_CSR_EXT,            /** Replace the cert's ext with csr's */
    HITLS_X509_ADD_SUBJECT_NAME,       /** Add the subject name for the cert/csr. */
    HITLS_X509_CRL_ADD_REVOKED_CERT,   /** Add the revoke cert to crl. */

    HITLS_X509_EXT_SET_SKI = 0x0400,            /** Set the subject key identifier extension. */
    HITLS_X509_EXT_SET_AKI,                     /** Set the authority key identifier extension. */
    HITLS_X509_EXT_SET_KUSAGE,                  /** Set the key usage extension. */
    HITLS_X509_EXT_SET_SAN,                     /** Set the subject alternative name extension. */
    HITLS_X509_EXT_SET_BCONS,                   /** Set the basic constraints extension. */
    HITLS_X509_EXT_SET_EXKUSAGE,                /** Set the extended key usage extension. */
    HITLS_X509_EXT_SET_CRLNUMBER,               /** Set the crlnumber extension. */
    HITLS_X509_EXT_SET_GENERIC,                 /** Set a generic extension by OID.
                                                    Note: Only supported for custom extensions. */

    HITLS_X509_EXT_GET_SKI = 0x0500,            /** Get Subject Key Identifier from extensions.
                                                    Note: Kid is a shallow copy. */
    HITLS_X509_EXT_GET_CRLNUMBER,               /** get the crlnumber form the crl. */
    HITLS_X509_EXT_GET_AKI,                     /** get the Authority Key Identifier form the crl/cert/csr. */
    HITLS_X509_EXT_GET_KUSAGE,                  /** get the key usage form the crl/cert/csr.
                                                    Note: If key usage is not set, return 0xffff. */
    HITLS_X509_EXT_GET_BCONS,                   /** Not supported yet. */
    HITLS_X509_EXT_GET_SAN,                     /** Not supported yet. */
    HITLS_X509_EXT_GET_GENERIC,                 /** Get a generic extension by OID.
                                                    Note: Only supported for custom extensions. */

    HITLS_X509_EXT_CHECK_SKI = 0x0600,          /** Check if ski is exists. */

    HITLS_X509_CSR_GET_ATTRIBUTES = 0x0700,     /** Get the attributes from the csr. */

    HITLS_X509_SET_VFY_SM2_USER_ID = 0x800,             /** Set sm2 user Id when verify cert/csr/crl. */
} HITLS_X509_Cmd;

typedef enum {
    HITLS_X509_ATTR_SET_REQUESTED_EXTENSIONS = 0x0100,
    HITLS_X509_ATTR_GET_REQUESTED_EXTENSIONS = 0x0200,
} HITLS_X509_AttrCmd;

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
 * Subject Alternative Name
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
    int32_t algId;    /**< Algorithm identifier */
    union {
        CRYPT_RSA_PssPara rsaPss;       /**< RSA PSS padding parameters */
        BSL_Buffer sm2UserId;
    };
} HITLS_X509_SignAlgParam;

/**
 * Crl number
 */
typedef struct {
    bool critical;        // Default to false.
    BSL_Buffer crlNumber; // crlNumber
} HITLS_X509_ExtCrlNumber;

/**
 * Generic extension for setting/getting arbitrary extensions by OID
 *
 * For SET operation (HITLS_X509_EXT_SET_GENERIC):
 *   - oid: Input, DER-encoded OID buffer (can be converted from dot-notation using BSL_OBJ_GetOidFromNumericString)
 *   - value: Input, DER-encoded extension value
 *   - critical: Input, critical flag
 *
 * For GET operation (HITLS_X509_EXT_GET_GENERIC):
 *   - oid: Input, DER-encoded OID buffer (used to search for the extension)
 *   - value: Must be NULL on input (function will allocate memory and fill it
 *            with DER-encoded extension value)
 *   - critical: Output, critical flag
 *
 * Note: After GET operation, caller must free the memory allocated for value
 *       field using the appropriate buffer free function.
 */
typedef struct {
    bool critical;      /**< Critical flag of the extension */
    BSL_Buffer oid;     /**< DER-encoded OID buffer */
    BSL_Buffer value;   /**< DER-encoded extension value */
} HITLS_X509_ExtGeneric;

typedef struct {
    bool critical;
    BSL_TIME time;
} HITLS_X509_RevokeExtTime;

typedef enum {
    HITLS_X509_CRL_SET_REVOKED_SERIALNUM = 0,       /** Set the revoked serial number. */
    HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME,         /** Set the revoke time. */
    HITLS_X509_CRL_SET_REVOKED_INVALID_TIME,        /** Set the invalid time extension. */
    HITLS_X509_CRL_SET_REVOKED_REASON,              /** Set the revoke reason extension. */
    HITLS_X509_CRL_SET_REVOKED_CERTISSUER,          /** Set the revoke cert issuer extension. */

    HITLS_X509_CRL_GET_REVOKED_SERIALNUM = 0x0100,  /** Get the revoked serial number. */
    HITLS_X509_CRL_GET_REVOKED_REVOKE_TIME,         /** Get the revoke time. */
    HITLS_X509_CRL_GET_REVOKED_INVALID_TIME,        /** Get the invalid time extension. */
    HITLS_X509_CRL_GET_REVOKED_REASON,              /** Get the revoke reason extension. */
    HITLS_X509_CRL_GET_REVOKED_CERTISSUER,          /** Get the revoke cert issuer extension. */
} HITLS_X509_RevokeCmd;

typedef enum {
    HITLS_X509_REVOKED_REASON_UNSPECIFIED = 0,         /** CRLReason: Unspecified. */
    HITLS_X509_REVOKED_REASON_KEY_COMPROMISE,          /** CRLReason: Key compromise. */
    HITLS_X509_REVOKED_REASON_CA_COMPROMISE,           /** CRLReason: CA compromise. */
    HITLS_X509_REVOKED_REASON_AFFILIATION_CHANGED,     /** CRLReason: Affiliation changed. */
    HITLS_X509_REVOKED_REASON_SUPERSEDED,              /** CRLReason: Superseded. */
    HITLS_X509_REVOKED_REASON_CESSATION_OF_OPERATION,  /** CRLReason: Cessation of operation. */
    HITLS_X509_REVOKED_REASON_CERTIFICATE_HOLD,        /** CRLReason: Certificate hold. */
    HITLS_X509_REVOKED_REASON_REMOVE_FROM_CRL = 8,     /** CRLReason: Remove from CRL. */
    HITLS_X509_REVOKED_REASON_PRIVILEGE_WITHDRAWN,     /** CRLReason: Privilege withdrawn. */
    HITLS_X509_REVOKED_REASON_AA_COMPROMISE,           /** CRLReason: aA compromise. */
} HITLS_X509_RevokeReason;

typedef struct {
    bool critical;
    int32_t reason;
} HITLS_X509_RevokeExtReason;

typedef struct {
    bool critical;
    BslList *issuerName; // List of HITLS_X509_GeneralName
} HITLS_X509_RevokeExtCertIssuer;

typedef enum {
    HITLS_X509_EXT_TYPE_CSR,
} HITLS_X509_ExtType;

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
    HITLS_X509_STORECTX_CLEAR_CRL,
    HITLS_X509_STORECTX_REF_UP,
    HITLS_X509_STORECTX_SET_VFY_SM2_USERID,
    HITLS_X509_STORECTX_ADD_CA_PATH,       /**< Add additional CA path for on-demand loading */
    HITLS_X509_STORECTX_MAX
} HITLS_X509_StoreCtxCmd;

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

typedef enum {
    HITLS_PKCS12_BAG_ADD_ATTR,                  /** Add attribute to safeBag. */
} HITLS_PKCS12_BagCmd;
#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_TYPES_H

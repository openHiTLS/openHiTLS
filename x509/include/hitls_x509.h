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

#ifndef HITLS_X509_H
#define HITLS_X509_H

#include <stdint.h>
#include <stdbool.h>
#include "bsl_list.h"
#include "bsl_type.h"
#include "bsl_uio.h"
#include "bsl_obj.h"
#include "crypt_algid.h"
#include "crypt_eal_encode.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HITLS_X509_List BslList

typedef struct _HITLS_X509_Cert HITLS_X509_Cert;

typedef struct _HITLS_X509_Ext HITLS_X509_Ext;

typedef struct _HITLS_X509_Crl HITLS_X509_Crl;

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
    HITLS_X509_REF_UP = 0,

    HITLS_X509_GET_ENCODELEN = 0x0100, /** Get the length of the ASN.1 DER encoded cert/csr. */
    HITLS_X509_GET_ENCODE,             /** Get the ASN.1 DER encoded cert/csr. */
    HITLS_X509_GET_PUBKEY,             /** Get the public key for the cert/csr */
    HITLS_X509_GET_SIGNALG,            /** Get the signature algorithm for the cert. */
    HITLS_X509_GET_SUBJECT_DNNAME_STR, /** Get the string of subject name. */
    HITLS_X509_GET_ISSUER_DNNAME_STR,  /** Get the string of issuer name. */
    HITLS_X509_GET_SERIALNUM,          /** Get the string of serial number. */
    HITLS_X509_GET_BEFORE_TIME,        /** Get the string of before time. */
    HITLS_X509_GET_AFTER_TIME,         /** Get the string of after time. */
    HITLS_X509_GET_SUBJECT_DNNAME,     /** Get the subject name list. */
    HITLS_X509_GET_ISSUER_DNNAME,      /** Get the issuer name list. */
    HITLS_X509_GET_EXT,                /** Get the extension from cert. */

    HITLS_X509_SET_VERSION = 0x0200,   /** Set the version for the cert. */
    HITLS_X509_SET_SERIALNUM,          /** Set the serial number for the cert, the length range is 1 to 20. */
    HITLS_X509_SET_BEFORE_TIME,        /** Set the before time for the cert. */
    HITLS_X509_SET_AFTER_TIME,         /** Set the after time for the cert. */
    HITLS_X509_SET_PRIVKEY,            /** Set the private key for signing the cert/csr. */
    HITLS_X509_SET_SIGN_MD_ID,         /** Set the hash algorithm for signing the cert/csr。 */
    HITLS_X509_SET_SIGN_RSA_PADDING,   /** Set the padding mode(CRYPT_PKEY_EMSA_PKCSV15 or CRYPT_PKEY_EMSA_PSS)
                                           for the RSA signature algorithm.
                                           Before that, you need to use cmd HITLS_X509_SET_PRIVKEY
                                           to set the private key.
                                           If the padding mode is already set, setting different mode will fail. */
    HITLS_X509_SET_SIGN_RSA_PSS_PARAM, /** Set the parameters for the RSA-PSS signature algorithm.
                                           Before that, you need to use cmd HITLS_X509_SET_PRIVKEY
                                           to set the private key.
                                           If the padding mode is not rsa pss, it will fail.
                                           If the parameter has already been set in the private key, this setting
                                           can be omitted, or the same parameter must be set, except for saltLen */
    HITLS_X509_SET_PUBKEY,             /** Set the public key for the cert/csr. */
    HITLS_X509_SET_SUBJECT_DNNAME,     /** Set the subject name list. */
    HITLS_X509_SET_ISSUER_DNNAME,      /** Set the issuer name list. */
    HITLS_X509_SET_CSR_EXT,            /** Replace the cert's ext with csr's */
    HITLS_X509_ADD_SUBJECT_NAME,       /** Add the subject name for the cert/csr. */

    HITLS_X509_EXT_KU_KEYENC = 0x0300,
    HITLS_X509_EXT_KU_DIGITALSIGN,
    HITLS_X509_EXT_KU_CERTSIGN,
    HITLS_X509_EXT_KU_KEYAGREEMENT,

    HITLS_X509_EXT_SET_SKI = 0x0400,
    HITLS_X509_EXT_SET_AKI,
    HITLS_X509_EXT_SET_KUSAGE,
    HITLS_X509_EXT_SET_SAN,
    HITLS_X509_EXT_SET_BCONS,
    HITLS_X509_EXT_SET_EXKUSAGE,

    HITLS_X509_EXT_GET_SKI = 0x0500,            /** Get aki from extensions.
                                                    Note: Kid is a shallow copy. */

    HITLS_X509_EXT_CHECK_SKI = 0x0600,          /** Check if ski is exists. */

    HITLS_X509_CSR_GET_ATTRIBUTES = 0x0700,     /** Get the attributes from the csr. */

    HITLS_X509_ATTR_SET_REQUESTED_EXTENSIONS = 0x0800,
    HITLS_X509_ATTR_GET_REQUESTED_EXTENSIONS,

    HITLS_PKCS12_GEN_LOCALKEYID = 0x0900,       /** Gen and set localKeyId in p12-ctx. */
    HITLS_PKCS12_SET_ENTITY_KEYBAG,             /** Set entity key-Bag to p12-ctx. */
    HITLS_PKCS12_SET_ENTITY_CERTBAG,            /** Set entity cert-Bag to p12-ctx. */
    HITLS_PKCS12_ADD_CERTBAG,                   /** Set other cert-Bag to p12-ctx. */
    HITLS_PKCS12_GET_ENTITY_CERT,               /** Obtain entity cert from p12-ctx. */
    HITLS_PKCS12_GET_ENTITY_KEY,                /** Obtain entity pkey from p12-ctx. */
} HITLS_X509_Cmd;

typedef enum {
    HITLS_X509_GN_EMAIL,  // rfc822Name                [1] IA5String
    HITLS_X509_GN_DNS,    // dNSName                   [2] IA5String
    HITLS_X509_GN_DNNAME, // directoryName             [4] Name
    HITLS_X509_GN_URI,    // uniformResourceIdentifier [6] IA5String
    HITLS_X509_GN_IP,     // iPAddress                 [7] Octet String

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
 * @ingroup x509
 * @brief Allocate a certificate.
 *
 * @retval HITLS_X509_Cert *
 */
HITLS_X509_Cert *HITLS_X509_CertNew(void);

/**
 * @ingroup x509
 * @brief Unallocate a certificate.
 *
 * @param cert [IN] The certificate.
 */
void HITLS_X509_CertFree(HITLS_X509_Cert *cert);

/**
 * @ingroup x509
 * @brief Duplicate a certificate.
 *
 * @param src  [IN] Source certificate.
 * @param dest [OUT] Destination certificate.
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CertDup(HITLS_X509_Cert *src, HITLS_X509_Cert **dest);

/**
 * @ingroup x509
 * @brief Compute the digest of the certificate.
 *
 * @param cert  [IN] The certificate.
 * @param mdId [IN] Digest algorithm.
 * @param data [IN/OUT] The digest result.
 * @param dataLen [IN/OUT] The length of the digest.
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CertDigest(HITLS_X509_Cert *cert, CRYPT_MD_AlgId mdId, uint8_t *data, uint32_t *dataLen);

/**
 * @ingroup x509
 * @brief Generic function to process certificate.
 *
 * @param cert   [IN] The certificate.
 * @param cmd    [IN] HITLS_X509_Cmd
 * @param val    [IN/OUT] input and output value
 * @param valLen [In] value length
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CertCtrl(HITLS_X509_Cert *cert, int32_t cmd, void *val, int32_t valLen);

/**
 * @ingroup x509
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
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_ExtCtrl(HITLS_X509_Ext *ext, int32_t cmd, void *val, int32_t valLen);

/**
 * @ingroup x509
 * @brief Parse the CERT in the buffer.
 * @par Description: Parse the CERT in the buffer.
 *  If the encoding is successful, the memory for the crl is requested from within the function,
 *  and the user needs to free it after using it.
 * @attention None
 * @param format [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param encode [IN] CERT data.
 * @param cert   [OUT] CERT after parse.
 * @return #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CertParseBuff(int32_t format, BSL_Buffer *encode, HITLS_X509_Cert **cert);

/**
 * @ingroup x509
 * @brief Parse the CERT in the file.
 * @par Description: Parse the CERT in the file.
 *  If the encoding is successful, the memory for the crl is requested from within the function,
 *  and the user needs to free it after using it.
 * @attention None
 * @param format [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param path   [IN] CERT file path.
 * @param cert   [OUT] CERT after parse.
 * @return #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CertParseFile(int32_t format, const char *path, HITLS_X509_Cert **cert);

/**
 * @ingroup x509
 * @brief Parse the CERTs in the file.
 * @par Description: Parse multiple CERTs in the file.
 *  If the encoding is successful, the memory for the certlist is requested from within the function,
 *  and the user needs to free it after using it.
 * @attention None
 * @param format  [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param path    [IN] CRL file path.
 * @param crllist [OUT] CRL list after parse.
 * @return #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CertMulParseFile(int32_t format, const char *path, HITLS_X509_List **certlist);

/**
 * @ingroup x509
 * @brief Generate a encoded certificate.
 * @attention You need to first call interfaces HITLS_X509_CertCtrl and HITLS_X509_ExtCtrl to set
 *            certificate information.
 *
 * @param format [IN] Encoding format: BSL_FORMAT_ASN1 or BSL_FORMAT_PEM
 * @param cert   [IN] cert
 * @param buff   [OUT] encode result
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CertGenBuff(int32_t format, HITLS_X509_Cert *cert, BSL_Buffer *buff);

/**
 * @ingroup x509
 * @brief Generate a certificate file.
 * @attention You need to first call interfaces HITLS_X509_CertCtrl and HITLS_X509_ExtCtrl to set
 *            certificate information.
 *
 * @param format [IN] Encoding format: BSL_FORMAT_ASN1 or BSL_FORMAT_PEM
 * @param cert   [IN] cert
 * @param path   [IN] file path
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CertGenFile(int32_t format, HITLS_X509_Cert *cert, const char *path);

/**
 * @ingroup x509
 * @brief Add a distinguish name array to list.
 *
 * @param list [IN] The name list
 * @param dnNames   [IN] dnName array
 * @param size   [IN] The count of dnName array
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_AddDnName(BslList *list, HITLS_X509_DN *dnNames, int32_t size);

typedef enum {
    HITLS_X509_CRL_REF_UP,
} HITLS_X509_CrlCmd;

/**
 * @ingroup x509
 * @brief Release the CRL.
 * @par Description: Release the memory of the CRL.
 *
 * @attention None
 * @param crl           [IN] CRL after parse.
 * @return Error code
 */
void HITLS_X509_CrlFree(HITLS_X509_Crl *crl);

/**
 * @ingroup x509
 * @brief Crl setting interface.
 * @par Description: Set CRL information.
 *         parameter           data type         Length(len):number of data bytes
 * HITLS_X509_CRL_REF_UP       int           The length is sizeof(int), which is used to increase the
 *                                            number of CRL references.
 * @attention None
 * @param crl            [IN] CRL data
 * @param cmd            [IN] Set type.
 * @param val           [OUT] Set data.
 * @param valLen         [IN] The length of val.
 * @return Error code
 */
int32_t HITLS_X509_CrlCtrl(HITLS_X509_Crl *crl, int32_t cmd, void *val, int32_t valLen);

/**
 * @ingroup x509
 * @brief Parse the CRL in the buffer.
 * @par Description: Parse the CRL in the buffer.
 *  If the encoding is successful, the memory for the crl is requested from within the function,
 *  and the user needs to free it after using it.
 * @attention None
 * @param format         [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1/
 *                            BSL_FORMAT_UNKNOWN.
 * @param encode         [IN] CRL data.
 * @param crl           [OUT] CRL after parse.
 * @return Error code
 */
int32_t HITLS_X509_CrlParseBuff(int32_t format, BSL_Buffer *encode, HITLS_X509_Crl **crl);

/**
 * @ingroup x509
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
 * @ingroup x509
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
 * @ingroup x509
 * @brief Generate a CRL and encode it.
 * @par Description: This function encodes the CRL into the specified format.
 *  If the encoding is successful, the memory for the encode data is requested from within the function,
 *  and the user needs to free it after using it.
 * @attention None
 * @param format        [IN] Encoding format: BSL_FORMAT_PEM or BSL_FORMAT_ASN1.
 * @param crl           [IN] CRL raw data.
 * @param encode       [OUT] Encode data.
 * @param encodeLen    [OUT] Number of encoded bytes excluding the terminator.
 * @return Error code
 */
int32_t HITLS_X509_CrlGenBuff(int32_t format, HITLS_X509_Crl *crl, uint8_t **encode, uint32_t *encodeLen);

/**
 * @ingroup x509
 * @brief Generate a CRL and encode it to specific file.
 * @par Description: This function encodes the CRL into the specified format.
 *  If the encoding is successful, the memory for the encode data is requested from within the function,
 *  and the user needs to free it after using it.
 * @attention None
 * @param format         [IN] Encoding format: BSL_FORMAT_PEM or BSL_FORMAT_ASN1.
 * @param crl            [IN] CRL raw data.
 * @param path          [OUT] Encoding data file path.
 * @return Error code
 */
int32_t HITLS_X509_CrlGenFile(int32_t format, HITLS_X509_Crl *crl, const char *path);

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
 * @ingroup x509
 * @brief Allocate a StoreCtx.
 *
 * @retval HITLS_X509_StoreCtx *
 */
HITLS_X509_StoreCtx *HITLS_X509_StoreCtxNew(void);

/**
 * @ingroup x509
 * @brief Release the StoreCtx.
 *
 * @param storeCtx    [IN] StoreCtx.
 * @retval void
 */
void HITLS_X509_StoreCtxFree(HITLS_X509_StoreCtx *storeCtx);

/**
 * @ingroup x509
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
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_StoreCtxCtrl(HITLS_X509_StoreCtx *storeCtx, int32_t cmd, void *val, int32_t valLen);

/**
 * @ingroup x509
 * @brief Certificate chain verify function.
 *
 * @param storeCtx [IN] StoreCtx.
 * @param chain [IN] certificate chain.
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CertVerify(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain);

/**
 * @ingroup x509
 * @brief Certificate chain build function.
 *
 * @param storeCtx [IN] StoreCtx.
 * @param cert [IN] certificate.
 * @param chain [OUT] certificate chain.
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CertChainBuild(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert, HITLS_X509_List **chain);

/**
 * @ingroup x509
 * @brief Certificate chain build with root cert function.
 *
 * @param storeCtx [IN] StoreCtx.
 * @param cert [IN] certificate.
 * @param chain [OUT] certificate chain.
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CertChainBuildWithRoot(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *cert,
    HITLS_X509_List **chain);

typedef struct _HITLS_X509_Attr {
    BslCid cid;
    void *value;
} HITLS_X509_Attr;

/**
 * @ingroup x509
 * @brief Allocate a pkcs10 csr.
 *
 * @retval HITLS_X509_Csr *
 */
HITLS_X509_Csr *HITLS_X509_CsrNew(void);

/**
 * @ingroup x509
 * @brief Release the pkcs10 csr.
 *
 * @param csr    [IN] CSR context.
 * @retval void
 */
void HITLS_X509_CsrFree(HITLS_X509_Csr *csr);

/**
 * @ingroup x509
 * @brief Generate csr to store in buffer
 *
 * @param csr    [IN] The csr context
 * @param format [IN] The format of the generated csr.
 * @param buff   [OUT] The buffer of the generated csr.
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CsrGenBuff(HITLS_X509_Csr *csr, int32_t format, BSL_Buffer *buff);

/**
 * @ingroup x509
 * @brief Generate csr to store in file
 *
 * @param csr    [IN] The csr context
 * @param format [IN] The format of the generated csr.
 * @param path   [IN] The path of the generated csr.
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CsrGenFile(HITLS_X509_Csr *csr, int32_t format, const char *path);

/**
 * @ingroup x509
 * @brief Generic function to process csr function
 *
 * @param csr [IN] The csr context
 * @param cmd [IN] HITLS_X509_Cmd
 * @param val [IN/OUT] input and output value.
 * @param valLen [IN] value length.
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CsrCtrl(HITLS_X509_Csr *csr, int32_t cmd, void *val, int32_t valLen);

/**
 * @ingroup x509
 * @brief Parse the csr in the buffer
 *
 * @param format [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1
 * @param encode [IN] The csr data
 * @param csr [OUT] The csr context after parsing
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CsrParseBuff(int32_t format, BSL_Buffer *encode, HITLS_X509_Csr **csr);

/**
 * @ingroup x509
 * @brief Parse the csr in the file
 *
 * @param format [IN] Encoding format: BSL_FORMAT_PEM/BSL_FORMAT_ASN1
 * @param path [IN] The csr file path
 * @param csr [OUT] The csr context after parsing
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CsrParseFile(int32_t format, const char *path, HITLS_X509_Csr **csr);

/**
 * @ingroup x509
 * @brief Csr verify function
 *
 * @param csr [OUT] The csr context
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_CsrVerify(HITLS_X509_Csr *csr);

/**
 * @ingroup x509
 * @brief Generic function to process attribute function
 *
 * @param attributes [IN] The attribute list
 * @param cmd [IN] HITLS_X509_AttrCmd
 * @param val                                               data type
 *        HITLS_X509_ATTR_XX_REQUESTED_EXTENSIONS         HITLS_X509_Ext
 * @param valLen  The length of value.
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_X509_AttrCtrl(BslList *attributes, int32_t cmd, void *val, int32_t valLen);

typedef struct {
    BSL_Buffer *macPwd;
    BSL_Buffer *encPwd;
} HITLS_PKCS12_PwdParam;

typedef struct {
    uint32_t saltLen;
    uint32_t itCnt;
    uint32_t macId;
    uint8_t *pwd;
    uint32_t pwdLen;
} HITLS_PKCS12_HmacParam;

typedef struct {
    CRYPT_EncodeParam certEncParam;
    CRYPT_EncodeParam keyEncParam;
    HITLS_PKCS12_HmacParam macParam;
} HITLS_PKCS12_EncodeParam;

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
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_PKCS12_BagAddAttr(HITLS_PKCS12_Bag *bag, uint32_t type, const BSL_Buffer *attrValue);

/**
 * @ingroup pkcs12
 * @brief Generic function to set a p12 context.
 *
 * @param p12    [IN] p12 context.
 * @param cmd    [IN] HITLS_PKCS12_XXX
 *        cmd                                   val type
 *        HITLS_PKCS12_GEN_LOCALKEYID           none
 *        HITLS_PKCS12_SET_ENTITY_KEYBAG        a pkey bag
 *        HITLS_PKCS12_SET_ENTITY_CERTBAG       a cert bag
 *        HITLS_PKCS12_ADD_CERTBAG              a cert bag
 *        HITLS_PKCS12_GET_ENTITY_CERT          HITLS_X509_Cert**
 *        HITLS_PKCS12_GET_ENTITY_KEY           CRYPT_EAL_PkeyCtx**
 * @param val    [IN/OUT] input and output value
 * @param valLen [In] value length
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_PKCS12_Ctrl(HITLS_PKCS12 *p12, int32_t cmd, void *val, int32_t valLen);

/**
 * @ingroup pkcs12
 * @brief pkcs12 parse
 * @par Description: parse p12 buffer, and set the p12 struct.

 * @attention Only support to parse p12 buffer in key-integrity and key-privacy protection mode.
 * @param format         [IN] Decoding format: BSL_FORMAT_ASN1/BSL_FORMAT_UNKNOWN.
 * @param encode         [IN] encode data
 * @param pwdParam       [IN] include MAC-pwd, enc-pwd, they can be different.
 * @param p12            [OUT] the p12 struct.
 * @param needMacVerify  [IN] true, need verify mac; false, skip mac check.
 * @retval #HITLS_X509_SUCCESS, success.
 *         error codes see the hitls_x509_errno.h
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
 *         error codes see the hitls_x509_errno.h
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
 *         error codes see the hitls_x509_errno.h
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
 *         error codes see the hitls_x509_errno.h
 */
int32_t HITLS_PKCS12_GenFile(int32_t format, HITLS_PKCS12 *p12, const HITLS_PKCS12_EncodeParam *encodeParam,
    bool isNeedMac, const char *path);

#ifdef __cplusplus
}
#endif

#endif // HITLS_X509_H

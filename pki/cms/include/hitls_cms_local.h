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
#include "hitls_crl_local.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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
    CRYPT_EAL_MdCTX *mdCtx; /**< Message digest context for streaming signature */
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

#define HITLS_CMS_FLAG_GEN               0x01
#define HITLS_CMS_FLAG_PARSE             0x10

/**
 * @brief SignerInfo structure
 * Reference: RFC 5652 Section 5.3
 */
typedef struct _CMS_SignerInfo {
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

#define HITLS_CMS_UNINIT                      0
#define HITLS_CMS_SIGN_INIT                   1
#define HITLS_CMS_VERIFY_INIT                 2
#define HITLS_CMS_SIGN_FINISHED               3
#define HITLS_CMS_VERIFY_FINISHED             4
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
 * @brief CMS ContentInfo structure
 * Reference: RFC 5652 Section 3
 */
typedef struct {
    int32_t contentType;   /**< Content type */
    BSL_Buffer content;   /**< Content (optional) */
} CMS_ContentInfo;

typedef struct _HITLS_CMS {
    int32_t dataType;                     /**< CMS data type */
    union {
        CMS_SignedData *signedData;
    } ctx;
} HITLS_CMS;

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

/**
 * @ingroup cms
 * @brief cms generate
 * @par Description: generate cms buffer. Now only support to generate signeddata.
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

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_CMS

#endif // HITLS_CMS_LOCAL_H

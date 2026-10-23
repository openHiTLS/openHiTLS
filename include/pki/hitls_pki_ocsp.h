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

/**
 * @defgroup hitls_pki_ocsp OCSP
 * @ingroup hitls_pki
 * @brief Online Certificate Status Protocol (RFC 6960) support.
 */

#ifndef HITLS_PKI_OCSP_H
#define HITLS_PKI_OCSP_H

#include <stdint.h>
#include <stdbool.h>
#include "bsl_obj.h"
#include "bsl_sal.h"
#include "bsl_uio.h"
#include "crypt_types.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"
#include "hitls_pki_types.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_x509.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ===== Opaque types ===== */

/**
 * @ingroup hitls_pki_ocsp
 * @brief OCSP CertID (certificate identifier for status requests).
 */
typedef struct CertId_St HITLS_OCSP_CertId;

/**
 * @ingroup hitls_pki_ocsp
 * @brief OCSP SingleRequest (one CertID per request).
 */
typedef struct SingleReq_St HITLS_OCSP_SingleReq;

/**
 * @ingroup hitls_pki_ocsp
 * @brief OCSPRequest (contains one or more SingleRequests).
 */
typedef struct Req_St HITLS_OCSP_Req;

/**
 * @ingroup hitls_pki_ocsp
 * @brief OCSP SingleResponse (status for one certificate).
 */
typedef struct SingleResp_St HITLS_OCSP_SingleResp;

/**
 * @ingroup hitls_pki_ocsp
 * @brief BasicOCSPResponse (contains one or more SingleResponses, signed by responder).
 */
typedef struct BasicResp_St HITLS_OCSP_BasicResp;

/**
 * @ingroup hitls_pki_ocsp
 * @brief OCSPResponse (outer wrapper carrying responseStatus and optional BasicOCSPResponse).
 */
typedef struct Resp_St HITLS_OCSP_Resp;

/**
 * @ingroup hitls_pki_ocsp
 * @brief OCSP response and request opaque types.
 */

/* ===== Enumerations ===== */

/**
 * @ingroup hitls_pki_ocsp
 * @brief OCSP responseStatus (RFC 6960 Section 4.2.1)
 */
typedef enum {
    HITLS_OCSP_RESP_STATUS_SUCCESSFUL = 0,
    HITLS_OCSP_RESP_STATUS_MALFORMED_REQUEST = 1,
    HITLS_OCSP_RESP_STATUS_INTERNAL_ERROR = 2,
    HITLS_OCSP_RESP_STATUS_TRY_LATER = 3,
    /* 4 is reserved by RFC 6960 */
    HITLS_OCSP_RESP_STATUS_SIG_REQUIRED = 5,
    HITLS_OCSP_RESP_STATUS_UNAUTHORIZED = 6
} HITLS_OCSP_RespStatus;

/**
 * @ingroup hitls_pki_ocsp
 * @brief certStatus CHOICE (RFC 6960 Section 4.2.1)
 */
typedef enum {
    HITLS_OCSP_CERT_STATUS_GOOD = 0,
    HITLS_OCSP_CERT_STATUS_REVOKED = 1,
    HITLS_OCSP_CERT_STATUS_UNKNOWN = 2
} HITLS_OCSP_CertStatus;

/**
 * @ingroup hitls_pki_ocsp
 * @brief Ctrl commands for HITLS_OCSP_Req
 */
typedef enum {
    HITLS_OCSP_REQ_GET_NONCE = 0x0100,
    HITLS_OCSP_REQ_ADD_SINGLEREQ = 0x0200,
    /**< Set the request nonce.
     * val = uint8_t* (raw bytes, length in valLen; data is copied).
     * If val == NULL and valLen == 0, a random nonce of 32 bytes
     * is generated automatically; if val == NULL and valLen > 0, valLen random bytes are
     * generated. Otherwise val[0,valLen) is copied as the nonce (valLen must be > 0). */
    HITLS_OCSP_REQ_SET_NONCE,
} HITLS_OCSP_ReqCmd;

/**
 * @ingroup hitls_pki_ocsp
 * @brief Ctrl commands for HITLS_OCSP_SingleResp
 */
typedef enum {
    HITLS_OCSP_SINGLERESP_GET_CERTID = 0x0100,
    HITLS_OCSP_SINGLERESP_GET_CERT_STATUS,
    HITLS_OCSP_SINGLERESP_GET_THIS_UPDATE,
    HITLS_OCSP_SINGLERESP_GET_NEXT_UPDATE,
    HITLS_OCSP_SINGLERESP_GET_REVOCATION_TIME,
    HITLS_OCSP_SINGLERESP_GET_REVOCATION_REASON,
    HITLS_OCSP_SINGLERESP_SET_NEXT_UPDATE = 0x0200,
    HITLS_OCSP_SINGLERESP_SET_REVOCATION_TIME,
    HITLS_OCSP_SINGLERESP_SET_REVOCATION_REASON,
} HITLS_OCSP_SingleRespCmd;

/**
 * @ingroup hitls_pki_ocsp
 * @brief Ctrl commands for HITLS_OCSP_BasicResp
 */
typedef enum {
    HITLS_OCSP_BASICRESP_GET_PRODUCED_AT = 0x0100,
    HITLS_OCSP_BASICRESP_GET_NONCE,
    HITLS_OCSP_BASICRESP_ADD_RESP = 0x0200,
    HITLS_OCSP_BASICRESP_SET_NONCE,
} HITLS_OCSP_BasicRespCmd;

/**
 * @ingroup hitls_pki_ocsp
 * @brief Ctrl commands for HITLS_OCSP_Resp
 */
typedef enum {
    HITLS_OCSP_RESP_GET_STATUS = 0x0100,
    HITLS_OCSP_RESP_GET_BASIC,
} HITLS_OCSP_RespCmd;

/* ===== Flags and macros ===== */

/**
 * @ingroup hitls_pki_ocsp
 * @brief Signature control flags passed to HITLS_OCSP_BasicRespSign and HITLS_OCSP_ReqSign.
 */
typedef uint32_t HITLS_OCSP_SignFlag;

#define HITLS_OCSP_SIGN_NOCERTS (1U << 0) /**< Do not embed the signer certificate / cert chain into the message. */
#define HITLS_OCSP_SIGN_RESPID_BYKEY (1U << 1) /**< Use ResponderID byKey (SHA-1 of the signer public key); default is byName. */

/**
 * @ingroup hitls_pki_ocsp
 * @brief Verification sub-item control flags for HITLS_OCSP_BasicRespVerify.
 */
typedef uint32_t HITLS_OCSP_VfyFlag;

#define HITLS_OCSP_VFY_TRUSTOTHER \
    (1U << 0) /**< Treat a signer certificate found in the external certs list as a
                                                 locally configured OCSP signing authority (RFC 6960 §4.2.2.2 condition 1):
                                                 skip chain/path validation and the issuer/delegation authorization check;
                                                 the response signature is still verified. */
#define HITLS_OCSP_VFY_NOINTERN (1U << 1)   /**< Do not look for the signer among embedded certs. */

/**
 * @ingroup hitls_pki_ocsp
 * @brief Nonce comparison result type.
 */
typedef int32_t HITLS_OCSP_NonceStatus;

#define HITLS_OCSP_NONCE_NOT_EQUAL 0   /**< Both present but different (failure). */
#define HITLS_OCSP_NONCE_EQUAL 1       /**< Both present and equal. */
#define HITLS_OCSP_NONCE_BOTH_ABSENT 2 /**< Both absent. */
#define HITLS_OCSP_NONCE_RESP_ONLY 3   /**< Only the response carries a Nonce (abnormal). */
#define HITLS_OCSP_NONCE_REQ_ONLY 4     /**< Only the request carries a Nonce (acceptable). */

/* ===== CertID ===== */

/**
 * @ingroup hitls_pki_ocsp
 * @brief CertID constructor from certificate and issuer certificate.
 *
 * @param mdCtx  [IN] Hash context created by the caller (may carry a provider).
 *                Currently, only SHA1 and SHA256 are supported.
 * @param cert   [IN] Certificate to be checked (serialNumber is extracted).
 * @param issuer [IN] Issuer certificate (issuerNameHash + issuerKeyHash are extracted).
 *
 * @retval HITLS_OCSP_CertId * on success, NULL on failure.
 */
HITLS_OCSP_CertId *HITLS_OCSP_CertIdNewFromCert(CRYPT_EAL_MdCtx *mdCtx, const HITLS_X509_Cert *cert,
                                                 const HITLS_X509_Cert *issuer);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Compare two CertIDs (all four fields: hashAlg, issuerNameHash, issuerKeyHash, serialNumber).
 *
 * @param a [IN] First CertId, may be NULL.
 * @param b [IN] Second CertId, may be NULL.
 *
 * @retval 0 if both are non-NULL and all fields match, non-zero otherwise.
 */
int32_t HITLS_OCSP_CertIdCmp(const HITLS_OCSP_CertId *a, const HITLS_OCSP_CertId *b);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Free a CertID. NULL safe.
 *
 * @param certId [IN] CertID context to free.
 *
 * @retval void
 */
void HITLS_OCSP_CertIdFree(HITLS_OCSP_CertId *certId);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Get fields of a CertId. Each OUT parameter is optional (pass NULL to skip).
 *        Returned BSL_Buffer fields are shallow references to internal data (not copies);
 *        they remain valid until certId is freed.
 *
 * @param certId         [IN]  The CertId to query.
 * @param hashAlg        [OUT] Hash algorithm (SHA-1/SHA-256), may be NULL.
 * @param issuerNameHash [OUT] Hash of the issuer DN, may be NULL.
 * @param issuerKeyHash  [OUT] Hash of the issuer public key, may be NULL.
 * @param serialNumber   [OUT] Certificate serial number (raw INTEGER bytes), may be NULL.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 * @note Caller must NOT free the returned BSL_Buffer.data pointers.
 */
int32_t HITLS_OCSP_CertIdGetInfo(const HITLS_OCSP_CertId *certId, CRYPT_MD_AlgId *hashAlg,
                                 BSL_Buffer *issuerNameHash, BSL_Buffer *issuerKeyHash,
                                 BSL_Buffer *serialNumber);

/* ===== Request: SingleReq ===== */

/**
 * @ingroup hitls_pki_ocsp
 * @brief Create a SingleRequest. Ownership of certId is transferred to the SingleReq on
 *        success only. On failure (NULL or OOM) certId is NOT consumed and the caller
 *        still owns it and must free it with #HITLS_OCSP_CertIdFree.
 *
 * @param certId [IN] CertId to attach (ownership transferred on success). Must not be NULL.
 *
 * @retval HITLS_OCSP_SingleReq * on success, NULL on failure (certId is NULL or OOM).
 */
HITLS_OCSP_SingleReq *HITLS_OCSP_SingleReqNew(HITLS_OCSP_CertId *certId);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Free a SingleRequest and its associated CertId. NULL safe.
 *
 * @param singleReq [IN] SingleRequest context to free.
 *
 * @retval void
 */
void HITLS_OCSP_SingleReqFree(HITLS_OCSP_SingleReq *singleReq);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Get the CertID from a SingleRequest (shallow reference).
 *
 * @param singleReq [IN]  SingleRequest context.
 * @param certId    [OUT] Pointer to receive the CertId. Must not be NULL.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 * @note The returned certId is owned by the SingleReq; caller must NOT free it.
 *       It remains valid until singleReq is freed.
 */
int32_t HITLS_OCSP_SingleReqGetCertId(const HITLS_OCSP_SingleReq *singleReq, HITLS_OCSP_CertId **certId);

/* ===== Request: Req ===== */

/**
 * @ingroup hitls_pki_ocsp
 * @brief Create an empty OCSPRequest.
 *
 * @retval HITLS_OCSP_Req * on success, NULL on failure (OOM).
 */
HITLS_OCSP_Req *HITLS_OCSP_ReqNew(void);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Free an OCSPRequest. NULL safe.
 *
 * @param req [IN] OCSPRequest context to free.
 *
 * @retval void
 */
void HITLS_OCSP_ReqFree(HITLS_OCSP_Req *req);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Encode an OCSPRequest into DER.
 *
 * @param format [IN] Encoding format: BSL_FORMAT_ASN1.
 * @param req    [IN] OCSPRequest to encode.
 * @param buff   [OUT] Output buffer. Caller must free buff->data with BSL_SAL_FREE.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_ReqGenBuff(int32_t format, const HITLS_OCSP_Req *req, BSL_Buffer *buff);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Decode DER into an OCSPRequest.
 *
 * @param format [IN]  Decoding format: BSL_FORMAT_ASN1.
 * @param encode [IN]  DER-encoded data.
 * @param req    [OUT] Decoded OCSPRequest. Caller must free with HITLS_OCSP_ReqFree.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         #HITLS_OCSP_ERR_INVALID_REQUEST, the OCSPRequest DER is malformed.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_ReqParseBuff(int32_t format, const BSL_Buffer *encode, HITLS_OCSP_Req **req);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Generic function to get/set properties of an OCSPRequest.
 *
 * @param req    [IN/OUT] OCSPRequest context.
 * @param cmd    [IN] HITLS_OCSP_ReqCmd command.
 *               cmd                                 val type
 *               HITLS_OCSP_REQ_GET_NONCE            BSL_Buffer* (borrowed pointer, do not free)
 *               HITLS_OCSP_REQ_ADD_SINGLEREQ        HITLS_OCSP_SingleReq* (ownership transferred
 *                                                    on success only; on failure the caller
 *                                                    still owns it and must free it with
 *                                                    HITLS_OCSP_SingleReqFree)
 *               HITLS_OCSP_REQ_SET_NONCE            uint8_t* (raw bytes, length in valLen;
 *                                                  data is copied)
 *                                                  val==NULL && valLen==0: auto-generate
 *                                                  32 random bytes;
 *                                                  val==NULL && valLen>0: generate valLen
 *                                                  random bytes; otherwise copy val bytes.
 * @param val    [IN/OUT] Input and output value.
 * @param valLen [IN] Value length.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_ReqCtrl(HITLS_OCSP_Req *req, int32_t cmd, void *val, uint32_t valLen);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Check whether an OCSPRequest carries an optionalSignature.
 *
 * @param req      [IN]  Request context.
 * @param isSigned [OUT] true if optionalSignature is present, false otherwise.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_ReqIsSigned(const HITLS_OCSP_Req *req, bool *isSigned);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Sign an OCSPRequest (RFC 6960 Section 4.1). requestorName is extracted from the Subject DN
 *        of requestorCert.
 *
 * @param mdId          [IN] Hash algorithm ID.
 * @param prvKey        [IN] Signing private key.
 * @param algParam      [IN] Signature algorithm parameters, may be NULL.
 * @param requestorCert [IN] Requestor certificate whose Subject DN becomes requestorName.
 *                           It is embedded into the certs field automatically (unless
 *                           HITLS_OCSP_SIGN_NOCERTS is set); callers should not pass it again in certs.
 *                           Its reference count is incremented when embedded (the caller retains
 *                           ownership and must keep it alive until the sign call returns).
 * @param certs         [IN] Additional cert chain embedded into the optionalSignature certs field unless
 *                           HITLS_OCSP_SIGN_NOCERTS is set. Reference counts of certificates are
 *                           incremented; caller retains ownership.
 * @param req           [IN] OCSPRequest to sign.
 * @param flags         [IN] HITLS_OCSP_SignFlag control flags.
 *
 * @note requestorName is generated as a GeneralName directoryName from requestorCert's Subject DN.
 *       This module supports only the directoryName form of requestorName.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_ReqSign(int32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam,
                           const HITLS_X509_Cert *requestorCert, const HITLS_X509_List *certs, HITLS_OCSP_Req *req,
                           HITLS_OCSP_SignFlag flags);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Verify the optionalSignature of an OCSPRequest (RFC 6960 Section 4.1.2).
 *
 * @param req      [IN] Parsed OCSPRequest that must carry an optionalSignature.
 * @param certs    [IN] External certificate list used to locate the signer, and trusted as-is
 *                      (no chain validation) when HITLS_OCSP_VFY_TRUSTOTHER is set.
 * @param storeCtx [IN] X.509 store context for chain validation. Required unless the signer
 *                      comes from certs with HITLS_OCSP_VFY_TRUSTOTHER set.
 * @param flags    [IN] HITLS_OCSP_VfyFlag control flags (only TRUSTOTHER and NOINTERN).
 *
 * @retval #HITLS_PKI_SUCCESS, signature verification passed.
 *         #HITLS_OCSP_ERR_NOT_SIGNED, request has no optionalSignature.
 *         #HITLS_OCSP_ERR_SIGNER_NOT_FOUND, no certificate matches requestorName.
 *         #HITLS_OCSP_ERR_REQUESTOR_NAME_UNSUPPORT, requestorName is not a directoryName
 *                                                    GeneralName (only this form is supported).
 *         #HITLS_OCSP_ERR_INVALID_PARAM, unsupported flag bits.
 *         #HITLS_OCSP_ERR_NULL_POINTER, chain validation required but storeCtx is NULL.
 *         Error codes can be found in hitls_pki_errno.h
 * @note The signer certificate is located by matching its Subject DN against the request's
 *       requestorName, first in the external certs list, then in the embedded certs (unless
 *       HITLS_OCSP_VFY_NOINTERN). Only the directoryName form of requestorName is supported
 *       (RFC 6960 permits any GeneralName); a requestorName that is not a directoryName is
 *       rejected with #HITLS_OCSP_ERR_REQUESTOR_NAME_UNSUPPORT. When the signer comes from the external certs and
 *       HITLS_OCSP_VFY_TRUSTOTHER is set, it is treated as a locally configured OCSP signing
 *       authority (RFC 6960 §4.2.2.2 condition 1): chain/path validation is skipped and only
 *       the signature is verified. Otherwise the signer's chain is verified against storeCtx
 *       (which must be non-NULL).
 */
int32_t HITLS_OCSP_ReqVerify(const HITLS_OCSP_Req *req, const HITLS_X509_List *certs,
                             const HITLS_X509_StoreCtx *storeCtx, HITLS_OCSP_VfyFlag flags);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Get the number of SingleRequests in an OCSPRequest.
 *
 * @param req   [IN]  Request context.
 * @param count [OUT] Number of SingleRequests. Must not be NULL.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_ReqGetSingleReqCount(const HITLS_OCSP_Req *req, uint32_t *count);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Get a SingleRequest by index (shallow reference).
 *
 * @param req       [IN]  Request context.
 * @param index     [IN]  Zero-based index.
 * @param singleReq [OUT] Pointer to receive the SingleReq. Must not be NULL.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_ReqGetSingleReqByIndex(const HITLS_OCSP_Req *req, uint32_t index,
                                           HITLS_OCSP_SingleReq **singleReq);

/* ===== Response: SingleResp ===== */

/**
 * @ingroup hitls_pki_ocsp
 * @brief Create a SingleResponse with required fields (responder side). Ownership of certId is transferred.
 *
 * @param certId     [IN] CertID (ownership transferred on success; on failure the caller
 *                        still owns it and must free it with #HITLS_OCSP_CertIdFree).
 * @param certStatus [IN] Certificate status (HITLS_OCSP_CERT_STATUS_GOOD / REVOKED / UNKNOWN).
 * @param thisUpdate [IN] Time of this update (input, copied into the object; must not be NULL).
 *
 * @retval HITLS_OCSP_SingleResp * on success, NULL on failure.
 */
HITLS_OCSP_SingleResp *HITLS_OCSP_SingleRespNew(HITLS_OCSP_CertId *certId,
                                                 HITLS_OCSP_CertStatus certStatus,
                                                 const BSL_TIME *thisUpdate);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Free a SingleResponse. NULL safe.
 *
 * @param single [IN] SingleResponse context to free.
 *
 * @retval void
 */
void HITLS_OCSP_SingleRespFree(HITLS_OCSP_SingleResp *single);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Generic function to get/set properties of a SingleResponse.
 *
 * @param single [IN/OUT] SingleResponse context.
 * @param cmd    [IN] HITLS_OCSP_SingleRespCmd command.
 *               cmd                                     val type
 *               HITLS_OCSP_SINGLERESP_GET_CERTID        HITLS_OCSP_CertId** (borrowed pointer)
 *               HITLS_OCSP_SINGLERESP_GET_CERT_STATUS   int32_t*
 *               HITLS_OCSP_SINGLERESP_GET_THIS_UPDATE   BSL_TIME*
 *               HITLS_OCSP_SINGLERESP_GET_NEXT_UPDATE   BSL_TIME*
 *               HITLS_OCSP_SINGLERESP_GET_REVOCATION_TIME    BSL_TIME*
 *               HITLS_OCSP_SINGLERESP_GET_REVOCATION_REASON  int32_t*
 *               HITLS_OCSP_SINGLERESP_SET_NEXT_UPDATE   BSL_TIME*
 *               HITLS_OCSP_SINGLERESP_SET_REVOCATION_TIME    BSL_TIME*
 *               HITLS_OCSP_SINGLERESP_SET_REVOCATION_REASON  int32_t*
 * @param val    [IN/OUT] Input and output value.
 * @param valLen [IN] Value length.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_SingleRespCtrl(HITLS_OCSP_SingleResp *single, int32_t cmd, void *val, uint32_t valLen);

/* ===== Response: BasicResp ===== */

/**
 * @ingroup hitls_pki_ocsp
 * @brief Create a BasicOCSPResponse (responder side).
 *
 * @retval HITLS_OCSP_BasicResp * on success, NULL on failure.
 * @note producedAt is auto-generated with the current system time at sign time.
 */
HITLS_OCSP_BasicResp *HITLS_OCSP_BasicRespNew(void);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Free a BasicOCSPResponse. NULL safe.
 *
 * @param bs [IN] BasicOCSPResponse context to free.
 *
 * @retval void
 */
void HITLS_OCSP_BasicRespFree(HITLS_OCSP_BasicResp *bs);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Sign a BasicOCSPResponse.
 *
 * @param mdId      [IN] Hash algorithm ID.
 * @param prvKey    [IN] Signing private key.
 * @param algParam  [IN] Signature algorithm parameters, may be NULL.
 * @param signerCert [IN] Signer certificate. Internally verified against prvKey, used to generate the
 *                        ResponderID (byName/byKey per flags), and embedded into the response certs field
 *                        unless HITLS_OCSP_SIGN_NOCERTS is set. Its reference count is incremented when
 *                        embedded (the caller retains ownership and must keep it alive until the sign
 *                        call returns).
 * @param certs     [IN] Additional cert chain embedded into the response certs field unless
 *                       HITLS_OCSP_SIGN_NOCERTS is set. Reference counts of certificates are incremented;
 *                       caller retains ownership and must free certs independently after this call.
 * @param bs        [IN] BasicOCSPResponse to sign.
 * @param flags     [IN] HITLS_OCSP_SignFlag control flags.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_BasicRespSign(int32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam,
                                 const HITLS_X509_Cert *signerCert, const HITLS_X509_List *certs,
                                 HITLS_OCSP_BasicResp *bs, HITLS_OCSP_SignFlag flags);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Generic function to get/set properties of a BasicOCSPResponse.
 *
 * @param bs     [IN/OUT] BasicOCSPResponse context.
 * @param cmd    [IN] HITLS_OCSP_BasicRespCmd command.
 *               cmd                                    val type
 *               HITLS_OCSP_BASICRESP_GET_PRODUCED_AT   BSL_TIME*
 *               HITLS_OCSP_BASICRESP_GET_NONCE         BSL_Buffer* (borrowed pointer, do not free)
 *               HITLS_OCSP_BASICRESP_ADD_RESP          HITLS_OCSP_SingleResp* (ownership transferred
 *                                                       on success only; on failure the caller
 *                                                       still owns it and must free it with
 *                                                       HITLS_OCSP_SingleRespFree)
 *               HITLS_OCSP_BASICRESP_SET_NONCE         uint8_t* (raw bytes, length in valLen;
 *                                                       data is copied; unlike
 *                                                       HITLS_OCSP_REQ_SET_NONCE, val must not
 *                                                       be NULL and valLen must be greater
 *                                                       than 0)
 * @param val    [IN/OUT] Input and output value.
 * @param valLen [IN] Value length.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_BasicRespCtrl(HITLS_OCSP_BasicResp *bs, int32_t cmd, void *val, uint32_t valLen);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Get the number of SingleResponses in a BasicOCSPResponse.
 *
 * @param bs    [IN]  BasicOCSPResponse context.
 * @param count [OUT] Number of SingleResponses. Must not be NULL.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_BasicRespGetRespCount(const HITLS_OCSP_BasicResp *bs, uint32_t *count);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Get a SingleResponse by index (shallow reference).
 *
 * @param bs     [IN]  BasicOCSPResponse context.
 * @param index  [IN]  Zero-based index.
 * @param single [OUT] Pointer to receive the SingleResponse. Must not be NULL.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_BasicRespGetRespByIndex(const HITLS_OCSP_BasicResp *bs, uint32_t index,
                                            HITLS_OCSP_SingleResp **single);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Find the SingleResponse matching the given CertID in a BasicOCSPResponse (shallow reference).
 *
 * @param bs     [IN]  BasicOCSPResponse context.
 * @param certId [IN]  Target CertID to search for.
 * @param single [OUT] Pointer to receive the matched SingleResponse. Must not be NULL.
 *
 * @retval #HITLS_PKI_SUCCESS, found.
 *         #HITLS_OCSP_ERR_CERTID_NOT_FOUND, no SingleResponse matches certId.
 *         Error codes can be found in hitls_pki_errno.h
 * @note The returned SingleResponse is owned by the BasicOCSPResponse;
 *       caller must NOT free it. It remains valid until bs is freed.
 */
int32_t HITLS_OCSP_BasicRespFindResp(const HITLS_OCSP_BasicResp *bs, const HITLS_OCSP_CertId *certId,
                                     HITLS_OCSP_SingleResp **single);

/* ===== Response: Resp ===== */

/**
 * @ingroup hitls_pki_ocsp
 * @brief Single-step create an OCSPResponse with a status and an optional BasicOCSPResponse.
 *
 * @param status [IN] OCSP response status (HITLS_OCSP_RespStatus).
 * @param bs     [IN] BasicOCSPResponse. When status is
 *                    #HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs MUST NOT be NULL and the
 *                    BasicOCSPResponse must already be signed (see HITLS_OCSP_BasicRespSign);
 *                    when status is an error status (e.g.
 *                    #HITLS_OCSP_RESP_STATUS_MALFORMED_REQUEST), bs MUST be NULL, because
 *                    the responseBytes field is not set for error statuses (RFC 6960 4.2.1).
 *                    On success its ownership is transferred; the caller must not use or
 *                    free it afterwards. On failure the ownership is NOT transferred; the
 *                    caller must free it with HITLS_OCSP_BasicRespFree. Failure scenarios:
 *                    invalid status, a status/bs mismatch as described above, or an
 *                    unsigned BasicOCSPResponse.
 *
 * @retval HITLS_OCSP_Resp * on success, NULL on failure.
 */
HITLS_OCSP_Resp *HITLS_OCSP_RespNew(HITLS_OCSP_RespStatus status, HITLS_OCSP_BasicResp *bs);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Free an OCSPResponse. NULL safe.
 *
 * @param resp [IN] OCSPResponse context to free.
 *
 * @retval void
 */
void HITLS_OCSP_RespFree(HITLS_OCSP_Resp *resp);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Encode an OCSPResponse into DER.
 *
 * @param format [IN]  Encoding format: BSL_FORMAT_ASN1.
 * @param resp   [IN]  OCSPResponse to encode.
 * @param buff   [OUT] Output buffer. Caller must free buff->data with BSL_SAL_FREE.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_RespGenBuff(int32_t format, const HITLS_OCSP_Resp *resp, BSL_Buffer *buff);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Decode DER into an OCSPResponse.
 *
 * @param format [IN]  Decoding format: BSL_FORMAT_ASN1.
 * @param encode [IN]  DER-encoded data.
 * @param resp   [OUT] Decoded OCSPResponse. Caller must free with HITLS_OCSP_RespFree.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         #HITLS_OCSP_ERR_INVALID_RESPONSE, the OCSPResponse DER is malformed.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_RespParseBuff(int32_t format, const BSL_Buffer *encode, HITLS_OCSP_Resp **resp);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Generic function to get properties of an OCSPResponse (GET only).
 *
 * @param resp   [IN/OUT] OCSPResponse context.
 * @param cmd    [IN] HITLS_OCSP_RespCmd command.
 *               cmd                                 val type
 *               HITLS_OCSP_RESP_GET_STATUS          int32_t* (responseStatus value)
 *               HITLS_OCSP_RESP_GET_BASIC           HITLS_OCSP_BasicResp** (borrowed pointer, do not free)
 * @param val    [IN/OUT] Input and output value.
 * @param valLen [IN] Value length.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_RespCtrl(HITLS_OCSP_Resp *resp, int32_t cmd, void *val, uint32_t valLen);

/* ===== Utility ===== */

/**
 * @ingroup hitls_pki_ocsp
 * @brief Convert a revocation reason code to a readable string.
 *        Reason values are HITLS_X509_REVOKED_REASON_* (0~10, value 7 reserved by RFC 5280).
 *
 * @param reason [IN] Revocation reason code (HITLS_X509_REVOKED_REASON_*).
 *
 * @retval Static string; NULL for an invalid value. No free needed.
 */
const char *HITLS_OCSP_RevocationReasonToStr(int32_t reason);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Convert a certificate status code to a readable string.
 *
 * @param status [IN] HITLS_OCSP_CertStatus value.
 *
 * @retval Static string; NULL for an invalid value. No free needed.
 */
const char *HITLS_OCSP_CertStatusToStr(HITLS_OCSP_CertStatus status);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Convert an OCSP response status code to a readable string.
 *
 * @param status [IN] HITLS_OCSP_RespStatus value (0/1/2/3/5/6, 4 reserved).
 *
 * @retval Static string; NULL for an invalid value. No free needed.
 */
const char *HITLS_OCSP_RespStatusToStr(HITLS_OCSP_RespStatus status);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Extract all OCSP responder URIs from the certificate's Authority Information Access extension.
 *
 * @param cert [IN]  Target certificate.
 * @param urls [OUT] Pointer to receive the URI list. Each element is a BSL_Buffer* holding a byte copy
 *                   of one URI. On success the list is non-NULL and contains at least one entry.
 *
 * @retval #HITLS_PKI_SUCCESS, success. Returns #HITLS_OCSP_ERR_NO_OCSP_URL when the certificate
 *         carries no usable OCSP access-location URI (no AIA, or none of the AIA descriptions
 *         holds an id-ad-ocsp accessMethod with a URI GeneralName).
 *         Error codes can be found in hitls_pki_errno.h
 * @note Caller must free each BSL_Buffer.data and then free the list.
 */
int32_t HITLS_OCSP_GetCertOcspUrls(const HITLS_X509_Cert *cert, BslList **urls);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Integrated OCSP response verification (signature + chain + EKU + authorization).
 *
 * @param bs       [IN] BasicOCSPResponse to verify.
 * @param certs    [IN] Trusted certificate list (optional, used with HITLS_OCSP_VFY_TRUSTOTHER).
 * @param storeCtx [IN] X.509 store context for chain validation.
 * @param flags    [IN] HITLS_OCSP_VfyFlag control flags.
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 * @note The signer is located first in the external certs list, then in the embedded certs
 *       (unless HITLS_OCSP_VFY_NOINTERN). When the signer comes from the external certs and
 *       HITLS_OCSP_VFY_TRUSTOTHER is set, it is treated as a locally configured OCSP signing
 *       authority (RFC 6960 §4.2.2.2 condition 1): chain/path validation and the
 *       issuer/delegation authorization check are skipped and only the response signature is
 *       verified. Otherwise the signer's chain is verified
 *       against storeCtx and the RFC 6960 §4.2.2.2 authorization check (conditions 2/3) applies.
 */
int32_t HITLS_OCSP_BasicRespVerify(const HITLS_OCSP_BasicResp *bs, const HITLS_X509_List *certs,
                                   const HITLS_X509_StoreCtx *storeCtx, HITLS_OCSP_VfyFlag flags);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Compare the request and response Nonce consistency.
 *
 * The comparison outcome is fully reported through the @p status output parameter;
 * the return value only signals whether the comparison could be performed.
 *
 * @param req    [IN]  OCSPRequest (may be NULL if no nonce to compare).
 * @param bs     [IN]  BasicOCSPResponse (may be NULL if no nonce to compare).
 * @param status [OUT] Nonce comparison result. Must not be NULL.
 *
 * @retval #HITLS_PKI_SUCCESS, the comparison was performed; check @p status for the result.
 *         #HITLS_OCSP_ERR_NULL_POINTER, @p status is NULL.
 */
int32_t HITLS_OCSP_CheckNonce(const HITLS_OCSP_Req *req, const HITLS_OCSP_BasicResp *bs,
                              HITLS_OCSP_NonceStatus *status);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Check the validity of a SingleResponse (drift + maxage).
 *
 * @param single   [IN]  SingleResponse to check.
 * @param driftSec [IN]  Allowed clock drift in seconds (e.g. 300 for 5 minutes).
 * @param maxageSec [IN] Maximum age in seconds (0 to disable maxage check).
 *
 * @retval #HITLS_PKI_SUCCESS, success (response is within validity window).
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_CheckValidity(const HITLS_OCSP_SingleResp *single, int64_t driftSec, int64_t maxageSec);

/**
 * @ingroup hitls_pki_ocsp
 * @brief Get the response signer certificate (ResponderID identity match only, no verification).
 *
 * @attention The returned certificate is reference-counted: this function takes an additional
 *            reference on it, so the caller owns the returned pointer and must release it exactly
 *            once with #HITLS_X509_CertFree. The certificate stays valid independently of the
 *            lifetime of @p bs and of the @p certs list.
 *
 * @param bs     [IN]  BasicOCSPResponse context.
 * @param certs  [IN]  Certificate list to search (optional external certs + embedded certs).
 * @param signer [OUT] Pointer to receive the matched signer certificate. Must not be NULL, and
 *                    must be initialized to NULL on entry. On success the caller must release it
 *                    with #HITLS_X509_CertFree; on failure it is left unchanged (NULL).
 *
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_OCSP_BasicRespGetSigner(const HITLS_OCSP_BasicResp *bs, const HITLS_X509_List *certs,
                                      HITLS_X509_Cert **signer);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_PKI_OCSP_H */

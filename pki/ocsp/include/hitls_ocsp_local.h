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

#ifndef HITLS_OCSP_LOCAL_H
#define HITLS_OCSP_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_PKI_OCSP
#include <stdint.h>
#include "bsl_asn1_internal.h"
#include "bsl_obj.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"
#include "hitls_pki_ocsp.h"
#include "hitls_pki_types.h"
#include "hitls_x509_local.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HITLS_OCSP_NONCE_DEFAULT_LEN 32
#define HITLS_OCSP_REVOKED_REASON_UNUSED 7  // RFC 5280 CRLReason: value 7 is unused

/* Upper bound on the number of SingleRequest / SingleResponse entries a request
 * or response may accumulate. Applied at the ADD ctrl; keeps the encode-side
 * "count * 2" leaf array from overflowing uint32. */
#define HITLS_OCSP_MAX_SINGLE_REQ  1024
#define HITLS_OCSP_MAX_SINGLE_RESP 1024

/*
 * ResponderID CHOICE type (RFC 6960 Section 4.2.1)
 * Internal only — generated from the signer cert at sign time.
 */
typedef enum {
    HITLS_OCSP_RESPONDERID_BY_NAME = 0,
    HITLS_OCSP_RESPONDERID_BY_KEY = 1
} HITLS_OCSP_ResponderIdType;

typedef struct HITLS_OCSP_ResponderId {
    HITLS_OCSP_ResponderIdType type; /**< Discriminator; MUST be set before accessing value, see OcspResponderIdNewFromCert. */
    union {
        BSL_Buffer byName;   /**< DER-encoded Name, used when type == HITLS_OCSP_RESPONDERID_BY_NAME */
        BSL_Buffer byKey;    /**< Responder public key hash (KeyHash), used when type == HITLS_OCSP_RESPONDERID_BY_KEY */
    } value;
} HITLS_OCSP_ResponderId;

/*
 * OCSP Request ASN.1 Structure (RFC 6960) — Phase 1 scope (unsigned only)
 *
 * OCSPRequest ::= SEQUENCE {
 *     tbsRequest      TBSRequest }
 *     -- optionalSignature [0] EXPLICIT — Phase 2
 *
 * TBSRequest ::= SEQUENCE {
 *     -- version [0] DEFAULT v1 — omitted (v1 default)
 *     -- requestorName [1] — Phase 2 (required when signed, per RFC 6960)
 *     requestList     SEQUENCE OF Request,
 *     requestExtensions [2] EXPLICIT Extensions OPTIONAL }
 *
 * Request ::= SEQUENCE {
 *     reqCert        CertID,
 *     -- singleRequestExtensions [0] — Phase 2
 * }
 *
 * CertID ::= SEQUENCE {
 *     hashAlgorithm  AlgorithmIdentifier,
 *     issuerNameHash OCTET STRING,
 *     issuerKeyHash  OCTET STRING,
 *     serialNumber   INTEGER }
 *
 * Nonce Extension:
 * Extension ::= SEQUENCE {
 *     extnID    OBJECT IDENTIFIER  -- id-pkix-ocsp-nonce (1.3.6.1.5.5.7.48.1.2)
 *     extnValue OCTET STRING       -- content = DER(OCTET STRING nonce_bytes)
 * }
 *
 * Encoding flow (bottom-up):
 * 1. OcspEncodeAlgId: AlgorithmIdentifier (OID + NULL)
 * 2. OcspEncodeCertId: CertID SEQUENCE (AlgId + nameHash + keyHash + serial)
 * 3. OcspEncodeRequestList: SEQUENCE OF Request via BSL_ASN1_EncodeListItem
 * 4. OcspEncodeExtensions: Nonce Extension SEQUENCE → Extensions SEQUENCE OF
 * 5. OcspEncodeTbsRequest: TBSRequest SEQUENCE (requestList + [2] EXPLICIT Extensions?)
 * 6. ReqGenBuff: OCSPRequest = SEQUENCE { TBSRequest }
 *    — g_ocspReqTempl, TBSRequest built from requestList + extensions leaves
 */

typedef struct CertId_St {
    CRYPT_MD_AlgId hashAlg;
    BSL_ASN1_Buffer issuerNameHash;
    BSL_ASN1_Buffer issuerKeyHash;
    BSL_ASN1_Buffer serialNumber;
} HITLS_OCSP_CertId_Internal;

typedef struct SingleReq_St {
    HITLS_OCSP_CertId *certId;
    HITLS_X509_Ext *ext; /* singleRequestExtensions [0] EXPLICIT, optional */
} HITLS_OCSP_SingleReq_Internal;

typedef struct Req_St {
    BslList *singleReqs;
    HITLS_X509_Ext *ext;
    bool isSigned;
    /* optionalSignature fields (RFC 6960 Section 4.1), valid when isSigned */
    BSL_Buffer requestorName;              /* requestorName [1] EXPLICIT GeneralName: raw GeneralName TLV */
    HITLS_X509_Asn1AlgId signAlgId;        /* signatureAlgorithm */
    BSL_ASN1_BitString signature;          /* signature */
    BslList *certs;                        /* certs [0] EXPLICIT SEQUENCE OF Certificate */
    BSL_Buffer tbsRawData;                 /* TBSRequest content DER (signed data) */
    BSL_Buffer rawData;                    /* full OCSPRequest DER, saved at sign time */
} HITLS_OCSP_Req_Internal;

/*
 * SingleResponse ::= SEQUENCE {
 *     certID          CertID
 *     certStatus      CertStatus (good/revoked/unknown)
 *     thisUpdate      GeneralizedTime
 *     nextUpdate      [0] EXPLICIT GeneralizedTime OPTIONAL
 *     singleExtensions [1] EXPLICIT Extensions OPTIONAL
 * }
 *
 * CertStatus ::= CHOICE {
 *     good    [0] IMPLICIT NULL
 *     revoked [1] IMPLICIT RevokedInfo
 *     unknown [2] IMPLICIT UnknownInfo (NULL) }
 *
 * RevokedInfo ::= SEQUENCE {
 *     revocationTime   GeneralizedTime
 *     revocationReason [0] EXPLICIT CRLReason OPTIONAL }
 */
typedef struct SingleResp_St {
    HITLS_OCSP_CertId *certId;
    HITLS_OCSP_CertStatus certStatus;
    BSL_TIME thisUpdate;
    bool hasNextUpdate;
    BSL_TIME nextUpdate;
    bool hasRevocationTime;
    BSL_TIME revocationTime;
    bool hasRevocationReason;
    int32_t revocationReason;
    HITLS_X509_Ext *ext; /* singleExtensions [1] EXPLICIT, optional */
} HITLS_OCSP_SingleResp_Internal;

/*
 * BasicOCSPResponse ::= SEQUENCE {
 *     tbsResponseData      ResponseData
 *     signatureAlgorithm   AlgorithmIdentifier
 *     signature            BIT STRING
 *     certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 *
 * ResponseData ::= SEQUENCE {
 *     version              [0] EXPLICIT Version DEFAULT v1
 *     responderID          ResponderID
 *     producedAt           GeneralizedTime
 *     responses            SEQUENCE OF SingleResponse
 *     responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
 *
 * ResponderID ::= CHOICE {
 *     byName [1] Name
 *     byKey  [2] KeyHash }
 */
typedef struct BasicResp_St {
    /* ResponseData fields */
    HITLS_OCSP_ResponderId *responderId;  /**< Generated from the signer cert at sign time; parsed from DER otherwise */
    BSL_TIME producedAt;
    BslList *responses;
    HITLS_X509_Ext *ext;

    /* BasicOCSPResponse outer fields (populated after signing) */
    BSL_Buffer tbsRawData;
    HITLS_X509_Asn1AlgId signAlgId;
    BSL_ASN1_BitString signature;
    BslList *certs;
    bool isSigned;
} HITLS_OCSP_BasicResp_Internal;

/*
 * OCSPResponse ::= SEQUENCE {
 *     responseStatus     OCSPResponseStatus
 *     responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL }
 *
 * ResponseBytes ::= SEQUENCE {
 *     responseType    OBJECT IDENTIFIER
 *     response        OCTET STRING }
 */
typedef struct Resp_St {
    uint8_t status;
    HITLS_OCSP_BasicResp *basicResp;
} HITLS_OCSP_Resp_Internal;

/* Shared encoding functions (ocsp_common.c) */
int32_t OcspEncodeCertId(const HITLS_OCSP_CertId *certId, BSL_ASN1_Buffer *out);
int32_t OcspEncodeExt(HITLS_X509_Ext *ext, uint8_t tag, BSL_ASN1_Buffer *extData);
int32_t OcspDecodeExt(BSL_ASN1_Buffer *extSeqof, HITLS_X509_Ext **ext);
int32_t OcspSetNonce(HITLS_X509_Ext **ext, uint8_t *data, uint32_t dataLen);
/* OcspGetNonce fills *val (a BSL_Buffer) with a BORROWED pointer into the extension's
 * internal storage; callers must not free val->data. OcspSetNonce copies data and
 * rejects dataLen > HITLS_OCSP_NONCE_MAX_LEN. */
int32_t OcspGetNonce(HITLS_X509_Ext *ext, BSL_Buffer *val, uint32_t valLen);

/* Shared cert chain encode/decode (used by response and request).
 * Encode: certsV = SEQUENCE OF Certificate TLV. An empty/NULL list yields a zeroed
 * certsV (tag==0, len==0); callers must omit the certs field in that case (the
 * [0]/[1] EXPLICIT template items are OPTIONAL).
 * Parse:  certsAsn = [0] V (SEQUENCE OF TLV); allocates and fills *certs. */
int32_t OcspEncodeCerts(BslList *certs, BSL_ASN1_Buffer *certsV);
int32_t OcspParseCerts(BSL_ASN1_Buffer *certsAsn, BslList **certs);

/* Build a new cert list from signerCert + src, REF_UP-ing each cert (ownership shared with caller).
 * src may be NULL/empty. *dst must be NULL on entry. */
int32_t OcspRefUpSignerCerts(const HITLS_X509_Cert *signerCert, const HITLS_X509_List *src, HITLS_X509_List **dst);

/* Validate the signing key before signing: reject SM2, check key/signer-cert match. */
int32_t OcspCheckSignKey(const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_Cert *signerCert);

/* Free a ResponderID. NULL safe. */
void OcspResponderIdFree(HITLS_OCSP_ResponderId *responderId);

/* Verify the signer's cert chain to the trusted root via storeCtx.
 * embeddedCerts is the chain carried in the OCSP message (response or request certs).
 * On success *signerIssuer is the verified issuer of signer (caller frees). */
int32_t OcspVerifySigner(const HITLS_X509_List *embeddedCerts, const HITLS_X509_List *certs,
                         const HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *signer, HITLS_X509_Cert **signerIssuer);

/* Strip T+L from a full TLV buffer, output only V (value content).
 * Does NOT modify the input; out->buff borrows into in->buff's memory.
 * The original in->buff must remain valid and be freed (not out->buff).
 * Returns HITLS_PKI_SUCCESS on success, or an error code if the TLV header is malformed. */
int32_t OcspStripTlv(const BSL_ASN1_Buffer *in, BSL_ASN1_Buffer *out);

/* Shared decoding functions (ocsp_common.c) */
int32_t OcspSetHashField(CRYPT_MD_AlgId hashAlg, BSL_ASN1_Buffer *field, const uint8_t *hash, uint32_t hashLen);
int32_t OcspParseCertId(const BSL_ASN1_Buffer *asn, HITLS_OCSP_CertId_Internal *certId);

/* Shared helpers (ocsp_certid.c) */
bool OcspCertIdIssuerMatch(const HITLS_OCSP_CertId_Internal *a, const HITLS_OCSP_CertId_Internal *b);
int32_t OcspGetIssuerNameHash(CRYPT_EAL_MdCtx *mdCtx, const HITLS_X509_Cert *issuer,
                             uint8_t *out, uint32_t *outLen);
int32_t OcspGetPubKeyHash(CRYPT_EAL_MdCtx *mdCtx, const HITLS_X509_Cert *cert,
                          uint8_t *out, uint32_t *outLen);

/* Shared ASN.1 ANY/CHOICE callback for decode templates (ocsp_common.c) */
int32_t OcspTagGetOrCheck(int32_t type, uint32_t idx, void *data, void *expVal);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_OCSP
#endif // HITLS_OCSP_LOCAL_H

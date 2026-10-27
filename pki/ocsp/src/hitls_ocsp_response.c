/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "hitls_build.h"
#ifdef HITLS_PKI_OCSP

#include <string.h>
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_err_internal.h"
#include "bsl_asn1_internal.h"
#include "bsl_obj.h"
#include "bsl_obj_internal.h"
#include "crypt_errno.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_ocsp.h"
#include "hitls_x509_local.h"
#include "hitls_ocsp_local.h"
#ifdef HITLS_PKI_X509_VFY
#include "hitls_x509_verify.h"
#include "hitls_x509_store_local.h"
#endif
#include "hitls_cert_local.h"

#define CRYPT_SHA1_DIGEST_SIZE 20

/* ==================== ASN.1 Templates ==================== */

/*
 * RevokedInfo ::= SEQUENCE {                                    depth=0
 *     revocationTime      GeneralizedTime                       depth=1
 *     revocationReason    [0] EXPLICIT CRLReason OPTIONAL       depth=1 (container)
 *         ENUMERATED                                            depth=2 }
 * Shared by the encode and decode paths.
 */
static BSL_ASN1_TemplateItem g_ocspRevokedInfoTempl[] = {
    {BSL_ASN1_TAG_GENERALIZEDTIME, 0, 0},                                             /* revocationTime */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0, BSL_ASN1_FLAG_OPTIONAL, 0}, /* revocationReason [0] */
        {BSL_ASN1_TAG_ENUMERATED, 0, 1},                                              /* CRLReason (ENUMERATED) */
};
#define REVOKED_INFO_DEC_LEAF_NUM 2

enum {
    REVOKED_INFO_DEC_TIME_IDX = 0,
    REVOKED_INFO_DEC_REASON_IDX,
    REVOKED_INFO_DEC_MAX_IDX,
};

/* Encode template for the SingleResponse element (SEQUENCE OF encoding). */
static BSL_ASN1_TemplateItem g_ocspSingleRespElemEncTempl[] = {
    {BSL_ASN1_TAG_ANY, 0, 0}, /* SingleResponse TLV */
};

/*
 * Encode template for ResponseData (version omitted, defaults to v1):
 * ResponseData ::= SEQUENCE {                                    depth=0
 *     version              [0] EXPLICIT Version DEFAULT v1       (omitted)
 *     responderID          ResponderID (CHOICE, HEADERONLY)      depth=1
 *     producedAt           GeneralizedTime                       depth=1
 *     responses            SEQUENCE OF SingleResponse            depth=1
 *     responseExtensions   [1] EXPLICIT Extensions OPTIONAL      depth=1 (HEADERONLY) }
 */
static BSL_ASN1_TemplateItem g_ocspRespDataEncTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},        /* ResponseData */
        {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_HEADERONLY, 1},             /* responderID */
        {BSL_ASN1_TAG_GENERALIZEDTIME, 0, 1},                        /* producedAt */
        {BSL_ASN1_TAG_ANY, 0, 1},                                    /* responses */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1, /* responseExtensions [1] */
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
};

/*
 * Encode template for BasicOCSPResponse:
 * BasicOCSPResponse ::= SEQUENCE {                               depth=0
 *     tbsResponseData      ResponseData(HEADERONLY)              depth=1
 *     signatureAlgorithm   AlgorithmIdentifier(HEADERONLY)       depth=1
 *     signature            BIT STRING                            depth=1
 *     certs            [0] EXPLICIT SEQUENCE OF Certificate      depth=1 (OPTIONAL | HEADERONLY) }
 */
static BSL_ASN1_TemplateItem g_ocspBasicRespEncTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},        /* BasicOCSPResponse */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1}, /* tbsResponseData */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1}, /* signatureAlgorithm */
        {BSL_ASN1_TAG_BITSTRING, 0, 1},                             /* signature */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED,     /* certs [0] */
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
};

/*
 * ResponseBytes ::= SEQUENCE {                                   depth=0
 *     responseType    OBJECT IDENTIFIER                          depth=1
 *     response        OCTET STRING                               depth=1 }
 * Shared by the encode and decode paths.
 */
static BSL_ASN1_TemplateItem g_ocspRespBytesTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* ResponseBytes */
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},                       /* responseType */
        {BSL_ASN1_TAG_OCTETSTRING, 0, 1},                     /* response */
};

/* ResponseBytes leaf indices (shared template g_ocspRespBytesTempl). */
enum { RESP_BYTES_DEC_LEAF_NUM = 2 };

enum {
    RESP_BYTES_DEC_OID_IDX = 0,
    RESP_BYTES_DEC_RESPONSE_IDX,
    RESP_BYTES_DEC_MAX_IDX,
};

/*
 * OCSPResponse ::= SEQUENCE {                                   depth=0
 *     responseStatus    OCSPResponseStatus (ENUMERATED)          depth=1
 *     responseBytes [0] EXPLICIT ResponseBytes OPTIONAL          depth=1 (HEADERONLY) }
 * Shared by the encode and decode paths.
 */
static BSL_ASN1_TemplateItem g_ocspRespTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* OCSPResponse */
        {BSL_ASN1_TAG_ENUMERATED, 0, 1},                      /* responseStatus */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, /* responseBytes [0] */
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
};

/* OCSPResponse leaf indices (shared template g_ocspRespTempl). */
enum { OCSP_RESP_DEC_LEAF_NUM = 2 };

enum {
    OCSP_RESP_DEC_STATUS_IDX = 0,
    OCSP_RESP_DEC_BYTES_IDX,
    OCSP_RESP_DEC_MAX_IDX,
};

/*
 * SingleResponse content (input = content of SingleResponse SEQUENCE), shared by
 * the encode and decode paths:
 * SingleResponse ::= SEQUENCE {
 *     certID              CertID                                   depth=0  leaf[0] (HEADERONLY)
 *     certStatus          CertStatus (CHOICE)                      depth=0  leaf[1] (ANY | HEADERONLY)
 *     thisUpdate          GeneralizedTime                          depth=0  leaf[2]
 *     nextUpdate          [0] EXPLICIT GeneralizedTime OPTIONAL    depth=0  (OPTIONAL, container)
 *         GeneralizedTime                                          depth=1  leaf[3]
 *     singleExtensions    [1] EXPLICIT Extensions OPTIONAL         depth=0  leaf[4] (OPTIONAL | HEADERONLY)
 * }
 */
static BSL_ASN1_TemplateItem g_ocspSingleRespTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0}, /* certID */
    {BSL_ASN1_TAG_CHOICE, BSL_ASN1_FLAG_HEADERONLY, 0},                             /* certStatus */
    {BSL_ASN1_TAG_GENERALIZEDTIME, 0, 0},                                           /* thisUpdate */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, BSL_ASN1_FLAG_OPTIONAL, 0}, /* nextUpdate [0] */
        {BSL_ASN1_TAG_GENERALIZEDTIME, 0, 1},                                       /* nextUpdate GeneralizedTime */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1,                    /* singleExtensions [1] */
        BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
};

enum {
    SINGLE_RESP_DEC_CERTID_IDX = 0,
    SINGLE_RESP_DEC_CERT_STATUS_IDX,
    SINGLE_RESP_DEC_THIS_UPDATE_IDX,
    SINGLE_RESP_DEC_NEXT_UPDATE_IDX,
    SINGLE_RESP_DEC_EXTENSIONS_IDX,
    SINGLE_RESP_DEC_MAX_IDX,
};

/*
 * Decode template for BasicOCSPResponse:
 * BasicOCSPResponse ::= SEQUENCE {                                depth=0
 *     tbsResponseData      ResponseData                           depth=1  leaf[0] (HEADERONLY)
 *     signatureAlgorithm   AlgorithmIdentifier                    depth=1  container
 *         algorithm   OBJECT IDENTIFIER                           depth=2  leaf[1]
 *         parameters  ANY OPTIONAL                                depth=2  leaf[2]
 *     signature            BIT STRING                             depth=1  leaf[3]
 *     certs            [0] EXPLICIT SEQUENCE OF Certificate OPT   depth=1  leaf[4] (HEADERONLY, skipped)
 * }
 * Input = full BasicOCSPResponse DER (from OCTET STRING content).
 * Used by the BasicOCSPResponse decoder.
 */
static BSL_ASN1_TemplateItem g_ocspBasicRespDecTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},        /* BasicOCSPResponse */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1}, /* tbsResponseData */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},     /* signatureAlgorithm */
            {BSL_ASN1_TAG_OBJECT_ID, 0, 2},                           /* algorithm */
            {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 2},            /* parameters */
        {BSL_ASN1_TAG_BITSTRING, 0, 1},                              /* signature */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED,      /* certs [0] */
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
};

enum {
    BASIC_RESP_DEC_TBS_IDX = 0,
    BASIC_RESP_DEC_SIGALG_OID_IDX,
    BASIC_RESP_DEC_SIGALG_PARAM_IDX,
    BASIC_RESP_DEC_SIG_IDX,
    BASIC_RESP_DEC_CERTS_IDX,
    BASIC_RESP_DEC_MAX_IDX,
};

/*
 * Decode template for ResponseData content (input = content of ResponseData SEQUENCE):
 * ResponseData ::= SEQUENCE {
 *     version              [0] EXPLICIT Version DEFAULT v1         depth=0  (OPTIONAL, container)
 *         INTEGER                                                   depth=1  leaf[0] (ignored)
 *     responderID          ResponderID (CHOICE)                    depth=0  leaf[1] (ANY | HEADERONLY)
 *     producedAt           GeneralizedTime                          depth=0  leaf[2]
 *     responses            SEQUENCE OF SingleResponse              depth=0  leaf[3] (HEADERONLY)
 *     responseExtensions   [1] EXPLICIT Extensions OPTIONAL        depth=0  leaf[4] (OPTIONAL | HEADERONLY)
 * }
 * Used by the ResponseData decoder.
 */
static BSL_ASN1_TemplateItem g_ocspRespDataDecTempl[] = {
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, BSL_ASN1_FLAG_OPTIONAL, 0}, /* version [0] */
        {BSL_ASN1_TAG_INTEGER, 0, 1},                                                /* Version (INTEGER) */
    {BSL_ASN1_TAG_CHOICE, BSL_ASN1_FLAG_HEADERONLY, 0},                              /* responderID */
    {BSL_ASN1_TAG_GENERALIZEDTIME, 0, 0},                                           /* producedAt */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0}, /* responses */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1,                    /* responseExtensions [1] */
        BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
};

enum {
    RESP_DATA_DEC_VERSION_IDX = 0,
    RESP_DATA_DEC_RESPONDER_ID_IDX,
    RESP_DATA_DEC_PRODUCED_AT_IDX,
    RESP_DATA_DEC_RESPONSES_IDX,
    RESP_DATA_DEC_EXTENSIONS_IDX,
    RESP_DATA_DEC_MAX_IDX,
};

/* ==================== SingleResp ==================== */

/*
 * SingleResponse ::= SEQUENCE {
 *     certID              CertID
 *     certStatus          CertStatus
 *     thisUpdate          GeneralizedTime
 *     nextUpdate          [0] EXPLICIT GeneralizedTime OPTIONAL
 *     singleExtensions    [1] EXPLICIT Extensions OPTIONAL }
 *
 * CertStatus ::= CHOICE {
 *     good        [0] IMPLICIT NULL
 *     revoked     [1] IMPLICIT RevokedInfo
 *     unknown     [2] IMPLICIT UnknownInfo }
 *
 * RevokedInfo ::= SEQUENCE {
 *     revocationTime      GeneralizedTime
 *     revocationReason    [0] EXPLICIT CRLReason OPTIONAL }
 *
 * UnknownInfo ::= NULL
 */

HITLS_OCSP_SingleResp *HITLS_OCSP_SingleRespNew(HITLS_OCSP_CertId *certId,
                                                 HITLS_OCSP_CertStatus certStatus,
                                                 const BSL_TIME *thisUpdate)
{
    if (certId == NULL || thisUpdate == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return NULL;
    }
    if (certStatus < HITLS_OCSP_CERT_STATUS_GOOD || certStatus > HITLS_OCSP_CERT_STATUS_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return NULL;
    }

    HITLS_OCSP_SingleResp_Internal *single =
        BSL_SAL_Calloc(1, sizeof(HITLS_OCSP_SingleResp_Internal));
    if (single == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    single->certId = certId;
    single->certStatus = certStatus;
    single->thisUpdate = *thisUpdate;
    return (HITLS_OCSP_SingleResp *)single;
}

void HITLS_OCSP_SingleRespFree(HITLS_OCSP_SingleResp *single)
{
    if (single == NULL) {
        return;
    }
    HITLS_OCSP_SingleResp_Internal *internal = (HITLS_OCSP_SingleResp_Internal *)single;
    HITLS_OCSP_CertIdFree(internal->certId);
    if (internal->ext != NULL) {
        HITLS_X509_ExtFree(internal->ext);
    }
    BSL_SAL_Free(internal);
}

static int32_t OcspSingleRespGetCtrl(HITLS_OCSP_SingleResp_Internal *internal, int32_t cmd, void *val, uint32_t valLen)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    switch (cmd) {
        case HITLS_OCSP_SINGLERESP_GET_CERTID:
            if (valLen < sizeof(HITLS_OCSP_CertId *)) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            *(HITLS_OCSP_CertId **)val = internal->certId;
            return HITLS_PKI_SUCCESS;
        case HITLS_OCSP_SINGLERESP_GET_CERT_STATUS:
            if (valLen < sizeof(HITLS_OCSP_CertStatus)) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            *(HITLS_OCSP_CertStatus *)val = internal->certStatus;
            return HITLS_PKI_SUCCESS;
        case HITLS_OCSP_SINGLERESP_GET_THIS_UPDATE:
            if (valLen < sizeof(BSL_TIME)) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            *(BSL_TIME *)val = internal->thisUpdate;
            return HITLS_PKI_SUCCESS;
        case HITLS_OCSP_SINGLERESP_GET_NEXT_UPDATE:
            if (valLen < sizeof(BSL_TIME)) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            if (!internal->hasNextUpdate) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_FIELD_NOT_PRESENT);
                return HITLS_OCSP_ERR_FIELD_NOT_PRESENT;
            }
            *(BSL_TIME *)val = internal->nextUpdate;
            return HITLS_PKI_SUCCESS;
        case HITLS_OCSP_SINGLERESP_GET_REVOCATION_TIME:
            if (valLen < sizeof(BSL_TIME)) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            if (!internal->hasRevocationTime) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_FIELD_NOT_PRESENT);
                return HITLS_OCSP_ERR_FIELD_NOT_PRESENT;
            }
            *(BSL_TIME *)val = internal->revocationTime;
            return HITLS_PKI_SUCCESS;
        case HITLS_OCSP_SINGLERESP_GET_REVOCATION_REASON:
            if (valLen < sizeof(int32_t)) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            if (!internal->hasRevocationReason) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_FIELD_NOT_PRESENT);
                return HITLS_OCSP_ERR_FIELD_NOT_PRESENT;
            }
            *(int32_t *)val = internal->revocationReason;
            return HITLS_PKI_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_CMD_UNSUPPORT);
            return HITLS_OCSP_ERR_CMD_UNSUPPORT;
    }
}

/* RFC 6960 §4.2.2.1: nextUpdate must not precede thisUpdate. Returns HITLS_PKI_SUCCESS,
 * or HITLS_OCSP_ERR_INVALID_PARAM (pushed once) when either time is invalid or nextUpdate
 * is earlier than thisUpdate. */
static int32_t OcspCheckNextUpdateOrder(const BSL_TIME *thisUpdate, const BSL_TIME *nextUpdate)
{
    int64_t thisUtc = 0;
    int64_t nextUtc = 0;
    if (BSL_SAL_DateToUtcTimeConvert(thisUpdate, &thisUtc) != BSL_SUCCESS ||
        BSL_SAL_DateToUtcTimeConvert(nextUpdate, &nextUtc) != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    if (nextUtc < thisUtc) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t OcspSingleRespSetCtrl(HITLS_OCSP_SingleResp_Internal *internal, int32_t cmd, void *val, uint32_t valLen)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    /* A SingleResp that is part of a signed BasicResp or was parsed from DER is
     * covered by the response signature; mutating it after the fact would make
     * the in-memory state diverge from the signed data (RFC 6960 §3.2). */
    if (internal->frozen) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_ALREADY_SIGNED);
        return HITLS_OCSP_ERR_ALREADY_SIGNED;
    }
    switch (cmd) {
        case HITLS_OCSP_SINGLERESP_SET_NEXT_UPDATE:
            if (valLen < sizeof(BSL_TIME)) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            int32_t ret = OcspCheckNextUpdateOrder(&internal->thisUpdate, (const BSL_TIME *)val);
            if (ret != HITLS_PKI_SUCCESS) {
                return ret;
            }
            internal->nextUpdate = *(BSL_TIME *)val;
            internal->hasNextUpdate = true;
            return HITLS_PKI_SUCCESS;
        case HITLS_OCSP_SINGLERESP_SET_REVOCATION_TIME:
            /* RFC 6960 §3.2: revocationTime only exists in the RevokedInfo of a
             * revoked certStatus; reject it for GOOD/UNKNOWN responses. */
            if (internal->certStatus != HITLS_OCSP_CERT_STATUS_REVOKED) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            if (valLen < sizeof(BSL_TIME)) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            internal->revocationTime = *(BSL_TIME *)val;
            internal->hasRevocationTime = true;
            return HITLS_PKI_SUCCESS;
        case HITLS_OCSP_SINGLERESP_SET_REVOCATION_REASON: {
            /* RFC 6960 §3.2: revocationReason only exists in the RevokedInfo of a
             * revoked certStatus; reject it for GOOD/UNKNOWN responses. */
            if (internal->certStatus != HITLS_OCSP_CERT_STATUS_REVOKED) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            if (valLen < sizeof(int32_t)) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            int32_t reason = *(int32_t *)val;
            if (reason < 0 || reason > HITLS_X509_REVOKED_REASON_AA_COMPROMISE ||
                reason == HITLS_OCSP_REVOKED_REASON_UNUSED) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            internal->revocationReason = reason;
            internal->hasRevocationReason = true;
            return HITLS_PKI_SUCCESS;
        }
        default:
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_CMD_UNSUPPORT);
            return HITLS_OCSP_ERR_CMD_UNSUPPORT;
    }
}

int32_t HITLS_OCSP_SingleRespCtrl(HITLS_OCSP_SingleResp *single, int32_t cmd, void *val, uint32_t valLen)
{
    if (single == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    HITLS_OCSP_SingleResp_Internal *internal = (HITLS_OCSP_SingleResp_Internal *)single;

    if (cmd < HITLS_OCSP_SINGLERESP_SET_NEXT_UPDATE) {
        return OcspSingleRespGetCtrl(internal, cmd, val, valLen);
    }
    return OcspSingleRespSetCtrl(internal, cmd, val, valLen);
}

/* ==================== BasicResp ==================== */

HITLS_OCSP_BasicResp *HITLS_OCSP_BasicRespNew(void)
{
    HITLS_OCSP_BasicResp_Internal *bs = BSL_SAL_Calloc(1, sizeof(HITLS_OCSP_BasicResp_Internal));
    if (bs == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    bs->responses = BSL_LIST_New(sizeof(HITLS_OCSP_SingleResp *));
    if (bs->responses == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_Free(bs);
        return NULL;
    }
    return (HITLS_OCSP_BasicResp *)bs;
}

void HITLS_OCSP_BasicRespFree(HITLS_OCSP_BasicResp *bs)
{
    if (bs == NULL) {
        return;
    }
    HITLS_OCSP_BasicResp_Internal *internal = (HITLS_OCSP_BasicResp_Internal *)bs;
    OcspResponderIdFree(internal->responderId);
    BSL_LIST_FREE(internal->responses, (BSL_LIST_PFUNC_FREE)HITLS_OCSP_SingleRespFree);
    HITLS_X509_ExtFree(internal->ext);

    BSL_SAL_FREE(internal->tbsRawData.data);
#ifdef HITLS_CRYPTO_SM2
    /* sm2UserId lives in a union with rsaPssParam, so only free it when the algId says SM2.
     * SM2 signing is currently rejected by OcspCheckSignKey, so this is effectively a no-op
     * today; it matches X509_CertFree/CSR and guards against future SM2 re-enablement. */
    if (internal->signAlgId.algId == BSL_CID_SM2DSAWITHSM3) {
        BSL_SAL_FREE(internal->signAlgId.sm2UserId.data);
        internal->signAlgId.sm2UserId.dataLen = 0;
    }
#endif
    BSL_SAL_FREE(internal->signature.buff);
    BSL_LIST_FREE(internal->certs, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_SAL_Free(internal);
}

static int32_t OcspBasicRespGetCtrl(HITLS_OCSP_BasicResp_Internal *internal, int32_t cmd, void *val, uint32_t valLen)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    switch (cmd) {
        case HITLS_OCSP_BASICRESP_GET_PRODUCED_AT:
            if (valLen < sizeof(BSL_TIME)) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            *(BSL_TIME *)val = internal->producedAt;
            return HITLS_PKI_SUCCESS;
        case HITLS_OCSP_BASICRESP_GET_NONCE:
            return OcspGetNonce(internal->ext, (BSL_Buffer *)val, valLen);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_CMD_UNSUPPORT);
            return HITLS_OCSP_ERR_CMD_UNSUPPORT;
    }
}

/* HITLS_OCSP_BASICRESP_ADD_RESP: validate and append a SingleResp to the
 * responses list. Ownership transfers only on success. */
static int32_t OcspBasicRespAddSingleResp(HITLS_OCSP_BasicResp_Internal *internal, void *val, uint32_t valLen)
{
    if (valLen < sizeof(HITLS_OCSP_SingleResp *)) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    HITLS_OCSP_SingleResp_Internal *singleResp = (HITLS_OCSP_SingleResp_Internal *)val;
    if (singleResp->certStatus == HITLS_OCSP_CERT_STATUS_REVOKED && singleResp->hasRevocationTime == false) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NO_REVOCATION_TIME);
        return HITLS_OCSP_ERR_NO_REVOCATION_TIME;
    }
    if (BSL_LIST_COUNT(internal->responses) >= HITLS_OCSP_MAX_SINGLE_RESP) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_TOO_MANY);
        return HITLS_OCSP_ERR_TOO_MANY;
    }
    int32_t ret = BSL_LIST_AddElement(internal->responses, val, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t OcspBasicRespSetCtrl(HITLS_OCSP_BasicResp_Internal *internal, int32_t cmd, void *val, uint32_t valLen)
{
    if (internal->isSigned) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_ALREADY_SIGNED);
        return HITLS_OCSP_ERR_ALREADY_SIGNED;
    }
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    switch (cmd) {
        case HITLS_OCSP_BASICRESP_ADD_RESP:
            return OcspBasicRespAddSingleResp(internal, val, valLen);
        case HITLS_OCSP_BASICRESP_SET_NONCE:
            return OcspSetNonce(&internal->ext, val, valLen);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_CMD_UNSUPPORT);
            return HITLS_OCSP_ERR_CMD_UNSUPPORT;
    }
}

int32_t HITLS_OCSP_BasicRespCtrl(HITLS_OCSP_BasicResp *bs, int32_t cmd, void *val, uint32_t valLen)
{
    if (bs == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    HITLS_OCSP_BasicResp_Internal *internal = (HITLS_OCSP_BasicResp_Internal *)bs;

    if (cmd < HITLS_OCSP_BASICRESP_ADD_RESP) {
        return OcspBasicRespGetCtrl(internal, cmd, val, valLen);
    }
    return OcspBasicRespSetCtrl(internal, cmd, val, valLen);
}

int32_t HITLS_OCSP_BasicRespGetRespCount(const HITLS_OCSP_BasicResp *bs, uint32_t *count)
{
    if (bs == NULL || count == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    const HITLS_OCSP_BasicResp_Internal *internal = (const HITLS_OCSP_BasicResp_Internal *)bs;
    *count = BSL_LIST_COUNT(internal->responses);
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_OCSP_BasicRespGetRespByIndex(const HITLS_OCSP_BasicResp *bs, uint32_t index,
                                            HITLS_OCSP_SingleResp **single)
{
    if (bs == NULL || single == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    const HITLS_OCSP_BasicResp_Internal *internal = (const HITLS_OCSP_BasicResp_Internal *)bs;
    uint32_t count = BSL_LIST_COUNT(internal->responses);
    if (index >= count) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    *single = (HITLS_OCSP_SingleResp *)BSL_LIST_GetIndexNode(index, internal->responses);
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_OCSP_BasicRespFindResp(const HITLS_OCSP_BasicResp *bs, const HITLS_OCSP_CertId *certId,
                                     HITLS_OCSP_SingleResp **single)
{
    if (bs == NULL || certId == NULL || single == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    const HITLS_OCSP_BasicResp_Internal *internal = (const HITLS_OCSP_BasicResp_Internal *)bs;
    BslListNode *node = BSL_LIST_FirstNode(internal->responses);
    while (node != NULL) {
        HITLS_OCSP_SingleResp_Internal *sr = (HITLS_OCSP_SingleResp_Internal *)BSL_LIST_GetData(node);
        if (sr != NULL && sr->certId != NULL && HITLS_OCSP_CertIdCmp(certId, sr->certId) == 0) {
            *single = (HITLS_OCSP_SingleResp *)sr;
            return HITLS_PKI_SUCCESS;
        }
        node = BSL_LIST_GetNextNode(internal->responses, node);
    }
    BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_CERTID_NOT_FOUND);
    return HITLS_OCSP_ERR_CERTID_NOT_FOUND;
}

/* ==================== BasicResp Sign ==================== */

static int32_t OcspCheckBasicRespTbs(const HITLS_OCSP_BasicResp_Internal *internal)
{
    if (internal->responderId->type == HITLS_OCSP_RESPONDERID_BY_NAME) {
        if (internal->responderId->value.byName.data == NULL || internal->responderId->value.byName.dataLen == 0) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_FIELD_NOT_SET);
            return HITLS_OCSP_ERR_FIELD_NOT_SET;
        }
    } else {
        if (internal->responderId->value.byKey.data == NULL || internal->responderId->value.byKey.dataLen == 0) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_FIELD_NOT_SET);
            return HITLS_OCSP_ERR_FIELD_NOT_SET;
        }
    }
    if (BSL_LIST_COUNT(internal->responses) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_EMPTY_RESPONSE);
        return HITLS_OCSP_ERR_EMPTY_RESPONSE;
    }
    BslListNode *node = BSL_LIST_FirstNode(internal->responses);
    while (node != NULL) {
        HITLS_OCSP_SingleResp_Internal *sr =
            (HITLS_OCSP_SingleResp_Internal *)BSL_LIST_GetData(node);
        if (sr->certStatus == HITLS_OCSP_CERT_STATUS_REVOKED && !sr->hasRevocationTime) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_FIELD_NOT_SET);
            return HITLS_OCSP_ERR_FIELD_NOT_SET;
        }
        node = BSL_LIST_GetNextNode(internal->responses, node);
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t OcspEncodeSingleResp(HITLS_OCSP_SingleResp *singleResp, BSL_ASN1_Buffer *out)
{
    HITLS_OCSP_SingleResp_Internal *sr = (HITLS_OCSP_SingleResp_Internal *)singleResp;

    /* Encode CertID, strip T+L for HEADERONLY embedding */
    BSL_ASN1_Buffer certIdDer = {0};
    int32_t ret = OcspEncodeCertId(sr->certId, &certIdDer);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    /* certStatus: CHOICE encoded as ANY HEADERONLY */
    BSL_ASN1_Buffer certStatusAsn = {0};
    if (sr->certStatus == HITLS_OCSP_CERT_STATUS_GOOD) {
        certStatusAsn.tag = BSL_ASN1_CLASS_CTX_SPECIFIC | 0;
        certStatusAsn.len = 0;
        certStatusAsn.buff = NULL;
    } else if (sr->certStatus == HITLS_OCSP_CERT_STATUS_REVOKED) {
        /* RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime, revocationReason [0] EXPLICIT CRLReason OPTIONAL } */
        BSL_ASN1_Buffer revokedAsns[2] = {
            {BSL_ASN1_TAG_GENERALIZEDTIME, sizeof(BSL_TIME), (uint8_t *)&sr->revocationTime},
            {BSL_ASN1_TAG_ENUMERATED, 0, NULL},
        };

        uint8_t reason = 0;
        if (sr->hasRevocationReason) {
            revokedAsns[1].len = sizeof(uint8_t);
            reason = (uint8_t)sr->revocationReason;
            revokedAsns[1].buff = &reason;
        }
        BSL_ASN1_Template tmpl = {g_ocspRevokedInfoTempl,
                                   sizeof(g_ocspRevokedInfoTempl) / sizeof(g_ocspRevokedInfoTempl[0])};
        ret = BSL_ASN1_EncodeTemplate(&tmpl, revokedAsns, 2, &certStatusAsn.buff, &certStatusAsn.len);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_Free(certIdDer.buff);
            return ret;
        }
        certStatusAsn.tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1;
    } else {
        /* unknown */
        certStatusAsn.tag = BSL_ASN1_CLASS_CTX_SPECIFIC | 2;
        certStatusAsn.len = 0;
        certStatusAsn.buff = NULL;
    }

    /* SingleResponse ::= SEQUENCE {
     *     certID      CertID          depth=1 (HEADERONLY)
     *     certStatus  CertStatus      depth=1 (ANY)
     *     thisUpdate  GeneralizedTime depth=1
     *     nextUpdate [0] EXPLICIT GT   depth=1 (OPTIONAL, container)
     *         GeneralizedTime          depth=2 }
     *     singleExtensions     [1]     EXPLICIT Extensions{{re-ocsp-crl |
     *                                        re-ocsp-archive-cutoff |
     *                                        CrlEntryExtensions, ...}
     *                                        } OPTIONAL }
     */
    BSL_ASN1_Buffer srAsns[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, certIdDer.len, certIdDer.buff},
        certStatusAsn,
        {BSL_ASN1_TAG_GENERALIZEDTIME, sizeof(BSL_TIME), (uint8_t *)&sr->thisUpdate},
        {BSL_ASN1_TAG_GENERALIZEDTIME, 0, NULL},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1, 0, NULL},
    };
    if (sr->hasNextUpdate) {
        srAsns[3].len = sizeof(BSL_TIME);
        srAsns[3].buff = (uint8_t *)&sr->nextUpdate;
    }
    /* singleExtensions [1] EXPLICIT (HEADERONLY): OcspEncodeExt emits the full [1] TLV
     * when present and zeroes the buffer when absent (so the optional leaf is omitted). */
    ret = OcspEncodeExt(sr->ext, BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1, &srAsns[4]);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(certIdDer.buff);
        BSL_SAL_Free(certStatusAsn.buff);
        return ret;
    }
    BSL_ASN1_Template templ = {g_ocspSingleRespTempl, sizeof(g_ocspSingleRespTempl) / sizeof(g_ocspSingleRespTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, srAsns, 5, &out->buff, &out->len);

    BSL_SAL_Free(certIdDer.buff);
    BSL_SAL_Free(certStatusAsn.buff);
    BSL_SAL_Free(srAsns[4].buff);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    out->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    return HITLS_PKI_SUCCESS;
}

/* RFC 6960 responseStatus values: 0,1,2,3,5,6 (4 is reserved and must be rejected). */
static bool OcspIsValidRespStatus(int32_t status)
{
    switch (status) {
        case HITLS_OCSP_RESP_STATUS_SUCCESSFUL:
        case HITLS_OCSP_RESP_STATUS_MALFORMED_REQUEST:
        case HITLS_OCSP_RESP_STATUS_INTERNAL_ERROR:
        case HITLS_OCSP_RESP_STATUS_TRY_LATER:
        case HITLS_OCSP_RESP_STATUS_SIG_REQUIRED:
        case HITLS_OCSP_RESP_STATUS_UNAUTHORIZED:
            return true;
        default:
            return false;
    }
}

static int32_t OcspEncodeRespExt(HITLS_X509_Ext *ocspExt, BSL_ASN1_Buffer *extData)
{
    return OcspEncodeExt(ocspExt,
        BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1, extData);
}

/* Build the ResponderID TLV: byName [1] Name (HEADERONLY) or byKey [2] EXPLICIT OCTET
 * STRING KeyHash. *keyHashOctetDer is set only for byKey (caller frees). */
static int32_t OcspEncodeResponderId(const HITLS_OCSP_BasicResp_Internal *internal, BSL_ASN1_Buffer *responderIdAsn,
                                     uint8_t **keyHashOctetDer)
{
    if (internal->responderId->type == HITLS_OCSP_RESPONDERID_BY_NAME) {
        responderIdAsn->tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1;
        responderIdAsn->len = internal->responderId->value.byName.dataLen;
        responderIdAsn->buff = internal->responderId->value.byName.data;
        return HITLS_PKI_SUCCESS;
    }

    /* RFC 6960: byKey [2] EXPLICIT OCTET STRING KeyHash. */
    uint8_t *keyHashData = internal->responderId->value.byKey.data;
    uint32_t keyHashLen = internal->responderId->value.byKey.dataLen;
    BSL_ASN1_Buffer keyHashAsn = {BSL_ASN1_TAG_OCTETSTRING, keyHashLen, keyHashData};
    BSL_ASN1_TemplateItem octetTempl[] = {{BSL_ASN1_TAG_OCTETSTRING, 0, 0}};
    BSL_ASN1_Template octetTmpl = {octetTempl, 1};
    uint32_t octetDerLen = 0;
    int32_t ret = BSL_ASN1_EncodeTemplate(&octetTmpl, &keyHashAsn, 1, keyHashOctetDer, &octetDerLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    responderIdAsn->tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 2;
    responderIdAsn->len = octetDerLen;
    responderIdAsn->buff = *keyHashOctetDer;
    return HITLS_PKI_SUCCESS;
}

/* Encode all SingleResponses into a SEQUENCE OF TLV. Output is owned by caller (free buff). */
static int32_t OcspEncodeResponses(const HITLS_OCSP_BasicResp_Internal *internal, BSL_ASN1_Buffer *responsesSeq)
{
    uint32_t count = BSL_LIST_COUNT(internal->responses);
    if (count == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_EMPTY_RESPONSE);
        return HITLS_OCSP_ERR_EMPTY_RESPONSE;
    }
    BSL_ASN1_Buffer *respAsns = BSL_SAL_Calloc(count, sizeof(BSL_ASN1_Buffer));
    if (respAsns == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    uint32_t i = 0;
    int32_t ret = HITLS_PKI_SUCCESS;
    BslListNode *node = BSL_LIST_FirstNode(internal->responses);
    while (node != NULL) {
        HITLS_OCSP_SingleResp *singleResp = (HITLS_OCSP_SingleResp *)BSL_LIST_GetData(node);
        ret = OcspEncodeSingleResp(singleResp, &respAsns[i]);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
        i++;
        node = BSL_LIST_GetNextNode(internal->responses, node);
    }

    BSL_ASN1_Template elemTempl = {g_ocspSingleRespElemEncTempl,
                                   sizeof(g_ocspSingleRespElemEncTempl) / sizeof(g_ocspSingleRespElemEncTempl[0])};
    ret = BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SEQUENCE, count, &elemTempl, respAsns, i, responsesSeq);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    for (uint32_t j = 0; j < i; j++) {
        BSL_SAL_Free(respAsns[j].buff);
    }
    BSL_SAL_Free(respAsns);
    return HITLS_PKI_SUCCESS;

EXIT:
    for (uint32_t j = 0; j < i; j++) {
        BSL_SAL_Free(respAsns[j].buff);
    }
    BSL_SAL_Free(respAsns);
    return ret;
}

static int32_t OcspEncodeResponseData(HITLS_OCSP_BasicResp_Internal *internal, BSL_ASN1_Buffer *out)
{
    int32_t ret = HITLS_PKI_SUCCESS;
    uint8_t *keyHashOctetDer = NULL;
    /* ResponderID: byName [1] Name (HEADERONLY) or byKey [2] KeyHash (HEADERONLY) */
    BSL_ASN1_Buffer responderIdAsn = {0};
    ret = OcspEncodeResponderId(internal, &responderIdAsn, &keyHashOctetDer);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    BSL_ASN1_Buffer responsesSeq = {0};
    ret = OcspEncodeResponses(internal, &responsesSeq);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(keyHashOctetDer);
        return ret;
    }

    /* Encode extension if present */
    BSL_ASN1_Buffer responseExtensions = {0};
    ret = OcspEncodeRespExt(internal->ext, &responseExtensions);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_Free(responsesSeq.buff);
        BSL_SAL_Free(keyHashOctetDer);
        return ret;
    }

    BSL_ASN1_Buffer respDataAsns[4] = {
        responderIdAsn,
        {BSL_ASN1_TAG_GENERALIZEDTIME, sizeof(BSL_TIME), (uint8_t *)&internal->producedAt},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, responsesSeq.len, responsesSeq.buff},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1, responseExtensions.len, responseExtensions.buff},
    };
    BSL_ASN1_Template templ = {g_ocspRespDataEncTempl,
                                sizeof(g_ocspRespDataEncTempl) / sizeof(g_ocspRespDataEncTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, respDataAsns, 4, &out->buff, &out->len);
    BSL_SAL_Free(responsesSeq.buff);
    BSL_SAL_Free(responseExtensions.buff);
    BSL_SAL_Free(keyHashOctetDer);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    out->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    return HITLS_PKI_SUCCESS;
}

static int32_t OcspResponderIdNewFromCert(const HITLS_X509_Cert *cert, HITLS_OCSP_ResponderIdType type,
                                          HITLS_OCSP_ResponderId **responderId)
{
    HITLS_OCSP_ResponderId *rid = BSL_SAL_Calloc(1, sizeof(HITLS_OCSP_ResponderId));
    if (rid == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    rid->type = type;

    int32_t ret = HITLS_PKI_SUCCESS;
    if (type == HITLS_OCSP_RESPONDERID_BY_NAME) {
        BSL_Buffer dnDer = {0};
        ret = HITLS_X509_CertCtrl((HITLS_X509_Cert *)(uintptr_t)cert, HITLS_X509_GET_ENCODE_SUBJECT_DN, &dnDer,
                                  sizeof(BSL_Buffer *));
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        rid->value.byName.data = dnDer.data;
        rid->value.byName.dataLen = dnDer.dataLen;
    } else if (type == HITLS_OCSP_RESPONDERID_BY_KEY) {
        CRYPT_EAL_MdCtx *mdCtx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA1);
        if (mdCtx == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            ret = BSL_MALLOC_FAIL;
            goto EXIT;
        }
        rid->value.byKey.data = BSL_SAL_Malloc(CRYPT_SHA1_DIGEST_SIZE);
        if (rid->value.byKey.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            CRYPT_EAL_MdFreeCtx(mdCtx);
            ret = BSL_MALLOC_FAIL;
            goto EXIT;
        }
        uint32_t keyHashLen = CRYPT_SHA1_DIGEST_SIZE;
        ret = OcspGetPubKeyHash(mdCtx, cert, rid->value.byKey.data, &keyHashLen);
        CRYPT_EAL_MdFreeCtx(mdCtx);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
        rid->value.byKey.dataLen = keyHashLen;
    } else {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        ret = HITLS_OCSP_ERR_INVALID_PARAM;
        goto EXIT;
    }

    *responderId = rid;
    return HITLS_PKI_SUCCESS;

EXIT:
    OcspResponderIdFree(rid);
    return ret;
}

static int32_t OcspBasicRespSignCb(int32_t mdId, CRYPT_EAL_PkeyCtx *prvKey,
    HITLS_X509_Asn1AlgId *signAlgId, void *obj)
{
    HITLS_OCSP_BasicResp_Internal *internal = (HITLS_OCSP_BasicResp_Internal *)obj;
    internal->signAlgId = *signAlgId;

    BSL_ASN1_Buffer respDataAsn = {0};
    int32_t ret = OcspEncodeResponseData(internal, &respDataAsn);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    /* Strip outer SEQUENCE tag+length so SignAsn1Data wraps content correctly */
    uint8_t *contentPtr = respDataAsn.buff;
    uint32_t contentLen = respDataAsn.len;
    uint32_t valLen = 0;
    ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
                                &contentPtr, &contentLen, &valLen);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(respDataAsn.buff);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Buffer respDataContent = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
                                        valLen, contentPtr};

    ret = HITLS_X509_SignAsn1Data(prvKey, (CRYPT_MD_AlgId)mdId, &respDataContent,
                                  &internal->tbsRawData, &internal->signature);
    BSL_SAL_Free(respDataAsn.buff);
    return ret;
}

/* Validate signer/params before signing: SM2 keys are rejected (OCSP no longer supports
 * SM2), and the private key must match the signer certificate. */
/* Auto-generate producedAt and the ResponderID from the signer cert before signing. */
static int32_t OcspSignPrepareResponderId(HITLS_OCSP_BasicResp_Internal *internal, const HITLS_X509_Cert *signerCert,
                                          HITLS_OCSP_SignFlag flags)
{
    BSL_TIME now = {0};
    int32_t ret = BSL_SAL_SysTimeGet(&now);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    internal->producedAt = now;

    /* byName default, byKey via flag. */
    HITLS_OCSP_ResponderIdType ridType = HITLS_OCSP_RESPONDERID_BY_NAME;
    if (flags & HITLS_OCSP_SIGN_RESPID_BYKEY) {
        ridType = HITLS_OCSP_RESPONDERID_BY_KEY;
    }
    OcspResponderIdFree(internal->responderId);
    internal->responderId = NULL;
    ret = OcspResponderIdNewFromCert(signerCert, ridType, &internal->responderId);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_OCSP_BasicRespSign(int32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam,
                                 const HITLS_X509_Cert *signerCert, const HITLS_X509_List *certs,
                                 HITLS_OCSP_BasicResp *bs, HITLS_OCSP_SignFlag flags)
{
    if (bs == NULL || prvKey == NULL || signerCert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }

    /* Validate flags: only NOCERTS and RESPID_BYKEY are supported; byName is the default */
    if (flags & ~(HITLS_OCSP_SIGN_NOCERTS | HITLS_OCSP_SIGN_RESPID_BYKEY)) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }

    int32_t ret = OcspCheckSignKey(prvKey, signerCert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    HITLS_OCSP_BasicResp_Internal *internal = (HITLS_OCSP_BasicResp_Internal *)bs;
    if (internal->isSigned) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_ALREADY_SIGNED);
        return HITLS_OCSP_ERR_ALREADY_SIGNED;
    }

    ret = OcspSignPrepareResponderId(internal, signerCert, flags);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = OcspCheckBasicRespTbs(internal);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    BSL_SAL_FREE(internal->signature.buff);
    BSL_SAL_FREE(internal->tbsRawData.data);
    BSL_LIST_FREE(internal->certs, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);

    if (!(flags & HITLS_OCSP_SIGN_NOCERTS)) {
        ret = OcspRefUpSignerCerts(signerCert, certs, &internal->certs);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
    }

    ret = HITLS_X509_Sign(mdId, prvKey, algParam, internal, OcspBasicRespSignCb);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    internal->isSigned = true;
    /* Freeze every SingleResp: their fields are now covered by the response
     * signature, so later mutation would desynchronize them from the signed
     * ResponseData (RFC 6960 §3.2). */
    BslListNode *node = BSL_LIST_FirstNode(internal->responses);
    while (node != NULL) {
        HITLS_OCSP_SingleResp_Internal *single = (HITLS_OCSP_SingleResp_Internal *)BSL_LIST_GetData(node);
        if (single != NULL) {
            single->frozen = true;
        }
        node = BSL_LIST_GetNextNode(internal->responses, node);
    }
    return HITLS_PKI_SUCCESS;

EXIT:
    OcspResponderIdFree(internal->responderId);
    internal->responderId = NULL;
    BSL_SAL_FREE(internal->signature.buff);
    BSL_SAL_FREE(internal->tbsRawData.data);
    BSL_LIST_FREE(internal->certs, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return ret;
}

/* ==================== Resp ==================== */

HITLS_OCSP_Resp *HITLS_OCSP_RespNew(HITLS_OCSP_RespStatus status, HITLS_OCSP_BasicResp *bs)
{
    if (!OcspIsValidRespStatus(status)) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return NULL;
    }
    if (status == HITLS_OCSP_RESP_STATUS_SUCCESSFUL && bs == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return NULL;
    }
    if (bs != NULL && status != HITLS_OCSP_RESP_STATUS_SUCCESSFUL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return NULL;
    }
    if (bs != NULL) {
        HITLS_OCSP_BasicResp_Internal *bsInternal = (HITLS_OCSP_BasicResp_Internal *)bs;
        if (!bsInternal->isSigned) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NOT_SIGNED);
            return NULL;
        }
    }

    HITLS_OCSP_Resp_Internal *internal = BSL_SAL_Calloc(1, sizeof(HITLS_OCSP_Resp_Internal));
    if (internal == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    internal->status = status;

    if (bs != NULL) {
        internal->basicResp = bs;
    }

    return (HITLS_OCSP_Resp *)internal;
}

void HITLS_OCSP_RespFree(HITLS_OCSP_Resp *resp)
{
    if (resp == NULL) {
        return;
    }
    HITLS_OCSP_Resp_Internal *internal = (HITLS_OCSP_Resp_Internal *)resp;
    if (internal->basicResp != NULL) {
        HITLS_OCSP_BasicRespFree(internal->basicResp);
    }
    BSL_SAL_Free(internal);
}

int32_t HITLS_OCSP_RespCtrl(HITLS_OCSP_Resp *resp, int32_t cmd, void *val, uint32_t valLen)
{
    if (resp == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    HITLS_OCSP_Resp_Internal *internal = (HITLS_OCSP_Resp_Internal *)resp;
    switch (cmd) {
        case HITLS_OCSP_RESP_GET_STATUS:
            if (val == NULL || valLen < sizeof(int32_t)) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            *(int32_t *)val = internal->status;
            return HITLS_PKI_SUCCESS;
        case HITLS_OCSP_RESP_GET_BASIC:
            if (val == NULL || valLen < sizeof(HITLS_OCSP_BasicResp *)) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            if (internal->basicResp == NULL) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_FIELD_NOT_PRESENT);
                return HITLS_OCSP_ERR_FIELD_NOT_PRESENT;
            }
            *(HITLS_OCSP_BasicResp **)val = internal->basicResp;
            return HITLS_PKI_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_CMD_UNSUPPORT);
            return HITLS_OCSP_ERR_CMD_UNSUPPORT;
    }
}

/* ==================== Resp Verify ==================== */

static bool OcspMatchResponderId(const HITLS_OCSP_BasicResp_Internal *bs, const HITLS_X509_Cert *cert)
{
    const HITLS_OCSP_ResponderId *rid = bs->responderId;
    if (rid == NULL) {
        /* A fresh (never signed nor parsed) BasicResp has no ResponderID; it cannot match. */
        return false;
    }
    if (rid->type == HITLS_OCSP_RESPONDERID_BY_NAME) {
        BSL_Buffer dnDer = {0};
        int32_t ret = HITLS_X509_CertCtrl((HITLS_X509_Cert *)(uintptr_t)cert, HITLS_X509_GET_ENCODE_SUBJECT_DN,
                                          &dnDer, sizeof(BSL_Buffer *));
        if (ret != HITLS_PKI_SUCCESS) {
            return false;
        }
        bool match = (dnDer.dataLen == rid->value.byName.dataLen &&
                      memcmp(dnDer.data, rid->value.byName.data, dnDer.dataLen) == 0);
        BSL_SAL_Free(dnDer.data);
        return match;
    }
    if (rid->type == HITLS_OCSP_RESPONDERID_BY_KEY) {
        /* RFC 6960 §4.2.1: byKey is the SHA-1 hash of the responder's public key
         * (excluding tag and length fields), so SHA-1 is mandated here. */
        CRYPT_EAL_MdCtx *mdCtx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA1);
        if (mdCtx == NULL) {
            return false;
        }
        uint8_t keyHash[CRYPT_SHA1_DIGEST_SIZE] = {0};
        uint32_t keyHashLen = sizeof(keyHash);
        int32_t ret = OcspGetPubKeyHash(mdCtx, cert, keyHash, &keyHashLen);
        CRYPT_EAL_MdFreeCtx(mdCtx);
        if (ret != HITLS_PKI_SUCCESS) {
            return false;
        }
        return (keyHashLen == rid->value.byKey.dataLen &&
                memcmp(keyHash, rid->value.byKey.data, keyHashLen) == 0);
    }
    return false;
}

static int32_t OcspFindSignerInList(const HITLS_OCSP_BasicResp_Internal *bs, const BslList *certs,
                                     HITLS_X509_Cert **signer)
{
    if (certs == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    BslListNode *node = BSL_LIST_FirstNode(certs);
    while (node != NULL) {
        HITLS_X509_Cert *cert = (HITLS_X509_Cert *)BSL_LIST_GetData(node);
        if (OcspMatchResponderId(bs, cert)) {
            /* Borrowed pointer: ownership stays with certs. Callers that hand the pointer
             * to the API user must take their own reference. */
            *signer = cert;
            return HITLS_PKI_SUCCESS;
        }
        node = BSL_LIST_GetNextNode(certs, node);
    }
    return HITLS_PKI_SUCCESS;
}

/* Takes one additional reference on the located signer certificate so that the pointer
 * returned to the API user stays valid after bs and the searched cert list are released.
 * On failure *signer is reset to NULL so the caller never sees an un-referenced pointer. */
static int32_t OcspSignerRefUp(HITLS_X509_Cert **signer)
{
    int32_t ref = 0;
    int32_t ret = HITLS_X509_CertCtrl(*signer, HITLS_X509_REF_UP, &ref, sizeof(int));
    if (ret != HITLS_PKI_SUCCESS) {
        *signer = NULL;
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_OCSP_BasicRespGetSigner(const HITLS_OCSP_BasicResp *bs, const HITLS_X509_List *certs,
                                       HITLS_X509_Cert **signer)
{
    if (bs == NULL || signer == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    if (*signer != NULL) {
        /* The output must be NULL on entry; a pre-filled pointer would be overwritten (leaking it). */
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    const HITLS_OCSP_BasicResp_Internal *internal = (const HITLS_OCSP_BasicResp_Internal *)bs;

    /* Try external certs first */
    int32_t ret = OcspFindSignerInList(internal, certs, signer);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (*signer != NULL) {
        return OcspSignerRefUp(signer);
    }

    /* Fall back to embedded certs */
    ret = OcspFindSignerInList(internal, internal->certs, signer);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (*signer == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_SIGNER_NOT_FOUND);
        return HITLS_OCSP_ERR_SIGNER_NOT_FOUND;
    }
    return OcspSignerRefUp(signer);
}

/* Detect whether all SingleResponse CertIDs reference the same issuer
 * (same hashAlg + issuerNameHash + issuerKeyHash).
 * - All equivalent: *outCertId is set to the common CertID so the caller runs a
 *   single issuer match.
 * - Different hash alg: CertIDs cannot be compared directly; *outCertId stays NULL
 *   and the caller checks each SingleResponse's CertID individually.
 * - Same hash alg but different issuer: rejected with CERTID_INCONSISTENT.
 * Returns an error only for structural problems (empty/invalid response). */
static int32_t OcspCheckIds(const HITLS_OCSP_BasicResp_Internal *bs,
                           const HITLS_OCSP_CertId_Internal **outCertId)
{
    if (BSL_LIST_COUNT(bs->responses) <= 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_EMPTY_RESPONSE);
        return HITLS_OCSP_ERR_EMPTY_RESPONSE;
    }
    BslListNode *node = BSL_LIST_FirstNode(bs->responses);
    if (node == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_EMPTY_RESPONSE);
        return HITLS_OCSP_ERR_EMPTY_RESPONSE;
    }
    HITLS_OCSP_SingleResp_Internal *firstSr = (HITLS_OCSP_SingleResp_Internal *)BSL_LIST_GetData(node);
    if (firstSr == NULL || firstSr->certId == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
        return HITLS_OCSP_ERR_INVALID_RESPONSE;
    }
    const HITLS_OCSP_CertId_Internal *firstId = (const HITLS_OCSP_CertId_Internal *)firstSr->certId;

    node = BSL_LIST_GetNextNode(bs->responses, node);
    while (node != NULL) {
        HITLS_OCSP_SingleResp_Internal *sr = (HITLS_OCSP_SingleResp_Internal *)BSL_LIST_GetData(node);
        if (sr == NULL || sr->certId == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
            return HITLS_OCSP_ERR_INVALID_RESPONSE;
        }
        const HITLS_OCSP_CertId_Internal *curId = (const HITLS_OCSP_CertId_Internal *)sr->certId;
        if (firstId->hashAlg != curId->hashAlg) {
            *outCertId = NULL;
            return HITLS_PKI_SUCCESS;
        }
        if (!OcspCertIdIssuerMatch(firstId, curId)) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_CERTID_INCONSISTENT);
            return HITLS_OCSP_ERR_CERTID_INCONSISTENT;
        }
        node = BSL_LIST_GetNextNode(bs->responses, node);
    }
    *outCertId = firstId;
    return HITLS_PKI_SUCCESS;
}

/* Match a certificate against a CertID's issuer fields (issuerNameHash + issuerKeyHash).
 * Returns HITLS_PKI_SUCCESS on match, HITLS_OCSP_ERR_DELEGATE_AUTH on no match,
 * or other error code on internal failure. */
static int32_t OcspMatchIssuerId(const HITLS_X509_Cert *cert,
                                const HITLS_OCSP_CertId_Internal *cid)
{
    CRYPT_EAL_MdCtx *mdCtx = CRYPT_EAL_MdNewCtx(cid->hashAlg);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    uint8_t nameHash[64] = {0};
    uint32_t nameHashLen = sizeof(nameHash);
    int32_t ret = OcspGetNameHash(mdCtx, cert, HITLS_X509_GET_ENCODE_SUBJECT_DN, nameHash, &nameHashLen);
    if (ret != HITLS_PKI_SUCCESS) {
        CRYPT_EAL_MdFreeCtx(mdCtx);
        return ret;
    }
    if (nameHashLen != cid->issuerNameHash.len ||
        memcmp(nameHash, cid->issuerNameHash.buff, nameHashLen) != 0) {
        CRYPT_EAL_MdFreeCtx(mdCtx);
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_DELEGATE_AUTH);
        return HITLS_OCSP_ERR_DELEGATE_AUTH;
    }

    uint8_t keyHash[64] = {0};
    uint32_t keyHashLen = sizeof(keyHash);
    ret = OcspGetPubKeyHash(mdCtx, cert, keyHash, &keyHashLen);
    CRYPT_EAL_MdFreeCtx(mdCtx);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (keyHashLen != cid->issuerKeyHash.len ||
        memcmp(keyHash, cid->issuerKeyHash.buff, keyHashLen) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_DELEGATE_AUTH);
        return HITLS_OCSP_ERR_DELEGATE_AUTH;
    }
    return HITLS_PKI_SUCCESS;
}

/* Match a cert against the issuer(s) referenced by the response.
 * - cid != NULL: all CertIDs share the same issuer, so a single match suffices.
 * - cid == NULL: CertIDs are not all equivalent; the cert must match EVERY
 *   SingleResponse's CertID issuer. */
static int32_t OcspBsMatchIssuerId(const HITLS_OCSP_BasicResp_Internal *bs, const HITLS_X509_Cert *cert,
                                   const HITLS_OCSP_CertId_Internal *cid)
{
    if (cid != NULL) {
        return OcspMatchIssuerId(cert, cid);
    }

    if (BSL_LIST_COUNT(bs->responses) <= 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_EMPTY_RESPONSE);
        return HITLS_OCSP_ERR_EMPTY_RESPONSE;
    }

    BslListNode *node = BSL_LIST_FirstNode(bs->responses);
    while (node != NULL) {
        HITLS_OCSP_SingleResp_Internal *sr = (HITLS_OCSP_SingleResp_Internal *)BSL_LIST_GetData(node);
        if (sr == NULL || sr->certId == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
            return HITLS_OCSP_ERR_INVALID_RESPONSE;
        }
        int32_t ret = OcspMatchIssuerId(cert, sr->certId);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
        node = BSL_LIST_GetNextNode(bs->responses, node);
    }
    return HITLS_PKI_SUCCESS;
}

/* Check that signer cert has id-kp-OCSPSigning EKU extension (RFC 6960 §4.2.2.2).
 * Returns HITLS_PKI_SUCCESS if the signer is a delegated responder,
 * HITLS_OCSP_ERR_NO_OCSPSIGNING_EXKUSAGE if it is not, or an internal error code. */
static int32_t OcspCheckDelegated(HITLS_X509_Cert *signer)
{
    HITLS_X509_ExtExKeyUsage exku = {0};
    int32_t ret = HITLS_X509_CertCtrl(signer, HITLS_X509_EXT_GET_EXKUSAGE, &exku, sizeof(exku));
    if (ret == HITLS_X509_ERR_EXT_NOT_FOUND) {
        /* No extended key usage extension: the signer is not a delegated responder. */
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NO_OCSPSIGNING_EXKUSAGE);
        return HITLS_OCSP_ERR_NO_OCSPSIGNING_EXKUSAGE;
    }
    if (ret != HITLS_PKI_SUCCESS) {
        return ret; /* internal error, already pushed by the callee */
    }

    bool found = false;
    BslListNode *node = BSL_LIST_FirstNode(exku.oidList);
    while (node != NULL) {
        BSL_Buffer *oidBuf = (BSL_Buffer *)BSL_LIST_GetData(node);
        if (oidBuf != NULL && oidBuf->data != NULL && oidBuf->dataLen > 0 &&
            BSL_OBJ_GetCidFromOidBuff(oidBuf->data, oidBuf->dataLen) == BSL_CID_KP_OCSPSIGNING) {
            found = true;
            break;
        }
        node = BSL_LIST_GetNextNode(exku.oidList, node);
    }
    HITLS_X509_ClearExtendedKeyUsage(&exku);

    if (!found) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NO_OCSPSIGNING_EXKUSAGE);
        return HITLS_OCSP_ERR_NO_OCSPSIGNING_EXKUSAGE;
    }

    /* RFC 5280 §4.2.1.12: KeyUsage and Extended KeyUsage must both be satisfied
     * for the certificate's actual use. A delegated responder signs responses,
     * so a present KeyUsage must permit digitalSignature; an absent KeyUsage
     * (HITLS_X509_ERR_KU_IS_NONE) imposes no restriction. */
    uint32_t keyUsage = 0;
    ret = HITLS_X509_CertCtrl(signer, HITLS_X509_EXT_GET_KUSAGE, &keyUsage, sizeof(keyUsage));
    if (ret == HITLS_X509_ERR_KU_IS_NONE) {
        return HITLS_PKI_SUCCESS;
    }
    if (ret != HITLS_PKI_SUCCESS) {
        return ret; /* internal error, already pushed by the callee */
    }
    if ((keyUsage & HITLS_X509_EXT_KU_DIGITAL_SIGN) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NO_SIGN_KEYUSAGE);
        return HITLS_OCSP_ERR_NO_SIGN_KEYUSAGE;
    }
    return HITLS_PKI_SUCCESS;
}

/* RFC 6960 §4.2.2.2: Verify the signer is authorized to sign OCSP responses.
 * (RFC condition 1 - a locally configured signing authority - is handled separately by
 *  HITLS_OCSP_VFY_TRUSTOTHER, which skips this function.)
 *
 * Check order (RFC condition 2 first as the common case):
 * - RFC condition 2: Signer IS the CA that issued the target certs (direct signing).
 * - RFC condition 3: Signer is a delegated responder: issued by the target CA and has
 *   id-kp-OCSPSigning EKU.
 *
 * Returns HITLS_PKI_SUCCESS if authorized, error code otherwise.
 */
static int32_t OcspCheckIssuer(const HITLS_OCSP_BasicResp_Internal *bs,
                               HITLS_X509_Cert *signer, HITLS_X509_Cert *signerIssuer)
{
    /* Check all CertIDs share the same issuer */
    const HITLS_OCSP_CertId_Internal *certId = NULL;
    int32_t ret = OcspCheckIds(bs, &certId);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    /* RFC condition 2: signer IS the CA that issued the target certs */
    ret = OcspBsMatchIssuerId(bs, signer, certId);
    if (ret == HITLS_PKI_SUCCESS) {
        return HITLS_PKI_SUCCESS;
    }
    if (ret != HITLS_OCSP_ERR_DELEGATE_AUTH) {
        return ret; /* internal error */
    }

    /* RFC condition 3: signer is a delegated responder. The signerIssuer (captured
     * by the verify callback from the verified chain) must match the CertID
     * issuer, and the signer must have id-kp-OCSPSigning EKU. */
    if (signerIssuer == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_DELEGATE_AUTH);
        return HITLS_OCSP_ERR_DELEGATE_AUTH;
    }
    ret = OcspBsMatchIssuerId(bs, signerIssuer, certId);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return OcspCheckDelegated(signer);
}

static int32_t OcspVerifySignature(const HITLS_OCSP_BasicResp_Internal *bs, HITLS_X509_Cert *signer)
{
    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    int32_t ret = HITLS_X509_CertCtrl(signer, HITLS_X509_GET_PUBKEY, &pubKey, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HITLS_X509_CheckSignature(pubKey, bs->tbsRawData.data, bs->tbsRawData.dataLen, &bs->signAlgId,
        &bs->signature);
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_SIGN_VERIFY);
        return HITLS_OCSP_ERR_SIGN_VERIFY;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t OcspAddCertsToCerts(const HITLS_X509_List *sourceCerts, HITLS_X509_List *dstCerts)
{
    if (sourceCerts == NULL) {
        return HITLS_PKI_SUCCESS;
    }
    BslListNode *node = BSL_LIST_FirstNode(sourceCerts);
    while (node != NULL) {
        HITLS_X509_Cert *cert = (HITLS_X509_Cert *)BSL_LIST_GetData(node);
        int32_t ret = BSL_LIST_AddElement(dstCerts, cert, BSL_LIST_POS_END);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        node = BSL_LIST_GetNextNode(sourceCerts, node);
    }
    return HITLS_PKI_SUCCESS;
}

static void OcspFreeListData(void *data)
{
    (void)data;
}

int32_t OcspVerifySigner(const HITLS_X509_List *embeddedCerts, const HITLS_X509_List *certs,
                         const HITLS_X509_StoreCtx *storeCtx, HITLS_X509_Cert *signer, HITLS_X509_Cert **signerIssuer)
{
    if (storeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }

    HITLS_X509_StoreCtx *newStoreCtx = HITLS_X509_StoreCtxDup(storeCtx);
    if (newStoreCtx == NULL) {
        return BSL_MALLOC_FAIL;
    }

    int32_t keepCertChain = 1;
    int32_t ret =
        HITLS_X509_StoreCtxCtrl(newStoreCtx, HITLS_X509_STORECTX_SET_KEEP_CERT_CHAIN, &keepCertChain, sizeof(int32_t));
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_StoreCtxFree(newStoreCtx);
        return ret;
    }

    /* Build chain: signer + external certs + embedded certs */
    HITLS_X509_List *certChain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (certChain == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        HITLS_X509_StoreCtxFree(newStoreCtx);
        return BSL_MALLOC_FAIL;
    }
    ret = BSL_LIST_AddElement(certChain, signer, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        goto EXIT;
    }
    ret = OcspAddCertsToCerts(certs, certChain);
    if (ret != BSL_SUCCESS) {
        goto EXIT;
    }
    ret = OcspAddCertsToCerts(embeddedCerts, certChain);
    if (ret != BSL_SUCCESS) {
        goto EXIT;
    }

    /* Chain verification: build and verify chain to trusted root. With
     * keepCertChain enabled the built chain survives the successful return
     * and stays owned by newStoreCtx (released by StoreCtxFree below). */
    ret = HITLS_X509_CertVerify(newStoreCtx, certChain);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    /* Built chain layout: [signer, signer's issuer, ..., root]; index 1 is
     * the signer's issuer, which the authorization check needs. */
    HITLS_X509_List *builtChain = NULL;
    ret = HITLS_X509_StoreCtxCtrl(newStoreCtx, HITLS_X509_STORECTX_GET_CERT_CHAIN, &builtChain,
                                  sizeof(HITLS_X509_List *));
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    HITLS_X509_Cert *issuer = (HITLS_X509_Cert *)BSL_LIST_GetIndexNode(1, builtChain);
    if (issuer == NULL) {
        /* The chain has a single cert, i.e. the signer is itself the trusted root.
         * It has no issuer, so *signerIssuer stays NULL and the authorization check
         * (OcspCheckIssuer condition 1: signer is the target CertID issuer) decides. */
        *signerIssuer = NULL;
        ret = HITLS_PKI_SUCCESS;
        goto EXIT;
    }
    int32_t ref = 0;
    ret = HITLS_X509_CertCtrl(issuer, HITLS_X509_REF_UP, &ref, sizeof(int));
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    *signerIssuer = issuer;

EXIT:
    BSL_LIST_FREE(certChain, (BSL_LIST_PFUNC_FREE)OcspFreeListData);
    HITLS_X509_StoreCtxFree(newStoreCtx);
    return ret;
}

int32_t HITLS_OCSP_BasicRespVerify(const HITLS_OCSP_BasicResp *bs, const HITLS_X509_List *certs,
                                   const HITLS_X509_StoreCtx *storeCtx, HITLS_OCSP_VfyFlag flags)
{
    if (bs == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }

    /* Validate flags: only TRUSTOTHER and NOINTERN are supported */
    if (flags & ~(HITLS_OCSP_VFY_TRUSTOTHER | HITLS_OCSP_VFY_NOINTERN)) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }

    const HITLS_OCSP_BasicResp_Internal *internal = (const HITLS_OCSP_BasicResp_Internal *)bs;
    if (!internal->isSigned) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NOT_SIGNED);
        return HITLS_OCSP_ERR_NOT_SIGNED;
    }

    /* Locate signer: prefer external certs first */
    HITLS_X509_Cert *signer = NULL;
    int32_t ret = OcspFindSignerInList(internal, certs, &signer);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    bool signerFromExternal = (signer != NULL);

    /* Fall back to embedded certs unless NOINTERN */
    if (signer == NULL && !(flags & HITLS_OCSP_VFY_NOINTERN)) {
        ret = OcspFindSignerInList(internal, internal->certs, &signer);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    if (signer == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_SIGNER_NOT_FOUND);
        return HITLS_OCSP_ERR_SIGNER_NOT_FOUND;
    }

    /* Verify signature (always) */
    ret = OcspVerifySignature(internal, signer);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    if (signerFromExternal && (flags & HITLS_OCSP_VFY_TRUSTOTHER)) {
        /* RFC 6960 §4.2.2.2 condition 1: the caller-supplied external signer certificate
         * is treated as a locally configured OCSP signing authority. Chain/path validation
         * and the issuer/delegation authorization checks are skipped; only the response
         * signature is verified (done above). */
        return HITLS_PKI_SUCCESS;
    }

    /* Chain verification: verify signer chain to trusted root */
    HITLS_X509_Cert *signerIssuer = NULL;
    ret = OcspVerifySigner(internal->certs, certs, storeCtx, signer, &signerIssuer);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    /* Authorization check: verify signer is authorized for the target certs */
    ret = OcspCheckIssuer(internal, signer, signerIssuer);
    HITLS_X509_CertFree(signerIssuer);
    return ret;
}

int32_t HITLS_OCSP_CheckValidity(const HITLS_OCSP_SingleResp *single, int64_t driftSec, int64_t maxageSec)
{
    if (single == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    if (driftSec < 0 || maxageSec < 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    const HITLS_OCSP_SingleResp_Internal *internal = (const HITLS_OCSP_SingleResp_Internal *)single;

    BSL_TIME now = {0};
    int32_t ret = BSL_SAL_SysTimeGet(&now);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* Check thisUpdate is not too far in the future (drift). Written as a difference
     * comparison (a > b + s <=> a - b > s): both UTC values are bounded by the
     * uint16 BSL_TIME.year range, so the subtraction never overflows even though
     * driftSec/maxageSec are unbounded caller inputs. */
    int64_t thisUtc = 0;
    ret = BSL_SAL_DateToUtcTimeConvert(&internal->thisUpdate, &thisUtc);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    int64_t nowUtc = 0;
    ret = BSL_SAL_DateToUtcTimeConvert(&now, &nowUtc);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (thisUtc - nowUtc > driftSec) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NOT_YET_VALID);
        return HITLS_OCSP_ERR_NOT_YET_VALID;
    }

    /* Check thisUpdate is not too old (maxage). maxageSec == 0 disables this check. */
    if (maxageSec > 0 && nowUtc - thisUtc > maxageSec) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_TOO_OLD);
        return HITLS_OCSP_ERR_TOO_OLD;
    }

    /* If nextUpdate is present, check not expired */
    if (internal->hasNextUpdate) {
        int64_t nextUtc = 0;
        ret = BSL_SAL_DateToUtcTimeConvert(&internal->nextUpdate, &nextUtc);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (nextUtc < thisUtc) {
            /* RFC 6960 §4.2.2.1: nextUpdate must not precede thisUpdate. */
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_VALIDITY);
            return HITLS_OCSP_ERR_VALIDITY;
        }
        if (nowUtc - nextUtc > driftSec) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_HAS_EXPIRED);
            return HITLS_OCSP_ERR_HAS_EXPIRED;
        }
    }

    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_OCSP_CheckNonce(const HITLS_OCSP_Req *req, const HITLS_OCSP_BasicResp *bs, HITLS_OCSP_NonceStatus *status)
{
    if (status == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    *status = HITLS_OCSP_NONCE_BOTH_ABSENT;

    BSL_Buffer reqNonce = {0};
    BSL_Buffer respNonce = {0};
    bool reqHasNonce = false;
    bool respHasNonce = false;

    if (req != NULL) {
        int32_t ret =
            HITLS_OCSP_ReqCtrl((HITLS_OCSP_Req *)(uintptr_t)req, HITLS_OCSP_REQ_GET_NONCE, &reqNonce, sizeof(reqNonce));
        if (ret == HITLS_PKI_SUCCESS) {
            reqHasNonce = (reqNonce.data != NULL && reqNonce.dataLen > 0);
        } else if (ret != HITLS_X509_ERR_EXT_NOT_FOUND) {
            return ret;
        }
    }
    if (bs != NULL) {
        int32_t ret = HITLS_OCSP_BasicRespCtrl((HITLS_OCSP_BasicResp *)(uintptr_t)bs, HITLS_OCSP_BASICRESP_GET_NONCE,
                                               &respNonce, sizeof(respNonce));
        if (ret == HITLS_PKI_SUCCESS) {
            respHasNonce = (respNonce.data != NULL && respNonce.dataLen > 0);
        } else if (ret != HITLS_X509_ERR_EXT_NOT_FOUND) {
            return ret;
        }
    }

    if (reqHasNonce && respHasNonce) {
        if (reqNonce.dataLen == respNonce.dataLen &&
            memcmp(reqNonce.data, respNonce.data, reqNonce.dataLen) == 0) {
            *status = HITLS_OCSP_NONCE_EQUAL;
        } else {
            *status = HITLS_OCSP_NONCE_NOT_EQUAL;
        }
    } else if (reqHasNonce && !respHasNonce) {
        *status = HITLS_OCSP_NONCE_REQ_ONLY;
    } else if (!reqHasNonce && respHasNonce) {
        *status = HITLS_OCSP_NONCE_RESP_ONLY;
    } else {
        *status = HITLS_OCSP_NONCE_BOTH_ABSENT;
    }

    return HITLS_PKI_SUCCESS;
}

/* ==================== Resp DER Encoding ==================== */

static int32_t OcspEncodeBasicResp(HITLS_OCSP_BasicResp_Internal *internal, BSL_ASN1_Buffer *out)
{
    BSL_ASN1_Buffer algIdDer = {0};
    int32_t ret = HITLS_X509_EncodeSignAlgInfo(&internal->signAlgId, &algIdDer);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* tbsRawData = SEQUENCE { ResponseData TLV }, strip outer SEQUENCE */
    BSL_ASN1_Buffer tbsWrap = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
                                internal->tbsRawData.dataLen, internal->tbsRawData.data};
    BSL_ASN1_Buffer tbsV = {0};
    ret = OcspStripTlv(&tbsWrap, &tbsV);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(algIdDer.buff);
        return ret;
    }

    /* Encode certs [0] EXPLICIT SEQUENCE OF Certificate if present */
    BSL_ASN1_Buffer certsV = {0};
    ret = OcspEncodeCerts(internal->certs, &certsV);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(algIdDer.buff);
        return ret;
    }

    /*
     * BasicOCSPResponse ::= SEQUENCE {
     *     tbsResponseData      ResponseData            depth=1 (HEADERONLY)
     *     signatureAlgorithm   AlgorithmIdentifier    depth=1 (HEADERONLY)
     *     signature            BIT STRING             depth=1
     *     certs [0] EXPLICIT SEQUENCE OF Certificate  depth=1 (OPTIONAL | HEADERONLY)
     * }
     */
    BSL_ASN1_Buffer asns[4] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, tbsV.len, tbsV.buff},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, algIdDer.len, algIdDer.buff},
        {BSL_ASN1_TAG_BITSTRING, sizeof(BSL_ASN1_BitString), (uint8_t *)&internal->signature},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, certsV.len, certsV.buff},
    };
    BSL_ASN1_Template templ = {g_ocspBasicRespEncTempl,
                                sizeof(g_ocspBasicRespEncTempl) / sizeof(g_ocspBasicRespEncTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asns, 4, &out->buff, &out->len);

    BSL_SAL_Free(algIdDer.buff);
    BSL_SAL_Free(certsV.buff);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    out->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_OCSP_RespGenBuff(int32_t format, const HITLS_OCSP_Resp *resp, BSL_Buffer *buff)
{
    if (resp == NULL || buff == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    if (buff->data != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    if (format != BSL_FORMAT_ASN1) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }

    const HITLS_OCSP_Resp_Internal *internal = (const HITLS_OCSP_Resp_Internal *)resp;

    BSL_ASN1_Buffer basicRespDer = {0};
    uint8_t *respBytesDer = NULL;
    uint32_t respBytesLen = 0;

    if (internal->status == HITLS_OCSP_RESP_STATUS_SUCCESSFUL) {
        int32_t ret = OcspEncodeBasicResp((HITLS_OCSP_BasicResp_Internal *)internal->basicResp, &basicRespDer);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }

        /* Encode ResponseBytes = SEQUENCE { responseType OID, response OCTET STRING(BasicOCSPResp DER) } */
        BslOidString *oidStr = BSL_OBJ_GetOID(BSL_CID_PKIX_OCSP_BASIC);
        if (oidStr == NULL) {
            BSL_SAL_Free(basicRespDer.buff);
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
            return HITLS_OCSP_ERR_INVALID_PARAM;
        }
        BSL_ASN1_Buffer respBytesAsns[2] = {
            {BSL_ASN1_TAG_OBJECT_ID, oidStr->octetLen, (uint8_t *)oidStr->octs},
            {BSL_ASN1_TAG_OCTETSTRING, basicRespDer.len, basicRespDer.buff},
        };
        BSL_ASN1_Template respBytesTmpl = {g_ocspRespBytesTempl,
                                            sizeof(g_ocspRespBytesTempl) / sizeof(g_ocspRespBytesTempl[0])};
        ret = BSL_ASN1_EncodeTemplate(&respBytesTmpl, respBytesAsns, 2, &respBytesDer, &respBytesLen);
        BSL_SAL_Free(basicRespDer.buff);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    /*
     * OCSPResponse ::= SEQUENCE {
     *     responseStatus    ENUMERATED                 depth=1
     *     responseBytes [0] EXPLICIT ResponseBytes    depth=1 (OPTIONAL | HEADERONLY)
     * }
     */
    uint8_t status = internal->status;
    BSL_ASN1_Buffer respAsns[2] = {
        {BSL_ASN1_TAG_ENUMERATED, sizeof(uint8_t), (uint8_t *)&status},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, respBytesLen, respBytesDer},
    };
    BSL_ASN1_Template templ = {g_ocspRespTempl, sizeof(g_ocspRespTempl) / sizeof(g_ocspRespTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, respAsns, 2, &buff->data, &buff->dataLen);
    BSL_SAL_Free(respBytesDer);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return HITLS_PKI_SUCCESS;
}

/* ==================== Resp DER Decoding ==================== */

static int32_t OcspParseRevokedInfo(const BSL_ASN1_Buffer *certStatusAsn, HITLS_OCSP_SingleResp_Internal *sr)
{
    BSL_ASN1_Buffer asns[REVOKED_INFO_DEC_MAX_IDX] = {0};
    BSL_ASN1_Template tmpl = {g_ocspRevokedInfoTempl,
        sizeof(g_ocspRevokedInfoTempl) / sizeof(g_ocspRevokedInfoTempl[0])};
    uint8_t *buff = certStatusAsn->buff;
    uint32_t len = certStatusAsn->len;
    int32_t ret = BSL_ASN1_DecodeTemplate(&tmpl, OcspTagGetOrCheck, &buff, &len,
        asns, REVOKED_INFO_DEC_LEAF_NUM);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (len != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
        return HITLS_OCSP_ERR_INVALID_RESPONSE;
    }

    ret = BSL_ASN1_DecodePrimitiveItem(&asns[REVOKED_INFO_DEC_TIME_IDX], &sr->revocationTime);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    sr->hasRevocationTime = true;

    if (asns[REVOKED_INFO_DEC_REASON_IDX].tag != 0) {
        int32_t reason = 0;
        ret = BSL_ASN1_DecodePrimitiveItem(&asns[REVOKED_INFO_DEC_REASON_IDX], &reason);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (reason < 0 || reason > HITLS_X509_REVOKED_REASON_AA_COMPROMISE ||
            reason == HITLS_OCSP_REVOKED_REASON_UNUSED) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
            return HITLS_OCSP_ERR_INVALID_RESPONSE;
        }
        sr->revocationReason = reason;
        sr->hasRevocationReason = true;
    }
    return HITLS_PKI_SUCCESS;
}

/* Parse the certStatus CHOICE into sr (good / revoked / unknown). */
static int32_t OcspParseCertStatus(const BSL_ASN1_Buffer *csAsn, HITLS_OCSP_SingleResp_Internal *sr)
{
    if (csAsn->tag == (BSL_ASN1_CLASS_CTX_SPECIFIC | 0)) {
        sr->certStatus = HITLS_OCSP_CERT_STATUS_GOOD;
        return HITLS_PKI_SUCCESS;
    }
    if (csAsn->tag == (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1)) {
        sr->certStatus = HITLS_OCSP_CERT_STATUS_REVOKED;
        return OcspParseRevokedInfo((BSL_ASN1_Buffer *)(uintptr_t)csAsn, sr);
    }
    if (csAsn->tag == (BSL_ASN1_CLASS_CTX_SPECIFIC | 2)) {
        sr->certStatus = HITLS_OCSP_CERT_STATUS_UNKNOWN;
        return HITLS_PKI_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
    return HITLS_OCSP_ERR_INVALID_RESPONSE;
}

/* Response-side wrappers: the shared decode helpers return the context-neutral
 * HITLS_OCSP_ERR_MALFORMED for malformed DER; convert it to the response code. */
static int32_t OcspParseRespCertId(const BSL_ASN1_Buffer *asn, HITLS_OCSP_CertId_Internal *certId)
{
    int32_t ret = OcspParseCertId(asn, certId);
    if (ret == HITLS_OCSP_ERR_MALFORMED) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
        ret = HITLS_OCSP_ERR_INVALID_RESPONSE;
    }
    return ret;
}

static int32_t OcspParseRespCerts(BSL_ASN1_Buffer *certsAsn, BslList **certs)
{
    int32_t ret = OcspParseCerts(certsAsn, certs);
    if (ret == HITLS_OCSP_ERR_MALFORMED) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
        ret = HITLS_OCSP_ERR_INVALID_RESPONSE;
    }
    return ret;
}

/* Parse the SingleResponse leaf fields (certId, certStatus, thisUpdate, nextUpdate)
 * into a freshly allocated sr. On failure sr is freed. */
static int32_t OcspParseSingleRespFields(const BSL_ASN1_Buffer *asns, HITLS_OCSP_SingleResp_Internal **outSr)
{
    HITLS_OCSP_CertId_Internal *certId = BSL_SAL_Calloc(1, sizeof(HITLS_OCSP_CertId_Internal));
    if (certId == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = OcspParseRespCertId((BSL_ASN1_Buffer *)(uintptr_t)&asns[SINGLE_RESP_DEC_CERTID_IDX], certId);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(certId);
        return ret;
    }

    HITLS_OCSP_SingleResp_Internal *sr = BSL_SAL_Calloc(1, sizeof(HITLS_OCSP_SingleResp_Internal));
    if (sr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        HITLS_OCSP_CertIdFree((HITLS_OCSP_CertId *)certId);
        return BSL_MALLOC_FAIL;
    }
    sr->certId = (HITLS_OCSP_CertId *)certId;
    /* Parsed from DER: the fields are covered by the response signature and must
     * stay immutable (see OcspSingleRespSetCtrl). */
    sr->frozen = true;

    ret = OcspParseCertStatus(&asns[SINGLE_RESP_DEC_CERT_STATUS_IDX], sr);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    ret = BSL_ASN1_DecodePrimitiveItem((BSL_ASN1_Buffer *)(uintptr_t)&asns[SINGLE_RESP_DEC_THIS_UPDATE_IDX],
                                       &sr->thisUpdate);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    if (asns[SINGLE_RESP_DEC_NEXT_UPDATE_IDX].tag != 0) {
        ret = BSL_ASN1_DecodePrimitiveItem((BSL_ASN1_Buffer *)(uintptr_t)&asns[SINGLE_RESP_DEC_NEXT_UPDATE_IDX],
                                           &sr->nextUpdate);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        sr->hasNextUpdate = true;
    }

    if (asns[SINGLE_RESP_DEC_EXTENSIONS_IDX].tag != 0) {
        ret = OcspDecodeExt((BSL_ASN1_Buffer *)(uintptr_t)&asns[SINGLE_RESP_DEC_EXTENSIONS_IDX], &sr->ext);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT; /* error already pushed by the callee */
        }
    }

    *outSr = sr;
    return HITLS_PKI_SUCCESS;

EXIT:
    HITLS_OCSP_SingleRespFree((HITLS_OCSP_SingleResp *)sr);
    return ret;
}

static int32_t OcspParseSingleResp(uint32_t layer, BSL_ASN1_Buffer *asn, void *cbParam, BSL_ASN1_List *list)
{
    (void)layer;
    (void)cbParam;

    BSL_ASN1_Buffer asns[SINGLE_RESP_DEC_MAX_IDX] = {0};
    BSL_ASN1_Template tmpl = {g_ocspSingleRespTempl, sizeof(g_ocspSingleRespTempl) / sizeof(g_ocspSingleRespTempl[0])};
    uint8_t *buff = asn->buff;
    uint32_t len = asn->len;
    int32_t ret = BSL_ASN1_DecodeTemplate(&tmpl, OcspTagGetOrCheck, &buff, &len, asns, SINGLE_RESP_DEC_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (len != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
        return HITLS_OCSP_ERR_INVALID_RESPONSE;
    }

    HITLS_OCSP_SingleResp_Internal *sr = NULL;
    ret = OcspParseSingleRespFields(asns, &sr);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = BSL_LIST_AddElement((BslList *)list, sr, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        HITLS_OCSP_SingleRespFree((HITLS_OCSP_SingleResp *)sr);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t OcspParseOctetString(const BSL_ASN1_Buffer *asn, uint8_t **out, uint32_t *outLen)
{
    uint8_t *p = asn->buff;
    uint32_t remaining = asn->len;
    uint32_t contentLen = 0;
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OCTETSTRING, &p, &remaining, &contentLen);
    if (ret != BSL_SUCCESS) {
        return ret; /* DecodeTagLen already pushed its error */
    }
    if (remaining != contentLen) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
        return HITLS_OCSP_ERR_INVALID_RESPONSE;
    }
    *out = p;
    *outLen = contentLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t OcspParseResponderID(BSL_ASN1_Buffer *ridAsn, HITLS_OCSP_BasicResp_Internal *internal)
{
    HITLS_OCSP_ResponderId *rid = BSL_SAL_Calloc(1, sizeof(HITLS_OCSP_ResponderId));
    if (rid == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    if (ridAsn->tag == (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1)) {
        rid->value.byName.data = BSL_SAL_Dump(ridAsn->buff, ridAsn->len);
        if (rid->value.byName.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            BSL_SAL_Free(rid);
            return BSL_MALLOC_FAIL;
        }
        rid->value.byName.dataLen = ridAsn->len;
        rid->type = HITLS_OCSP_RESPONDERID_BY_NAME;
    } else if (ridAsn->tag == (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 2)) {
        uint8_t *keyData = NULL;
        uint32_t keyLen = 0;
        int32_t ret = OcspParseOctetString(ridAsn, &keyData, &keyLen);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_SAL_Free(rid);
            return ret;
        }
        if (keyLen != CRYPT_SHA1_DIGEST_SIZE) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
            BSL_SAL_Free(rid);
            return HITLS_OCSP_ERR_INVALID_RESPONSE;
        }
        rid->value.byKey.data = BSL_SAL_Dump(keyData, keyLen);
        if (rid->value.byKey.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            BSL_SAL_Free(rid);
            return BSL_MALLOC_FAIL;
        }
        rid->value.byKey.dataLen = keyLen;
        rid->type = HITLS_OCSP_RESPONDERID_BY_KEY;
    } else {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
        BSL_SAL_Free(rid);
        return HITLS_OCSP_ERR_INVALID_RESPONSE;
    }
    internal->responderId = rid;
    return HITLS_PKI_SUCCESS;
}

static int32_t OcspParseResponseData(const BSL_ASN1_Buffer *tbsContent, HITLS_OCSP_BasicResp_Internal *internal)
{
    BSL_ASN1_Buffer asns[RESP_DATA_DEC_MAX_IDX] = {0};
    BSL_ASN1_Template tmpl = {g_ocspRespDataDecTempl,
                               sizeof(g_ocspRespDataDecTempl) / sizeof(g_ocspRespDataDecTempl[0])};
    uint8_t *buff = tbsContent->buff;
    uint32_t len = tbsContent->len;
    int32_t ret = BSL_ASN1_DecodeTemplate(&tmpl, OcspTagGetOrCheck, &buff, &len, asns, RESP_DATA_DEC_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (len != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
        return HITLS_OCSP_ERR_INVALID_RESPONSE;
    }
    /* RFC 6960 §4.2.1: ResponseData version is DEFAULT v1 and only v1 is defined;
     * reject any present non-v1 version like the request decoder does. */
    if (asns[RESP_DATA_DEC_VERSION_IDX].tag != 0) {
        const uint8_t *vp = asns[RESP_DATA_DEC_VERSION_IDX].buff;
        uint32_t vl = asns[RESP_DATA_DEC_VERSION_IDX].len;
        if (vl != 1 || vp == NULL || *vp != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_VERSION);
            return HITLS_OCSP_ERR_INVALID_VERSION;
        }
    }

    ret = OcspParseResponderID(&asns[RESP_DATA_DEC_RESPONDER_ID_IDX], internal);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    ret = BSL_ASN1_DecodePrimitiveItem(&asns[RESP_DATA_DEC_PRODUCED_AT_IDX], &internal->producedAt);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t expTag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    BSL_ASN1_DecodeListParam listParam = {1, &expTag};
    ret = BSL_ASN1_DecodeListItem(&listParam, &asns[RESP_DATA_DEC_RESPONSES_IDX],
                                  OcspParseSingleResp, NULL, internal->responses);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (BSL_LIST_COUNT(internal->responses) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_EMPTY_RESPONSE);
        return HITLS_OCSP_ERR_EMPTY_RESPONSE;
    }
    /* Cap the parsed count like the encode-side ADD_SINGLERESP ctrl, so an
     * attacker-controlled response cannot force unbounded allocation. */
    if (BSL_LIST_COUNT(internal->responses) > HITLS_OCSP_MAX_SINGLE_RESP) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_TOO_MANY);
        return HITLS_OCSP_ERR_TOO_MANY;
    }
    if (asns[RESP_DATA_DEC_EXTENSIONS_IDX].tag != 0) {
        ret = OcspDecodeExt(&asns[RESP_DATA_DEC_EXTENSIONS_IDX], &internal->ext);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    return HITLS_PKI_SUCCESS;
}

/* Save the signed ResponseData bytes (tbsRawData) needed for signature verification. */
static int32_t OcspParseRespTbsData(uint8_t *basicRespDer, uint32_t basicRespLen,
                                    HITLS_OCSP_BasicResp_Internal *internal)
{
    uint8_t *tbsRawPtr = NULL;
    uint32_t tbsRawLen = 0;
    int32_t ret = HITLS_X509_ParseTbsRawData(basicRespDer, basicRespLen, &tbsRawPtr, &tbsRawLen);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    internal->tbsRawData.data = BSL_SAL_Dump(tbsRawPtr, tbsRawLen);
    if (internal->tbsRawData.data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    internal->tbsRawData.dataLen = tbsRawLen;
    return HITLS_PKI_SUCCESS;
}

/* Parse signatureAlgorithm + signature and deep-copy the signature bytes. */
static int32_t OcspParseRespSignature(BSL_ASN1_Buffer *asns, HITLS_OCSP_BasicResp_Internal *internal)
{
    int32_t ret = HITLS_X509_ParseSignAlgInfo(&asns[BASIC_RESP_DEC_SIGALG_OID_IDX],
                                              &asns[BASIC_RESP_DEC_SIGALG_PARAM_IDX], &internal->signAlgId);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BSL_ASN1_DecodePrimitiveItem(&asns[BASIC_RESP_DEC_SIG_IDX], &internal->signature);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /* ParseBitString borrows the pointer into input buffer; deep-copy for ownership */
    uint8_t *sigCopy = BSL_SAL_Dump(internal->signature.buff, internal->signature.len);
    if (sigCopy == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        internal->signature.buff = NULL;
        internal->signature.len = 0;
        return BSL_MALLOC_FAIL;
    }
    internal->signature.buff = sigCopy;
    return HITLS_PKI_SUCCESS;
}

static int32_t OcspParseBasicResp(uint8_t *basicRespDer, uint32_t basicRespLen, HITLS_OCSP_BasicResp_Internal *internal)
{
    uint8_t *temp = basicRespDer;
    uint32_t tempLen = basicRespLen;

    BSL_ASN1_Buffer asns[BASIC_RESP_DEC_MAX_IDX] = {0};
    BSL_ASN1_Template tmpl = {g_ocspBasicRespDecTempl,
                               sizeof(g_ocspBasicRespDecTempl) / sizeof(g_ocspBasicRespDecTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&tmpl, OcspTagGetOrCheck, &temp, &tempLen, asns, BASIC_RESP_DEC_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (tempLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
        return HITLS_OCSP_ERR_INVALID_RESPONSE;
    }

    ret = OcspParseRespTbsData(basicRespDer, basicRespLen, internal);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = OcspParseRespSignature(asns, internal);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    ret = OcspParseResponseData(&asns[BASIC_RESP_DEC_TBS_IDX], internal);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    if (asns[BASIC_RESP_DEC_CERTS_IDX].tag != 0) {
        ret = OcspParseRespCerts(&asns[BASIC_RESP_DEC_CERTS_IDX], &internal->certs);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
    }

    internal->isSigned = true;
    return HITLS_PKI_SUCCESS;

EXIT:
    BSL_SAL_FREE(internal->tbsRawData.data);
    BSL_SAL_FREE(internal->signature.buff);
    return ret;
}

/* Parse and validate the outer OCSPResponse. On entry *resp must be NULL.
 * On success sets *status and, when responseBytes [0] is present, *bytesAsn to the
 * [0] TLV. When the status is not successful and there are no responseBytes, a
 * status-only response is built and returned through *resp (caller returns directly). */
/* Parse and validate the outer OCSPResponse. On success sets *status and *bytesAsn
 * (bytesAsn->tag == 0 means responseBytes [0] is absent). */
static int32_t OcspParseRespOuter(int32_t format, const BSL_Buffer *encode, int32_t *status, BSL_ASN1_Buffer *bytesAsn)
{
    if (encode == NULL || encode->data == NULL || status == NULL || bytesAsn == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    if (format != BSL_FORMAT_ASN1) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }

    uint8_t *temp = (uint8_t *)encode->data;
    uint32_t tempLen = encode->dataLen;
    BSL_ASN1_Buffer respAsns[OCSP_RESP_DEC_MAX_IDX] = {0};
    BSL_ASN1_Template tmpl = {g_ocspRespTempl, sizeof(g_ocspRespTempl) / sizeof(g_ocspRespTempl[0])};
    int32_t ret =
        BSL_ASN1_DecodeTemplate(&tmpl, OcspTagGetOrCheck, &temp, &tempLen, respAsns, OCSP_RESP_DEC_LEAF_NUM);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (tempLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
        return HITLS_OCSP_ERR_INVALID_RESPONSE;
    }

    ret = BSL_ASN1_DecodePrimitiveItem(&respAsns[OCSP_RESP_DEC_STATUS_IDX], status);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (!OcspIsValidRespStatus(*status)) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_STATUS);
        return HITLS_OCSP_ERR_INVALID_STATUS;
    }

    *bytesAsn = respAsns[OCSP_RESP_DEC_BYTES_IDX];
    return HITLS_PKI_SUCCESS;
}

/* Parse ResponseBytes (responseType OID + response OCTET STRING) and validate that the
 * type is id-pkix-ocsp-basic. Outputs the BasicOCSPResponse content DER. */
static int32_t OcspParseRespBytes(const BSL_ASN1_Buffer *bytesAsn, BSL_ASN1_Buffer *basicRespContent)
{
    BSL_ASN1_Buffer respBytesAsns[RESP_BYTES_DEC_MAX_IDX] = {0};
    BSL_ASN1_Template rbTmpl = {g_ocspRespBytesTempl, sizeof(g_ocspRespBytesTempl) / sizeof(g_ocspRespBytesTempl[0])};
    uint8_t *rbBuff = bytesAsn->buff;
    uint32_t rbLen = bytesAsn->len;
    int32_t ret =
        BSL_ASN1_DecodeTemplate(&rbTmpl, OcspTagGetOrCheck, &rbBuff, &rbLen, respBytesAsns, RESP_BYTES_DEC_LEAF_NUM);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (rbLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
        return HITLS_OCSP_ERR_INVALID_RESPONSE;
    }

    BslCid cid = BSL_OBJ_GetCidFromOidBuff(respBytesAsns[RESP_BYTES_DEC_OID_IDX].buff,
                                           respBytesAsns[RESP_BYTES_DEC_OID_IDX].len);
    if (cid != BSL_CID_PKIX_OCSP_BASIC) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
        return HITLS_OCSP_ERR_INVALID_RESPONSE;
    }

    *basicRespContent = respBytesAsns[RESP_BYTES_DEC_RESPONSE_IDX];
    return HITLS_PKI_SUCCESS;
}

/* Allocate a BasicResp and parse the BasicOCSPResponse content, then wrap it into a
 * HITLS_OCSP_Resp. Ownership of the BasicResp is transferred to the response. */
static int32_t OcspParseBasicRespObj(const BSL_ASN1_Buffer *basicRespContent, int32_t status, HITLS_OCSP_Resp **resp)
{
    HITLS_OCSP_BasicResp_Internal *bs = (HITLS_OCSP_BasicResp_Internal *)BSL_SAL_Calloc(1, sizeof(*bs));
    if (bs == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    bs->responses = BSL_LIST_New(sizeof(HITLS_OCSP_SingleResp *));
    if (bs->responses == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_Free(bs);
        return BSL_MALLOC_FAIL;
    }

    int32_t ret = OcspParseBasicResp(basicRespContent->buff, basicRespContent->len, bs);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_OCSP_BasicRespFree((HITLS_OCSP_BasicResp *)bs);
        return ret;
    }

    HITLS_OCSP_Resp *r = HITLS_OCSP_RespNew(status, (HITLS_OCSP_BasicResp *)bs);
    if (r == NULL) {
        /* RespNew already pushed the failure code (BSL_MALLOC_FAIL here); release bs and propagate. */
        HITLS_OCSP_BasicRespFree((HITLS_OCSP_BasicResp *)bs);
        return BSL_MALLOC_FAIL;
    }
    *resp = r;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_OCSP_RespParseBuff(int32_t format, const BSL_Buffer *encode, HITLS_OCSP_Resp **resp)
{
    if (encode == NULL || encode->data == NULL || resp == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    if (*resp != NULL) {
        /* The output must be NULL on entry; a pre-filled pointer would be overwritten (leaking it). */
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    int32_t status = 0;
    BSL_ASN1_Buffer bytesAsn = {0};
    BSL_ASN1_Buffer basicRespContent = {0};

    int32_t ret = OcspParseRespOuter(format, encode, &status, &bytesAsn);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    if (bytesAsn.tag == 0) {
        /* No responseBytes: only allowed for a non-successful status, which yields a
         * status-only response. A successful status must carry responseBytes. */
        if (status == HITLS_OCSP_RESP_STATUS_SUCCESSFUL) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NO_RESPONSE_BYTES);
            return HITLS_OCSP_ERR_NO_RESPONSE_BYTES;
        }
        HITLS_OCSP_Resp *r = HITLS_OCSP_RespNew(status, NULL);
        if (r == NULL) {
            /* RespNew already pushed the failure code (BSL_MALLOC_FAIL here). */
            return BSL_MALLOC_FAIL;
        }
        *resp = r;
        return HITLS_PKI_SUCCESS;
    }

    /* responseBytes present: the status must be successful. */
    if (status != HITLS_OCSP_RESP_STATUS_SUCCESSFUL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_STATUS);
        return HITLS_OCSP_ERR_INVALID_STATUS;
    }

    ret = OcspParseRespBytes(&bytesAsn, &basicRespContent);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    return OcspParseBasicRespObj(&basicRespContent, status, resp);
}

#endif // HITLS_PKI_OCSP

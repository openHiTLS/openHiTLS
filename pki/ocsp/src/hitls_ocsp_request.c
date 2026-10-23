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
#include "crypt_eal_rand.h"

/* ==================== ASN.1 encode/decode templates ==================== */

/* --- Encode templates (outer to inner) --- */

/* Encode template for the unsigned OCSPRequest (optionalSignature omitted):
 * OCSPRequest ::= SEQUENCE {
 *     tbsRequest         TBSRequest,
 *     optionalSignature  [0] EXPLICIT Signature OPTIONAL }   (absent when unsigned)
 * tbsRequest is passed as a complete TLV (HEADERONLY).
 * Used by HITLS_OCSP_ReqGenBuff. */
static BSL_ASN1_TemplateItem g_ocspReqUnsignedEncTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0}, /* OCSPRequest (tbsRequest) */
};

/* Encode template for the signed OCSPRequest outer wrapper:
 * OCSPRequest ::= SEQUENCE {
 *     tbsRequest         TBSRequest,
 *     optionalSignature  [0] EXPLICIT Signature OPTIONAL }
 * Used by the signed-request encoder. */
static BSL_ASN1_TemplateItem g_ocspReqSignedEncTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},                          /* OCSPRequest, */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1}, /* tbsRequest */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, BSL_ASN1_FLAG_OPTIONAL, 1}, /* optionalSignature [0] */
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},                  /* Signature SEQUENCE */
                {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 3}, /* signatureAlgorithm */
                {BSL_ASN1_TAG_BITSTRING, 0, 3},                                        /* signature */
                {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED,               /* certs [0] */
                    BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 3},
};

/* Encode template for TBSRequest (version omitted, defaults to v1):
 * TBSRequest ::= SEQUENCE {
 *     version             [0] EXPLICIT Version DEFAULT v1     (omitted)
 *     requestorName       [1] EXPLICIT GeneralName OPTIONAL   depth=2 (HEADERONLY)
 *     requestList         SEQUENCE OF Request                 depth=2 (HEADERONLY)
 *     requestExtensions   [2] EXPLICIT Extensions OPTIONAL    depth=2 (HEADERONLY)
 * }
 * Used by OcspReqEncodeTbsRawData. */
static BSL_ASN1_TemplateItem g_ocspTbsReqEncTempl[] = {
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1,  /* requestorName [1] */
        BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0}, /* requestList */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 2,  /* requestExtensions [2] */
        BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
};

/* Encode template for the Request element (SEQUENCE OF Request):
 * Request ::= SEQUENCE {
 *     reqCert                   CertID                        (HEADERONLY)
 *     singleRequestExtensions   [0] EXPLICIT Extensions OPTIONAL (HEADERONLY) }
 * Used by OcspEncodeRequestList. */
static BSL_ASN1_TemplateItem g_ocspRequestElemEncTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},                            /* Request */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1}, /* reqCert */
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED,  /* singleRequestExtensions [0] */
            BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 1},
};

/* --- Decode templates (outer to inner) --- */

/* Decode template for OCSPRequest:
 * OCSPRequest ::= SEQUENCE {                               depth=0
 *     tbsRequest      TBSRequest                           depth=1 (SEQUENCE, container)
 *         version [0] EXPLICIT Version DEFAULT v1          depth=2 (OPTIONAL, skipped if absent)
 *             INTEGER                                      depth=3
 *         requestorName [1] EXPLICIT GeneralName OPTIONAL  depth=2 (OPTIONAL | HEADERONLY)
 *         requestList SEQUENCE OF Request                 depth=2 (HEADERONLY | SAME)
 *         requestExtensions [2] EXPLICIT Extensions OPTIONAL depth=2 (OPTIONAL | HEADERONLY | SAME)
 *     optionalSignature [0] EXPLICIT Signature OPTIONAL    depth=1 (OPTIONAL, container)
 *         Signature ::= SEQUENCE                           depth=2 (container)
 *             signatureAlgorithm AlgorithmIdentifier       depth=3 (SEQUENCE, container)
 *                 algorithm OID                            depth=4
 *                 parameters ANY OPTIONAL                  depth=4
 *             signature BIT STRING                         depth=3
 *             certs [0] EXPLICIT SEQUENCE OF Certificate   depth=3 (OPTIONAL | HEADERONLY)
 * }
 * Leaves: [0]=version, [1]=requestorName, [2]=requestList, [3]=requestExtensions,
 *         [4]=sigAlg OID, [5]=sigAlg params, [6]=signature, [7]=certs
 * Used by the OCSPRequest DER decoder. */
static BSL_ASN1_TemplateItem g_ocspReqDecTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},                           /* OCSPRequest */
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},                       /* TBSRequest */
            {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED,                     /* version [0] */
                BSL_ASN1_FLAG_OPTIONAL, 2},
                {BSL_ASN1_TAG_INTEGER, 0, 3},                                        /* Version (INTEGER) */
            {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1,               /* requestorName [1] */
                BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 2},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,                          /* requestList */
                BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 2},
            {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 2,                /* requestExtensions [2] */
                BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 2},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED,                        /* optionalSignature [0] */
            BSL_ASN1_FLAG_OPTIONAL, 1},
            {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},                  /* Signature SEQUENCE */
                {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 3},              /* signatureAlgorithm */
                    {BSL_ASN1_TAG_OBJECT_ID, 0, 4},                                    /* algorithm */
                    {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 4},                     /* parameters */
                {BSL_ASN1_TAG_BITSTRING, 0, 3},                                        /* signature */
                {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED,               /* certs [0] */
                    BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 3},
};

enum {
    OCSP_REQ_DEC_VERSION_IDX = 0,
    OCSP_REQ_DEC_REQUESTOR_NAME_IDX,
    OCSP_REQ_DEC_REQUESTLIST_IDX,
    OCSP_REQ_DEC_EXTENSIONS_IDX,
    OCSP_REQ_DEC_SIGALG_OID_IDX,
    OCSP_REQ_DEC_SIGALG_PARAM_IDX,
    OCSP_REQ_DEC_SIG_IDX,
    OCSP_REQ_DEC_CERTS_IDX,
    OCSP_REQ_DEC_MAX_IDX,
};

/* Decode template for Request content (input = content of Request SEQUENCE):
 * Request ::= SEQUENCE {
 *     reqCert                    CertID                    depth=0 (HEADERONLY)
 *     singleRequestExtensions    [0] EXPLICIT Extensions   depth=0 (OPTIONAL | HEADERONLY, skipped)
 * }
 * Leaf indices: [0]=reqCert (CertID content), [1]=extensions
 * Used by OcspParseSingleReq. */
static BSL_ASN1_TemplateItem g_ocspRequestDecTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0}, /* reqCert */
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED,                         /* singleRequestExtensions [0] */
        BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY, 0},
};

enum {
    REQUEST_DEC_CERTID_IDX = 0,
    REQUEST_DEC_SINGLE_EXT_IDX,
    REQUEST_DEC_MAX_IDX,
};

/* ==================== SingleReq ==================== */

HITLS_OCSP_SingleReq *HITLS_OCSP_SingleReqNew(HITLS_OCSP_CertId *certId)
{
    if (certId == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return NULL;
    }

    HITLS_OCSP_SingleReq_Internal *singleReq =
        BSL_SAL_Calloc(1, sizeof(HITLS_OCSP_SingleReq_Internal));
    if (singleReq == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    singleReq->certId = certId;
    return (HITLS_OCSP_SingleReq *)singleReq;
}

void HITLS_OCSP_SingleReqFree(HITLS_OCSP_SingleReq *singleReq)
{
    if (singleReq == NULL) {
        return;
    }
    HITLS_OCSP_SingleReq_Internal *internal = (HITLS_OCSP_SingleReq_Internal *)singleReq;
    HITLS_OCSP_CertIdFree(internal->certId);
    if (internal->ext != NULL) {
        HITLS_X509_ExtFree(internal->ext);
    }
    BSL_SAL_Free(internal);
}

int32_t HITLS_OCSP_SingleReqGetCertId(const HITLS_OCSP_SingleReq *singleReq, HITLS_OCSP_CertId **certId)
{
    if (singleReq == NULL || certId == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    const HITLS_OCSP_SingleReq_Internal *internal = (const HITLS_OCSP_SingleReq_Internal *)singleReq;
    *certId = internal->certId;
    return HITLS_PKI_SUCCESS;
}

/* ==================== Req ==================== */

HITLS_OCSP_Req *HITLS_OCSP_ReqNew(void)
{
    HITLS_OCSP_Req_Internal *req = BSL_SAL_Calloc(1, sizeof(HITLS_OCSP_Req_Internal));
    if (req == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    req->singleReqs = BSL_LIST_New(sizeof(HITLS_OCSP_SingleReq *));
    if (req->singleReqs == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_Free(req);
        return NULL;
    }

    return (HITLS_OCSP_Req *)req;
}

void HITLS_OCSP_ReqFree(HITLS_OCSP_Req *req)
{
    if (req == NULL) {
        return;
    }
    HITLS_OCSP_Req_Internal *internal = (HITLS_OCSP_Req_Internal *)req;
    BSL_LIST_FREE(internal->singleReqs, (BSL_LIST_PFUNC_FREE)HITLS_OCSP_SingleReqFree);
    if (internal->ext != NULL) {
        HITLS_X509_ExtFree(internal->ext);
    }
    BSL_SAL_FREE(internal->requestorName.data);
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
    BSL_SAL_FREE(internal->tbsRawData.data);
    BSL_SAL_FREE(internal->rawData.data);
    BSL_LIST_FREE(internal->certs, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_SAL_Free(internal);
}

/* ==================== Req Ctrl / Query ==================== */
static int32_t OcspReqAddSingleReq(HITLS_OCSP_Req_Internal *internal, HITLS_OCSP_SingleReq *singleReq)
{
    if (singleReq == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    if (BSL_LIST_COUNT(internal->singleReqs) >= HITLS_OCSP_MAX_SINGLE_REQ) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_TOO_MANY);
        return HITLS_OCSP_ERR_TOO_MANY;
    }
    int32_t ret = BSL_LIST_AddElement(internal->singleReqs, singleReq, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        /* Ownership transfers only on success: the caller still owns singleReq and must free it. */
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t OcspReqSetNonce(HITLS_OCSP_Req_Internal *internal, const uint8_t *data, uint32_t dataLen)
{
    if (dataLen == 0) {
        if (data != NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
            return HITLS_OCSP_ERR_INVALID_PARAM;
        } else {
            dataLen = HITLS_OCSP_NONCE_DEFAULT_LEN;
        }
    }

    if (dataLen > HITLS_OCSP_NONCE_MAX_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_OCSP_NONCE_LEN);
        return HITLS_X509_ERR_EXT_OCSP_NONCE_LEN;
    }

    uint8_t *nonceBuf = BSL_SAL_Malloc(dataLen);
    if (nonceBuf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    if (data == NULL) {
        int32_t ret = CRYPT_EAL_Randbytes(nonceBuf, dataLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_Free(nonceBuf);
            return ret;
        }
    } else {
        (void)memcpy(nonceBuf, data, dataLen);
    }
    int32_t ret = OcspSetNonce(&internal->ext, nonceBuf, dataLen);
    BSL_SAL_Free(nonceBuf);
    return ret;
}

int32_t HITLS_OCSP_ReqCtrl(HITLS_OCSP_Req *req, int32_t cmd, void *val, uint32_t valLen)
{
    if (req == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    /* GET_NONCE / ADD_SINGLEREQ require a non-NULL val. SET_NONCE is intentionally
     * excluded: val == NULL auto-generates a random nonce (see HITLS_OCSP_ReqCmd). */
    if (val == NULL && (cmd == HITLS_OCSP_REQ_GET_NONCE || cmd == HITLS_OCSP_REQ_ADD_SINGLEREQ)) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    HITLS_OCSP_Req_Internal *internal = (HITLS_OCSP_Req_Internal *)req;

    switch (cmd) {
        case HITLS_OCSP_REQ_GET_NONCE:
            if (valLen < sizeof(BSL_Buffer)) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            return OcspGetNonce(internal->ext, (BSL_Buffer *)val, valLen);
        case HITLS_OCSP_REQ_ADD_SINGLEREQ:
            if (valLen < sizeof(HITLS_OCSP_SingleReq *)) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
                return HITLS_OCSP_ERR_INVALID_PARAM;
            }
            if (internal->isSigned) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_ALREADY_SIGNED);
                return HITLS_OCSP_ERR_ALREADY_SIGNED;
            }
            return OcspReqAddSingleReq(internal, (HITLS_OCSP_SingleReq *)val);
        case HITLS_OCSP_REQ_SET_NONCE:
            if (internal->isSigned) {
                BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_ALREADY_SIGNED);
                return HITLS_OCSP_ERR_ALREADY_SIGNED;
            }
            return OcspReqSetNonce(internal, (const uint8_t *)val, valLen);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_CMD_UNSUPPORT);
            return HITLS_OCSP_ERR_CMD_UNSUPPORT;
    }
}

int32_t HITLS_OCSP_ReqIsSigned(const HITLS_OCSP_Req *req, bool *isSigned)
{
    if (req == NULL || isSigned == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    const HITLS_OCSP_Req_Internal *internal = (const HITLS_OCSP_Req_Internal *)req;
    *isSigned = internal->isSigned;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_OCSP_ReqGetSingleReqCount(const HITLS_OCSP_Req *req, uint32_t *count)
{
    if (req == NULL || count == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    const HITLS_OCSP_Req_Internal *internal = (const HITLS_OCSP_Req_Internal *)req;
    *count = BSL_LIST_COUNT(internal->singleReqs);
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_OCSP_ReqGetSingleReqByIndex(const HITLS_OCSP_Req *req, uint32_t index, HITLS_OCSP_SingleReq **singleReq)
{
    if (req == NULL || singleReq == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    const HITLS_OCSP_Req_Internal *internal = (const HITLS_OCSP_Req_Internal *)req;
    uint32_t count = BSL_LIST_COUNT(internal->singleReqs);
    if (index >= count) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    *singleReq = (HITLS_OCSP_SingleReq *)BSL_LIST_GetIndexNode(index, internal->singleReqs);
    return HITLS_PKI_SUCCESS;
}

/* ==================== Req DER Encoding ==================== */

/*
 * OCSPRequest ::= SEQUENCE {                               depth=0
 *     tbsRequest      TBSRequest                           depth=1 (SEQUENCE, container)
 * }
 * TBSRequest ::= SEQUENCE {
 *     requestList SEQUENCE OF Request                      depth=2 (HEADERONLY, pre-encoded)
 *     requestExtensions [2] EXPLICIT Extensions OPTIONAL   depth=2 (container, OPTIONAL)
 *         Extensions SEQUENCE OF Extension                 depth=3 (HEADERONLY, pre-encoded)
 * }
 */
static int32_t OcspEncodeRequestList(BslList *singleReqs, BSL_ASN1_Buffer *out)
{
    uint32_t count = BSL_LIST_COUNT(singleReqs);
    if (count == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }

    /* Each Request has two leaves: reqCert (CertID) and optional singleRequestExtensions [0].
     * count is capped at HITLS_OCSP_MAX_SINGLE_REQ (1024) by the ADD_SINGLEREQ ctrl, so
     * count * 2 cannot overflow uint32. */
    BSL_ASN1_Buffer *asnArr = BSL_SAL_Calloc(count * 2, sizeof(BSL_ASN1_Buffer));
    if (asnArr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    int32_t ret = HITLS_PKI_SUCCESS;
    uint32_t i = 0;
    BslListNode *node = BSL_LIST_FirstNode(singleReqs);
    while (node != NULL) {
        HITLS_OCSP_SingleReq *singleReq = (HITLS_OCSP_SingleReq *)BSL_LIST_GetData(node);
        const HITLS_OCSP_SingleReq_Internal *sr = (const HITLS_OCSP_SingleReq_Internal *)singleReq;
        ret = OcspEncodeCertId(sr->certId, &asnArr[i * 2]);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
        ret = OcspEncodeExt(sr->ext, BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, &asnArr[i * 2 + 1]);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
        i++;
        node = BSL_LIST_GetNextNode(singleReqs, node);
    }

    BSL_ASN1_Template elemTempl = {g_ocspRequestElemEncTempl,
                                    sizeof(g_ocspRequestElemEncTempl) / sizeof(g_ocspRequestElemEncTempl[0])};
    ret = BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SEQUENCE, count, &elemTempl, asnArr, i * 2, out);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    /* Success path falls through to the shared EXIT cleanup; ret is already HITLS_PKI_SUCCESS. */
EXIT:
    /* asnArr is Calloc-zeroed and BSL_SAL_Free(NULL) is a no-op, so freeing all count
     * slots is safe even when the loop was interrupted: the current (i-th) iteration's
     * CertID leaf is reclaimed and any unwritten leaf stays NULL. */
    for (uint32_t j = 0; j < count; j++) {
        BSL_SAL_Free(asnArr[j * 2].buff);
        BSL_SAL_Free(asnArr[j * 2 + 1].buff);
    }
    BSL_SAL_Free(asnArr);
    return ret;
}

static int32_t OcspReqEncodeTbsRawData(const HITLS_OCSP_Req_Internal *internal, bool needSequence, BSL_Buffer *buff)
{
    /* Reuse the existing TBSRequest encoder; when isSigned we must not be here
     * with an empty request (ReqSign validates the request first). */
    BSL_ASN1_Buffer requestListDer = {0};
    int32_t ret = OcspEncodeRequestList(internal->singleReqs, &requestListDer);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    BSL_ASN1_Buffer extensionsDer = {0};
    ret = OcspEncodeExt(internal->ext, BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 2,
                        &extensionsDer);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(requestListDer.buff);
        return ret;
    }
    BSL_ASN1_Buffer tbsAsns[3] = {
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1, internal->requestorName.dataLen,
            internal->requestorName.data},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, requestListDer.len, requestListDer.buff},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 2, extensionsDer.len,
            extensionsDer.buff},
    };
    BSL_ASN1_Template templ = {g_ocspTbsReqEncTempl, sizeof(g_ocspTbsReqEncTempl) / sizeof(g_ocspTbsReqEncTempl[0])};
    uint8_t *tbsDer = NULL;
    uint32_t tbsDerLen = 0;
    ret = BSL_ASN1_EncodeTemplate(&templ, tbsAsns, 3, &tbsDer, &tbsDerLen);
    BSL_SAL_Free(requestListDer.buff);
    BSL_SAL_Free(extensionsDer.buff);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (!needSequence) {
        buff->data = tbsDer;
        buff->dataLen = tbsDerLen;
        return HITLS_PKI_SUCCESS;
    }

    BSL_ASN1_Buffer tbsContent = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, tbsDerLen, tbsDer};
    BSL_ASN1_TemplateItem templItem = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0};
    BSL_ASN1_Template templ2 = {&templItem, 1};

    ret = BSL_ASN1_EncodeTemplate(&templ2, &tbsContent, 1, &buff->data, &buff->dataLen);
    BSL_SAL_Free(tbsDer);
    return ret;
}

int32_t HITLS_OCSP_ReqGenBuff(int32_t format, const HITLS_OCSP_Req *req, BSL_Buffer *buff)
{
    if (req == NULL || buff == NULL) {
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

    const HITLS_OCSP_Req_Internal *internal = (const HITLS_OCSP_Req_Internal *)req;
    if (BSL_LIST_COUNT(internal->singleReqs) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_EMPTY_REQUEST);
        return HITLS_OCSP_ERR_EMPTY_REQUEST;
    }

    /* Signed requests were fully encoded at sign time; return the saved encoding. */
    if (internal->isSigned) {
        if (internal->rawData.data == NULL || internal->rawData.dataLen == 0) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NOT_SIGNED);
            return HITLS_OCSP_ERR_NOT_SIGNED;
        }
        buff->data = BSL_SAL_Dump(internal->rawData.data, internal->rawData.dataLen);
        if (buff->data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        buff->dataLen = internal->rawData.dataLen;
        return HITLS_PKI_SUCCESS;
    }

    BSL_Buffer tbsRawData = {0};
    uint8_t *outDer = NULL;
    uint32_t outLen = 0;
    int32_t ret = OcspReqEncodeTbsRawData(internal, true, &tbsRawData);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    BSL_ASN1_Template templ = {g_ocspReqUnsignedEncTempl,
                               sizeof(g_ocspReqUnsignedEncTempl) / sizeof(g_ocspReqUnsignedEncTempl[0])};
    BSL_ASN1_Buffer asns[1] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, tbsRawData.dataLen, tbsRawData.data},
    };

    ret = BSL_ASN1_EncodeTemplate(&templ, asns, 1, &outDer, &outLen);
    BSL_SAL_Free(tbsRawData.data);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    buff->data = outDer;
    buff->dataLen = outLen;
    outDer = NULL;
    return ret;
}

/* ==================== Req DER Decoding ==================== */

int32_t OcspSetHashField(CRYPT_MD_AlgId hashAlg, BSL_ASN1_Buffer *field, const uint8_t *hash, uint32_t hashLen)
{
    uint32_t expectLen;
    switch (hashAlg) {
        case CRYPT_MD_SHA1:
            expectLen = 20;
            break;
        case CRYPT_MD_SHA224:
            expectLen = 28;
            break;
        case CRYPT_MD_SHA256:
            expectLen = 32;
            break;
        case CRYPT_MD_SHA384:
            expectLen = 48;
            break;
        case CRYPT_MD_SHA512:
            expectLen = 64;
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_MD_UNSUPPORT);
            return HITLS_OCSP_ERR_MD_UNSUPPORT;
    }
    if (hashLen != expectLen) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_HASH_LEN);
        return HITLS_OCSP_ERR_INVALID_HASH_LEN;
    }
    field->buff = BSL_SAL_Dump(hash, hashLen);
    if (field->buff == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    field->len = hashLen;
    field->tag = BSL_ASN1_TAG_OCTETSTRING;
    return HITLS_PKI_SUCCESS;
}

/* Request-side wrappers: the shared decode helpers return the context-neutral
 * HITLS_OCSP_ERR_MALFORMED for malformed DER; convert it to the request code. */
static int32_t OcspParseReqCertId(const BSL_ASN1_Buffer *asn, HITLS_OCSP_CertId_Internal *certId)
{
    int32_t ret = OcspParseCertId(asn, certId);
    if (ret == HITLS_OCSP_ERR_MALFORMED) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_REQUEST);
        ret = HITLS_OCSP_ERR_INVALID_REQUEST;
    }
    return ret;
}

static int32_t OcspParseReqCerts(BSL_ASN1_Buffer *certsAsn, BslList **certs)
{
    int32_t ret = OcspParseCerts(certsAsn, certs);
    if (ret == HITLS_OCSP_ERR_MALFORMED) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_REQUEST);
        ret = HITLS_OCSP_ERR_INVALID_REQUEST;
    }
    return ret;
}

static int32_t OcspParseSingleReq(uint32_t layer, BSL_ASN1_Buffer *asn, void *cbParam, BSL_ASN1_List *list)
{
    (void)layer;
    (void)cbParam;

    BSL_ASN1_Buffer reqAsns[REQUEST_DEC_MAX_IDX] = {0};
    BSL_ASN1_Template reqTempl = {g_ocspRequestDecTempl,
                                   sizeof(g_ocspRequestDecTempl) / sizeof(g_ocspRequestDecTempl[0])};
    uint8_t *buff = asn->buff;
    uint32_t len = asn->len;
    int32_t ret = BSL_ASN1_DecodeTemplate(&reqTempl, OcspTagGetOrCheck, &buff, &len, reqAsns, REQUEST_DEC_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (len != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_REQUEST);
        return HITLS_OCSP_ERR_INVALID_REQUEST;
    }

    HITLS_OCSP_CertId_Internal *certId = BSL_SAL_Calloc(1, sizeof(HITLS_OCSP_CertId_Internal));
    if (certId == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ret = OcspParseReqCertId(&reqAsns[REQUEST_DEC_CERTID_IDX], certId);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_OCSP_CertIdFree((HITLS_OCSP_CertId *)certId);
        return ret;
    }
    HITLS_OCSP_SingleReq_Internal *singleReq = BSL_SAL_Calloc(1, sizeof(HITLS_OCSP_SingleReq_Internal));
    if (singleReq == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        HITLS_OCSP_CertIdFree((HITLS_OCSP_CertId *)certId);
        return BSL_MALLOC_FAIL;
    }
    singleReq->certId = (HITLS_OCSP_CertId *)certId;
    if (reqAsns[REQUEST_DEC_SINGLE_EXT_IDX].tag != 0) {
        ret = OcspDecodeExt(&reqAsns[REQUEST_DEC_SINGLE_EXT_IDX], &singleReq->ext);
        if (ret != HITLS_PKI_SUCCESS) {
            HITLS_OCSP_SingleReqFree((HITLS_OCSP_SingleReq *)singleReq);
            return ret;
        }
    }
    ret = BSL_LIST_AddElement((BslList *)list, singleReq, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        HITLS_OCSP_SingleReqFree((HITLS_OCSP_SingleReq *)singleReq);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

/* Save the signed-data copies (tbsRawData / rawData) needed to re-encode or verify. */
static int32_t OcspParseReqSignedData(const BSL_Buffer *encode, HITLS_OCSP_Req_Internal *internal)
{
    uint8_t *tbsPtr = NULL;
    uint32_t tbsLen = 0;
    int32_t ret = HITLS_X509_ParseTbsRawData((uint8_t *)encode->data, encode->dataLen, &tbsPtr, &tbsLen);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    internal->tbsRawData.data = BSL_SAL_Dump(tbsPtr, tbsLen);
    if (internal->tbsRawData.data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    /* Save the full encoding so ReqGenBuff can re-emit the parsed signed request. */
    internal->rawData.data = BSL_SAL_Dump((uint8_t *)encode->data, encode->dataLen);
    if (internal->rawData.data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_FREE(internal->tbsRawData.data);
        return BSL_MALLOC_FAIL;
    }
    internal->rawData.dataLen = encode->dataLen;
    internal->tbsRawData.dataLen = tbsLen;
    return HITLS_PKI_SUCCESS;
}

/* Parse the optionalSignature fields (signatureAlgorithm, signature, certs) and, when a
 * signature is present, the signed-data copies (tbsRawData / rawData). */
static int32_t OcspParseReqSignature(BSL_ASN1_Buffer *asns, const BSL_Buffer *encode, HITLS_OCSP_Req_Internal *internal)
{
    if (asns[OCSP_REQ_DEC_SIGALG_OID_IDX].tag == 0) {
        return HITLS_PKI_SUCCESS; /* unsigned request: no optionalSignature */
    }

    int32_t ret = HITLS_X509_ParseSignAlgInfo(&asns[OCSP_REQ_DEC_SIGALG_OID_IDX],
                                              &asns[OCSP_REQ_DEC_SIGALG_PARAM_IDX], &internal->signAlgId);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_ASN1_DecodePrimitiveItem(&asns[OCSP_REQ_DEC_SIG_IDX], &internal->signature);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t *sigCopy = BSL_SAL_Dump(internal->signature.buff, internal->signature.len);
    if (sigCopy == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        internal->signature.buff = NULL; /* was borrowed from encode->data; must not be freed */
        internal->signature.len = 0;
        return BSL_MALLOC_FAIL;
    }
    internal->signature.buff = sigCopy;
    if (asns[OCSP_REQ_DEC_CERTS_IDX].tag != 0) {
        ret = OcspParseReqCerts(&asns[OCSP_REQ_DEC_CERTS_IDX], &internal->certs);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    internal->isSigned = true;

    return OcspParseReqSignedData(encode, internal);
}

/* Parse the TBSRequest leaf fields: version, requestorName and extensions. */
static int32_t OcspParseReqFields(BSL_ASN1_Buffer *asns, HITLS_OCSP_Req_Internal *internal)
{
    if (asns[OCSP_REQ_DEC_VERSION_IDX].tag != 0) {
        const uint8_t *vp = asns[OCSP_REQ_DEC_VERSION_IDX].buff;
        uint32_t vl = asns[OCSP_REQ_DEC_VERSION_IDX].len;
        if (vl != 1 || *vp != 0) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_VERSION);
            return HITLS_OCSP_ERR_INVALID_VERSION;
        }
    }

    if (asns[OCSP_REQ_DEC_EXTENSIONS_IDX].tag != 0) {
        int32_t ret = OcspDecodeExt(&asns[OCSP_REQ_DEC_EXTENSIONS_IDX], &internal->ext);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    if (asns[OCSP_REQ_DEC_REQUESTOR_NAME_IDX].tag != 0) {
        /* The [1] EXPLICIT wrapper is unwrapped by the template; the leaf holds the inner
         * GeneralName TLV (A4 ...), matching the representation produced by
         * OcspGenRequestorName at sign time. */
        internal->requestorName.data =
            BSL_SAL_Dump(asns[OCSP_REQ_DEC_REQUESTOR_NAME_IDX].buff, asns[OCSP_REQ_DEC_REQUESTOR_NAME_IDX].len);
        if (internal->requestorName.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        internal->requestorName.dataLen = asns[OCSP_REQ_DEC_REQUESTOR_NAME_IDX].len;
    }
    return HITLS_PKI_SUCCESS;
}

/* Decode the outer OCSPRequest template. On success outputs the leaf fields into asns. */
static int32_t OcspDecodeReqTemplate(const BSL_Buffer *encode, BSL_ASN1_Buffer *asns)
{
    uint8_t *temp = (uint8_t *)encode->data;
    uint32_t tempLen = encode->dataLen;
    BSL_ASN1_Template templ = {g_ocspReqDecTempl, sizeof(g_ocspReqDecTempl) / sizeof(g_ocspReqDecTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, OcspTagGetOrCheck, &temp, &tempLen, asns, OCSP_REQ_DEC_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (tempLen != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_REQUEST);
        return HITLS_OCSP_ERR_INVALID_REQUEST;
    }
    return HITLS_PKI_SUCCESS;
}

/* Parse the requestList SEQUENCE OF Request into internal->singleReqs. */
static int32_t OcspParseReqRequestList(BSL_ASN1_Buffer *asns, HITLS_OCSP_Req_Internal *internal)
{
    if (asns[OCSP_REQ_DEC_REQUESTLIST_IDX].tag == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_EMPTY_REQUEST);
        return HITLS_OCSP_ERR_EMPTY_REQUEST;
    }

    uint8_t expTag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    BSL_ASN1_DecodeListParam listParam = {1, &expTag};
    int32_t ret = BSL_ASN1_DecodeListItem(&listParam, &asns[OCSP_REQ_DEC_REQUESTLIST_IDX], OcspParseSingleReq, NULL,
                                          internal->singleReqs);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (BSL_LIST_COUNT(internal->singleReqs) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_EMPTY_REQUEST);
        return HITLS_OCSP_ERR_EMPTY_REQUEST;
    }
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_OCSP_ReqParseBuff(int32_t format, const BSL_Buffer *encode, HITLS_OCSP_Req **req)
{
    if (encode == NULL || encode->data == NULL || req == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    if (*req != NULL) {
        /* The output must be NULL on entry; a pre-filled pointer would be overwritten (leaking it). */
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    if (format != BSL_FORMAT_ASN1) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }

    HITLS_OCSP_Req_Internal *internal = (HITLS_OCSP_Req_Internal *)HITLS_OCSP_ReqNew();
    if (internal == NULL) {
        return BSL_MALLOC_FAIL;
    }

    BSL_ASN1_Buffer asns[OCSP_REQ_DEC_MAX_IDX] = {0};
    int32_t ret = OcspDecodeReqTemplate(encode, asns);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    ret = OcspParseReqRequestList(asns, internal);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    ret = OcspParseReqFields(asns, internal);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    ret = OcspParseReqSignature(asns, encode, internal);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    *req = (HITLS_OCSP_Req *)internal;
    return HITLS_PKI_SUCCESS;

EXIT:
    HITLS_OCSP_ReqFree((HITLS_OCSP_Req *)internal);
    return ret;
}

/* ==================== Req Sign / Verify ==================== */

/* Encode the full signed OCSPRequest:
 * OCSPRequest ::= SEQUENCE {
 *     tbsRequest      TBSRequest,
 *     optionalSignature [0] EXPLICIT Signature OPTIONAL }
 * Signature ::= SEQUENCE { signatureAlgorithm, signature, certs [0] EXPLICIT ... OPTIONAL }
 * Reuses the shared cert encoder and HITLS_X509_EncodeSignAlgInfo (same as response). */
static int32_t OcspEncodeSignedReq(HITLS_OCSP_Req_Internal *internal, BSL_Buffer *out)
{
    if (internal->tbsRawData.data == NULL || internal->tbsRawData.dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NOT_SIGNED);
        return HITLS_OCSP_ERR_NOT_SIGNED;
    }

    /* Signature ::= SEQUENCE { signatureAlgorithm, signature, certs [0]? } */
    BSL_ASN1_Buffer algIdDer = {0};
    int32_t ret = HITLS_X509_EncodeSignAlgInfo(&internal->signAlgId, &algIdDer);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_Buffer certsV = {0};
    ret = OcspEncodeCerts(internal->certs, &certsV);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(algIdDer.buff);
        return ret;
    }

    /* OCSPRequest ::= SEQUENCE { tbsRequest, optionalSignature [0] EXPLICIT Signature }
     * tbsRawData is the full TBSRequest TLV; strip outer T+L then re-wrap as the
     * tbsRequest field (mirrors OcspEncodeBasicResp). */
    BSL_ASN1_Buffer tbsWrap = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
                                internal->tbsRawData.dataLen, internal->tbsRawData.data};
    BSL_ASN1_Buffer tbsV = {0};
    ret = OcspStripTlv(&tbsWrap, &tbsV);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(algIdDer.buff);
        BSL_SAL_Free(certsV.buff);
        return ret;
    }
    BSL_ASN1_Buffer outerAsns[] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, tbsV.len, tbsV.buff},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, algIdDer.len, algIdDer.buff},
        {BSL_ASN1_TAG_BITSTRING, sizeof(BSL_ASN1_BitString), (uint8_t *)&internal->signature},
        {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED, certsV.len, certsV.buff},
    };
    BSL_ASN1_Template outerTempl = {g_ocspReqSignedEncTempl,
                                    sizeof(g_ocspReqSignedEncTempl) / sizeof(g_ocspReqSignedEncTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&outerTempl, outerAsns, 4, &out->data, &out->dataLen);
    BSL_SAL_Free(algIdDer.buff);
    BSL_SAL_Free(certsV.buff);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

/* Build requestorName [1] EXPLICIT GeneralName (directoryName [4] Name).
 * On success, *out points to a malloc'd buffer holding the full requestorName TLV. */

static int32_t OcspReqSignCb(int32_t mdId, CRYPT_EAL_PkeyCtx *prvKey, HITLS_X509_Asn1AlgId *signAlgId, void *obj)
{
    HITLS_OCSP_Req_Internal *internal = (HITLS_OCSP_Req_Internal *)obj;
    internal->signAlgId = *signAlgId;

    BSL_Buffer buff = {0};
    int32_t ret = OcspReqEncodeTbsRawData(internal, false, &buff);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    BSL_ASN1_Buffer tbsContent = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, buff.dataLen, buff.data};
    ret = HITLS_X509_SignAsn1Data(prvKey, (CRYPT_MD_AlgId)mdId, &tbsContent,
                                  &internal->tbsRawData, &internal->signature);
    BSL_SAL_Free(buff.data);
    return ret;
}

static int32_t OcspGenRequestorName(HITLS_OCSP_Req_Internal *internal, const HITLS_X509_Cert *requestorCert)
{
    /* Extract requestorName from the cert's Subject DN as GeneralName directoryName [4] */
    int32_t ret = 0;
    BSL_Buffer dnDer = {0};
    ret = HITLS_X509_CertCtrl((HITLS_X509_Cert *)(uintptr_t)requestorCert,
                              HITLS_X509_GET_ENCODE_SUBJECT_DN, &dnDer, sizeof(BSL_Buffer *));
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_ASN1_TemplateItem gnItem = {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 4, 0, 0};
    BSL_ASN1_Template gnTempl = {&gnItem, 1};
    BSL_ASN1_Buffer nameAsn = {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 4,
                               dnDer.dataLen, dnDer.data};
    uint8_t *gnDer = NULL;
    uint32_t gnDerLen = 0;
    ret = BSL_ASN1_EncodeTemplate(&gnTempl, &nameAsn, 1, &gnDer, &gnDerLen);
    BSL_SAL_Free(dnDer.data);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /* Re-signing a parsed request overwrites requestorName: release the old buffer first. */
    BSL_SAL_FREE(internal->requestorName.data);
    internal->requestorName.data = gnDer;
    internal->requestorName.dataLen = gnDerLen;
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_OCSP_ReqSign(int32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam,
                           const HITLS_X509_Cert *requestorCert, const HITLS_X509_List *certs, HITLS_OCSP_Req *req,
                           HITLS_OCSP_SignFlag flags)
{
    if (req == NULL || prvKey == NULL || requestorCert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }

    /* Validate flags: only NOCERTS applies to requests (RESPID_BYKEY is response-only). */
    if (flags & ~HITLS_OCSP_SIGN_NOCERTS) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }

    int32_t ret = OcspCheckSignKey(prvKey, requestorCert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    HITLS_OCSP_Req_Internal *internal = (HITLS_OCSP_Req_Internal *)req;
    if (internal->isSigned) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_ALREADY_SIGNED);
        return HITLS_OCSP_ERR_ALREADY_SIGNED;
    }
    if (BSL_LIST_COUNT(internal->singleReqs) == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_EMPTY_REQUEST);
        return HITLS_OCSP_ERR_EMPTY_REQUEST;
    }

    ret = OcspGenRequestorName(internal, requestorCert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    /* Reference-count the embedded certs; requestorCert is embedded automatically
     * (unless NOCERTS) so the request is self-contained for verification. */
    if (!(flags & HITLS_OCSP_SIGN_NOCERTS)) {
        ret = OcspRefUpSignerCerts(requestorCert, certs, &internal->certs);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
    }

    ret = HITLS_X509_Sign(mdId, prvKey, algParam, internal, OcspReqSignCb);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    /* Encode the full signed OCSPRequest and save it; ReqGenBuff returns this directly. */
    ret = OcspEncodeSignedReq(internal, &internal->rawData);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    internal->isSigned = true;
    return HITLS_PKI_SUCCESS;

EXIT:
    BSL_SAL_FREE(internal->signature.buff);
    BSL_SAL_FREE(internal->tbsRawData.data);
    BSL_SAL_FREE(internal->requestorName.data);
    BSL_LIST_FREE(internal->certs, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return ret;
}

/* Match a certificate against the request's requestorName.
 * requestorName is a GeneralName directoryName TLV (A4 <len> <Name SEQUENCE>);
 * compare the inner Name SEQUENCE with the cert's encoded subject DN. */
static bool OcspMatchRequestorName(const HITLS_OCSP_Req_Internal *internal, const HITLS_X509_Cert *cert)
{
    if (internal->requestorName.data == NULL || internal->requestorName.dataLen == 0) {
        return false;
    }
    BSL_ASN1_Buffer gnTlv = {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 4,
                             internal->requestorName.dataLen, internal->requestorName.data};
    BSL_ASN1_Buffer nameTlv = {0};
    if (OcspStripTlv(&gnTlv, &nameTlv) != HITLS_PKI_SUCCESS) {
        return false;
    }
    if (nameTlv.buff == NULL || nameTlv.len == 0) {
        return false;
    }

    BSL_Buffer dnDer = {0};
    int32_t ret = HITLS_X509_CertCtrl((HITLS_X509_Cert *)(uintptr_t)cert,
                                      HITLS_X509_GET_ENCODE_SUBJECT_DN, &dnDer, sizeof(BSL_Buffer *));
    if (ret != HITLS_PKI_SUCCESS) {
        return false;
    }
    bool match = (dnDer.dataLen == nameTlv.len && memcmp(dnDer.data, nameTlv.buff, dnDer.dataLen) == 0);
    BSL_SAL_Free(dnDer.data);
    return match;
}

/* Find the signer cert matching requestorName in a cert list. */
static HITLS_X509_Cert *OcspFindSignerByRequestorName(const HITLS_OCSP_Req_Internal *internal,
                                                      const HITLS_X509_List *certs)
{
    if (certs == NULL) {
        return NULL;
    }
    BslListNode *node = BSL_LIST_FirstNode(certs);
    while (node != NULL) {
        HITLS_X509_Cert *cert = (HITLS_X509_Cert *)BSL_LIST_GetData(node);
        if (cert != NULL && OcspMatchRequestorName(internal, cert)) {
            return cert;
        }
        node = BSL_LIST_GetNextNode(certs, node);
    }
    return NULL;
}

int32_t HITLS_OCSP_ReqVerify(const HITLS_OCSP_Req *req, const HITLS_X509_List *certs,
                             const HITLS_X509_StoreCtx *storeCtx, HITLS_OCSP_VfyFlag flags)
{
    if (req == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    /* Validate flags: only TRUSTOTHER and NOINTERN are supported */
    if (flags & ~(HITLS_OCSP_VFY_TRUSTOTHER | HITLS_OCSP_VFY_NOINTERN)) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }

    const HITLS_OCSP_Req_Internal *internal = (const HITLS_OCSP_Req_Internal *)req;
    if (!internal->isSigned) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NOT_SIGNED);
        return HITLS_OCSP_ERR_NOT_SIGNED;
    }
    if (internal->signature.buff == NULL || internal->tbsRawData.data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }

    /* Signer lookup only supports a directoryName [4] requestorName (the form produced by
     * ReqSign). RFC 6960 permits any GeneralName, but resolving the other forms against a
     * certificate is not implemented, so reject them explicitly instead of a misleading
     * SIGNER_NOT_FOUND. */
    if (internal->requestorName.data != NULL && internal->requestorName.dataLen > 0 &&
        internal->requestorName.data[0] != (BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 4)) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_REQUESTOR_NAME_UNSUPPORT);
        return HITLS_OCSP_ERR_REQUESTOR_NAME_UNSUPPORT;
    }

    /* Locate the signer certificate by matching the requestorName (Subject DN) in the
     * external certs list first, then in the embedded certs unless NOINTERN. */
    HITLS_X509_Cert *signer = NULL;
    bool signerFromExternal = false;
    signer = OcspFindSignerByRequestorName(internal, certs);
    signerFromExternal = (signer != NULL);
    if (signer == NULL && !(flags & HITLS_OCSP_VFY_NOINTERN)) {
        signer = OcspFindSignerByRequestorName(internal, internal->certs);
    }
    if (signer == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_SIGNER_NOT_FOUND);
        return HITLS_OCSP_ERR_SIGNER_NOT_FOUND;
    }

    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    int32_t ret = HITLS_X509_CertCtrl(signer, HITLS_X509_GET_PUBKEY, &pubKey, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HITLS_X509_CheckSignature(pubKey, internal->tbsRawData.data, internal->tbsRawData.dataLen,
                                    &internal->signAlgId, &internal->signature);
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_SIGN_VERIFY);
        return HITLS_OCSP_ERR_SIGN_VERIFY;
    }

    /* A signer taken from the external certs with HITLS_OCSP_VFY_TRUSTOTHER is trusted as-is;
     * no chain validation is performed (matches BasicRespVerify semantics). */
    if (signerFromExternal && (flags & HITLS_OCSP_VFY_TRUSTOTHER)) {
        return HITLS_PKI_SUCCESS;
    }

    /* Otherwise chain validation is required; storeCtx must be provided. */
    if (storeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    HITLS_X509_Cert *signerIssuer = NULL;
    ret = OcspVerifySigner(internal->certs, certs, storeCtx, signer, &signerIssuer);
    HITLS_X509_CertFree(signerIssuer);
    return ret;
}

#endif // HITLS_PKI_OCSP

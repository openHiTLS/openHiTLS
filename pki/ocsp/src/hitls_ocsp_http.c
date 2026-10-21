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

#include <stdint.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_asn1.h"
#include "bsl_http.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_ocsp.h"
#include "hitls_pki_ocsp_http.h"
#include "hitls_ocsp_local.h"

#define HITLS_OCSP_HTTP_REQ_CONTENT_TYPE "application/ocsp-request"
#define HITLS_OCSP_HTTP_EXPECTED_RESP_CT "application/ocsp-response"

/* Cross-check the HTTP response body against its ASN.1 DER length: the received body
 * must be exactly one well-formed OCSPResponse SEQUENCE. A Content-Length that
 * disagrees with the DER length inside the body is rejected before decoding. */
static int32_t OcspHttpCheckRespDer(const uint8_t *body, uint32_t bodyLen)
{
    /* An empty or sub-2-byte body is a malformed response (it cannot carry an
     * OCSPResponse SEQUENCE), not an internal NULL fault. Checked before
     * body == NULL so an empty body (respBody = NULL, respLen = 0 from the
     * HTTP layer) is reported as LENGTH_MISMATCH rather than NULL_POINTER. */
    if (bodyLen < 2) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_LENGTH_MISMATCH);
        return HITLS_OCSP_ERR_LENGTH_MISMATCH;
    }
    if (body == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    if (bodyLen < 2) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_LENGTH_MISMATCH);
        return HITLS_OCSP_ERR_LENGTH_MISMATCH;
    }
    uint8_t *p = (uint8_t *)(uintptr_t)body;
    uint32_t rest = bodyLen;
    uint32_t valLen = 0;
    int32_t ret = BSL_ASN1_DecodeTagLen(0x30, &p, &rest, &valLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_RESPONSE);
        return HITLS_OCSP_ERR_INVALID_RESPONSE;
    }
    uint32_t hdrLen = bodyLen - rest; /* tag + length field consumed */
    if ((uint64_t)hdrLen + valLen != bodyLen) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_LENGTH_MISMATCH);
        return HITLS_OCSP_ERR_LENGTH_MISMATCH;
    }
    return HITLS_PKI_SUCCESS;
}

HITLS_HTTP_ReqCtx *HITLS_OCSP_HttpReqCtxNew(BSL_UIO *uio, const char *path, const HITLS_OCSP_Req *req)
{
    if (uio == NULL || path == NULL || req == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return NULL;
    }
    HITLS_HTTP_ReqCtx *httpCtx = HITLS_HTTP_ReqCtxNew(uio, HITLS_HTTP_METHOD_POST, path);
    if (httpCtx == NULL) {
        return NULL;
    }
    int32_t ret = HITLS_HTTP_ReqCtxCtrl(httpCtx, HITLS_HTTP_CTRL_SET_EXPECTED_CT, HITLS_OCSP_HTTP_EXPECTED_RESP_CT, 0);
    if (ret != BSL_SUCCESS) {
        HITLS_HTTP_ReqCtxFree(httpCtx);
        return NULL;
    }
    BSL_Buffer derBuf = {0};
    ret = HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &derBuf);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_HTTP_ReqCtxFree(httpCtx);
        return NULL;
    }
    ret = HITLS_HTTP_ReqCtxSetReq(httpCtx, HITLS_OCSP_HTTP_REQ_CONTENT_TYPE, derBuf.data, derBuf.dataLen);
    BSL_SAL_FREE(derBuf.data);
    if (ret != BSL_SUCCESS) {
        HITLS_HTTP_ReqCtxFree(httpCtx);
        return NULL;
    }
    return httpCtx;
}

int32_t HITLS_OCSP_HttpReqCtxExchange(HITLS_HTTP_ReqCtx *ctx, HITLS_OCSP_Resp **resp)
{
    if (ctx == NULL || resp == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    *resp = NULL;
    const uint8_t *respBody = NULL;
    uint32_t respLen = 0;
    /* One non-blocking step of the HTTP exchange; on HITLS_OCSP_ERR_IN_PROGRESS
     * the caller retries (typically sleeping between attempts). */
    int32_t ret = HITLS_HTTP_ReqCtxExchange(ctx, &respBody, &respLen);
    if (ret == BSL_HTTP_ERR_IN_PROGRESS) {
        return HITLS_OCSP_ERR_IN_PROGRESS;
    }
    if (ret != BSL_SUCCESS) {
        /* A non-200 status means the responder did not produce an OCSP
         * response; surface it as an HTTP-status error instead of the raw
         * BSL_HTTP_ERR_RESP_STATUS (the status code is available via
         * HITLS_HTTP_CTRL_GET_RESP_STATUS). */
        if (ret == BSL_HTTP_ERR_RESP_STATUS) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_HTTP_STATUS);
            return HITLS_OCSP_ERR_HTTP_STATUS;
        }
        return ret;
    }
    ret = OcspHttpCheckRespDer(respBody, respLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    BSL_Buffer respDer = {(uint8_t *)(uintptr_t)respBody, respLen};
    return HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &respDer, resp);
}

#endif /* HITLS_PKI_OCSP */

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
#ifdef HITLS_TLS_FEATURE_STATUS_REQUEST
#include <string.h>
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "hitls_error.h"
#include "hitls_status_request.h"
#include "hitls_cert.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_msg.h"
#include "hs_extensions.h"
#include "hs_common.h"
#include "hs_kx.h"
#include "hs.h"
#include "pack.h"
#include "pack_extensions.h"
#include "parse_common.h"
#include "send_process.h"
#include "cert.h"
#include "cert_method.h"
#include "cert_mgr.h"
#include "status_request.h"

static void OcspRespFree(void *data)
{
    SAL_CERT_OcspRespFree((HITLS_CERT_OcspResp *)data);
}

/* OCSP stapling is supported on stream TLS 1.0-1.3 connections (RFC 6066);
 * DTLS and TLCP are excluded (DTLS has no such extension support, and the
 * TLCP stream protocol does not implement OCSP stapling). */
static bool IsStreamTlsStatusRequest(const TLS_Ctx *ctx)
{
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        return false;
    }
    uint32_t version = GET_VERSION_FROM_CTX(ctx);
    return (version == HITLS_VERSION_TLS10) || (version == HITLS_VERSION_TLS11) || (version == HITLS_VERSION_TLS12) ||
           (version == HITLS_VERSION_TLS13);
}

/* RFC 6066 allows the server to acknowledge status_request in the ServerHello
 * on stream TLS 1.0-1.2; TLS 1.3 carries the answer in CertificateEntry
 * extensions instead (RFC 8446), so a ServerHello echo is not legal there. */
bool IsServerHelloStatusRequestValid(const TLS_Ctx *ctx)
{
    return IsStreamTlsStatusRequest(ctx) && !IS_TLS13_FAMILY_VERSION(GET_VERSION_FROM_CTX(ctx));
}

/* Invoke the client status callback registered in the connection config. */
#ifdef HITLS_TLS_HOST_CLIENT
static int32_t InvokeOcspStatusCb(TLS_Ctx *ctx)
{
    HITLS_StatusCb cb = ctx->config.tlsConfig.statusCb;
    void *arg = ctx->config.tlsConfig.statusCbArg;
    if (cb == NULL) {
        return HITLS_SUCCESS;
    }
    return cb(ctx, arg);
}
#endif /* HITLS_TLS_HOST_CLIENT */

/* Invoke the server per-certificate stapling callback registered in the
 * connection config. The callback returns one response for the given certificate
 * through *resp. Without a callback the application did not opt into stapling,
 * so the certificate is skipped. The return value is one of
 * HITLS_STAPLING_SEND / _SKIP / _ERROR (or an invalid value to be rejected by
 * the caller). */
#ifdef HITLS_TLS_HOST_SERVER
static int32_t ServerStaplingCbInvoke(TLS_Ctx *ctx, HITLS_CERT_X509 *cert, uint32_t chainidx, HITLS_CERT_OcspResp **resp)
{
    *resp = NULL;
    HITLS_StaplingOneCertCb cb = ctx->config.tlsConfig.staplingCb;
    void *arg = ctx->config.tlsConfig.staplingCbArg;
    if (cb == NULL) {
        return HITLS_STAPLING_SKIP;
    }
    int32_t ret = cb(ctx, cert, chainidx, resp, arg);
    if (ret != HITLS_STAPLING_SEND && ret != HITLS_STAPLING_SKIP) {
        return ret; /* caller converts to internal_error */
    }
    /* A SEND without a response (or with a response that does not belong to this
     * certificate) means nothing is stapled for this certificate: fold both into
     * SKIP so the callers only handle SEND (matched) / SKIP (skip) / error. */
    if (ret != HITLS_STAPLING_SEND || *resp == NULL) {
        return HITLS_STAPLING_SKIP;
    }
    return SAL_CERT_OcspRespMatchCert(ctx, *resp, cert) ? HITLS_STAPLING_SEND : HITLS_STAPLING_SKIP;
}
#endif /* HITLS_TLS_HOST_SERVER */

/* Store a parsed OCSP response at the certificate depth index (chainidx 0 is
 * the EE certificate). The array is grown on demand and certificates without a
 * status_request extension leave a NULL entry so the array index stays aligned
 * with the peer certificate chain; the application can then match each response
 * to the certificate at the same depth. */
#ifdef HITLS_TLS_HOST_CLIENT
static int32_t StoreOcspRespToList(TLS_Ctx *ctx, HITLS_CERT_OcspResp *resp, uint32_t chainidx)
{
    if (ctx->peerOcspRespList == NULL) {
        ctx->peerOcspRespList = (HITLS_CERT_OcspResp **)BSL_SAL_Calloc(chainidx + 1, sizeof(HITLS_CERT_OcspResp *));
        if (ctx->peerOcspRespList == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        ctx->peerOcspRespCount = chainidx + 1;
    } else if (chainidx >= ctx->peerOcspRespCount) {
        /* Grow the array so index chainidx exists; new entries default to NULL. */
        HITLS_CERT_OcspResp **grown = (HITLS_CERT_OcspResp **)BSL_SAL_Calloc(chainidx + 1, sizeof(HITLS_CERT_OcspResp *));
        if (grown == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        (void)memcpy(grown, ctx->peerOcspRespList, ctx->peerOcspRespCount * sizeof(HITLS_CERT_OcspResp *));
        BSL_SAL_FREE(ctx->peerOcspRespList);
        ctx->peerOcspRespList = grown;
        ctx->peerOcspRespCount = chainidx + 1;
    }
    /* Defensive: a duplicate write to an already-filled slot would leak the
     * previous response (owned by the ctx); release it before overwriting. */
    if (ctx->peerOcspRespList[chainidx] != NULL) {
        OcspRespFree(ctx->peerOcspRespList[chainidx]);
    }
    ctx->peerOcspRespList[chainidx] = resp;
    return HITLS_SUCCESS;
}

/* Parse a DER OCSPResponse and store it at the certificate chain depth index.
 * Shared by the TLS 1.2 CertificateStatus and TLS 1.3 CertificateEntry paths;
 * a malformed DER aborts with bad_certificate_status_response (RFC 6066 §8). */
static int32_t ParseAndStoreOcspResp(TLS_Ctx *ctx, const BSL_Buffer *encode, uint32_t chainidx,
                                     uint32_t logId, const char *logStr)
{
    HITLS_CERT_OcspResp *resp = NULL;
    if (SAL_CERT_OcspRespParseBuff(ctx, encode, &resp) != HITLS_SUCCESS || resp == NULL) {
        return ParseErrorProcess(ctx, HITLS_MSG_HANDLE_OCSP_STATUS_ERR, logId, logStr,
                                 ALERT_BAD_CERTIFICATE_STATUS_RESPONSE);
    }
    int32_t ret = StoreOcspRespToList(ctx, resp, chainidx);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_OcspRespFree(resp);
    }
    return ret;
}
#endif /* HITLS_TLS_HOST_CLIENT */

#ifdef HITLS_TLS_HOST_CLIENT
int32_t PackClientStatusRequest(const TLS_Ctx *ctx, PackPacket *pkt)
{
    if (!IsStreamTlsStatusRequest(ctx)) {
        return HITLS_SUCCESS;
    }
    /* Extension body: status_type(1) + responder_id_list length(2) + request_extensions length(2). */
    int32_t ret = PackExtensionHeader(HS_EX_TYPE_STATUS_REQUEST, sizeof(uint8_t) + sizeof(uint16_t) * 2, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = PackAppendUint8ToBuf(pkt, HITLS_STATUS_REQUEST_TYPE_OCSP);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = PackAppendUint16ToBuf(pkt, 0);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = PackAppendUint16ToBuf(pkt, 0);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_HOST_CLIENT */

#ifdef HITLS_TLS_HOST_SERVER
int32_t PackServerStatusRequest(const TLS_Ctx *ctx, PackPacket *pkt)
{
    if (!IsServerHelloStatusRequestValid(ctx)) {
        return HITLS_SUCCESS;
    }
    /* The ServerHello acknowledgment carries an empty status_request body. */
    return PackEmptyExtension(HS_EX_TYPE_STATUS_REQUEST, true, pkt);
}
#endif /* HITLS_TLS_HOST_SERVER */

#ifdef HITLS_TLS_HOST_CLIENT
int32_t ParseServerStatusRequest(ParsePacket *pkt)
{
    TLS_Ctx *ctx = pkt->ctx;
    /* The negotiated version is not known while the ServerHello extensions are
     * parsed (GET_VERSION_FROM_CTX falls back to the configured maxVersion), so
     * protocol-version legality of an echo is not checked here. A TLS 1.3 echo
     * is rejected later by HS_CheckReceivedExtension (status_request is not in
     * the TLS 1.3 ServerHello allowed list); a DTLS/TLCP echo is rejected in
     * ClientCheckStatusRequest, where the negotiated version is known and
     * IsServerHelloStatusRequestValid is reliable. */
    if (ctx->config.tlsConfig.statusRequestType != HITLS_STATUS_REQUEST_TYPE_OCSP) {
        /* The client did not request stapling but the server acknowledged it. */
        return ParseErrorProcess(ctx, HITLS_PARSE_UNSUPPORTED_EXTENSION, 0, NULL, ALERT_UNSUPPORTED_EXTENSION);
    }
    if (pkt->bufLen != 0) {
        /* The ServerHello status_request extension must carry an empty body. */
        return ParseErrorProcess(ctx, HITLS_MSG_HANDLE_OCSP_STATUS_ERR, 0, NULL, ALERT_ILLEGAL_PARAMETER);
    }
    ctx->statusExpected = true;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_HOST_CLIENT */

#ifdef HITLS_TLS_HOST_SERVER
/* Parse the status_request extension from the client. Server-side handling is
 * lenient: RFC 6066 section 1.1 makes extensions backwards compatible (a
 * server that does not support an extension ignores it), and section 8 gives
 * the server the MAY to answer or not. A request the server cannot process
 * (wrong protocol, malformed body, unsupported status_type) is therefore
 * treated as "not requested": stapling is skipped and the handshake continues. */
int32_t ParseClientStatusRequest(ParsePacket *pkt, ClientHelloMsg *msg)
{
    (void)msg;
    if (!IsStreamTlsStatusRequest(pkt->ctx)) {
        /* DTLS/TLCP do not carry status_request; ignore the offer. */
        return HITLS_SUCCESS;
    }
    if (pkt->bufLen < (sizeof(uint8_t) + sizeof(uint16_t) * 2)) {
        /* Malformed extension, ignore it (RFC 6066 section 8: the server MAY
         * choose not to answer, so an unparseable request is not an error). */
        return HITLS_SUCCESS;
    }
    if (pkt->buf[0] != HITLS_STATUS_REQUEST_TYPE_OCSP) {
        /* Only the OCSP status type is supported (RFC 6066 section 8 defines
         * ocsp(1) as the only status_type); an unsupported type means the
         * server cannot fulfil the request and ignores it. */
        return HITLS_SUCCESS;
    }
    /* Only record the request here. The per-certificate stapling callback is
     * invoked once the certificates to be stapled are known: at certificate
     * selection time for TLS 1.2 (ServerFetchStaplingEeResp) and while building
     * the Certificate message for TLS 1.3 (PackCertEntryOcspStatus). */
    pkt->ctx->statusExpected = true;
    return HITLS_SUCCESS;
}

/* TLS 1.2: fetch the EE certificate's OCSP response from the per-certificate
 * callback once the certificate chain has been selected (called after
 * ProcessCertCallback in ServerPostProcessClientHello). The response and the
 * resulting staplingResult are cached so the ServerHello acknowledgment and the
 * CertificateStatus packing reuse them; the callback runs at most once per
 * handshake for the EE certificate. */
int32_t ServerFetchStaplingEeResp(TLS_Ctx *ctx)
{
    if (!IsStreamTlsStatusRequest(ctx) || !ctx->statusExpected) {
        return HITLS_SUCCESS;
    }
    /* The per-certificate callback is invoked at most once per handshake: this
     * function runs once from ServerPostProcessClientHello after the certificate
     * was selected. */
    HITLS_CERT_X509 *eeCert = HITLS_GetCertificate(ctx);
    HITLS_CERT_OcspResp *resp = NULL;
    int32_t cbRet = HITLS_STAPLING_SKIP;
    if (eeCert != NULL) {
        cbRet = ServerStaplingCbInvoke(ctx, eeCert, 0, &resp);
        if (cbRet != HITLS_STAPLING_SEND && cbRet != HITLS_STAPLING_SKIP) {
            return ParseErrorProcess(ctx, HITLS_INTERNAL_EXCEPTION, 0, NULL, ALERT_INTERNAL_ERROR);
        }
    }
    ctx->staplingResp = (cbRet == HITLS_STAPLING_SEND) ? resp : NULL;
    ctx->staplingResult = (cbRet == HITLS_STAPLING_SEND && resp != NULL) ? HITLS_STAPLING_SEND : HITLS_STAPLING_SKIP;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_HOST_SERVER */

#ifdef HITLS_TLS_HOST_SERVER
#endif /* HITLS_TLS_HOST_SERVER */

#ifdef HITLS_TLS_HOST_SERVER
/* Append the OCSP response body shared by the TLS 1.2 CertificateStatus message
 * and the TLS 1.3 CertificateEntry extension: status_type(1) + 24-bit length(3)
 * + the OCSP response DER. Frees der->data; on failure the caller's packet is
 * left in a partial state (the handshake aborts). */
static int32_t PackOcspRespBody(PackPacket *pkt, BSL_Buffer *der)
{
    int32_t ret = PackAppendUint8ToBuf(pkt, HITLS_STATUS_REQUEST_TYPE_OCSP);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(der->data);
        return ret;
    }
    uint32_t lenPos = 0;
    ret = PackStartLengthField(pkt, UINT24_SIZE, &lenPos);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(der->data);
        return ret;
    }
    ret = PackAppendDataToBuf(pkt, der->data, der->dataLen);
    BSL_SAL_FREE(der->data);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    PackCloseUint24Field(pkt, lenPos);
    return HITLS_SUCCESS;
}

/* Build the CertificateStatus message body (stream TLS up to 1.2). This is
 * reached only through the state machine: the server enters
 * TRY_SEND_CERTIFICATE_STATUS only when ServerNeedSendCertificateStatus
 * returns true (stapling was negotiated, the callback chose SEND, and an OCSP
 * response is ready), so the packing function itself only checks that the
 * first response is a non-empty, representable list entry. TLS 1.3 does not
 * use this message; it embeds the response in CertificateEntry instead. */
int32_t PackCertificateStatus(const TLS_Ctx *ctx, PackPacket *pkt)
{
    if (ctx->staplingResp == NULL) {
        /* Reached the send state without the EE response: an internal state
         * inconsistency. Fail explicitly instead of emitting an empty
         * CertificateStatus that would abort the peer. */
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_INPUT);
        return HITLS_INVALID_INPUT;
    }
    BSL_Buffer buff = {0};
    int32_t ret = SAL_CERT_OcspRespGenBuff(ctx->staplingResp, &buff);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (buff.dataLen > 0xFFFFFFu) {
        BSL_SAL_FREE(buff.data);
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_INPUT);
        return HITLS_INVALID_INPUT;
    }
    /* Message body: status_type(1) + response length(3) + OCSP response DER. */
    return PackOcspRespBody(pkt, &buff);
}
#endif /* HITLS_TLS_HOST_SERVER */

/* TLS 1.2 client: transition to the state following the CertificateStatus message. */
#ifdef HITLS_TLS_HOST_CLIENT
int32_t ClientRecvCertificateStatus(TLS_Ctx *ctx, const HS_Msg *hsMsg)
{
    const CertificateStatusMsg *msg = &hsMsg->body.certificateStatus;
    /* The client only waits for CertificateStatus when it requested stapling and
     * the server acknowledged it; a CertificateStatus otherwise is unexpected. */
    if (!ctx->statusExpected) {
        return ParseErrorProcess(ctx, HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE, 0, NULL, ALERT_UNEXPECTED_MESSAGE);
    }
    if (msg->statusType != HITLS_STATUS_REQUEST_TYPE_OCSP) {
        return ParseErrorProcess(ctx, HITLS_MSG_HANDLE_OCSP_STATUS_ERR, 0, NULL, ALERT_ILLEGAL_PARAMETER);
    }
    /* RFC 6066 section 8: OCSPResponse is opaque<1..2^24-1>, and a client that requested the status
     * request must abort with bad_certificate_status_response(113) on an unsatisfactory response. */
    if (msg->response == NULL || msg->responseLen == 0) {
        return ParseErrorProcess(ctx, HITLS_MSG_HANDLE_OCSP_STATUS_ERR, BINLOG_ID17426,
                                 BINGLOG_STR("certificate status response is empty"),
                                 ALERT_BAD_CERTIFICATE_STATUS_RESPONSE);
    }
    /* The peer response must be a parseable OCSPResponse; a malformed DER is an
     * unsatisfactory response and aborts the handshake. */
    BSL_Buffer encode = {(uint8_t *)msg->response, msg->responseLen};
    int32_t ret = ParseAndStoreOcspResp(ctx, &encode, 0, BINLOG_ID17427,
                                        BINGLOG_STR("certificate status response cannot be parsed"));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* CertificateStatus comes right before ServerKeyExchange (DHE) or
     * CertificateRequest (RSA/ECDH); move on to the next expected message. */
    if (IsNeedServerKeyExchange(ctx)) {
        return HS_ChangeState(ctx, TRY_RECV_SERVER_KEY_EXCHANGE);
    }
    return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE_REQUEST);
}
#endif /* HITLS_TLS_HOST_CLIENT */

/* TLS 1.2 server: transition to the state following the CertificateStatus message. */
#ifdef HITLS_TLS_HOST_SERVER
static int32_t ServerTransitAfterCertificateStatus(TLS_Ctx *ctx)
{
    if (IsNeedServerKeyExchange(ctx)) {
        return HS_ChangeState(ctx, TRY_SEND_SERVER_KEY_EXCHANGE);
    }
#ifdef HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY
    if (ctx->config.tlsConfig.isSupportClientVerify) {
        if (ctx->negotiatedInfo.certReqSendTime < 1 || !(ctx->config.tlsConfig.isSupportClientOnceVerify)) {
            return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE_REQUEST);
        }
    }
#endif
    return HS_ChangeState(ctx, TRY_SEND_SERVER_HELLO_DONE);
}

int32_t ServerSendCertificateStatusProcess(TLS_Ctx *ctx)
{
    HS_Ctx *hsCtx = ctx->hsCtx;
    if (hsCtx->msgLen == 0) {
        int32_t ret = HS_PackMsg(ctx, CERTIFICATION_STATUS);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17428, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                                  "pack certificate status msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }
    int32_t ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return ServerTransitAfterCertificateStatus(ctx);
}
#endif /* HITLS_TLS_HOST_SERVER */

#ifdef HITLS_TLS_HOST_CLIENT
int32_t ParseCertEntryOcspStatus(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint32_t chainidx)
{
    if (ctx->config.tlsConfig.statusRequestType != HITLS_STATUS_REQUEST_TYPE_OCSP) {
        /* RFC 8446 section 4.2: an extension in Certificate that the client did not offer
         * must be rejected with unsupported_extension. */
        return ParseErrorProcess(ctx, HITLS_PARSE_UNSUPPORTED_EXTENSION, 0, NULL, ALERT_UNSUPPORTED_EXTENSION);
    }
    if (bufLen < (sizeof(uint8_t) + UINT24_SIZE)) {
        /* Too short to carry status_type(1) + response length(3). */
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID17429,
                                 BINGLOG_STR("certificate entry status request length is incorrect"),
                                 ALERT_DECODE_ERROR);
    }
    if (buf[0] != HITLS_STATUS_REQUEST_TYPE_OCSP) {
        /* RFC 6066 defines only the OCSP status type. */
        return ParseErrorProcess(ctx, HITLS_MSG_HANDLE_OCSP_STATUS_ERR, 0, NULL, ALERT_ILLEGAL_PARAMETER);
    }
    uint32_t respLen = BSL_ByteToUint24(&buf[1]);
    /* RFC 8446 section 6.2: an invalid OCSP response provided via status_request is
     * reported with bad_certificate_status_response. RFC 6066 makes OCSPResponse
     * opaque<1..2^24-1>, so a zero-length response is invalid. */
    if (respLen == 0) {
        return ParseErrorProcess(ctx, HITLS_MSG_HANDLE_OCSP_STATUS_ERR, BINLOG_ID17430,
                                 BINGLOG_STR("certificate entry OCSP response is empty"),
                                 ALERT_BAD_CERTIFICATE_STATUS_RESPONSE);
    }
    /* RFC 8446 section 4.4.2.1: the extension is exactly status_type(1) +
     * response length(3) + the OCSPResponse DER; a length mismatch (trailing
     * bytes after the response, or a length larger than the body) is malformed. */
    if (respLen != (bufLen - (sizeof(uint8_t) + UINT24_SIZE))) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID17431,
                                 BINGLOG_STR("certificate entry OCSP response length is incorrect"),
                                 ALERT_DECODE_ERROR);
    }
    /* The entry response must be a parseable OCSPResponse; a malformed DER is an
     * unsatisfactory response and aborts the handshake. */
    BSL_Buffer encode = {(uint8_t *)(uintptr_t)&buf[sizeof(uint8_t) + UINT24_SIZE], respLen};
    return ParseAndStoreOcspResp(ctx, &encode, chainidx, BINLOG_ID17432,
                                 BINGLOG_STR("certificate entry OCSP response cannot be parsed"));
}
#endif /* HITLS_TLS_HOST_CLIENT */

#ifdef HITLS_TLS_HOST_SERVER
int32_t PackCertEntryOcspStatus(TLS_Ctx *ctx, HITLS_CERT_X509 *cert, PackPacket *pkt, uint32_t chainidx)
{
    if (!ctx->statusExpected) {
        return HITLS_SUCCESS;
    }
    /* Self-signed certificates are skipped. */
    bool isSelfSigned = false;
    int32_t ret =
        SAL_CERT_X509Ctrl(&ctx->config.tlsConfig, cert, CERT_CTRL_IS_SELF_SIGNED, NULL, (void *)&isSelfSigned);
    if (ret == HITLS_SUCCESS && isSelfSigned) {
        return HITLS_SUCCESS;
    }
    /* The per-certificate callback returns the response for this certificate.
     * SEND with a response staples it; SKIP / no response skips this
     * certificate; an invalid return aborts with internal_error. */
    HITLS_CERT_OcspResp *resp = NULL;
    int32_t cbRet = ServerStaplingCbInvoke(ctx, cert, chainidx, &resp);
    if (cbRet != HITLS_STAPLING_SEND && cbRet != HITLS_STAPLING_SKIP) {
        return ParseErrorProcess(ctx, HITLS_INTERNAL_EXCEPTION, 0, NULL, ALERT_INTERNAL_ERROR);
    }
    /* ServerStaplingCbInvoke already folded "no response" and "no matching
     * CertID" into SKIP, so a SEND result carries a valid matched response. */
    if (cbRet != HITLS_STAPLING_SEND || resp == NULL) {
        return HITLS_SUCCESS;
    }
    BSL_Buffer buff = {0};
    ret = SAL_CERT_OcspRespGenBuff(resp, &buff);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* The TLS 1.3 CertificateEntry extension length field is a uint16; a
     * response too large to fit is a configuration error and aborts the
     * handshake. Only "no matching response" is skipped. */
    if (buff.dataLen > (uint32_t)(UINT16_MAX - sizeof(uint8_t) - UINT24_SIZE)) {
        BSL_SAL_FREE(buff.data);
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_INPUT);
        return HITLS_INVALID_INPUT;
    }
    /* Extension header, then the shared status_type + length(3) + DER body. */
    ret = PackExtensionHeader(HS_EX_TYPE_STATUS_REQUEST, sizeof(uint8_t) + UINT24_SIZE + buff.dataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(buff.data);
        return ret;
    }
    return PackOcspRespBody(pkt, &buff);
}
#endif /* HITLS_TLS_HOST_SERVER */

#ifdef HITLS_TLS_HOST_CLIENT
int32_t ClientNotifyOcspStatus(TLS_Ctx *ctx)
{
    /* The client must have requested the certificate status for a decision point
     * to exist. If it did not, there is nothing to report. */
    if (!IsStreamTlsStatusRequest(ctx) || ctx->config.tlsConfig.statusRequestType != HITLS_STATUS_REQUEST_TYPE_OCSP) {
        return HITLS_SUCCESS;
    }
    /* When a status callback is registered, the application decides whether the
     * stapling outcome is acceptable, including when the peer sent no response at
     * all (the list is empty). Without a callback, there is nothing to do. */
    int32_t ret = InvokeOcspStatusCb(ctx);
    if (ret == HITLS_STATUS_REJECT) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_CERTIFICATE_STATUS_RESPONSE);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_OCSP_STATUS_ERR);
        return HITLS_MSG_HANDLE_OCSP_STATUS_ERR;
    }
    if (ret != HITLS_STATUS_OK) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_HOST_CLIENT */

void CleanOcspStapling(TLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->peerOcspRespList != NULL) {
        for (uint32_t i = 0; i < ctx->peerOcspRespCount; i++) {
            OcspRespFree(ctx->peerOcspRespList[i]);
        }
        BSL_SAL_FREE(ctx->peerOcspRespList);
    }
    ctx->peerOcspRespList = NULL;
    ctx->peerOcspRespCount = 0;
    /* staplingResp is borrowed from the application, do not release it. */
    ctx->staplingResp = NULL;
    ctx->statusExpected = false;
    ctx->staplingResult = HITLS_STAPLING_SKIP;
}

#ifdef HITLS_TLS_HOST_SERVER
/* Reports whether the server will send a CertificateStatus message (stream TLS
 * up to 1.2). TLS 1.3 embeds OCSP responses into CertificateEntry extensions
 * instead and is excluded here; that path is handled by PackCertEntryOcspStatus.
 * The EE response was already fetched and validated against the EE certificate
 * by ServerFetchStaplingEeResp (via ServerStaplingCbInvoke, which folds "no
 * response" and "no matching CertID" into SKIP); a SEND staplingResult means a
 * matched response is ready.
 *
 * The match outcome is folded into ctx->staplingResult so that the TLS 1.2
 * send_certificate state transition can reuse it instead of re-running the
 * (expensive) match check: matched keeps SEND, every "not sent" path sets SKIP.
 * This function is invoked once per handshake (during ServerHello packing).
 * The TLS 1.3 branch must leave staplingResult untouched: it answers through
 * PackCertEntryOcspStatus. */
bool ServerNeedSendCertificateStatus(const TLS_Ctx *ctx)
{
    if (IS_TLS13_FAMILY_CTX(ctx)) {
        return false;
    }
#ifdef HITLS_TLS_FEATURE_SESSION
    /* An abbreviated handshake (session resumption) does not send a Certificate
     * message, so it cannot carry CertificateStatus. Acknowledging status_request
     * in that handshake would promise stapling that is never delivered (RFC 6066
     * section 8), so it is not acknowledged. */
    if (ctx->negotiatedInfo.isResume) {
        goto OCSP_NOT_SENT;
    }
#endif
    if (ctx->staplingResult != HITLS_STAPLING_SEND || !ctx->statusExpected || ctx->staplingResp == NULL) {
        goto OCSP_NOT_SENT;
    }
    HITLS_CERT_X509 *eeCert = HITLS_GetCertificate(ctx);
    if (eeCert == NULL) {
        goto OCSP_NOT_SENT;
    }
    /* The callback response is already validated against the certificate by
     * ServerStaplingCbInvoke (ServerFetchStaplingEeResp); a SEND result means
     * the response matches, so nothing to re-check here. */
    return true;
OCSP_NOT_SENT:
    /* No CertificateStatus will be sent: fold the decision into staplingResult
     * (SKIP) so send_certificate does not reuse the callback-time SEND and
     * wrongly enter the send state. */
    ((TLS_Ctx *)(uintptr_t)ctx)->staplingResult = HITLS_STAPLING_SKIP;
    return false;
}
#endif /* HITLS_TLS_HOST_SERVER */
#endif /* HITLS_TLS_FEATURE_STATUS_REQUEST */

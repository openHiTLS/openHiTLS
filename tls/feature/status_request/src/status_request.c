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
#include "hitls_pki_cert.h"
#include "hitls_pki_ocsp.h"
#include "hitls_pki_errno.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"
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
    HITLS_OCSP_Resp *resp = (HITLS_OCSP_Resp *)data;
    if (resp != NULL) {
        HITLS_OCSP_RespFree(resp);
    }
}

/* OCSP stapling is supported on stream TLS 1.0-1.3 connections (RFC 6066);
 * DTLS and TLCP are excluded. */
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

/* Invoke the client status callback with ctx-level priority over config-level. */
#ifdef HITLS_TLS_HOST_CLIENT
static int32_t InvokeOcspStatusCb(TLS_Ctx *ctx)
{
    HITLS_StatusCb cb = ctx->statusCb;
    void *arg = ctx->statusCbArg;
    if (cb == NULL) {
        cb = ctx->config.tlsConfig.statusCb;
        arg = ctx->config.tlsConfig.statusCbArg;
    }
    if (cb == NULL) {
        return HITLS_SUCCESS;
    }
    return cb(ctx, arg);
}
#endif /* HITLS_TLS_HOST_CLIENT */

/* Invoke the server stapling callback with ctx-level priority over config-level.
 * Without a callback the application did not opt into stapling, so nothing is
 * sent unless a callback explicitly returns HITLS_STAPLING_SEND. */
#ifdef HITLS_TLS_HOST_SERVER
static int32_t ServerStaplingCbInvoke(TLS_Ctx *ctx)
{
    HITLS_StaplingCb cb = ctx->staplingCb;
    void *arg = ctx->staplingCbArg;
    if (cb == NULL) {
        cb = ctx->config.tlsConfig.staplingCb;
        arg = ctx->config.tlsConfig.staplingCbArg;
    }
    if (cb == NULL) {
        return HITLS_STAPLING_SKIP;
    }
    return cb(ctx, arg);
}
#endif /* HITLS_TLS_HOST_SERVER */

/* Store a parsed OCSP response at the certificate depth index (chainidx 0 is
 * the EE certificate). The array is grown on demand and certificates without a
 * status_request extension leave a NULL entry so the array index stays aligned
 * with the peer certificate chain; the application can then match each response
 * to the certificate at the same depth. */
#ifdef HITLS_TLS_HOST_CLIENT
static int32_t StoreOcspRespToList(TLS_Ctx *ctx, HITLS_OCSP_Resp *resp, uint32_t chainidx)
{
    if (ctx->peerOcspRespList == NULL) {
        ctx->peerOcspRespList = (HITLS_OCSP_Resp **)BSL_SAL_Calloc(chainidx + 1, sizeof(HITLS_OCSP_Resp *));
        if (ctx->peerOcspRespList == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        ctx->peerOcspRespCount = chainidx + 1;
    } else if (chainidx >= ctx->peerOcspRespCount) {
        /* Grow the array so index chainidx exists; new entries default to NULL. */
        HITLS_OCSP_Resp **grown = (HITLS_OCSP_Resp **)BSL_SAL_Calloc(chainidx + 1, sizeof(HITLS_OCSP_Resp *));
        if (grown == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }
        (void)memcpy(grown, ctx->peerOcspRespList, ctx->peerOcspRespCount * sizeof(HITLS_OCSP_Resp *));
        BSL_SAL_FREE(ctx->peerOcspRespList);
        ctx->peerOcspRespList = grown;
        ctx->peerOcspRespCount = chainidx + 1;
    }
    ctx->peerOcspRespList[chainidx] = resp;
    return HITLS_SUCCESS;
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
    pkt->ctx->statusExpected = true;
    /* Give the application a chance to provide the OCSP responses before the
     * ServerHello acknowledgment is decided. The return value must be one of
     * HITLS_STAPLING_SEND / _SKIP / _ERROR; any other value is an invalid
     * callback return and aborts with the fatal internal_error alert. */
    int32_t cbRet = ServerStaplingCbInvoke(pkt->ctx);
    if (cbRet != HITLS_STAPLING_SEND && cbRet != HITLS_STAPLING_SKIP) {
        return ParseErrorProcess(pkt->ctx, HITLS_INTERNAL_EXCEPTION, 0, NULL, ALERT_INTERNAL_ERROR);
    }
    if (pkt->ctx->ocspResponseCount == 0 || pkt->ctx->ocspResponseList == NULL) {
        cbRet = HITLS_STAPLING_SKIP;
    }
    pkt->ctx->staplingResult = cbRet;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_HOST_SERVER */

#ifdef HITLS_TLS_HOST_SERVER
/* Extract the serialNumber and the issuer Name (DER) from a server certificate.
 * HITLS_CERT_X509 is the TLS-adapted pki HITLS_X509_Cert (the adapt layer casts
 * it directly, see hitls_x509_cert_magr.c), so the pki CertCtrl commands are
 * used without encoding and re-parsing the certificate. The output buffers are
 * freshly allocated; the caller must free serial->data and issuerDn->data. */
static int32_t ExtractCertSerialAndIssuerDn(HITLS_CERT_X509 *cert, BSL_Buffer *serial, BSL_Buffer *issuerDn)
{
    /* Serial number (shallow copy inside the cert). */
    BSL_Buffer tmpSerial = {0};
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM, &tmpSerial, sizeof(BSL_Buffer));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (tmpSerial.data == NULL || tmpSerial.dataLen == 0) {
        return HITLS_INVALID_INPUT;
    }
    /* Normalize the DER INTEGER serial (strip redundant leading 0x00/0xFF bytes
     * while keeping the sign byte) to match the OCSP CertID serial encoding
     * (RFC 6960 uses the minimal DER integer). */
    uint8_t *serialData = tmpSerial.data;
    uint32_t serialLen = tmpSerial.dataLen;
    bool negative = (serialData[0] & 0x80) != 0;
    while (serialLen > 1) {
        if (serialData[0] == 0x00 && !negative && (serialData[1] & 0x80) == 0) {
            serialData++;
            serialLen--;
        } else if (serialData[0] == 0xFF && negative && (serialData[1] & 0x80) != 0) {
            serialData++;
            serialLen--;
        } else {
            break;
        }
    }
    serial->data = (uint8_t *)BSL_SAL_Dump(serialData, serialLen);
    serial->dataLen = serialLen;
    if (serial->data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    /* Issuer DN as DER (freshly allocated by the encoder; caller frees it). */
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ENCODE_ISSUER_DN, issuerDn, sizeof(BSL_Buffer *));
    if (ret != HITLS_PKI_SUCCESS) {
        /* Propagate the encoder error (EncodeTemplate OOM is not pushed by the
         * callee); the caller only treats any non-success as "not matching". */
        BSL_SAL_FREE(serial->data);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_SUCCESS;
}

/* Check whether a CertID belongs to the certificate: its serialNumber must match
 * and its issuerNameHash (computed over the certificate's issuer DN with the
 * CertID hash algorithm) must match. Returns HITLS_SUCCESS on match,
 * HITLS_OCSP_ERR_CERTID_NOT_FOUND when the serial differs (this SingleResponse
 * is not for the certificate; the caller keeps looking), and a real error code
 * on failure. */
static int32_t OcspCertIdMatchesCert(const HITLS_OCSP_CertId *certId, const BSL_Buffer *serial,
                                     const BSL_Buffer *issuerDn)
{
    CRYPT_MD_AlgId hashAlg = CRYPT_MD_SHA1;
    BSL_Buffer respIssuerHash = {0};
    BSL_Buffer respSerial = {0};
    int32_t ret = HITLS_OCSP_CertIdGetInfo(certId, &hashAlg, &respIssuerHash, NULL, &respSerial);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (respSerial.dataLen != serial->dataLen || memcmp(respSerial.data, serial->data, serial->dataLen) != 0) {
        return HITLS_OCSP_ERR_CERTID_NOT_FOUND;
    }
    /* Hash the certificate's issuer DN with the same algorithm as the CertID. */
    CRYPT_EAL_MdCtx *md = CRYPT_EAL_MdNewCtx(hashAlg);
    if (md == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    uint8_t digest[64] = {0}; /* SHA-512 is the largest supported digest */
    uint32_t digestLen = sizeof(digest);
    int32_t hr = CRYPT_EAL_MdInit(md);
    if (hr == CRYPT_SUCCESS) {
        hr = CRYPT_EAL_MdUpdate(md, issuerDn->data, issuerDn->dataLen);
    }
    if (hr == CRYPT_SUCCESS) {
        hr = CRYPT_EAL_MdFinal(md, digest, &digestLen);
    }
    CRYPT_EAL_MdFreeCtx(md);
    if (hr != CRYPT_SUCCESS) {
        return hr;
    }
    return (respIssuerHash.dataLen == digestLen && memcmp(respIssuerHash.data, digest, digestLen) == 0) ?
               HITLS_SUCCESS :
               HITLS_OCSP_ERR_CERTID_NOT_FOUND;
}

/* Basic OCSP response validation for a certificate.
 * Returns:
 *   - HITLS_SUCCESS: the response is valid for this certificate (status
 *     successful, a BasicOCSPResponse is present, and one of its SingleResponses
 *     carries a CertID matching the certificate).
 *   - HITLS_OCSP_ERR_CERTID_NOT_FOUND: the response is valid but contains no
 *     CertID matching this certificate ("no matching response" -> the caller
 *     skips stapling for this certificate and the handshake continues).
 *   - any other error code: a real failure (OOM, invalid response, encode
 *     error) that must be propagated, not silently treated as "not matching". */
static int32_t OcspRespMatchesCert(const HITLS_OCSP_Resp *resp, HITLS_CERT_X509 *cert)
{
    int32_t status = -1;
    int32_t ret =
        HITLS_OCSP_RespCtrl((HITLS_OCSP_Resp *)(uintptr_t)resp, HITLS_OCSP_RESP_GET_STATUS, &status, sizeof(status));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (status != HITLS_OCSP_RESP_STATUS_SUCCESSFUL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_STATUS);
        return HITLS_OCSP_ERR_INVALID_STATUS;
    }
    HITLS_OCSP_BasicResp *bs = NULL;
    ret = HITLS_OCSP_RespCtrl((HITLS_OCSP_Resp *)(uintptr_t)resp, HITLS_OCSP_RESP_GET_BASIC, &bs, sizeof(bs));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (bs == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_FIELD_NOT_PRESENT);
        return HITLS_OCSP_ERR_FIELD_NOT_PRESENT;
    }
    BSL_Buffer serial = {0};
    BSL_Buffer issuerDn = {0};
    ret = ExtractCertSerialAndIssuerDn(cert, &serial, &issuerDn);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint32_t count = 0;
    ret = HITLS_OCSP_BasicRespGetRespCount(bs, &count);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_FREE(serial.data);
        BSL_SAL_FREE(issuerDn.data);
        return ret;
    }
    int32_t result = HITLS_OCSP_ERR_CERTID_NOT_FOUND;
    for (uint32_t i = 0; i < count; i++) {
        HITLS_OCSP_SingleResp *single = NULL;
        ret = HITLS_OCSP_BasicRespGetRespByIndex(bs, i, &single);
        if (ret != HITLS_PKI_SUCCESS) {
            result = ret;
            goto EXIT;
        }
        if (single == NULL) {
            result = HITLS_OCSP_ERR_FIELD_NOT_PRESENT;
            goto EXIT;
        }
        HITLS_OCSP_CertId *certId = NULL;
        ret = HITLS_OCSP_SingleRespCtrl(single, HITLS_OCSP_SINGLERESP_GET_CERTID, &certId, sizeof(certId));
        if (ret != HITLS_PKI_SUCCESS) {
            result = ret;
            goto EXIT;
        }
        if (certId == NULL) {
            result = HITLS_OCSP_ERR_FIELD_NOT_PRESENT;
            goto EXIT;
        }
        ret = OcspCertIdMatchesCert(certId, &serial, &issuerDn);
        if (ret == HITLS_SUCCESS) {
            result = HITLS_SUCCESS;
            break;
        }
        if (ret != HITLS_OCSP_ERR_CERTID_NOT_FOUND) {
            result = ret;
            goto EXIT;
        }
        /* CERTID_NOT_FOUND: this SingleResponse is for another certificate;
         * keep looking at the remaining ones. */
    }
EXIT:
    BSL_SAL_FREE(serial.data);
    BSL_SAL_FREE(issuerDn.data);
    return result;
}
#endif /* HITLS_TLS_HOST_SERVER */

#ifdef HITLS_TLS_HOST_SERVER
/* Build the CertificateStatus message body (stream TLS up to 1.2). This is
 * reached only through the state machine: the server enters
 * TRY_SEND_CERTIFICATE_STATUS only when ServerNeedSendCertificateStatus
 * returns true (stapling was negotiated, the callback chose SEND, and an OCSP
 * response is ready), so the packing function itself only checks that the
 * first response is a non-empty, representable list entry. TLS 1.3 does not
 * use this message; it embeds the response in CertificateEntry instead. */
int32_t PackCertificateStatus(const TLS_Ctx *ctx, PackPacket *pkt)
{
    if (ctx->ocspResponseList == NULL || ctx->ocspResponseCount == 0) {
        /* Reached the send state without any response: an internal state
         * inconsistency. Fail explicitly instead of emitting an empty
         * CertificateStatus that would abort the peer. */
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_INPUT);
        return HITLS_INVALID_INPUT;
    }
    const HITLS_OCSP_Resp *resp = ctx->ocspResponseList[0];
    if (resp == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_INPUT);
        return HITLS_INVALID_INPUT;
    }
    BSL_Buffer buff = {0};
    int32_t ret = HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &buff);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (buff.dataLen > 0xFFFFFFu) {
        BSL_SAL_FREE(buff.data);
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_INPUT);
        return HITLS_INVALID_INPUT;
    }
    /* Message body: status_type(1) + response length(3) + OCSP response DER. */
    ret = PackAppendUint8ToBuf(pkt, HITLS_STATUS_REQUEST_TYPE_OCSP);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(buff.data);
        return ret;
    }
    uint32_t lenPos = 0;
    ret = PackStartLengthField(pkt, UINT24_SIZE, &lenPos);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(buff.data);
        return ret;
    }
    ret = PackAppendDataToBuf(pkt, buff.data, buff.dataLen);
    BSL_SAL_FREE(buff.data);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    PackCloseUint24Field(pkt, lenPos);
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_HOST_SERVER */

/* TLS 1.2 client: transition to the state following the CertificateStatus message. */
#ifdef HITLS_TLS_HOST_CLIENT
static int32_t ClientTransitAfterCertificateStatus(TLS_Ctx *ctx)
{
    if (IsNeedServerKeyExchange(ctx)) {
        return HS_ChangeState(ctx, TRY_RECV_SERVER_KEY_EXCHANGE);
    }
    return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE_REQUEST);
}

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
    HITLS_OCSP_Resp *resp = NULL;
    if (HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &encode, &resp) != HITLS_PKI_SUCCESS || resp == NULL) {
        return ParseErrorProcess(ctx, HITLS_MSG_HANDLE_OCSP_STATUS_ERR, BINLOG_ID17427,
                                 BINGLOG_STR("certificate status response cannot be parsed"),
                                 ALERT_BAD_CERTIFICATE_STATUS_RESPONSE);
    }
    int32_t ret = StoreOcspRespToList(ctx, resp, 0);
    if (ret != HITLS_SUCCESS) {
        HITLS_OCSP_RespFree(resp);
        return ret;
    }
    return ClientTransitAfterCertificateStatus(ctx);
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
    if (respLen > (bufLen - (sizeof(uint8_t) + UINT24_SIZE))) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID17431,
                                 BINGLOG_STR("certificate entry OCSP response length is incorrect"),
                                 ALERT_DECODE_ERROR);
    }
    /* The entry response must be a parseable OCSPResponse; a malformed DER is an
     * unsatisfactory response and aborts the handshake. */
    BSL_Buffer encode = {(uint8_t *)(uintptr_t)&buf[sizeof(uint8_t) + UINT24_SIZE], respLen};
    HITLS_OCSP_Resp *resp = NULL;
    if (HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &encode, &resp) != HITLS_PKI_SUCCESS || resp == NULL) {
        return ParseErrorProcess(ctx, HITLS_MSG_HANDLE_OCSP_STATUS_ERR, BINLOG_ID17432,
                                 BINGLOG_STR("certificate entry OCSP response cannot be parsed"),
                                 ALERT_BAD_CERTIFICATE_STATUS_RESPONSE);
    }
    int32_t ret = StoreOcspRespToList(ctx, resp, chainidx);
    if (ret != HITLS_SUCCESS) {
        HITLS_OCSP_RespFree(resp);
    }
    return ret;
}
#endif /* HITLS_TLS_HOST_CLIENT */

#ifdef HITLS_TLS_HOST_SERVER
int32_t PackCertEntryOcspStatus(TLS_Ctx *ctx, HITLS_CERT_X509 *cert, PackPacket *pkt, uint32_t chainidx)
{
    if (ctx->staplingResult != HITLS_STAPLING_SEND || !ctx->statusExpected) {
        return HITLS_SUCCESS;
    }
    /* Self-signed certificates are skipped. */
    bool isSelfSigned = false;
    int32_t ret =
        SAL_CERT_X509Ctrl(&ctx->config.tlsConfig, cert, CERT_CTRL_IS_SELF_SIGNED, NULL, (void *)&isSelfSigned);
    if (ret == HITLS_SUCCESS && isSelfSigned) {
        return HITLS_SUCCESS;
    }
    const HITLS_OCSP_Resp *resp = NULL;
    if (chainidx < ctx->ocspResponseCount) {
        resp = ctx->ocspResponseList[chainidx];
    }
    if (resp == NULL) {
        return HITLS_SUCCESS;
    }
    /* Only staple a response that matches this certificate. "No matching CertID"
     * skips stapling for this certificate; real failures are propagated. */
    int32_t matchRet = OcspRespMatchesCert(resp, cert);
    if (matchRet != HITLS_SUCCESS) {
        if (matchRet == HITLS_OCSP_ERR_CERTID_NOT_FOUND) {
            return HITLS_SUCCESS;
        }
        return matchRet;
    }
    BSL_Buffer buff = {0};
    ret = HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &buff);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    /* The TLS 1.3 CertificateEntry extension length field is a uint16; a
     * response too large to fit is a configuration error and aborts the
     * handshake (matching OpenSSL). Only "no matching response" is skipped. */
    if (buff.dataLen > (uint32_t)(UINT16_MAX - sizeof(uint8_t) - UINT24_SIZE)) {
        BSL_SAL_FREE(buff.data);
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_INPUT);
        return HITLS_INVALID_INPUT;
    }
    /* Extension body: status_type(1) + response length(3) + OCSP response DER. */
    ret = PackExtensionHeader(HS_EX_TYPE_STATUS_REQUEST, sizeof(uint8_t) + UINT24_SIZE + buff.dataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(buff.data);
        return ret;
    }
    ret = PackAppendUint8ToBuf(pkt, HITLS_STATUS_REQUEST_TYPE_OCSP);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(buff.data);
        return ret;
    }
    uint32_t lenPos = 0;
    ret = PackStartLengthField(pkt, UINT24_SIZE, &lenPos);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(buff.data);
        return ret;
    }
    ret = PackAppendDataToBuf(pkt, buff.data, buff.dataLen);
    BSL_SAL_FREE(buff.data);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    PackCloseUint24Field(pkt, lenPos);
    return HITLS_SUCCESS;
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
    /* ocspResponseList is owned by the application, do not release it. */
    ctx->ocspResponseList = NULL;
    ctx->ocspResponseCount = 0;
    ctx->statusExpected = false;
    ctx->staplingResult = HITLS_STAPLING_SKIP;
}

#ifdef HITLS_TLS_HOST_SERVER
/* Reports whether the server will send a CertificateStatus message (stream TLS
 * up to 1.2). TLS 1.3 embeds OCSP responses into CertificateEntry extensions
 * instead and is excluded here; that path is handled by PackCertEntryOcspStatus.
 * The application callback has already been invoked when the status_request
 * extension was parsed. The first (EE) response must exist and match the EE
 * certificate (status + CertID), otherwise nothing is sent. A NULL first slot is
 * the documented "no response for that certificate" marker and means skip. Real
 * failures from the match check are propagated, not folded into a silent skip
 * (consistent with PackCertEntryOcspStatus).
 *
 * The match outcome is folded into ctx->staplingResult so that the TLS 1.2
 * send_certificate state transition can reuse it instead of re-running the
 * (expensive) match check: matched keeps SEND, every "not sent" path sets SKIP.
 * This function is invoked once per handshake (during ServerHello packing).
 * The TLS 1.3 branch must leave staplingResult untouched: it answers through
 * PackCertEntryOcspStatus, which still needs the callback-time SEND. */
int32_t ServerNeedSendCertificateStatus(const TLS_Ctx *ctx, bool *needSend)
{
    *needSend = false;
    if (IS_TLS13_FAMILY_CTX(ctx)) {
        return HITLS_SUCCESS;
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
    if (ctx->staplingResult != HITLS_STAPLING_SEND || !ctx->statusExpected || ctx->ocspResponseList == NULL ||
        ctx->ocspResponseCount == 0 || ctx->ocspResponseList[0] == NULL) {
        goto OCSP_NOT_SENT;
    }
    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    HITLS_CERT_X509 *eeCert = (mgrCtx != NULL) ? SAL_CERT_GetCurrentCert(mgrCtx) : NULL;
    if (eeCert == NULL) {
        goto OCSP_NOT_SENT;
    }
    int32_t matchRet = OcspRespMatchesCert(ctx->ocspResponseList[0], eeCert);
    if (matchRet == HITLS_SUCCESS) {
        /* Match: keep staplingResult SEND; send_certificate reuses it so the
         * validity check runs only once per handshake (during ServerHello packing). */
        *needSend = true;
        return HITLS_SUCCESS;
    }
    if (matchRet == HITLS_OCSP_ERR_CERTID_NOT_FOUND) {
        goto OCSP_NOT_SENT;
    }
    return matchRet;
OCSP_NOT_SENT:
    /* No CertificateStatus will be sent: fold the decision into staplingResult
     * (SKIP) so send_certificate does not reuse the callback-time SEND and
     * wrongly enter the send state (e.g. when ocspResponseList[0] is NULL). */
    ((TLS_Ctx *)(uintptr_t)ctx)->staplingResult = HITLS_STAPLING_SKIP;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_HOST_SERVER */
#endif /* HITLS_TLS_FEATURE_STATUS_REQUEST */

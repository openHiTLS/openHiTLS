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
#ifdef HITLS_TLS_HOST_CLIENT
#include <stdint.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_log.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_msg.h"
#include "hs_common.h"
#include "hs_extensions.h"
#include "hitls_error.h"
#include "tls_binlog_id.h"
#include "cert_mgr_ctx.h"
#include "recv_process.h"
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
// The client processes the certificate request
int32_t ClientRecvCertRequestProcess(TLS_Ctx *ctx)
{
    /**
     *  If the server certificate is not received, a failure message is returned after the cert request is received
     *  RFC 5246 7.4.4: Note: It is a fatal handshake_failure alert for
     *  an anonymous server to request client authentication.
     */
#ifdef HITLS_TLS_FEATURE_CERT_CB
    int32_t ret = ProcessCertCallback(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif /* HITLS_TLS_FEATURE_CERT_CB */
    if (ctx->hsCtx->peerCert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15869, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "got cert request but not get peer certificate.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE;
    }
    /* If ECC and ECHDE of TLCP are used, this parameter must be set because the
     * TLCP server must send the req cert message to the client to send the certificate, which may be
     * used for identity authentication, The latter may be used for key derivation, depending on the cipher suite and
     * server configuration (isSupportClientVerify). */
    ctx->hsCtx->isNeedClientCert = true;

    CERT_ExpectInfo expectCertInfo = {0};
    expectCertInfo.certType = CERT_TYPE_UNKNOWN;
    expectCertInfo.signSchemeList = ctx->peerInfo.signatureAlgorithms;
    expectCertInfo.signSchemeNum = ctx->peerInfo.signatureAlgorithmsSize;
    expectCertInfo.caList = ctx->peerInfo.caList;
    (void)SAL_CERT_SelectCertByInfo(ctx, &expectCertInfo);
    return HS_ChangeState(ctx, TRY_RECV_SERVER_HELLO_DONE);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */

#ifdef HITLS_TLS_FEATURE_PHA
static int32_t Tls13ClientStoreCertReqCtx(TLS_Ctx *ctx, const CertificateRequestMsg *certReq)
{
    /** If authentication is not performed after handshake, the cert req ctx length should be 0 */
    if ((ctx->phaState != PHA_REQUESTED && certReq->certificateReqCtxSize != 0) ||
        (ctx->phaState == PHA_REQUESTED && certReq->certificateReqCtxSize == 0)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15870, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "certificateReqCtxSize is invalid.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_MSG_HANDLE_INVALID_CERT_REQ_CTX;
    }
    if (certReq->certificateReqCtxSize != 0) {
        BSL_SAL_FREE(ctx->certificateReqCtx);
        ctx->certificateReqCtx = BSL_SAL_Calloc(certReq->certificateReqCtxSize, sizeof(uint8_t));
        if (ctx->certificateReqCtx == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17039, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Calloc fail", 0, 0, 0, 0);
            return HITLS_MEMALLOC_FAIL;
        }
        ctx->certificateReqCtxSize = certReq->certificateReqCtxSize;
        int32_t ret = memcpy_s(ctx->certificateReqCtx, certReq->certificateReqCtxSize,
            certReq->certificateReqCtx, certReq->certificateReqCtxSize);
        if (ret != EOK) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16171, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
                "client calloc cert req ctx failed.", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            return HITLS_MEMCPY_FAIL;
        }
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_PHA */

#ifdef HITLS_TLS_PROTO_TLS13
static int32_t Tls13ClientPreProcessCertRequest(TLS_Ctx *ctx, const CertificateRequestMsg *certReq)
{
    int32_t ret = HS_CheckReceivedExtension(
        ctx, CERTIFICATE_REQUEST, certReq->extensionTypeMask, HS_EX_TYPE_TLS1_3_ALLOWED_OF_CERTIFICATE_REQUEST);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#ifdef HITLS_TLS_FEATURE_PHA
    ret = Tls13ClientStoreCertReqCtx(ctx, certReq);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#else
    if (certReq->certificateReqCtxSize != 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15729, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "certificateReqCtxSize is invalid.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_MSG_HANDLE_INVALID_CERT_REQ_CTX;
    }
#endif /* HITLS_TLS_FEATURE_PHA */
    ctx->hsCtx->isNeedClientCert = true;
    if (certReq->signatureAlgorithms == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17040, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "miss signatureAlgorithms extension", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_MISSING_EXTENSION);
        return HITLS_MSG_HANDLE_MISSING_EXTENSION;
    }
    return HITLS_SUCCESS;
}

int32_t Tls13ClientRecvCertRequestProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    const CertificateRequestMsg *certReq = &msg->body.certificateReq;
    int32_t ret = HITLS_SUCCESS;
    if (ctx->hsCtx->readSubState == TLS_PROCESS_STATE_A) {
        ret = Tls13ClientPreProcessCertRequest(ctx, certReq);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        ctx->hsCtx->readSubState = TLS_PROCESS_STATE_B;
    }
#ifdef HITLS_TLS_FEATURE_PHA
    if (ctx->hsCtx->readSubState == TLS_PROCESS_STATE_B) {
        if (ctx->phaState == PHA_REQUESTED) {
#ifdef HITLS_TLS_FEATURE_CERT_CB
            ret = ProcessCertCallback(ctx);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
#endif /* HITLS_TLS_FEATURE_CERT_CB */
            CERT_ExpectInfo expectCertInfo = {0};
            expectCertInfo.certType = CERT_TYPE_UNKNOWN;
            expectCertInfo.signSchemeList = ctx->peerInfo.signatureAlgorithms;
            expectCertInfo.signSchemeNum = ctx->peerInfo.signatureAlgorithmsSize;
            expectCertInfo.caList = ctx->peerInfo.caList;
            (void)SAL_CERT_SelectCertByInfo(ctx, &expectCertInfo);
        }
    }
    if (ctx->phaState == PHA_REQUESTED) {
        return HS_ChangeState(ctx, TRY_SEND_CERTIFICATE);
    }
#endif /* HITLS_TLS_FEATURE_PHA */
    return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_HOST_CLIENT */
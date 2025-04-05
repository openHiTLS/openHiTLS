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

#include <stdint.h>
#include <string.h>
#include "hitls_build.h"
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "hs_verify.h"
#include "hs_msg.h"
#include "hs_extensions.h"
#include "alert.h"

static const int32_t X509_ERR_ALERT_MAP[] = {
    [(HITLS_X509_V_ERR_UNSPECIFIED - 1) & 0XFF] = ALERT_INTERNAL_ERROR,
    [(HITLS_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT - 1) & 0XFF] = ALERT_UNKNOWN_CA,
    [(HITLS_X509_V_ERR_UNABLE_TO_GET_CRL - 1) & 0XFF] = ALERT_UNKNOWN_CA,
    [(HITLS_X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_CERT_SIGNATURE_FAILURE - 1) & 0XFF] = ALERT_DECRYPT_ERROR,
    [(HITLS_X509_V_ERR_CRL_SIGNATURE_FAILURE - 1) & 0XFF] = ALERT_DECRYPT_ERROR,
    [(HITLS_X509_V_ERR_CERT_NOT_YET_VALID - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_CERT_HAS_EXPIRED - 1) & 0XFF] = ALERT_CERTIFICATE_EXPIRED,
    [(HITLS_X509_V_ERR_CRL_NOT_YET_VALID - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_CRL_HAS_EXPIRED - 1) & 0XFF] = ALERT_CERTIFICATE_EXPIRED,
    [(HITLS_X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_OUT_OF_MEM - 1) & 0XFF] = ALERT_INTERNAL_ERROR,
    [(HITLS_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT - 1) & 0XFF] = ALERT_UNKNOWN_CA,
    [(HITLS_X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN - 1) & 0XFF] = ALERT_UNKNOWN_CA,
    [(HITLS_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY - 1) & 0XFF] = ALERT_UNKNOWN_CA,
    [(HITLS_X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE - 1) & 0XFF] = ALERT_UNKNOWN_CA,
    [(HITLS_X509_V_ERR_CERT_CHAIN_TOO_LONG - 1) & 0XFF] = ALERT_UNKNOWN_CA,
    [(HITLS_X509_V_ERR_CERT_REVOKED - 1) & 0XFF] = ALERT_CERTIFICATE_REVOKED,
    [(HITLS_X509_V_ERR_INVALID_CA - 1) & 0XFF] = ALERT_UNKNOWN_CA,
    [(HITLS_X509_V_ERR_PATH_LENGTH_EXCEEDED - 1) & 0XFF] = ALERT_UNKNOWN_CA,
    [(HITLS_X509_V_ERR_INVALID_PURPOSE - 1) & 0XFF] = ALERT_UNSUPPORTED_CERTIFICATE,
    [(HITLS_X509_V_ERR_CERT_UNTRUSTED - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_CERT_REJECTED - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_SUBJECT_ISSUER_MISMATCH - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_AKID_SKID_MISMATCH - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_KEYUSAGE_NO_CERTSIGN - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER - 1) & 0XFF] = ALERT_UNKNOWN_CA,
    [(HITLS_X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_KEYUSAGE_NO_CRL_SIGN - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_INVALID_NON_CA - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_INVALID_EXTENSION - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_INVALID_POLICY_EXTENSION - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_NO_EXPLICIT_POLICY - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_DIFFERENT_CRL_SCOPE - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_ERROR_IN_CMP_CERT_NOT_AFTER_FIELD - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_ERROR_IN_CMP_CRL_THIS_UPDATE_FIELD - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_ERROR_IN_CMP_CRL_NEXT_UPDATE_FIELD - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_ERROR_IN_CMP_CERT_NOT_BEFORE_FIELD - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
    [(HITLS_X509_V_ERR_CRL_PATH_VALIDATION_ERROR - 1) & 0XFF] = ALERT_BAD_CERTIFICATE,
};

ALERT_Description GetAlertfromX509Err(HITLS_ERROR x509err)
{
    uint32_t size = sizeof(X509_ERR_ALERT_MAP) / sizeof(X509_ERR_ALERT_MAP[0]);
    uint32_t index = ((uint32_t)x509err - 1) & 0XFF;
    if (index < size) {
        return X509_ERR_ALERT_MAP[index];
    }

    return ALERT_BAD_CERTIFICATE;
}

int32_t ClientCheckPeerCert(TLS_Ctx *ctx, HITLS_CERT_X509 *cert)
{
    CERT_ExpectInfo expectCertInfo = {0};
    expectCertInfo.certType = CFG_GetCertTypeByCipherSuite(ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite);
    expectCertInfo.signSchemeList = ctx->config.tlsConfig.signAlgorithms;
    expectCertInfo.signSchemeNum = ctx->config.tlsConfig.signAlgorithmsSize;
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
        expectCertInfo.ellipticCurveList = ctx->config.tlsConfig.groups;
        expectCertInfo.ellipticCurveNum = ctx->config.tlsConfig.groupsSize;
    }
    expectCertInfo.ecPointFormatList = ctx->config.tlsConfig.pointFormats;
    expectCertInfo.ecPointFormatNum = ctx->config.tlsConfig.pointFormatsSize;

    return SAL_CERT_CheckCertInfo(ctx, &expectCertInfo, cert, false, true);
}

int32_t ServerCheckPeerCert(TLS_Ctx *ctx, HITLS_CERT_X509 *cert)
{
    CERT_ExpectInfo expectCertInfo = {0};
    expectCertInfo.certType = CERT_TYPE_UNKNOWN;
    expectCertInfo.signSchemeList = ctx->config.tlsConfig.signAlgorithms;
    expectCertInfo.signSchemeNum = ctx->config.tlsConfig.signAlgorithmsSize;

    return SAL_CERT_CheckCertInfo(ctx, &expectCertInfo, cert, false, true);
}

static int32_t ClientCheckCert(TLS_Ctx *ctx, CERT_Pair *peerCert)
{
    int32_t ret;
    ret = ClientCheckPeerCert(ctx, SAL_CERT_PairGetX509(peerCert));
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16224, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client check peer cert failed", 0, 0, 0, 0);
        return ret;
    }
#ifdef HITLS_TLS_PROTO_TLCP11
    /* The encryption certificate is required for TLS of TLCP. Both ECDHE and ECC of the client depend on the encryption
     * certificate. */
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11) {
        HITLS_CERT_Key *cert = SAL_CERT_GetTlcpEncCert(peerCert);
        if (cert == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16225, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "client check peer enc cert failed.", 0, 0, 0, 0);
            return HITLS_CERT_ERR_EXP_CERT;
        }
        /* The encryption certificate only needs to ensure that the certificate type matches the TLCP.
         * That is, the encryption public key type matches the negotiation cipher suite. */
        CERT_ExpectInfo expectCertInfo = {0};
        expectCertInfo.certType = CFG_GetCertTypeByCipherSuite(ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite);
        ret = SAL_CERT_CheckCertInfo(ctx, &expectCertInfo, cert, false, false);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17041, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "CheckCertInfo fail, ret = %d.", ret, 0, 0, 0);
        }
    }
#endif
    return ret;
}

static int32_t ServerCheckCert(TLS_Ctx *ctx, CERT_Pair *peerCert)
{
    int32_t ret;
    ret = ServerCheckPeerCert(ctx, SAL_CERT_PairGetX509(peerCert));
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16226, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server check peer cert failed.", 0, 0, 0, 0);
        return ret;
    }
#ifdef HITLS_TLS_PROTO_TLCP11
    /* Service processing logic. The ECDHE exchange algorithm logic requires the encryption certificate */
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11 &&
        ctx->negotiatedInfo.cipherSuiteInfo.kxAlg == HITLS_KEY_EXCH_ECDHE) {
        HITLS_CERT_Key *cert = SAL_CERT_GetTlcpEncCert(peerCert);
        if (cert == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16227, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "service check peer enc cert failed", 0, 0, 0, 0);
            return HITLS_CERT_ERR_EXP_CERT;
        }
        /* The encryption certificate only needs to ensure that the certificate type matches the TLCP.
         * That is, the encryption public key type matches the negotiation cipher suite. */
        CERT_ExpectInfo expectCertInfo = {0};
        expectCertInfo.certType = CFG_GetCertTypeByCipherSuite(ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite);
        ret = SAL_CERT_CheckCertInfo(ctx, &expectCertInfo, cert, false, false);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17042, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "CheckCertInfo fail, ret = %d.", ret, 0, 0, 0);
        }
    }
#endif
    return ret;
}
#ifdef HITLS_TLS_CONFIG_KEY_USAGE
static bool CheckCertKeyUsage(TLS_Ctx *ctx, CERT_Pair *peerCert)
{
    bool checkUsageRec = false;
    HITLS_CERT_X509 *cert = SAL_CERT_PairGetX509(peerCert);
#ifdef HITLS_TLS_PROTO_TLCP11
    HITLS_CERT_X509 *encCert = SAL_CERT_GetTlcpEncCert(peerCert);
#endif
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        return SAL_CERT_CheckCertKeyUsage(ctx, cert, CERT_KEY_CTRL_IS_DIGITAL_SIGN_USAGE);
    }

    HITLS_KeyExchAlgo kxAlg = ctx->negotiatedInfo.cipherSuiteInfo.kxAlg;
    if (ctx->isClient) {
        switch (kxAlg) {
            case HITLS_KEY_EXCH_DHE:
            case HITLS_KEY_EXCH_ECDHE:
            case HITLS_KEY_EXCH_ECDHE_PSK:
            case HITLS_KEY_EXCH_DHE_PSK:
                checkUsageRec = SAL_CERT_CheckCertKeyUsage(ctx, cert, CERT_KEY_CTRL_IS_DIGITAL_SIGN_USAGE);
                break;
            case HITLS_KEY_EXCH_RSA:
            case HITLS_KEY_EXCH_ECC:
            case HITLS_KEY_EXCH_RSA_PSK:
#ifdef HITLS_TLS_PROTO_TLCP11
                if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11) {
                    checkUsageRec = SAL_CERT_CheckCertKeyUsage(ctx, cert, CERT_KEY_CTRL_IS_DIGITAL_SIGN_USAGE) &&
                                    SAL_CERT_CheckCertKeyUsage(ctx, encCert, CERT_KEY_CTRL_IS_KEYENC_USAGE);
                    break;
                }
#endif
                checkUsageRec = SAL_CERT_CheckCertKeyUsage(ctx, cert, CERT_KEY_CTRL_IS_KEYENC_USAGE);
                break;
            case HITLS_KEY_EXCH_ECDH:
            case HITLS_KEY_EXCH_DH:
                checkUsageRec = SAL_CERT_CheckCertKeyUsage(ctx, cert, CERT_KEY_CTRL_IS_KEY_AGREEMENT_USAGE);
                break;
            default:
                break;
        }
    } else {
        switch (kxAlg) {
            case HITLS_KEY_EXCH_ECDH:
            case HITLS_KEY_EXCH_DH:
                checkUsageRec = SAL_CERT_CheckCertKeyUsage(ctx, cert, CERT_KEY_CTRL_IS_KEY_AGREEMENT_USAGE);
                break;
            default:
                checkUsageRec = SAL_CERT_CheckCertKeyUsage(ctx, cert, CERT_KEY_CTRL_IS_DIGITAL_SIGN_USAGE);
                break;
        }
    }
    return checkUsageRec;
}
#endif /* HITLS_TLS_CONFIG_KEY_USAGE */
/**
* @brief Process the peer certificate, check, and save it.
*
* @param ctx [IN/OUT] TLS context
* @param certs [IN] Certificate message
*
* @retval HITLS_SUCCESS succeeded.
* @retval For other error codes, see hitls_error.h.
*/
static int32_t ProcessPeerCertificate(TLS_Ctx *ctx, const CertificateMsg *certs)
{
    int32_t ret;
    CERT_Pair *peerCert = NULL;

    ret = SAL_CERT_ParseCertChain(ctx, certs->cert, &peerCert);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15723, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse certificate list fail when process peer certificate.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_CERTIFICATE);
        return ret;
    }
#ifdef HITLS_TLS_CONFIG_KEY_USAGE
    if (ctx->config.tlsConfig.needCheckKeyUsage == true && !CheckCertKeyUsage(ctx, peerCert)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17043, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CheckCertKeyUsage fail", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_CERTIFICATE);
        SAL_CERT_PairFree(ctx->config.tlsConfig.certMgrCtx, peerCert);
        return HITLS_CERT_ERR_KEYUSAGE;
    }
#endif /* HITLS_TLS_CONFIG_KEY_USAGE */
    if (ctx->isClient) {
        ret = ClientCheckCert(ctx, peerCert);
    } else {
        ret = ServerCheckCert(ctx, peerCert);
    }
    if (ret != HITLS_SUCCESS) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_CERTIFICATE);
        SAL_CERT_PairFree(ctx->config.tlsConfig.certMgrCtx, peerCert);
        return ret;
    }

    ctx->hsCtx->peerCert = peerCert;
    return HITLS_SUCCESS;
}
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
static int32_t VerifyCertChain(TLS_Ctx *ctx)
{
    int32_t ret = SAL_CERT_VerifyCertChain(ctx, ctx->hsCtx->peerCert, false);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16228, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "process peer certificate fail, ret = 0x%x.", (uint32_t)ret, 0, 0, 0);
        return ret;
    }
#ifdef HITLS_TLS_PROTO_TLCP11
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLCP_DTLCP11) {
        return ret;
    }
    if (ctx->isClient) {
        ret = SAL_CERT_VerifyCertChain(ctx, ctx->hsCtx->peerCert, true);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16229, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "process client enc certificate fail, ret = 0x%x.", (uint32_t)ret, 0, 0, 0);
        }
        return ret;
    }
    /* Processing logic on the service side of TLCP, which is verified only when used. */
    if (ctx->negotiatedInfo.cipherSuiteInfo.kxAlg == HITLS_KEY_EXCH_ECDHE) {
        ret = SAL_CERT_VerifyCertChain(ctx, ctx->hsCtx->peerCert, true);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16230, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "process server enc certificate fail, ret = 0x%x.", (uint32_t)ret, 0, 0, 0);
        }
        return ret;
    }
#endif
    return ret;
}

/**
* @brief Process the certificate.
*
* @param ctx [IN/OUT] TLS context
* @param msg [IN] Packet structure
*
* @retval HITLS_SUCCESS succeeded.
* @retval For other error codes, see hitls_error.h.
*/
int32_t RecvCertificateProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    int32_t ret;
    const CertificateMsg *certs = &msg->body.certificate;

    /**
     * RFC 5426 7.4.6：If no suitable certificate is available,
     * the client MUST send a certificate message containing no certificates.
     */
    if (certs->certCount == 0) {
        /** Only the server allows the peer certificate to be empty */
        if ((ctx->isClient == false) &&
            (ctx->config.tlsConfig.isSupportClientVerify && ctx->config.tlsConfig.isSupportNoClientCert)) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17105, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
                "server recv empty cert", 0, 0, 0, 0);
            return HS_ChangeState(ctx, TRY_RECV_CLIENT_KEY_EXCHANGE);
        }

        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15724, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "peer certificate is needed!", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        return HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE;
    }

    /** Process the obtained peer certificate */
    ret = ProcessPeerCertificate(ctx, certs);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15725, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "process peer certificate fail, ret = 0x%x.", ret, 0, 0, 0);
        return ret;
    }

    /** Verify the peer certificate */
    ret = VerifyCertChain(ctx);
    /* After the VerifyNone function is enabled, the client can continue the handshake process if the server certificate
     * fails to be verified */
    if (ret != HITLS_SUCCESS) {
        if (!ctx->config.tlsConfig.isSupportVerifyNone) {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, GetAlertfromX509Err(ctx->peerInfo.verifyResult));
            return ret;
        }
    }

    /** Update the state machine */
    if (ctx->isClient) {
        if (IsNeedServerKeyExchange(ctx) == true) {
            return HS_ChangeState(ctx, TRY_RECV_SERVER_KEY_EXCHANGE);
        }
        return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE_REQUEST);
    }
    return HS_ChangeState(ctx, TRY_RECV_CLIENT_KEY_EXCHANGE);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
static int32_t CertificateReqCtxCheck(TLS_Ctx *ctx, const CertificateMsg *certs)
{
#ifdef HITLS_TLS_FEATURE_PHA
    /* In the handshake phase, certificate_request_context must be empty. */
    if (ctx->phaState != PHA_REQUESTED && certs->certificateReqCtxSize != 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15726, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server receive a non-zero certificateReqCtx.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_MSG_HANDLE_INVALID_CERT_REQ_CTX;
    }
    /* pha phase, which must be non-empty and equal */
    if (ctx->certificateReqCtxSize != 0 && (ctx->certificateReqCtxSize != certs->certificateReqCtxSize ||
                memcmp(ctx->certificateReqCtx, certs->certificateReqCtx, certs->certificateReqCtxSize) != 0)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17044, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "certificateReqCtx is not equal", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_MSG_HANDLE_INVALID_CERT_REQ_CTX;
    }
#else
    if (certs->certificateReqCtxSize != 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15732, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server receive a non-zero certificateReqCtx.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_MSG_HANDLE_INVALID_CERT_REQ_CTX;
    }
#endif /* HITLS_TLS_FEATURE_PHA */
    return HITLS_SUCCESS;
}

int32_t Tls13RecvCertificateProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    const CertificateMsg *certs = &msg->body.certificate;

    if (ctx->isClient == false) {
        ctx->plainAlertForbid = true;
    }
    int32_t ret = HS_CheckReceivedExtension(
        ctx, CERTIFICATE, certs->extensionTypeMask, HS_EX_TYPE_TLS1_3_ALLOWED_OF_CERTIFICATE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = CertificateReqCtxCheck(ctx, certs);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /**
     * RFC 5426 7.4.6：If no suitable certificate is available,
     * the client MUST send a certificate message containing no certificates.
     */
    if (certs->certCount == 0) {
        if (ctx->isClient) {
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE);
            return RETURN_ALERT_PROCESS(ctx, HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE, BINLOG_ID16126,
                "peer certificate is needed!", ALERT_DECODE_ERROR);
        }
        /** Only the server allows the peer certificate to be empty */
        if ((ctx->config.tlsConfig.isSupportClientVerify && ctx->config.tlsConfig.isSupportNoClientCert)) {
            ret = VERIFY_Tls13CalcVerifyData(ctx, true);
            if (ret != HITLS_SUCCESS) {
                return RETURN_ALERT_PROCESS(ctx, ret, BINLOG_ID15729,
                    "server calculate client finished data error.", ALERT_INTERNAL_ERROR);
            }
            return HS_ChangeState(ctx, TRY_RECV_FINISH);
        }

        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE);
        return RETURN_ALERT_PROCESS(ctx, HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE, BINLOG_ID15727,
            "peer certificate is needed!", ALERT_CERTIFICATE_REQUIRED);
    }

    /** Process the obtained peer certificate */
    ret = ProcessPeerCertificate(ctx, certs);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15728, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "process peer certificate fail, ret = 0x%x.", ret, 0, 0, 0);
        return ret;
    }

    /** Verify the peer certificate */
    ret = SAL_CERT_VerifyCertChain(ctx, ctx->hsCtx->peerCert, false);
    if (ret != HITLS_SUCCESS) {
        if (!ctx->config.tlsConfig.isSupportVerifyNone) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17045, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "VerifyCertChain fail, ret = 0x%x.", (uint32_t)ret, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, GetAlertfromX509Err(ctx->peerInfo.verifyResult));
            return ret;
        }
    }

    return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE_VERIFY);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
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
#include "hitls_error.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "hitls_type.h"
#include "hitls_config.h"
#include "tls.h"
#ifdef HITLS_TLS_FEATURE_SESSION
#include "session.h"
#endif
#include "cert_method.h"
#include "record.h"

#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
int32_t HITLS_GetNegotiatedVersion(const HITLS_Ctx *ctx, uint16_t *version)
{
    if (ctx == NULL || version == NULL) {
        return HITLS_NULL_INPUT;
    }
    *version = ctx->negotiatedInfo.version;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_CONFIG_VERSION
int32_t HITLS_GetMaxProtoVersion(const HITLS_Ctx *ctx, uint16_t *maxVersion)
{
    if (ctx == NULL || maxVersion == NULL) {
        return HITLS_NULL_INPUT;
    }

    *maxVersion = ctx->config.tlsConfig.maxVersion;
    return HITLS_SUCCESS;
}

int32_t HITLS_GetMinProtoVersion(const HITLS_Ctx *ctx, uint16_t *minVersion)
{
    if (ctx == NULL || minVersion == NULL) {
        return HITLS_NULL_INPUT;
    }

    *minVersion = ctx->config.tlsConfig.minVersion;
    return HITLS_SUCCESS;
}

int32_t HITLS_SetMinProtoVersion(HITLS_Ctx *ctx, uint16_t version)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    uint16_t maxVersion = ctx->config.tlsConfig.maxVersion;
    return HITLS_CFG_SetVersion(&(ctx->config.tlsConfig), version, maxVersion);
}

int32_t HITLS_SetMaxProtoVersion(HITLS_Ctx *ctx, uint16_t version)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    uint16_t minVersion = ctx->config.tlsConfig.minVersion;
    return HITLS_CFG_SetVersion(&(ctx->config.tlsConfig), minVersion, version);
}
#endif

#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
int32_t HITLS_IsAead(const HITLS_Ctx *ctx, bool *isAead)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    /* Check whether the input parameter is empty. The system does not need to check whether the input parameter is
     * empty */
    return HITLS_CIPHER_IsAead(&(ctx->negotiatedInfo.cipherSuiteInfo), isAead);
}
#endif
#ifdef HITLS_TLS_PROTO_DTLS
int32_t HITLS_IsDtls(const HITLS_Ctx *ctx, bool *isDtls)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_IsDtls(&(ctx->config.tlsConfig), isDtls);
}
#endif

#ifdef HITLS_TLS_FEATURE_SESSION
int32_t HITLS_IsSessionReused(HITLS_Ctx *ctx, bool *isReused)
{
    if (ctx == NULL || isReused == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isReused = ctx->negotiatedInfo.isResume;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_FEATURE_SESSION_ID
int32_t HITLS_SetSessionIdCtx(HITLS_Ctx *ctx, const uint8_t *sessionIdCtx, uint32_t len)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetSessionIdCtx(&ctx->config.tlsConfig, sessionIdCtx, len);
}
#endif

#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
int32_t HITLS_GetSessionTicketKey(const HITLS_Ctx *ctx, uint8_t *key, uint32_t keySize, uint32_t *outSize)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetSessionTicketKey(&ctx->config.tlsConfig, key, keySize, outSize);
}

int32_t HITLS_SetSessionTicketKey(HITLS_Ctx *ctx, const uint8_t *key, uint32_t keySize)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetSessionTicketKey(&ctx->config.tlsConfig, key, keySize);
}
#endif

int32_t HITLS_SetVerifyResult(HITLS_Ctx *ctx, HITLS_ERROR verifyResult)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    ctx->peerInfo.verifyResult = verifyResult;
    return HITLS_SUCCESS;
}

int32_t HITLS_GetVerifyResult(const HITLS_Ctx *ctx, HITLS_ERROR *verifyResult)
{
    if (ctx == NULL || verifyResult == NULL) {
        return HITLS_NULL_INPUT;
    }

    *verifyResult = ctx->peerInfo.verifyResult;
    return HITLS_SUCCESS;
}

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
int32_t HITLS_SetDtlsTimerCb(HITLS_Ctx *ctx, HITLS_DtlsTimerCb cb)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetDtlsTimerCb(&(ctx->config.tlsConfig), cb);
}
#endif

#if defined(HITLS_TLS_CONNECTION_INFO_NEGOTIATION) && defined(HITLS_TLS_FEATURE_SESSION)
HITLS_CERT_X509 *HITLS_GetPeerCertificate(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    CERT_Pair *peerCert = NULL;

    int32_t ret = SESS_GetPeerCert(ctx->session, &peerCert);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17157, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GetPeerCert fail", 0, 0, 0, 0);
        return NULL;
    }

    HITLS_CERT_X509 *cert = SAL_CERT_PairGetX509(peerCert);
    /* Certificate reference increments by one */
    return cert == NULL ? NULL : SAL_CERT_X509Ref(ctx->config.tlsConfig.certMgrCtx, cert);
}
#endif

int32_t HITLS_SetQuietShutdown(HITLS_Ctx *ctx, int32_t mode)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    // The mode value 0 indicates that the quiet disconnection mode is disabled. The mode value 1 indicates that the
    // quiet disconnection mode is enabled
    if (mode != 0 && mode != 1) {
        return HITLS_CONFIG_INVALID_SET;
    }

    ctx->config.tlsConfig.isQuietShutdown = (mode != 0);

    return HITLS_SUCCESS;
}

int32_t HITLS_GetQuietShutdown(const HITLS_Ctx *ctx, int32_t *mode)
{
    if (ctx == NULL || mode == NULL) {
        return HITLS_NULL_INPUT;
    }

    *mode = (int32_t)ctx->config.tlsConfig.isQuietShutdown;

    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
int32_t HITLS_GetRenegotiationState(const HITLS_Ctx *ctx, bool *isRenegotiationState)
{
    if (ctx == NULL || isRenegotiationState == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isRenegotiationState = ctx->negotiatedInfo.isRenegotiation;

    return HITLS_SUCCESS;
}
#endif
#ifdef HITLS_TLS_CONFIG_STATE
int32_t HITLS_GetRwstate(const HITLS_Ctx *ctx, uint8_t *rwstate)
{
    if (ctx == NULL || rwstate == NULL) {
        return HITLS_NULL_INPUT;
    }

    *rwstate = ctx->rwstate;
    return HITLS_SUCCESS;
}
#endif
int32_t HITLS_SetShutdownState(HITLS_Ctx *ctx, uint32_t mode)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    ctx->shutdownState = mode;
    return HITLS_SUCCESS;
}

int32_t HITLS_GetShutdownState(const HITLS_Ctx *ctx, uint32_t *mode)
{
    if (ctx == NULL || mode == NULL) {
        return HITLS_NULL_INPUT;
    }

    *mode = ctx->shutdownState;
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_FEATURE_CERT_MODE
int32_t HITLS_GetClientVerifySupport(HITLS_Ctx *ctx, bool *isSupport)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetClientVerifySupport(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_GetNoClientCertSupport(HITLS_Ctx *ctx, bool *isSupport)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetNoClientCertSupport(&(ctx->config.tlsConfig), isSupport);
}
#endif

#ifdef HITLS_TLS_FEATURE_PHA
int32_t HITLS_GetPostHandshakeAuthSupport(HITLS_Ctx *ctx, bool *isSupport)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetPostHandshakeAuthSupport(&(ctx->config.tlsConfig), isSupport);
}
#endif
#ifdef HITLS_TLS_FEATURE_CERT_MODE
int32_t HITLS_GetVerifyNoneSupport(HITLS_Ctx *ctx, bool *isSupport)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetVerifyNoneSupport(&(ctx->config.tlsConfig), isSupport);
}
#endif

#if defined(HITLS_TLS_FEATURE_CERT_MODE) && defined(HITLS_TLS_FEATURE_RENEGOTIATION)
int32_t HITLS_GetClientOnceVerifySupport(HITLS_Ctx *ctx, bool *isSupport)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetClientOnceVerifySupport(&(ctx->config.tlsConfig), isSupport);
}
#endif

#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
int32_t HITLS_ClearRenegotiationNum(HITLS_Ctx *ctx, uint32_t *renegotiationNum)
{
    if (ctx == NULL || renegotiationNum == NULL) {
        return HITLS_NULL_INPUT;
    }

    *renegotiationNum = ctx->negotiatedInfo.renegotiationNum;
    ctx->negotiatedInfo.renegotiationNum = 0;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_FEATURE_MODE
int32_t HITLS_SetModeSupport(HITLS_Ctx *ctx, uint32_t mode)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetModeSupport(&(ctx->config.tlsConfig), mode);
}

int32_t HITLS_ClearModeSupport(HITLS_Ctx *ctx, uint32_t mode)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_ClearModeSupport(&(ctx->config.tlsConfig), mode);
}

int32_t HITLS_GetModeSupport(const HITLS_Ctx *ctx, uint32_t *mode)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_GetModeSupport(&(ctx->config.tlsConfig), mode);
}
#endif

#ifdef HITLS_TLS_SUITE_CIPHER_CBC
int32_t HITLS_SetEncryptThenMac(HITLS_Ctx *ctx, bool encryptThenMacType)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetEncryptThenMac(&(ctx->config.tlsConfig), encryptThenMacType);
}

int32_t HITLS_GetEncryptThenMac(const HITLS_Ctx *ctx, bool *encryptThenMacType)
{
    if (ctx == NULL || encryptThenMacType == NULL) {
        return HITLS_NULL_INPUT;
    }

    // Returns the negotiated value if it has been negotiated
    if (ctx->negotiatedInfo.version > 0) {
        *encryptThenMacType = ctx->negotiatedInfo.isEncryptThenMac;
        return HITLS_SUCCESS;
    } else {
        return HITLS_CFG_GetEncryptThenMac(&(ctx->config.tlsConfig), encryptThenMacType);
    }
}
#endif

#ifdef HITLS_TLS_FEATURE_SNI
int32_t HITLS_SetServerName(HITLS_Ctx *ctx, uint8_t *serverName, uint32_t serverNameStrlen)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetServerName(&(ctx->config.tlsConfig), serverName, serverNameStrlen);
}
#endif
int32_t HITLS_SetCipherServerPreference(HITLS_Ctx *ctx, bool isSupport)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetCipherServerPreference(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_GetCipherServerPreference(const HITLS_Ctx *ctx, bool *isSupport)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetCipherServerPreference(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_SetRenegotiationSupport(HITLS_Ctx *ctx, bool isSupport)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetRenegotiationSupport(&(ctx->config.tlsConfig), isSupport);
}
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
int32_t HITLS_SetClientRenegotiateSupport(HITLS_Ctx *ctx, bool isSupport)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetClientRenegotiateSupport(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_GetClientRenegotiateSupport(HITLS_Ctx *ctx, bool *isSupport)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetClientRenegotiateSupport(&(ctx->config.tlsConfig), isSupport);
}
#endif
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
int32_t HITLS_SetLegacyRenegotiateSupport(HITLS_Ctx *ctx, bool isSupport)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetLegacyRenegotiateSupport(&(ctx->config.tlsConfig), isSupport);
}
#endif /* defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12) */
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
int32_t HITLS_SetSessionTicketSupport(HITLS_Ctx *ctx, bool isSupport)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetSessionTicketSupport(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_GetSessionTicketSupport(const HITLS_Ctx *ctx, bool *isSupport)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetSessionTicketSupport(&(ctx->config.tlsConfig), isSupport);
}
#endif
int32_t HITLS_SetEmptyRecordsNum(HITLS_Ctx *ctx, uint32_t emptyNum)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetEmptyRecordsNum(&(ctx->config.tlsConfig), emptyNum);
}

int32_t HITLS_GetEmptyRecordsNum(const HITLS_Ctx *ctx, uint32_t *emptyNum)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetEmptyRecordsNum(&(ctx->config.tlsConfig), emptyNum);
}

#ifdef HITLS_TLS_FEATURE_MAX_SEND_FRAGMENT
int32_t HITLS_SetMaxSendFragment(HITLS_Ctx *ctx, uint16_t maxSendFragment)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (ctx->recCtx != NULL && ctx->recCtx->outBuf != NULL && ctx->recCtx->outBuf->start != ctx->recCtx->outBuf->end) {
        return HITLS_REC_NORMAL_IO_BUSY;
    }
    return HITLS_CFG_SetMaxSendFragment(&(ctx->config.tlsConfig), maxSendFragment);
}

int32_t HITLS_GetMaxSendFragment(const HITLS_Ctx *ctx, uint16_t *maxSendFragment)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_GetMaxSendFragment(&(ctx->config.tlsConfig), maxSendFragment);
}
#endif

#ifdef HITLS_TLS_FEATURE_REC_INBUFFER_SIZE
int32_t HITLS_SetRecInbufferSize(HITLS_Ctx *ctx, uint32_t recInbufferSize)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetRecInbufferSize(&(ctx->config.tlsConfig), recInbufferSize);
}

int32_t HITLS_GetRecInbufferSize(const HITLS_Ctx *ctx, uint32_t *recInbufferSize)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_GetRecInbufferSize(&(ctx->config.tlsConfig), recInbufferSize);
}
#endif

#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
int32_t HITLS_SetTicketNums(HITLS_Ctx *ctx, uint32_t ticketNums)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetTicketNums(&ctx->config.tlsConfig, ticketNums);
}

uint32_t HITLS_GetTicketNums(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetTicketNums(&ctx->config.tlsConfig);
}
#endif
#ifdef HITLS_TLS_FEATURE_FLIGHT
int32_t HITLS_SetFlightTransmitSwitch(HITLS_Ctx *ctx, bool isEnable)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetFlightTransmitSwitch(&(ctx->config.tlsConfig), isEnable);
}

int32_t HITLS_GetFlightTransmitSwitch(const HITLS_Ctx *ctx, bool *isEnable)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetFlightTransmitSwitch(&(ctx->config.tlsConfig), isEnable);
}
#endif

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
int32_t HITLS_SetDtlsCookieExangeSupport(HITLS_Ctx *ctx, bool isEnable)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetDtlsCookieExchangeSupport(&(ctx->config.tlsConfig), isEnable);
}

int32_t HITLS_GetDtlsCookieExangeSupport(const HITLS_Ctx *ctx, bool *isEnable)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetDtlsCookieExchangeSupport(&(ctx->config.tlsConfig), isEnable);
}
#endif

#ifdef HITLS_TLS_CONFIG_CERT
/**
 * @ingroup hitls
 * @brief Set the maximum size of the certificate chain that can be sent by the peer end.
 *
 * @param  ctx [IN/OUT]      TLS connection handle
 * @param  maxSize [IN]      Set the maximum size of the certificate chain that can be sent by the peer end.
 * @retval HITLS_NULL_INPUT The input parameter pointer is null.
 * @retval HITLS_SUCCESS    succeeded.
 */
int32_t HITLS_SetMaxCertList(HITLS_Ctx *ctx, uint32_t maxSize)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetMaxCertList(&(ctx->config.tlsConfig), maxSize);
}

/**
 * @ingroup hitls
 * @brief  Obtain the maximum size of the certificate chain that can be sent by the peer end.
 *
 * @param  ctx [IN]         TLS connection handle
 * @param  maxSize [OUT]    Maximum size of the certificate chain that can be sent by the peer end
 * @retval HITLS_NULL_INPUT The input parameter pointer is null.
 * @retval HITLS_SUCCESS    succeeded.
 */
int32_t HITLS_GetMaxCertList(const HITLS_Ctx *ctx, uint32_t *maxSize)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetMaxCertList(&(ctx->config.tlsConfig), maxSize);
}
#endif

#ifdef HITLS_TLS_CONFIG_MANUAL_DH
int32_t HITLS_SetTmpDhCb(HITLS_Ctx *ctx, HITLS_DhTmpCb cb)
{
    if (ctx == NULL || cb == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetTmpDhCb(&(ctx->config.tlsConfig), cb);
}
#endif /* HITLS_TLS_CONFIG_MANUAL_DH */

#ifdef HITLS_TLS_CONFIG_RECORD_PADDING
int32_t HITLS_SetRecordPaddingCb(HITLS_Ctx *ctx, HITLS_RecordPaddingCb cb)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetRecordPaddingCb(&(ctx->config.tlsConfig), cb);
}

HITLS_RecordPaddingCb HITLS_GetRecordPaddingCb(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetRecordPaddingCb(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetRecordPaddingCbArg(HITLS_Ctx *ctx, void *arg)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetRecordPaddingCbArg(&(ctx->config.tlsConfig), arg);
}

void *HITLS_GetRecordPaddingCbArg(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetRecordPaddingCbArg(&(ctx->config.tlsConfig));
}
#endif

#ifdef HITLS_TLS_CONFIG_KEY_USAGE
int32_t HITLS_SetCheckKeyUsage(HITLS_Ctx *ctx, bool isCheck)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetCheckKeyUsage(&(ctx->config.tlsConfig), isCheck);
}
#endif

#ifdef HITLS_TLS_PROTO_TLS13
int32_t HITLS_SetMiddleBoxCompat(HITLS_Ctx *ctx, bool isMiddleBox)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetMiddleBoxCompat(&(ctx->config.tlsConfig), isMiddleBox);
}

int32_t HITLS_GetMiddleBoxCompat(HITLS_Ctx *ctx, bool *isMiddleBox)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetMiddleBoxCompat(&(ctx->config.tlsConfig), isMiddleBox);
}
#endif
#ifdef HITLS_TLS_FEATURE_SESSION_CUSTOM_TICKET
int32_t HITLS_SetSessionTicketExtProcessCb(HITLS_Ctx *ctx, const HITLS_SessionTicketExtProcessCb sessionTicketExtCb,
                                           void *arg)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    ctx->config.tlsConfig.sessionTicketExtCb = sessionTicketExtCb;
    ctx->config.tlsConfig.sessionTicketExtCbArg = arg;
    return HITLS_SUCCESS;
}

int32_t HITLS_SetSessionTicketExtData(HITLS_Ctx *ctx, uint8_t *data, uint32_t dataSize)
{
    if (ctx == NULL || data == NULL || dataSize == 0) {
        return HITLS_INVALID_INPUT;
    }
    HITLS_Config *config = &(ctx->config.tlsConfig);

    BSL_SAL_FREE(config->sessionTicketExt);
    config->sessionTicketExtSize = 0;
    config->sessionTicketExt = BSL_SAL_Dump(data, dataSize);
    if (config->sessionTicketExt == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    config->sessionTicketExtSize = dataSize;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SESSION_CUSTOM_TICKET */

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

#include "hitls_error.h"
#include "bsl_err_internal.h"
#include "hitls_type.h"
#include "hitls_config.h"
#include "tls.h"
#include "session.h"
#include "cert_method.h"

int32_t HITLS_GetNegotiatedVersion(const HITLS_Ctx *ctx, uint16_t *version)
{
    if (ctx == NULL || version == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    *version = ctx->negotiatedInfo.version;
    return HITLS_SUCCESS;
}

int32_t HITLS_GetMaxProtoVersion(const HITLS_Ctx *ctx, uint16_t *maxVersion)
{
    if (ctx == NULL || maxVersion == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *maxVersion = ctx->config.tlsConfig.maxVersion;
    return HITLS_SUCCESS;
}

int32_t HITLS_GetMinProtoVersion(const HITLS_Ctx *ctx, uint16_t *minVersion)
{
    if (ctx == NULL || minVersion == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *minVersion = ctx->config.tlsConfig.minVersion;
    return HITLS_SUCCESS;
}

int32_t HITLS_SetMinProtoVersion(HITLS_Ctx *ctx, uint16_t version)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    uint16_t maxVersion = ctx->config.tlsConfig.maxVersion;
    return HITLS_CFG_SetVersion(&(ctx->config.tlsConfig), version, maxVersion);
}

int32_t HITLS_SetMaxProtoVersion(HITLS_Ctx *ctx, uint16_t version)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    uint16_t minVersion = ctx->config.tlsConfig.minVersion;
    return HITLS_CFG_SetVersion(&(ctx->config.tlsConfig), minVersion, version);
}

int32_t HITLS_IsAead(const HITLS_Ctx *ctx, uint8_t *isAead)
{
    if (ctx == NULL || isAead == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    /* Check whether the input parameter is empty. The system does not need to check whether the input parameter is
     * empty */
    return HITLS_CIPHER_IsAead(&(ctx->negotiatedInfo.cipherSuiteInfo), isAead);
}

int32_t HITLS_IsDtls(const HITLS_Ctx *ctx, uint8_t *isDtls)
{
    if (ctx == NULL || isDtls == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_IsDtls(&(ctx->config.tlsConfig), isDtls);
}

int32_t HITLS_IsSessionReused(HITLS_Ctx *ctx, uint8_t *isReused)
{
    if (ctx == NULL || isReused == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isReused = (uint8_t)ctx->negotiatedInfo.isResume;
    return HITLS_SUCCESS;
}

int32_t HITLS_SetSessionIdCtx(HITLS_Ctx *ctx, const uint8_t *sessionIdCtx, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetSessionIdCtx(&ctx->config.tlsConfig, sessionIdCtx, len);
}

int32_t HITLS_GetSessionTicketKey(const HITLS_Ctx *ctx, uint8_t *key, uint32_t keySize, uint32_t *outSize)
{
    if (ctx == NULL || key == NULL || outSize == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetSessionTicketKey(&ctx->config.tlsConfig, key, keySize, outSize);
}

int32_t HITLS_SetSessionTicketKey(HITLS_Ctx *ctx, const uint8_t *key, uint32_t keySize)
{
    if (ctx == NULL || key == NULL ||
        (keySize != HITLS_TICKET_KEY_NAME_SIZE + HITLS_TICKET_KEY_SIZE + HITLS_TICKET_KEY_SIZE)) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetSessionTicketKey(&ctx->config.tlsConfig, key, keySize);
}

int32_t HITLS_SetVerifyResult(HITLS_Ctx *ctx, HITLS_ERROR verifyResult)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    ctx->peerInfo.verifyResult = verifyResult;
    return HITLS_SUCCESS;
}

int32_t HITLS_GetVerifyResult(const HITLS_Ctx *ctx, HITLS_ERROR *verifyResult)
{
    if (ctx == NULL || verifyResult == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *verifyResult = ctx->peerInfo.verifyResult;
    return HITLS_SUCCESS;
}

HITLS_CERT_X509 *HITLS_GetPeerCertificate(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    CERT_Pair *peerCert = NULL;

    int32_t ret = SESS_GetPeerCert(ctx->session, &peerCert);
    if (ret != HITLS_SUCCESS) {
        return NULL;
    }

    HITLS_CERT_X509 *cert = SAL_CERT_PairGetX509(peerCert);
    /* Certificate reference increments by one */
    return SAL_CERT_X509Ref(ctx->config.tlsConfig.certMgrCtx, cert);
}

int32_t HITLS_SetQuietShutdown(HITLS_Ctx *ctx, int32_t mode)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    // The mode value 0 indicates that the quiet disconnection mode is disabled. The mode value 1 indicates that the
    // quiet disconnection mode is enabled
    if (mode != 0 && mode != 1) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_INVALID_SET);
        return HITLS_CONFIG_INVALID_SET;
    }

    if (mode == 0) {
        ctx->config.tlsConfig.isQuietShutdown = false;
    } else {
        ctx->config.tlsConfig.isQuietShutdown = true;
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_GetQuietShutdown(const HITLS_Ctx *ctx, int32_t *mode)
{
    if (ctx == NULL || mode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *mode = (int32_t)ctx->config.tlsConfig.isQuietShutdown;

    return HITLS_SUCCESS;
}

int32_t HITLS_GetRenegotiationState(const HITLS_Ctx *ctx, uint8_t *isRenegotiationState)
{
    if (ctx == NULL || isRenegotiationState == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isRenegotiationState = (uint8_t)ctx->negotiatedInfo.isRenegotiation;

    return HITLS_SUCCESS;
}

int32_t HITLS_GetRwstate(const HITLS_Ctx *ctx, uint8_t *rwstate)
{
    if (ctx == NULL || rwstate == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *rwstate = ctx->rwstate;
    return HITLS_SUCCESS;
}

int32_t HITLS_SetShutdownState(HITLS_Ctx *ctx, uint32_t mode)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    ctx->shutdownState = mode;
    return HITLS_SUCCESS;
}

int32_t HITLS_GetShutdownState(const HITLS_Ctx *ctx, uint32_t *mode)
{
    if (ctx == NULL || mode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *mode = ctx->shutdownState;
    return HITLS_SUCCESS;
}

int32_t HITLS_GetClientVerifySupport(HITLS_Ctx *ctx, uint8_t *isSupport)
{
    if (ctx == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetClientVerifySupport(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_GetNoClientCertSupport(HITLS_Ctx *ctx, uint8_t *isSupport)
{
    if (ctx == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetNoClientCertSupport(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_GetPostHandshakeAuthSupport(HITLS_Ctx *ctx, uint8_t *isSupport)
{
    if (ctx == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetPostHandshakeAuthSupport(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_GetVerifyNoneSupport(HITLS_Ctx *ctx, uint8_t *isSupport)
{
    if (ctx == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetVerifyNoneSupport(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_GetClientOnceVerifySupport(HITLS_Ctx *ctx, uint8_t *isSupport)
{
    if (ctx == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetClientOnceVerifySupport(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_ClearRenegotiationNum(HITLS_Ctx *ctx, uint32_t *renegotiationNum)
{
    if (ctx == NULL || renegotiationNum == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *renegotiationNum = ctx->negotiatedInfo.renegotiationNum;
    ctx->negotiatedInfo.renegotiationNum = 0;
    return HITLS_SUCCESS;
}

int32_t HITLS_SetEncryptThenMac(HITLS_Ctx *ctx, uint32_t encryptThenMacType)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetEncryptThenMac(&(ctx->config.tlsConfig), encryptThenMacType);
}

int32_t HITLS_GetEncryptThenMac(const HITLS_Ctx *ctx, uint32_t *encryptThenMacType)
{
    if (ctx == NULL || encryptThenMacType == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    // Returns the negotiated value if it has been negotiated
    if (ctx->negotiatedInfo.version > 0) {
        *encryptThenMacType = (uint32_t)ctx->negotiatedInfo.isEncryptThenMac;
        return HITLS_SUCCESS;
    } else {
        return HITLS_CFG_GetEncryptThenMac(&(ctx->config.tlsConfig), encryptThenMacType);
    }
}

int32_t HITLS_SetServerName(HITLS_Ctx *ctx, uint8_t *serverName, uint32_t serverNameStrlen)
{
    if (ctx == NULL || serverName == NULL || serverNameStrlen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetServerName(&(ctx->config.tlsConfig), serverName, serverNameStrlen);
}

int32_t HITLS_SetCipherServerPreference(HITLS_Ctx *ctx, bool isSupport)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetCipherServerPreference(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_GetCipherServerPreference(const HITLS_Ctx *ctx, bool *isSupport)
{
    if (ctx == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetCipherServerPreference(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_SetRenegotiationSupport(HITLS_Ctx *ctx, bool isSupport)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetRenegotiationSupport(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_SetSessionTicketSupport(HITLS_Ctx *ctx, bool isSupport)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetSessionTicketSupport(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_GetSessionTicketSupport(const HITLS_Ctx *ctx, uint8_t *isSupport)
{
    if (ctx == NULL || isSupport == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetSessionTicketSupport(&(ctx->config.tlsConfig), isSupport);
}

int32_t HITLS_SetTicketNums(HITLS_Ctx *ctx, uint32_t ticketNums)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetTicketNums(&ctx->config.tlsConfig, ticketNums);
}

uint32_t HITLS_GetTicketNums(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetTicketNums(&ctx->config.tlsConfig);
}

int32_t HITLS_SetFlightTransmitSwitch(HITLS_Ctx *ctx, uint8_t isEnable)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetFlightTransmitSwitch(&(ctx->config.tlsConfig), isEnable);
}

int32_t HITLS_GetFlightTransmitSwitch(const HITLS_Ctx *ctx, uint8_t *isEnable)
{
    if (ctx == NULL || isEnable == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetFlightTransmitSwitch(&(ctx->config.tlsConfig), isEnable);
}

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
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
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
    if (ctx == NULL || maxSize == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetMaxCertList(&(ctx->config.tlsConfig), maxSize);
}

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

int32_t HITLS_SetCloseCheckKeyUsage(HITLS_Ctx *ctx, bool isClose)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetCloseCheckKeyUsage(&(ctx->config.tlsConfig), isClose);
}

void *HITLS_GetRecordPaddingCbArg(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetRecordPaddingCbArg(&(ctx->config.tlsConfig));
}
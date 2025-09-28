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
#include <string.h>
#include "hitls_build.h"
#include "securec.h"
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls.h"
#include "hitls_error.h"
#include "tls_config.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "uio_base.h"
#ifdef HITLS_TLS_FEATURE_INDICATOR
#include "indicator.h"
#endif /* HITLS_TLS_FEATURE_INDICATOR */
#include "pack.h"
#ifdef HITLS_TLS_FEATURE_SECURITY
#include "security.h"
#endif
#include "parse.h"
#include "hs_kx.h"
#include "hs.h"
#include "hs_extensions.h"
#include "hs_common.h"
#include "config_type.h"
#include "config_check.h"
#include "record.h"

#ifdef HITLS_TLS_PROTO_DTLS12
#define DTLS_SCTP_AUTH_LABEL "EXPORTER_DTLS_OVER_SCTP" /* dtls SCTP auth key label */
#endif
#ifdef HITLS_TLS_PROTO_TLS13
/* Fixed random value of the hello retry request packet */
const uint8_t g_hrrRandom[HS_RANDOM_SIZE] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};

const uint8_t *HS_GetHrrRandom(uint32_t *len)
{
    *len = HS_RANDOM_SIZE;
    return g_hrrRandom;
}
#ifdef HITLS_TLS_PROTO_TLS_BASIC
const uint8_t g_tls12Downgrade[HS_DOWNGRADE_RANDOM_SIZE] = {
    0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01
};

const uint8_t *HS_GetTls12DowngradeRandom(uint32_t *len)
{
    *len = HS_DOWNGRADE_RANDOM_SIZE;
    return g_tls12Downgrade;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#endif /* HITLS_TLS_PROTO_TLS13 */

uint32_t HS_GetVersion(const TLS_Ctx *ctx)
{
    if (ctx->negotiatedInfo.version > 0) {
        return ctx->negotiatedInfo.version;
    } else {
        /* If the version is not negotiated, the latest version supported by the local is returned */
        return ctx->config.tlsConfig.maxVersion;
    }
}

static const char *g_stateMachineStr[] = {
    [TLS_IDLE] = "idle",
    [TLS_CONNECTED] = "connected",
#ifdef HITLS_TLS_HOST_CLIENT
    [TRY_SEND_CLIENT_HELLO] = "send client hello",
    [TRY_SEND_CLIENT_KEY_EXCHANGE] = "send client key exchange",
    [TRY_RECV_SERVER_HELLO] = "recv server hello",
    [TRY_RECV_HELLO_VERIFY_REQUEST] = "recv hello verify request",
    [TRY_RECV_SERVER_KEY_EXCHANGE] = "recv server key exchange",
    [TRY_RECV_SERVER_HELLO_DONE] = "recv server hello done",
    [TRY_RECV_NEW_SESSION_TICKET] = "recv new session ticket",
    [TRY_RECV_HELLO_REQUEST] = "recv hello request",
#endif
#ifdef HITLS_TLS_HOST_SERVER
    [TRY_SEND_HELLO_REQUEST] = "send hello request",
    [TRY_SEND_SERVER_HELLO] = "send server hello",
    [TRY_SEND_HELLO_VERIFY_REQUEST] = "send hello verify request",
    [TRY_SEND_SERVER_KEY_EXCHANGE] = "send server key exchange",
    [TRY_RECV_CLIENT_HELLO] = "recv client hello",
    [TRY_RECV_CLIENT_KEY_EXCHANGE] = "recv client key exchange",
    [TRY_SEND_SERVER_HELLO_DONE] = "send server hello done",
    [TRY_SEND_NEW_SESSION_TICKET] = "send new session ticket",
#endif
#ifdef HITLS_TLS_PROTO_TLS13
    [TRY_RECV_KEY_UPDATE] = "recv keyupdate",
    [TRY_SEND_KEY_UPDATE] = "send keyupdate",
#ifdef HITLS_TLS_HOST_CLIENT
    [TRY_RECV_ENCRYPTED_EXTENSIONS] = "recv encrypted extensions",
    [TRY_SEND_END_OF_EARLY_DATA] = "send end of early data",
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
    [TRY_SEND_ENCRYPTED_EXTENSIONS] = "send encrypted extensions",
    [TRY_SEND_HELLO_RETRY_REQUEST] = "send hello retry request",
    [TRY_RECV_END_OF_EARLY_DATA] = "recv end of early data",
#endif /* HITLS_TLS_HOST_SERVER */
#endif /* HITLS_TLS_PROTO_TLS13 */
    [TRY_SEND_CERTIFICATE] = "send certificate",
    [TRY_SEND_CERTIFICATE_REQUEST] = "send certificate request",
    [TRY_SEND_CERTIFICATE_VERIFY] = "send certificate verify",
    [TRY_SEND_CHANGE_CIPHER_SPEC] = "send change cipher spec",
    [TRY_RECV_CERTIFICATE] = "recv certificate",
    [TRY_RECV_CERTIFICATE_REQUEST] = "recv certificate request",
    [TRY_RECV_CERTIFICATE_VERIFY] = "recv certificate verify",
    [TRY_RECV_FINISH] = "recv finished",
    [TRY_SEND_FINISH] = "send finished",
};

const char *HS_GetStateStr(uint32_t state)
{
    if ((state >= (sizeof(g_stateMachineStr) / sizeof(char *))) || (g_stateMachineStr[state] == NULL)) {
        return "unknown";
    }

    return g_stateMachineStr[state];
}

const char *HS_GetMsgTypeStr(HS_MsgType type)
{
    switch (type) {
        case HELLO_REQUEST:
            return "hello request";
        case CLIENT_HELLO:
            return "client hello";
        case SERVER_HELLO:
            return "server hello";
#ifdef HITLS_TLS_PROTO_TLS13
        case ENCRYPTED_EXTENSIONS:
            return "encrypted extensions";
#endif
        case CERTIFICATE:
            return "certificate";
        case SERVER_KEY_EXCHANGE:
            return "server key exchange";
        case CERTIFICATE_REQUEST:
            return "certificate request";
        case SERVER_HELLO_DONE:
            return "server hello done";
        case CERTIFICATE_VERIFY:
            return "certificate verify";
        case CLIENT_KEY_EXCHANGE:
            return "client key exchange";
        case NEW_SESSION_TICKET:
            return "new session ticket";
        case FINISHED:
            return "finished";
        default:
            break;
    }
    return "unknown";
}

int32_t HS_ChangeState(TLS_Ctx *ctx, uint32_t nextState)
{
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    hsCtx->state = nextState;
#ifdef HITLS_TLS_FEATURE_MODE_RELEASE_BUFFERS
    if ((ctx->config.tlsConfig.modeSupport & HITLS_MODE_RELEASE_BUFFERS) != 0) {
        if (hsCtx->state == TLS_CONNECTED) {
            RecTryFreeRecBuf(ctx, false);
            RecTryFreeRecBuf(ctx, true);
        } else if (IsHsSendState(hsCtx->state)) {
            RecTryFreeRecBuf(ctx, false);
        } else {
            RecTryFreeRecBuf(ctx, true);
        }
    }
#endif
    /* when link state is transporting, unexpected hs message should be processed, the log shouldn't be printed during
        the hsCtx initiation */
    if (ctx->state != CM_STATE_TRANSPORTING) {
#ifdef HITLS_TLS_FEATURE_INDICATOR
        if (ctx->isClient) {
            INDICATOR_StatusIndicate(ctx, INDICATE_EVENT_STATE_CONNECT_LOOP, INDICATE_VALUE_SUCCESS);
        } else {
            INDICATOR_StatusIndicate(ctx, INDICATE_EVENT_STATE_ACCEPT_LOOP, INDICATE_VALUE_SUCCESS);
        }
#endif /* HITLS_TLS_FEATURE_INDICATOR */

        BSL_LOG_BINLOG_VARLEN(BINLOG_ID15573, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "handshake state machine change to:%s.", HS_GetStateStr(nextState));
    }
    return HITLS_SUCCESS;
}

int32_t HS_CombineRandom(const uint8_t *random1, const uint8_t *random2, uint32_t randomSize,
                         uint8_t *dest, uint32_t destSize)
{
    /** If the random number length is 0 or the memory address is less than twice the random number length, return an
     * error code. */
    if ((randomSize == 0u) || (destSize < randomSize * 2)) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_RANDOM_SIZE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15574, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "invalid randomSize for combine random.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_RANDOM_SIZE_ERR;
    }

    if (memcpy_s(dest, destSize, random1, randomSize) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15575, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "combine random1 fail.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    if (memcpy_s(&dest[randomSize], destSize - randomSize, random2, randomSize) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15576, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "combine random2 fail.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }

    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_PROTO_TLCP11
uint8_t *HS_PrepareSignDataTlcp(const TLS_Ctx *ctx, const uint8_t *partSignData, uint32_t partSignDataLen,
    uint32_t *signDataLen)
{
    /* Signature data: client random number + server random number + exchange parameter length + key exchange packet
     * data/encryption certificate */
    uint32_t exchParamLen = 3;
    uint32_t randomLen = HS_RANDOM_SIZE * 2u;
    uint32_t dataLen = randomLen + partSignDataLen + exchParamLen;

    uint8_t *data = BSL_SAL_Calloc(1u, dataLen);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15577, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "signature data memory alloc fail.", 0, 0, 0, 0);
        return NULL;
    }

    (void)memcpy_s(data, dataLen, ctx->hsCtx->clientRandom, HS_RANDOM_SIZE);
    (void)memcpy_s(&data[HS_RANDOM_SIZE], dataLen - HS_RANDOM_SIZE, ctx->hsCtx->serverRandom, HS_RANDOM_SIZE);
    /* Fill the length of the key exchange parameter */
    BSL_Uint24ToByte(partSignDataLen, &data[randomLen]);
    /* Copy key exchange packet data */
    (void)memcpy_s(&data[randomLen] + exchParamLen, dataLen - randomLen - exchParamLen, partSignData, partSignDataLen);

    *signDataLen = dataLen;
    return data;
}
#endif

uint8_t *HS_PrepareSignData(const TLS_Ctx *ctx, const uint8_t *partSignData,
    uint32_t partSignDataLen, uint32_t *signDataLen)
{
    int32_t ret;
    /* Signature data: client random number + server random number + key exchange packet data/encryption certificate */
    uint32_t randomLen = HS_RANDOM_SIZE * 2u;
    uint32_t dataLen = randomLen + partSignDataLen;

    uint8_t *data = BSL_SAL_Calloc(1u, dataLen);
    if (data == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16813, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return NULL;
    }

    (void)memcpy_s(data, dataLen, ctx->hsCtx->clientRandom, HS_RANDOM_SIZE);
    (void)memcpy_s(&data[HS_RANDOM_SIZE], dataLen - HS_RANDOM_SIZE, ctx->hsCtx->serverRandom, HS_RANDOM_SIZE);
    /* Copy key exchange packet data */
    ret = memcpy_s(&data[randomLen], dataLen - randomLen, partSignData, partSignDataLen);
    if (ret != EOK) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16814, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "memcpy fail", 0, 0, 0, 0);
        BSL_SAL_Free(data);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return NULL;
    }

    *signDataLen = dataLen;
    return data;
}

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_SCTP)
/**
 * @brief   Calculate the sctp auth key
 * @details auth key: PRF(SecurityParameters.master_secret, label,
 *              SecurityParameters.client_random +
 *              SecurityParameters.server_random)[length]
 *
 * @param ctx [IN] TLS context
 * @param authKey [OUT] Authorization key
 * @param authKeyLen [IN] Key length
 *
 * @retval HITLS_SUCCESS calculation is complete.
 * @retval HITLS_MSG_HANDLE_RANDOM_SIZE_ERR The random number length is incorrect.
 * @retval For other error codes, see SAL_CRYPT_PRF.
 */
int32_t CalcSctpAuthKey(const TLS_Ctx *ctx, uint8_t *authKey, uint32_t authKeyLen)
{
    int32_t ret;
    uint8_t randomValue[HS_RANDOM_SIZE * 2] = {0};  // key derivation seed, with the length of two random characters
    uint32_t randomValueSize = HS_RANDOM_SIZE * 2;  // key derivation seed, with the length of two random characters
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    /** Combine the two random values */
    ret = HS_CombineRandom(hsCtx->clientRandom, hsCtx->serverRandom, HS_RANDOM_SIZE, randomValue, randomValueSize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15579, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "combine random fail.", 0, 0, 0, 0);
        return ret;
    }

    CRYPT_KeyDeriveParameters deriveInfo;
    deriveInfo.hashAlgo = ctx->negotiatedInfo.cipherSuiteInfo.hashAlg;
    deriveInfo.secret = hsCtx->masterKey;
    deriveInfo.secretLen = MASTER_SECRET_LEN;
    deriveInfo.label = (const uint8_t *)DTLS_SCTP_AUTH_LABEL;
    deriveInfo.labelLen = strlen(DTLS_SCTP_AUTH_LABEL);
    deriveInfo.seed = randomValue;
    deriveInfo.seedLen = randomValueSize;
    deriveInfo.libCtx = LIBCTX_FROM_CTX(ctx);
    deriveInfo.attrName = ATTRIBUTE_FROM_CTX(ctx);
    /** Key derivation */
    ret = SAL_CRYPT_PRF(&deriveInfo, authKey, authKeyLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15580, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SAL_CRYPT_PRF fail when calc sctp auth key.", 0, 0, 0, 0);
    }
    return ret;
}

int32_t HS_SetSctpAuthKey(TLS_Ctx *ctx)
{
    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_SCTP)) {
        return HITLS_SUCCESS;
    }

    int32_t ret;
    uint8_t authKey[DTLS_SCTP_SHARED_AUTHKEY_LEN] = {0};
    uint16_t authKeyLen = sizeof(authKey);

    ret = CalcSctpAuthKey(ctx, authKey, authKeyLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15581, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "calc sctp auth key failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    /* If the UIO_SctpAddAuthKey is added but not active, return HITLS_SUCCESS when the interface
        is invoked again */
    ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_SCTP_ADD_AUTH_SHARED_KEY, (int32_t)authKeyLen, authKey);
    /* Clear sensitive information */
    BSL_SAL_CleanseData(authKey, DTLS_SCTP_SHARED_AUTHKEY_LEN);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_UIO_SCTP_ADD_AUTH_KEY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15582, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio add sctp auth shared key failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_UIO_SCTP_ADD_AUTH_KEY_FAIL;
    }

    return HITLS_SUCCESS;
}

int32_t HS_ActiveSctpAuthKey(TLS_Ctx *ctx)
{
    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_SCTP)) {
        return HITLS_SUCCESS;
    }

    int32_t ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_SCTP_ACTIVE_AUTH_SHARED_KEY, 0, NULL);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15583, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "next sctp auth key error.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_UIO_SCTP_ACTIVE_AUTH_KEY_FAIL;
    }
    return HITLS_SUCCESS;
}

int32_t HS_DeletePreviousSctpAuthKey(TLS_Ctx *ctx)
{
    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_SCTP)) {
        return HITLS_SUCCESS;
    }

    /* After the handshake is complete, delete the old sctp auth key */
    int32_t ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_SCTP_DEL_PRE_AUTH_SHARED_KEY, 0, NULL);
    if (ret != BSL_SUCCESS) {
        ret = HITLS_UIO_SCTP_DEL_AUTH_KEY_FAIL;
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15584, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio delete sctp auth shared key failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    }
    return ret;
}
#endif /* defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_SCTP) */

bool IsNeedServerKeyExchange(const TLS_Ctx *ctx)
{
    HITLS_KeyExchAlgo kxAlg = ctx->negotiatedInfo.cipherSuiteInfo.kxAlg;

    /* Special: If the PSK identity hint is set, the PSK and RSA_PSK may also need to send
     * the ServerKeyExchange message
     */
    if ((kxAlg == HITLS_KEY_EXCH_PSK) || (kxAlg == HITLS_KEY_EXCH_RSA_PSK)) {
        /* In this case, the client receives the ServerKeyExchange message by default */
        if (ctx->isClient) {
            return true;
        } else {
            /* If the PSK identity hint is set on the server, the ServerKeyExchange message needs to be sent */
            if (ctx->config.tlsConfig.pskIdentityHint != NULL) {
                return true;
            }
            return false;
        }
    }
#ifdef HITLS_TLS_PROTO_TLCP11
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11) {
        return true; /* The TLCP needs to send the ServerKeyExchange message. */
    }
#endif
    /* The ECDH and DH certificates already contain the public key information, and the ServerKeyExchange message
     *  is not required. */
    /* RSA keys are generated by the client, and the ServerKeyExchange message is not required. */
    return ((kxAlg != HITLS_KEY_EXCH_ECDH) && (kxAlg != HITLS_KEY_EXCH_DH) && (kxAlg != HITLS_KEY_EXCH_RSA));
}

bool IsNeedCertPrepare(const CipherSuiteInfo *cipherSuiteInfo)
{
    if (cipherSuiteInfo == NULL) {
        return false;
    }

    /* PSK related ciphersuite */
    switch (cipherSuiteInfo->kxAlg) {
        case HITLS_KEY_EXCH_PSK:
        case HITLS_KEY_EXCH_DHE_PSK:
        case HITLS_KEY_EXCH_ECDHE_PSK:
            return false;
        default:
            break;
    }

    /* Anonymous ciphersuite related */
    switch (cipherSuiteInfo->authAlg) {
        case HITLS_AUTH_NULL:
            return false;
        default:
            break;
    }

    return true;
}
bool IsTicketSupport(const TLS_Ctx *ctx)
{
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
    if (ctx->config.tlsConfig.isSupportSessionTicket && (!ctx->config.isSupportPto)
#ifdef HITLS_TLS_FEATURE_SECURITY
    && (SECURITY_SslCheck(ctx, HITLS_SECURITY_SECOP_TICKET, 0, 0, NULL) == SECURITY_SUCCESS)
#endif
    ) {
        return true;
    }
#endif
    (void)ctx;
    return false;
}
#ifdef HITLS_TLS_FEATURE_PSK

bool IsPskNegotiation(const TLS_Ctx *ctx)
{
    HITLS_KeyExchAlgo kxAlg = ctx->negotiatedInfo.cipherSuiteInfo.kxAlg;

    return ((kxAlg == HITLS_KEY_EXCH_ECDHE_PSK) || (kxAlg == HITLS_KEY_EXCH_DHE_PSK) ||
        (kxAlg == HITLS_KEY_EXCH_RSA_PSK) || (kxAlg == HITLS_KEY_EXCH_PSK));
}

int32_t CheckClientPsk(TLS_Ctx *ctx)
{
    uint8_t psk[HS_PSK_MAX_LEN] = {0};
    uint8_t identity[HS_PSK_IDENTITY_MAX_LEN + 1] = {0};

    /* If the value of psk is not NULL, it has been processed. */
    if (ctx->hsCtx->kxCtx->pskInfo != NULL && ctx->hsCtx->kxCtx->pskInfo->psk != NULL) {
        return HITLS_SUCCESS;
    }

    if (ctx->config.tlsConfig.pskClientCb == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_UNREGISTERED_CALLBACK, BINLOG_ID16815, "unregistered pskClientCb");
    }

    uint32_t pskUsedLen = ctx->config.tlsConfig.pskClientCb(ctx, NULL, identity, HS_PSK_IDENTITY_MAX_LEN,
                                                            psk, HS_PSK_MAX_LEN);
    if (pskUsedLen == 0 || pskUsedLen > HS_PSK_IDENTITY_MAX_LEN) {
        (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MSG_HANDLE_ILLEGAL_PSK_LEN, BINLOG_ID16816, "pskUsedLen incorrect");
    }
    /* Length of pskid will not exceed 128 bytes */
    uint32_t identityUsedLen = (uint32_t)strnlen((char *)identity, HS_PSK_IDENTITY_MAX_LEN + 1);
    if (identityUsedLen > HS_PSK_IDENTITY_MAX_LEN) {
        (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);
        return HITLS_MSG_HANDLE_ILLEGAL_IDENTITY_LEN;
    }

    if (ctx->hsCtx->kxCtx->pskInfo == NULL) {
        ctx->hsCtx->kxCtx->pskInfo = (PskInfo *)BSL_SAL_Calloc(1u, sizeof(PskInfo));
        if (ctx->hsCtx->kxCtx->pskInfo == NULL) {
            (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID16694, "Calloc fail");
        }
    }

    uint8_t *tmpIdentity = NULL;
    if (identityUsedLen > 0) {
        tmpIdentity = (uint8_t *)BSL_SAL_Calloc(1u, (identityUsedLen + 1));
        if (tmpIdentity == NULL) {
            (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID16817, "Calloc fail");
        }
        (void)memcpy_s(tmpIdentity, identityUsedLen + 1, identity, identityUsedLen);
    }
    ctx->hsCtx->kxCtx->pskInfo->psk = (uint8_t *)BSL_SAL_Dump(psk, pskUsedLen);
    (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);
    if (ctx->hsCtx->kxCtx->pskInfo->psk == NULL) {
        BSL_SAL_FREE(tmpIdentity);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID16818, "Dump fail");
    }
    ctx->hsCtx->kxCtx->pskInfo->pskLen = pskUsedLen;

    if (tmpIdentity != NULL) {
        BSL_SAL_FREE(ctx->hsCtx->kxCtx->pskInfo->identity);
        ctx->hsCtx->kxCtx->pskInfo->identity = tmpIdentity;
        ctx->hsCtx->kxCtx->pskInfo->identityLen = identityUsedLen;
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_PSK */

uint32_t HS_GetState(const TLS_Ctx *ctx)
{
    if (ctx->hsCtx == NULL) {
        return HS_STATE_BUTT;
    }

    return ctx->hsCtx->state;
}
#ifdef HITLS_TLS_FEATURE_SNI
const char *HS_GetServerName(const TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->hsCtx == NULL) {
        return NULL;
    }
    return (char *)ctx->hsCtx->serverName;
}
#endif

int32_t HS_GrowMsgBuf(TLS_Ctx *ctx, uint32_t msgSize, bool keepOldData)
{
    if (msgSize <= ctx->hsCtx->bufferLen) {
        return HITLS_SUCCESS;
    }
    uint32_t bufSize = ctx->hsCtx->bufferLen;
    uint32_t oldDataSize = bufSize;
    uint8_t *oldDataAddr = ctx->hsCtx->msgBuf;
    while (bufSize != 0 && bufSize < msgSize) {
        bufSize = bufSize << 1;
    }
    ctx->hsCtx->msgBuf = BSL_SAL_Calloc(1u, bufSize);
    if (ctx->hsCtx->msgBuf == NULL) {
        ctx->hsCtx->msgBuf = oldDataAddr;
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15935, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "msgBuf malloc fail while get reass msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    ctx->hsCtx->bufferLen = bufSize;
    if (keepOldData) {
        (void)memcpy_s(ctx->hsCtx->msgBuf, bufSize, oldDataAddr, oldDataSize);
    }
    BSL_SAL_FREE(oldDataAddr);
    return HITLS_SUCCESS;
}

int32_t HS_ReSizeMsgBuf(TLS_Ctx *ctx, uint32_t msgSize)
{
    bool keepOldData = false;
    return HS_GrowMsgBuf(ctx, msgSize, keepOldData);
}

uint32_t HS_MaxMessageSize(TLS_Ctx *ctx, HS_MsgType type)
{
    switch (type) {
        case HELLO_REQUEST:
            return HITLS_HELLO_REQUEST_MAX_SIZE;
        case CLIENT_HELLO:
            return HITLS_CLIENT_HELLO_MAX_SIZE;
#ifdef HITLS_TLS_PROTO_DTLS12
        case HELLO_VERIFY_REQUEST:
            return HITLS_HELLO_VERIFY_REQUEST_MAX_SIZE;
#endif
        case SERVER_HELLO:
            return HITLS_SERVER_HELLO_MAX_SIZE;
        case ENCRYPTED_EXTENSIONS:
            return HITLS_ENCRYPTED_EXTENSIONS_MAX_SIZE;
        case CERTIFICATE:
            if (ctx->config.tlsConfig.maxCertList == 0) {
                return HITLS_MAX_CERT_LIST_DEFAULT;
            }
            return ctx->config.tlsConfig.maxCertList;
        case SERVER_KEY_EXCHANGE:
            return HITLS_SERVER_KEY_EXCH_MAX_SIZE;
        case CERTIFICATE_REQUEST:
            if (ctx->config.tlsConfig.maxCertList == 0) {
                return HITLS_MAX_CERT_LIST_DEFAULT;
            }
            return ctx->config.tlsConfig.maxCertList;
        case SERVER_HELLO_DONE:
            return HITLS_SERVER_HELLO_DONE_MAX_SIZE;
        case CLIENT_KEY_EXCHANGE:
            return HITLS_CLIENT_KEY_EXCH_MAX_SIZE;
        case CERTIFICATE_VERIFY:
            return REC_MAX_PLAIN_LENGTH;
        case NEW_SESSION_TICKET:
            if (HS_GetVersion(ctx) == HITLS_VERSION_TLS13) {
                return HITLS_SESSION_TICKET_MAX_SIZE_TLS13;
            }
            return HITLS_SESSION_TICKET_MAX_SIZE_TLS12;
        case END_OF_EARLY_DATA:
            return HITLS_END_OF_EARLY_DATA_MAX_SIZE;
        case FINISHED:
            return HITLS_FINISHED_MAX_SIZE;
        case KEY_UPDATE:
            return HITLS_KEY_UPDATE_MAX_SIZE;
        default:
            return 0;
    }
}
#ifdef HITLS_TLS_PROTO_TLS13
uint32_t HS_GetBinderLen(HITLS_Session *session, HITLS_HashAlgo *hashAlg)
{
    if (*hashAlg != HITLS_HASH_BUTT) {
        return SAL_CRYPT_HmacSize(*hashAlg);
    }

    if (session == NULL) {
        return 0;
    }

    uint16_t cipherSuite = 0;
    int32_t ret = HITLS_SESS_GetCipherSuite(session, &cipherSuite);
    if (ret != HITLS_SUCCESS) {
        return 0;
    }

    CipherSuiteInfo cipherInfo = {0};
    ret = CFG_GetCipherSuiteInfo(cipherSuite, &cipherInfo);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16819, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GetCipherSuiteInfo fail", 0, 0, 0, 0);
        return 0;
    }
    *hashAlg = cipherInfo.hashAlg;
    return SAL_CRYPT_HmacSize(*hashAlg);
}
#endif /* HITLS_TLS_PROTO_TLS13 */

bool GroupConformToVersion(const TLS_Ctx *ctx, uint16_t version, uint16_t group)
{
    uint32_t versionBits = MapVersion2VersionBit(IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask), version);
    const TLS_GroupInfo *groupInfo = ConfigGetGroupInfo(&ctx->config.tlsConfig, group);
    if (groupInfo == NULL || ((groupInfo->versionBits & versionBits) != versionBits)) {
        return false;
    }
    return true;
}

uint16_t *CheckSupportSignAlgorithms(const TLS_Ctx *ctx, const uint16_t *signAlgorithms,
    uint32_t signAlgorithmsSize, uint32_t *newSignAlgorithmsSize)
{
    (void)ctx;
    uint32_t validNum = 0;
    uint16_t *retSignAlgorithms = BSL_SAL_Calloc(signAlgorithmsSize, sizeof(uint16_t));
    if (retSignAlgorithms == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17308, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return NULL;
    }
    for (uint32_t i = 0; i < signAlgorithmsSize; i++) {
#ifdef HITLS_TLS_PROTO_TLS13
        const uint32_t dsaMask = 0x02;
        const uint32_t sha1Mask = 0x0200;
        const uint32_t sha224Mask = 0x0300;
        if (ctx->config.tlsConfig.maxVersion == HITLS_VERSION_TLS13 &&
            ctx->config.tlsConfig.minVersion == HITLS_VERSION_TLS13) {
            if (ctx->isClient &&
                (((signAlgorithms[i] & 0xff00) == sha1Mask) ||
                ((signAlgorithms[i] & 0xff00) == sha224Mask))) {
                continue;
            }
            if (((signAlgorithms[i] & 0xff) == dsaMask) ||
                signAlgorithms[i] == CERT_SIG_SCHEME_RSA_PKCS1_SHA1 ||
                signAlgorithms[i] == CERT_SIG_SCHEME_RSA_PKCS1_SHA224) {
                continue;
            }
        }
#endif /* HITLS_TLS_PROTO_TLS13 */
        if (ctx->config.tlsConfig.maxVersion != HITLS_VERSION_TLCP_DTLCP11 &&
            ctx->config.tlsConfig.maxVersion != HITLS_VERSION_TLS13 &&
            signAlgorithms[i] == CERT_SIG_SCHEME_SM2_SM3) {
            continue;
        }
#ifdef HITLS_TLS_FEATURE_SECURITY
        if (SECURITY_SslCheck(ctx, HITLS_SECURITY_SECOP_SIGALG_CHECK, 0, signAlgorithms[i], NULL) != SECURITY_SUCCESS) {
            continue;
        }
#endif /* HITLS_TLS_FEATURE_SECURITY */
        retSignAlgorithms[validNum] = signAlgorithms[i];
        validNum++;
    }
    *newSignAlgorithmsSize = validNum;

    return retSignAlgorithms;
}

uint32_t HS_GetExtensionTypeId(uint32_t hsExtensionsType)
{
    switch (hsExtensionsType) {
        case HS_EX_TYPE_SERVER_NAME: return HS_EX_TYPE_ID_SERVER_NAME;
        case HS_EX_TYPE_SUPPORTED_GROUPS: return HS_EX_TYPE_ID_SUPPORTED_GROUPS;
        case HS_EX_TYPE_POINT_FORMATS: return HS_EX_TYPE_ID_POINT_FORMATS;
        case HS_EX_TYPE_SIGNATURE_ALGORITHMS: return HS_EX_TYPE_ID_SIGNATURE_ALGORITHMS;
        case HS_EX_TYPE_APP_LAYER_PROTOCOLS: return HS_EX_TYPE_ID_APP_LAYER_PROTOCOLS;
        case HS_EX_TYPE_ENCRYPT_THEN_MAC: return HS_EX_TYPE_ID_ENCRYPT_THEN_MAC;
        case HS_EX_TYPE_EXTENDED_MASTER_SECRET: return HS_EX_TYPE_ID_EXTENDED_MASTER_SECRET;
        case HS_EX_TYPE_SESSION_TICKET: return HS_EX_TYPE_ID_SESSION_TICKET;
        case HS_EX_TYPE_PRE_SHARED_KEY: return HS_EX_TYPE_ID_PRE_SHARED_KEY;
        case HS_EX_TYPE_SUPPORTED_VERSIONS: return HS_EX_TYPE_ID_SUPPORTED_VERSIONS;
        case HS_EX_TYPE_COOKIE: return HS_EX_TYPE_ID_COOKIE;
        case HS_EX_TYPE_PSK_KEY_EXCHANGE_MODES: return HS_EX_TYPE_ID_PSK_KEY_EXCHANGE_MODES;
        case HS_EX_TYPE_CERTIFICATE_AUTHORITIES: return HS_EX_TYPE_ID_CERTIFICATE_AUTHORITIES;
        case HS_EX_TYPE_POST_HS_AUTH: return HS_EX_TYPE_ID_POST_HS_AUTH;
        case HS_EX_TYPE_KEY_SHARE: return HS_EX_TYPE_ID_KEY_SHARE;
        case HS_EX_TYPE_RENEGOTIATION_INFO: return HS_EX_TYPE_ID_RENEGOTIATION_INFO;
        default: break;
    }
    return HS_EX_TYPE_ID_UNRECOGNIZED;
}

int32_t HS_CheckReceivedExtension(HITLS_Ctx *ctx, HS_MsgType hsType, uint64_t hsMsgExtensionsMask,
    uint64_t hsMsgAllowedExtensionsMask)
{
    if ((hsMsgExtensionsMask & hsMsgAllowedExtensionsMask) != hsMsgExtensionsMask) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17311, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "%d msg have illegal extensions, extensionMask: %lu", hsType, hsMsgExtensionsMask, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }
    return HITLS_SUCCESS;
}

bool IsCipherSuiteAllowed(const HITLS_Ctx *ctx, uint16_t cipherSuite, bool checkNegoVersion)
{
    if (!CFG_CheckCipherSuiteSupported(cipherSuite)) {
        return false;
    }

    uint16_t minVersion = ctx->config.tlsConfig.minVersion;
    uint16_t maxVersion = ctx->config.tlsConfig.maxVersion;
    if (!CFG_CheckCipherSuiteVersion(cipherSuite, minVersion, maxVersion)) {
        return false;
    }

    CipherSuiteInfo cipherInfo = {0};
    (void)CFG_GetCipherSuiteInfo(cipherSuite, &cipherInfo);
    if ((ctx->isClient && ctx->config.tlsConfig.pskClientCb == NULL) ||
        (!ctx->isClient && ctx->config.tlsConfig.pskServerCb == NULL)) {
            if ((cipherInfo.kxAlg == HITLS_KEY_EXCH_PSK) ||
                (cipherInfo.kxAlg == HITLS_KEY_EXCH_DHE_PSK) ||
                (cipherInfo.kxAlg == HITLS_KEY_EXCH_ECDHE_PSK) ||
                (cipherInfo.kxAlg == HITLS_KEY_EXCH_RSA_PSK)) {
                return false;
            }
    }

    if (checkNegoVersion) {
        uint16_t negotiatedVersion = ctx->negotiatedInfo.version;
        if (negotiatedVersion > 0) {
            if (!CFG_CheckCipherSuiteVersion(cipherSuite, negotiatedVersion, negotiatedVersion)) {
                return false;
            }
        }
    }

    return true;
}
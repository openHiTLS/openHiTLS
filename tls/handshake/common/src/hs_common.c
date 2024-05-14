/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <string.h>
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
#include "indicator.h"
#include "pack.h"
#include "security.h"
#include "parse.h"
#include "hs_kx.h"
#include "hs.h"
#include "hs_common.h"


#define DTLS_SCTP_AUTH_LABEL "EXPORTER_DTLS_OVER_SCTP" /* dtls SCTP auth key label */

typedef int32_t (*GET_EXTSIZE_FUNC)(TLS_Ctx *ctx, uint32_t *exSize);
typedef struct {
    HITLS_HandshakeState state;
    GET_EXTSIZE_FUNC getSizeFunc;
} GetHSMsgSize;

/* Fixed random value of the hello retry request packet */
const uint8_t g_hrrRandom[HS_RANDOM_SIZE] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};

const uint8_t g_tls12Downgrade[HS_DOWNGRADE_RANDOM_SIZE] = {
    0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01
};

const uint8_t *HS_GetHrrRandom(uint32_t *len)
{
    *len = HS_RANDOM_SIZE;
    return g_hrrRandom;
}

const uint8_t *HS_GetTls12DowngradeRandom(uint32_t *len)
{
    *len = HS_DOWNGRADE_RANDOM_SIZE;
    return g_tls12Downgrade;
}

uint32_t HS_GetVersion(const TLS_Ctx *ctx)
{
    if (ctx->negotiatedInfo.version > 0) {
        /* The version has been negotiated */
        return ctx->negotiatedInfo.version;
    } else {
        /* If the version is not negotiated, the latest version supported by the local is returned */
        return ctx->config.tlsConfig.maxVersion;
    }
}

const char *HS_GetStateStr(uint32_t state)
{
    /** The handshake status is abnormal. */
    if (state > TRY_RECV_FINISH) {
        return "unknown";
    }

    static const char *stateMachineStr[] = {
        [TLS_IDLE] = "idle",
        [TLS_CONNECTED] = "connected",
        [TRY_SEND_HELLO_REQUEST] = "send hello request",
        [TRY_SEND_CLIENT_HELLO] = "send client hello",
        [TRY_SEND_HELLO_RETRY_REQUEST] = "send hello retry request",
        [TRY_SEND_HELLO_VERIFY_REQUEST] = "send hello verify request",
        [TRY_SEND_SERVER_HELLO] = "send server hello",
        [TRY_SEND_ENCRYPTED_EXTENSIONS] = "send encrypted extensions",
        [TRY_SEND_CERTIFICATE] = "send certificate",
        [TRY_SEND_SERVER_KEY_EXCHANGE] = "send server key exchange",
        [TRY_SEND_CERTIFICATE_REQUEST] = "send certificate request",
        [TRY_SEND_SERVER_HELLO_DONE] = "send server hello done",
        [TRY_SEND_CERTIFICATE_VERIFY] = "send certificate verify",
        [TRY_SEND_NEW_SESSION_TICKET] = "send new session ticket",
        [TRY_SEND_CLIENT_KEY_EXCHANGE] = "send client key exchange",
        [TRY_SEND_CHANGE_CIPHER_SPEC] = "send change cipher spec",
        [TRY_SEND_END_OF_EARLY_DATA] = "send end of early data",
        [TRY_SEND_FINISH] = "send finished",
        [TRY_RECV_HELLO_VERIFY_REQUEST] = "recv hello verify request",
        [TRY_RECV_CLIENT_HELLO] = "recv client hello",
        [TRY_RECV_SERVER_HELLO] = "recv server hello",
        [TRY_RECV_ENCRYPTED_EXTENSIONS] = "recv encrypted extensions",
        [TRY_RECV_CERTIFICATE] = "recv certificate",
        [TRY_RECV_SERVER_KEY_EXCHANGE] = "recv server key exchange",
        [TRY_RECV_CERTIFICATE_REQUEST] = "recv certificate request",
        [TRY_RECV_SERVER_HELLO_DONE] = "recv server hello done",
        [TRY_RECV_CERTIFICATE_VERIFY] = "recv certificate verify",
        [TRY_RECV_NEW_SESSION_TICKET] = "recv new session ticket",
        [TRY_RECV_CLIENT_KEY_EXCHANGE] = "recv client key exchange",
        [TRY_RECV_END_OF_EARLY_DATA] = "recv end of early data",
        [TRY_RECV_FINISH] = "recv finished",
    };

    /** Status character string */
    return stateMachineStr[state];
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
        case ENCRYPTED_EXTENSIONS:
            return "encrypted extensions";
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
    if (ctx->isClient) {
        INDICATOR_StatusIndicate(ctx, INDICATE_EVENT_STATE_CONNECT_LOOP, INDICATE_VALUE_SUCCESS);
    } else {
        INDICATOR_StatusIndicate(ctx, INDICATE_EVENT_STATE_ACCEPT_LOOP, INDICATE_VALUE_SUCCESS);
    }
    BSL_LOG_BINLOG_VARLEN(BINLOG_ID15573, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "handshake state machine change to:%s.", HS_GetStateStr(nextState));
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

    /** Copy the first random value */
    if (memcpy_s(dest, destSize, random1, randomSize) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15575, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "combine random1 fail.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    /** Copy the second random value */
    if (memcpy_s(&dest[randomSize], destSize - randomSize, random2, randomSize) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15576, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "combine random2 fail.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }

    return HITLS_SUCCESS;
}

/**
 * @brief Obtain the public key length of the Named Curve curve of the ECDHE key agreement algorithm.
 * @attention The length of the public key cannot exceed 255 bytes.
 * @param namedcurve [IN] Named Curve Enumerated type
 *
 * @retval len Length of the public key
 */
uint32_t HS_GetNamedCurvePubkeyLen(HITLS_NamedGroup namedcurve)
{
    uint32_t len = 0u;
    switch (namedcurve) {
        case HITLS_EC_GROUP_CURVE25519:
            len = 32u; /* 32 elliptic curve X25519 public key length */
            break;
        case HITLS_EC_GROUP_CURVE448:
            len = 56u; /* 56 elliptic curve X448 public key length */
            break;
        case HITLS_EC_GROUP_SECP256R1:
        case HITLS_EC_GROUP_BRAINPOOLP256R1:
            len = 65u; /* (32 * 2) + 1 elliptic curve SECP256R1,brainpoolP256r1 public key length */
            break;
        case HITLS_EC_GROUP_SECP384R1:
        case HITLS_EC_GROUP_BRAINPOOLP384R1:
            len = 97u; /* (48 * 2) + 1 elliptic curve SECP384R1,brainpoolP384r1 public key length */
            break;
        case HITLS_EC_GROUP_BRAINPOOLP512R1:
            len = 129u; /* Length of the elliptic curve brainpoolP512r1 public key */
            break;
        case HITLS_EC_GROUP_SECP521R1:
            len = 133u; /* (66 * 2) + 1 elliptic curve SECP521R1 public key length */
            break;
#ifndef HITLS_NO_TLCP11
        case HITLS_EC_GROUP_SM2:
            len = 65u; /* (32 * 2) + 1 elliptic curve SM2 public key length */
            break;
#endif
        case HITLS_FF_DHE_2048:
            len = 256u; /* HITLS_FF_DHE_2048 public key length */
            break;
        case HITLS_FF_DHE_3072:
            len = 384u; /* HITLS_FF_DHE_3072 public key length */
            break;
        case HITLS_FF_DHE_4096:
            len = 512u; /* HITLS_FF_DHE_4096 public key length */
            break;
        case HITLS_FF_DHE_6144:
            len = 768u; /* HITLS_FF_DHE_6144 public key length */
            break;
        case HITLS_FF_DHE_8192:
            len = 1024u; /* HITLS_FF_DHE_8192 public key length */
            break;
        default:
            break;
    }
    return len;
}

#ifndef HITLS_NO_TLCP11
uint8_t *HS_PrepareSignDataTlcp(const TLS_Ctx *ctx, const uint8_t *partSignData, uint32_t partSignDataLen,
    uint32_t *signDataLen)
{
    /* Signature data: client random number + server random number + exchange parameter length + key exchange packet
     * data/encryption certificate */
    uint32_t exchParamLen = 3;
    uint32_t randomLen = HS_RANDOM_SIZE * 2u;
    uint32_t dataLen = randomLen + partSignDataLen + exchParamLen;

    /* Allocate the signature data memory. */
    uint8_t *data = BSL_SAL_Calloc(1u, dataLen);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15577, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "signature data memory alloc fail.", 0, 0, 0, 0);
        return NULL;
    }

    /* Replicate the random number of the client */
    (void)memcpy_s(data, dataLen, ctx->hsCtx->clientRandom, HS_RANDOM_SIZE);
    /* Replicate the random number on the server */
    (void)memcpy_s(&data[HS_RANDOM_SIZE], dataLen - HS_RANDOM_SIZE, ctx->hsCtx->serverRandom, HS_RANDOM_SIZE);
    /* Fill the length of the key exchange parameter */
    BSL_Uint24ToByte(partSignDataLen, &data[randomLen]);
    /* Copy key exchange packet data */
    if (memcpy_s(&data[randomLen] + exchParamLen, dataLen - randomLen - exchParamLen,
        partSignData, partSignDataLen) != EOK) {
        BSL_SAL_FREE(data);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15578, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "memcpy key exchange data fail.", 0, 0, 0, 0);
        return NULL;
    }

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

    /* Allocate the signature data memory. */
    uint8_t *data = BSL_SAL_Calloc(1u, dataLen);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return NULL;
    }

    /* Replicate the random number of the client */
    (void)memcpy_s(data, dataLen, ctx->hsCtx->clientRandom, HS_RANDOM_SIZE);
    /* Replicate the random number on the server */
    (void)memcpy_s(&data[HS_RANDOM_SIZE], dataLen - HS_RANDOM_SIZE, ctx->hsCtx->serverRandom, HS_RANDOM_SIZE);
    /* Copy key exchange packet data */
    ret = memcpy_s(&data[randomLen], dataLen - randomLen, partSignData, partSignDataLen);
    if (ret != EOK) {
        BSL_SAL_Free(data);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return NULL;
    }

    *signDataLen = dataLen;
    return data;
}

#ifndef HITLS_NO_DTLS12
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
    /** Key derivation */
    ret = SAL_CRYPT_PRF(&deriveInfo, authKey, authKeyLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15580, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SAL_CRYPT_PRF fail when calc sctp auth key.", 0, 0, 0, 0);
        return ret;
    }

    return HITLS_SUCCESS;
}

int32_t HS_SetSctpAuthKey(TLS_Ctx *ctx)
{
    /* If the bottom layer is not SCTP, the auth key does not need to be configured and return HITLS_SUCCESS */
    if (BSL_UIO_GetTransportType(ctx->uio) != BSL_UIO_SCTP) {
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
    BSL_UIO_SctpAuthKey key = {0};
    key.authKey = authKey;
    key.authKeySize = authKeyLen;
    ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_SCTP_ADD_AUTH_SHARED_KEY, (int32_t)sizeof(BSL_UIO_SctpAuthKey), &key);
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
    /* If the bottom layer is not SCTP, the auth key does not need to be configured and
     * return HITLS_SUCCESS.
     */
    if (BSL_UIO_GetTransportType(ctx->uio) != BSL_UIO_SCTP) {
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
    int32_t ret;

    if (BSL_UIO_GetTransportType(ctx->uio) != BSL_UIO_SCTP) {
        return HITLS_SUCCESS;
    }

    /* After the handshake is complete, delete the old sctp auth key */
    ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_SCTP_DEL_PRE_AUTH_SHARED_KEY, 0, NULL);
    if (ret != BSL_SUCCESS) {
        ret = HITLS_UIO_SCTP_DEL_AUTH_KEY_FAIL;
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15584, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio delete sctp auth shared key failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    return HITLS_SUCCESS;
}
#endif /* end #ifndef HITLS_NO_DTLS12 */

int32_t HS_GetSupportedCertTypeList(const TLS_Config *config, uint8_t *buf, uint32_t bufSize, uint32_t *listSize)
{
    bool isCertTypeSupported[MAX_CERT_TYPE_LISTS_SIZE] = {0};
    uint32_t supportedCertTypesSize = 0;
    uint32_t bufOffset = 0;
    for (uint32_t i = 0; i < config->cipherSuitesSize; i++) {
        /* Find the supported certificate type based on the configured cipher suite and return the certificate type */
        uint8_t type = CFG_GetCertTypeByCipherSuite(config->cipherSuites[i]);
        if ((type != CERT_TYPE_UNKNOWN) && (isCertTypeSupported[type] == false)) {
            if (bufSize <= bufOffset) {
                BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15585, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "the buf length of cert type is not enough.", 0, 0, 0, 0);
                return HITLS_INTERNAL_EXCEPTION;
            }
            buf[bufOffset++] = type;
            isCertTypeSupported[type] = true;
            supportedCertTypesSize++;
        }
    }
    *listSize = supportedCertTypesSize;
    return HITLS_SUCCESS;
}

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
#ifndef HITLS_NO_TLCP11
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP11) {
        return true; /* The TLCP needs to send the ServerKeyExchange message. */
    }
#endif
    /* The ECDH and DH certificates already contain the public key information, and the ServerKeyExchange message
     *  is not required. */
    /* RSA keys are generated by the client, and the ServerKeyExchange message is not required. */
    return ((kxAlg != HITLS_KEY_EXCH_ECDH) && (kxAlg != HITLS_KEY_EXCH_DH) && (kxAlg != HITLS_KEY_EXCH_RSA));
}

bool IsPskNegotiation(const TLS_Ctx *ctx)
{
    HITLS_KeyExchAlgo kxAlg = ctx->negotiatedInfo.cipherSuiteInfo.kxAlg;

    return ((kxAlg == HITLS_KEY_EXCH_ECDHE_PSK) || (kxAlg == HITLS_KEY_EXCH_DHE_PSK) ||
        (kxAlg == HITLS_KEY_EXCH_RSA_PSK) || (kxAlg == HITLS_KEY_EXCH_PSK));
}

/* Check whether the certificate needs to be prepared. */
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

bool IsTicketSupport(TLS_Ctx *ctx)
{
    return ctx->config.tlsConfig.isSupportSessionTicket &&
        (SECURITY_SslCheck(ctx, HITLS_SECURITY_SECOP_TICKET, 0, 0, NULL) == SECURITY_SUCCESS);
}

int32_t CheckClientPsk(TLS_Ctx *ctx)
{
    PskInfo *pskInfo = ctx->hsCtx->kxCtx->pskInfo;
    uint8_t psk[HS_PSK_MAX_LEN] = {0};
    uint8_t identity[HS_PSK_IDENTITY_MAX_LEN + 1] = {0};

    /* If the value of psk is not NULL, it has been processed. */
    if (pskInfo != NULL && pskInfo->psk != NULL) {
        return HITLS_SUCCESS;
    }

    if (ctx->config.tlsConfig.pskClientCb == NULL) {
        return HITLS_UNREGISTERED_CALLBACK;
    }

    uint32_t pskUsedLen = ctx->config.tlsConfig.pskClientCb(ctx, NULL, identity, HS_PSK_IDENTITY_MAX_LEN,
                                                            psk, HS_PSK_MAX_LEN);
    if (pskUsedLen == 0 || pskUsedLen > HS_PSK_IDENTITY_MAX_LEN) {
        return HITLS_MSG_HANDLE_ILLEGAL_PSK_LEN;
    }
    /* Length of pskid will not exceed 128 bytes */
    uint32_t identityUsedLen = (uint32_t)strnlen((char *)identity, HS_PSK_IDENTITY_MAX_LEN + 1);
    if (identityUsedLen > HS_PSK_IDENTITY_MAX_LEN) {
        return HITLS_MSG_HANDLE_ILLEGAL_IDENTITY_LEN;
    }

    if (ctx->hsCtx->kxCtx->pskInfo == NULL) {
        ctx->hsCtx->kxCtx->pskInfo = (PskInfo *)BSL_SAL_Calloc(1u, sizeof(PskInfo));
        if (ctx->hsCtx->kxCtx->pskInfo == NULL) {
            (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);
            return HITLS_MEMALLOC_FAIL;
        }
    }

    uint8_t *tmpIdentity = NULL;
    if (identityUsedLen > 0) {
        tmpIdentity = (uint8_t *)BSL_SAL_Calloc(1u, (identityUsedLen + 1));
        if (tmpIdentity == NULL) {
            (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);
            return HITLS_MEMALLOC_FAIL;
        }
        (void)memcpy_s(tmpIdentity, identityUsedLen + 1, identity, identityUsedLen);
    }
    uint8_t *tmpPsk = (uint8_t *)BSL_SAL_Dump(psk, pskUsedLen);
    (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);
    if (tmpPsk == NULL) {
        BSL_SAL_FREE(tmpIdentity);
        return HITLS_MEMALLOC_FAIL;
    }

    if (tmpIdentity != NULL) {
        BSL_SAL_FREE(ctx->hsCtx->kxCtx->pskInfo->identity);
        ctx->hsCtx->kxCtx->pskInfo->identity = tmpIdentity;
        ctx->hsCtx->kxCtx->pskInfo->identityLen = identityUsedLen;
    }

    ctx->hsCtx->kxCtx->pskInfo->psk = tmpPsk;
    ctx->hsCtx->kxCtx->pskInfo->pskLen = pskUsedLen;

    return HITLS_SUCCESS;
}

uint32_t HS_GetState(const TLS_Ctx *ctx)
{
    if (ctx->hsCtx == NULL) {
        return HS_STATE_BUTT;
    }

    return ctx->hsCtx->state;
}

const char *HS_GetServerName(const TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->hsCtx == NULL) {
        return NULL;
    }
    return (char *)ctx->hsCtx->serverName;
}

int32_t HS_GrowMsgBuf(TLS_Ctx *ctx, uint32_t msgSize, uint32_t upperBound, bool keepOldData)
{
    if (msgSize <= ctx->hsCtx->bufferLen) {
        return HITLS_SUCCESS;
    }
    uint32_t bufSize = ctx->hsCtx->bufferLen;
    uint32_t oldDataSize = bufSize;

    uint8_t *oldDataAddr = ctx->hsCtx->msgBuf;

    while (bufSize < msgSize && bufSize < upperBound) {
        bufSize = bufSize << 1;
    }

    /* The maximum value cannot exceed upperBound */
    bufSize = (bufSize > upperBound) ? upperBound : bufSize;
    ctx->hsCtx->msgBuf = BSL_SAL_Calloc(1u, bufSize);
    if (ctx->hsCtx->msgBuf == NULL) {
        BSL_SAL_FREE(oldDataAddr);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15935, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "msgBuf malloc fail while get reass msg.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    ctx->hsCtx->bufferLen = bufSize;

    if (keepOldData) {
        if (memcpy_s(ctx->hsCtx->msgBuf, bufSize, oldDataAddr, oldDataSize) != EOK) {
            BSL_SAL_FREE(ctx->hsCtx->msgBuf);
            BSL_SAL_FREE(oldDataAddr);
            ctx->hsCtx->bufferLen = 0;
            return HITLS_MEMCPY_FAIL;
        }
    }
    BSL_SAL_FREE(oldDataAddr);
    return HITLS_SUCCESS;
}

int32_t HS_ReSizeMsgBuf(TLS_Ctx *ctx, uint32_t msgSize)
{
    bool keepOldData = false;
    return HS_GrowMsgBuf(ctx, msgSize, REC_MAX_PLAIN_LENGTH, keepOldData);
}

uint32_t HS_MaxMessageSize(TLS_Ctx *ctx, HS_MsgType type)
{
    switch (type) {
        case HELLO_REQUEST:
            return HITLS_HELLO_REQUEST_MAX_SIZE;
        case CLIENT_HELLO:
            return HITLS_CLIENT_HELLO_MAX_SIZE;
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

uint32_t HS_GetBinderLen(HITLS_Session *session, HITLS_HashAlgo *hashAlg)
{
    if (*hashAlg > HITLS_HASH_NULL && *hashAlg < HITLS_HASH_BUTT) {
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
        return 0;
    }
    *hashAlg = cipherInfo.hashAlg;
    return SAL_CRYPT_HmacSize(*hashAlg);
}

static struct {
    uint16_t group;
    uint16_t minVersion;
    uint16_t maxVersion;
    uint16_t minDtlsVersion;
    uint16_t maxDtlsVersion;
} g_groupsConfomVersion[] = {
    {HITLS_EC_GROUP_CURVE25519, HITLS_VERSION_TLS10, HITLS_VERSION_TLS13, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12},
    {HITLS_EC_GROUP_SECP256R1, HITLS_VERSION_TLS10, HITLS_VERSION_TLS13, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12},
    {HITLS_EC_GROUP_SECP521R1, HITLS_VERSION_TLS10, HITLS_VERSION_TLS13, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12},
    {HITLS_EC_GROUP_SECP384R1, HITLS_VERSION_TLS10, HITLS_VERSION_TLS13, HITLS_VERSION_DTLS12, HITLS_VERSION_DTLS12},
    {HITLS_EC_GROUP_SM2, HITLS_VERSION_TLCP11, HITLS_VERSION_TLCP11, 0, 0},
    {HITLS_FF_DHE_2048, HITLS_VERSION_TLS13, HITLS_VERSION_TLS13, 0, 0},
    {HITLS_FF_DHE_3072, HITLS_VERSION_TLS13, HITLS_VERSION_TLS13, 0, 0},
    {HITLS_FF_DHE_4096, HITLS_VERSION_TLS13, HITLS_VERSION_TLS13, 0, 0},
    {HITLS_FF_DHE_6144, HITLS_VERSION_TLS13, HITLS_VERSION_TLS13, 0, 0},
    {HITLS_FF_DHE_8192, HITLS_VERSION_TLS13, HITLS_VERSION_TLS13, 0, 0},
    {HITLS_EC_GROUP_BRAINPOOLP256R1,
        HITLS_VERSION_TLS10,
        HITLS_VERSION_TLS12,
        HITLS_VERSION_DTLS12,
        HITLS_VERSION_DTLS12},
    {HITLS_EC_GROUP_BRAINPOOLP384R1,
        HITLS_VERSION_TLS10,
        HITLS_VERSION_TLS12,
        HITLS_VERSION_DTLS12,
        HITLS_VERSION_DTLS12},
    {HITLS_EC_GROUP_BRAINPOOLP512R1,
        HITLS_VERSION_TLS10,
        HITLS_VERSION_TLS12,
        HITLS_VERSION_DTLS12,
        HITLS_VERSION_DTLS12},
};

bool GroupConformToVersion(uint16_t version, uint16_t group)
{
    for (size_t i = 0; i < sizeof(g_groupsConfomVersion) / sizeof(g_groupsConfomVersion[0]); i++) {
        if (group == g_groupsConfomVersion[i].group) {
            if (version >= g_groupsConfomVersion[i].minVersion && version <= g_groupsConfomVersion[i].maxVersion) {
                return true;
            }
            if (version >= g_groupsConfomVersion[i].minDtlsVersion &&
                version <= g_groupsConfomVersion[i].maxDtlsVersion) {
                return true;
            }
            break;
        }
    }
    return false;
}

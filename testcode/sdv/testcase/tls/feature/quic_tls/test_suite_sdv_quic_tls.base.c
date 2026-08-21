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

/*
 * Shared in-memory QUIC transport for the QUIC-TLS API and interaction suites.
 * TLS emits raw Handshake bytes through AddHandshakeData. The tests reassemble
 * and push those bytes into the peer at its current encryption level, exactly
 * as a QUIC implementation handles CRYPTO frames.
 */

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hitls.h"
#include "hitls_alpn.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "hitls_quic_tls.h"
#include "bsl_hash.h"
#include "frame_tls.h"
#include "frame_link.h"

#define QUIC_TEST_LEVEL_COUNT 4u
#define QUIC_TEST_MAX_SECRET_LEN 64u
#define QUIC_TEST_MAX_DRIVE_STEPS 4096u
#define QUIC_TEST_TP_MUTATION_NONE 0u
#define QUIC_TEST_TP_MUTATION_CHANGE_SECOND_CH 1u
#define QUIC_TEST_TP_MUTATION_OMIT_SECOND_CH 2u
#define QUIC_TEST_SIDE_NONE 0u
#define QUIC_TEST_SIDE_CLIENT 1u
#define QUIC_TEST_SIDE_SERVER 2u
#define QUIC_TEST_CONFIG_TLS 0
#define QUIC_TEST_CONFIG_TLS13 1
#define QUIC_TEST_CONFIG_TLS12 2

static const uint8_t g_quicTestAlpn[] = {2u, 'h', '3'};
static const uint8_t g_quicTestClientParams[] = {0x01u, 0x02u, 0x03u};
static const uint8_t g_quicTestServerParams[] = {0x04u, 0x05u};
static const uint16_t g_quicTestP256[] = {HITLS_EC_GROUP_SECP256R1};

/* Growable byte buffer collecting the TLS Handshake bytes emitted by one
 * endpoint at a single encryption level, playing the role of the peer-bound
 * CRYPTO stream of a QUIC implementation. */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} QuicTlsTestBuffer;

/* Per-endpoint QUIC-TLS test state. output[] gathers AddHandshakeData bytes
 * per encryption level; the secret/callback counters and last-error fields
 * record what the push API delivered so test cases can assert on the exact
 * handshake progress (installation order, alert mapping, failure injection). */
typedef struct {
    QuicTlsTestBuffer output[QUIC_TEST_LEVEL_COUNT];
    uint8_t readSecret[QUIC_TEST_LEVEL_COUNT][QUIC_TEST_MAX_SECRET_LEN];
    uint8_t writeSecret[QUIC_TEST_LEVEL_COUNT][QUIC_TEST_MAX_SECRET_LEN];
    size_t readSecretLen[QUIC_TEST_LEVEL_COUNT];
    size_t writeSecretLen[QUIC_TEST_LEVEL_COUNT];
    uint32_t addDataCount[QUIC_TEST_LEVEL_COUNT];
    uint32_t readSecretCount;
    uint32_t writeSecretCount;
    uint32_t flushCount;
    uint32_t alertCount;
    HITLS_QUIC_TLS_EncryptionLevel lastAlertLevel;
    uint8_t lastAlert;
    uint32_t failCallbackId;
    bool setTransportParamsInCallback;
    bool transportParamsSetInCallback;
    int32_t transportParamsCallbackRet;
    const uint8_t *callbackTransportParams;
    size_t callbackTransportParamsLen;
    uint32_t initialFlightCount;
    uint32_t transportParamsMutation;
    bool transportParamsMutationDone;
} QuicTlsTestEndpoint;

/* One client/server test pair: two configurations, two FRAME links holding
 * the HITLS_Ctx objects, and the two endpoints' QUIC callback state. The
 * handshake is driven by QuicTlsTestRunHandshake which moves output buffers
 * between the endpoints through HITLS_QUIC_TLS_ProvideData. */
typedef struct {
    HITLS_Config *clientConfig;
    HITLS_Config *serverConfig;
    FRAME_LinkObj *clientLink;
    FRAME_LinkObj *serverLink;
    QuicTlsTestEndpoint clientEndpoint;
    QuicTlsTestEndpoint serverEndpoint;
} QuicTlsTestPair;

/* Release both links, configurations, and endpoint states of a test pair. */
static void QuicTlsTestPairFree(QuicTlsTestPair *pair);

/* Append len bytes to a growable test buffer, doubling capacity on demand. */
static int32_t QuicTlsTestBufferAppend(QuicTlsTestBuffer *buffer, const uint8_t *data, size_t len)
{
    uint8_t *newData;
    size_t newCap;
    if (len == 0u) {
        return HITLS_SUCCESS;
    }
    if (buffer == NULL || data == NULL || buffer->len > SIZE_MAX - len) {
        return HITLS_INVALID_INPUT;
    }
    if (buffer->len + len > buffer->cap) {
        newCap = buffer->cap == 0u ? 4096u : buffer->cap;
        while (newCap < buffer->len + len) {
            if (newCap > SIZE_MAX / 2u) {
                return HITLS_MEMALLOC_FAIL;
            }
            newCap *= 2u;
        }
        newData = (uint8_t *)realloc(buffer->data, newCap);
        if (newData == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        buffer->data = newData;
        buffer->cap = newCap;
    }
    (void)memcpy(buffer->data + buffer->len, data, len);
    buffer->len += len;
    return HITLS_SUCCESS;
}

/* Copy one traffic secret into the fixed-size per-level test slot. */
static int32_t QuicTlsTestStoreSecret(uint8_t dst[QUIC_TEST_MAX_SECRET_LEN], size_t *dstLen,
    const uint8_t *secret, size_t secretLen)
{
    if (secret == NULL || secretLen == 0u || secretLen > QUIC_TEST_MAX_SECRET_LEN) {
        return HITLS_INVALID_INPUT;
    }
    (void)memcpy(dst, secret, secretLen);
    *dstLen = secretLen;
    return HITLS_SUCCESS;
}

/* set_read_secret callback: records the secret, enforces optional failure
 * injection, and counts installations per level. */
static int32_t QuicTlsTestSetReadSecret(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level,
    const HITLS_Cipher *cipher, const uint8_t *secret, size_t secretLen, void *arg)
{
    QuicTlsTestEndpoint *endpoint = (QuicTlsTestEndpoint *)arg;
    (void)ctx;
    if (endpoint == NULL || cipher == NULL || (uint32_t)level >= QUIC_TEST_LEVEL_COUNT) {
        return HITLS_INVALID_INPUT;
    }
    if (endpoint->failCallbackId == HITLS_QUIC_TLS_FUNC_SET_READ_SECRET) {
        return HITLS_REC_CB_FAIL;
    }
    if (QuicTlsTestStoreSecret(endpoint->readSecret[level], &endpoint->readSecretLen[level],
        secret, secretLen) != HITLS_SUCCESS) {
        return HITLS_INVALID_INPUT;
    }
    endpoint->readSecretCount++;
    return HITLS_SUCCESS;
}

/* set_write_secret callback: like the read variant, and additionally runs
 * the optional SetTransportParams-from-callback scenario on the HANDSHAKE
 * level write secret (server-side EE timing). */
static int32_t QuicTlsTestSetWriteSecret(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level,
    const HITLS_Cipher *cipher, const uint8_t *secret, size_t secretLen, void *arg)
{
    QuicTlsTestEndpoint *endpoint = (QuicTlsTestEndpoint *)arg;
    if (endpoint == NULL || cipher == NULL || (uint32_t)level >= QUIC_TEST_LEVEL_COUNT) {
        return HITLS_INVALID_INPUT;
    }
    if (endpoint->failCallbackId == HITLS_QUIC_TLS_FUNC_SET_WRITE_SECRET) {
        return HITLS_REC_CB_FAIL;
    }
    if (endpoint->setTransportParamsInCallback && !endpoint->transportParamsSetInCallback &&
        level == HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE) {
        endpoint->transportParamsCallbackRet = HITLS_QUIC_TLS_SetTransportParams(ctx,
            endpoint->callbackTransportParams, endpoint->callbackTransportParamsLen);
        endpoint->transportParamsSetInCallback = true;
        if (endpoint->transportParamsCallbackRet != HITLS_SUCCESS) {
            return endpoint->transportParamsCallbackRet;
        }
    }
    if (QuicTlsTestStoreSecret(endpoint->writeSecret[level], &endpoint->writeSecretLen[level],
        secret, secretLen) != HITLS_SUCCESS) {
        return HITLS_INVALID_INPUT;
    }
    endpoint->writeSecretCount++;
    return HITLS_SUCCESS;
}

/* Fault injection for the HRR transport-parameter tests: rewrite the QUIC
 * transport-parameters extension inside the second ClientHello so the server
 * sees a changed value (CHANGE) or a replaced unknown extension (OMIT). */
static void QuicTlsTestMutateSecondClientHello(QuicTlsTestEndpoint *endpoint, size_t oldLen, size_t dataLen)
{
    static const uint8_t transportParamsExtension[] = {
        0x00u, 0x39u, 0x00u, 0x03u, 0x01u, 0x02u, 0x03u
    };
    size_t i;
    if ((endpoint->transportParamsMutation != QUIC_TEST_TP_MUTATION_CHANGE_SECOND_CH &&
        endpoint->transportParamsMutation != QUIC_TEST_TP_MUTATION_OMIT_SECOND_CH) ||
        endpoint->initialFlightCount != 2u) {
        return;
    }
    for (i = oldLen; i + sizeof(transportParamsExtension) <= oldLen + dataLen; ++i) {
        if (memcmp(endpoint->output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL].data + i,
            transportParamsExtension, sizeof(transportParamsExtension)) == 0) {
            if (endpoint->transportParamsMutation == QUIC_TEST_TP_MUTATION_CHANGE_SECOND_CH) {
                endpoint->output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL].data[
                    i + sizeof(transportParamsExtension) - 1u] ^= 1u;
            } else {
                endpoint->output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL].data[i] = 0xffu;
                endpoint->output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL].data[i + 1u] = 0xa5u;
            }
            endpoint->transportParamsMutationDone = true;
            return;
        }
    }
}

/* add_handshake_data callback: appends the flight bytes to the per-level
 * output buffer and applies the second-ClientHello mutation when armed. */
static int32_t QuicTlsTestAddHandshakeData(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level,
    const uint8_t *data, size_t dataLen, void *arg)
{
    QuicTlsTestEndpoint *endpoint = (QuicTlsTestEndpoint *)arg;
    size_t oldLen;
    (void)ctx;
    if (endpoint == NULL || (uint32_t)level >= QUIC_TEST_LEVEL_COUNT) {
        return HITLS_INVALID_INPUT;
    }
    if (endpoint->failCallbackId == HITLS_QUIC_TLS_FUNC_ADD_HANDSHAKE_DATA) {
        return HITLS_REC_CB_FAIL;
    }
    oldLen = endpoint->output[level].len;
    if (QuicTlsTestBufferAppend(&endpoint->output[level], data, dataLen) != HITLS_SUCCESS) {
        return HITLS_REC_CB_FAIL;
    }
    endpoint->addDataCount[level]++;
    if (level == HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL) {
        endpoint->initialFlightCount++;
        QuicTlsTestMutateSecondClientHello(endpoint, oldLen, dataLen);
    }
    return HITLS_SUCCESS;
}

/* flush_flight callback: counts flight completions; failure injection turns
 * one flush into an error return. */
static int32_t QuicTlsTestFlushFlight(HITLS_Ctx *ctx, void *arg)
{
    QuicTlsTestEndpoint *endpoint = (QuicTlsTestEndpoint *)arg;
    (void)ctx;
    if (endpoint == NULL) {
        return HITLS_INVALID_INPUT;
    }
    if (endpoint->failCallbackId == HITLS_QUIC_TLS_FUNC_FLUSH_FLIGHT) {
        return HITLS_REC_CB_FAIL;
    }
    endpoint->flushCount++;
    return HITLS_SUCCESS;
}

/* send_alert callback: records the alert description and its encryption
 * level for later assertions. */
static int32_t QuicTlsTestSendAlert(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level,
    uint8_t alert, void *arg)
{
    QuicTlsTestEndpoint *endpoint = (QuicTlsTestEndpoint *)arg;
    (void)ctx;
    if (endpoint == NULL) {
        return HITLS_INVALID_INPUT;
    }
    endpoint->alertCount++;
    endpoint->lastAlertLevel = level;
    endpoint->lastAlert = alert;
    if (endpoint->failCallbackId == HITLS_QUIC_TLS_FUNC_SEND_ALERT) {
        return HITLS_REC_CB_FAIL;
    }
    return HITLS_SUCCESS;
}

static const HITLS_QUIC_TLS_Callbacks g_quicTestDispatch[] = {
    {HITLS_QUIC_TLS_FUNC_SET_READ_SECRET, (void *)QuicTlsTestSetReadSecret},
    {HITLS_QUIC_TLS_FUNC_SET_WRITE_SECRET, (void *)QuicTlsTestSetWriteSecret},
    {HITLS_QUIC_TLS_FUNC_ADD_HANDSHAKE_DATA, (void *)QuicTlsTestAddHandshakeData},
    {HITLS_QUIC_TLS_FUNC_FLUSH_FLIGHT, (void *)QuicTlsTestFlushFlight},
    {HITLS_QUIC_TLS_FUNC_SEND_ALERT, (void *)QuicTlsTestSendAlert},
    HITLS_QUIC_TLS_CALLBACKS_END
};

/* Server-side ALPN selection callback: accepts exactly the test ALPN list. */
static int32_t QuicTlsTestSelectAlpn(HITLS_Ctx *ctx, uint8_t **selectedProto,
    uint8_t *selectedProtoSize, uint8_t *clientAlpnList,
    uint32_t clientAlpnListSize, void *userData)
{
    (void)ctx;
    (void)userData;
    if (selectedProto == NULL || selectedProtoSize == NULL ||
        clientAlpnListSize != sizeof(g_quicTestAlpn) ||
        memcmp(clientAlpnList, g_quicTestAlpn, sizeof(g_quicTestAlpn)) != 0) {
        return HITLS_ALPN_ERR_ALERT_FATAL;
    }
    *selectedProto = (uint8_t *)&g_quicTestAlpn[1];
    *selectedProtoSize = g_quicTestAlpn[0];
    return HITLS_ALPN_ERR_OK;
}

/* Report whether the endpoint's handshake has completed. */
static bool QuicTlsTestIsDone(HITLS_Ctx *ctx)
{
    uint8_t done = 0u;
    return HITLS_IsHandShakeDone(ctx, &done) == HITLS_SUCCESS && done != 0u;
}

/* Classify a drive-step return value as normal progress (including the
 * expected would-block outcomes) rather than failure. */
static bool QuicTlsTestIsProgressResult(int32_t ret)
{
    return ret == HITLS_SUCCESS || ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY ||
        ret == HITLS_REC_NORMAL_IO_BUSY;
}

/* Move up to maxChunk bytes from one endpoint's output buffer at the peer's
 * current read level into the peer through HITLS_QUIC_TLS_ProvideData,
 * simulating in-order CRYPTO stream delivery (optionally fragmented). */
static int32_t QuicTlsTestTransferCurrentLevel(QuicTlsTestEndpoint *source, HITLS_Ctx *peer, size_t maxChunk)
{
    HITLS_QUIC_TLS_EncryptionLevel level = HITLS_QUIC_TLS_GetReadLevel(peer);
    QuicTlsTestBuffer *buffer;
    size_t transferLen;
    int32_t ret;
    if ((uint32_t)level >= QUIC_TEST_LEVEL_COUNT || maxChunk == 0u) {
        return HITLS_INVALID_INPUT;
    }
    buffer = &source->output[level];
    if (buffer->len == 0u) {
        return HITLS_SUCCESS;
    }
    transferLen = buffer->len < maxChunk ? buffer->len : maxChunk;
    ret = HITLS_QUIC_TLS_ProvideData(peer, level, buffer->data, transferLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    buffer->len -= transferLen;
    if (buffer->len != 0u) {
        (void)memmove(buffer->data, buffer->data + transferLen, buffer->len);
    }
    return HITLS_SUCCESS;
}

/* Drive both endpoints alternately (Connect/Accept plus CRYPTO transfer in
 * both directions) until the handshake completes, a step fails, or the step
 * budget is exhausted. failedSide reports which side errored. */
static int32_t QuicTlsTestRunHandshake(QuicTlsTestPair *pair, size_t maxChunk, uint32_t *failedSide)
{
    uint32_t step;
    int32_t ret;
    if (failedSide != NULL) {
        *failedSide = QUIC_TEST_SIDE_NONE;
    }
    for (step = 0u; step < QUIC_TEST_MAX_DRIVE_STEPS; ++step) {
        if (QuicTlsTestIsDone(pair->clientLink->ssl) && QuicTlsTestIsDone(pair->serverLink->ssl)) {
            return HITLS_SUCCESS;
        }
        if (!QuicTlsTestIsDone(pair->clientLink->ssl)) {
            ret = HITLS_Connect(pair->clientLink->ssl);
            if (!QuicTlsTestIsProgressResult(ret)) {
                if (failedSide != NULL) {
                    *failedSide = QUIC_TEST_SIDE_CLIENT;
                }
                return ret;
            }
        }
        ret = QuicTlsTestTransferCurrentLevel(&pair->clientEndpoint, pair->serverLink->ssl, maxChunk);
        if (ret != HITLS_SUCCESS) {
            if (failedSide != NULL) {
                *failedSide = QUIC_TEST_SIDE_SERVER;
            }
            return ret;
        }
        if (!QuicTlsTestIsDone(pair->serverLink->ssl)) {
            ret = HITLS_Accept(pair->serverLink->ssl);
            if (!QuicTlsTestIsProgressResult(ret)) {
                if (failedSide != NULL) {
                    *failedSide = QUIC_TEST_SIDE_SERVER;
                }
                return ret;
            }
        }
        ret = QuicTlsTestTransferCurrentLevel(&pair->serverEndpoint, pair->clientLink->ssl, maxChunk);
        if (ret != HITLS_SUCCESS) {
            if (failedSide != NULL) {
                *failedSide = QUIC_TEST_SIDE_CLIENT;
            }
            return ret;
        }
    }
    return HITLS_INTERNAL_EXCEPTION;
}

/* Apply the per-role QUIC settings: optional groups, client ALPN offer or
 * server ALPN selection callback, and no server-certificate verification. */
static int32_t QuicTlsTestConfigureEndpoint(HITLS_Config *config, bool isClient,
    const uint16_t *groups, uint32_t groupCount)
{
    int32_t ret;
    if (groups != NULL && groupCount != 0u) {
        ret = HITLS_CFG_SetGroups(config, groups, groupCount);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
    if (isClient) {
        ret = HITLS_CFG_SetVerifyNoneSupport(config, true);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        return HITLS_CFG_SetAlpnProtos(config, g_quicTestAlpn, sizeof(g_quicTestAlpn));
    }
    return HITLS_CFG_SetAlpnProtosSelectCb(config, QuicTlsTestSelectAlpn, NULL);
}

/* Create a configuration of the requested flavor (any-TLS, TLS 1.3 only, or
 * TLS 1.2 only) for version-negotiation test cases. */
static HITLS_Config *QuicTlsTestNewConfig(int configType)
{
    switch (configType) {
        case QUIC_TEST_CONFIG_TLS:
            return HITLS_CFG_NewTLSConfig();
        case QUIC_TEST_CONFIG_TLS13:
            return HITLS_CFG_NewTLS13Config();
        case QUIC_TEST_CONFIG_TLS12:
            return HITLS_CFG_NewTLS12Config();
        default:
            return NULL;
    }
}

/* Build a full test pair from explicit configuration flavors, create the
 * QUIC links, install the QUIC method dispatch on both connections, and
 * optionally install local transport parameters on either side. */
static int32_t QuicTlsTestPairNewWithConfigs(QuicTlsTestPair *pair,
    int clientConfigType, int serverConfigType,
    const uint16_t *clientGroups, uint32_t clientGroupCount,
    const uint16_t *serverGroups, uint32_t serverGroupCount,
    bool setClientParams, bool setServerParams)
{
    int32_t ret;
    (void)memset(pair, 0, sizeof(*pair));
    pair->clientConfig = QuicTlsTestNewConfig(clientConfigType);
    pair->serverConfig = QuicTlsTestNewConfig(serverConfigType);
    if (pair->clientConfig == NULL || pair->serverConfig == NULL) {
        ret = HITLS_MEMALLOC_FAIL;
        goto ERR;
    }
    ret = QuicTlsTestConfigureEndpoint(pair->clientConfig, true, clientGroups, clientGroupCount);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }
    ret = QuicTlsTestConfigureEndpoint(pair->serverConfig, false, serverGroups, serverGroupCount);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }
    pair->clientLink = FRAME_CreateQuicLink(pair->clientConfig);
    pair->serverLink = FRAME_CreateQuicLink(pair->serverConfig);
    if (pair->clientLink == NULL || pair->serverLink == NULL) {
        ret = HITLS_MEMALLOC_FAIL;
        goto ERR;
    }
    ret = HITLS_QUIC_TLS_SetQuicTlsMethod(pair->clientLink->ssl, g_quicTestDispatch, &pair->clientEndpoint);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }
    ret = HITLS_QUIC_TLS_SetQuicTlsMethod(pair->serverLink->ssl, g_quicTestDispatch, &pair->serverEndpoint);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }
    if (setClientParams) {
        ret = HITLS_QUIC_TLS_SetTransportParams(pair->clientLink->ssl,
            g_quicTestClientParams, sizeof(g_quicTestClientParams));
        if (ret != HITLS_SUCCESS) {
            goto ERR;
        }
    }
    if (setServerParams) {
        ret = HITLS_QUIC_TLS_SetTransportParams(pair->serverLink->ssl,
            g_quicTestServerParams, sizeof(g_quicTestServerParams));
        if (ret != HITLS_SUCCESS) {
            goto ERR;
        }
    }
    return HITLS_SUCCESS;

ERR:
    QuicTlsTestPairFree(pair);
    return ret;
}

/* Common case of QuicTlsTestPairNewWithConfigs with two TLS 1.3
 * configurations. */
static int32_t QuicTlsTestPairNew(QuicTlsTestPair *pair,
    const uint16_t *clientGroups, uint32_t clientGroupCount,
    const uint16_t *serverGroups, uint32_t serverGroupCount,
    bool setClientParams, bool setServerParams)
{
    return QuicTlsTestPairNewWithConfigs(pair, QUIC_TEST_CONFIG_TLS13, QUIC_TEST_CONFIG_TLS13,
        clientGroups, clientGroupCount, serverGroups, serverGroupCount, setClientParams, setServerParams);
}

/* Release one endpoint's per-level output buffers and reset its state. */
static void QuicTlsTestEndpointFree(QuicTlsTestEndpoint *endpoint)
{
    uint32_t i;
    for (i = 0u; i < QUIC_TEST_LEVEL_COUNT; ++i) {
        free(endpoint->output[i].data);
    }
    (void)memset(endpoint, 0, sizeof(*endpoint));
}

static void QuicTlsTestPairFree(QuicTlsTestPair *pair)
{
    if (pair == NULL) {
        return;
    }
    FRAME_FreeLink(pair->clientLink);
    FRAME_FreeLink(pair->serverLink);
    HITLS_CFG_FreeConfig(pair->clientConfig);
    HITLS_CFG_FreeConfig(pair->serverConfig);
    QuicTlsTestEndpointFree(&pair->clientEndpoint);
    QuicTlsTestEndpointFree(&pair->serverEndpoint);
    (void)memset(pair, 0, sizeof(*pair));
}

/* Check that one endpoint's write secret at a level equals the peer's read
 * secret at the same level (the key-installation pairing invariant). */
static bool QuicTlsTestSecretsMatch(const QuicTlsTestEndpoint *writer,
    const QuicTlsTestEndpoint *reader, HITLS_QUIC_TLS_EncryptionLevel level)
{
    size_t len = writer->writeSecretLen[level];
    return len != 0u && len == reader->readSecretLen[level] &&
        memcmp(writer->writeSecret[level], reader->readSecret[level], len) == 0;
}

/* Check that the connection's received peer transport parameters equal the
 * expected value. */
static bool QuicTlsTestPeerParamsMatch(HITLS_Ctx *ctx, const uint8_t *expected, size_t expectedLen)
{
    const uint8_t *params = NULL;
    size_t paramsLen = 0u;
    int32_t ret = HITLS_QUIC_TLS_GetPeerTransportParams(ctx, &params, &paramsLen);
    if (ret != HITLS_SUCCESS || paramsLen != expectedLen) {
        return false;
    }
    return expectedLen == 0u || (params != NULL && memcmp(params, expected, expectedLen) == 0);
}

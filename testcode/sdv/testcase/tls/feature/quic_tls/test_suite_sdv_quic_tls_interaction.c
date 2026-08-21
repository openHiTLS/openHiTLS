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

/* BEGIN_HEADER */
/* INCLUDE_BASE test_suite_sdv_quic_tls */
#include "hitls_session.h"
#include "hs_extensions.h"
#include "hs_msg.h"
#include "tls.h"
/* END_HEADER */

static const uint16_t g_quicTestP384[] = {HITLS_EC_GROUP_SECP384R1};
static const uint16_t g_quicTestP256P384[] = {
    HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1
};

#define QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET (HS_MSG_HEADER_SIZE + sizeof(uint16_t) + HS_RANDOM_SIZE)

static bool QuicTlsTestInjectLegacySessionId(QuicTlsTestBuffer *clientHello)
{
    uint8_t extra[TLS_HS_MAX_SESSION_ID_SIZE] = {0};
    uint32_t handshakeLen;
    size_t oldLen;
    if (clientHello == NULL || clientHello->len <= QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET ||
        clientHello->data[0] != CLIENT_HELLO ||
        clientHello->data[QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET] != 0u) {
        return false;
    }
    oldLen = clientHello->len;
    if (QuicTlsTestBufferAppend(clientHello, extra, sizeof(extra)) != HITLS_SUCCESS) {
        return false;
    }
    (void)memmove(clientHello->data + QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET + 1u +
            TLS_HS_MAX_SESSION_ID_SIZE,
        clientHello->data + QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET + 1u,
        oldLen - QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET - 1u);
    clientHello->data[QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET] = TLS_HS_MAX_SESSION_ID_SIZE;
    (void)memset(clientHello->data + QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET + 1u,
        0xa5, TLS_HS_MAX_SESSION_ID_SIZE);
    handshakeLen = ((uint32_t)clientHello->data[1] << 16) |
        ((uint32_t)clientHello->data[2] << 8) | clientHello->data[3];
    handshakeLen += TLS_HS_MAX_SESSION_ID_SIZE;
    clientHello->data[1] = (uint8_t)(handshakeLen >> 16);
    clientHello->data[2] = (uint8_t)(handshakeLen >> 8);
    clientHello->data[3] = (uint8_t)handshakeLen;
    return true;
}

/* Replace the first offered cipher suite in a raw ClientHello without changing its encoded length. */
static bool QuicTlsTestSetFirstClientHelloCipherSuite(QuicTlsTestBuffer *clientHello, uint16_t cipherSuite)
{
    uint8_t *data;
    uint32_t handshakeLen;
    size_t msgEnd;
    size_t offset;
    uint8_t sessionIdLen;
    uint16_t cipherSuitesLen;
    if (clientHello == NULL || clientHello->data == NULL ||
        clientHello->len <= QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET || clientHello->data[0] != CLIENT_HELLO) {
        return false;
    }

    data = clientHello->data;
    handshakeLen = ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
    if (handshakeLen > clientHello->len - 4u) {
        return false;
    }
    msgEnd = 4u + handshakeLen;
    offset = QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET;
    sessionIdLen = data[offset++];
    if ((size_t)sessionIdLen > msgEnd - offset || msgEnd - offset - sessionIdLen < 4u) {
        return false;
    }
    offset += sessionIdLen;
    cipherSuitesLen = ((uint16_t)data[offset] << 8) | data[offset + 1u];
    offset += 2u;
    if (cipherSuitesLen < 2u || (size_t)cipherSuitesLen > msgEnd - offset) {
        return false;
    }
    data[offset] = (uint8_t)(cipherSuite >> 8);
    data[offset + 1u] = (uint8_t)cipherSuite;
    return true;
}

static bool QuicTlsTestClientHelloHasExtension(const QuicTlsTestBuffer *clientHello,
    uint16_t expectedType, bool *hasExtension)
{
    const uint8_t *data;
    uint32_t handshakeLen;
    size_t msgEnd;
    size_t offset;
    size_t extensionsEnd;
    uint16_t fieldLen;
    if (clientHello == NULL || clientHello->data == NULL || hasExtension == NULL ||
        clientHello->len <= QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET || clientHello->data[0] != CLIENT_HELLO) {
        return false;
    }
    *hasExtension = false;
    data = clientHello->data;
    handshakeLen = ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
    if (handshakeLen > clientHello->len - 4u) {
        return false;
    }
    msgEnd = 4u + handshakeLen;
    offset = QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET;
    if (offset >= msgEnd) {
        return false;
    }
    fieldLen = data[offset++];
    if ((size_t)fieldLen > msgEnd - offset || msgEnd - offset - fieldLen < 2u) {
        return false;
    }
    offset += fieldLen;
    fieldLen = ((uint16_t)data[offset] << 8) | data[offset + 1u];
    offset += 2u;
    if ((size_t)fieldLen > msgEnd - offset || msgEnd - offset - fieldLen < 1u) {
        return false;
    }
    offset += fieldLen;
    fieldLen = data[offset++];
    if ((size_t)fieldLen > msgEnd - offset || msgEnd - offset - fieldLen < 2u) {
        return false;
    }
    offset += fieldLen;
    fieldLen = ((uint16_t)data[offset] << 8) | data[offset + 1u];
    offset += 2u;
    if ((size_t)fieldLen > msgEnd - offset) {
        return false;
    }
    extensionsEnd = offset + fieldLen;
    while (offset + 4u <= extensionsEnd) {
        uint16_t extensionType = ((uint16_t)data[offset] << 8) | data[offset + 1u];
        uint16_t extensionLen = ((uint16_t)data[offset + 2u] << 8) | data[offset + 3u];
        offset += 4u;
        if ((size_t)extensionLen > extensionsEnd - offset) {
            return false;
        }
        if (extensionType == expectedType) {
            *hasExtension = true;
        }
        offset += extensionLen;
    }
    return offset == extensionsEnd;
}

/* Remove supported_versions from a raw ServerHello and set legacy_version to the supplied value. */
static bool QuicTlsTestOmitServerSupportedVersion(QuicTlsTestBuffer *serverHello, uint16_t legacyVersion)
{
    uint8_t *data;
    uint32_t handshakeLen;
    size_t msgEnd;
    size_t offset;
    size_t extensionsLenOffset;
    size_t extensionsEnd;
    if (serverHello == NULL || serverHello->data == NULL ||
        serverHello->len <= QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET ||
        serverHello->data[0] != SERVER_HELLO) {
        return false;
    }

    data = serverHello->data;
    handshakeLen = ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
    if (handshakeLen > serverHello->len - 4u) {
        return false;
    }
    msgEnd = 4u + handshakeLen;
    offset = QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET;
    uint8_t sessionIdLen = data[offset++];
    if ((size_t)sessionIdLen > msgEnd - offset || msgEnd - offset - sessionIdLen < 5u) {
        return false;
    }

    offset += sessionIdLen + 3u; /* session ID, cipher suite, and compression method */
    extensionsLenOffset = offset;
    uint16_t extensionsLen = ((uint16_t)data[offset] << 8) | data[offset + 1u];
    offset += 2u;
    if ((size_t)extensionsLen > msgEnd - offset) {
        return false;
    }
    extensionsEnd = offset + extensionsLen;

    while (offset + 4u <= extensionsEnd) {
        uint16_t extensionType = ((uint16_t)data[offset] << 8) | data[offset + 1u];
        uint16_t extensionLen = ((uint16_t)data[offset + 2u] << 8) | data[offset + 3u];
        size_t encodedExtensionLen = 4u + extensionLen;
        if (encodedExtensionLen > extensionsEnd - offset) {
            return false;
        }
        if (extensionType == HS_EX_TYPE_SUPPORTED_VERSIONS) {
            (void)memmove(data + offset, data + offset + encodedExtensionLen,
                serverHello->len - offset - encodedExtensionLen);
            serverHello->len -= encodedExtensionLen;
            handshakeLen -= (uint32_t)encodedExtensionLen;
            extensionsLen -= (uint16_t)encodedExtensionLen;
            data[1] = (uint8_t)(handshakeLen >> 16);
            data[2] = (uint8_t)(handshakeLen >> 8);
            data[3] = (uint8_t)handshakeLen;
            data[extensionsLenOffset] = (uint8_t)(extensionsLen >> 8);
            data[extensionsLenOffset + 1u] = (uint8_t)extensionsLen;
            data[HS_MSG_HEADER_SIZE] = (uint8_t)(legacyVersion >> 8);
            data[HS_MSG_HEADER_SIZE + 1u] = (uint8_t)legacyVersion;
            return true;
        }
        offset += encodedExtensionLen;
    }
    return false;
}

/* Replace the selected cipher suite in a raw ServerHello while leaving the rest of the message intact. */
static bool QuicTlsTestSetServerHelloCipherSuite(QuicTlsTestBuffer *serverHello, uint16_t cipherSuite)
{
    uint8_t *data;
    uint32_t handshakeLen;
    size_t msgEnd;
    size_t cipherSuiteOffset;
    uint8_t sessionIdLen;
    if (serverHello == NULL || serverHello->data == NULL ||
        serverHello->len <= QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET ||
        serverHello->data[0] != SERVER_HELLO) {
        return false;
    }

    data = serverHello->data;
    handshakeLen = ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
    if (handshakeLen > serverHello->len - 4u) {
        return false;
    }
    msgEnd = 4u + handshakeLen;
    sessionIdLen = data[QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET];
    cipherSuiteOffset = QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET + 1u + sessionIdLen;
    if (cipherSuiteOffset + 2u > msgEnd) {
        return false;
    }
    data[cipherSuiteOffset] = (uint8_t)(cipherSuite >> 8);
    data[cipherSuiteOffset + 1u] = (uint8_t)cipherSuite;
    return true;
}

/* Remove one extension from EncryptedExtensions and repair both enclosing lengths. */
static bool QuicTlsTestOmitEncryptedExtensionsType(QuicTlsTestBuffer *encryptedExtensions,
    uint16_t omittedType)
{
    uint8_t *data;
    uint32_t handshakeLen;
    size_t msgEnd;
    size_t offset;
    size_t extensionsEnd;
    if (encryptedExtensions == NULL || encryptedExtensions->data == NULL ||
        encryptedExtensions->len < 6u || encryptedExtensions->data[0] != ENCRYPTED_EXTENSIONS) {
        return false;
    }

    data = encryptedExtensions->data;
    handshakeLen = ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
    if (handshakeLen > encryptedExtensions->len - 4u) {
        return false;
    }
    msgEnd = 4u + handshakeLen;
    offset = 4u;
    size_t extensionsLenOffset = offset;
    uint16_t extensionsLen = ((uint16_t)data[offset] << 8) | data[offset + 1u];
    offset += 2u;
    if ((size_t)extensionsLen > msgEnd - offset) {
        return false;
    }
    extensionsEnd = offset + extensionsLen;

    while (offset + 4u <= extensionsEnd) {
        uint16_t extensionType = ((uint16_t)data[offset] << 8) | data[offset + 1u];
        uint16_t extensionLen = ((uint16_t)data[offset + 2u] << 8) | data[offset + 3u];
        size_t encodedExtensionLen = 4u + extensionLen;
        if (encodedExtensionLen > extensionsEnd - offset) {
            return false;
        }
        if (extensionType == omittedType) {
            (void)memmove(data + offset, data + offset + encodedExtensionLen,
                encryptedExtensions->len - offset - encodedExtensionLen);
            encryptedExtensions->len -= encodedExtensionLen;
            handshakeLen -= (uint32_t)encodedExtensionLen;
            extensionsLen -= (uint16_t)encodedExtensionLen;
            data[1] = (uint8_t)(handshakeLen >> 16);
            data[2] = (uint8_t)(handshakeLen >> 8);
            data[3] = (uint8_t)handshakeLen;
            data[extensionsLenOffset] = (uint8_t)(extensionsLen >> 8);
            data[extensionsLenOffset + 1u] = (uint8_t)extensionsLen;
            return true;
        }
        offset += encodedExtensionLen;
    }
    return false;
}

/**
 * @test SDV_TLS_QUIC_INTERACTION_VERSION_RANGE_FUNC_TC001
 * @title QUIC narrows mixed TLS configurations to TLS 1.3
 * @precon Each endpoint uses either the generic TLS 1.2-to-1.3 configuration or the TLS 1.3-only configuration
 * @brief Complete a QUIC handshake for each mixed configuration pair requested by the API contract.
 * @expect Every pair negotiates TLS 1.3 while the configured minimum versions remain unchanged.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_VERSION_RANGE_FUNC_TC001(int clientConfigType, int serverConfigType)
{
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    uint16_t clientVersion = 0u;
    uint16_t serverVersion = 0u;
    uint16_t clientMinVersion = 0u;
    uint16_t serverMinVersion = 0u;
    uint16_t expectedClientMin = clientConfigType == QUIC_TEST_CONFIG_TLS ?
        HITLS_VERSION_TLS12 : HITLS_VERSION_TLS13;
    uint16_t expectedServerMin = serverConfigType == QUIC_TEST_CONFIG_TLS ?
        HITLS_VERSION_TLS12 : HITLS_VERSION_TLS13;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNewWithConfigs(&pair, clientConfigType, serverConfigType,
        g_quicTestP256, 1u, g_quicTestP256, 1u, true, true), HITLS_SUCCESS);
    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_SUCCESS);
    ASSERT_EQ(failedSide, QUIC_TEST_SIDE_NONE);
    ASSERT_EQ(HITLS_GetNegotiatedVersion(pair.clientLink->ssl, &clientVersion), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_GetNegotiatedVersion(pair.serverLink->ssl, &serverVersion), HITLS_SUCCESS);
    ASSERT_EQ(clientVersion, HITLS_VERSION_TLS13);
    ASSERT_EQ(serverVersion, HITLS_VERSION_TLS13);

    ASSERT_EQ(HITLS_GetMinProtoVersion(pair.clientLink->ssl, &clientMinVersion), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_GetMinProtoVersion(pair.serverLink->ssl, &serverMinVersion), HITLS_SUCCESS);
    ASSERT_EQ(clientMinVersion, expectedClientMin);
    ASSERT_EQ(serverMinVersion, expectedServerMin);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_VERSION_RANGE_FUNC_TC002
 * @title QUIC rejects ServerHello without supported_versions for every legacy_version value
 * @precon Client and server use QUIC-TLS 1.3
 * @brief Remove supported_versions from ServerHello and replace legacy_version with the requested value.
 * @expect The client reports unsupported version before installing either Handshake traffic secret.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_VERSION_RANGE_FUNC_TC002(int legacyVersion)
{
    QuicTlsTestPair pair = {0};
    int32_t ret;

    FRAME_Init();
    ASSERT_TRUE(legacyVersion >= 0 && legacyVersion <= (int)UINT16_MAX);
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true), HITLS_SUCCESS);

    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.clientEndpoint, pair.serverLink->ssl, SIZE_MAX), HITLS_SUCCESS);
    ret = HITLS_Accept(pair.serverLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_TRUE(QuicTlsTestOmitServerSupportedVersion(
        &pair.serverEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL], (uint16_t)legacyVersion));
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.serverEndpoint, pair.clientLink->ssl, SIZE_MAX), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Connect(pair.clientLink->ssl), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    ASSERT_EQ(pair.clientEndpoint.alertCount, 1u);
    ASSERT_EQ(pair.clientEndpoint.lastAlertLevel, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL);
    ASSERT_EQ(pair.clientEndpoint.lastAlert, ALERT_PROTOCOL_VERSION);
    ASSERT_EQ(pair.clientEndpoint.readSecretCount, 0u);
    ASSERT_EQ(pair.clientEndpoint.writeSecretCount, 0u);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_TLS12_ONLY_FUNC_TC001
 * @title A TLS 1.2-only QUIC configuration has no usable handshake version
 * @precon QUIC method installation accepts stream TLS configurations
 * @brief Put a TLS 1.2-only configuration on one endpoint and TLS 1.3 on the peer.
 * @expect Method installation and connection creation succeed, but the handshake fails on the TLS 1.2-only side.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_TLS12_ONLY_FUNC_TC001(int tls12Side)
{
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    int clientConfigType = tls12Side == QUIC_TEST_SIDE_CLIENT ?
        QUIC_TEST_CONFIG_TLS12 : QUIC_TEST_CONFIG_TLS13;
    int serverConfigType = tls12Side == QUIC_TEST_SIDE_SERVER ?
        QUIC_TEST_CONFIG_TLS12 : QUIC_TEST_CONFIG_TLS13;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNewWithConfigs(&pair, clientConfigType, serverConfigType,
        g_quicTestP256, 1u, g_quicTestP256, 1u, true, true), HITLS_SUCCESS);
    ASSERT_TRUE(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide) != HITLS_SUCCESS);
    ASSERT_EQ(failedSide, (uint32_t)tls12Side);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_UNSUPPORTED_CIPHER_FUNC_TC001
 * @title Reject a TLS 1.3 cipher suite without QUIC header-protection support
 * @precon rejectSide selects server negotiation or client ServerHello validation
 * @brief Rewrite the ClientHello offer for a server configured with the forbidden suite, or rewrite the selected
 *        ServerHello suite before the client consumes it.
 * @expect The selected endpoint rejects the suite before installing traffic secrets; the client path emits
 *         illegal_parameter at the Initial level.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_UNSUPPORTED_CIPHER_FUNC_TC001(int rejectSide)
{
    static const uint16_t unsupportedCipher[] = {HITLS_AES_128_CCM_8_SHA256};
    QuicTlsTestPair pair = {0};
    int32_t ret;

    FRAME_Init();
    ASSERT_TRUE(rejectSide == (int)QUIC_TEST_SIDE_CLIENT || rejectSide == (int)QUIC_TEST_SIDE_SERVER);
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    if (rejectSide == (int)QUIC_TEST_SIDE_SERVER) {
        ASSERT_EQ(HITLS_SetCipherSuites(pair.serverLink->ssl, unsupportedCipher,
            sizeof(unsupportedCipher) / sizeof(unsupportedCipher[0])), HITLS_SUCCESS);
        ret = HITLS_Connect(pair.clientLink->ssl);
        ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
        ASSERT_TRUE(QuicTlsTestSetFirstClientHelloCipherSuite(
            &pair.clientEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL], unsupportedCipher[0]));
        ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.clientEndpoint,
            pair.serverLink->ssl, SIZE_MAX), HITLS_SUCCESS);
        ret = HITLS_Accept(pair.serverLink->ssl);
        ASSERT_TRUE(!QuicTlsTestIsProgressResult(ret));
        ASSERT_EQ(pair.serverEndpoint.readSecretCount, 0u);
        ASSERT_EQ(pair.serverEndpoint.writeSecretCount, 0u);
    } else {
        ret = HITLS_Connect(pair.clientLink->ssl);
        ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
        ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.clientEndpoint,
            pair.serverLink->ssl, SIZE_MAX), HITLS_SUCCESS);
        ret = HITLS_Accept(pair.serverLink->ssl);
        ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
        ASSERT_TRUE(QuicTlsTestSetServerHelloCipherSuite(
            &pair.serverEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL], unsupportedCipher[0]));
        ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.serverEndpoint,
            pair.clientLink->ssl, SIZE_MAX), HITLS_SUCCESS);
        ASSERT_EQ(HITLS_Connect(pair.clientLink->ssl), HITLS_MSG_HANDLE_CIPHER_SUITE_ERR);
        ASSERT_EQ(pair.clientEndpoint.alertCount, 1u);
        ASSERT_EQ(pair.clientEndpoint.lastAlertLevel, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL);
        ASSERT_EQ(pair.clientEndpoint.lastAlert, ALERT_ILLEGAL_PARAMETER);
        ASSERT_EQ(pair.clientEndpoint.readSecretCount, 0u);
        ASSERT_EQ(pair.clientEndpoint.writeSecretCount, 0u);
    }

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_MISSING_PEER_EXTENSION_FUNC_TC001
 * @title Reject mandatory QUIC EncryptedExtensions fields omitted by the server
 * @precon Client and server have emitted a valid TLS 1.3 ServerHello and EncryptedExtensions
 * @brief Remove either the transport-parameters or ALPN extension before the client consumes the message.
 * @expect The client rejects the message at Handshake level with the extension-specific fatal alert.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_MISSING_PEER_EXTENSION_FUNC_TC001(int omittedType)
{
    QuicTlsTestPair pair = {0};
    int32_t expectedRet;
    uint8_t expectedAlert;
    int32_t ret;

    FRAME_Init();
    ASSERT_TRUE(omittedType == (int)HS_EX_TYPE_QUIC_TRANSPORT_PARAMETERS ||
        omittedType == (int)HS_EX_TYPE_APP_LAYER_PROTOCOLS);
    expectedRet = omittedType == (int)HS_EX_TYPE_QUIC_TRANSPORT_PARAMETERS ?
        HITLS_MSG_HANDLE_MISSING_EXTENSION : HITLS_MSG_HANDLE_ALPN_PROTOCOL_NO_MATCH;
    expectedAlert = omittedType == (int)HS_EX_TYPE_QUIC_TRANSPORT_PARAMETERS ?
        ALERT_MISSING_EXTENSION : ALERT_NO_APPLICATION_PROTOCOL;
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true), HITLS_SUCCESS);

    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.clientEndpoint, pair.serverLink->ssl, SIZE_MAX), HITLS_SUCCESS);
    ret = HITLS_Accept(pair.serverLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_TRUE(QuicTlsTestOmitEncryptedExtensionsType(
        &pair.serverEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE], (uint16_t)omittedType));

    /* ServerHello is consumed at Initial first; that installs the Handshake read secret used for the next transfer. */
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.serverEndpoint, pair.clientLink->ssl, SIZE_MAX), HITLS_SUCCESS);
    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_EQ(HITLS_QUIC_TLS_GetReadLevel(pair.clientLink->ssl), HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE);
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.serverEndpoint, pair.clientLink->ssl, SIZE_MAX), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Connect(pair.clientLink->ssl), expectedRet);
    ASSERT_EQ(pair.clientEndpoint.alertCount, 1u);
    ASSERT_EQ(pair.clientEndpoint.lastAlertLevel, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE);
    ASSERT_EQ(pair.clientEndpoint.lastAlert, expectedAlert);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_BASIC_HANDSHAKE_FUNC_TC001
 * @title Complete a QUIC-TLS handshake and validate the transport-facing contract
 * @precon Client and server use TLS 1.3, ALPN h3 and QUIC transport parameters
 * @brief Exchange TLS Handshake bytes through QUIC callbacks with no record-layer UIO traffic.
 * @expect The handshake, transport parameters, traffic secrets, levels and ALPN all agree.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_BASIC_HANDSHAKE_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    uint8_t *clientAlpn = NULL;
    uint8_t *serverAlpn = NULL;
    uint32_t clientAlpnLen = 0u;
    uint32_t serverAlpnLen = 0u;
    uint8_t appData = 0u;
    uint32_t appDataLen = 0u;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_SUCCESS);
    ASSERT_EQ(failedSide, QUIC_TEST_SIDE_NONE);
    ASSERT_TRUE(QuicTlsTestIsDone(pair.clientLink->ssl));
    ASSERT_TRUE(QuicTlsTestIsDone(pair.serverLink->ssl));

    ASSERT_TRUE(QuicTlsTestPeerParamsMatch(pair.clientLink->ssl,
        g_quicTestServerParams, sizeof(g_quicTestServerParams)));
    ASSERT_TRUE(QuicTlsTestPeerParamsMatch(pair.serverLink->ssl,
        g_quicTestClientParams, sizeof(g_quicTestClientParams)));
    ASSERT_TRUE(QuicTlsTestSecretsMatch(&pair.clientEndpoint, &pair.serverEndpoint,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE));
    ASSERT_TRUE(QuicTlsTestSecretsMatch(&pair.serverEndpoint, &pair.clientEndpoint,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE));
    ASSERT_TRUE(QuicTlsTestSecretsMatch(&pair.clientEndpoint, &pair.serverEndpoint,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION));
    ASSERT_TRUE(QuicTlsTestSecretsMatch(&pair.serverEndpoint, &pair.clientEndpoint,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION));
    ASSERT_EQ(pair.clientEndpoint.readSecretCount, 2u);
    ASSERT_EQ(pair.clientEndpoint.writeSecretCount, 2u);
    ASSERT_EQ(pair.serverEndpoint.readSecretCount, 2u);
    ASSERT_EQ(pair.serverEndpoint.writeSecretCount, 2u);
    ASSERT_TRUE(pair.clientEndpoint.flushCount != 0u);
    ASSERT_TRUE(pair.serverEndpoint.flushCount != 0u);
    ASSERT_EQ(pair.clientEndpoint.alertCount, 0u);
    ASSERT_EQ(pair.serverEndpoint.alertCount, 0u);

    ASSERT_EQ(HITLS_QUIC_TLS_GetReadLevel(pair.clientLink->ssl),
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION);
    ASSERT_EQ(HITLS_QUIC_TLS_GetWriteLevel(pair.clientLink->ssl),
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION);
    ASSERT_EQ(HITLS_QUIC_TLS_GetReadLevel(pair.serverLink->ssl),
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION);
    ASSERT_EQ(HITLS_QUIC_TLS_GetWriteLevel(pair.serverLink->ssl),
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION);
    ASSERT_EQ(HITLS_GetSelectedAlpnProto(pair.clientLink->ssl, &clientAlpn, &clientAlpnLen), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_GetSelectedAlpnProto(pair.serverLink->ssl, &serverAlpn, &serverAlpnLen), HITLS_SUCCESS);
    ASSERT_EQ(clientAlpnLen, 2u);
    ASSERT_EQ(serverAlpnLen, 2u);
    ASSERT_TRUE(memcmp(clientAlpn, "h3", 2u) == 0);
    ASSERT_TRUE(memcmp(serverAlpn, "h3", 2u) == 0);

    ASSERT_EQ(HITLS_QUIC_TLS_ProcessPostHandshake(pair.clientLink->ssl), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(pair.clientLink->ssl, &appData, sizeof(appData), &appDataLen), HITLS_CONFIG_UNSUPPORT);
    ASSERT_EQ(HITLS_Write(pair.clientLink->ssl, &appData, sizeof(appData), &appDataLen), HITLS_CONFIG_UNSUPPORT);
    ASSERT_EQ(HITLS_Close(pair.clientLink->ssl), HITLS_CONFIG_UNSUPPORT);
    ASSERT_EQ(HITLS_KeyUpdate(pair.clientLink->ssl, HITLS_UPDATE_NOT_REQUESTED), HITLS_CONFIG_UNSUPPORT);
    ASSERT_EQ(HITLS_VerifyClientPostHandshake(pair.serverLink->ssl), HITLS_CONFIG_UNSUPPORT);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_MUTUAL_AUTH_FUNC_TC001
 * @title Complete a QUIC-TLS handshake with a client certificate
 * @precon Both QUIC endpoints have certificates and the server requests client authentication
 * @brief Start the server far enough to commit its role, validate its Handshake-level input bound, then finish the
 *        mutual-authentication exchange.
 * @expect The server uses one certificate-message bound, the client emits its certificate flight without reinstalling
 *         the Handshake write secret, and both endpoints complete normally.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_MUTUAL_AUTH_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    int32_t ret;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetClientVerifySupport(pair.serverLink->ssl, true), HITLS_SUCCESS);

    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.clientEndpoint,
        pair.serverLink->ssl, SIZE_MAX), HITLS_SUCCESS);
    ret = HITLS_Accept(pair.serverLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_EQ(HITLS_QUIC_TLS_GetMaxHandshakeFlightLen(pair.serverLink->ssl,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE), HITLS_HS_BUFFER_SIZE_LIMIT);

    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_SUCCESS);
    ASSERT_EQ(failedSide, QUIC_TEST_SIDE_NONE);
    ASSERT_TRUE(QuicTlsTestIsDone(pair.clientLink->ssl));
    ASSERT_TRUE(QuicTlsTestIsDone(pair.serverLink->ssl));
    ASSERT_TRUE(pair.clientEndpoint.addDataCount[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE] >= 3u);
    ASSERT_EQ(pair.clientEndpoint.writeSecretCount, 2u);
    ASSERT_EQ(pair.serverEndpoint.readSecretCount, 2u);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_FRAGMENTED_CRYPTO_FUNC_TC001
 * @title Reassemble fragmented QUIC CRYPTO streams during and after the handshake
 * @precon A normal QUIC-TLS client/server pair exists
 * @brief Deliver handshake flights in seven-byte chunks and NewSessionTicket in one-byte chunks.
 * @expect Partial messages return WANT-data semantics and the complete handshake/post-handshake flow succeeds.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_FRAGMENTED_CRYPTO_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    int32_t ret;
    bool sawIncomplete = false;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, 7u, &failedSide), HITLS_SUCCESS);
    ASSERT_EQ(failedSide, QUIC_TEST_SIDE_NONE);

    ret = HITLS_QUIC_TLS_ProcessPostHandshake(pair.clientLink->ssl);
    if (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
        sawIncomplete = true;
    }
    ASSERT_TRUE(ret == HITLS_SUCCESS || ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    while (pair.serverEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION].len != 0u) {
        ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.serverEndpoint, pair.clientLink->ssl, 1u), HITLS_SUCCESS);
        ret = HITLS_QUIC_TLS_ProcessPostHandshake(pair.clientLink->ssl);
        if (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
            sawIncomplete = true;
        }
        ASSERT_TRUE(ret == HITLS_SUCCESS || ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    }
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_TRUE(sawIncomplete);
    ASSERT_EQ(pair.clientEndpoint.alertCount, 0u);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_TP_IN_CALLBACK_FUNC_TC001
 * @title Set server transport parameters from the Handshake write-secret callback
 * @precon The client has configured transport parameters; the server has not
 * @brief Configure server parameters at the callback point immediately before EncryptedExtensions is emitted.
 * @expect The callback succeeds and the client receives the configured value.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_TP_IN_CALLBACK_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, false),
        HITLS_SUCCESS);
    pair.serverEndpoint.setTransportParamsInCallback = true;
    pair.serverEndpoint.callbackTransportParams = g_quicTestServerParams;
    pair.serverEndpoint.callbackTransportParamsLen = sizeof(g_quicTestServerParams);

    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_SUCCESS);
    ASSERT_EQ(failedSide, QUIC_TEST_SIDE_NONE);
    ASSERT_TRUE(pair.serverEndpoint.transportParamsSetInCallback);
    ASSERT_EQ(pair.serverEndpoint.transportParamsCallbackRet, HITLS_SUCCESS);
    ASSERT_TRUE(QuicTlsTestPeerParamsMatch(pair.clientLink->ssl,
        g_quicTestServerParams, sizeof(g_quicTestServerParams)));

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_HRR_TP_STABLE_FUNC_TC001
 * @title Preserve transport parameters across a QUIC HelloRetryRequest
 * @precon The client initially offers P-256 while the server only accepts P-384
 * @brief Trigger HRR, retain the first ClientHello parameters, and complete with the second ClientHello.
 * @expect CH2 repeats identical parameters and the borrowed peer-parameter pointer remains stable.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_HRR_TP_STABLE_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    const uint8_t *paramsBefore = NULL;
    const uint8_t *paramsAfter = NULL;
    size_t paramsBeforeLen = 0u;
    size_t paramsAfterLen = 0u;
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    int32_t ret;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256P384, 2u, g_quicTestP384, 1u, true, true),
        HITLS_SUCCESS);
    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.clientEndpoint, pair.serverLink->ssl, SIZE_MAX), HITLS_SUCCESS);
    ret = HITLS_Accept(pair.serverLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_EQ(HITLS_QUIC_TLS_GetPeerTransportParams(pair.serverLink->ssl,
        &paramsBefore, &paramsBeforeLen), HITLS_SUCCESS);
    ASSERT_TRUE(paramsBefore != NULL);
    ASSERT_EQ(paramsBeforeLen, sizeof(g_quicTestClientParams));
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.serverEndpoint, pair.clientLink->ssl, SIZE_MAX), HITLS_SUCCESS);

    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_SUCCESS);
    ASSERT_EQ(failedSide, QUIC_TEST_SIDE_NONE);
    ASSERT_EQ(pair.clientEndpoint.initialFlightCount, 2u);
    ASSERT_EQ(HITLS_QUIC_TLS_GetPeerTransportParams(pair.serverLink->ssl,
        &paramsAfter, &paramsAfterLen), HITLS_SUCCESS);
    ASSERT_TRUE(paramsAfter == paramsBefore);
    ASSERT_EQ(paramsAfterLen, paramsBeforeLen);
    ASSERT_TRUE(memcmp(paramsAfter, g_quicTestClientParams, paramsAfterLen) == 0);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_HRR_TP_CHANGED_FUNC_TC001
 * @title Reject changed QUIC transport parameters in the second ClientHello
 * @precon The connection is configured to trigger HelloRetryRequest
 * @brief Mutate the transport-parameter value in CH2 while leaving CH1 untouched.
 * @expect The server aborts with illegal_parameter and reports a handshake failure.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_HRR_TP_CHANGED_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256P384, 2u, g_quicTestP384, 1u, true, true),
        HITLS_SUCCESS);
    pair.clientEndpoint.transportParamsMutation = QUIC_TEST_TP_MUTATION_CHANGE_SECOND_CH;

    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_MSG_HANDLE_HANDSHAKE_FAILURE);
    ASSERT_EQ(failedSide, QUIC_TEST_SIDE_SERVER);
    ASSERT_TRUE(pair.clientEndpoint.transportParamsMutationDone);
    ASSERT_EQ(pair.serverEndpoint.alertCount, 1u);
    ASSERT_EQ(pair.serverEndpoint.lastAlert, ALERT_ILLEGAL_PARAMETER);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_HRR_TP_MISSING_FUNC_TC001
 * @title Reject missing QUIC transport parameters in the second ClientHello
 * @precon The connection is configured to trigger HelloRetryRequest
 * @brief Replace the CH2 transport-parameter extension type so that the required extension is absent.
 * @expect The server aborts with missing_extension as required by RFC 9001 Section 8.2.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_HRR_TP_MISSING_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256P384, 2u, g_quicTestP384, 1u, true, true),
        HITLS_SUCCESS);
    pair.clientEndpoint.transportParamsMutation = QUIC_TEST_TP_MUTATION_OMIT_SECOND_CH;

    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_MSG_HANDLE_MISSING_EXTENSION);
    ASSERT_EQ(failedSide, QUIC_TEST_SIDE_SERVER);
    ASSERT_TRUE(pair.clientEndpoint.transportParamsMutationDone);
    ASSERT_EQ(pair.serverEndpoint.alertCount, 1u);
    ASSERT_EQ(pair.serverEndpoint.lastAlert, ALERT_MISSING_EXTENSION);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_LEGACY_SESSION_ID_FUNC_TC001
 * @title Enforce the QUIC ClientHello legacy_session_id rule
 * @precon injectSessionId is zero for a normal ClientHello and one for a tampered ClientHello
 * @brief Inspect the emitted ClientHello and optionally inject a one-byte legacy session ID.
 * @expect QUIC emits an empty ID; a peer-provided non-empty ID is reported as PROTOCOL_VIOLATION.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_LEGACY_SESSION_ID_FUNC_TC001(int injectSessionId)
{
    QuicTlsTestPair pair = {0};
    QuicTlsTestBuffer *clientHello;
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    int32_t ret;

    FRAME_Init();
    ASSERT_TRUE(injectSessionId == 0 || injectSessionId == 1);
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    clientHello = &pair.clientEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL];
    ASSERT_TRUE(clientHello->len > QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET);
    ASSERT_EQ(clientHello->data[QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET], 0u);
    if (injectSessionId != 0) {
        ASSERT_TRUE(QuicTlsTestInjectLegacySessionId(clientHello));
        ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_QUIC_TLS_PROTOCOL_VIOLATION);
        ASSERT_EQ(failedSide, QUIC_TEST_SIDE_SERVER);
        ASSERT_EQ(pair.serverEndpoint.alertCount, 0u);
    } else {
        ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_SUCCESS);
        ASSERT_EQ(failedSide, QUIC_TEST_SIDE_NONE);
    }

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_LEGACY_SESSION_ID_FUNC_TC002
 * @title Ignore a cached TLS 1.2 session ID when building a QUIC ClientHello
 * @precon A QUIC client has a valid TLS 1.2 session with a non-empty session ID
 * @brief Attach the legacy session, start the QUIC handshake and inspect the emitted ClientHello.
 * @expect The QUIC ClientHello legacy_session_id remains empty.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_LEGACY_SESSION_ID_FUNC_TC002(void)
{
    static uint8_t sessionId[] = {0x11u, 0x22u, 0x33u, 0x44u};
    QuicTlsTestPair pair = {0};
    QuicTlsTestBuffer *clientHello;
    HITLS_Session *legacySession = NULL;
    int32_t ret;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    legacySession = HITLS_SESS_New();
    ASSERT_TRUE(legacySession != NULL);
    ASSERT_EQ(HITLS_SESS_SetProtocolVersion(legacySession, HITLS_VERSION_TLS12), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SESS_SetSessionId(legacySession, sessionId, sizeof(sessionId)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SESS_SetTimeout(legacySession, 3600u), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetSession(pair.clientLink->ssl, legacySession), HITLS_SUCCESS);
    HITLS_SESS_Free(legacySession);
    legacySession = NULL;

    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    clientHello = &pair.clientEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL];
    ASSERT_TRUE(clientHello->len > QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET);
    ASSERT_EQ(clientHello->data[QUIC_TEST_HELLO_SESSION_ID_LEN_OFFSET], 0u);

EXIT:
    HITLS_SESS_Free(legacySession);
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_PHA_DISABLED_FUNC_TC001
 * @title Keep post-handshake authentication disabled in QUIC mode
 * @precon A QUIC client is idle
 * @brief Reject the public PHA setter, then force the copied flag on to exercise ClientHello packing defensively.
 * @expect Enabling PHA is unsupported and ClientHello does not contain post_handshake_auth.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_PHA_DISABLED_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    QuicTlsTestBuffer *clientHello;
    TLS_Ctx *clientCtx;
    bool phaSupport = true;
    bool hasPhaExtension = true;
    int32_t ret;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    ASSERT_EQ(HITLS_GetPostHandshakeAuthSupport(pair.clientLink->ssl, &phaSupport), HITLS_SUCCESS);
    ASSERT_TRUE(!phaSupport);
    ASSERT_EQ(HITLS_SetPostHandshakeAuthSupport(pair.clientLink->ssl, true), HITLS_CONFIG_UNSUPPORT);

    clientCtx = (TLS_Ctx *)pair.clientLink->ssl;
    clientCtx->config.tlsConfig.isSupportPostHandshakeAuth = true;
    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    clientHello = &pair.clientEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL];
    ASSERT_TRUE(QuicTlsTestClientHelloHasExtension(clientHello,
        HS_EX_TYPE_POST_HS_AUTH, &hasPhaExtension));
    ASSERT_TRUE(!hasPhaExtension);
    ASSERT_EQ(clientCtx->phaState, PHA_NONE);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_HALF_RTT_KEYS_FUNC_TC001
 * @title Validate server half-RTT key availability during a QUIC-TLS handshake
 * @precon A normal QUIC-TLS pair exists
 * @brief Pause after the server sends its first flight, before the client Finished is delivered.
 * @expect The server has Application write keys but not Application read keys until handshake completion.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_HALF_RTT_KEYS_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    int32_t ret;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.clientEndpoint, pair.serverLink->ssl, SIZE_MAX), HITLS_SUCCESS);
    ret = HITLS_Accept(pair.serverLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_TRUE(pair.serverEndpoint.writeSecretLen[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION] != 0u);
    ASSERT_EQ(pair.serverEndpoint.readSecretLen[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION], 0u);
    ASSERT_EQ(pair.serverEndpoint.writeSecretCount, 2u);
    ASSERT_EQ(pair.serverEndpoint.readSecretCount, 1u);

    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_SUCCESS);
    ASSERT_EQ(failedSide, QUIC_TEST_SIDE_NONE);
    ASSERT_TRUE(pair.serverEndpoint.readSecretLen[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION] != 0u);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_EXCESS_INITIAL_DATA_FUNC_TC001
 * @title Reject Handshake-level bytes coalesced into an Initial-level CRYPTO delivery
 * @precon The server has emitted ServerHello at Initial and the rest of its flight at Handshake level
 * @brief Concatenate both encryption-level outputs and provide them to the client as Initial data.
 * @expect The key-level transition detects leftover old-level data and reports PROTOCOL_VIOLATION.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_EXCESS_INITIAL_DATA_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    QuicTlsTestBuffer *initial;
    QuicTlsTestBuffer *handshake;
    uint8_t *combined = NULL;
    size_t combinedLen;
    int32_t ret;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.clientEndpoint, pair.serverLink->ssl, SIZE_MAX), HITLS_SUCCESS);
    ret = HITLS_Accept(pair.serverLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));

    initial = &pair.serverEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL];
    handshake = &pair.serverEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE];
    ASSERT_TRUE(initial->len != 0u);
    ASSERT_TRUE(handshake->len != 0u);
    combinedLen = initial->len + handshake->len;
    combined = (uint8_t *)malloc(combinedLen);
    ASSERT_TRUE(combined != NULL);
    (void)memcpy(combined, initial->data, initial->len);
    (void)memcpy(combined + initial->len, handshake->data, handshake->len);
    initial->len = 0u;
    handshake->len = 0u;
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(pair.clientLink->ssl,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL, combined, combinedLen), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(pair.clientLink->ssl), HITLS_QUIC_TLS_PROTOCOL_VIOLATION);
    ASSERT_EQ(pair.clientEndpoint.readSecretLen[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE], 0u);
    ASSERT_TRUE(!QuicTlsTestIsDone(pair.clientLink->ssl));
    ASSERT_EQ(pair.clientEndpoint.alertCount, 0u);

EXIT:
    free(combined);
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_MISSING_LOCAL_TP_FUNC_TC001
 * @title Reject a QUIC endpoint that omitted its local transport parameters
 * @precon missingSide selects the client (1) or server (2)
 * @brief Start a handshake without calling SetTransportParams on one endpoint.
 * @expect The endpoint fails before emitting the mandatory transport-parameters extension.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_MISSING_LOCAL_TP_FUNC_TC001(int missingSide)
{
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    bool setClientParams = missingSide != (int)QUIC_TEST_SIDE_CLIENT;
    bool setServerParams = missingSide != (int)QUIC_TEST_SIDE_SERVER;

    FRAME_Init();
    ASSERT_TRUE(missingSide == (int)QUIC_TEST_SIDE_CLIENT || missingSide == (int)QUIC_TEST_SIDE_SERVER);
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u,
        setClientParams, setServerParams), HITLS_SUCCESS);
    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_CONFIG_INVALID_SET);
    ASSERT_EQ(failedSide, (uint32_t)missingSide);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_ZERO_LENGTH_LOCAL_TP_FUNC_TC001
 * @title Reject zero-length local QUIC transport parameters
 * @precon Both endpoints have QUIC methods installed
 * @brief Try both NULL/zero and non-NULL/zero setters, then start the handshake.
 * @expect Both setters fail and the unconfigured client cannot emit its mandatory extension.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_ZERO_LENGTH_LOCAL_TP_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    uint8_t value = 1u;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, false, false),
        HITLS_SUCCESS);
    ASSERT_EQ(HITLS_QUIC_TLS_SetTransportParams(pair.clientLink->ssl, NULL, 0u), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_QUIC_TLS_SetTransportParams(pair.serverLink->ssl, &value, 0u), HITLS_INVALID_INPUT);
    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_CONFIG_INVALID_SET);
    ASSERT_EQ(failedSide, QUIC_TEST_SIDE_CLIENT);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_BAD_POST_HANDSHAKE_FUNC_TC001
 * @title Reject malformed QUIC post-handshake CRYPTO data
 * @precon A QUIC-TLS handshake has completed
 * @brief Process valid pending tickets followed by an invalid post-handshake message.
 * @expect Processing fails and a TLS alert is delivered through the QUIC alert callback.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_BAD_POST_HANDSHAKE_FUNC_TC001(void)
{
    static const uint8_t junk[] = {0x17u, 0x00u, 0x00u, 0x04u, 0x0bu, 0x0eu, 0x0eu, 0x0fu};
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    int32_t ret;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_SUCCESS);
    while (pair.serverEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION].len != 0u) {
        ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.serverEndpoint, pair.clientLink->ssl, SIZE_MAX), HITLS_SUCCESS);
    }
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(pair.clientLink->ssl,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION, junk, sizeof(junk)), HITLS_SUCCESS);
    ret = HITLS_QUIC_TLS_ProcessPostHandshake(pair.clientLink->ssl);
    ASSERT_TRUE(ret != HITLS_SUCCESS && ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(pair.clientEndpoint.alertCount != 0u);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_FORBIDDEN_POST_HANDSHAKE_FUNC_TC001
 * @title Reject TLS KeyUpdate and post-handshake authentication over QUIC
 * @precon messageType is KEY_UPDATE or CERTIFICATE_REQUEST
 * @brief Deliver a syntactically complete forbidden message on the Application CRYPTO stream.
 * @expect Both report unexpected_message through sendAlert; PHA returns PROTOCOL_VIOLATION with higher priority.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_FORBIDDEN_POST_HANDSHAKE_FUNC_TC001(int messageType)
{
    static const uint8_t keyUpdate[] = {KEY_UPDATE, 0u, 0u, 1u, 0u};
    static const uint8_t certificateRequest[] = {CERTIFICATE_REQUEST, 0u, 0u, 3u, 0u, 0u, 0u};
    QuicTlsTestPair pair = {0};
    const uint8_t *message;
    size_t messageLen;
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    int32_t ret;

    FRAME_Init();
    ASSERT_TRUE(messageType == KEY_UPDATE || messageType == CERTIFICATE_REQUEST);
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_SUCCESS);
    while (pair.serverEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION].len != 0u) {
        ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.serverEndpoint, pair.clientLink->ssl, SIZE_MAX), HITLS_SUCCESS);
    }
    ASSERT_EQ(HITLS_QUIC_TLS_ProcessPostHandshake(pair.clientLink->ssl), HITLS_SUCCESS);
    if (messageType == KEY_UPDATE) {
        message = keyUpdate;
        messageLen = sizeof(keyUpdate);
    } else {
        message = certificateRequest;
        messageLen = sizeof(certificateRequest);
    }
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(pair.clientLink->ssl,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION, message, messageLen), HITLS_SUCCESS);
    ret = HITLS_QUIC_TLS_ProcessPostHandshake(pair.clientLink->ssl);
    if (messageType == KEY_UPDATE) {
        ASSERT_EQ(ret, HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
    } else {
        ASSERT_EQ(ret, HITLS_QUIC_TLS_PROTOCOL_VIOLATION);
    }
    ASSERT_EQ(pair.clientEndpoint.alertCount, 1u);
    ASSERT_EQ(pair.clientEndpoint.lastAlert, ALERT_UNEXPECTED_MESSAGE);
    ASSERT_EQ(HITLS_QUIC_TLS_ProcessPostHandshake(pair.clientLink->ssl), HITLS_MSG_HANDLE_STATE_ILLEGAL);
    ASSERT_EQ(pair.clientEndpoint.alertCount, 1u);
    if (messageType == CERTIFICATE_REQUEST) {
        /* RFC 9001 s4.4 mandates PROTOCOL_VIOLATION only for clients; a server
         * receiving a post-handshake CertificateRequest takes the generic
         * unexpected_message alert path (CRYPTO_ERROR 0x010a). */
        while (pair.clientEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION].len != 0u) {
            ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.clientEndpoint, pair.serverLink->ssl, SIZE_MAX),
                HITLS_SUCCESS);
        }
        ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(pair.serverLink->ssl,
            HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION, message, messageLen), HITLS_SUCCESS);
        ASSERT_EQ(HITLS_QUIC_TLS_ProcessPostHandshake(pair.serverLink->ssl),
            HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
        ASSERT_EQ(pair.serverEndpoint.alertCount, 1u);
        ASSERT_EQ(pair.serverEndpoint.lastAlert, ALERT_UNEXPECTED_MESSAGE);
    }

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_FORBIDDEN_POST_HANDSHAKE_FUNC_TC002
 * @title Fragmented CertificateRequest reports an alert and authoritative PROTOCOL_VIOLATION
 * @precon A completed QUIC handshake on the client
 * @brief Deliver only the 4-byte handshake header of a CertificateRequest (declared body
 *        length 3, body missing) on the Application CRYPTO stream.
 * @expect sendAlert reports unexpected_message once, ProcessPostHandshake returns
 *         HITLS_QUIC_TLS_PROTOCOL_VIOLATION, and later calls fail the terminal-state check.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_FORBIDDEN_POST_HANDSHAKE_FUNC_TC002(void)
{
    static const uint8_t fragmentedCertReq[] = {CERTIFICATE_REQUEST, 0u, 0u, 3u};
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_SUCCESS);
    while (pair.serverEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION].len != 0u) {
        ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.serverEndpoint, pair.clientLink->ssl, SIZE_MAX), HITLS_SUCCESS);
    }
    ASSERT_EQ(HITLS_QUIC_TLS_ProcessPostHandshake(pair.clientLink->ssl), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(pair.clientLink->ssl,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION, fragmentedCertReq, sizeof(fragmentedCertReq)),
        HITLS_SUCCESS);
    ASSERT_EQ(HITLS_QUIC_TLS_ProcessPostHandshake(pair.clientLink->ssl),
        HITLS_QUIC_TLS_PROTOCOL_VIOLATION);
    ASSERT_EQ(pair.clientEndpoint.alertCount, 1u);
    ASSERT_EQ(pair.clientEndpoint.lastAlert, ALERT_UNEXPECTED_MESSAGE);
    ASSERT_EQ(HITLS_QUIC_TLS_ProcessPostHandshake(pair.clientLink->ssl), HITLS_MSG_HANDLE_STATE_ILLEGAL);
    ASSERT_EQ(pair.clientEndpoint.alertCount, 1u);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_CALLBACK_FAILURE_FUNC_TC001
 * @title Propagate a QUIC traffic-secret callback failure through handshake processing
 * @precon A server QUIC method is configured to fail setWriteSecret
 * @brief Drive the handshake until Handshake keys are installed.
 * @expect The server handshake fails and does not continue with an uninstalled traffic secret.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_CALLBACK_FAILURE_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    int32_t ret;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    pair.serverEndpoint.failCallbackId = HITLS_QUIC_TLS_FUNC_SET_WRITE_SECRET;
    ret = QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide);
    ASSERT_TRUE(!QuicTlsTestIsProgressResult(ret));
    ASSERT_EQ(failedSide, QUIC_TEST_SIDE_SERVER);
    ASSERT_EQ(pair.serverEndpoint.writeSecretCount, 0u);
    ASSERT_TRUE(!QuicTlsTestIsDone(pair.serverLink->ssl));

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_CALLBACK_FAILURE_FUNC_TC002
 * @title Propagate failures from each handshake-progress callback on either endpoint
 * @precon callbackId selects a secret, add-data or flush callback and failingSide selects the endpoint
 * @brief Arm one callback failure and drive the in-memory QUIC handshake until that callback is reached.
 * @expect The handshake returns HITLS_REC_CB_FAIL on the armed endpoint and never completes there.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_CALLBACK_FAILURE_FUNC_TC002(int callbackId, int failingSide)
{
    QuicTlsTestPair pair = {0};
    QuicTlsTestEndpoint *failingEndpoint = NULL;
    HITLS_Ctx *failingCtx = NULL;
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;

    FRAME_Init();
    ASSERT_TRUE(callbackId >= HITLS_QUIC_TLS_FUNC_SET_READ_SECRET &&
        callbackId <= HITLS_QUIC_TLS_FUNC_FLUSH_FLIGHT);
    ASSERT_TRUE(failingSide == (int)QUIC_TEST_SIDE_CLIENT || failingSide == (int)QUIC_TEST_SIDE_SERVER);
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    if (failingSide == (int)QUIC_TEST_SIDE_CLIENT) {
        failingEndpoint = &pair.clientEndpoint;
        failingCtx = pair.clientLink->ssl;
    } else {
        failingEndpoint = &pair.serverEndpoint;
        failingCtx = pair.serverLink->ssl;
    }
    failingEndpoint->failCallbackId = (uint32_t)callbackId;

    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_REC_CB_FAIL);
    ASSERT_EQ(failedSide, (uint32_t)failingSide);
    ASSERT_TRUE(!QuicTlsTestIsDone(failingCtx));

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_CALLBACK_FAILURE_FUNC_TC003
 * @title Propagate a failed QUIC alert callback
 * @precon A client callback is configured to fail and ServerHello is made version-invalid
 * @brief Remove supported_versions so TLS emits a fatal protocol_version alert through the failing callback.
 * @expect The callback is invoked once and the handshake reports HITLS_REC_CB_FAIL instead of hiding the transport
 *         integration failure.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_CALLBACK_FAILURE_FUNC_TC003(void)
{
    QuicTlsTestPair pair = {0};
    int32_t ret;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    pair.clientEndpoint.failCallbackId = HITLS_QUIC_TLS_FUNC_SEND_ALERT;
    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.clientEndpoint,
        pair.serverLink->ssl, SIZE_MAX), HITLS_SUCCESS);
    ret = HITLS_Accept(pair.serverLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_TRUE(QuicTlsTestOmitServerSupportedVersion(
        &pair.serverEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL], HITLS_VERSION_TLS13));
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.serverEndpoint,
        pair.clientLink->ssl, SIZE_MAX), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Connect(pair.clientLink->ssl), HITLS_REC_CB_FAIL);
    ASSERT_EQ(pair.clientEndpoint.alertCount, 1u);
    ASSERT_EQ(pair.clientEndpoint.lastAlertLevel, HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL);
    ASSERT_EQ(pair.clientEndpoint.lastAlert, ALERT_PROTOCOL_VERSION);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_BIG_ENCRYPTED_EXTENSIONS_FUNC_TC001
 * @title Reassemble an EncryptedExtensions enlarged beyond one record by oversized server transport parameters
 * @precon The server sends oversized opaque QUIC transport parameters (a rising byte pattern)
 * @brief Size the transport parameters so the server EncryptedExtensions spans multiple TLS records
 *        (beyond the 16 KB record size) and deliver the flight in 300-byte ProvideData chunks.
 * @expect The handshake completes, both endpoints reach the application level, and the client
 *         receives the transport parameters unchanged (pattern detects mis-ordered reassembly).
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_BIG_ENCRYPTED_EXTENSIONS_FUNC_TC001(void)
{
    /* The server transport parameters are the one field that can drive the
     * EncryptedExtensions over the 16 KB record size, so the client must
     * reassemble the message from several TLS records. */
    static uint8_t bigParams[18 * 1024u];
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    uint32_t i;
    const uint8_t *peerParams = NULL;
    size_t peerParamsLen = 0u;

    FRAME_Init();
    /* A rising pattern so that a mis-ordered or offset reassembly shows up in the comparison. */
    for (i = 0u; i < sizeof(bigParams); ++i) {
        bigParams[i] = (uint8_t)i;
    }

    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, false),
        HITLS_SUCCESS);
    ASSERT_EQ(HITLS_QUIC_TLS_SetTransportParams(pair.serverLink->ssl, bigParams, sizeof(bigParams)),
        HITLS_SUCCESS);
    /* One Handshake-level flight chunk is a QUIC packet-sized fraction of the enlarged extensions. */
    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, 300u, &failedSide), HITLS_SUCCESS);
    ASSERT_EQ(failedSide, QUIC_TEST_SIDE_NONE);

    ASSERT_TRUE(QuicTlsTestIsDone(pair.clientLink->ssl));
    ASSERT_TRUE(QuicTlsTestIsDone(pair.serverLink->ssl));
    ASSERT_EQ(HITLS_QUIC_TLS_GetPeerTransportParams(pair.clientLink->ssl, &peerParams, &peerParamsLen),
        HITLS_SUCCESS);
    ASSERT_EQ(peerParamsLen, sizeof(bigParams));
    ASSERT_TRUE(peerParams != NULL);
    ASSERT_EQ(memcmp(peerParams, bigParams, sizeof(bigParams)), 0);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_EARLY_HS_SECRET_FUNC_TC001
 * @title Handshake secrets are installed before the peer flight needs them
 * @precon A QUIC pair driven stepwise through ServerHello
 * @brief After the server emits its flight, assert the client-handshake READ secret is
 *        already installed on the server; after the client processes ServerHello (before any
 *        EE/Certificate data is delivered), assert the handshake WRITE secret is already
 *        installed on the client; then complete the handshake.
 * @expect Both early installs hold: the QUIC stack can send/decrypt handshake-level ACKs
 *         during a large peer flight (late write/read installs stall flights larger than the
 *         initial congestion window). The handshake still completes normally.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_EARLY_HS_SECRET_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    int32_t ret;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    /* Step 1: client produces ClientHello at INITIAL. */
    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.clientEndpoint, pair.serverLink->ssl, SIZE_MAX),
        HITLS_SUCCESS);
    /* Step 2: server consumes CH and emits ServerHello (INITIAL) plus the
     * EE flight (HANDSHAKE).  The client-handshake READ secret must be
     * installed by now so the QUIC stack can decrypt client ACKs arriving
     * while the flight is still being sent. */
    ret = HITLS_Accept(pair.serverLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_TRUE(pair.serverEndpoint.readSecretLen[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE] != 0u);
    /* Step 3: deliver only ServerHello; the client installs BOTH handshake
     * secrets while processing it, before any handshake-level flight data
     * (EE..Finished) has arrived. */
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.serverEndpoint, pair.clientLink->ssl, SIZE_MAX),
        HITLS_SUCCESS);
    ret = HITLS_Connect(pair.clientLink->ssl);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    ASSERT_TRUE(pair.clientEndpoint.writeSecretLen[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE] != 0u);
    /* Step 4: the handshake must still complete normally. */
    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_SUCCESS);
    ASSERT_EQ(failedSide, QUIC_TEST_SIDE_NONE);
    ASSERT_TRUE(QuicTlsTestIsDone(pair.clientLink->ssl));
    ASSERT_TRUE(QuicTlsTestIsDone(pair.serverLink->ssl));

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_BUFFER_LIMIT_FUNC_TC001
 * @title Reject CRYPTO input beyond the per-level buffered limit
 * @precon A client QUIC connection with an empty input buffer
 * @brief Provide more than HITLS_QUIC_TLS_GetMaxHandshakeFlightLen bytes in one Initial-level delivery.
 * @expect ProvideData fails with HITLS_REC_RECORD_OVERFLOW and no byte is buffered.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_BUFFER_LIMIT_FUNC_TC001(void)
{
    QuicTlsTestPair pair = {0};
    size_t limit;
    uint8_t *filler = NULL;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    limit = HITLS_QUIC_TLS_GetMaxHandshakeFlightLen(pair.clientLink->ssl,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL);
    ASSERT_TRUE(limit != 0u);
    filler = (uint8_t *)malloc(limit + 1u);
    ASSERT_TRUE(filler != NULL);
    memset(filler, 0, limit + 1u);
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(pair.clientLink->ssl,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL, filler, limit + 1u),
        HITLS_REC_RECORD_OVERFLOW);

EXIT:
    free(filler);
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

/**
 * @test SDV_TLS_QUIC_INTERACTION_SET_PARAMS_MID_NST_FUNC_TC001
 * @title Reject SetTransportParams while a fragmented post-handshake NST is pending
 * @precon A completed QUIC handshake on the client
 * @brief Deliver a truncated NewSessionTicket on the Application CRYPTO stream so the
 *        client parks in re-entrant HANDSHAKING (preState TRANSPORTING) awaiting the rest,
 *        then call HITLS_QUIC_TLS_SetTransportParams.
 * @expect ProcessPostHandshake reports BUF_EMPTY and SetTransportParams fails with
 *         HITLS_MSG_HANDLE_STATE_ILLEGAL: the CH/EE flights are gone, so new params could
 *         never be transmitted.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_INTERACTION_SET_PARAMS_MID_NST_FUNC_TC001(void)
{
    static const uint8_t truncatedNst[] = {4u, 0u, 0u, 8u, 0u, 0u};
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;

    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, g_quicTestP256, 1u, g_quicTestP256, 1u, true, true),
        HITLS_SUCCESS);
    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, SIZE_MAX, &failedSide), HITLS_SUCCESS);
    while (pair.serverEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION].len != 0u) {
        ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.serverEndpoint, pair.clientLink->ssl, SIZE_MAX), HITLS_SUCCESS);
    }
    ASSERT_EQ(HITLS_QUIC_TLS_ProcessPostHandshake(pair.clientLink->ssl), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_QUIC_TLS_ProvideData(pair.clientLink->ssl,
        HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION, truncatedNst, sizeof(truncatedNst)),
        HITLS_SUCCESS);
    /* The incomplete NST parks the client in re-entrant HANDSHAKING, asking for more data. */
    ASSERT_EQ(HITLS_QUIC_TLS_ProcessPostHandshake(pair.clientLink->ssl),
        HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(HITLS_QUIC_TLS_SetTransportParams(pair.clientLink->ssl,
        g_quicTestClientParams, sizeof(g_quicTestClientParams)),
        HITLS_MSG_HANDLE_STATE_ILLEGAL);

EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

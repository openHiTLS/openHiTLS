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
#include "bsl_bytes.h"
#include "hitls_psk.h"
#include "hitls_session.h"
#include "alert.h"
#include "hs_extensions.h"
#include "hs_msg.h"
#include "parser_frame_msg.h"
#include "tls.h"
/* END_HEADER */

static const uint8_t g_certPskIdentity[] = "quic-rfc9973";
static const uint8_t g_certPskKey[32] = {1, 2, 3, 4, 5, 6, 7, 8};
static uint16_t g_certPskCipher;
static bool g_certPskMismatch;

static HITLS_Session *QuicCertPskSession(bool server)
{
    HITLS_Session *session = HITLS_SESS_New();
    uint8_t key[sizeof(g_certPskKey)];
    memcpy(key, g_certPskKey, sizeof(key));
    if (server && g_certPskMismatch) {
        key[0] ^= 1;
    }
    if (session != NULL && (HITLS_SESS_SetProtocolVersion(session, HITLS_VERSION_TLS13) != HITLS_SUCCESS ||
                            HITLS_SESS_SetCipherSuite(session, g_certPskCipher) != HITLS_SUCCESS ||
                            HITLS_SESS_SetMasterKey(session, key, sizeof(key)) != HITLS_SUCCESS)) {
        HITLS_SESS_Free(session);
        session = NULL;
    }
    BSL_SAL_CleanseData(key, sizeof(key));
    return session;
}

static int32_t QuicCertPskUse(HITLS_Ctx *ctx, uint32_t hash, const uint8_t **id, uint32_t *idLen,
                              HITLS_Session **session)
{
    (void)ctx;
    (void)hash;
    *id = g_certPskIdentity;
    *idLen = sizeof(g_certPskIdentity) - 1;
    *session = QuicCertPskSession(false);
    return *session == NULL ? HITLS_PSK_USE_SESSION_CB_FAIL : HITLS_PSK_USE_SESSION_CB_SUCCESS;
}

static int32_t QuicCertPskFind(HITLS_Ctx *ctx, const uint8_t *id, uint32_t idLen, HITLS_Session **session)
{
    (void)ctx;
    *session = NULL;
    if (idLen == sizeof(g_certPskIdentity) - 1 && memcmp(id, g_certPskIdentity, idLen) == 0) {
        *session = QuicCertPskSession(true);
        if (*session == NULL) {
            return HITLS_PSK_FIND_SESSION_CB_FAIL;
        }
    }
    return HITLS_PSK_FIND_SESSION_CB_SUCCESS;
}

static void QuicCertPskCheckHello(const QuicTlsTestBuffer *buffer, bool server, bool selected)
{
    FRAME_Type type = {.versionType = HITLS_VERSION_TLS13, .transportType = BSL_UIO_TCP};
    FRAME_Msg msg = {0};
    msg.recType.data = REC_TYPE_HANDSHAKE;
    uint32_t parsed = 0;
    ASSERT_EQ(FRAME_ParseMsgBody(&type, buffer->data, buffer->len, &msg, &parsed), HITLS_SUCCESS);
    ASSERT_EQ(parsed, buffer->len);
    if (server) {
        FRAME_ServerHelloMsg *hello = &msg.body.hsMsg.body.serverHello;
        ASSERT_EQ(hello->certWithExternalPsk.exState, selected ? INITIAL_FIELD : MISSING_FIELD);
        ASSERT_EQ(hello->pskSelectedIdentity.exState, selected ? INITIAL_FIELD : MISSING_FIELD);
        ASSERT_EQ(hello->keyShare.exState, INITIAL_FIELD);
        if (selected) {
            ASSERT_EQ(hello->certWithExternalPsk.exLen.data, 0);
            ASSERT_EQ(hello->pskSelectedIdentity.data.data, 0);
        }
    } else {
        FRAME_ClientHelloMsg *hello = &msg.body.hsMsg.body.clientHello;
        ASSERT_EQ(hello->certWithExternalPsk.exState, INITIAL_FIELD);
        ASSERT_EQ(hello->certWithExternalPsk.exLen.data, 0);
        ASSERT_EQ(hello->psks.identities.size, 1);
        ASSERT_EQ(hello->pskModes.exData.data[0], 1);
        ASSERT_EQ(hello->keyshares.exState, INITIAL_FIELD);
        ASSERT_EQ(hello->supportedGroups.exState, INITIAL_FIELD);
        ASSERT_EQ(hello->earlyData.exState, MISSING_FIELD);
    }
EXIT:
    FRAME_CleanMsg(&type, &msg);
}

/**
 * @test SDV_TLS_QUIC_RFC9973_HANDSHAKE_TC001
 * @brief Negotiate certificates with an external PSK through the QUIC data and traffic-secret callbacks.
 * Exercise HRR, mutual authentication, certificate fallback and a mismatched PSK with both binder hashes.
 * @precon nan
 * @expect Valid peers complete certificate authentication with matching traffic secrets; a bad PSK is rejected.
 */
/* BEGIN_CASE */
void SDV_TLS_QUIC_RFC9973_HANDSHAKE_TC001(int sha384, int retry, int mutual, int pskCase)
{
    QuicTlsTestPair pair = {0};
    uint32_t failedSide = QUIC_TEST_SIDE_NONE;
    static const uint16_t clientGroups[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1};
    static const uint16_t retryGroups[] = {HITLS_EC_GROUP_SECP384R1};
    g_certPskCipher = sha384 ? HITLS_AES_256_GCM_SHA384 : HITLS_AES_128_GCM_SHA256;
    g_certPskMismatch = pskCase == 2;
    FRAME_Init();
    ASSERT_EQ(QuicTlsTestPairNew(&pair, clientGroups, 2, retry ? retryGroups : g_quicTestP256, 1, true, true),
              HITLS_SUCCESS);
    HITLS_Ctx *client = pair.clientLink->ssl;
    HITLS_Ctx *server = pair.serverLink->ssl;
    ASSERT_EQ(HITLS_CFG_SetKeyExchMode(&client->config.tlsConfig,
        TLS13_KE_MODE_PSK_WITH_DHE | TLS13_CERT_AUTH_WITH_EXTERNAL_PSK), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetKeyExchMode(&server->config.tlsConfig,
        TLS13_KE_MODE_PSK_WITH_DHE | TLS13_CERT_AUTH_WITH_EXTERNAL_PSK), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetCipherSuites(client, &g_certPskCipher, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetCipherSuites(server, &g_certPskCipher, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetPskUseSessionCallback(client, QuicCertPskUse), HITLS_SUCCESS);
    if (pskCase != 1) {
        ASSERT_EQ(HITLS_SetPskFindSessionCallback(server, QuicCertPskFind), HITLS_SUCCESS);
    }
    ASSERT_EQ(HITLS_SetClientVerifySupport(server, mutual != 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetVerifyNoneSupport(client, false), HITLS_SUCCESS);
    ASSERT_TRUE(QuicTlsTestIsProgressResult(HITLS_Connect(client)));
    QuicCertPskCheckHello(&pair.clientEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL], false, true);
    ASSERT_EQ(QuicTlsTestTransferCurrentLevel(&pair.clientEndpoint, server, SIZE_MAX), HITLS_SUCCESS);
    int32_t ret = HITLS_Accept(server);
    if (pskCase == 2) {
        ASSERT_TRUE(!QuicTlsTestIsProgressResult(ret));
        ASSERT_EQ(pair.serverEndpoint.lastAlert, ALERT_ILLEGAL_PARAMETER);
        ASSERT_EQ(pair.serverEndpoint.alertCount, 1);
        goto EXIT;
    }
    ASSERT_TRUE(QuicTlsTestIsProgressResult(ret));
    if (!retry) {
        QuicCertPskCheckHello(&pair.serverEndpoint.output[HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL], true, pskCase == 0);
    }
    ASSERT_EQ(QuicTlsTestRunHandshake(&pair, 37, &failedSide), HITLS_SUCCESS);
    ASSERT_EQ(failedSide, QUIC_TEST_SIDE_NONE);
    uint32_t expected = pskCase == 0 ? TLS13_CERT_AUTH_WITH_EXTERNAL_PSK : TLS13_CERT_AUTH_WITH_DHE;
    ASSERT_EQ(client->negotiatedInfo.tls13BasicKeyExMode, expected);
    ASSERT_EQ(server->negotiatedInfo.tls13BasicKeyExMode, expected);
    ASSERT_EQ(client->negotiatedInfo.isResume, false);
    ASSERT_EQ(server->negotiatedInfo.isResume, false);
    ASSERT_EQ(pair.clientEndpoint.initialFlightCount, retry ? 2 : 1);
    for (uint32_t level = HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE;
         level <= HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION; level++) {
        ASSERT_TRUE(pair.clientEndpoint.writeSecretLen[level] != 0);
        ASSERT_EQ(pair.clientEndpoint.writeSecretLen[level], pair.serverEndpoint.readSecretLen[level]);
        ASSERT_EQ(ConstTimeMemcmp(pair.clientEndpoint.writeSecret[level], pair.serverEndpoint.readSecret[level],
                                  pair.clientEndpoint.writeSecretLen[level]),
                  0xffffffffu);
        ASSERT_EQ(pair.serverEndpoint.writeSecretLen[level], pair.clientEndpoint.readSecretLen[level]);
        ASSERT_EQ(ConstTimeMemcmp(pair.serverEndpoint.writeSecret[level], pair.clientEndpoint.readSecret[level],
                                  pair.serverEndpoint.writeSecretLen[level]),
                  0xffffffffu);
    }
EXIT:
    QuicTlsTestPairFree(&pair);
}
/* END_CASE */

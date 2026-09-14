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
/* INCLUDE_BASE test_suite_tls13_consistency_rfc8446 */

#include <stdint.h>
#include <string.h>
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "hitls_psk.h"
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "bsl_uio.h"
#include "tls.h"
#include "frame_link.h"
#include "frame_tls.h"
#include "parser_frame_msg.h"
#include "rec_wrapper.h"
#include "alert.h"
#include "hs_extensions.h"
#include "hs_verify.h"
#include "session.h"
/* END_HEADER */

#define RFC9973_TEST_PSK_LEN 32u

static const uint8_t g_rfc9973Identity[] = "openhitls-rfc9973";
static const uint8_t g_rfc9973Psk[RFC9973_TEST_PSK_LEN] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
static BSL_UIO_TransportType g_rfc9973Transport = BSL_UIO_TCP;

static uint32_t g_rfc9973PskLen = RFC9973_TEST_PSK_LEN;
static uint32_t g_rfc9973ServerPskCbCalls = 0;
static uint32_t g_rfc9973ServerPskCbMatches = 0;

static uint32_t Rfc9973ClientPskCb(HITLS_Ctx *ctx, const uint8_t *hint, uint8_t *identity, uint32_t maxIdentityLen,
                                   uint8_t *psk, uint32_t maxPskLen)
{
    /* 1. Supply the fixed identity and configurable key length after checking output capacities. */
    (void)ctx;
    (void)hint;
    if (maxIdentityLen < sizeof(g_rfc9973Identity) || maxPskLen < g_rfc9973PskLen) {
        return 0;
    }
    memcpy(identity, g_rfc9973Identity, sizeof(g_rfc9973Identity));
    memcpy(psk, g_rfc9973Psk, g_rfc9973PskLen);
    return g_rfc9973PskLen;
}

static uint32_t Rfc9973ServerPskCb(HITLS_Ctx *ctx, const uint8_t *identity, uint8_t *psk, uint32_t maxPskLen)
{
    /* 1. Count lookups, match the fixed identity, then return the configured test PSK. */
    (void)ctx;
    g_rfc9973ServerPskCbCalls++;
    if (identity == NULL || strcmp((const char *)identity, (const char *)g_rfc9973Identity) != 0 ||
        maxPskLen < g_rfc9973PskLen) {
        return 0;
    }
    g_rfc9973ServerPskCbMatches++;
    memcpy(psk, g_rfc9973Psk, g_rfc9973PskLen);
    return g_rfc9973PskLen;
}

static HITLS_Session *Rfc9973Sha384PskSession(void)
{
    /* 1. Store the fixed PSK in a TLS 1.3 session bound to the SHA-384 cipher suite. */
    HITLS_Session *session = HITLS_SESS_New();
    if (session == NULL) {
        return NULL;
    }
    if (HITLS_SESS_SetProtocolVersion(
            session, g_rfc9973Transport == BSL_UIO_UDP ? HITLS_VERSION_DTLS13 : HITLS_VERSION_TLS13) != HITLS_SUCCESS ||
        HITLS_SESS_SetCipherSuite(session, HITLS_AES_256_GCM_SHA384) != HITLS_SUCCESS ||
        HITLS_SESS_SetMasterKey(session, g_rfc9973Psk, g_rfc9973PskLen) != HITLS_SUCCESS) {
        HITLS_SESS_Free(session);
        return NULL;
    }
    return session;
}

static int32_t Rfc9973UseSha384Psk(HITLS_Ctx *ctx, uint32_t hashAlgo, const uint8_t **identity, uint32_t *identityLen,
                                   HITLS_Session **session)
{
    /* 1. Return a SHA-384 candidate even for another requested hash, exercising library-side filtering. */
    (void)ctx;
    (void)hashAlgo;
    *identity = g_rfc9973Identity;
    *identityLen = sizeof(g_rfc9973Identity) - 1;
    *session = Rfc9973Sha384PskSession();
    return *session == NULL ? HITLS_PSK_USE_SESSION_CB_FAIL : HITLS_PSK_USE_SESSION_CB_SUCCESS;
}

static int32_t Rfc9973FindSha384Psk(HITLS_Ctx *ctx, const uint8_t *identity, uint32_t identityLen,
                                    HITLS_Session **session)
{
    /* 1. Return a SHA-384 PSK session only for the known identity; unknown identities return NULL. */
    (void)ctx;
    *session = NULL;
    if (identityLen == sizeof(g_rfc9973Identity) - 1 && memcmp(identity, g_rfc9973Identity, identityLen) == 0) {
        *session = Rfc9973Sha384PskSession();
        if (*session == NULL) {
            return HITLS_PSK_FIND_SESSION_CB_FAIL;
        }
    }
    return HITLS_PSK_FIND_SESSION_CB_SUCCESS;
}

static uint32_t g_rfc9973RecomputeCalls;
static uint32_t g_rfc9973RecomputeHash;
static int g_rfc9973RecomputeChange;

static uint32_t Rfc9973RecomputeLegacyPsk(HITLS_Ctx *ctx, const uint8_t *hint, uint8_t *identity,
                                          uint32_t maxIdentityLen, uint8_t *psk, uint32_t maxPskLen)
{
    /* 1. Count callback invocations to verify that HRR obtains the legacy PSK again. */
    g_rfc9973RecomputeCalls++;
    return Rfc9973ClientPskCb(ctx, hint, identity, maxIdentityLen, psk, maxPskLen);
}

static int32_t Rfc9973RecomputeSessionPsk(HITLS_Ctx *ctx, uint32_t hashAlgo, const uint8_t **identity,
                                          uint32_t *identityLen, HITLS_Session **session)
{
    /* 1. Record the invocation count and requested hash to distinguish ClientHello1 from ClientHello2. */
    g_rfc9973RecomputeCalls++;
    g_rfc9973RecomputeHash = hashAlgo;
    *session = NULL;
    /* 2. On the second call, optionally omit the PSK or report a callback failure. */
    if (g_rfc9973RecomputeCalls > 1) {
        if (g_rfc9973RecomputeChange == 1) {
            return HITLS_PSK_USE_SESSION_CB_SUCCESS;
        }
        if (g_rfc9973RecomputeChange == 4) {
            return HITLS_PSK_USE_SESSION_CB_FAIL;
        }
    }
    int32_t ret = Rfc9973UseSha384Psk(ctx, hashAlgo, identity, identityLen, session);
    if (ret != HITLS_PSK_USE_SESSION_CB_SUCCESS || g_rfc9973RecomputeCalls == 1) {
        return ret;
    }
    /* 3. Otherwise mutate identity, hash, or key length only after the original offer was sent. */
    if (g_rfc9973RecomputeChange == 2) {
        *identity = (const uint8_t *)"changed-identity";
        *identityLen = sizeof("changed-identity") - 1;
    } else if (g_rfc9973RecomputeChange == 3) {
        (void)HITLS_SESS_SetCipherSuite(*session, HITLS_AES_128_GCM_SHA256);
    } else if (g_rfc9973RecomputeChange == 5) {
        (void)HITLS_SESS_SetMasterKey(*session, g_rfc9973Psk, 8);
    }
    return ret;
}

static uint32_t Rfc9973UnknownPskCb(HITLS_Ctx *ctx, const uint8_t *identity, uint8_t *psk, uint32_t maxPskLen)
{
    /* 1. Force the lookup to miss while preserving the callback counters. */
    (void)identity;
    return Rfc9973ServerPskCb(ctx, (const uint8_t *)"unknown", psk, maxPskLen);
}

static HITLS_Config *Rfc9973NewConfig(uint32_t mode, bool withClientPsk, bool withServerPsk)
{
    /* 1. Create a TLS 1.3 configuration with the requested modes and the fixed SHA-256 suite. */
    HITLS_Config *config = NULL;
#ifdef HITLS_TLS_PROTO_DTLS13
    if (g_rfc9973Transport == BSL_UIO_UDP) {
        config = HITLS_CFG_NewDTLS13Config();
    } else
#endif
    {
        config = HITLS_CFG_NewTLS13Config();
    }
    if ((mode & TLS13_CERT_AUTH_WITH_EXTERNAL_PSK) != 0) {
        mode |= TLS13_KE_MODE_PSK_WITH_DHE;
    }
    if (config == NULL || HITLS_CFG_SetKeyExchMode(config, mode) != HITLS_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }
    uint16_t groups[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP521R1};
    if (HITLS_CFG_SetGroups(config, groups, 2) != HITLS_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    if (HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1) != HITLS_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }
    (void)HITLS_CFG_SetCheckKeyUsage(config, false);
    (void)HITLS_CFG_SetFlightTransmitSwitch(config, false);
    /* 2. Install only the callbacks requested by the case, controlling whether either peer knows the PSK. */
    if (withClientPsk) {
        (void)HITLS_CFG_SetPskClientCallback(config, Rfc9973ClientPskCb);
    }
    if (withServerPsk) {
        (void)HITLS_CFG_SetPskServerCallback(config, Rfc9973ServerPskCb);
    }
    return config;
}

static void Rfc9973AssertFatalAlert(FRAME_LinkObj *link, uint8_t description)
{
    /* 1. Read the local alert state and require a sent fatal alert with the expected description. */
    ALERT_Info alert = {0};
    ALERT_GetInfo(link->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, description);
EXIT:
    return;
}

static void Rfc9973AssertPeerReceivesIllegalParameter(FRAME_LinkObj *server, FRAME_LinkObj *client)
{
    /* 1. Check the actual plaintext TLS record: fatal (2), illegal_parameter (47). */
    const uint8_t expected[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2f};
    FrameUioUserData *serverIo = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIo != NULL);
    if (g_rfc9973Transport == BSL_UIO_TCP) {
        ASSERT_COMPARE("illegal_parameter record", serverIo->sndMsg.msg, serverIo->sndMsg.len, expected,
                       sizeof(expected));
    } else {
        ASSERT_EQ(serverIo->sndMsg.len, 15);
        ASSERT_EQ(serverIo->sndMsg.msg[0], REC_TYPE_ALERT);
        ASSERT_EQ(serverIo->sndMsg.msg[13], ALERT_LEVEL_FATAL);
        ASSERT_EQ(serverIo->sndMsg.msg[14], ALERT_ILLEGAL_PARAMETER);
    }

    /* 2. Deliver the alert after the server handshake error stops FRAME_CreateConnection. */
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_NE(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_RECV);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    return;
}

static void Rfc9973ObserveClientOffer(TLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    /* 1. Parse the outgoing ClientHello without changing its bytes. */
    (void)ctx;
    (void)bufSize;
    const uint32_t *expected = user;
    FRAME_Type frameType = {0};
    frameType.versionType = g_rfc9973Transport == BSL_UIO_UDP ? HITLS_VERSION_DTLS13 : HITLS_VERSION_TLS13;
    frameType.transportType = g_rfc9973Transport;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    frameMsg.length.data = *len;
    uint32_t parseLen = 0;
    ASSERT_EQ(FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen), HITLS_SUCCESS);
    ASSERT_EQ(parseLen, *len);
    FRAME_ClientHelloMsg *hello = &frameMsg.body.hsMsg.body.clientHello;
    /* 2. Check extension 33 presence and the exact number of offered PSK identities. */
    ASSERT_EQ(hello->certWithExternalPsk.exState, expected[0] ? INITIAL_FIELD : MISSING_FIELD);
    ASSERT_EQ(hello->psks.exState, expected[1] ? INITIAL_FIELD : MISSING_FIELD);
    if (expected[1] != 0) {
        ASSERT_EQ(hello->psks.identities.size, expected[1]);
    }
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
}

typedef enum {
    RFC9973_OBSERVE_CLIENT_HELLO,
    RFC9973_OBSERVE_SERVER_HELLO,
    RFC9973_MISSING_KEY_SHARE,
    RFC9973_MISSING_SUPPORTED_GROUPS,
    RFC9973_MISSING_PSK_MODES,
    RFC9973_MISSING_PRE_SHARED_KEY,
    RFC9973_CLIENT_EXT_NONEMPTY,
    RFC9973_SERVER_EXT_NONEMPTY,
    RFC9973_ONLY_PSK_KE,
    RFC9973_ADD_EARLY_DATA,
    RFC9973_BAD_BINDER,
    RFC9973_SERVER_MISSING_KEY_SHARE,
    RFC9973_SERVER_MISSING_PRE_SHARED_KEY,
    RFC9973_ADD_CERT_WITH_EXTERNAL_PSK,
    RFC9973_MISSING_CERT_WITH_EXTERNAL_PSK,
    RFC9973_OBSERVE_CLIENT_HELLO_WITH_PSK_KE,
    RFC9973_SERVER_SELECTED_IDENTITY_OUT_OF_RANGE,
    RFC9973_OBSERVE_SERVER_WITHOUT_PSK
} Rfc9973Mutation;

static void Rfc9973SetEmptyExtension(FRAME_HsExtArray8 *extension, uint16_t type)
{
    /* 1. Encode an assigned type and zero body length, omitting the array-length and payload fields. */
    extension->exState = ASSIGNED_FIELD;
    extension->exType.state = ASSIGNED_FIELD;
    extension->exType.data = type;
    extension->exLen.state = ASSIGNED_FIELD;
    extension->exLen.data = 0;
    extension->exDataLen.state = MISSING_FIELD;
    extension->exData.state = MISSING_FIELD;
}

static void Rfc9973MutateHello(TLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    /* 1. Parse ClientHello or ServerHello into mutable fields. */
    (void)ctx;
    Rfc9973Mutation mutation = (Rfc9973Mutation)(uintptr_t)user;
    FRAME_Type frameType = {0};
    frameType.versionType = g_rfc9973Transport == BSL_UIO_UDP ? HITLS_VERSION_DTLS13 : HITLS_VERSION_TLS13;
    frameType.transportType = g_rfc9973Transport;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    frameMsg.length.data = *len;
    uint32_t parseLen = 0;
    ASSERT_EQ(FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen), HITLS_SUCCESS);
    ASSERT_EQ(parseLen, *len);

    /* 2. Observe the required fields or apply one requested client/server mutation. */
    if (frameMsg.body.hsMsg.type.data == CLIENT_HELLO) {
        FRAME_ClientHelloMsg *clientHello = &frameMsg.body.hsMsg.body.clientHello;
        if (mutation == RFC9973_OBSERVE_CLIENT_HELLO || mutation == RFC9973_OBSERVE_CLIENT_HELLO_WITH_PSK_KE) {
            ASSERT_EQ(clientHello->certWithExternalPsk.exState, INITIAL_FIELD);
            ASSERT_EQ(clientHello->certWithExternalPsk.exType.data, HS_EX_TYPE_CERT_WITH_EXTERNAL_PSK);
            ASSERT_EQ(clientHello->certWithExternalPsk.exLen.data, 0);
            ASSERT_EQ(clientHello->keyshares.exState, INITIAL_FIELD);
            ASSERT_EQ(clientHello->supportedGroups.exState, INITIAL_FIELD);
            ASSERT_EQ(clientHello->pskModes.exState, INITIAL_FIELD);
            ASSERT_EQ(clientHello->pskModes.exData.size, mutation == RFC9973_OBSERVE_CLIENT_HELLO ? 1 : 2);
            ASSERT_EQ(clientHello->pskModes.exData.data[0], 1u); /* psk_dhe_ke */
            if (mutation == RFC9973_OBSERVE_CLIENT_HELLO_WITH_PSK_KE) {
                ASSERT_EQ(clientHello->pskModes.exData.data[1], 0u); /* psk_ke */
            }
            ASSERT_EQ(clientHello->psks.exState, INITIAL_FIELD);
            ASSERT_EQ(clientHello->psks.identities.size, 1);
            ASSERT_EQ(clientHello->psks.identities.data[0].obfuscatedTicketAge.data, 0);
            ASSERT_EQ(clientHello->earlyData.exState, MISSING_FIELD);
            goto EXIT;
        }
        switch (mutation) {
            case RFC9973_MISSING_KEY_SHARE:
                clientHello->keyshares.exState = MISSING_FIELD;
                break;
            case RFC9973_MISSING_SUPPORTED_GROUPS:
                clientHello->supportedGroups.exState = MISSING_FIELD;
                break;
            case RFC9973_MISSING_PSK_MODES:
                clientHello->pskModes.exState = MISSING_FIELD;
                break;
            case RFC9973_MISSING_PRE_SHARED_KEY:
                clientHello->psks.exState = MISSING_FIELD;
                break;
            case RFC9973_CLIENT_EXT_NONEMPTY:
                clientHello->certWithExternalPsk.exLen.state = ASSIGNED_FIELD;
                clientHello->certWithExternalPsk.exLen.data = 1;
                clientHello->certWithExternalPsk.exDataLen.state = ASSIGNED_FIELD;
                clientHello->certWithExternalPsk.exDataLen.data = 0;
                break;
            case RFC9973_ONLY_PSK_KE:
                clientHello->pskModes.exData.data[0] = 0u; /* psk_ke */
                break;
            case RFC9973_ADD_EARLY_DATA:
                Rfc9973SetEmptyExtension(&clientHello->earlyData, HS_EX_TYPE_EARLY_DATA);
                break;
            case RFC9973_BAD_BINDER:
                clientHello->psks.binders.data[0].binder.data[0] ^= 0x80u;
                break;
            case RFC9973_ADD_CERT_WITH_EXTERNAL_PSK:
                Rfc9973SetEmptyExtension(&clientHello->certWithExternalPsk, HS_EX_TYPE_CERT_WITH_EXTERNAL_PSK);
                break;
            case RFC9973_MISSING_CERT_WITH_EXTERNAL_PSK:
                clientHello->certWithExternalPsk.exState = MISSING_FIELD;
                break;
            default:
                break;
        }
    } else {
        FRAME_ServerHelloMsg *serverHello = &frameMsg.body.hsMsg.body.serverHello;
        if (mutation == RFC9973_OBSERVE_SERVER_WITHOUT_PSK) {
            ASSERT_EQ(serverHello->certWithExternalPsk.exState, MISSING_FIELD);
            ASSERT_EQ(serverHello->pskSelectedIdentity.exState, MISSING_FIELD);
            goto EXIT;
        }
        if (mutation == RFC9973_OBSERVE_SERVER_HELLO) {
            ASSERT_EQ(serverHello->certWithExternalPsk.exState, INITIAL_FIELD);
            ASSERT_EQ(serverHello->certWithExternalPsk.exLen.data, 0);
            ASSERT_EQ(serverHello->keyShare.exState, INITIAL_FIELD);
            ASSERT_EQ(serverHello->pskSelectedIdentity.exState, INITIAL_FIELD);
            goto EXIT;
        }
        switch (mutation) {
            case RFC9973_SERVER_EXT_NONEMPTY:
                serverHello->certWithExternalPsk.exLen.state = ASSIGNED_FIELD;
                serverHello->certWithExternalPsk.exLen.data = 1;
                serverHello->certWithExternalPsk.exDataLen.state = ASSIGNED_FIELD;
                serverHello->certWithExternalPsk.exDataLen.data = 0;
                break;
            case RFC9973_SERVER_MISSING_KEY_SHARE:
                serverHello->keyShare.exState = MISSING_FIELD;
                break;
            case RFC9973_SERVER_MISSING_PRE_SHARED_KEY:
                serverHello->pskSelectedIdentity.exState = MISSING_FIELD;
                break;
            case RFC9973_ADD_CERT_WITH_EXTERNAL_PSK:
                Rfc9973SetEmptyExtension(&serverHello->certWithExternalPsk, HS_EX_TYPE_CERT_WITH_EXTERNAL_PSK);
                break;
            case RFC9973_SERVER_SELECTED_IDENTITY_OUT_OF_RANGE:
                serverHello->pskSelectedIdentity.data.state = ASSIGNED_FIELD;
                serverHello->pskSelectedIdentity.data.data = 1;
                break;
            default:
                break;
        }
    }

    /* 3. Repack the changed message. Deliberately leave binders unchanged for negative cases. */
    memset(data, 0, bufSize);
    ASSERT_EQ(FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len), HITLS_SUCCESS);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
}

static int32_t Rfc9973ConnectWithMutation(Rfc9973Mutation mutation, bool mutateServer, FRAME_LinkObj **client,
                                          FRAME_LinkObj **server, HITLS_Config **config)
{
    /* 1. Install the requested ClientHello or ServerHello mutation before creating the peers. */
    RecWrapper wrapper = {mutateServer ? TRY_SEND_SERVER_HELLO : TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false,
                          (void *)(uintptr_t)mutation, Rfc9973MutateHello};
    RegisterWrapper(wrapper);
    *config = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, true);
    if (*config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    *client = FRAME_CreateLink(*config, g_rfc9973Transport);
    *server = FRAME_CreateLink(*config, g_rfc9973Transport);
    if (*client == NULL || *server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    /* 2. Drive the handshake; the caller verifies success or the expected fatal alert. */
    return FRAME_CreateConnection(*client, *server, true, HS_STATE_BUTT);
}

typedef struct {
    uint32_t clientHelloCount;
    bool addOnSecondClientHello;
} Rfc9973SecondClientHelloMutation;

static void Rfc9973MutateSecondClientHello(TLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    /* 1. Count ClientHellos and change extension 33 only in the second one. */
    Rfc9973SecondClientHelloMutation *mutation = (Rfc9973SecondClientHelloMutation *)user;
    mutation->clientHelloCount++;
    if (mutation->clientHelloCount != 2) {
        return;
    }
    Rfc9973MutateHello(ctx, data, len, bufSize,
                       (void *)(uintptr_t)(mutation->addOnSecondClientHello ? RFC9973_ADD_CERT_WITH_EXTERNAL_PSK :
                                                                              RFC9973_MISSING_CERT_WITH_EXTERNAL_PSK));
}

static void Rfc9973ForceHelloRetryRequest(FRAME_LinkObj *server)
{
    /* 1. Require a supported group absent from the initial key_share to force HRR. */
    const uint16_t group = HITLS_EC_GROUP_SECP521R1;
    (void)HITLS_CFG_SetGroups(&server->ssl->config.tlsConfig, &group, 1);
}

typedef enum {
    RFC9973_WRONG_ENCRYPTED_EXTENSIONS,
    RFC9973_WRONG_CERTIFICATE_REQUEST,
    RFC9973_WRONG_CERTIFICATE,
    RFC9973_WRONG_NEW_SESSION_TICKET
} Rfc9973WrongMessage;

static uint32_t Rfc9973ReadUint24(const uint8_t *data)
{
    /* 1. Decode a TLS three-byte length in network byte order. */
    return ((uint32_t)data[0] << 16) | ((uint32_t)data[1] << 8) | data[2];
}

static void Rfc9973WriteUint24(uint32_t value, uint8_t *data)
{
    /* 1. Encode a TLS three-byte length in network byte order. */
    data[0] = (uint8_t)(value >> 16);
    data[1] = (uint8_t)(value >> 8);
    data[2] = (uint8_t)value;
}

static uint16_t Rfc9973ReadUint16(const uint8_t *data)
{
    /* 1. Decode a TLS two-byte length in network byte order. */
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static void Rfc9973WriteUint16(uint16_t value, uint8_t *data)
{
    /* 1. Encode a TLS two-byte length in network byte order. */
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)value;
}

static void Rfc9973AppendExtensionAt(uint8_t *data, uint32_t *len, uint32_t bufSize, uint32_t insertOffset,
                                     uint32_t extensionLengthOffset, uint32_t enclosingLengthOffset)
{
    /* 1. Reserve four bytes and insert the empty extension 33 header at the selected offset. */
    ASSERT_TRUE(*len + HS_EX_HEADER_LEN <= bufSize && insertOffset <= *len);
    memmove(data + insertOffset + HS_EX_HEADER_LEN, data + insertOffset, *len - insertOffset);
    Rfc9973WriteUint16(HS_EX_TYPE_CERT_WITH_EXTERNAL_PSK, data + insertOffset);
    Rfc9973WriteUint16(0, data + insertOffset + sizeof(uint16_t));
    /* 2. Repair extension, enclosing vector, and handshake lengths so only the extension placement is invalid. */
    uint16_t extensionLength = Rfc9973ReadUint16(data + extensionLengthOffset);
    Rfc9973WriteUint16((uint16_t)(extensionLength + HS_EX_HEADER_LEN), data + extensionLengthOffset);
    if (enclosingLengthOffset != UINT32_MAX) {
        uint32_t enclosingLength = Rfc9973ReadUint24(data + enclosingLengthOffset);
        Rfc9973WriteUint24(enclosingLength + HS_EX_HEADER_LEN, data + enclosingLengthOffset);
    }
    Rfc9973WriteUint24(Rfc9973ReadUint24(data + 1) + HS_EX_HEADER_LEN, data + 1);
    if (g_rfc9973Transport == BSL_UIO_UDP) {
        Rfc9973WriteUint24(Rfc9973ReadUint24(data + 9) + HS_EX_HEADER_LEN, data + 9);
    }
    *len += HS_EX_HEADER_LEN;
EXIT:
    return;
}

static void Rfc9973InjectWrongMessageExtension(TLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    Rfc9973WrongMessage wrongMessage = (Rfc9973WrongMessage)(uintptr_t)user;
    uint32_t extensionLengthOffset = 0;
    uint32_t insertOffset = 0;
    uint32_t enclosingLengthOffset = UINT32_MAX;

    uint32_t headerLen = g_rfc9973Transport == BSL_UIO_UDP ? DTLS_HS_MSG_HEADER_SIZE : HS_MSG_HEADER_SIZE;
    /* 1. Locate the extension vector using the selected handshake message format. */
    switch (wrongMessage) {
        case RFC9973_WRONG_ENCRYPTED_EXTENSIONS:
            extensionLengthOffset = headerLen;
            insertOffset = headerLen + 2 + Rfc9973ReadUint16(data + extensionLengthOffset);
            break;
        case RFC9973_WRONG_CERTIFICATE_REQUEST:
            extensionLengthOffset = headerLen + 1 + data[headerLen];
            insertOffset = extensionLengthOffset + sizeof(uint16_t) + Rfc9973ReadUint16(data + extensionLengthOffset);
            break;
        case RFC9973_WRONG_CERTIFICATE: {
            uint32_t certificateListLengthOffset = headerLen + 1 + data[headerLen];
            uint32_t certificateOffset = certificateListLengthOffset + 3;
            uint32_t certificateLength = Rfc9973ReadUint24(data + certificateOffset);
            extensionLengthOffset = certificateOffset + 3 + certificateLength;
            insertOffset = extensionLengthOffset + sizeof(uint16_t) + Rfc9973ReadUint16(data + extensionLengthOffset);
            enclosingLengthOffset = certificateListLengthOffset;
            break;
        }
        case RFC9973_WRONG_NEW_SESSION_TICKET: {
            uint32_t offset = headerLen + 8; /* ticket_lifetime and ticket_age_add */
            offset += sizeof(uint8_t) + data[offset];
            uint16_t ticketLength = Rfc9973ReadUint16(data + offset);
            extensionLengthOffset = offset + sizeof(uint16_t) + ticketLength;
            insertOffset = extensionLengthOffset + sizeof(uint16_t) + Rfc9973ReadUint16(data + extensionLengthOffset);
            break;
        }
        default:
            ASSERT_TRUE(false);
    }
    /* 2. Insert extension 33 and repair all enclosing lengths before the peer parses the message. */
    Rfc9973AppendExtensionAt(data, len, bufSize, insertOffset, extensionLengthOffset, enclosingLengthOffset);
EXIT:
    return;
}

static void Rfc9973ObserveHandshakeMessage(TLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    /* 1. Check the record wrapper received the expected handshake message type. */
    (void)ctx;
    (void)bufSize;
    ASSERT_TRUE(data != NULL && len != NULL && *len >= HS_MSG_HEADER_SIZE);
    ASSERT_EQ(data[0], (uint8_t)(uintptr_t)user);
EXIT:
    return;
}

static void Rfc9973SetExternalPskAge(TLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    /* 1. Parse the offer, replace obfuscated_ticket_age, and repack the ClientHello. */
    uint32_t age = (uint32_t)(uintptr_t)user;
    FRAME_Type frameType = {0};
    frameType.versionType = g_rfc9973Transport == BSL_UIO_UDP ? HITLS_VERSION_DTLS13 : HITLS_VERSION_TLS13;
    frameType.transportType = g_rfc9973Transport;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    frameMsg.length.data = *len;
    uint32_t parseLen = 0;
    ASSERT_EQ(FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen), HITLS_SUCCESS);
    ASSERT_EQ(parseLen, *len);
    FRAME_HsExtOfferedPsks *psks = &frameMsg.body.hsMsg.body.clientHello.psks;
    ASSERT_EQ(psks->identities.size, 1);
    ASSERT_EQ(psks->binders.size, 1);
    psks->identities.data[0].obfuscatedTicketAge.state = ASSIGNED_FIELD;
    psks->identities.data[0].obfuscatedTicketAge.data = age;
    memset(data, 0, bufSize);
    ASSERT_EQ(FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len), HITLS_SUCCESS);

    /* 2. Recalculate the binder over the changed age so the test isolates age handling. */
    uint32_t binderLen = psks->binders.data[0].binder.size;
    uint32_t binderVectorLen = sizeof(uint16_t) + sizeof(uint8_t) + binderLen;
    ASSERT_TRUE(*len > binderVectorLen && binderLen == 32u);
    ASSERT_EQ(VERIFY_CalcPskBinder(ctx, HITLS_HASH_SHA_256, true, (uint8_t *)(uintptr_t)g_rfc9973Psk, g_rfc9973PskLen,
                                   data, *len - binderVectorLen, data + *len - binderLen, binderLen),
              HITLS_SUCCESS);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
}

typedef struct {
    const uint8_t *ticket;
    uint32_t ticketLen;
    bool ticketFirst;
} Rfc9973TicketMutation;

static void Rfc9973InsertTicketIdentity(TLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    /* 1. Parse the external-only offer and grow both identity and binder arrays to two entries. */
    Rfc9973TicketMutation *mutation = (Rfc9973TicketMutation *)user;
    FRAME_Type frameType = {0};
    frameType.versionType = g_rfc9973Transport == BSL_UIO_UDP ? HITLS_VERSION_DTLS13 : HITLS_VERSION_TLS13;
    frameType.transportType = g_rfc9973Transport;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    frameMsg.length.data = *len;
    uint32_t parseLen = 0;
    ASSERT_EQ(FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen), HITLS_SUCCESS);
    ASSERT_EQ(parseLen, *len);
    FRAME_HsExtOfferedPsks *psks = &frameMsg.body.hsMsg.body.clientHello.psks;
    ASSERT_EQ(psks->identities.size, 1);
    ASSERT_EQ(psks->binders.size, 1);

    FRAME_HsPskIdentity *identities = BSL_SAL_Calloc(2, sizeof(FRAME_HsPskIdentity));
    FRAME_HsPskBinder *binders = BSL_SAL_Calloc(2, sizeof(FRAME_HsPskBinder));
    ASSERT_TRUE(identities != NULL && binders != NULL);
    identities[0] = psks->identities.data[0];
    binders[0] = psks->binders.data[0];
    BSL_SAL_FREE(psks->identities.data);
    BSL_SAL_FREE(psks->binders.data);
    psks->identities.data = identities;
    psks->identities.size = 2;
    psks->binders.data = binders;
    psks->binders.size = 2;

    /* 2. Append a real server-issued ticket and a placeholder binder. Classification must reject the list first. */
    FRAME_HsPskIdentity *ticketIdentity = &identities[1];
    ticketIdentity->state = ASSIGNED_FIELD;
    ticketIdentity->identityLen.state = ASSIGNED_FIELD;
    ticketIdentity->identityLen.data = mutation->ticketLen;
    ticketIdentity->identity.state = ASSIGNED_FIELD;
    ticketIdentity->identity.size = mutation->ticketLen;
    ticketIdentity->identity.data = BSL_SAL_Dump(mutation->ticket, mutation->ticketLen);
    ASSERT_TRUE(ticketIdentity->identity.data != NULL);
    ticketIdentity->obfuscatedTicketAge.state = ASSIGNED_FIELD;
    ticketIdentity->obfuscatedTicketAge.data = 0;

    FRAME_HsPskBinder *ticketBinder = &binders[1];
    ticketBinder->state = ASSIGNED_FIELD;
    ticketBinder->binderLen.state = ASSIGNED_FIELD;
    ticketBinder->binderLen.data = 32;
    ticketBinder->binder.state = ASSIGNED_FIELD;
    ticketBinder->binder.size = 32;
    ticketBinder->binder.data = BSL_SAL_Calloc(32, sizeof(uint8_t));
    ASSERT_TRUE(ticketBinder->binder.data != NULL);

    /* 3. Update vector lengths and repack; no binder validation is expected for this forbidden list. */
    uint32_t addedIdentityLen = sizeof(uint16_t) + mutation->ticketLen + sizeof(uint32_t);
    uint32_t addedBinderLen = sizeof(uint8_t) + 32u;
    psks->identitySize.data += addedIdentityLen;
    psks->binderSize.data += addedBinderLen;
    psks->exLen.data += addedIdentityLen + addedBinderLen;
    if (mutation->ticketFirst) {
        FRAME_HsPskIdentity externalIdentity = identities[0];
        identities[0] = identities[1];
        identities[1] = externalIdentity;
    }
    memset(data, 0, bufSize);
    ASSERT_EQ(FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len), HITLS_SUCCESS);
    /* 4. Keep the external binder valid; rejection must result from the ticket anywhere in the list. */
    uint32_t truncatedLen = *len - sizeof(uint16_t) - 2u * (sizeof(uint8_t) + 32u);
    uint32_t externalBinderOffset =
        truncatedLen + sizeof(uint16_t) + sizeof(uint8_t) + (mutation->ticketFirst ? sizeof(uint8_t) + 32u : 0u);
    ASSERT_EQ(VERIFY_CalcPskBinder(ctx, HITLS_HASH_SHA_256, true, (uint8_t *)(uintptr_t)g_rfc9973Psk, g_rfc9973PskLen,
                                   data, truncatedLen, data + externalBinderOffset, 32u),
              HITLS_SUCCESS);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
}

/*
 * Prepend a matching external PSK identity in front of the resumption ticket
 * offered by the client. The ticket binder is recomputed for the enlarged
 * identity list (RFC 8446 Section 4.2.11.2); the prepended binder is valid
 * only when requested. The resumption PSK equals the session master key,
 * so both binders can be recomputed inside the wrapper.
 */
typedef struct {
    bool validBinder;
    uint8_t masterKey[HS_PSK_MAX_LEN];
    uint32_t masterKeyLen;
} Rfc9973PrependMutation;

static void Rfc9973PrependExternalIdentity(TLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    Rfc9973PrependMutation *mutation = (Rfc9973PrependMutation *)user;
    FRAME_Type frameType = {0};
    frameType.versionType = g_rfc9973Transport == BSL_UIO_UDP ? HITLS_VERSION_DTLS13 : HITLS_VERSION_TLS13;
    frameType.transportType = g_rfc9973Transport;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    frameMsg.length.data = *len;
    uint32_t parseLen = 0;
    ASSERT_EQ(FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen), HITLS_SUCCESS);
    ASSERT_EQ(parseLen, *len);
    FRAME_ClientHelloMsg *hello = &frameMsg.body.hsMsg.body.clientHello;
    FRAME_HsExtOfferedPsks *psks = &hello->psks;
    /* 1. Start with a ticket-only offer without extension 33. */
    ASSERT_EQ(hello->certWithExternalPsk.exState, MISSING_FIELD);
    ASSERT_EQ(psks->identities.size, 1);
    ASSERT_EQ(psks->binders.size, 1);

    /* 2. Move the ticket to index 1 and insert the known external identity at index 0. */
    FRAME_HsPskIdentity *identities = BSL_SAL_Calloc(2, sizeof(FRAME_HsPskIdentity));
    FRAME_HsPskBinder *binders = BSL_SAL_Calloc(2, sizeof(FRAME_HsPskBinder));
    ASSERT_TRUE(identities != NULL && binders != NULL);
    identities[1] = psks->identities.data[0];
    binders[1] = psks->binders.data[0];

    identities[0].state = ASSIGNED_FIELD;
    identities[0].identityLen.state = ASSIGNED_FIELD;
    identities[0].identityLen.data = sizeof(g_rfc9973Identity);
    identities[0].identity.state = ASSIGNED_FIELD;
    identities[0].identity.size = sizeof(g_rfc9973Identity);
    identities[0].identity.data = BSL_SAL_Dump(g_rfc9973Identity, sizeof(g_rfc9973Identity));
    ASSERT_TRUE(identities[0].identity.data != NULL);
    identities[0].obfuscatedTicketAge.state = ASSIGNED_FIELD;
    identities[0].obfuscatedTicketAge.data = 0; /* RFC 9973 Section 5.1: ignored for external PSKs. */

    binders[0].state = ASSIGNED_FIELD;
    binders[0].binderLen.state = ASSIGNED_FIELD;
    binders[0].binderLen.data = 32;
    binders[0].binder.state = ASSIGNED_FIELD;
    binders[0].binder.size = 32;
    binders[0].binder.data = BSL_SAL_Calloc(32, sizeof(uint8_t));
    ASSERT_TRUE(binders[0].binder.data != NULL);

    BSL_SAL_FREE(psks->identities.data);
    BSL_SAL_FREE(psks->binders.data);
    psks->identities.data = identities;
    psks->identities.size = 2;
    psks->binders.data = binders;
    psks->binders.size = 2;
    uint32_t addedIdentityLen = sizeof(uint16_t) + sizeof(g_rfc9973Identity) + sizeof(uint32_t);
    uint32_t addedBinderLen = sizeof(uint8_t) + 32u;
    psks->identitySize.data += addedIdentityLen;
    psks->binderSize.data += addedBinderLen;
    psks->exLen.data += addedIdentityLen + addedBinderLen;

    memset(data, 0, bufSize);
    ASSERT_EQ(FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len), HITLS_SUCCESS);
    /* 3. Recalculate the ticket binder over the enlarged list; optionally make the external binder valid. */
    uint32_t binderVectorLen = sizeof(uint16_t) + 2u * (sizeof(uint8_t) + 32u);
    uint8_t *ticketBinder = data + *len - 32u;
    ASSERT_EQ(VERIFY_CalcPskBinder(ctx, HITLS_HASH_SHA_256, false, mutation->masterKey, mutation->masterKeyLen, data,
                                   *len - binderVectorLen, ticketBinder, 32u),
              HITLS_SUCCESS);
    if (mutation->validBinder) {
        uint8_t *extBinder = data + *len - binderVectorLen + sizeof(uint16_t) + sizeof(uint8_t);
        ASSERT_EQ(VERIFY_CalcPskBinder(ctx, HITLS_HASH_SHA_256, true, (uint8_t *)(uintptr_t)g_rfc9973Psk,
                                       g_rfc9973PskLen, data, *len - binderVectorLen, extBinder, 32u),
                  HITLS_SUCCESS);
    }
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
}

static void Rfc9973SelectSecondExternalPsk(TLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    /* 1. Parse the single external PSK offer and grow the identity and binder arrays. */
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = g_rfc9973Transport == BSL_UIO_UDP ? HITLS_VERSION_DTLS13 : HITLS_VERSION_TLS13;
    frameType.transportType = g_rfc9973Transport;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    frameMsg.length.data = *len;
    uint32_t parseLen = 0;
    ASSERT_EQ(FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen), HITLS_SUCCESS);
    ASSERT_EQ(parseLen, *len);
    FRAME_HsExtOfferedPsks *psks = &frameMsg.body.hsMsg.body.clientHello.psks;
    ASSERT_EQ(psks->identities.size, 1);
    ASSERT_EQ(psks->binders.size, 1);

    FRAME_HsPskIdentity *identities = BSL_SAL_Calloc(2, sizeof(FRAME_HsPskIdentity));
    FRAME_HsPskBinder *binders = BSL_SAL_Calloc(2, sizeof(FRAME_HsPskBinder));
    ASSERT_TRUE(identities != NULL && binders != NULL);
    identities[1] = psks->identities.data[0];
    binders[1] = psks->binders.data[0];

    /* 2. Keep the known identity at index 1; prepend an unknown identity with a zero binder. */
    identities[0] = identities[1];
    identities[0].identity.data = BSL_SAL_Dump(identities[1].identity.data, identities[1].identity.size);
    ASSERT_TRUE(identities[0].identity.data != NULL && identities[0].identity.size != 0);
    identities[0].identity.data[0] ^= 0x20u; /* Keep the same encoded length, but make the first identity unknown. */
    binders[0] = binders[1];
    binders[0].binder.data = BSL_SAL_Calloc(binders[1].binder.size, sizeof(uint8_t));
    ASSERT_TRUE(binders[0].binder.data != NULL);

    BSL_SAL_FREE(psks->identities.data);
    BSL_SAL_FREE(psks->binders.data);
    psks->identities.data = identities;
    psks->identities.size = 2;
    psks->binders.data = binders;
    psks->binders.size = 2;
    uint32_t addedIdentityLen = sizeof(uint16_t) + identities[0].identity.size + sizeof(uint32_t);
    uint32_t addedBinderLen = sizeof(uint8_t) + binders[0].binder.size;
    psks->identitySize.data += addedIdentityLen;
    psks->binderSize.data += addedBinderLen;
    psks->exLen.data += addedIdentityLen + addedBinderLen;

    memset(data, 0, bufSize);
    ASSERT_EQ(FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len), HITLS_SUCCESS);
    /* 3. Recalculate only the known identity binder; the server must skip the unknown identity. */
    uint32_t binderVectorLen = sizeof(uint16_t) + 2u * (sizeof(uint8_t) + binders[1].binder.size);
    ASSERT_TRUE(*len > binderVectorLen && binders[1].binder.size == 32u);
    ASSERT_EQ(VERIFY_CalcPskBinder(ctx, HITLS_HASH_SHA_256, true, (uint8_t *)(uintptr_t)g_rfc9973Psk, g_rfc9973PskLen,
                                   data, *len - binderVectorLen, data + *len - binders[1].binder.size,
                                   binders[1].binder.size),
              HITLS_SUCCESS);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
}

/** @
* @test UT_TLS_TLS13_RFC9973_MODE_API_FUNC_TC001
* @spec RFC 9973, local API profile mapping
* @title The existing TLS 1.3 key-exchange-mode API accepts the RFC 9973 profile bit with legacy mask semantics.
* @expect Legal bits round-trip, mixed unknown bits are masked, and values with no supported bit are rejected.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_MODE_API_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Create a TLS 1.3 configuration and check the mode 8 dependency on PSK-DHE. */
    FRAME_Init();
    HITLS_Config *config = NULL;
#ifdef HITLS_TLS_PROTO_DTLS13
    if (g_rfc9973Transport == BSL_UIO_UDP) {
        config = HITLS_CFG_NewDTLS13Config();
    } else
#endif
    {
        config = HITLS_CFG_NewTLS13Config();
    }
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetKeyExchMode(config, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK), HITLS_CONFIG_INVALID_SET);
    ASSERT_EQ(HITLS_CFG_SetKeyExchMode(config, TLS13_KE_MODE_PSK_ONLY | TLS13_KE_MODE_PSK_WITH_DHE |
                                                   TLS13_CERT_AUTH_WITH_EXTERNAL_PSK),
              HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_GetKeyExchMode(config),
              TLS13_KE_MODE_PSK_ONLY | TLS13_KE_MODE_PSK_WITH_DHE | TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
    /* 2. Reject unsupported-only values and mask unknown bits when a supported bit remains. */
    ASSERT_EQ(HITLS_CFG_SetKeyExchMode(config, 0), HITLS_CONFIG_INVALID_SET);
    ASSERT_EQ(HITLS_CFG_SetKeyExchMode(config, 16u), HITLS_CONFIG_INVALID_SET);
    ASSERT_EQ(HITLS_CFG_SetKeyExchMode(config, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK | 16u), HITLS_CONFIG_INVALID_SET);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_PSK_CIPHER_FUNC_TC001
* @brief Preserve cipher preference and use certificate fallback when the server declines the external PSK. An incompatible HRR cannot preserve the external PSK offer.
* @expect Certificate fallback succeeds without HRR; a selected PSK requires a matching hash.
* @precon nan
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_PSK_CIPHER_FUNC_TC001(int sessionPsk, int serverPreference, int helloRetry, int serverPsk,
                                                int cipherCase, int badBinder, int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Put a different cipher first and test both matching and mismatching PSK hashes. */
    FRAME_Init();
    HITLS_Config *clientConfig = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, !sessionPsk, false);
    HITLS_Config *serverConfig = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, false, !sessionPsk && serverPsk);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);
    uint16_t pskCipher = sessionPsk ? HITLS_AES_256_GCM_SHA384 : HITLS_AES_128_GCM_SHA256;
    uint16_t otherCipher = sessionPsk ? HITLS_AES_128_GCM_SHA256 : HITLS_AES_256_GCM_SHA384;
    if (cipherCase == 2) {
        otherCipher = HITLS_CHACHA20_POLY1305_SHA256; /* Different suite, same SHA-256 PSK hash. */
    }
    uint16_t clientSuites[] = {otherCipher, pskCipher};
    uint16_t serverSuites[] = {otherCipher, pskCipher};
    if (serverPreference) {
        clientSuites[0] = pskCipher;
        clientSuites[1] = otherCipher;
    }
    if (badBinder) {
        /* Select the PSK-compatible cipher so the corrupted binder is actually checked. */
        clientSuites[0] = serverSuites[0] = pskCipher;
        clientSuites[1] = serverSuites[1] = otherCipher;
    }
    ASSERT_EQ(HITLS_CFG_SetCipherServerPreference(serverConfig, serverPreference), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(clientConfig, clientSuites, 2), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(serverConfig, serverSuites, cipherCase == 1 ? 1 : 2), HITLS_SUCCESS);
    if (sessionPsk) {
        ASSERT_EQ(HITLS_CFG_SetPskUseSessionCallback(clientConfig, Rfc9973UseSha384Psk), HITLS_SUCCESS);
        if (serverPsk) {
            ASSERT_EQ(HITLS_CFG_SetPskFindSessionCallback(serverConfig, Rfc9973FindSha384Psk), HITLS_SUCCESS);
        }
    }
    client = FRAME_CreateLink(clientConfig, g_rfc9973Transport);
    server = FRAME_CreateLink(serverConfig, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    if (helloRetry) {
        Rfc9973ForceHelloRetryRequest(server);
    }
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, (void *)(uintptr_t)RFC9973_BAD_BINDER,
                          Rfc9973MutateHello};
    /* 2. Exercise selected-binder failure separately from a cipher hash mismatch. */
    if (badBinder) {
        RegisterWrapper(wrapper);
        ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
        Rfc9973AssertFatalAlert(server, ALERT_ILLEGAL_PARAMETER);
        goto EXIT;
    }
    /* Inspect the actual PSK and extension 33 fields before the client handles the response. */
    wrapper.ctrlState = helloRetry && cipherCase != 2 ? TRY_SEND_HELLO_RETRY_REQUEST : TRY_SEND_SERVER_HELLO;
    wrapper.userData =
        (void *)(uintptr_t)(cipherCase == 2 ? RFC9973_OBSERVE_SERVER_HELLO : RFC9973_OBSERVE_SERVER_WITHOUT_PSK);
    RegisterWrapper(wrapper);
    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    /* 3. Preserve cipher preference; PSK matching compares hashes, not suite IDs. */
    ASSERT_EQ(server->ssl->negotiatedInfo.cipherSuiteInfo.cipherSuite, otherCipher);
    if (cipherCase != 2) {
        if (helloRetry) {
            ASSERT_NE(ret, HITLS_SUCCESS);
            Rfc9973AssertFatalAlert(client, ALERT_HANDSHAKE_FAILURE);
        } else {
            ASSERT_EQ(ret, HITLS_SUCCESS);
            ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_DHE);
        }
        if (!helloRetry) {
            ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_DHE);
        }
        if (helloRetry) {
            ASSERT_TRUE(server->ssl->hsCtx->kxCtx->pskInfo13.psk == NULL);
        }
        goto EXIT;
    }
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
    ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
    if (helloRetry) {
        ASSERT_EQ(client->ssl->negotiatedInfo.negotiatedGroup, HITLS_EC_GROUP_SECP521R1);
    }

EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_HANDSHAKE_FUNC_TC001
* @spec RFC 9973 Sections 3-5
* @title Complete a certificate-authenticated TLS 1.3 handshake strengthened by an External PSK.
* @expect Both peers select profile bit 8 and complete the certificate flight and Finished validation.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_HANDSHAKE_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Configure matching external PSKs and certificates on both peers. */
    FRAME_Init();
    HITLS_Config *config = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    /* 2. Complete mode 8, verify it is not resumption, then exchange application data in both directions. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
    ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
    ASSERT_EQ(client->ssl->negotiatedInfo.isResume, false);
    ASSERT_EQ(server->ssl->negotiatedInfo.isResume, false);
    static const uint8_t clientData[] = "RFC9973 client application data";
    static const uint8_t serverData[] = "RFC9973 server application data";
    uint8_t readBuf[sizeof(clientData) > sizeof(serverData) ? sizeof(clientData) : sizeof(serverData)] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Write(client->ssl, clientData, sizeof(clientData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(clientData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(clientData));
    ASSERT_EQ(ConstTimeMemcmp(readBuf, clientData, sizeof(clientData)), 0xffffffffu);
    ASSERT_EQ(HITLS_Write(server->ssl, serverData, sizeof(serverData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(serverData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(serverData));
    ASSERT_EQ(ConstTimeMemcmp(readBuf, serverData, sizeof(serverData)), 0xffffffffu);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_SERVER_AUTH_FLIGHT_FUNC_TC001
* @spec RFC 9973 Section 4
* @title Observe the server Certificate and CertificateVerify in an RFC 9973 handshake.
* @expect Both mandatory server-authentication messages are sent and the handshake succeeds.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_SERVER_AUTH_FLIGHT_FUNC_TC001(int observedMessage, int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Select Certificate or CertificateVerify as the message to observe. */
    FRAME_Init();
    static const HITLS_HandshakeState states[] = {TRY_SEND_CERTIFICATE, TRY_SEND_CERTIFICATE_VERIFY};
    static const uint8_t messageTypes[] = {CERTIFICATE, CERTIFICATE_VERIFY};
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *config = NULL;
    ASSERT_TRUE(observedMessage >= 0 && (uint32_t)observedMessage < sizeof(states) / sizeof(states[0]));
    config = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, true);
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    RecWrapper wrapper = {states[observedMessage], REC_TYPE_HANDSHAKE, false,
                          (void *)(uintptr_t)messageTypes[observedMessage], Rfc9973ObserveHandshakeMessage};
    /* 2. Observe the selected authentication message and require a successful mode 8 handshake. */
    RegisterWrapper(wrapper);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_WIRE_FORMAT_FUNC_TC001
* @spec RFC 9973 Sections 3.1, 3.2, and 4
* @title Inspect the RFC 9973 ClientHello or ServerHello wire fields.
* @expect Extension 33 is empty; all required companion extensions are present; the only wire PSK mode is psk_dhe_ke.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_WIRE_FORMAT_FUNC_TC001(int observeServer, int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Choose ClientHello or ServerHello for field inspection. */
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *config = NULL;
    Rfc9973Mutation mutation = observeServer ? RFC9973_OBSERVE_SERVER_HELLO : RFC9973_OBSERVE_CLIENT_HELLO;
    /* 2. Check the wire fields inside the wrapper and require handshake success. */
    ASSERT_EQ(Rfc9973ConnectWithMutation(mutation, observeServer != 0, &client, &server, &config), HITLS_SUCCESS);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_MISSING_COMPANION_FUNC_TC001
* @spec RFC 9973 Section 3.1
* @title Remove one required companion extension from an RFC 9973 ClientHello.
* @expect The server aborts with fatal missing_extension.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_MISSING_COMPANION_FUNC_TC001(int missingField, int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Remove one required companion extension from ClientHello. */
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *config = NULL;
    Rfc9973Mutation mutation = (Rfc9973Mutation)(RFC9973_MISSING_KEY_SHARE + missingField);
    ASSERT_NE(Rfc9973ConnectWithMutation(mutation, false, &client, &server, &config), HITLS_SUCCESS);
    /* 2. Require the server to send fatal missing_extension. */
    Rfc9973AssertFatalAlert(server, ALERT_MISSING_EXTENSION);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_ILLEGAL_CLIENT_HELLO_FUNC_TC001
* @spec RFC 9973 Sections 3.1 and 4
* @title Inject a non-empty extension, early_data, or psk_ke-only offer into the RFC 9973 ClientHello.
* @expect The server aborts with fatal illegal_parameter.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_ILLEGAL_CLIENT_HELLO_FUNC_TC001(int mutationOffset, int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Select a malformed ClientHello offer or bad binder. */
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *config = NULL;
    static const Rfc9973Mutation mutations[] = {RFC9973_CLIENT_EXT_NONEMPTY, RFC9973_ONLY_PSK_KE,
                                                RFC9973_ADD_EARLY_DATA, RFC9973_BAD_BINDER};
    ASSERT_TRUE(mutationOffset >= 0 && (uint32_t)mutationOffset < sizeof(mutations) / sizeof(mutations[0]));
    ASSERT_NE(Rfc9973ConnectWithMutation(mutations[mutationOffset], false, &client, &server, &config), HITLS_SUCCESS);
    /* 2. Require the server to send fatal illegal_parameter. */
    Rfc9973AssertFatalAlert(server, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_ILLEGAL_SERVER_HELLO_FUNC_TC001
* @spec RFC 9973 Section 3.2
* @title Make extension 33 non-empty or remove a required ServerHello companion extension.
* @expect The client aborts with fatal illegal_parameter.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_ILLEGAL_SERVER_HELLO_FUNC_TC001(int mutationOffset, int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Select a nonempty extension 33 or a missing ServerHello companion. */
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *config = NULL;
    static const Rfc9973Mutation mutations[] = {RFC9973_SERVER_EXT_NONEMPTY, RFC9973_SERVER_MISSING_KEY_SHARE,
                                                RFC9973_SERVER_MISSING_PRE_SHARED_KEY};
    ASSERT_TRUE(mutationOffset >= 0 && (uint32_t)mutationOffset < sizeof(mutations) / sizeof(mutations[0]));
    ASSERT_NE(Rfc9973ConnectWithMutation(mutations[mutationOffset], true, &client, &server, &config), HITLS_SUCCESS);
    /* 2. Require the client to send fatal illegal_parameter. */
    Rfc9973AssertFatalAlert(client, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_UNSOLICITED_SERVER_EXTENSION_FUNC_TC001
* @spec RFC 9973 Section 5 and RFC 9846 Section 4.2
* @title Add extension 33 to ServerHello when the ordinary-PSK client did not offer it.
* @expect The client rejects the unsolicited extension with fatal unsupported_extension.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_UNSOLICITED_SERVER_EXTENSION_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Use PSK_WITH_DHE without a client extension 33 offer. */
    FRAME_Init();
    HITLS_Config *config = Rfc9973NewConfig(TLS13_KE_MODE_PSK_WITH_DHE, true, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    RecWrapper wrapper = {TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false,
                          (void *)(uintptr_t)RFC9973_ADD_CERT_WITH_EXTERNAL_PSK, Rfc9973MutateHello};
    /* 2. Inject extension 33 into ServerHello and require client unsupported_extension. */
    RegisterWrapper(wrapper);
    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    Rfc9973AssertFatalAlert(client, ALERT_UNSUPPORTED_EXTENSION);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_FALLBACK_FUNC_TC001
* @spec RFC 9973 negotiation and local profile policy
* @title Verify that RFC 9973 and ordinary PSK-DHE are independent selectable profiles.
* @expect A client allowing bit 2 and bit 8 accepts an ordinary bit-2 selection from a server that does not enable bit 8.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_FALLBACK_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Let the client allow mode 8 and PSK_WITH_DHE; let the server allow only PSK_WITH_DHE. */
    FRAME_Init();
    HITLS_Config *clientConfig =
        Rfc9973NewConfig(TLS13_KE_MODE_PSK_WITH_DHE | TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, false);
    HITLS_Config *serverConfig = Rfc9973NewConfig(TLS13_KE_MODE_PSK_WITH_DHE, false, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);
    client = FRAME_CreateLink(clientConfig, g_rfc9973Transport);
    server = FRAME_CreateLink(serverConfig, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    /* 2. Require both peers to complete using the shared PSK_WITH_DHE mode. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_KE_MODE_PSK_WITH_DHE);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_CERT_FALLBACK_FUNC_TC001
* @spec RFC 9973 negotiation and local profile policy
* @title Let a server without a matching External PSK decline extension 33.
* @expect The connection falls back to ordinary certificate authentication and selects profile bit 4.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_CERT_FALLBACK_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Offer mode 8 to a server with certificates but no external PSK callback. */
    FRAME_Init();
    HITLS_Config *clientConfig = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, false);
    HITLS_Config *serverConfig = Rfc9973NewConfig(TLS13_KE_MODE_PSK_WITH_DHE, false, false);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);
    client = FRAME_CreateLink(clientConfig, g_rfc9973Transport);
    server = FRAME_CreateLink(serverConfig, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    /* 2. Require certificate authentication on both peers when no PSK matches. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_DHE);
    ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_DHE);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_REJECT_RESUMPTION_IN_LIST_FUNC_TC001
* @spec RFC 9973 Section 5.1
* @title Add extension 33 to a ClientHello whose pre_shared_key list contains a valid resumption ticket.
* @expect The server aborts with fatal illegal_parameter instead of skipping or selecting the ticket.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_REJECT_RESUMPTION_IN_LIST_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Complete a certificate handshake and retain the issued ticket. */
    FRAME_Init();
    HITLS_Config *config = Rfc9973NewConfig(TLS13_KE_MODE_PSK_WITH_DHE, false, false);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    client = NULL;
    server = NULL;

    ASSERT_EQ(HITLS_CFG_SetKeyExchMode(config, TLS13_KE_MODE_PSK_WITH_DHE | TLS13_CERT_AUTH_WITH_EXTERNAL_PSK),
              HITLS_SUCCESS);
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false,
                          (void *)(uintptr_t)RFC9973_ADD_CERT_WITH_EXTERNAL_PSK, Rfc9973MutateHello};
    /* 2. Add extension 33 to the ticket offer and require rejection before PSK selection. */
    RegisterWrapper(wrapper);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    Rfc9973AssertFatalAlert(server, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    HITLS_SESS_Free(session);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_RESUMPTION_FUNC_TC001
* @spec RFC 9973 Section 5.1
* @title Resume an RFC 9973 session after the mode 8 configuration is normalized to PSK-DHE.
* @expect Session resumption uses PSK_WITH_DHE after the external PSK callback is removed.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_RESUMPTION_FUNC_TC001(int offerPskKe, int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Complete mode 8 and retain its ticket under the selected resumption-mode configuration. */
    FRAME_Init();
    uint32_t mode = TLS13_CERT_AUTH_WITH_EXTERNAL_PSK |
                    (offerPskKe == 1 ? TLS13_KE_MODE_PSK_ONLY : (offerPskKe == 2 ? TLS13_KE_MODE_PSK_WITH_DHE : 0));
    HITLS_Config *config = Rfc9973NewConfig(mode, true, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    bool isReused = false;
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    client = NULL;
    server = NULL;

    /* 2. Remove the external offer. Ticket resumption needs an explicitly shared PSK_ONLY or PSK_WITH_DHE mode. */
    ASSERT_EQ(HITLS_CFG_SetPskClientCallback(config, NULL), HITLS_SUCCESS);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);
    uint32_t expectedMode = TLS13_KE_MODE_PSK_WITH_DHE;
    ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, expectedMode);
    ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, expectedMode);
EXIT:
    ClearWrapper();
    HITLS_SESS_Free(session);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_HRR_FUNC_TC001
* @spec RFC 9973 Section 5
* @title Complete RFC 9973 negotiation across a HelloRetryRequest.
* @expect CH1 and CH2 contain extension 33, the HRR omits it, and the final handshake selects profile bit 8.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_HRR_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Configure matching mode 8 credentials on both peers. */
    FRAME_Init();
    HITLS_Config *config = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    /* 2. Force a different key-share group and require mode 8 to survive HRR. */
    Rfc9973ForceHelloRetryRequest(server);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.negotiatedGroup, HITLS_EC_GROUP_SECP521R1);
    ASSERT_EQ(server->ssl->negotiatedInfo.negotiatedGroup, HITLS_EC_GROUP_SECP521R1);
    ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
    ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_HRR_EXTENSION_FUNC_TC001
* @spec RFC 9973 Section 5
* @title Inject extension 33 into a HelloRetryRequest.
* @expect The client aborts with fatal illegal_parameter.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_HRR_EXTENSION_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Configure mode 8 and force a HelloRetryRequest. */
    FRAME_Init();
    HITLS_Config *config = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    Rfc9973ForceHelloRetryRequest(server);
    RecWrapper wrapper = {TRY_SEND_HELLO_RETRY_REQUEST, REC_TYPE_HANDSHAKE, false,
                          (void *)(uintptr_t)RFC9973_ADD_CERT_WITH_EXTERNAL_PSK, Rfc9973MutateHello};
    /* 2. Insert extension 33 into HRR and require client illegal_parameter. */
    RegisterWrapper(wrapper);
    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    Rfc9973AssertFatalAlert(client, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_SECOND_CLIENT_HELLO_FUNC_TC001
* @spec RFC 9973 Section 5
* @title Change the presence of extension 33 between CH1 and CH2.
* @expect The server aborts with fatal illegal_parameter.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_SECOND_CLIENT_HELLO_FUNC_TC001(int addOnSecondClientHello, int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Choose whether extension 33 is absent or present in ClientHello1. */
    FRAME_Init();
    uint32_t mode = addOnSecondClientHello ? TLS13_KE_MODE_PSK_WITH_DHE : TLS13_CERT_AUTH_WITH_EXTERNAL_PSK;
    HITLS_Config *config = Rfc9973NewConfig(mode, true, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    Rfc9973SecondClientHelloMutation mutation = {0, addOnSecondClientHello != 0};
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    if (addOnSecondClientHello) {
        ASSERT_EQ(HITLS_CFG_SetKeyExchMode(&server->ssl->config.tlsConfig,
                                           TLS13_KE_MODE_PSK_WITH_DHE | TLS13_CERT_AUTH_WITH_EXTERNAL_PSK),
                  HITLS_SUCCESS);
    }
    Rfc9973ForceHelloRetryRequest(server);
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, &mutation, Rfc9973MutateSecondClientHello};
    /* 2. Change its presence only in ClientHello2 and require server illegal_parameter. */
    RegisterWrapper(wrapper);
    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(mutation.clientHelloCount >= 2);
    Rfc9973AssertFatalAlert(server, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_WRONG_MESSAGE_FUNC_TC001
* @spec RFC 9973 Section 5
* @title Inject extension 33 into a forbidden TLS 1.3 handshake message.
* @expect The receiving client recognizes the extension and aborts with fatal illegal_parameter.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_WRONG_MESSAGE_FUNC_TC001(int wrongMessage, int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Choose a forbidden server message and enable client authentication for CertificateRequest. */
    FRAME_Init();
    ASSERT_TRUE(wrongMessage >= RFC9973_WRONG_ENCRYPTED_EXTENSIONS && wrongMessage <= RFC9973_WRONG_NEW_SESSION_TICKET);
    HITLS_Config *config = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config != NULL);
    config->isSupportClientVerify = true;
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    static const HITLS_HandshakeState states[] = {TRY_SEND_ENCRYPTED_EXTENSIONS, TRY_SEND_CERTIFICATE_REQUEST,
                                                  TRY_SEND_CERTIFICATE, TRY_SEND_NEW_SESSION_TICKET};
    RecWrapper wrapper = {states[wrongMessage], REC_TYPE_HANDSHAKE, false, (void *)(uintptr_t)wrongMessage,
                          Rfc9973InjectWrongMessageExtension};
    /* 2. Insert extension 33 into that message and require client illegal_parameter. */
    RegisterWrapper(wrapper);
    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    Rfc9973AssertFatalAlert(client, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_EXTERNAL_PSK_AGE_FUNC_TC001
* @spec RFC 9973 Section 5.1
* @title Send a valid External PSK binder with a nonzero obfuscated_ticket_age.
* @expect The server ignores the age and completes the RFC 9973 handshake.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_EXTERNAL_PSK_AGE_FUNC_TC001(int age, int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Configure mode 8 with the shared external PSK. */
    FRAME_Init();
    HITLS_Config *config = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, (void *)(uintptr_t)(uint32_t)age,
                          Rfc9973SetExternalPskAge};
    /* 2. Change the age and recalculate its binder; the handshake must still succeed. */
    RegisterWrapper(wrapper);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
    ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_MUTUAL_AUTH_FUNC_TC001
* @spec RFC 9973 Section 5.2
* @title Request and complete client certificate authentication in an RFC 9973 handshake.
* @expect CertificateRequest is permitted despite PSK use, and both peers complete with profile bit 8.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_MUTUAL_AUTH_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Configure matching external PSKs and enable client certificate verification. */
    FRAME_Init();
    HITLS_Config *config = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config != NULL);
    config->isSupportClientVerify = true;
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    /* 2. Require mutual certificate authentication to complete with mode 8. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
    ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_PSK_KE_ADVERTISEMENT_FUNC_TC001
* @spec RFC 9973 Section 5.1
* @title Configure psk_ke as an additional future-resumption mode.
* @expect ClientHello sends psk_dhe_ke followed by psk_ke, while the initial handshake still selects RFC 9973 bit 8.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_PSK_KE_ADVERTISEMENT_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Allow PSK_ONLY alongside mode 8 on both peers. */
    FRAME_Init();
    HITLS_Config *config = Rfc9973NewConfig(TLS13_KE_MODE_PSK_ONLY | TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config != NULL);
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false,
                          (void *)(uintptr_t)RFC9973_OBSERVE_CLIENT_HELLO_WITH_PSK_KE, Rfc9973MutateHello};
    /* 2. Check that psk_ke and psk_dhe_ke are advertised while the initial handshake still selects mode 8. */
    RegisterWrapper(wrapper);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_PROFILE_ISOLATION_FUNC_TC001
* @spec RFC 9973 profile negotiation
* @title Let a server that has not enabled bit 8 select ordinary External-PSK-DHE.
* @expect The client accepts the ordinary External-PSK-DHE profile as a fallback.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_PROFILE_ISOLATION_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Let the client allow only mode 8 and the server allow only PSK_WITH_DHE. */
    FRAME_Init();
    HITLS_Config *clientConfig = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, false);
    HITLS_Config *serverConfig = Rfc9973NewConfig(TLS13_KE_MODE_PSK_WITH_DHE, false, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);
    client = FRAME_CreateLink(clientConfig, g_rfc9973Transport);
    server = FRAME_CreateLink(serverConfig, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    /* 2. The server may omit extension 33 and use ordinary External-PSK-DHE. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_KE_MODE_PSK_WITH_DHE);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_SELECTED_IDENTITY_FUNC_TC001
* @spec RFC 9973 Section 5.1 and RFC 9846 Section 4.2.11
* @title Make ServerHello select an External PSK identity that was not offered.
* @expect The client aborts with fatal illegal_parameter.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_SELECTED_IDENTITY_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Offer one external identity and make ServerHello select index 1. */
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *config = NULL;
    ASSERT_NE(
        Rfc9973ConnectWithMutation(RFC9973_SERVER_SELECTED_IDENTITY_OUT_OF_RANGE, true, &client, &server, &config),
        HITLS_SUCCESS);
    /* 2. Require the client to reject the out-of-range selected identity. */
    Rfc9973AssertFatalAlert(client, ALERT_ILLEGAL_PARAMETER);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_SELECT_SECOND_EXTERNAL_PSK_FUNC_TC001
* @spec RFC 9973 Section 5.1
* @title Offer an unknown External PSK first and a valid External PSK second.
* @expect The server ignores the unknown first identity, validates only the second binder, and selects index 1.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_SELECT_SECOND_EXTERNAL_PSK_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Reset lookup counters and configure one known external PSK. */
    FRAME_Init();
    g_rfc9973ServerPskCbCalls = 0;
    g_rfc9973ServerPskCbMatches = 0;
    HITLS_Config *config = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Rfc9973SelectSecondExternalPsk};
    /* 2. Prepend an unknown identity, then inspect server selection and callback counts. */
    RegisterWrapper(wrapper);
    /* Stop after the server has consumed ClientHello. The frame mutation changes the wire list only;
     * the client's private PSK metadata still contains one identity and cannot consume selected_identity=1. */
    int32_t ret = FRAME_CreateConnection(client, server, false, TRY_RECV_SERVER_HELLO);
    ASSERT_EQ(g_rfc9973ServerPskCbCalls, 2);
    ASSERT_EQ(g_rfc9973ServerPskCbMatches, 1);
    /* The client-side frame model has one local PSK entry and therefore cannot
     * consume selected_identity=1 after the server sends ServerHello.  The
     * normative assertion is the server-side selection and binder filtering;
     * the transport return value is intentionally not used here. */
    (void)ret;
    ASSERT_EQ(server->ssl->hsCtx->kxCtx->pskInfo13.selectIndex, 1);
    ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_REJECT_TRAILING_RESUMPTION_FUNC_TC001
* @spec RFC 9973 Section 5.1
* @title Handle a resumption ticket according to the first usable PSK in the offered list.
* @expect A leading ticket is rejected with illegal_parameter; a trailing ticket is not scanned after an external PSK.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_REJECT_TRAILING_RESUMPTION_FUNC_TC001(int ticketFirst, int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Obtain a real ticket from an initial certificate handshake. */
    FRAME_Init();
    HITLS_Config *config = Rfc9973NewConfig(TLS13_KE_MODE_PSK_WITH_DHE, false, false);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    uint8_t *ticket = NULL;
    uint32_t ticketLen = 0;
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);
    ASSERT_EQ(SESS_GetTicket(session, &ticket, &ticketLen), HITLS_SUCCESS);
    ASSERT_TRUE(ticket != NULL && ticketLen != 0);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    client = NULL;
    server = NULL;

    ASSERT_EQ(HITLS_CFG_SetKeyExchMode(config,
        TLS13_KE_MODE_PSK_WITH_DHE | TLS13_CERT_AUTH_WITH_EXTERNAL_PSK), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetPskClientCallback(config, Rfc9973ClientPskCb), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetPskServerCallback(config, Rfc9973ServerPskCb), HITLS_SUCCESS);
    Rfc9973TicketMutation mutation = {ticket, ticketLen, ticketFirst != 0};
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, &mutation, Rfc9973InsertTicketIdentity};
    /* 2. Insert the ticket at either position and preserve the first-usable-PSK behavior. */
    RegisterWrapper(wrapper);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    g_rfc9973ServerPskCbCalls = 0;
    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    if (ticketFirst) {
        ASSERT_NE(ret, HITLS_SUCCESS);
        ASSERT_EQ(g_rfc9973ServerPskCbCalls, 1);
        Rfc9973AssertFatalAlert(server, ALERT_ILLEGAL_PARAMETER);
        Rfc9973AssertPeerReceivesIllegalParameter(server, client);
    } else {
        ASSERT_EQ(ret, HITLS_SUCCESS);
        ASSERT_EQ(g_rfc9973ServerPskCbCalls, 1);
        ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_EXTERNAL_PSK);
    }
EXIT:
    g_rfc9973ServerPskCbCalls = 0;
    ClearWrapper();
    HITLS_SESS_Free(session);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_CLIENT_OFFER_FUNC_TC001
* @spec RFC 9973 Section 5.1
* @title Offer any available external PSK under mode 8 and exclude stored tickets.
* @expect Only eligible external PSKs advertise extension 33, without tickets; other paths remain usable.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_CLIENT_OFFER_FUNC_TC001(int pskLen, int mode, int withTicket, int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Optionally obtain a ticket, then configure the external PSK length and allowed modes. */
    FRAME_Init();
    HITLS_Config *config = Rfc9973NewConfig((uint32_t)mode, true, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    ASSERT_TRUE(config != NULL);
    if (withTicket) {
        client = FRAME_CreateLink(config, g_rfc9973Transport);
        server = FRAME_CreateLink(config, g_rfc9973Transport);
        ASSERT_TRUE(client != NULL && server != NULL);
        ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
        session = HITLS_GetDupSession(client->ssl);
        ASSERT_TRUE(session != NULL && HITLS_SESS_HasTicket(session));
        FRAME_FreeLink(client);
        FRAME_FreeLink(server);
        client = NULL;
        server = NULL;
    }
    g_rfc9973PskLen = (uint32_t)pskLen;
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    if (session != NULL) {
        ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    }
    /* 2. Derive expected offer contents and verify the selected mode or no-intersection failure. */
    bool eligible = pskLen > 0; /* A zero legacy callback result still means no PSK. */
    bool sendCertWithExternalPsk = eligible && !withTicket;
    bool allowOrdinaryPsk = ((uint32_t)mode & (TLS13_KE_MODE_PSK_WITH_DHE | TLS13_CERT_AUTH_WITH_EXTERNAL_PSK)) != 0;
    uint32_t expected[] = {sendCertWithExternalPsk, (uint32_t)(withTicket + eligible)};
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, expected, Rfc9973ObserveClientOffer};
    RegisterWrapper(wrapper);
    if (withTicket && !eligible && !allowOrdinaryPsk) {
        ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
        Rfc9973AssertFatalAlert(server, ALERT_HANDSHAKE_FAILURE);
        goto EXIT;
    }
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    uint32_t selectedMode = sendCertWithExternalPsk ? TLS13_CERT_AUTH_WITH_EXTERNAL_PSK :
                                       ((withTicket || (pskLen > 0 && allowOrdinaryPsk)) ? TLS13_KE_MODE_PSK_WITH_DHE :
                                                                                           TLS13_CERT_AUTH_WITH_DHE);
    ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, selectedMode);
    ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, selectedMode);
    ASSERT_EQ(client->ssl->negotiatedInfo.isResume, withTicket);
    ASSERT_EQ(server->ssl->negotiatedInfo.isResume, withTicket);
EXIT:
    g_rfc9973PskLen = RFC9973_TEST_PSK_LEN;
    ClearWrapper();
    HITLS_SESS_Free(session);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_HRR_FALLBACK_FUNC_TC001
* @spec RFC 8446 Section 4.1.4; RFC 9973 Section 5
* @title Reject an HRR cipher whose hash differs from the external PSK hash.
* @expect The client sends handshake_failure before ClientHello2; the server has no selected PSK.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_HRR_FALLBACK_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    FRAME_Init();
    HITLS_Config *cConfig = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, false);
    HITLS_Config *sConfig = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, false, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(cConfig != NULL && sConfig != NULL);
    /* 1. Offer a SHA-256 PSK but make the server select SHA-384, which cannot use that PSK. */
    uint16_t clientSuites[] = {HITLS_AES_128_GCM_SHA256, HITLS_AES_256_GCM_SHA384};
    uint16_t serverSuites[] = {HITLS_AES_256_GCM_SHA384};
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(cConfig, clientSuites, sizeof(clientSuites) / sizeof(uint16_t)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(sConfig, serverSuites, sizeof(serverSuites) / sizeof(uint16_t)), HITLS_SUCCESS);
    client = FRAME_CreateLink(cConfig, g_rfc9973Transport);
    server = FRAME_CreateLink(sConfig, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    /* 2. Observe the initial external PSK offer, then force an incompatible HRR. */
    uint32_t expected[] = {1, 1};
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, expected, Rfc9973ObserveClientOffer};
    RegisterWrapper(wrapper);
    Rfc9973ForceHelloRetryRequest(server);
    /* 3. Reject the HRR hash before sending ClientHello2, even though the server declines PSK. */
    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    Rfc9973AssertFatalAlert(client, ALERT_HANDSHAKE_FAILURE);
    ASSERT_EQ(server->ssl->negotiatedInfo.cipherSuiteInfo.hashAlg, HITLS_HASH_SHA_384);
    ASSERT_TRUE(server->ssl->hsCtx->kxCtx->pskInfo13.psk == NULL);

EXIT:
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(cConfig);
    HITLS_CFG_FreeConfig(sConfig);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_HRR_RECOMPUTE_FUNC_TC001
* @spec RFC 9973 Section 5
* @title Rebuild the external PSK offer after HRR without changing its identity or hash.
* @expect Stable callbacks preserve extension 33; changed identities/hashes fail locally, changed keys fail binder checks.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_HRR_RECOMPUTE_FUNC_TC001(int sessionPsk, int incompatible, int change, int pskLen,
                                                   int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Configure stable or changing callbacks and a compatible or incompatible HRR cipher. */
    FRAME_Init();
    g_rfc9973PskLen = (uint32_t)pskLen;
    g_rfc9973RecomputeCalls = 0;
    g_rfc9973RecomputeHash = HITLS_HASH_BUTT;
    g_rfc9973RecomputeChange = change;
    HITLS_Config *cConfig = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, false, false);
    HITLS_Config *sConfig = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, false, !sessionPsk);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(cConfig != NULL && sConfig != NULL);
    uint16_t pskCipher = sessionPsk ? HITLS_AES_256_GCM_SHA384 : HITLS_AES_128_GCM_SHA256;
    uint16_t otherCipher = sessionPsk ? HITLS_AES_128_GCM_SHA256 : HITLS_AES_256_GCM_SHA384;
    uint16_t clientSuites[] = {pskCipher, otherCipher};
    uint16_t serverCipher = incompatible ? otherCipher : pskCipher;
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(cConfig, clientSuites, 2), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(sConfig, &serverCipher, 1), HITLS_SUCCESS);
    if (sessionPsk) {
        ASSERT_EQ(HITLS_CFG_SetPskUseSessionCallback(cConfig, Rfc9973RecomputeSessionPsk), HITLS_SUCCESS);
        ASSERT_EQ(HITLS_CFG_SetPskFindSessionCallback(sConfig, Rfc9973FindSha384Psk), HITLS_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_CFG_SetPskClientCallback(cConfig, Rfc9973RecomputeLegacyPsk), HITLS_SUCCESS);
    }
    client = FRAME_CreateLink(cConfig, g_rfc9973Transport);
    server = FRAME_CreateLink(sConfig, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    uint32_t expected[] = {1, 1};
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, expected, Rfc9973ObserveClientOffer};
    RegisterWrapper(wrapper);
    Rfc9973ForceHelloRetryRequest(server);
    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    /* 2. A hash mismatch stops at HRR; otherwise the existing callback path prepares ClientHello2. */
    if (incompatible) {
        ASSERT_EQ(g_rfc9973RecomputeCalls, 1u);
        ASSERT_NE(ret, HITLS_SUCCESS);
        Rfc9973AssertFatalAlert(client, ALERT_HANDSHAKE_FAILURE);
        goto EXIT;
    }
    ASSERT_EQ(g_rfc9973RecomputeCalls, 2u);
    if (sessionPsk) {
        ASSERT_EQ(g_rfc9973RecomputeHash, HITLS_HASH_SHA_384);
    }
    if (change == 5) {
        /* A changed key passes client preparation, then fails the server binder check. */
        ASSERT_NE(ret, HITLS_SUCCESS);
        Rfc9973AssertFatalAlert(server, ALERT_ILLEGAL_PARAMETER);
    } else if (change != 0) {
        ASSERT_NE(ret, HITLS_SUCCESS);
        Rfc9973AssertFatalAlert(client, ALERT_INTERNAL_ERROR);
    } else {
        ASSERT_EQ(ret, HITLS_SUCCESS);
        uint32_t mode = TLS13_CERT_AUTH_WITH_EXTERNAL_PSK;
        ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, mode);
        ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, mode);
        ASSERT_EQ(client->ssl->negotiatedInfo.negotiatedGroup, HITLS_EC_GROUP_SECP521R1);
    }
EXIT:
    g_rfc9973PskLen = RFC9973_TEST_PSK_LEN;
    ClearWrapper();
    g_rfc9973RecomputeCalls = 0;
    g_rfc9973RecomputeChange = 0;
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(cConfig);
    HITLS_CFG_FreeConfig(sConfig);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_RESUME_PSK_MODES_FUNC_TC001
* @spec RFC 8446 Sections 4.2.9 and 4.2.11
* @title Check exchange modes after selecting an external PSK followed by a valid ticket.
* @expect A bad binder or absent mode intersection aborts; a matching mode selects the first identity once.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_RESUME_PSK_MODES_FUNC_TC001(int serverMode, int validBinder, int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    FRAME_Init();
    HITLS_Config *config = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    ASSERT_TRUE(config != NULL);

    /* 1. Complete a mode 8 handshake to obtain a resumption ticket. */
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL && HITLS_SESS_HasTicket(session));
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    client = NULL;
    server = NULL;

    /* 2. Offer the ticket without extension 33, then prepend an external identity. */
    ASSERT_EQ(HITLS_CFG_SetPskClientCallback(config, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetKeyExchMode(config, TLS13_KE_MODE_PSK_WITH_DHE), HITLS_SUCCESS);
    Rfc9973PrependMutation mutation = {0};
    mutation.validBinder = validBinder != 0;
    mutation.masterKeyLen = sizeof(mutation.masterKey);
    ASSERT_EQ(HITLS_SESS_GetMasterKey(session, mutation.masterKey, &mutation.masterKeyLen), HITLS_SUCCESS);
    uint32_t pskCbCallsBefore = g_rfc9973ServerPskCbCalls;
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, &mutation, Rfc9973PrependExternalIdentity};
    RegisterWrapper(wrapper);
    client = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_EQ(HITLS_CFG_SetKeyExchMode(config, (uint32_t)serverMode), HITLS_SUCCESS);
    server = FRAME_CreateLink(config, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);
    /* 3. Inspect server selection: reject a bad binder or disjoint modes, and perform one external lookup. */
    int32_t ret = FRAME_CreateConnection(client, server, false, TRY_RECV_SERVER_HELLO);
    bool hasCommonDhe = ((uint32_t)serverMode & TLS13_KE_MODE_PSK_WITH_DHE) != 0;
    if (!hasCommonDhe) {
        ASSERT_EQ(ret, HITLS_SUCCESS);
        ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_CERT_AUTH_WITH_DHE);
    } else if (!validBinder) {
        ASSERT_NE(ret, HITLS_SUCCESS);
        Rfc9973AssertFatalAlert(server, ALERT_DECRYPT_ERROR);
    } else {
        ASSERT_EQ(ret, HITLS_SUCCESS);
        ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_KE_MODE_PSK_WITH_DHE);
        ASSERT_EQ(server->ssl->negotiatedInfo.isResume, false);
        ASSERT_EQ(server->ssl->hsCtx->kxCtx->pskInfo13.selectIndex, 0);
    }
    ASSERT_EQ(g_rfc9973ServerPskCbCalls, hasCommonDhe ? pskCbCallsBefore + 1 : pskCbCallsBefore);
EXIT:
    ClearWrapper();
    HITLS_SESS_Free(session);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_PSK_MODE_INTERSECTION_FUNC_TC001
* @spec RFC 8446 Sections 4.2.9 and 4.2.11
* @title Enforce the mode intersection for a selected PSK while preserving certificate fallback without a match.
* @expect Matching PSK modes use the common mode; disjoint or unknown PSKs fall back to certificate authentication.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_PSK_MODE_INTERSECTION_FUNC_TC001(int clientMode, int serverMode, int matchPsk, int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Configure client/server PSK mode sets and whether the server knows the identity. */
    FRAME_Init();
    HITLS_Config *clientConfig = Rfc9973NewConfig((uint32_t)clientMode, true, false);
    HITLS_Config *serverConfig = Rfc9973NewConfig((uint32_t)serverMode, false, matchPsk != 0);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);
    client = FRAME_CreateLink(clientConfig, g_rfc9973Transport);
    server = FRAME_CreateLink(serverConfig, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    /* 2. A PSK with disjoint modes is ignored and the handshake falls back to certificate authentication. */
    ASSERT_EQ(ret, HITLS_SUCCESS);
    uint32_t expectedMode =
        (matchPsk && (clientMode & serverMode) != 0) ? (uint32_t)(clientMode & serverMode) :
        TLS13_CERT_AUTH_WITH_DHE;
    ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, expectedMode);
    ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, expectedMode);
EXIT:
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_DUPLICATE_CIPHERS_FUNC_TC001
* @title Repeated offered ciphers do not repeat the same external PSK lookup.
* @expect The server keeps SHA-384 without calling the SHA-256 PSK callback; certificate fallback succeeds.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_DUPLICATE_CIPHERS_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Offer duplicate SHA-256 suites after SHA-384 and make the PSK lookup miss. */
    FRAME_Init();
    HITLS_Config *clientConfig = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, true, false);
    HITLS_Config *serverConfig = Rfc9973NewConfig(TLS13_CERT_AUTH_WITH_EXTERNAL_PSK, false, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);
    uint16_t suites[] = {HITLS_AES_256_GCM_SHA384, HITLS_AES_128_GCM_SHA256, HITLS_AES_128_GCM_SHA256,
                         HITLS_AES_128_GCM_SHA256};
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(clientConfig, suites, 4), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(serverConfig, suites, 2), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetPskServerCallback(serverConfig, Rfc9973UnknownPskCb), HITLS_SUCCESS);
    client = FRAME_CreateLink(clientConfig, g_rfc9973Transport);
    server = FRAME_CreateLink(serverConfig, g_rfc9973Transport);
    ASSERT_TRUE(client != NULL && server != NULL);
    g_rfc9973ServerPskCbCalls = 0;
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->negotiatedInfo.cipherSuiteInfo.cipherSuite, HITLS_AES_256_GCM_SHA384);
    /* 2. Keep SHA-384 and skip the SHA-256 callback, regardless of duplicate later suites. */
    ASSERT_EQ(g_rfc9973ServerPskCbCalls, 0u);
EXIT:
    g_rfc9973ServerPskCbCalls = 0;
    ClearWrapper();
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC9973_SERVER_CERT_REQUIRED_FUNC_TC001
* @title Do not select mode 8 without a server certificate and private key.
* @expect Both peers use their shared PSK_WITH_DHE mode.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC9973_SERVER_CERT_REQUIRED_FUNC_TC001(int transport)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    if (transport == BSL_UIO_UDP) {
        SKIP_TEST();
    }
#endif
    g_rfc9973Transport = (BSL_UIO_TransportType)transport;
    /* 1. Enable both modes, but load certificates only on the client. */
    FRAME_Init();
    uint32_t modes = TLS13_CERT_AUTH_WITH_EXTERNAL_PSK | TLS13_KE_MODE_PSK_WITH_DHE;
    HITLS_Config *clientConfig = Rfc9973NewConfig(modes, true, false);
    HITLS_Config *serverConfig = Rfc9973NewConfig(modes, false, true);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);
    client = FRAME_CreateLink(clientConfig, g_rfc9973Transport);
    server = FRAME_CreateLinkBase(serverConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL && server != NULL);
    /* 2. A signature-algorithm list alone must not make the server select certificate authentication. */
    ASSERT_TRUE(server->ssl->config.tlsConfig.signAlgorithmsSize != 0);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_EQ(server->ssl->negotiatedInfo.tls13BasicKeyExMode, TLS13_KE_MODE_PSK_WITH_DHE);
EXIT:
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
}
/* END_CASE */

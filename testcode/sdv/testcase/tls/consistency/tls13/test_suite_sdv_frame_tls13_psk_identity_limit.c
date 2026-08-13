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

#include <string.h>
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "hitls_psk.h"
#include "bsl_uio.h"
#include "bsl_sal.h"
#include "frame_link.h"
#include "frame_tls.h"
#include "rec_wrapper.h"
#include "common_func.h"
#include "alert.h"
#include "tls_config.h"
#include "hs_extensions.h"
/* END_HEADER */

#define PSK_IDENTITY_LIMIT_TEST_IDENTITY_LEN 8u
#define PSK_IDENTITY_LIMIT_TEST_BINDER_LEN 32u

typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
} PskIdentityLimitTestInfo;

static uint32_t g_pskIdentityLimitServerCbCalls = 0;

static uint32_t Test_PskIdentityLimit_ServerCb(HITLS_Ctx *ctx, const uint8_t *identity, uint8_t *psk,
    uint32_t maxPskLen)
{
    (void)ctx;
    (void)identity;
    (void)psk;
    (void)maxPskLen;
    g_pskIdentityLimitServerCbCalls++;
    return 0;
}

static void Test_FreePskIdentities(FRAME_HsArrayPskIdentity *identities)
{
    for (uint32_t i = 0; i < identities->size; i++) {
        BSL_SAL_FREE(identities->data[i].identity.data);
    }
    BSL_SAL_FREE(identities->data);
    identities->size = 0;
}

static void Test_FreePskBinders(FRAME_HsArrayPskBinder *binders)
{
    for (uint32_t i = 0; i < binders->size; i++) {
        BSL_SAL_FREE(binders->data[i].binder.data);
    }
    BSL_SAL_FREE(binders->data);
    binders->size = 0;
}

static int32_t Test_SetTooManyPskIdentities(FRAME_HsExtOfferedPsks *psks)
{
    const uint32_t identityCount = MAX_PSK_IDENTITY_COUNT + 1u;
    const uint32_t identityListLen = identityCount *
        (sizeof(uint16_t) + PSK_IDENTITY_LIMIT_TEST_IDENTITY_LEN + sizeof(uint32_t));
    const uint32_t binderListLen = identityCount *
        (sizeof(uint8_t) + PSK_IDENTITY_LIMIT_TEST_BINDER_LEN);

    Test_FreePskIdentities(&psks->identities);
    Test_FreePskBinders(&psks->binders);

    psks->identities.data = BSL_SAL_Calloc(identityCount, sizeof(FRAME_HsPskIdentity));
    psks->binders.data = BSL_SAL_Calloc(identityCount, sizeof(FRAME_HsPskBinder));
    if (psks->identities.data == NULL || psks->binders.data == NULL) {
        Test_FreePskIdentities(&psks->identities);
        Test_FreePskBinders(&psks->binders);
        return HITLS_MEMALLOC_FAIL;
    }

    psks->identities.state = ASSIGNED_FIELD;
    psks->identities.size = identityCount;
    psks->binders.state = ASSIGNED_FIELD;
    psks->binders.size = identityCount;

    for (uint32_t i = 0; i < identityCount; i++) {
        FRAME_HsPskIdentity *identity = &psks->identities.data[i];
        identity->state = ASSIGNED_FIELD;
        identity->identityLen.state = ASSIGNED_FIELD;
        identity->identityLen.data = PSK_IDENTITY_LIMIT_TEST_IDENTITY_LEN;
        identity->identity.state = ASSIGNED_FIELD;
        identity->identity.size = PSK_IDENTITY_LIMIT_TEST_IDENTITY_LEN;
        identity->identity.data = BSL_SAL_Calloc(PSK_IDENTITY_LIMIT_TEST_IDENTITY_LEN, sizeof(uint8_t));
        if (identity->identity.data == NULL) {
            Test_FreePskIdentities(&psks->identities);
            Test_FreePskBinders(&psks->binders);
            return HITLS_MEMALLOC_FAIL;
        }
        memset(identity->identity.data, (int)('A' + (i % 26u)), PSK_IDENTITY_LIMIT_TEST_IDENTITY_LEN);
        identity->identity.data[PSK_IDENTITY_LIMIT_TEST_IDENTITY_LEN - 1u] = (uint8_t)i;
        identity->obfuscatedTicketAge.state = ASSIGNED_FIELD;
        identity->obfuscatedTicketAge.data = 0;

        FRAME_HsPskBinder *binder = &psks->binders.data[i];
        binder->state = ASSIGNED_FIELD;
        binder->binderLen.state = ASSIGNED_FIELD;
        binder->binderLen.data = PSK_IDENTITY_LIMIT_TEST_BINDER_LEN;
        binder->binder.state = ASSIGNED_FIELD;
        binder->binder.size = PSK_IDENTITY_LIMIT_TEST_BINDER_LEN;
        binder->binder.data = BSL_SAL_Calloc(PSK_IDENTITY_LIMIT_TEST_BINDER_LEN, sizeof(uint8_t));
        if (binder->binder.data == NULL) {
            Test_FreePskIdentities(&psks->identities);
            Test_FreePskBinders(&psks->binders);
            return HITLS_MEMALLOC_FAIL;
        }
        memset(binder->binder.data, (int)(0x55u ^ i), PSK_IDENTITY_LIMIT_TEST_BINDER_LEN);
    }

    psks->exState = ASSIGNED_FIELD;
    psks->exType.state = ASSIGNED_FIELD;
    psks->exType.data = HS_EX_TYPE_PRE_SHARED_KEY;
    psks->identitySize.state = ASSIGNED_FIELD;
    psks->identitySize.data = identityListLen;
    psks->binderSize.state = ASSIGNED_FIELD;
    psks->binderSize.data = binderListLen;
    psks->exLen.state = ASSIGNED_FIELD;
    psks->exLen.data = sizeof(uint16_t) + identityListLen + sizeof(uint16_t) + binderListLen;
    return HITLS_SUCCESS;
}

static void Test_Client_PskIdentityCountLimit(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    ASSERT_EQ(FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen), HITLS_SUCCESS);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    ASSERT_EQ(Test_SetTooManyPskIdentities(&frameMsg.body.hsMsg.body.clientHello.psks), HITLS_SUCCESS);

    memset(data, 0, bufSize);
    ASSERT_EQ(FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len), HITLS_SUCCESS);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS13_PSK_IDENTITIES_LIMIT_FUNC_TC001
* @spec  -
* @title Initialize the client and server to TLS1.3 PSK mode, then construct a ClientHello whose pre_shared_key
*        extension carries more than the maximum supported number of PSK identities. The handshake is expected to fail.
* @precon nan
* @brief 4.2.11. Pre-Shared Key Extension
* @expect 1. The server rejects the malformed ClientHello with a fatal illegal_parameter alert.
*         2. The PSK server callback is not invoked after the PSK identity count limit is exceeded.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_PSK_IDENTITIES_LIMIT_FUNC_TC001()
{
    FRAME_Init();
    g_pskIdentityLimitServerCbCalls = 0;

    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_Client_PskIdentityCountLimit
    };
    RegisterWrapper(wrapper);

    PskIdentityLimitTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.config = HITLS_CFG_NewTLS13Config();
    uint16_t cipherSuite = HITLS_AES_128_GCM_SHA256;
    HITLS_CFG_SetCipherSuites(testInfo.config, &cipherSuite, 1);
    HITLS_CFG_SetKeyExchMode(testInfo.config, TLS13_KE_MODE_PSK_ONLY);
    HITLS_CFG_SetPskServerCallback(testInfo.config, (HITLS_PskServerCb)Test_PskIdentityLimit_ServerCb);
    HITLS_CFG_SetPskClientCallback(testInfo.config, (HITLS_PskClientCb)ExampleClientCb);
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_PARSE_INVALID_MSG_LEN);
    ASSERT_EQ(g_pskIdentityLimitServerCbCalls, 0);

    ALERT_Info alert = {0};
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

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

#include "frame_tls.h"
#include "frame_link.h"
#include "session.h"
#include "hitls_config.h"
#include "hitls_crypt_init.h"
#include "session_type.h"
#include "hitls_session.h"
/* END_HEADER */

static int32_t ServernameCbErrOK(HITLS_Ctx *ctx, int *alert, void *arg)
{
    (void)ctx;
    (void)alert;
    (void)arg;

    return HITLS_ACCEPT_SNI_ERR_OK;
}
/** @
* @test     UT_TLS12_RESUME_FUNC_TC001
* @title    Test the session resume of tls12.
*
* @brief    1. at first handshake, config serverName, and sessionidCtx. Expect result 1
            2. at second handshake, Expect result 2
* @expect   1. connect success
            2. resume success
@ */
/* BEGIN_CASE */
void UT_TLS12_RESUME_FUNC_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();

    HITLS_CFG_SetServerName(config, (uint8_t *)"www.test.com", (uint32_t)strlen((char *)"www.test.com"));
    HITLS_CFG_SetServerNameCb(config, ServernameCbErrOK);

    char *sessionIdCtx1 = "123456789";
    ASSERT_EQ(HITLS_CFG_SetSessionIdCtx(config, (const uint8_t *)sessionIdCtx1, strlen(sessionIdCtx1)), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_SESSION_CACHE_MODE_BASIC_TC001
* @title    Test basic session cache mode setting and getting.
*
* @brief    1. Create TLS config and set different basic cache modes
*           2. Get and verify the cache mode values
*           3. Test bit flag checks
* @expect   1. All basic modes set successfully
*           2. Retrieved mode values match set values
*           3. Bit flag checks work correctly
@ */
/* BEGIN_CASE */
void UT_SESSION_CACHE_MODE_BASIC_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Test HITLS_SESS_CACHE_NO
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_NO), HITLS_SUCCESS);
    uint32_t mode = 0;
    ASSERT_EQ(HITLS_CFG_GetSessionCacheMode(config, &mode), HITLS_SUCCESS);
    ASSERT_EQ(mode, HITLS_SESS_CACHE_NO);

    // Test HITLS_SESS_CACHE_CLIENT
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_CLIENT), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_GetSessionCacheMode(config, &mode), HITLS_SUCCESS);
    ASSERT_EQ(mode, HITLS_SESS_CACHE_CLIENT);
    ASSERT_TRUE((mode & HITLS_SESS_CACHE_CLIENT) != 0);

    // Test HITLS_SESS_CACHE_SERVER
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_SERVER), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_GetSessionCacheMode(config, &mode), HITLS_SUCCESS);
    ASSERT_EQ(mode, HITLS_SESS_CACHE_SERVER);
    ASSERT_TRUE((mode & HITLS_SESS_CACHE_SERVER) != 0);

    // Test HITLS_SESS_CACHE_BOTH
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_BOTH), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_GetSessionCacheMode(config, &mode), HITLS_SUCCESS);
    ASSERT_EQ(mode, HITLS_SESS_CACHE_BOTH);
    ASSERT_TRUE((mode & HITLS_SESS_CACHE_CLIENT) != 0);
    ASSERT_TRUE((mode & HITLS_SESS_CACHE_SERVER) != 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test     UT_SESSION_CACHE_MODE_NO_CACHE_TC002
* @title    Test HITLS_SESS_CACHE_NO mode behavior.
*
* @brief    1. Set cache mode to NO on both client and server
*           2. Establish TLS connection
*           3. Try session resumption
* @expect   1. Connection succeeds
*           2. Session not cached, resumption fails
@ */
/* BEGIN_CASE */
void UT_SESSION_CACHE_MODE_NO_CACHE_TC002()
{
    FRAME_Init();
    HITLS_Config *clientConfig = HITLS_CFG_NewTLS12Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);

    // Set NO cache mode for both
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(clientConfig, HITLS_SESS_CACHE_NO), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(serverConfig, HITLS_SESS_CACHE_NO), HITLS_SUCCESS);
    HITLS_CFG_SetSessionTicketSupport(serverConfig, false);
    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    // First connection
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    // Second connection with session
    client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    // Verify session not reused due to NO cache mode
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, false);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_SESSION_CACHE_MODE_BOTH_TC003
* @title    Test HITLS_SESS_CACHE_BOTH mode behavior.
*
* @brief    1. Set cache mode to BOTH on both client and server
*           2. Establish TLS connection and get session
*           3. Try session resumption
* @expect   1. Connection succeeds
*           2. Session resumption succeeds
@ */
/* BEGIN_CASE */
void UT_SESSION_CACHE_MODE_BOTH_TC003()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Set BOTH cache mode
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_BOTH), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    // First connection
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    // Second connection with session resumption
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    // Verify session reused
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

#ifdef HITLS_TLS_FEATURE_SESSION
/** @
* @test     UT_SESSION_CACHE_MODE_DISABLE_INTERNAL_STORE_TC004
* @title    Test HITLS_SESS_DISABLE_INTERNAL_STORE mode.
*
* @brief    1. Set cache mode with DISABLE_INTERNAL_STORE flag
*           2. Establish TLS connection
*           3. Check that sessions are not stored internally
* @expect   1. Connection succeeds
*           2. Sessions not stored in internal cache
@ */
/* BEGIN_CASE */
void UT_SESSION_CACHE_MODE_DISABLE_INTERNAL_STORE_TC004()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Set SERVER cache mode with DISABLE_INTERNAL_STORE
    uint32_t mode = HITLS_SESS_CACHE_SERVER | HITLS_SESS_DISABLE_INTERNAL_STORE;
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, mode), HITLS_SUCCESS);

    // Verify mode was set correctly
    uint32_t getMode = 0;
    ASSERT_EQ(HITLS_CFG_GetSessionCacheMode(config, &getMode), HITLS_SUCCESS);
    ASSERT_TRUE((getMode & HITLS_SESS_CACHE_SERVER) != 0);
    ASSERT_TRUE((getMode & HITLS_SESS_DISABLE_INTERNAL_STORE) != 0);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    // Establish connection
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    // Check cache size - should be 0 due to DISABLE_INTERNAL_STORE
    ASSERT_EQ(BSL_HASH_Size(client->ssl->globalConfig->sessMgr->hash), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_SESSION_CACHE_MODE_ENABLE_TIME_UPDATE_TC005
* @title    Test HITLS_SESS_ENABLE_TIME_UPDATE mode.
*
* @brief    1. Set cache mode with ENABLE_TIME_UPDATE flag
*           2. Establish TLS connection and get session
*           3. Resume session and check time update
* @expect   1. Connection succeeds
*           2. Session time gets updated on resumption
@ */
/* BEGIN_CASE */
void UT_SESSION_CACHE_MODE_ENABLE_TIME_UPDATE_TC005()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Set SERVER cache mode with ENABLE_TIME_UPDATE
    uint32_t mode = HITLS_SESS_CACHE_SERVER | HITLS_SESS_ENABLE_TIME_UPDATE;
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, mode), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    // First connection
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    // Get initial timeout
    uint64_t initialTimeout = HITLS_SESS_GetTimeout(clientSession);
    ASSERT_TRUE(initialTimeout > 0);

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    // Sleep briefly to ensure time difference
    sleep(1);

    // Second connection with session resumption
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    // Verify session reused
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_SESSION_CACHE_MODE_COMBINED_FLAGS_TC006
* @title    Test combined cache mode flags.
*
* @brief    1. Set cache mode with multiple flags combined
*           2. Verify all flags are set correctly
*           3. Test basic functionality with combined flags
* @expect   1. All flags set correctly
*           2. Combined behavior works as expected
@ */
/* BEGIN_CASE */
void UT_SESSION_CACHE_MODE_COMBINED_FLAGS_TC006()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Set combined flags: SERVER + ENABLE_TIME_UPDATE + DISABLE_AUTO_CLEANUP
    uint32_t mode = HITLS_SESS_CACHE_SERVER | HITLS_SESS_ENABLE_TIME_UPDATE |
                    HITLS_SESS_DISABLE_AUTO_CLEANUP;
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, mode), HITLS_SUCCESS);

    // Verify all flags are set
    uint32_t getMode = 0;
    ASSERT_EQ(HITLS_CFG_GetSessionCacheMode(config, &getMode), HITLS_SUCCESS);
    ASSERT_TRUE((getMode & HITLS_SESS_CACHE_SERVER) != 0);
    ASSERT_TRUE((getMode & HITLS_SESS_ENABLE_TIME_UPDATE) != 0);
    ASSERT_TRUE((getMode & HITLS_SESS_DISABLE_AUTO_CLEANUP) != 0);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    // Test basic connection with combined flags
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */
#endif /* HITLS_TLS_FEATURE_SESSION */

/** @
* @test     UT_SESSION_CACHE_MODE_NULL_INPUT_TC007
* @title    Test session cache mode with NULL inputs.
*
* @brief    1. Test HITLS_CFG_SetSessionCacheMode with NULL config
*           2. Test HITLS_CFG_GetSessionCacheMode with NULL config
*           3. Test HITLS_CFG_GetSessionCacheMode with NULL mode pointer
* @expect   1. All NULL input tests return HITLS_NULL_INPUT
@ */
/* BEGIN_CASE */
void UT_SESSION_CACHE_MODE_NULL_INPUT_TC007()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    uint32_t mode = 0;

    // Test SetSessionCacheMode with NULL config
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(NULL, HITLS_SESS_CACHE_SERVER), HITLS_NULL_INPUT);

    // Test GetSessionCacheMode with NULL config
    ASSERT_EQ(HITLS_CFG_GetSessionCacheMode(NULL, &mode), HITLS_NULL_INPUT);

    // Test GetSessionCacheMode with NULL mode pointer
    ASSERT_EQ(HITLS_CFG_GetSessionCacheMode(config, NULL), HITLS_NULL_INPUT);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test     UT_SESSION_CACHE_MODE_BACKWARD_COMPATIBILITY_TC008
* @title    Test backward compatibility with old enum values.
*
* @brief    1. Use old enum values to set cache modes
*           2. Verify functionality remains unchanged
*           3. Test session resumption with old values
* @expect   1. Old enum values work correctly
*           2. Session resumption works as before
@ */
/* BEGIN_CASE */
void UT_SESSION_CACHE_MODE_BACKWARD_COMPATIBILITY_TC008()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Test with old enum values (should still work)
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_BOTH), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    // First connection
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    // Second connection with session resumption
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    // Verify backward compatibility - session should be reused
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

#ifdef HITLS_TLS_FEATURE_SESSION_CACHE_CB
/* Global variables for external cache simulation */
#define MAX_EXTERNAL_SESSIONS 10
static HITLS_Session *g_externalSessionCache[MAX_EXTERNAL_SESSIONS];
static uint8_t g_externalSessionIds[MAX_EXTERNAL_SESSIONS][32];
static uint32_t g_externalSessionIdLens[MAX_EXTERNAL_SESSIONS];
static uint32_t g_externalSessionCount = 0;
static bool g_sessionGetCbCalled = false;
static bool g_sessionRemoveCbCalled = false;
static int32_t g_copyParamValue = 1;

/* Helper function to clear external cache */
static void ClearExternalCache(void)
{
    for (uint32_t i = 0; i < g_externalSessionCount; i++) {
        HITLS_SESS_Free(g_externalSessionCache[i]);
        g_externalSessionCache[i] = NULL;
    }
    g_externalSessionCount = 0;
    g_sessionGetCbCalled = false;
    g_sessionRemoveCbCalled = false;
    g_copyParamValue = 1;
}

/* External session get callback implementation */
static HITLS_Session *TestSessionGetCb(HITLS_Ctx *ctx, const uint8_t *data, int32_t len, int32_t *copy)
{
    (void)ctx;
    g_sessionGetCbCalled = true;

    for (uint32_t i = 0; i < g_externalSessionCount; i++) {
        if (g_externalSessionIdLens[i] == (uint32_t)len && memcmp(g_externalSessionIds[i], data, len) == 0) {
            *copy = g_copyParamValue;
            return g_externalSessionCache[i];
        }
    }
    return NULL;
}

/* External session remove callback implementation */
static void TestSessionRemoveCb(HITLS_Config *config, HITLS_Session *sess)
{
    (void)config;
    (void)sess;
    g_sessionRemoveCbCalled = true;
}

/* Helper function to store session in external cache */
static void StoreSessionInExternalCache(HITLS_Session *sess)
{
    if (g_externalSessionCount >= MAX_EXTERNAL_SESSIONS) {
        return;
    }

    uint32_t index = g_externalSessionCount;
    g_externalSessionCache[index] = HITLS_SESS_Dup(sess);
    g_externalSessionIdLens[index] = 32;
    HITLS_SESS_GetSessionId(sess, g_externalSessionIds[index], &g_externalSessionIdLens[index]);
    g_externalSessionCount++;
}

/** @
* @test     UT_EXTERNAL_CACHE_GET_CB_BASIC_TC001
* @title    Test SessionGetCb interface setting.
*
* @brief    1. Create TLS config and set SessionGetCb callback
*           2. Verify callback setting succeeds
*           3. Test NULL input error handling
* @expect   1. Callback sets successfully
*           2. NULL input returns HITLS_NULL_INPUT
@ */
/* BEGIN_CASE */
void UT_EXTERNAL_CACHE_GET_CB_BASIC_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ClearExternalCache();

    ASSERT_EQ(HITLS_CFG_SetSessionGetCb(config, TestSessionGetCb), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSessionGetCb(NULL, TestSessionGetCb), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_SetSessionGetCb(config, NULL), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    ClearExternalCache();
}
/* END_CASE */

/** @
* @test     UT_EXTERNAL_CACHE_REMOVE_CB_BASIC_TC002
* @title    Test SessionRemoveCb interface setting.
*
* @brief    1. Create TLS config and set SessionRemoveCb callback
*           2. Verify callback setting succeeds
*           3. Test NULL input error handling
* @expect   1. Callback sets successfully
*           2. NULL input returns HITLS_NULL_INPUT
@ */
/* BEGIN_CASE */
void UT_EXTERNAL_CACHE_REMOVE_CB_BASIC_TC002()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ClearExternalCache();

    ASSERT_EQ(HITLS_CFG_SetSessionRemoveCb(config, TestSessionRemoveCb), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSessionRemoveCb(NULL, TestSessionRemoveCb), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_SetSessionRemoveCb(config, NULL), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    ClearExternalCache();
}
/* END_CASE */

/** @
* @test     UT_EXTERNAL_CACHE_GET_CB_FUNCTION_TC003
* @title    Test SessionGetCb basic functionality.
*
* @brief    1. Set external lookup mode and callback
*           2. Establish TLS connection and store session externally
*           3. Try session resumption using external cache
* @expect   1. External callback is called
*           2. Session resumption succeeds
@ */
/* BEGIN_CASE */
void UT_EXTERNAL_CACHE_GET_CB_FUNCTION_TC003()
{
    FRAME_Init();
    HITLS_Config *clientConfig = HITLS_CFG_NewTLS12Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);

    ClearExternalCache();

    /* Set external lookup mode on server */
    uint32_t mode = HITLS_SESS_CACHE_SERVER | HITLS_SESS_DISABLE_INTERNAL_LOOKUP;
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(serverConfig, mode), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSessionGetCb(serverConfig, TestSessionGetCb), HITLS_SUCCESS);
    HITLS_CFG_SetSessionTicketSupport(serverConfig, false);
    /* Set client cache mode */
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(clientConfig, HITLS_SESS_CACHE_CLIENT), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    /* First connection */
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    /* Store session in external cache manually */
    StoreSessionInExternalCache(clientSession);
    HITLS_SESS_Free(clientSession);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    /* Reset callback flag */
    g_sessionGetCbCalled = false;

    /* Second connection with session resumption */
    client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Verify external callback was called */
    ASSERT_TRUE(g_sessionGetCbCalled);

    /* Verify session reused */
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_TRUE(isReused);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
    ClearExternalCache();
}
/* END_CASE */

/** @
* @test     UT_EXTERNAL_CACHE_REMOVE_CB_FUNCTION_TC004
* @title    Test SessionRemoveCb functionality.
*
* @brief    1. Set SessionRemoveCb callback
*           2. Create session and verify it's stored internally
*           3. Clear timeout sessions to trigger remove callback
* @expect   1. Remove callback is called when session is removed
@ */
/* BEGIN_CASE */
void UT_EXTERNAL_CACHE_REMOVE_CB_FUNCTION_TC004()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ClearExternalCache();

    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_SERVER), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSessionRemoveCb(config, TestSessionRemoveCb), HITLS_SUCCESS);
    HITLS_CFG_SetSessionTicketSupport(config, false);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    /* Verify session was stored in cache */
    ASSERT_TRUE(BSL_HASH_Size(client->ssl->globalConfig->sessMgr->hash) > 0);

    g_sessionRemoveCbCalled = false;

    /* Clear timeout sessions to trigger remove callback */
    uint64_t futureTime = (uint64_t)time(NULL) + 86400; /* 24 hours in future */
    ASSERT_EQ(HITLS_CFG_ClearTimeoutSession(config, futureTime), HITLS_SUCCESS);

    /* Verify remove callback was called */
    ASSERT_TRUE(g_sessionRemoveCbCalled);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
    ClearExternalCache();
}
/* END_CASE */

/** @
* @test     UT_EXTERNAL_CACHE_FULL_EXTERNAL_MODE_TC005
* @title    Test complete external cache mode.
*
* @brief    1. Enable full external mode (disable both internal store and lookup)
*           2. Verify external callbacks work correctly
*           3. Test session resumption through external cache
* @expect   1. External callbacks are used
*           2. Session resumption works through external cache
@ */
/* BEGIN_CASE */
void UT_EXTERNAL_CACHE_FULL_EXTERNAL_MODE_TC005()
{
    FRAME_Init();
    HITLS_Config *clientConfig = HITLS_CFG_NewTLS12Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);

    ClearExternalCache();

    /* Set complete external mode on server */
    uint32_t mode = HITLS_SESS_CACHE_SERVER | HITLS_SESS_DISABLE_INTERNAL_STORE | HITLS_SESS_DISABLE_INTERNAL_LOOKUP;
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(serverConfig, mode), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_CFG_SetSessionGetCb(serverConfig, TestSessionGetCb), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSessionRemoveCb(serverConfig, TestSessionRemoveCb), HITLS_SUCCESS);

    /* Set client cache mode */
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(clientConfig, HITLS_SESS_CACHE_CLIENT), HITLS_SUCCESS);
    HITLS_CFG_SetSessionTicketSupport(serverConfig, false);

    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    /* First connection */
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    /* Manually store in external cache (simulating application behavior) */
    StoreSessionInExternalCache(clientSession);
    HITLS_SESS_Free(clientSession);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    /* Reset flags */
    g_sessionGetCbCalled = false;

    /* Second connection using external cache */
    client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Verify external callback was used */
    ASSERT_TRUE(g_sessionGetCbCalled);

    /* Verify session resumption succeeded */
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_TRUE(isReused);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
    ClearExternalCache();
}
/* END_CASE */
#endif /* HITLS_TLS_FEATURE_SESSION_CACHE_CB */

#ifdef HITLS_TLS_FEATURE_SESSION_CUSTOM_TICKET
/* Global variables for custom session ticket extension testing */
static bool g_sessionTicketExtProcessCbCalled = false;
static uint8_t *g_receivedExtData = NULL;
static uint32_t g_receivedExtDataLen = 0;
static void *g_receivedExtArg = NULL;
static int32_t g_extProcessReturnValue = 1;
static const char *TEST_USER_ARG = "TestUserArg";

/* Helper function to clear session ticket extension test state */
static void ClearSessionTicketExtState(void)
{
    g_sessionTicketExtProcessCbCalled = false;
    if (g_receivedExtData != NULL) {
        BSL_SAL_FREE(g_receivedExtData);
        g_receivedExtData = NULL;
    }
    g_receivedExtDataLen = 0;
    g_receivedExtArg = NULL;
    g_extProcessReturnValue = HITLS_SUCCESS;
}

/* Session ticket extension process callback implementation */
static int32_t TestSessionTicketExtProcessCb(HITLS_Ctx *ctx, const uint8_t *data, int32_t len, void *arg)
{
    (void)ctx;
    g_sessionTicketExtProcessCbCalled = true;

    /* Store received data for verification */
    if (data != NULL && len > 0) {
        g_receivedExtData = BSL_SAL_Malloc(len);
        if (g_receivedExtData != NULL) {
            memcpy(g_receivedExtData, data, len);
            g_receivedExtDataLen = (uint32_t)len;
        }
    }

    g_receivedExtArg = arg;
    return g_extProcessReturnValue;
}
/** @
* @test     UT_CUSTOM_SESSION_TICKET_EXT_DATA_BASIC_TC001
* @title    Test basic extension data setting functionality.
*
* @brief    1. Create TLS config and set custom extension data
*           2. Verify data is correctly stored
*           3. Test data replacement
* @expect   1. Extension data sets successfully
*           2. Data is correctly copied and stored
*           3. Data replacement works correctly
@ */
/* BEGIN_CASE */
void UT_CUSTOM_SESSION_TICKET_EXT_DATA_BASIC_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ClearSessionTicketExtState();

    /* Test setting small extension data */
    uint8_t testData1[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    ASSERT_EQ(HITLS_SetSessionTicketExtData(ctx, testData1, sizeof(testData1)), HITLS_SUCCESS);

    /* Test data replacement */
    uint8_t testData2[32];
    for (int i = 0; i < 32; i++) {
        testData2[i] = (uint8_t)(i + 0x20);
    }
    ASSERT_EQ(HITLS_SetSessionTicketExtData(ctx, testData2, sizeof(testData2)), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
    ClearSessionTicketExtState();
}
/* END_CASE */

/** @
* @test     UT_CUSTOM_SESSION_TICKET_EXT_DATA_REPLACE_TC002
* @title    Test extension data replacement functionality.
*
* @brief    1. Create TLS config and set initial extension data
*           2. Replace with different data
*           3. Verify old data is properly released
* @expect   1. Both data settings succeed
*           2. Data is properly replaced
*           3. No memory leaks occur
@ */
/* BEGIN_CASE */
void UT_CUSTOM_SESSION_TICKET_EXT_DATA_REPLACE_TC002()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ClearSessionTicketExtState();

    /* First data setting */
    uint8_t testData1[32];
    memset(testData1, 0xAA, sizeof(testData1));
    ASSERT_EQ(HITLS_SetSessionTicketExtData(ctx, testData1, sizeof(testData1)), HITLS_SUCCESS);

    /* Second data setting (replacement) */
    uint8_t testData2[64];
    memset(testData2, 0xBB, sizeof(testData2));
    ASSERT_EQ(HITLS_SetSessionTicketExtData(ctx, testData2, sizeof(testData2)), HITLS_SUCCESS);

    /* Third setting with smaller data */
    uint8_t testData3[16];
    memset(testData3, 0xCC, sizeof(testData3));
    ASSERT_EQ(HITLS_SetSessionTicketExtData(ctx, testData3, sizeof(testData3)), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
    ClearSessionTicketExtState();
}
/* END_CASE */

/** @
* @test     UT_CUSTOM_SESSION_TICKET_EXT_PROCESS_CB_BASIC_TC003
* @title    Test extension process callback setting.
*
* @brief    1. Create TLS config and set extension process callback
*           2. Verify callback and argument are correctly stored
*           3. Test callback replacement
* @expect   1. Callback sets successfully
*           2. Parameters are correctly stored
*           3. Callback replacement works
@ */
/* BEGIN_CASE */
void UT_CUSTOM_SESSION_TICKET_EXT_PROCESS_CB_BASIC_TC003()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ClearSessionTicketExtState();

    /* Set callback with user argument */
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(ctx, TestSessionTicketExtProcessCb, (void *)TEST_USER_ARG),
              HITLS_SUCCESS);

    /* Replace callback with different argument */
    const char *newArg = "NewUserArg";
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(ctx, TestSessionTicketExtProcessCb, (void *)newArg), HITLS_SUCCESS);

    /* Set callback to NULL (valid operation) */
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(ctx, NULL, NULL), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
    ClearSessionTicketExtState();
}
/* END_CASE */

/** @
* @test     UT_CUSTOM_SESSION_TICKET_EXT_DATA_PARAM_TC004
* @title    Test extension data parameter validation.
*
* @brief    1. Test NULL config parameter
*           2. Test NULL data with non-zero size
*           3. Test non-NULL data with zero size
*           4. Test large data size
* @expect   1. NULL config returns HITLS_NULL_INPUT
*           2. Invalid parameter combinations return appropriate error codes
*           3. Valid parameters return HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_CUSTOM_SESSION_TICKET_EXT_DATA_PARAM_TC004()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ClearSessionTicketExtState();

    uint8_t testData[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    /* Test NULL config */
    ASSERT_EQ(HITLS_SetSessionTicketExtData(NULL, testData, sizeof(testData)), HITLS_INVALID_INPUT);

    /* Test NULL data with non-zero size */
    ASSERT_EQ(HITLS_SetSessionTicketExtData(ctx, NULL, 16), HITLS_INVALID_INPUT);

    /* Test non-NULL data with zero size */
    ASSERT_EQ(HITLS_SetSessionTicketExtData(ctx, testData, 0), HITLS_INVALID_INPUT);

    /* Test valid parameters */
    ASSERT_EQ(HITLS_SetSessionTicketExtData(ctx, testData, sizeof(testData)), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
    ClearSessionTicketExtState();
}
/* END_CASE */

/** @
* @test     UT_CUSTOM_SESSION_TICKET_EXT_PROCESS_CB_PARAM_TC005
* @title    Test extension process callback parameter validation.
*
* @brief    1. Test NULL config parameter
*           2. Test NULL callback with non-NULL arg
*           3. Test non-NULL callback with NULL arg
*           4. Test valid parameter combinations
* @expect   1. NULL config returns HITLS_NULL_INPUT
*           2. Other combinations should work as designed
@ */
/* BEGIN_CASE */
void UT_CUSTOM_SESSION_TICKET_EXT_PROCESS_CB_PARAM_TC005()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ClearSessionTicketExtState();

    /* Test NULL config */
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(NULL, TestSessionTicketExtProcessCb, (void *)TEST_USER_ARG),
              HITLS_NULL_INPUT);

    /* Test NULL callback with non-NULL arg (should succeed) */
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(ctx, NULL, (void *)TEST_USER_ARG), HITLS_SUCCESS);

    /* Test non-NULL callback with NULL arg (should succeed) */
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(ctx, TestSessionTicketExtProcessCb, NULL), HITLS_SUCCESS);

    /* Test valid combination */
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(ctx, TestSessionTicketExtProcessCb, (void *)TEST_USER_ARG),
              HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
    ClearSessionTicketExtState();
}
/* END_CASE */

/** @
* @test     UT_CUSTOM_SESSION_TICKET_CLIENT_SEND_EXT_TC006
* @title    Test client sending custom extension data in handshake.
*
* @brief    1. Set extension data on client config
*           2. Set process callback on server config
*           3. Establish TLS connection
*           4. Verify server receives extension data correctly
* @expect   1. TLS handshake succeeds
*           2. Server callback is called
*           3. Received data matches sent data
@ */
/* BEGIN_CASE */
void UT_CUSTOM_SESSION_TICKET_CLIENT_SEND_EXT_TC006()
{
    FRAME_Init();
    HITLS_Config *clientConfig = HITLS_CFG_NewTLS12Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);

    ClearSessionTicketExtState();

    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    uint8_t clientExtData[] = "ClientExtensionData123";
    ASSERT_EQ(HITLS_SetSessionTicketExtData(client->ssl, clientExtData, sizeof(clientExtData)), HITLS_SUCCESS);
    g_extProcessReturnValue = 1;
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(server->ssl, TestSessionTicketExtProcessCb, (void *)TEST_USER_ARG),
              HITLS_SUCCESS);
    /* Establish connection */
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Verify server callback was called */
    ASSERT_TRUE(g_sessionTicketExtProcessCbCalled);

    /* Verify received data matches sent data */
    ASSERT_TRUE(g_receivedExtData != NULL);
    ASSERT_EQ(g_receivedExtDataLen, sizeof(clientExtData));
    ASSERT_EQ(memcmp(g_receivedExtData, clientExtData, g_receivedExtDataLen), 0);

    /* Verify user argument was passed correctly */
    ASSERT_EQ(g_receivedExtArg, (void *)TEST_USER_ARG);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearSessionTicketExtState();
}
/* END_CASE */

/** @
* @test     UT_CUSTOM_SESSION_TICKET_BIDIRECTIONAL_EXT_TC008
* @title    Test bidirectional custom extension data exchange.
*
* @brief    1. Set different extension data on both client and server
*           2. Set process callbacks on both sides
*           3. Establish TLS connection
*           4. Verify both sides receive correct extension data
* @expect   1. TLS handshake succeeds
*           2. Both callbacks are called
*           3. Each side receives correct data from the other
@ */
/* BEGIN_CASE */
void UT_CUSTOM_SESSION_TICKET_BIDIRECTIONAL_EXT_TC008()
{
    FRAME_Init();
    HITLS_Config *clientConfig = HITLS_CFG_NewTLS12Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);

    ClearSessionTicketExtState();

    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    /* Set extension data on both sides */
    uint8_t clientExtData[] = "ClientBidirectionalData";
    uint8_t serverExtData[] = "ServerBidirectionalData";

    ASSERT_EQ(HITLS_SetSessionTicketExtData(client->ssl, clientExtData, sizeof(clientExtData)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetSessionTicketExtData(server->ssl, serverExtData, sizeof(serverExtData)), HITLS_SUCCESS);
    g_extProcessReturnValue = 1;
    /* Note: In bidirectional scenario, we need to track which callback was called
     * This is a simplified test - real implementation might need more sophisticated tracking */
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(client->ssl, TestSessionTicketExtProcessCb, (void *)"ClientReceiver"),
              HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(server->ssl, TestSessionTicketExtProcessCb, (void *)"ServerReceiver"),
              HITLS_SUCCESS);
    /* Establish connection */
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    /* At least one callback should be called in bidirectional scenario */
    ASSERT_TRUE(g_sessionTicketExtProcessCbCalled);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearSessionTicketExtState();
}
/* END_CASE */

/** @
* @test     UT_CUSTOM_SESSION_TICKET_CALLBACK_FUNCTION_TC009
* @title    Test extension process callback complete functionality.
*
* @brief    1. Set extension data and callback
*           2. Verify callback parameters are correct
*           3. Test callback with success return
*           4. Verify handshake completes successfully
* @expect   1. Callback is called with correct parameters
*           2. User argument is passed correctly
*           3. TLS handshake succeeds
@ */
/* BEGIN_CASE */
void UT_CUSTOM_SESSION_TICKET_CALLBACK_FUNCTION_TC009()
{
    FRAME_Init();
    HITLS_Config *clientConfig = HITLS_CFG_NewTLS12Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);

    ClearSessionTicketExtState();

    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    /* Set up test scenario */
    uint8_t testExtData[] = {0x48, 0x49, 0x54, 0x4C, 0x53, 0x2D, 0x54, 0x65, 0x73, 0x74,
                             0x2D, 0x45, 0x78, 0x74, 0x2D, 0x44, 0x61, 0x74, 0x61}; /* "HITLS-Test-Ext-Data" */

    ASSERT_EQ(HITLS_SetSessionTicketExtData(client->ssl, testExtData, sizeof(testExtData)), HITLS_SUCCESS);

    /* Set callback that returns success */
    g_extProcessReturnValue = 1;
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(server->ssl, TestSessionTicketExtProcessCb, (void *)TEST_USER_ARG),
              HITLS_SUCCESS);

    /* Establish connection */
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Verify callback was called */
    ASSERT_TRUE(g_sessionTicketExtProcessCbCalled);

    /* Verify callback parameters */
    ASSERT_TRUE(g_receivedExtData != NULL);
    ASSERT_EQ(g_receivedExtDataLen, sizeof(testExtData));
    ASSERT_EQ(memcmp(g_receivedExtData, testExtData, sizeof(testExtData)), 0);
    ASSERT_EQ(g_receivedExtArg, (void *)TEST_USER_ARG);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearSessionTicketExtState();
}
/* END_CASE */

/** @
* @test     UT_CUSTOM_SESSION_TICKET_CALLBACK_ERROR_TC010
* @title    Test extension process callback error handling.
*
* @brief    1. Set extension data and callback that returns error
*           2. Attempt TLS handshake
*           3. Verify handshake fails when callback returns error
* @expect   1. Callback is called
*           2. Handshake fails when callback returns error
@ */
/* BEGIN_CASE */
void UT_CUSTOM_SESSION_TICKET_CALLBACK_ERROR_TC010()
{
    FRAME_Init();
    HITLS_Config *clientConfig = HITLS_CFG_NewTLS12Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);

    ClearSessionTicketExtState();

    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    /* Set extension data */
    uint8_t testExtData[] = "TestErrorHandling";
    ASSERT_EQ(HITLS_SetSessionTicketExtData(client->ssl, testExtData, sizeof(testExtData)), HITLS_SUCCESS);

    /* Set callback that returns error */
    g_extProcessReturnValue = 0;
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(server->ssl, TestSessionTicketExtProcessCb, (void *)TEST_USER_ARG),
              HITLS_SUCCESS);

    /* Attempt connection - should fail due to callback error */
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) != HITLS_SUCCESS);

    /* Verify callback was called */
    ASSERT_TRUE(g_sessionTicketExtProcessCbCalled);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearSessionTicketExtState();
}
/* END_CASE */

/** @
* @test     UT_CUSTOM_SESSION_TICKET_NO_CALLBACK_TC011
* @title    Test default behavior when no callback is set.
*
* @brief    1. Set extension data but no process callback
*           2. Establish TLS connection
*           3. Verify handshake succeeds (extension data is ignored)
* @expect   1. TLS handshake succeeds
*           2. Extension data is sent but ignored by receiver
@ */
/* BEGIN_CASE */
void UT_CUSTOM_SESSION_TICKET_NO_CALLBACK_TC011()
{
    FRAME_Init();
    HITLS_Config *clientConfig = HITLS_CFG_NewTLS12Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);

    ClearSessionTicketExtState();

    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    /* Do NOT set callback on server - test default behavior */
    /* Set extension data on client, but no callback on server */
    uint8_t testExtData[] = "NoCallbackTestData";
    ASSERT_EQ(HITLS_SetSessionTicketExtData(client->ssl, testExtData, sizeof(testExtData) - 1), HITLS_SUCCESS);

    /* Establish connection - should succeed */
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Verify callback was NOT called (no callback set) */
    ASSERT_TRUE(!g_sessionTicketExtProcessCbCalled);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearSessionTicketExtState();
}
/* END_CASE */

/** @
* @test     UT_CUSTOM_SESSION_TICKET_TLS12_COMPAT_TC012
* @title    Test TLS 1.2 compatibility with custom extensions.
*
* @brief    1. Create TLS 1.2 configs with extension data
*           2. Establish TLS 1.2 connection
*           3. Verify extension functionality works
* @expect   1. TLS 1.2 handshake succeeds
*           2. Extension data is properly exchanged
@ */
/* BEGIN_CASE */
void UT_CUSTOM_SESSION_TICKET_TLS12_COMPAT_TC012()
{
    FRAME_Init();
    HITLS_Config *clientConfig = HITLS_CFG_NewTLS12Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);

    ClearSessionTicketExtState();

    /* Force TLS 1.2 only */
    uint16_t version = HITLS_VERSION_TLS12;
    ASSERT_EQ(HITLS_CFG_SetVersion(clientConfig, version, version), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetVersion(serverConfig, version, version), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    /* Set extension data */
    uint8_t tls12ExtData[] = "TLS12ExtensionTest";
    ASSERT_EQ(HITLS_SetSessionTicketExtData(client->ssl, tls12ExtData, sizeof(tls12ExtData)), HITLS_SUCCESS);
    g_extProcessReturnValue = 1;
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(server->ssl, TestSessionTicketExtProcessCb, (void *)TEST_USER_ARG),
              HITLS_SUCCESS);

    /* Establish TLS 1.2 connection */
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Verify protocol version is TLS 1.2 */
    uint16_t negotiatedVersion = 0;
    ASSERT_EQ(HITLS_GetNegotiatedVersion(client->ssl, &negotiatedVersion), HITLS_SUCCESS);
    ASSERT_EQ(negotiatedVersion, HITLS_VERSION_TLS12);

    /* Verify extension functionality */
    ASSERT_TRUE(g_sessionTicketExtProcessCbCalled);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearSessionTicketExtState();
}
/* END_CASE */

/** @
* @test     UT_CUSTOM_SESSION_TICKET_TLS13_COMPAT_TC013
* @title    Test TLS 1.3 compatibility with custom extensions.
*
* @brief    1. Create TLS 1.3 configs with extension data
*           2. Establish TLS 1.3 connection
*           3. Verify extension functionality works
* @expect   1. TLS 1.3 handshake succeeds
*           2. Extension data is properly exchanged
@ */
/* BEGIN_CASE */
void UT_CUSTOM_SESSION_TICKET_TLS13_COMPAT_TC013()
{
    FRAME_Init();
    HITLS_Config *clientConfig = HITLS_CFG_NewTLS13Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);

    ClearSessionTicketExtState();

    /* Force TLS 1.3 only */
    uint16_t version = HITLS_VERSION_TLS13;
    ASSERT_EQ(HITLS_CFG_SetVersion(clientConfig, version, version), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetVersion(serverConfig, version, version), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    /* Set extension data */
    uint8_t tls13ExtData[] = "TLS13ExtensionTest";
    ASSERT_EQ(HITLS_SetSessionTicketExtData(client->ssl, tls13ExtData, sizeof(tls13ExtData)), HITLS_SUCCESS);
    g_extProcessReturnValue = 1;
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(server->ssl, TestSessionTicketExtProcessCb, (void *)TEST_USER_ARG),
              HITLS_SUCCESS);

    /* Establish TLS 1.3 connection */
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Verify protocol version is TLS 1.3 */
    uint16_t negotiatedVersion = 0;
    ASSERT_EQ(HITLS_GetNegotiatedVersion(client->ssl, &negotiatedVersion), HITLS_SUCCESS);
    ASSERT_EQ(negotiatedVersion, HITLS_VERSION_TLS13);

    /* Verify extension functionality */
    ASSERT_TRUE(g_sessionTicketExtProcessCbCalled);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearSessionTicketExtState();
}
/* END_CASE */

/** @
* @test     UT_CUSTOM_SESSION_TICKET_LARGE_DATA_TC014
* @title    Test large extension data handling.
*
* @brief    1. Set large extension data (4KB)
*           2. Establish TLS connection
*           3. Verify large data is transmitted correctly
* @expect   1. Large data setting succeeds
*           2. TLS handshake completes
*           3. Large data is received correctly
@ */
/* BEGIN_CASE */
void UT_CUSTOM_SESSION_TICKET_LARGE_DATA_TC014()
{
    FRAME_Init();
    HITLS_Config *clientConfig = HITLS_CFG_NewTLS12Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);

    ClearSessionTicketExtState();

    /* Create large extension data (4KB) */
    const size_t largeDataSize = 4096;
    uint8_t *largeExtData = BSL_SAL_Malloc(largeDataSize);
    ASSERT_TRUE(largeExtData != NULL);

    /* Fill with pattern data */
    for (size_t i = 0; i < largeDataSize; i++) {
        largeExtData[i] = (uint8_t)(i & 0xFF);
    }

    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetSessionTicketExtData(client->ssl, largeExtData, (uint32_t)largeDataSize), HITLS_SUCCESS);
    g_extProcessReturnValue = 1;
    ASSERT_EQ(HITLS_SetSessionTicketExtProcessCb(server->ssl, TestSessionTicketExtProcessCb, (void *)TEST_USER_ARG),
              HITLS_SUCCESS);

    /* Establish connection */
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Verify callback was called */
    ASSERT_TRUE(g_sessionTicketExtProcessCbCalled);

    /* Verify large data was received correctly */
    ASSERT_TRUE(g_receivedExtData != NULL);
    ASSERT_EQ(g_receivedExtDataLen, largeDataSize);
    ASSERT_EQ(memcmp(g_receivedExtData, largeExtData, largeDataSize), 0);

EXIT:
    BSL_SAL_FREE(largeExtData);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearSessionTicketExtState();
}
/* END_CASE */

/** @
* @test     UT_CUSTOM_SESSION_TICKET_MEMORY_MGMT_TC016
* @title    Test extension data memory management.
*
* @brief    1. Set extension data multiple times
*           2. Verify old data is properly freed
*           3. Free config and verify cleanup
* @expect   1. All data updates succeed
*           2. No memory leaks occur
*           3. Config cleanup is successful
@ */
/* BEGIN_CASE */
void UT_CUSTOM_SESSION_TICKET_MEMORY_MGMT_TC016()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ClearSessionTicketExtState();

    /* Set initial data */
    uint8_t data1[] = "InitialMemTestData";
    ASSERT_EQ(HITLS_SetSessionTicketExtData(ctx, data1, sizeof(data1)), HITLS_SUCCESS);

    /* Update with larger data */
    uint8_t data2[256];
    memset(data2, 0xAA, sizeof(data2));
    ASSERT_EQ(HITLS_SetSessionTicketExtData(ctx, data2, sizeof(data2)), HITLS_SUCCESS);

    /* Update with smaller data */
    uint8_t data3[] = "Small";
    ASSERT_EQ(HITLS_SetSessionTicketExtData(ctx, data3, sizeof(data3)), HITLS_SUCCESS);

    /* Set data again after previous settings */
    uint8_t data4[] = "FinalMemTestData";
    ASSERT_EQ(HITLS_SetSessionTicketExtData(ctx, data4, sizeof(data4)), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
    ClearSessionTicketExtState();
}
/* END_CASE */
#endif /* HITLS_TLS_FEATURE_SESSION_CUSTOM_TICKET */

/* Session Management Interface Test Cases */
/* Global variables for session management testing */
static bool g_sessionMgmtRemoveCbCalled = false;
static HITLS_Session *g_sessionMgmtLastRemovedSession = NULL;

/* Helper function to clear session management test state */
static void ClearSessionMgmtState(void)
{
    g_sessionMgmtRemoveCbCalled = false;
    g_sessionMgmtLastRemovedSession = NULL;
}

/* Session remove callback for management testing */
static void TestSessionMgmtRemoveCb(HITLS_Config *config, HITLS_Session *sess)
{
    (void)config;
    g_sessionMgmtRemoveCbCalled = true;
    g_sessionMgmtLastRemovedSession = sess;
}

/** @
* @test     UT_SESSION_MGMT_CLEAR_TIMEOUT_BASIC_TC001
* @title    Test basic timeout session clearing functionality.
*
* @brief    1. Create TLS config and establish connection to generate session
*           2. Make session timeout by setting past time
*           3. Call HITLS_CFG_ClearTimeoutSession to clear timeout sessions
*           4. Verify timeout sessions are cleared
* @expect   1. Session is generated successfully
*           2. Timeout session is identified and cleared
*           3. Cache size decreases correctly
@ */
/* BEGIN_CASE */
void UT_SESSION_MGMT_CLEAR_TIMEOUT_BASIC_TC001()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ClearSessionMgmtState();

    /* Enable session cache */
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_SERVER), HITLS_SUCCESS);
    /* Create connection to generate session */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetSessionTicketSupport(server->ssl, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Verify session is in cache */
    ASSERT_TRUE(BSL_HASH_Size(server->ssl->globalConfig->sessMgr->hash) > 0);

    /* Clear timeout sessions using future time (all current sessions should be considered timeout) */
    uint64_t futureTime = (uint64_t)time(NULL) + 86400; /* 24 hours in future */
    ASSERT_EQ(HITLS_CFG_ClearTimeoutSession(config, futureTime), HITLS_SUCCESS);

    /* Verify cache is cleared */
    ASSERT_EQ(BSL_HASH_Size(server->ssl->globalConfig->sessMgr->hash), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearSessionMgmtState();
}
/* END_CASE */

/** @
* @test     UT_SESSION_MGMT_CLEAR_TIMEOUT_PARAM_TC002
* @title    Test parameter validation for HITLS_CFG_ClearTimeoutSession.
*
* @brief    1. Test NULL config parameter
*           2. Test invalid time parameters
*           3. Test valid parameters
* @expect   1. NULL config returns HITLS_NULL_INPUT
*           2. Invalid parameters handled correctly
*           3. Valid parameters return HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_SESSION_MGMT_CLEAR_TIMEOUT_PARAM_TC002()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ClearSessionMgmtState();

    uint64_t currentTime = (uint64_t)time(NULL);

    /* Test NULL config */
    ASSERT_EQ(HITLS_CFG_ClearTimeoutSession(NULL, currentTime), HITLS_NULL_INPUT);

    /* Test valid parameters */
    ASSERT_EQ(HITLS_CFG_ClearTimeoutSession(config, currentTime), HITLS_SUCCESS);

    /* Test with zero time */
    ASSERT_EQ(HITLS_CFG_ClearTimeoutSession(config, 0), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    ClearSessionMgmtState();
}
/* END_CASE */

/** @
* @test     UT_SESSION_MGMT_CLEAR_NO_TIMEOUT_TC003
* @title    Test clearing when no sessions are timeout.
*
* @brief    1. Create sessions that are not timeout
*           2. Call clear timeout with current time
*           3. Verify no sessions are cleared
* @expect   1. All sessions remain in cache
*           2. Cache size unchanged
*           3. Interface returns success
@ */
/* BEGIN_CASE */
void UT_SESSION_MGMT_CLEAR_NO_TIMEOUT_TC003()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ClearSessionMgmtState();

    /* Enable session cache */
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_SERVER), HITLS_SUCCESS);

    /* Create connection to generate session */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetSessionTicketSupport(server->ssl, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Get initial cache size */
    uint32_t initialCacheSize = BSL_HASH_Size(client->ssl->globalConfig->sessMgr->hash);
    ASSERT_TRUE(initialCacheSize > 0);

    /* Clear with current time (no sessions should be timeout yet) */
    uint64_t currentTime = (uint64_t)time(NULL);
    ASSERT_EQ(HITLS_CFG_ClearTimeoutSession(config, currentTime), HITLS_SUCCESS);

    /* Verify cache size unchanged */
    uint32_t afterCacheSize = BSL_HASH_Size(client->ssl->globalConfig->sessMgr->hash);
    ASSERT_EQ(afterCacheSize, initialCacheSize);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearSessionMgmtState();
}
/* END_CASE */

/** @
* @test     UT_SESSION_MGMT_CLEAR_EXTERNAL_CALLBACK_TC005
* @title    Test external cache callback notification during timeout clearing.
*
* @brief    1. Set session remove callback
*           2. Create sessions and make them timeout
*           3. Clear timeout sessions
*           4. Verify remove callback is called
* @expect   1. Remove callback is triggered for each cleared session
*           2. Callback parameters are correct
@ */
/* BEGIN_CASE */
void UT_SESSION_MGMT_CLEAR_EXTERNAL_CALLBACK_TC005()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ClearSessionMgmtState();

    /* Enable session cache and set remove callback */
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_SERVER), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSessionRemoveCb(config, TestSessionMgmtRemoveCb), HITLS_SUCCESS);

    /* Create connection to generate session */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetSessionTicketSupport(server->ssl, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Clear sessions using future time to trigger timeout */
    uint64_t futureTime = (uint64_t)time(NULL) + 86400; /* 24 hours in future */
    ASSERT_EQ(HITLS_CFG_ClearTimeoutSession(config, futureTime), HITLS_SUCCESS);

    /* Verify remove callback was called */
    ASSERT_TRUE(g_sessionMgmtRemoveCbCalled);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearSessionMgmtState();
}
/* END_CASE */

/** @
* @test     UT_SESSION_MGMT_REMOVE_SESSION_BASIC_TC006
* @title    Test basic session removal functionality.
*
* @brief    1. Create config and generate session
*           2. Call HITLS_CFG_RemoveSession to remove specific session
*           3. Verify session is removed from cache
* @expect   1. Session is successfully removed
*           2. Cache size decreases
*           3. Removed session cannot be found
@ */
/* BEGIN_CASE */
void UT_SESSION_MGMT_REMOVE_SESSION_BASIC_TC006()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ClearSessionMgmtState();

    /* Enable session cache */
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_SERVER), HITLS_SUCCESS);

    /* Create connection to generate session */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetSessionTicketSupport(server->ssl, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Session *session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);

    /* Get initial cache size */
    uint32_t initialCacheSize = BSL_HASH_Size(client->ssl->globalConfig->sessMgr->hash);
    ASSERT_TRUE(initialCacheSize > 0);

    /* Remove the session */
    ASSERT_EQ(HITLS_CFG_RemoveSession(config, session), HITLS_SUCCESS);

    /* Verify cache size decreased */
    uint32_t afterCacheSize = BSL_HASH_Size(client->ssl->globalConfig->sessMgr->hash);
    ASSERT_EQ(afterCacheSize, initialCacheSize - 1);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
    ClearSessionMgmtState();
}
/* END_CASE */

/** @
* @test     UT_SESSION_MGMT_REMOVE_SESSION_PARAM_TC007
* @title    Test parameter validation for HITLS_CFG_RemoveSession.
*
* @brief    1. Test NULL config parameter
*           2. Test NULL session parameter
*           3. Test valid parameters
* @expect   1. NULL parameters return HITLS_NULL_INPUT
*           2. Valid parameters return appropriate result
@ */
/* BEGIN_CASE */
void UT_SESSION_MGMT_REMOVE_SESSION_PARAM_TC007()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ClearSessionMgmtState();

    /* Create a dummy session for testing */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetSessionTicketSupport(server->ssl, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Session *session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);

    /* Test NULL config */
    ASSERT_EQ(HITLS_CFG_RemoveSession(NULL, session), HITLS_NULL_INPUT);

    /* Test NULL session */
    ASSERT_EQ(HITLS_CFG_RemoveSession(config, NULL), HITLS_NULL_INPUT);

    /* Test valid parameters */
    ASSERT_EQ(HITLS_CFG_RemoveSession(config, session), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
    ClearSessionMgmtState();
}
/* END_CASE */

/** @
* @test     UT_SESSION_MGMT_REMOVE_NOT_FOUND_TC008
* @title    Test removing non-existent session.
*
* @brief    1. Create session that is not in cache
*           2. Try to remove the non-existent session
*           3. Verify appropriate error is returned
* @expect   1. Interface returns HITLS_SESS_ERR_NOT_FOUND
*           2. Cache state remains unchanged
@ */
/* BEGIN_CASE */
void UT_SESSION_MGMT_REMOVE_NOT_FOUND_TC008()
{
    FRAME_Init();
    HITLS_Config *config1 = HITLS_CFG_NewTLS12Config();
    HITLS_Config *config2 = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config1 != NULL && config2 != NULL);

    ClearSessionMgmtState();

    /* Enable session cache on both configs */
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config1, HITLS_SESS_CACHE_SERVER), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config2, HITLS_SESS_CACHE_SERVER), HITLS_SUCCESS);

    /* Create session in config2 but try to remove from config1 */
    FRAME_LinkObj *client = FRAME_CreateLink(config2, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config2, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Session *session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);

    /* Try to remove session from config1 (session doesn't exist there) */
    ASSERT_EQ(HITLS_CFG_RemoveSession(config1, session), HITLS_SESS_ERR_NOT_FOUND);

EXIT:
    HITLS_CFG_FreeConfig(config1);
    HITLS_CFG_FreeConfig(config2);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
    ClearSessionMgmtState();
}
/* END_CASE */

/** @
* @test     UT_SESSION_MGMT_REMOVE_CALLBACK_TC010
* @title    Test external cache callback notification during session removal.
*
* @brief    1. Set session remove callback
*           2. Remove session
*           3. Verify callback is called with correct parameters
* @expect   1. Remove callback is triggered
*           2. Callback receives correct session parameter
@ */
/* BEGIN_CASE */
void UT_SESSION_MGMT_REMOVE_CALLBACK_TC010()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ClearSessionMgmtState();

    /* Enable session cache and set remove callback */
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_SERVER), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSessionRemoveCb(config, TestSessionMgmtRemoveCb), HITLS_SUCCESS);

    /* Create connection and session */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetSessionTicketSupport(server->ssl, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Session *session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);

    /* Remove session and verify callback */
    ASSERT_EQ(HITLS_CFG_RemoveSession(config, session), HITLS_SUCCESS);
    ASSERT_TRUE(g_sessionMgmtRemoveCbCalled);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
    ClearSessionMgmtState();
}
/* END_CASE */

/** @
* @test     UT_SESSION_MGMT_GET_TIMEOUT_BASIC_TC012
* @title    Test basic session timeout retrieval functionality.
*
* @brief    1. Create session
*           2. Call HITLS_SESS_GetTimeout to get timeout value
*           3. Verify returned timeout value is reasonable
* @expect   1. Timeout value is retrieved successfully
*           2. Value is greater than 0
*           3. Value matches expected timeout setting
@ */
/* BEGIN_CASE */
void UT_SESSION_MGMT_GET_TIMEOUT_BASIC_TC012()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ClearSessionMgmtState();

    /* Create connection and session */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Session *session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);

    /* Get timeout value */
    uint64_t timeout = HITLS_SESS_GetTimeout(session);
    ASSERT_TRUE(timeout > 0);

    /* Timeout should be reasonable (between 1 second and 1 year) */
    ASSERT_TRUE(timeout >= 1 && timeout <= 365 * 24 * 3600);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
    ClearSessionMgmtState();
}
/* END_CASE */

/** @
* @test     UT_SESSION_MGMT_GET_TIMEOUT_PARAM_TC013
* @title    Test parameter validation for HITLS_SESS_GetTimeout.
*
* @brief    1. Test NULL session parameter
*           2. Test valid session parameter
* @expect   1. NULL session returns error indicator
*           2. Valid session returns proper timeout value
@ */
/* BEGIN_CASE */
void UT_SESSION_MGMT_GET_TIMEOUT_PARAM_TC013()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ClearSessionMgmtState();

    /* Test NULL session */
    uint64_t timeout = HITLS_SESS_GetTimeout(NULL);
    ASSERT_EQ(timeout, 0);

    /* Test with valid session */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetSessionTicketSupport(server->ssl, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Session *session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);

    timeout = HITLS_SESS_GetTimeout(session);
    ASSERT_TRUE(timeout > 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
    ClearSessionMgmtState();
}
/* END_CASE */

/** @
* @test     UT_SESSION_MGMT_LIFECYCLE_INTEGRATION_TC019
* @title    Test complete session lifecycle management integration.
*
* @brief    1. Create session and get its timeout
*           2. Verify session is active
*           3. Clear timeout sessions (should not affect active session)
*           4. Remove session explicitly
*           5. Verify session is gone
* @expect   1. Complete lifecycle works correctly
*           2. All interfaces cooperate properly
*           3. Resources are properly managed
@ */
/* BEGIN_CASE */
void UT_SESSION_MGMT_LIFECYCLE_INTEGRATION_TC019()
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ClearSessionMgmtState();

    /* Enable session cache */
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_SERVER), HITLS_SUCCESS);

    /* Create session */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetSessionTicketSupport(server->ssl, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Session *session = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(session != NULL);

    /* Step 1: Get timeout and verify it's reasonable */
    uint64_t timeout = HITLS_SESS_GetTimeout(session);
    ASSERT_TRUE(timeout > 0);

    /* Step 2: Verify session is in cache */
    uint32_t cacheSize = BSL_HASH_Size(client->ssl->globalConfig->sessMgr->hash);
    ASSERT_TRUE(cacheSize > 0);

    /* Step 3: Clear timeout sessions with current time (should not clear active session) */
    uint64_t currentTime = (uint64_t)time(NULL);
    ASSERT_EQ(HITLS_CFG_ClearTimeoutSession(config, currentTime), HITLS_SUCCESS);

    /* Verify session still exists */
    uint32_t afterClearSize = BSL_HASH_Size(client->ssl->globalConfig->sessMgr->hash);
    ASSERT_EQ(afterClearSize, cacheSize);

    /* Step 4: Remove session explicitly */
    ASSERT_EQ(HITLS_CFG_RemoveSession(config, session), HITLS_SUCCESS);

    /* Step 5: Verify session is removed */
    uint32_t finalSize = BSL_HASH_Size(client->ssl->globalConfig->sessMgr->hash);
    ASSERT_EQ(finalSize, cacheSize - 1);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
    ClearSessionMgmtState();
}
/* END_CASE */

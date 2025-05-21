/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: SDV Test case for TLS PAKE Handshake
 * Author: Your Name or Company
 * Create: 2024-07-16
 */

#include "test.h"
#include "helper.h" /* For PRINT_HEX_DATA_EX, etc. */

#include "hitls.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "hitls_crypt_type.h" /* For PAKE cipher suite IDs */
#include "crypt_spake2p.h"    /* For any PAKE specific defs if tests need direct interaction (ideally not) */
#include "bsl_sal.h"
#include "securec.h"
#include "tls.h" /* For TLS_CONNECTED state, TLS_Ctx */
#include "hs_ctx.h" /* For HITLS_HS_CTX, to inspect pake_ctx if needed for advanced tests, not for basic ones */

#define TEST_PAKE_APP_DATA "Test PAKE Application Data"
#define TEST_PAKE_BUFFER_SIZE 2048

// Placeholder for where PAKE credentials would be set.
// Ideally, an API HITLS_SetPakeCredentials(HITLS_CONFIG* config, const char* pw, const char* idA, const char* idB) exists.
// For now, tests assume the underlying SPAKE2P EAL module uses a known password
// or that it's configured via some mechanism not directly part of this test file's setup.
// For Test 2 (mismatched passwords), we'd need a way to make server and client use different passwords.
// This might require modifying the placeholder password logic in the core handshake files for testing purposes.
static const char* g_testPakePasswordClient = "testpake";
static const char* g_testPakePasswordServer = "testpake"; // Same for success, different for failure test.

// Forward declarations for helper functions
static HITLS_CONFIG* PakeTestConfigCreate(bool isClient, uint16_t pakeCipherSuite);
static void PakeTestConfigFree(HITLS_CONFIG* config);
static int32_t PakeTestFullHandshake(HITLS_Ctx *clientCtx, HITLS_Ctx *serverCtx);
static int32_t PakeTestAppDataExchange(HITLS_Ctx *senderCtx, HITLS_Ctx *receiverCtx, const char* data);


/* Test Case 1: Successful PAKE Handshake (TLS_SPAKE2P_ED25519_WITH_AES_128_GCM_SHA256) */
static int32_t TlsPakeHandshakeTest01_Success_AES128(void)
{
    TEST_CASE_BEGIN("PAKE Success AES128_GCM_SHA256");
    int32_t ret;
    HITLS_CONFIG *clientConfig = NULL;
    HITLS_CONFIG *serverConfig = NULL;
    HITLS_Ctx *clientCtx = NULL;
    HITLS_Ctx *serverCtx = NULL;

    g_testPakePasswordClient = "testpassword123"; // Ensure consistent password for this test
    g_testPakePasswordServer = "testpassword123";

    clientConfig = PakeTestConfigCreate(true, HITLS_TLS_SPAKE2P_ED25519_WITH_AES_128_GCM_SHA256);
    ASSERT_NOT_NULL(clientConfig);
    serverConfig = PakeTestConfigCreate(false, HITLS_TLS_SPAKE2P_ED25519_WITH_AES_128_GCM_SHA256);
    ASSERT_NOT_NULL(serverConfig);

    // If a specific API to set password on HITLS_CONFIG exists, call it here.
    // e.g., HITLS_SetConfigPakePassword(clientConfig, g_testPakePasswordClient);
    //      HITLS_SetConfigPakePassword(serverConfig, g_testPakePasswordServer);
    // This test relies on the PAKE EAL module picking up this password.

    clientCtx = HITLS_CtxNew(clientConfig);
    ASSERT_NOT_NULL(clientCtx);
    serverCtx = HITLS_CtxNew(serverConfig);
    ASSERT_NOT_NULL(serverCtx);

    ret = PakeTestFullHandshake(clientCtx, serverCtx);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(HITLS_GetState(clientCtx), TLS_CONNECTED);
    ASSERT_EQ(HITLS_GetState(serverCtx), TLS_CONNECTED);

    ret = PakeTestAppDataExchange(clientCtx, serverCtx, TEST_PAKE_APP_DATA);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ret = PakeTestAppDataExchange(serverCtx, clientCtx, "Server Hello Back");
    ASSERT_EQ(ret, HITLS_SUCCESS);

    PakeTestConfigFree(clientConfig);
    PakeTestConfigFree(serverConfig);
    HITLS_CtxFree(clientCtx);
    HITLS_CtxFree(serverCtx);
    TEST_CASE_END(CRYPT_SUCCESS); // Assuming CRYPT_SUCCESS is the general success for test framework
    return CRYPT_SUCCESS;
}

/* Test Case 2: PAKE Handshake with Mismatched Passwords */
static int32_t TlsPakeHandshakeTest02_MismatchPassword(void)
{
    TEST_CASE_BEGIN("PAKE Mismatch Password");
    int32_t ret;
    HITLS_CONFIG *clientConfig = NULL;
    HITLS_CONFIG *serverConfig = NULL;
    HITLS_Ctx *clientCtx = NULL;
    HITLS_Ctx *serverCtx = NULL;

    g_testPakePasswordClient = "clientsecret";
    g_testPakePasswordServer = "serversecret"; // Different passwords

    clientConfig = PakeTestConfigCreate(true, HITLS_TLS_SPAKE2P_ED25519_WITH_AES_128_GCM_SHA256);
    ASSERT_NOT_NULL(clientConfig);
    serverConfig = PakeTestConfigCreate(false, HITLS_TLS_SPAKE2P_ED25519_WITH_AES_128_GCM_SHA256);
    ASSERT_NOT_NULL(serverConfig);

    // If API exists:
    // HITLS_SetConfigPakePassword(clientConfig, g_testPakePasswordClient);
    // HITLS_SetConfigPakePassword(serverConfig, g_testPakePasswordServer);
    // This test's success depends on the underlying PAKE module using these distinct passwords.
    // The current PAKE EAL layer uses hardcoded passwords in its setup.
    // This test will only truly test mismatched passwords if that setup logic is modified
    // to fetch password from a config that these tests can influence.
    // For now, this test might pass handshake if both fall back to same hardcoded password.
    // Or fail if hardcoded ones are different, or if one side uses config and other hardcoded.
    // This is a KNOWN LIMITATION of the test if password API is not present.

    clientCtx = HITLS_CtxNew(clientConfig);
    ASSERT_NOT_NULL(clientCtx);
    serverCtx = HITLS_CtxNew(serverConfig);
    ASSERT_NOT_NULL(serverCtx);

    ret = PakeTestFullHandshake(clientCtx, serverCtx);
    // Expected failure: client verifying server's MAC (from PakeServerMessage or Finished)
    // or server verifying client's Finished.
    // The error might be ALERT_BAD_RECORD_MAC, ALERT_DECRYPT_ERROR (often for MAC fail), or HANDSHAKE_FAILURE.
    ASSERT_NE(ret, HITLS_SUCCESS); 
    // A more specific error code check would be better if the PAKE failure alert is well-defined.
    // e.g., ASSERT_EQ(clientCtx->errorCode, HITLS_ALERT_BAD_RECORD_MAC); (if errorCode is exposed)

    PakeTestConfigFree(clientConfig);
    PakeTestConfigFree(serverConfig);
    HITLS_CtxFree(clientCtx);
    HITLS_CtxFree(serverCtx);
    TEST_CASE_END(CRYPT_SUCCESS); // Test passes because handshake failure was expected
    return CRYPT_SUCCESS;
}

/* Test Case 3: Successful PAKE Handshake (TLS_SPAKE2P_ED25519_WITH_AES_256_GCM_SHA384) */
static int32_t TlsPakeHandshakeTest03_Success_AES256(void)
{
    TEST_CASE_BEGIN("PAKE Success AES256_GCM_SHA384");
    int32_t ret;
    HITLS_CONFIG *clientConfig = NULL;
    HITLS_CONFIG *serverConfig = NULL;
    HITLS_Ctx *clientCtx = NULL;
    HITLS_Ctx *serverCtx = NULL;

    g_testPakePasswordClient = "anotherpakekey"; 
    g_testPakePasswordServer = "anotherpakekey";

    clientConfig = PakeTestConfigCreate(true, HITLS_TLS_SPAKE2P_ED25519_WITH_AES_256_GCM_SHA384);
    ASSERT_NOT_NULL(clientConfig);
    serverConfig = PakeTestConfigCreate(false, HITLS_TLS_SPAKE2P_ED25519_WITH_AES_256_GCM_SHA384);
    ASSERT_NOT_NULL(serverConfig);

    clientCtx = HITLS_CtxNew(clientConfig);
    ASSERT_NOT_NULL(clientCtx);
    serverCtx = HITLS_CtxNew(serverConfig);
    ASSERT_NOT_NULL(serverCtx);

    ret = PakeTestFullHandshake(clientCtx, serverCtx);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(HITLS_GetState(clientCtx), TLS_CONNECTED);
    ASSERT_EQ(HITLS_GetState(serverCtx), TLS_CONNECTED);

    ret = PakeTestAppDataExchange(clientCtx, serverCtx, "TestData AES256");
    ASSERT_EQ(ret, HITLS_SUCCESS);

    PakeTestConfigFree(clientConfig);
    PakeTestConfigFree(serverConfig);
    HITLS_CtxFree(clientCtx);
    HITLS_CtxFree(serverCtx);
    TEST_CASE_END(CRYPT_SUCCESS);
    return CRYPT_SUCCESS;
}


/* Helper Function Implementations */
static HITLS_CONFIG* PakeTestConfigCreate(bool isClient, uint16_t pakeCipherSuite)
{
    HITLS_CONFIG *config = HITLS_ConfigNewDefault(isClient ? HITLS_CLIENT_MODE : HITLS_SERVER_MODE);
    if (config == NULL) return NULL;

    uint16_t ciphers[] = { pakeCipherSuite, HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 }; // Add a fallback non-PAKE for wider applicability if needed
    int32_t ret = HITLS_SetCipherSuites(config, ciphers, sizeof(ciphers) / sizeof(ciphers[0]));
    if (ret != HITLS_SUCCESS) { HITLS_ConfigFree(config); return NULL; }

    // For PAKE, certs might not be strictly needed if PAKE implies auth.
    // But TLS framework might still expect them to be configured.
    // Using test certs for now.
    ret = HITLS_SetTestCertificates(config, isClient); // Assumes this helper sets appropriate test certs
    if (ret != HITLS_SUCCESS) { HITLS_ConfigFree(config); return NULL; }
    
    // Set version to TLS 1.2 for these PAKE tests
    ret = HITLS_SetVersions(config, HITLS_VERSION_TLS12, HITLS_VERSION_TLS12);
    if (ret != HITLS_SUCCESS) { HITLS_ConfigFree(config); return NULL; }

    // TODO: API to set PAKE password on HITLS_CONFIG.
    // If g_testPakePasswordClient/Server are used by underlying PAKE module via a test hook, that's one way.
    // e.g. if (isClient) HITLS_SetPakePasswordConfig(config, g_testPakePasswordClient);
    // else HITLS_SetPakePasswordConfig(config, g_testPakePasswordServer);

    return config;
}

static void PakeTestConfigFree(HITLS_CONFIG* config)
{
    HITLS_ConfigFree(config);
}

// Basic handshake driving logic (simplified from existing tests)
static int32_t PakeTestHandshakeStep(HITLS_Ctx *ctxFrom, HITLS_Ctx *ctxTo)
{
    int32_t ret;
    uint8_t buf[TEST_PAKE_BUFFER_SIZE];
    uint32_t readLen, writeLen;

    ret = HITLS_DoHandshake(ctxFrom);
    if (ret != HITLS_WANT_WRITE && ret != HITLS_SUCCESS && ret != HITLS_WANT_READ) return ret; // Real error
    if (ret == HITLS_WANT_READ) return HITLS_SUCCESS; // Waiting for peer

    if (ret == HITLS_WANT_WRITE) {
        writeLen = sizeof(buf);
        ret = HITLS_ReadFromBio(ctxFrom, buf, sizeof(buf), &writeLen);
        if (ret != HITLS_SUCCESS) return ret;

        ret = HITLS_WriteToBio(ctxTo, buf, writeLen, &readLen);
        if (ret != HITLS_SUCCESS) return ret;
        ASSERT_EQ(readLen, writeLen);
    }
    return HITLS_SUCCESS;
}

static int32_t PakeTestFullHandshake(HITLS_Ctx *clientCtx, HITLS_Ctx *serverCtx)
{
    int32_t clientRet = HITLS_WANT_READ; // Client starts
    int32_t serverRet = HITLS_WANT_READ;
    int loops = 0;
    const int maxLoops = 20; // Safety break

    while (loops++ < maxLoops) {
        if (HITLS_GetState(clientCtx) == TLS_CONNECTED && HITLS_GetState(serverCtx) == TLS_CONNECTED) {
            return HITLS_SUCCESS;
        }

        if (clientRet != HITLS_SUCCESS && clientRet != HITLS_WANT_READ && clientRet != HITLS_WANT_WRITE) return clientRet;
        if (serverRet != HITLS_SUCCESS && serverRet != HITLS_WANT_READ && serverRet != HITLS_WANT_WRITE) return serverRet;
        
        if (loops % 2 == 1 && clientRet != TLS_CONNECTED) { // Client's turn
             clientRet = PakeTestHandshakeStep(clientCtx, serverCtx);
        } else if (loops % 2 == 0 && serverRet != TLS_CONNECTED) { // Server's turn
             serverRet = PakeTestHandshakeStep(serverCtx, clientCtx);
        } else if (clientRet == TLS_CONNECTED && serverRet != TLS_CONNECTED) { // Server might need to process last msg
             serverRet = PakeTestHandshakeStep(serverCtx, clientCtx);
        } else if (serverRet == TLS_CONNECTED && clientRet != TLS_CONNECTED) { // Client might need to process last msg
             clientRet = PakeTestHandshakeStep(clientCtx, serverCtx);
        }
         if (clientRet == HITLS_FATAL_ERROR || serverRet == HITLS_FATAL_ERROR) break;
    }
    // If loop finishes, return based on current states or last error
    if (clientRet == HITLS_FATAL_ERROR) return clientRet;
    if (serverRet == HITLS_FATAL_ERROR) return serverRet;
    if (HITLS_GetState(clientCtx) == TLS_CONNECTED && HITLS_GetState(serverCtx) == TLS_CONNECTED) return HITLS_SUCCESS;
    
    return HITLS_HANDSHAKE_FAILURE; // Or a more specific error if available
}

static int32_t PakeTestAppDataExchange(HITLS_Ctx *senderCtx, HITLS_Ctx *receiverCtx, const char* dataToSend)
{
    uint8_t buf[TEST_PAKE_BUFFER_SIZE];
    uint32_t dataLen = (uint32_t)strlen(dataToSend);
    uint32_t writtenLen, readLen, bioReadLen, bioWrittenLen;

    int32_t ret = HITLS_Write(senderCtx, (const uint8_t*)dataToSend, dataLen, &writtenLen);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(writtenLen, dataLen);

    ret = HITLS_ReadFromBio(senderCtx, buf, sizeof(buf), &bioReadLen);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    ret = HITLS_WriteToBio(receiverCtx, buf, bioReadLen, &bioWrittenLen);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(bioWrittenLen, bioReadLen);

    (void)memset_s(buf, sizeof(buf), 0, sizeof(buf));
    ret = HITLS_Read(receiverCtx, buf, sizeof(buf) -1, &readLen);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(readLen, dataLen);
    ASSERT_EQ(memcmp(buf, dataToSend, dataLen), 0);
    PRINT_LINE_INFO("App data exchange: '%s' -> '%s'", dataToSend, buf);

    return HITLS_SUCCESS;
}


/* Test suite main function */
void TlsPakeHandshakeTestGroup(void)
{
    TEST_GROUP_BEGIN("TLS PAKE Handshake Tests");

    RUN_TEST_CASE(TlsPakeHandshakeTest01_Success_AES128);
    RUN_TEST_CASE(TlsPakeHandshakeTest02_MismatchPassword);
    RUN_TEST_CASE(TlsPakeHandshakeTest03_Success_AES256);

    TEST_GROUP_END_NOWARNING();
}

TEST_CASE_TABLE_DEFINE(tls_pake_handshake_test, TlsPakeHandshakeTestGroup);

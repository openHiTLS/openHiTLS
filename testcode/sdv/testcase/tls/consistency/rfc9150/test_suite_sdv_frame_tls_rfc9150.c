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
/* INCLUDE_BASE test_suite_sdv_frame_tls_rfc9150 */

#include <string.h>
#include "hitls.h"
#include "hitls_error.h"
#include "frame_tls.h"
#include "frame_io.h"
#include "alert.h"
#include "helper.h"
#include "crypto_test_util.h"

/* END_HEADER */

/** @
* @test UT_TLS_RFC9150_FRAME_APP_ROUNDTRIP_TC001
* @title RFC 9150: TLS 1.3 handshake with TLS_SHA256_SHA256, then application data over integrity-only record protection
* @precon RFC 9150 / TLS 1.3 integrity cipher enabled in the build
* @brief
* 1. Configure client and server with only HITLS_TLS_SHA256_SHA256.
* 2. Complete handshake (HS_STATE_BUTT) via FRAME.
* 3. Client sends application data; server reads and checks plaintext.
* @expect
* 1. Negotiated cipher suite is HITLS_TLS_SHA256_SHA256; application data round-trips.
@ */
/* BEGIN_CASE */
void UT_TLS_RFC9150_FRAME_APP_ROUNDTRIP_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = HS_STATE_BUTT;
    testInfo.isClient = true;
    testInfo.emsMode = HITLS_EMS_MODE_FORCE;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = true;

    int32_t pret = Rfc9150Tls13InitConfig(&testInfo);
    if (pret == HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE) {
        goto EXIT;
    }
    ASSERT_EQ(pret, HITLS_SUCCESS);

    int32_t sret = StatusPark(&testInfo);
    if (sret == HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE) {
        goto EXIT;
    }
    ASSERT_EQ(sret, HITLS_SUCCESS);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(testInfo.client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(testInfo.server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.version, HITLS_VERSION_TLS13);
    ASSERT_EQ(serverTlsCtx->negotiatedInfo.version, HITLS_VERSION_TLS13);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.cipherSuiteInfo.cipherSuite, HITLS_TLS_SHA256_SHA256);
    ASSERT_EQ(serverTlsCtx->negotiatedInfo.cipherSuiteInfo.cipherSuite, HITLS_TLS_SHA256_SHA256);

    const char *msg = "Hello World";
    uint32_t mlen = (uint32_t)strlen(msg);
    uint32_t writeLen = 0;
    ASSERT_EQ(HITLS_Write(testInfo.client->ssl, (uint8_t *)msg, mlen, &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, mlen);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(testInfo.server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, mlen);
    ASSERT_TRUE(memcmp(readBuf, msg, mlen) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    if (testInfo.config != NULL) {
        HITLS_CFG_FreeConfig(testInfo.config);
    }
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_RFC9150_FRAME_APP_ROUNDTRIP_TC002
* @title RFC 9150: TLS 1.3 handshake with TLS_SHA384_SHA384, then application data round-trip
* @precon RFC 9150 / TLS 1.3 integrity cipher enabled in the build
* @brief
* 1. Configure client and server with only HITLS_TLS_SHA384_SHA384.
* 2. Complete handshake (HS_STATE_BUTT) via FRAME.
* 3. Client sends application data; server reads and checks plaintext.
* @expect
* 1. Negotiated cipher suite is HITLS_TLS_SHA384_SHA384; application data round-trips.
@ */
/* BEGIN_CASE */
void UT_TLS_RFC9150_FRAME_APP_ROUNDTRIP_TC002(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = HS_STATE_BUTT;
    testInfo.isClient = true;
    testInfo.emsMode = HITLS_EMS_MODE_FORCE;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = true;

    int32_t pret = Rfc9150Tls13InitConfigWithSuite(&testInfo, HITLS_TLS_SHA384_SHA384);
    if (pret == HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE) {
        goto EXIT;
    }
    ASSERT_EQ(pret, HITLS_SUCCESS);

    int32_t sret = StatusPark(&testInfo);
    if (sret == HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE) {
        goto EXIT;
    }
    ASSERT_EQ(sret, HITLS_SUCCESS);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(testInfo.client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(testInfo.server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.version, HITLS_VERSION_TLS13);
    ASSERT_EQ(serverTlsCtx->negotiatedInfo.version, HITLS_VERSION_TLS13);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.cipherSuiteInfo.cipherSuite, HITLS_TLS_SHA384_SHA384);
    ASSERT_EQ(serverTlsCtx->negotiatedInfo.cipherSuiteInfo.cipherSuite, HITLS_TLS_SHA384_SHA384);

    const char *msg = "Hello RFC9150 SHA384";
    uint32_t mlen = (uint32_t)strlen(msg);
    uint32_t writeLen = 0;
    ASSERT_EQ(HITLS_Write(testInfo.client->ssl, (uint8_t *)msg, mlen, &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, mlen);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(testInfo.server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, mlen);
    ASSERT_TRUE(memcmp(readBuf, msg, mlen) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    if (testInfo.config != NULL) {
        HITLS_CFG_FreeConfig(testInfo.config);
    }
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_RFC9150_FRAME_BAD_RECORD_MAC_TC001
* @title RFC 9150: tamper last byte of integrity record; peer must fail with bad_record_mac
* @precon RFC 9150 integrity suite compiled in
* @brief
* 1. Complete TLS 1.3 handshake with TLS_SHA256_SHA256 only.
* 2. Client sends application data; flip one byte in the protected record before the server reads.
* @expect
* 1. HITLS_Read on server returns HITLS_REC_BAD_RECORD_MAC; alert description ALERT_BAD_RECORD_MAC.
@ */
/* BEGIN_CASE */
void UT_TLS_RFC9150_FRAME_BAD_RECORD_MAC_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = HS_STATE_BUTT;
    testInfo.isClient = true;
    testInfo.emsMode = HITLS_EMS_MODE_FORCE;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = true;

    int32_t pret = Rfc9150Tls13InitConfig(&testInfo);
    if (pret == HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE) {
        goto EXIT;
    }
    ASSERT_EQ(pret, HITLS_SUCCESS);
    int32_t sret = StatusPark(&testInfo);
    if (sret == HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE) {
        goto EXIT;
    }
    ASSERT_EQ(sret, HITLS_SUCCESS);

    const char *msg = "tamper me";
    uint32_t mlen = (uint32_t)strlen(msg);
    uint32_t writeLen = 0;
    ASSERT_EQ(HITLS_Write(testInfo.client->ssl, (uint8_t *)msg, mlen, &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, mlen);

    uint8_t wireBuf[MAX_RECORD_LENTH] = {0};
    uint32_t wireLen = 0;
    ASSERT_EQ(FRAME_TransportSendMsg(testInfo.client->io, wireBuf, MAX_RECORD_LENTH, &wireLen), HITLS_SUCCESS);
    ASSERT_TRUE(wireLen > 1u);
    wireBuf[wireLen - 1u] ^= 0xFFu;
    ASSERT_EQ(FRAME_TransportRecMsg(testInfo.server->io, wireBuf, wireLen), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(testInfo.server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_BAD_RECORD_MAC);
    ALERT_Info alertInfo = {0};
    ALERT_GetInfo(testInfo.server->ssl, &alertInfo);
    ASSERT_EQ(alertInfo.description, ALERT_BAD_RECORD_MAC);

EXIT:
    if (testInfo.config != NULL) {
        HITLS_CFG_FreeConfig(testInfo.config);
    }
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

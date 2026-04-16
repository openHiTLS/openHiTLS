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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "cipher_suite.h"

#define READ_BUF_SIZE (18 * 1024)

typedef struct {
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_HandshakeState state;
    bool isClient;
    int32_t emsMode;
    bool isSupportClientVerify;
    bool isSupportNoClientCert;
    bool isServerExtendedMasterSecret;
    bool isSupportRenegotiation;
    bool needStopBeforeRecvCCS;
} HandshakeTestInfo;

int32_t StatusPark(HandshakeTestInfo *testInfo)
{
    testInfo->client = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    testInfo->server = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    testInfo->client->needStopBeforeRecvCCS = testInfo->isClient ? testInfo->needStopBeforeRecvCCS : false;
    testInfo->server->needStopBeforeRecvCCS = testInfo->isClient ? false : testInfo->needStopBeforeRecvCCS;

    if (FRAME_CreateConnection(testInfo->client, testInfo->server, testInfo->isClient, testInfo->state) !=
        HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

/**
 * Build TLS 1.3 config with a single RFC 9150 integrity-only suite (TLS_SHA256_SHA256 or TLS_SHA384_SHA384).
 * Caller must set emsMode / client verify flags on testInfo before calling.
 * @retval HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE if the suite is not compiled in.
 */
int32_t Rfc9150Tls13InitConfigWithSuite(HandshakeTestInfo *testInfo, uint16_t cipherSuite)
{
    FRAME_Init();
    if (!CFG_CheckCipherSuiteSupported(cipherSuite)) {
        return HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE;
    }

    testInfo->config = HITLS_CFG_NewTLS13Config();
    if (testInfo->config == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);
    uint16_t cipherSuits[] = { cipherSuite };
    int32_t ret = HITLS_CFG_SetCipherSuites(testInfo->config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));
    if (ret != HITLS_SUCCESS) {
        HITLS_CFG_FreeConfig(testInfo->config);
        testInfo->config = NULL;
        return ret;
    }

    testInfo->config->emsMode = testInfo->emsMode;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;
    testInfo->config->isSupportRenegotiation = testInfo->isSupportRenegotiation;

    return HITLS_SUCCESS;
}

int32_t Rfc9150Tls13InitConfig(HandshakeTestInfo *testInfo)
{
    return Rfc9150Tls13InitConfigWithSuite(testInfo, HITLS_TLS_SHA256_SHA256);
}

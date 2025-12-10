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
#include <stddef.h>
#include <unistd.h>
#include "securec.h"
#include "bsl_sal.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "hitls_cert_reg.h"
#include "hitls_crypt_type.h"
#include "tls.h"
#include "hs.h"
#include "hs_ctx.h"
#include "hs_state_recv.h"
#include "conn_init.h"
#include "recv_process.h"
#include "stub_replace.h"
#include "stub_crypt.h"
#include "frame_tls.h"
#include "frame_msg.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "pack_frame_msg.h"
#include "frame_io.h"
#include "frame_link.h"
#include "cert.h"
#include "cert_mgr.h"
#include "hs_extensions.h"
#include "hlt_type.h"
#include "hlt.h"
#include "sctp_channel.h"
#include "rec_wrapper.h"
#include "process.h"
#include "pthread.h"
#include "unistd.h"
#include "rec_header.h"
#include "bsl_log.h"
#include "cert_callback.h"


#define BUF_SIZE_DTO_TEST 18432
int32_t g_uiPort = 18887;

#define PARSEMSGHEADER_LEN 13
#define ILLEGAL_VALUE 0xFF
#define HASH_EXDATA_LEN_ERROR 23
#define SIGNATURE_ALGORITHMS 0x04, 0x03
#define READ_BUF_SIZE (18 * 1024)
#define TEMP_DATA_LEN 1024
#define REC_DTLS_RECORD_HEADER_LEN 13
#define BUF_TOOLONG_LEN ((1 << 14) + 1)

typedef struct {
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_HandshakeState state;
    bool isClient;
    bool isSupportExtendMasterSecret;
    bool isSupportClientVerify;
    bool isSupportNoClientCert;
} HandshakeTestInfo;

int32_t StatusPark(HandshakeTestInfo *testInfo, int uioType)
{
    int ret;
    testInfo->client = FRAME_CreateLink(testInfo->config, uioType);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    testInfo->server = FRAME_CreateLink(testInfo->config, uioType);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    ret = FRAME_CreateConnection(testInfo->client, testInfo->server,
        testInfo->isClient, testInfo->state);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
}

int32_t DefaultCfgStatusPark(HandshakeTestInfo *testInfo, int uioType)
{
    FRAME_Init();
    // FRAME_RegCryptMethod(); // stub all crypto functions

    testInfo->config = HITLS_CFG_NewDTLS12Config();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);
    HITLS_CFG_SetDtlsCookieExchangeSupport(testInfo->config, false);
    testInfo->config->isSupportExtendMasterSecret = testInfo->isSupportExtendMasterSecret;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;
    testInfo->config->isSupportDhAuto = true;
    return StatusPark(testInfo, uioType);
}

int32_t DefaultCfgStatusParkWithSuite(HandshakeTestInfo *testInfo, int uioType)
{
    FRAME_Init();

    testInfo->config = HITLS_CFG_NewDTLS12Config();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);
    uint16_t cipherSuits[] = {HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384};
    HITLS_CFG_SetCipherSuites(testInfo->config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));

    testInfo->config->isSupportExtendMasterSecret = testInfo->isSupportExtendMasterSecret;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;

    return StatusPark(testInfo, uioType);
}

int32_t SendHelloReqWithIndex(HITLS_Ctx *ctx, uint8_t index)
{
    uint8_t buf[DTLS_HS_MSG_HEADER_SIZE] = {0u};
    buf[5] = index;
    size_t len = DTLS_HS_MSG_HEADER_SIZE;


    return REC_Write(ctx, REC_TYPE_HANDSHAKE, buf, len);
}

int32_t ConstructAnEmptyCertMsg(FRAME_LinkObj *link)
{
    FRAME_Msg frameMsg = {0};
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(link->io);


    uint8_t *buffer = ioUserData->recMsg.msg;
    uint32_t len = ioUserData->recMsg.len;
    if (len == 0) {
        return HITLS_MEMCPY_FAIL;
    }


    uint32_t parseLen = 0;
    if (ParserTotalRecord(link, &frameMsg, buffer, len, &parseLen) != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }


    CERT_Item *tmpCert = frameMsg.body.handshakeMsg.body.certificate.cert;
    frameMsg.body.handshakeMsg.body.certificate.cert = NULL;
    frameMsg.bodyLen = 15;


    if (PackFrameMsg(&frameMsg) != HITLS_SUCCESS) {
        frameMsg.body.handshakeMsg.body.certificate.cert = tmpCert;
        CleanRecordBody(&frameMsg);
        return HITLS_INTERNAL_EXCEPTION;
    }


    ioUserData->recMsg.len = 0;
    if (FRAME_TransportRecMsg(link->io, frameMsg.buffer, frameMsg.len) != HITLS_SUCCESS) {
        frameMsg.body.handshakeMsg.body.certificate.cert = tmpCert;
        CleanRecordBody(&frameMsg);
        return HITLS_INTERNAL_EXCEPTION;
    }

    frameMsg.body.handshakeMsg.body.certificate.cert = tmpCert;
    CleanRecordBody(&frameMsg);
    return HITLS_SUCCESS;
}


static int32_t GetDisorderClientFinished(FRAME_LinkObj *client, uint8_t *data, uint32_t len, uint32_t *usedLen)
{
    int32_t ret;
    uint32_t readLen = 0;
    uint32_t offset = 0;
    (void)HITLS_Connect(client->ssl);
    ret = FRAME_TransportSendMsg(client->io, &data[offset], len - offset, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    offset += readLen;
    uint8_t tmpData[TEMP_DATA_LEN] = {0};
    uint32_t tmpLen = sizeof(tmpData);
    (void)HITLS_Connect(client->ssl);
    ret = FRAME_TransportSendMsg(client->io, tmpData, tmpLen, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    tmpLen = readLen;
    (void)HITLS_Connect(client->ssl);
    ret = FRAME_TransportSendMsg(client->io, &data[offset], len - offset, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    offset += readLen;
    if (memcpy_s(&data[offset], len - offset, tmpData, tmpLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += tmpLen;
    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t GetDisorderServerFinished(FRAME_LinkObj *server, uint8_t *data, uint32_t len, uint32_t *usedLen)
{
    int32_t ret;
    uint32_t readLen = 0;
    uint32_t offset = 0;
    uint8_t tmpData[TEMP_DATA_LEN] = {0};
    uint32_t tmpLen = sizeof(tmpData);
    (void)HITLS_Accept(server->ssl);
    ret = FRAME_TransportSendMsg(server->io, tmpData, tmpLen, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    tmpLen = readLen;
    (void)HITLS_Accept(server->ssl);
    ret = FRAME_TransportSendMsg(server->io, &data[offset], len - offset, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    offset += readLen;
    if (memcpy_s(&data[offset], len - offset, tmpData, tmpLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += tmpLen;
    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t AppWrite(HITLS_Ctx *ctx)
{
    int32_t ret;
    uint8_t writeBuf[] = "GET HTTP 1.0";
    uint32_t len = strlen((char *)writeBuf);
    do {
        uint32_t writeLen;
        ret = HITLS_Write(ctx, writeBuf, len, &writeLen);
    } while (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY);
    return ret;
}

static int32_t GetDisorderClientFinished_AppData(FRAME_LinkObj *client, uint8_t *data, uint32_t len, uint32_t *usedLen)
{
    int32_t ret;
    uint32_t readLen = 0;
    uint32_t offset = 0;
    uint8_t app[TEMP_DATA_LEN] = {0};
    uint32_t appLen = sizeof(app);
    uint8_t finished[TEMP_DATA_LEN] = {0};
    uint32_t finishedLen = sizeof(finished);
    (void)HITLS_Connect(client->ssl);
    ret = FRAME_TransportSendMsg(client->io, finished, finishedLen, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    finishedLen = readLen;
    appLen=finishedLen;
    if (memcpy_s(app, appLen, finished, finishedLen) != EOK) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    app[0] = 23;
    if (memcpy_s(&data[offset], len - offset, app, appLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += appLen;
    if (memcpy_s(&data[offset], len - offset, finished, finishedLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += finishedLen;
    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t GetDisorderServerFinish_AppData(FRAME_LinkObj *server, uint8_t *data, uint32_t len, uint32_t *usedLen)
{
    int32_t ret;
    uint32_t readLen = 0;
    uint32_t offset = 0;
    uint8_t ccs[TEMP_DATA_LEN] = {0};
    uint32_t ccsLen = sizeof(ccs);
    (void)HITLS_Accept(server->ssl);
    ret = FRAME_TransportSendMsg(server->io, ccs, ccsLen, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    ccsLen = readLen;
    uint8_t finished[TEMP_DATA_LEN] = {0};
    uint32_t finishedLen = sizeof(finished);
    (void)HITLS_Accept(server->ssl);
    ret = FRAME_TransportSendMsg(server->io, finished, finishedLen, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    finishedLen = readLen;
    uint8_t app[TEMP_DATA_LEN] = {0};
    uint32_t appLen = sizeof(finished);
    ret = AppWrite(server->ssl);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = FRAME_TransportSendMsg(server->io, app, appLen, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    appLen = readLen;
    if (memcpy_s(&data[offset], len - offset, ccs, ccsLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += ccsLen;
    if (memcpy_s(&data[offset], len - offset, app, appLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += appLen;
    if (memcpy_s(&data[offset], len - offset, finished, finishedLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += finishedLen;
    *usedLen = offset;
    return HITLS_SUCCESS;
}

int32_t DefaultCfgStatusPark1(HandshakeTestInfo *testInfo, int uioType)
{
    FRAME_Init();
    testInfo->config = HITLS_CFG_NewDTLS12Config();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);
    uint16_t groups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo->config, groups, sizeof(groups) / sizeof(uint16_t));
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(testInfo->config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    HITLS_CFG_SetClientVerifySupport(testInfo->config, testInfo->isSupportClientVerify);
    HITLS_CFG_SetNoClientCertSupport(testInfo->config, false);
    HITLS_CFG_SetExtenedMasterSecretSupport(testInfo->config, true);
    return StatusPark(testInfo, uioType);
}

static int32_t GetRepeatsApp(FRAME_LinkObj *obj, uint8_t *data, uint32_t *usedLen)
{
    int32_t ret;
    uint32_t readLen = 0;
    uint32_t offset = 0;
    uint8_t app[TEMP_DATA_LEN] = {0};
    uint32_t appLen = sizeof(app);
    ret = AppWrite(obj->ssl);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = FRAME_TransportSendMsg(obj->io, app, appLen, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    appLen = readLen;
    if (memcpy_s(&data[offset], TEMP_DATA_LEN, app, appLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += appLen;
    if (memcpy_s(&data[offset], TEMP_DATA_LEN - offset, app, appLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += appLen;
    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t GetDisorderApp(FRAME_LinkObj *obj, uint8_t *data, uint32_t *usedLen)
{
    int32_t ret;
    uint32_t readLen = 0;
    uint32_t offset = 0;
    uint8_t app1[TEMP_DATA_LEN] = {0};
    uint32_t app1Len = sizeof(app1);
    ret = AppWrite(obj->ssl);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = FRAME_TransportSendMsg(obj->io, app1, app1Len, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    app1Len = readLen;
    uint8_t app2[TEMP_DATA_LEN] = {0};
    uint32_t app2Len = sizeof(app2);
    ret = AppWrite(obj->ssl);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = FRAME_TransportSendMsg(obj->io, app2, app2Len, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    app2Len = readLen;
    if (memcpy_s(&data[offset], TEMP_DATA_LEN, app2, app2Len) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += app2Len;
    if (memcpy_s(&data[offset], TEMP_DATA_LEN - offset, app1, app1Len) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += app1Len;
    *usedLen = offset;
    return HITLS_SUCCESS;
}
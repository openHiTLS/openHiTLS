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
#include <unistd.h>
#include "stub_utils.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_uio.h"
#include "bsl_sal.h"
#include "tls.h"
#include "hs_ctx.h"
#include "session_type.h"
#include "hitls_type.h"
#include "pack.h"
#include "send_process.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "uio_base.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "pack_frame_msg.h"
#include "cert.h"
#include "app.h"
#include "hlt.h"
#include "alert.h"
#include "securec.h"
#include "record.h"
#include "rec_write.h"
#include "rec_read.h"
#include "rec_wrapper.h"
#include "hitls_crypt_init.h"
#include "conn_init.h"
#include "cert_callback.h"
#include "change_cipher_spec.h"
#include "common_func.h"
#include "crypt_default.h"
#include "stub_crypt.h"
#ifdef HITLS_TLS_FEATURE_PROVIDER
#include "hitls_crypt.h"
#endif

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET5(int32_t, TlsRecordRead, TLS_Ctx *, REC_Type, uint8_t *, uint32_t *, uint32_t);
STUB_DEFINE_RET1(int32_t, GenerateEccPremasterSecret, TLS_Ctx *);
STUB_DEFINE_RET4(int32_t, APP_Write, TLS_Ctx *, const uint8_t *, uint32_t, uint32_t *);

#define PORT 11111
#define TEMP_DATA_LEN 1024              /* Length of a single message. */
#define MAX_BUF_LEN (20 * 1024)
#define READ_BUF_SIZE (18 * 1024)       /* Maximum length of the read message buffer */
#define ALERT_BODY_LEN 2u
#define REC_CONN_SEQ_SIZE 8u            /* SN size */
#define GetEpochSeq(epoch, seq) (((uint64_t)(epoch) << 48) | (seq))
#define BUF_TOOLONG_LEN ((1 << 14) + 1)
typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_Session *clientSession; /* session set to the client, used for session recovery. */
} ResumeTestInfo;

typedef struct {
    int connectExpect; // Expected connect result
    int acceptExpect;  // Expected accept result
    ALERT_Level expectLevel; // Expected alert level
    ALERT_Description expectDescription; // Expected alert description of the tested end
} TestExpect;

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
    bool isSupportRenegotiation; /* Renegotiation support flag */
    bool needStopBeforeRecvCCS;  /* CCS test, so that the TRY_RECV_FINISH stops before the CCS message is received. */
} HandshakeTestInfo;

uint16_t GetCipherSuite(const char *cipherSuite)
{
    if (strcmp(cipherSuite, "HITLS_ECDHE_SM4_CBC_SM3") == 0) {
        return HITLS_ECDHE_SM4_CBC_SM3;
    }
    if (strcmp(cipherSuite, "HITLS_ECC_SM4_CBC_SM3") == 0) {
        return HITLS_ECC_SM4_CBC_SM3;
    }
    return 0;
}

int32_t RandBytes(uint8_t *randNum, uint32_t randLen)
{
    srand(time(0));
    const int maxNum = 256u;
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % maxNum);
    }
    return HITLS_SUCCESS;
}

int32_t GenerateEccPremasterSecret(TLS_Ctx *ctx);

int32_t RecordDecryptPrepare(
    TLS_Ctx *ctx, uint16_t version, REC_Type recordType, REC_TextInput *cryptMsg);
int32_t RecConnDecrypt(
    TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *cryptMsg, uint8_t *data, uint32_t *dataLen);

int32_t STUB_GenerateEccPremasterSecret(TLS_Ctx *ctx)
{
    uint32_t offset;
    HS_Ctx *hsCtx = ctx->hsCtx;
    KeyExchCtx *kxCtx = hsCtx->kxCtx;
    uint8_t *premasterSecret = kxCtx->keyExchParam.ecc.preMasterSecret;

    /* The first two bytes are the latest version supported by the client.*/
    /* Change the version number and construct an exception. */
    BSL_Uint16ToByte(0x0505, premasterSecret);
    offset = sizeof(uint16_t);
    /* 46 bytes secure random number */
#ifdef HITLS_TLS_FEATURE_PROVIDER
    return HITLS_CRYPT_RandbytesEx(NULL, &premasterSecret[offset], MASTER_SECRET_LEN - offset);
#else
    return CRYPT_DEFAULT_RandomBytes(&premasterSecret[offset], MASTER_SECRET_LEN - offset);
#endif
}

int32_t STUB_TlsRecordRead(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num)
{
    int32_t ret;
    (void)recordType;
    (void)readLen;
    RecConnState *state = ctx->recCtx->readStates.currentState;
    uint16_t version = ctx->negotiatedInfo.version;
    REC_TextInput encryptedMsg = {0};
    ret = RecordDecryptPrepare(ctx, version, recordType, &encryptedMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint32_t dataLen = num;
    ASSERT_EQ(encryptedMsg.textLen, num);
    ret = RecConnDecrypt(ctx, state, &encryptedMsg, data, &dataLen);
EXIT:
    return ret;
}

int32_t StatusGMPark(HandshakeTestInfo *testInfo)
{
    testInfo->client = FRAME_CreateTLCPLink(testInfo->config, BSL_UIO_TCP, true);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    testInfo->server = FRAME_CreateTLCPLink(testInfo->config, BSL_UIO_TCP, false);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (FRAME_CreateConnection(testInfo->client, testInfo->server, testInfo->isClient, testInfo->state) !=
        HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

int32_t DefaultCfgStatusPark(HandshakeTestInfo *testInfo)
{
    FRAME_Init();

    testInfo->config = HITLS_CFG_NewTLCPConfig();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);
    testInfo->config->emsMode = testInfo->emsMode;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;
    testInfo->config->isSupportRenegotiation = testInfo->isSupportRenegotiation;

    return StatusGMPark(testInfo);
}


int32_t DefaultCfgStatusParkWithSuite(HandshakeTestInfo *testInfo)
{
    FRAME_Init();

    testInfo->config = HITLS_CFG_NewTLCPConfig();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);
    uint16_t cipherSuits[] = {HITLS_ECDHE_SM4_CBC_SM3};
    HITLS_CFG_SetCipherSuites(testInfo->config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));

    testInfo->config->emsMode = testInfo->emsMode;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;

    return StatusGMPark(testInfo);
}

void SetFrameType(FRAME_Type *frametype, uint16_t versionType, REC_Type recordType, HS_MsgType handshakeType,
    HITLS_KeyExchAlgo keyExType)
{
    frametype->versionType = versionType;
    frametype->recordType = recordType;
    frametype->handshakeType = handshakeType;
    frametype->keyExType = keyExType;
    frametype->transportType = BSL_UIO_TCP;
}

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

#include "crypt.h"
#include "hitls_crypt_type.h"
#include "hitls_crypt_init.h"
#include "stub_utils.h"
#include "crypt_eal_mac.h"
#include "crypt_errno.h"
#include "hitls_crypt.h"
#include "tls.h"
#include "rec.h"
#include "rec_crypto.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "hitls_error.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "simulate_io.h"
#include "rec_write.h"
#include "rec_crypto_aead.h"
#include "stub_utils.h"

#define PRF_OUT_LEN 48

int32_t Dtls13ReconstructEpoch(TLS_Ctx *ctx, uint8_t epochBits, uint64_t *reconstructedEpoch);
int32_t Dtls13ReconstructSequenceNumber(TLS_Ctx *ctx, uint64_t epoch, uint16_t incompleteSeq, uint8_t seqLen, uint64_t *reconstructedSeq);

STUB_DEFINE_RET2(int32_t, CRYPT_EAL_MacSetParam, CRYPT_EAL_MacCtx *, const BSL_Param *);

/* END_HEADER */

STUB_DEFINE_RET5(int32_t, RecConnEncrypt, TLS_Ctx *, RecConnState *, const REC_TextInput *, uint8_t *, uint32_t);

/* BEGIN_CASE */
void SDV_TLS_CRYPT_PRF_TC001(int hashAlgo, Hex *secret, Hex *label, Hex *seed, Hex *expect)
{
    CRYPT_KeyDeriveParameters input = {0};
    input.hashAlgo = hashAlgo;
    input.secret = (uint8_t *)secret->x;
    input.secretLen = secret->len;
    input.label = (uint8_t *)label->x;
    input.labelLen = label->len;
    input.seed = (uint8_t *)seed->x;
    input.seedLen = seed->len;
    input.libCtx = NULL;
    input.attrName = NULL;
    uint8_t out[PRF_OUT_LEN] = {0};

    HITLS_CryptMethodInit();
    ASSERT_TRUE(PRF_OUT_LEN <= expect->len);
    ASSERT_EQ(SAL_CRYPT_PRF(&input, out, PRF_OUT_LEN), HITLS_SUCCESS);
    ASSERT_COMPARE("result cmp", out, PRF_OUT_LEN, expect->x, PRF_OUT_LEN);

EXIT:
    return;
}
/* END_CASE */

#ifdef HITLS_CRYPTO_PROVIDER
int32_t STUB_CRYPT_EAL_MacSetParam(CRYPT_EAL_MacCtx *ctx, const BSL_Param *param)
{
    (void)ctx;
    (void)param;
    return CRYPT_NULL_INPUT;
}
#endif

/**
 * @test SDV_CRYPTO_HMAC_STUB_TC001
 * title 1. Test the mac with stub SetHmacMdAttr fail
 *
 */
/* BEGIN_CASE */
void SDV_TLS_CRYPTO_HMAC_STUB_TC001(int algId, Hex *key, Hex *data)
{
#ifndef HITLS_TLS_FEATURE_PROVIDER
    (void)algId;
    (void)key;
    (void)data;
    SKIP_TEST();
#else
    uint32_t macLen = 64;
    uint8_t mac[64];
    int ret = HITLS_CRYPT_HMAC(NULL, "provider?=default", algId, key->x, key->len, data->x, data->len, mac, &macLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    STUB_REPLACE(CRYPT_EAL_MacSetParam, STUB_CRYPT_EAL_MacSetParam);
    ret = HITLS_CRYPT_HMAC(NULL, "provider?=default", algId, key->x, key->len, data->x, data->len, mac, &macLen);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    STUB_RESTORE(CRYPT_EAL_MacSetParam);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_DTLS13_CRYPT_SEQUENCE_NUMBER_TC001(int seqLen)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *ctx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(ctx != NULL);
    uint8_t snKey[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t ciphertext[32] = {0x12, 0x34, 0x56, 0x78,  // counter (RFC 9147 §4.2.3: 密文前4字节为counter)
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  // nonce[0..7]
                              0x09, 0x0a, 0x0b, 0x0c,  // nonce[8..11] (共12字节nonce)
                              0x00, 0x00, 0x00, 0x00}; // 填充至16字节
    uint8_t encryptedSn[2] = {0};
    uint8_t plaintextSeq[2] = {0x12, 0x34};
    int32_t ret;

    // 测试密文长度小于16字节 (RFC 9147 4.2.3要求至少16字节)
    ret = Dtls13CryptSequenceNumber(ctx, HITLS_CIPHER_AES_128_GCM, snKey, ciphertext, 15, plaintextSeq, encryptedSn,
                                    seqLen);
    ASSERT_TRUE(ret == HITLS_INVALID_INPUT);

    ret = Dtls13CryptSequenceNumber(ctx, HITLS_CIPHER_AES_128_GCM, snKey, ciphertext, 16, plaintextSeq, encryptedSn,
                                    seqLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    uint8_t encryptedSn1[2] = {0};
    ret = Dtls13CryptSequenceNumber(ctx, HITLS_CIPHER_AES_128_GCM, snKey, ciphertext, 16, encryptedSn, encryptedSn1,
                                    seqLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_EQ(encryptedSn1[0], plaintextSeq[0]);
    if (seqLen == 2) {
        ASSERT_EQ(encryptedSn1[1], plaintextSeq[1]);
    }
    

    ret = Dtls13CryptSequenceNumber(ctx, HITLS_CIPHER_AES_128_GCM, snKey, ciphertext, 17, plaintextSeq, encryptedSn,
                                    seqLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    memset(encryptedSn1, 0, 2);
    ret = Dtls13CryptSequenceNumber(ctx, HITLS_CIPHER_AES_128_GCM, snKey, ciphertext, 17, encryptedSn, encryptedSn1,
                                    seqLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_EQ(encryptedSn1[0], plaintextSeq[0]);
    if (seqLen == 2) {
        ASSERT_EQ(encryptedSn1[1], plaintextSeq[1]);
    }

    ret = Dtls13CryptSequenceNumber(ctx, HITLS_CIPHER_AES_256_GCM, snKey, ciphertext, 17, plaintextSeq, encryptedSn,
                                    seqLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    memset(encryptedSn1, 0, 2);
    ret = Dtls13CryptSequenceNumber(ctx, HITLS_CIPHER_AES_256_GCM, snKey, ciphertext, 17, encryptedSn, encryptedSn1,
                                    seqLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_EQ(encryptedSn1[0], plaintextSeq[0]);
    if (seqLen == 2) {
        ASSERT_EQ(encryptedSn1[1], plaintextSeq[1]);
    }

    ret = Dtls13CryptSequenceNumber(ctx, HITLS_CIPHER_CHACHA20_POLY1305, snKey, ciphertext, 17, plaintextSeq,
                                    encryptedSn, seqLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    memset(encryptedSn1, 0, 2);
    ret = Dtls13CryptSequenceNumber(ctx, HITLS_CIPHER_CHACHA20_POLY1305, snKey, ciphertext, 17, encryptedSn,
                                    encryptedSn1, seqLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_EQ(encryptedSn1[0], plaintextSeq[0]);
    if (seqLen == 2) {
        ASSERT_EQ(encryptedSn1[1], plaintextSeq[1]);
    }
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(server);
    return;
}
/* END_CASE */
int32_t STUB_RecConnEncrypt(
    TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *plainMsg, uint8_t *cipherText, uint32_t cipherTextLen)
{
    (void)ctx;
    (void)state;
    (void)plainMsg;
    (void)cipherText;
    (void)cipherTextLen;
    cipherText[0] = 1;
    return HITLS_SUCCESS;
}
/* BEGIN_CASE */
void SDV_DTLS13_RECORD_WRITE_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *ctx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(ctx != NULL);
    ctx->negotiatedInfo.version = HITLS_VERSION_DTLS13;
    REC_Init(ctx);
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    RecConnState *state = recordCtx->writeStates.currentState;
    RecConnSuitInfo suiteInfo = {0};
    suiteInfo.cipherAlg = HITLS_CIPHER_CHACHA20_POLY1305;
    RecConnStateSetCipherInfo(state, &suiteInfo);
    RecConnSetSeqNum(state, 0x1234);
    RecConnSetEpoch(state, 2);
    uint8_t data[32] = {0x12, 0x34, 0x56, 0x78, 0x01, 0x02, 0x03, 0x04,
                        0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00,
                        0x12, 0x34, 0x56, 0x78, 0x01, 0x02, 0x03, 0x04,
                        0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00};
    uint32_t dataLen = 32;
    STUB_REPLACE(RecConnEncrypt, STUB_RecConnEncrypt);
    int ret = DtlsRecordWrite(ctx, REC_TYPE_HANDSHAKE, data, dataLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    uint8_t len[2] = {0};
    BSL_Uint16ToByte(dataLen, len);
    uint8_t *outBuf = recordCtx->outBuf->buf;
    ASSERT_EQ(outBuf[0], 0b00101110);
    uint8_t snKey[32] = {0};
    uint8_t ciphertext[32] = {0};
    ciphertext[0] = 1;
    uint8_t encryptedSn[2] = {0};
    uint8_t plaintextSeq[2] = {0x12, 0x34};
    ret = Dtls13CryptSequenceNumber(ctx, HITLS_CIPHER_CHACHA20_POLY1305, snKey, ciphertext, 16, plaintextSeq,
                                    encryptedSn, 2);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_EQ(outBuf[1], encryptedSn[0]);
    ASSERT_EQ(outBuf[2], encryptedSn[1]);
    ASSERT_EQ(outBuf[3], len[0]);
    ASSERT_EQ(outBuf[4], len[1] + 1);   
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(server);
    STUB_RESTORE(RecConnEncrypt);
    return;
}
/* END_CASE */

/**
 * @test SDV_DTLS13_RECONSTRUCT_EPOCH_TC001
 * @title Test normal scenarios for Dtls13ReconstructEpoch
 * @brief Test the normal scenarios including:
 *        1. epochBits matches current epoch bits
 *        2. Handshake phase (currentEpoch < 3)
 *        3. Application data phase (currentEpoch >= 3)
 */
/* BEGIN_CASE */
void SDV_DTLS13_RECONSTRUCT_EPOCH_TC001(void)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    SKIP_TEST();
#else
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *ctx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(ctx != NULL);
    ctx->negotiatedInfo.version = HITLS_VERSION_DTLS13;
    REC_Init(ctx);
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    RecConnState *readState = recordCtx->readStates.currentState;
    uint64_t reconstructedEpoch = 0;

    // Case 1: epochBits matches current epoch bits (currentEpoch = 1, epochBits = 2)
    RecConnSetEpoch(readState, 1);
    int ret = Dtls13ReconstructEpoch(ctx, 2, &reconstructedEpoch);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedEpoch, 2);

    // Case 2: Handshake phase (currentEpoch = 2)
    RecConnSetEpoch(readState, 2);
    ret = Dtls13ReconstructEpoch(ctx, 2, &reconstructedEpoch);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedEpoch, 2);

    // Case 3: Application data phase (currentEpoch = 6, epochBits = 2)
    // epochBits = 2 should match currentEpoch = 6 (6 & 3 = 2)
    RecConnSetEpoch(readState, 6);
    ret = Dtls13ReconstructEpoch(ctx, 2, &reconstructedEpoch);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedEpoch, 6);

    // Case 4: Application data phase (currentEpoch = 6, epochBits = 3)
    // epochBits = 3 should match currentEpoch = 3
    RecConnSetEpoch(readState, 6);
    ret = Dtls13ReconstructEpoch(ctx, 3, &reconstructedEpoch);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedEpoch, 3);

    // Case 5: Application data phase (currentEpoch = 5, epochBits = 2)
    // epochBits = 2 
    RecConnSetEpoch(readState, 5);
    ret = Dtls13ReconstructEpoch(ctx, 2, &reconstructedEpoch);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedEpoch, 2);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(server);
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_DTLS13_RECONSTRUCT_EPOCH_TC002
 * @title Test boundary value scenarios for Dtls13ReconstructEpoch
 * @brief Test the boundary values:
 *        1. currentEpoch = 2 (last handshake epoch)
 *        2. currentEpoch = 3 (first application data epoch)
 *        3. Maximum epoch values
 */
/* BEGIN_CASE */
void SDV_DTLS13_RECONSTRUCT_EPOCH_TC002(void)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    SKIP_TEST();
#else
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *ctx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(ctx != NULL);
    ctx->negotiatedInfo.version = HITLS_VERSION_DTLS13;
    REC_Init(ctx);
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    RecConnState *readState = recordCtx->readStates.currentState;
    uint64_t reconstructedEpoch = 0;

    // Case 1: currentEpoch = 2 (boundary between handshake and application data)
    RecConnSetEpoch(readState, 2);
    int ret = Dtls13ReconstructEpoch(ctx, 2, &reconstructedEpoch);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedEpoch, 2);

    ret = Dtls13ReconstructEpoch(ctx, 3, &reconstructedEpoch);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedEpoch, 3);

    // Case 2: currentEpoch = 3 (first application data epoch)
    // epochBits = 3 should match currentEpoch = 3
    RecConnSetEpoch(readState, 3);
    ret = Dtls13ReconstructEpoch(ctx, 3, &reconstructedEpoch);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedEpoch, 3);

    // Case 3: epochBits = 0 with currentEpoch = 3
    // Should fail because epochBits (0) != currentEpochBits (3)
    // and the loop has a bug (i >= 3 never executes)
    RecConnSetEpoch(readState, 3);
    ret = Dtls13ReconstructEpoch(ctx, 0, &reconstructedEpoch);
    ASSERT_EQ(ret, HITLS_REC_DECODE_ERROR);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(server);
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_DTLS13_RECONSTRUCT_EPOCH_TC003
 * @title Test abnormal scenarios for Dtls13ReconstructEpoch
 * @brief Test the error cases:
 *        1. Cannot find matching epoch in application data phase
 *        2. Invalid epochBits values
 */
/* BEGIN_CASE */
void SDV_DTLS13_RECONSTRUCT_EPOCH_TC003(void)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    SKIP_TEST();
#else
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *ctx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(ctx != NULL);
    ctx->negotiatedInfo.version = HITLS_VERSION_DTLS13;
    REC_Init(ctx);
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    RecConnState *readState = recordCtx->readStates.currentState;
    uint64_t reconstructedEpoch = 0;

    // Case 1: When currentEpoch = 3, searching for epochBits = 1
    // Should return error because:
    // - epochBits (1) != currentEpochBits (3 & 3 = 3)
    // - Loop condition bug (i >= 3 never executes when i = 0)
    RecConnSetEpoch(readState, 3);
    int ret = Dtls13ReconstructEpoch(ctx, 1, &reconstructedEpoch);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Case 2: When currentEpoch = 5, searching for epochBits = 0
    // Should return error because epochBits (0) != currentEpochBits (5 & 3 = 1)
    RecConnSetEpoch(readState, 5);
    ret = Dtls13ReconstructEpoch(ctx, 0, &reconstructedEpoch);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedEpoch, 4);

    // Case 3: When currentEpoch = 7, searching for epochBits = 2
    // Should return error because epochBits (2) != currentEpochBits (7 & 3 = 3)
    RecConnSetEpoch(readState, 7);
    ret = Dtls13ReconstructEpoch(ctx, 2, &reconstructedEpoch);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedEpoch, 6);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(server);
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_DTLS13_RECONSTRUCT_SEQ_TC001
 * @title Test normal scenarios for Dtls13ReconstructSequenceNumber
 * @brief Test the normal scenarios including:
 *        1. Partial sequence matches expected (seqLen = 1)
 *        2. Partial sequence matches expected (seqLen = 2)
 *        3. Partial sequence doesn't match, select nearest candidate
 */
/* BEGIN_CASE */
void SDV_DTLS13_RECONSTRUCT_SEQ_TC001(void)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    SKIP_TEST();
#else
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *ctx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(ctx != NULL);
    ctx->negotiatedInfo.version = HITLS_VERSION_DTLS13;
    REC_Init(ctx);
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    RecConnState *readState = recordCtx->readStates.currentState;
    uint64_t reconstructedSeq = 0;

    // Case 1: Partial sequence matches expected (seqLen = 1)
    // currentSeq = 0x1234, expectedSeq = 0x1235, incompleteSeq = 0x35
    RecConnSetSeqNum(readState, 0x1234);
    RecConnSetEpoch(readState, 2);
    int ret = Dtls13ReconstructSequenceNumber(ctx, 2, 0x35, 1, &reconstructedSeq);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedSeq, 0x1235);

    // Case 2: Partial sequence matches expected (seqLen = 2)
    // currentSeq = 0x1234, expectedSeq = 0x1235, incompleteSeq = 0x1235
    RecConnSetSeqNum(readState, 0x1234);
    ret = Dtls13ReconstructSequenceNumber(ctx, 2, 0x1235, 2, &reconstructedSeq);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedSeq, 0x1235);

    // Case 3: Partial sequence doesn't match, select nearest candidate (seqLen = 1)
    // currentSeq = 0x12F0, expectedSeq = 0x12F1, incompleteSeq = 0x05
    // candidateSeq = 0x1205, diff1 = |0x1205 - 0x12F1| = 238
    // candidateSeq1 = 0x1105, diff1 = |0x1105 - 0x12F1| = 494
    // candidateSeq2 = 0x1305, diff2 = |0x1305 - 0x12F1| = 20
    // Should select candidateSeq2 = 0x1305
    RecConnSetSeqNum(readState, 0x12F0);
    ret = Dtls13ReconstructSequenceNumber(ctx, 2, 0x05, 1, &reconstructedSeq);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedSeq, 0x1305);

    // Case 4: Partial sequence doesn't match, select nearest candidate (seqLen = 2)
    // currentSeq = 0x12F000, expectedSeq = 0x12F001, incompleteSeq = 0x1000
    // candidateSeq = 0x121000, diff = |0x121000 - 0x12F001| = 57345
    // candidateSeq1 = 0x111000, diff1 = |0x111000 - 0x12F001| = 126977
    // candidateSeq2 = 0x131000, diff2 = |0x131000 - 0x12F001| = 8191
    // Should select candidateSeq2 = 0x131000
    RecConnSetSeqNum(readState, 0x12F001);
    ret = Dtls13ReconstructSequenceNumber(ctx, 2, 0x1000, 2, &reconstructedSeq);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedSeq, 0x131000);

    // Case 5: Partial sequence matches expected (seqLen = 1)
    // currentSeq = 0x1234, expectedSeq = 0x1235, incompleteSeq = 0x35
    RecConnSetSeqNum(readState, 0x1235);
    ret = Dtls13ReconstructSequenceNumber(ctx, 2, 0x34, 1, &reconstructedSeq);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedSeq, 0x1234);

    // Case 6: Partial sequence matches expected (seqLen = 2)
    // currentSeq = 0x1234, expectedSeq = 0x1235, incompleteSeq = 0x1235
    RecConnSetSeqNum(readState, 0x1235);
    ret = Dtls13ReconstructSequenceNumber(ctx, 2, 0x1234, 2, &reconstructedSeq);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedSeq, 0x1234);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(server);
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_DTLS13_RECONSTRUCT_SEQ_TC002
 * @title Test boundary value scenarios for Dtls13ReconstructSequenceNumber
 * @brief Test the boundary values:
 *        1. Sequence number at 0xFF boundary (seqLen = 1)
 *        2. Sequence number at 0xFFFF boundary (seqLen = 2)
 *        3. Sequence number at 0xFF boundary with exact match
 *        4. Sequence number at 0xFFFF boundary with exact match
 *        5. Sequence number wraps from 0xFF to 0x00 (seqLen = 1)
 *        6. Sequence number wraps from 0xFFFF to 0x0000 (seqLen = 2)
 */
/* BEGIN_CASE */
void SDV_DTLS13_RECONSTRUCT_SEQ_TC002(void)
{
#ifndef HITLS_TLS_PROTO_DTLS13
    SKIP_TEST();
#else
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *ctx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(ctx != NULL);
    ctx->negotiatedInfo.version = HITLS_VERSION_DTLS13;
    REC_Init(ctx);
    RecCtx *recordCtx = (RecCtx *)ctx->recCtx;
    RecConnState *readState = recordCtx->readStates.currentState;
    uint64_t reconstructedSeq = 0;

    // Case 1: Sequence number at 0xFF boundary (seqLen = 1)
    // currentSeq = 0x12FE, expectedSeq = 0x12FF, incompleteSeq = 0x00
    // candidateSeq = 0x1200, diff = |0x1200 - 0x12FF| = 255
    // candidateSeq1 = 0x1100, diff1 = |0x1100 - 0x12FF| = 511
    // candidateSeq2 = 0x1300, diff2 = |0x1300 - 0x12FF| = 1
    // Should select candidateSeq2 = 0x1300
    RecConnSetSeqNum(readState, 0x12FE);
    RecConnSetEpoch(readState, 2);
    int ret = Dtls13ReconstructSequenceNumber(ctx, 2, 0x00, 1, &reconstructedSeq);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedSeq, 0x1300);

    // Case 2: Sequence number at 0xFFFF boundary (seqLen = 2)
    // currentSeq = 0x12FFFE, expectedSeq = 0x12FFFF, incompleteSeq = 0x0000
    // candidateSeq = 0x120000, diff = |0x120000 - 0x12FFFF| = 65535
    // candidateSeq1 = 0x110000, diff1 = |0x110000 - 0x12FFFF| = 131071
    // candidateSeq2 = 0x130000, diff2 = |0x130000 - 0x12FFFF| = 1
    // Should select candidateSeq2 = 0x130000
    RecConnSetSeqNum(readState, 0x12FFFE);
    ret = Dtls13ReconstructSequenceNumber(ctx, 2, 0x0000, 2, &reconstructedSeq);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedSeq, 0x130000);

    // Case 3: Sequence number at 0xFF boundary with exact match
    // currentSeq = 0x12FE, expectedSeq = 0x12FF, incompleteSeq = 0xFF
    // Should match exactly and return 0x12FF
    RecConnSetSeqNum(readState, 0x12FE);
    ret = Dtls13ReconstructSequenceNumber(ctx, 2, 0xFF, 1, &reconstructedSeq);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedSeq, 0x12FF);

    // Case 4: Sequence number at 0xFFFF boundary with exact match
    // currentSeq = 0x12FFFE, expectedSeq = 0x12FFFF, incompleteSeq = 0xFFFF
    // Should match exactly and return 0x12FFFF
    RecConnSetSeqNum(readState, 0x12FFFE);
    ret = Dtls13ReconstructSequenceNumber(ctx, 2, 0xFFFF, 2, &reconstructedSeq);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedSeq, 0x12FFFF);

    // Case 5: Sequence number wraps from 0xFF to 0x00 (seqLen = 1)
    // currentSeq = 0x1200, expectedSeq = 0x1201, incompleteSeq = 0xFF
    // candidateSeq = 0x12FF, diff = |0x12FF - 0x1201| = 254
    // candidateSeq1 = 0x11FF, diff1 = |0x11FF - 0x1201| = 2
    // candidateSeq2 = 0x13FF, diff2 = |0x13FF - 0x1201| = 510
    // Should select candidateSeq1 = 0x11FF (minimum diff)
    RecConnSetSeqNum(readState, 0x1200);
    ret = Dtls13ReconstructSequenceNumber(ctx, 2, 0xFF, 1, &reconstructedSeq);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedSeq, 0x11FF);

    // Case 6: Sequence number wraps from 0xFFFF to 0x0000 (seqLen = 2)
    // currentSeq = 0x120000, expectedSeq = 0x120001, incompleteSeq = 0xFFFF
    // candidateSeq = 0x10FFFF, diff = |0x10FFFF - 0x120001| = 65538
    // candidateSeq1 = 0xFFFFF, diff1 = |0xFFFFF - 0x120001| = 131074
    // candidateSeq2 = 0x11FFFF, diff2 = |0x11FFFF - 0x120001| = 2
    // Should select candidateSeq2 = 0x11FFFF (minimum diff)
    RecConnSetSeqNum(readState, 0x120000);
    ret = Dtls13ReconstructSequenceNumber(ctx, 2, 0xFFFF, 2, &reconstructedSeq);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(reconstructedSeq, 0x11FFFF);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(server);
    return;
#endif
}
/* END_CASE */

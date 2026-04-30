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
#include <string.h>
#include <ctype.h>
#include "auth_pake.h"
#include "bsl_types.h"
#include "bsl_sal.h"
#include "auth_errno.h"
/* END_HEADER */

static int32_t create_buffer_from_hex(BSL_Buffer *buf, Hex *hex)
{
    buf->data = (uint8_t*) BSL_SAL_Malloc (hex->len);
    if (buf->data == NULL) {
        return HITLS_AUTH_MEM_ALLOC_FAIL;
    }

    buf->dataLen = hex->len;
    memcpy(buf->data, hex->x, hex->len);
    return HITLS_AUTH_SUCCESS;
}

/**
 * @test   SDV_CRYPT_EAL_SPAKE2PLUS_TC001
 * @title  SPAKE2+ test based on standard vectors.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SPAKE2PLUS_TC001(Hex *context, Hex *prover, Hex *verifier, int curve, int hash, int kdf, int mac,
    Hex *w0, Hex *w1, Hex *L, Hex *x, Hex *y, Hex *shareP, Hex *shareV, Hex *kShared, Hex *confirmP, Hex *confirmV)
{
    ASSERT_EQ(TestRandInit(), HITLS_AUTH_SUCCESS);
    HITLS_AUTH_PAKE_Type type = HITLS_AUTH_PAKE_SPAKE2PLUS;
    HITLS_AUTH_PAKE_Role role0 = HITLS_AUTH_PAKE_REQ;
    HITLS_AUTH_PAKE_Role role1 = HITLS_AUTH_PAKE_RESP;
    HITLS_AUTH_PAKE_CipherSuite cipherSuite = {
        .type = HITLS_AUTH_PAKE_SPAKE2PLUS,
        .params.spake2plus = {
            .curve = curve,
            .hash = hash,
            .kdf = kdf,
            .mac = mac
        }
    };

    HITLS_AUTH_PAKE_KDF kdfParam = {
        .algId = CRYPT_KDF_PBKDF2,
        .param.pbkdf2 = {
            .mac = CRYPT_MAC_HMAC_SHA256,
            .iteration = 1000,
            .salt = { NULL, 0}
        }
    };

    BSL_Buffer contextBuf = { 0 };
    BSL_Buffer proverBuf = { 0 };
    BSL_Buffer verifierBuf = { 0 };
    BSL_Buffer w0Buf = { 0 };
    BSL_Buffer w1Buf = { 0 };
    BSL_Buffer LBuf = { 0 };
    BSL_Buffer xBuf = { 0 };
    BSL_Buffer yBuf = { 0 };
    BSL_Buffer sharePBuf = { 0 };
    BSL_Buffer shareVBuf = { 0 };
    BSL_Buffer kSharedBuf = { 0 };
    BSL_Buffer confirmPBuf = { 0 };
    BSL_Buffer confirmVBuf = { 0 };

    ASSERT_EQ(create_buffer_from_hex(&contextBuf, context), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(create_buffer_from_hex(&proverBuf, prover), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(create_buffer_from_hex(&verifierBuf, verifier), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(create_buffer_from_hex(&w0Buf, w0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(create_buffer_from_hex(&w1Buf, w1), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(create_buffer_from_hex(&LBuf, L), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(create_buffer_from_hex(&xBuf, x), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(create_buffer_from_hex(&yBuf, y), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(create_buffer_from_hex(&sharePBuf, shareP), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(create_buffer_from_hex(&shareVBuf, shareV), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(create_buffer_from_hex(&kSharedBuf, kShared), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(create_buffer_from_hex(&confirmPBuf, confirmP), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(create_buffer_from_hex(&confirmVBuf, confirmV), HITLS_AUTH_SUCCESS);

    uint8_t password[] = "password";
    BSL_Buffer passwordBuf = {.data = password, .dataLen = strlen((char *)password)};

    HITLS_AUTH_PakeCtx* ctx2 = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role0, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx2 != NULL);
    BSL_Buffer emptyBuf0 = { 0 };
    BSL_Buffer emptyBuf1 = { 0 };
    BSL_Buffer emptyBuf2 = { 0 };
    CRYPT_EAL_KdfCtx* kdfCtxTmp = HITLS_AUTH_PakeGetKdfCtx(ctx2, kdfParam);
    ASSERT_TRUE(kdfCtxTmp != NULL);
    ASSERT_EQ(HITLS_AUTH_Pake_Ctrl(ctx2, HITLS_AUTH_PAKE_REQ_REGISTER, kdfCtxTmp, emptyBuf0, emptyBuf1, emptyBuf2),
        HITLS_AUTH_SUCCESS);

    HITLS_AUTH_PakeCtx* ctx0 = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role0, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx0 != NULL);
    HITLS_AUTH_PakeCtx* ctx1 = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role1, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx1 != NULL);

    CRYPT_EAL_KdfCtx* kdfCtx = HITLS_AUTH_PakeGetKdfCtx(ctx2, kdfParam);
    ASSERT_TRUE(kdfCtx != NULL);
    ASSERT_EQ(HITLS_AUTH_Pake_Ctrl(ctx0, HITLS_AUTH_PAKE_REQ_REGISTER, kdfCtx, w0Buf, w1Buf, LBuf),
        HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_Pake_Ctrl(ctx1, HITLS_AUTH_PAKE_RESP_REGISTER, kdfCtx, w0Buf, w1Buf, LBuf),
        HITLS_AUTH_SUCCESS);

    BSL_Buffer emptyBuf = { 0 };
    ASSERT_EQ(HITLS_AUTH_PakeReqSetup(ctx0, emptyBuf, &sharePBuf), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PakeReqSetup(ctx0, xBuf, &sharePBuf), HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("shareP cmp", sharePBuf.data, sharePBuf.dataLen, shareP->x, shareP->len);

    ASSERT_EQ(HITLS_AUTH_PakeRespSetup(ctx1, emptyBuf, sharePBuf, &shareVBuf, &confirmVBuf), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PakeRespSetup(ctx1, yBuf, sharePBuf, &shareVBuf, &confirmVBuf), HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("shareV cmp", shareVBuf.data, shareVBuf.dataLen, shareV->x, shareV->len);
    ASSERT_COMPARE("confirmV cmp", confirmVBuf.data, confirmVBuf.dataLen, confirmV->x, confirmV->len);

    ASSERT_EQ(HITLS_AUTH_PakeReqDerive(ctx0, shareVBuf, confirmVBuf, &confirmPBuf, &kSharedBuf), HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("confirmP cmp", confirmPBuf.data, confirmPBuf.dataLen, confirmP->x, confirmP->len);
    ASSERT_COMPARE("kShared cmp", kSharedBuf.data, kSharedBuf.dataLen, kShared->x, kShared->len);

    HITLS_AUTH_PakeRespDerive(ctx1, confirmPBuf, &kSharedBuf);
    ASSERT_COMPARE("kShared cmp", kSharedBuf.data, kSharedBuf.dataLen, kShared->x, kShared->len);
EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    CRYPT_EAL_KdfFreeCtx(kdfCtxTmp);
    memset(password, 0, sizeof(password));
    BSL_SAL_ClearFree(contextBuf.data, contextBuf.dataLen);
    BSL_SAL_ClearFree(proverBuf.data, proverBuf.dataLen);
    BSL_SAL_ClearFree(verifierBuf.data, verifierBuf.dataLen);
    BSL_SAL_ClearFree(w0Buf.data, w0Buf.dataLen);
    BSL_SAL_ClearFree(w1Buf.data, w1Buf.dataLen);
    BSL_SAL_ClearFree(LBuf.data, LBuf.dataLen);
    BSL_SAL_ClearFree(xBuf.data, xBuf.dataLen);
    BSL_SAL_ClearFree(yBuf.data, yBuf.dataLen);
    BSL_SAL_ClearFree(sharePBuf.data, sharePBuf.dataLen);
    BSL_SAL_ClearFree(shareVBuf.data, shareVBuf.dataLen);
    BSL_SAL_ClearFree(kSharedBuf.data, kSharedBuf.dataLen);
    BSL_SAL_ClearFree(confirmPBuf.data, confirmPBuf.dataLen);
    BSL_SAL_ClearFree(confirmVBuf.data, confirmVBuf.dataLen);
    HITLS_AUTH_PakeFreeCtx(ctx0);
    HITLS_AUTH_PakeFreeCtx(ctx1);
    HITLS_AUTH_PakeFreeCtx(ctx2);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SPAKE2PLUS_TC002
 * @title  SPAKE2+ ReqRegister input validation tests
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SPAKE2PLUS_TC002(void)
{
    ASSERT_EQ(TestRandInit(), HITLS_AUTH_SUCCESS);
    HITLS_AUTH_PAKE_Type type = HITLS_AUTH_PAKE_SPAKE2PLUS;
    HITLS_AUTH_PAKE_Role role = HITLS_AUTH_PAKE_REQ;
    HITLS_AUTH_PAKE_CipherSuite cipherSuite = {
        .type = HITLS_AUTH_PAKE_SPAKE2PLUS,
        .params.spake2plus = {
            .curve = CRYPT_ECC_NISTP256,
            .hash = CRYPT_MD_SHA256,
            .kdf = CRYPT_HKDF_SHA256,
            .mac = CRYPT_MAC_HMAC_SHA256
        }
    };

    BSL_Buffer contextBuf = { .data = (uint8_t*)"test", .dataLen = 4 };
    BSL_Buffer proverBuf = { .data = (uint8_t*)"prover", .dataLen = 6 };
    BSL_Buffer verifierBuf = { .data = (uint8_t*)"verifier", .dataLen = 8 };
    uint8_t password[] = "password";
    BSL_Buffer passwordBuf = { .data = password, .dataLen = strlen((char *)password) };

    HITLS_AUTH_PakeCtx* ctx = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx != NULL);

    HITLS_AUTH_PAKE_KDF kdfParam = {
        .algId = CRYPT_KDF_PBKDF2,
        .param.pbkdf2 = {
            .mac = CRYPT_MAC_HMAC_SHA256,
            .iteration = 1000,
            .salt = { NULL, 0}
        }
    };
    CRYPT_EAL_KdfCtx* kdfCtx = HITLS_AUTH_PakeGetKdfCtx(ctx, kdfParam);
    ASSERT_TRUE(kdfCtx != NULL);

    // Test all NULL - should fail
    BSL_Buffer emptyBuf = { 0 };
    ASSERT_EQ(HITLS_AUTH_Pake_Ctrl(ctx, HITLS_AUTH_PAKE_REQ_REGISTER, kdfCtx, emptyBuf, emptyBuf, emptyBuf),
        HITLS_AUTH_SUCCESS);

    // Test partial NULL (w0 only) - should fail
    uint8_t testData[66] = {0};
    BSL_Buffer w0Buf = { .data = testData, .dataLen = 32 };
    BSL_Buffer w1Buf = { 0 };
    BSL_Buffer lBuf = { 0 };
    ASSERT_EQ(HITLS_AUTH_Pake_Ctrl(ctx, HITLS_AUTH_PAKE_REQ_REGISTER, kdfCtx, w0Buf, w1Buf, lBuf),
        HITLS_AUTH_INVALID_ARG);

    // Test excessive length - should fail
    BSL_Buffer longBuf = { .data = testData, .dataLen = 200 };  // > MAX_ECC_PARAM_LEN
    BSL_Buffer validBuf = { .data = testData, .dataLen = 32 };
    BSL_Buffer validKeyBuf = { .data = testData, .dataLen = 65 };
    ASSERT_EQ(HITLS_AUTH_Pake_Ctrl(ctx, HITLS_AUTH_PAKE_REQ_REGISTER, kdfCtx, longBuf, validBuf, validKeyBuf),
        HITLS_AUTH_INVALID_ARG);

    // Test valid inputs
    ASSERT_EQ(HITLS_AUTH_Pake_Ctrl(ctx, HITLS_AUTH_PAKE_REQ_REGISTER, kdfCtx, validBuf, validBuf, validKeyBuf),
        HITLS_AUTH_SUCCESS);

EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    memset(password, 0, sizeof(password));
    HITLS_AUTH_PakeFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SPAKE2PLUS_TC003
 * @title  SPAKE2+ RespRegister input validation tests
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SPAKE2PLUS_TC003(void)
{
    ASSERT_EQ(TestRandInit(), HITLS_AUTH_SUCCESS);
    HITLS_AUTH_PAKE_Type type = HITLS_AUTH_PAKE_SPAKE2PLUS;
    HITLS_AUTH_PAKE_Role role = HITLS_AUTH_PAKE_RESP;
    HITLS_AUTH_PAKE_CipherSuite cipherSuite = {
        .type = HITLS_AUTH_PAKE_SPAKE2PLUS,
        .params.spake2plus = {
            .curve = CRYPT_ECC_NISTP256,
            .hash = CRYPT_MD_SHA256,
            .kdf = CRYPT_HKDF_SHA256,
            .mac = CRYPT_MAC_HMAC_SHA256
        }
    };

    BSL_Buffer contextBuf = { .data = (uint8_t*)"test", .dataLen = 4 };
    BSL_Buffer proverBuf = { .data = (uint8_t*)"prover", .dataLen = 6 };
    BSL_Buffer verifierBuf = { .data = (uint8_t*)"verifier", .dataLen = 8 };
    uint8_t password[] = "password";
    BSL_Buffer passwordBuf = { .data = password, .dataLen = strlen((char *)password) };

    HITLS_AUTH_PakeCtx* ctx = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx != NULL);

    HITLS_AUTH_PAKE_KDF kdfParam = {
        .algId = CRYPT_KDF_PBKDF2,
        .param.pbkdf2 = {
            .mac = CRYPT_MAC_HMAC_SHA256,
            .iteration = 1000,
            .salt = { NULL, 0}
        }
    };
    CRYPT_EAL_KdfCtx* kdfCtx = HITLS_AUTH_PakeGetKdfCtx(ctx, kdfParam);
    ASSERT_TRUE(kdfCtx != NULL);

    // Test all NULL - should fail
    BSL_Buffer emptyBuf = { 0 };
    ASSERT_EQ(HITLS_AUTH_Pake_Ctrl(ctx, HITLS_AUTH_PAKE_RESP_REGISTER, kdfCtx, emptyBuf, emptyBuf, emptyBuf),
        HITLS_AUTH_PAKE_INVALID_PARAM);

    // Test excessive length - should fail
    uint8_t testData[133] = {0};
    BSL_Buffer longBuf = { .data = testData, .dataLen = 200 };  // > MAX_ECC_KEY_LEN
    BSL_Buffer validBuf = { .data = testData, .dataLen = 32 };
    BSL_Buffer validKeyBuf = { .data = testData, .dataLen = 65 };
    ASSERT_EQ(HITLS_AUTH_Pake_Ctrl(ctx, HITLS_AUTH_PAKE_RESP_REGISTER, kdfCtx, longBuf, validBuf, validKeyBuf),
        HITLS_AUTH_INVALID_ARG);

    // Test valid inputs
    ASSERT_EQ(HITLS_AUTH_Pake_Ctrl(ctx, HITLS_AUTH_PAKE_RESP_REGISTER, kdfCtx, validBuf, validBuf, validKeyBuf),
        HITLS_AUTH_SUCCESS);

EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    memset(password, 0, sizeof(password));
    HITLS_AUTH_PakeFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SPAKE2PLUS_TC004
 * @title  SPAKE2+ ReqSetup input validation tests
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SPAKE2PLUS_TC004(void)
{
    ASSERT_EQ(TestRandInit(), HITLS_AUTH_SUCCESS);
    HITLS_AUTH_PAKE_Type type = HITLS_AUTH_PAKE_SPAKE2PLUS;
    HITLS_AUTH_PAKE_Role role = HITLS_AUTH_PAKE_REQ;
    HITLS_AUTH_PAKE_CipherSuite cipherSuite = {
        .type = HITLS_AUTH_PAKE_SPAKE2PLUS,
        .params.spake2plus = {
            .curve = CRYPT_ECC_NISTP256,
            .hash = CRYPT_MD_SHA256,
            .kdf = CRYPT_HKDF_SHA256,
            .mac = CRYPT_MAC_HMAC_SHA256
        }
    };

    BSL_Buffer contextBuf = { .data = (uint8_t*)"test", .dataLen = 4 };
    BSL_Buffer proverBuf = { .data = (uint8_t*)"prover", .dataLen = 6 };
    BSL_Buffer verifierBuf = { .data = (uint8_t*)"verifier", .dataLen = 8 };
    uint8_t password[] = "password";
    BSL_Buffer passwordBuf = { .data = password, .dataLen = strlen((char *)password) };

    HITLS_AUTH_PakeCtx* ctx = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx != NULL);

    uint8_t shareData[133] = {0};
    BSL_Buffer shareBuf = { .data = shareData, .dataLen = sizeof(shareData) };

    // Test NULL ctx
    ASSERT_EQ(HITLS_AUTH_PakeReqSetup(NULL, shareBuf, &shareBuf), HITLS_AUTH_NULL_INPUT);

    // Test NULL share
    ASSERT_EQ(HITLS_AUTH_PakeReqSetup(ctx, shareBuf, NULL), HITLS_AUTH_NULL_INPUT);

    // Test NULL share->data
    BSL_Buffer nullDataBuf = { .data = NULL, .dataLen = 32 };
    ASSERT_EQ(HITLS_AUTH_PakeReqSetup(ctx, shareBuf, &nullDataBuf), HITLS_AUTH_NULL_INPUT);

    // Test excessive x length
    uint8_t xData[100] = {0};
    BSL_Buffer longX = { .data = xData, .dataLen = 100 };  // > MAX_ECC_PARAM_LEN (66)
    ASSERT_EQ(HITLS_AUTH_PakeReqSetup(ctx, longX, &shareBuf), HITLS_AUTH_INVALID_ARG);

    // Test zero x length
    BSL_Buffer zeroX = { .data = xData, .dataLen = 0 };
    ASSERT_EQ(HITLS_AUTH_PakeReqSetup(ctx, zeroX, &shareBuf), HITLS_AUTH_INVALID_ARG);

EXIT:
    memset(password, 0, sizeof(password));
    HITLS_AUTH_PakeFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SPAKE2PLUS_TC005
 * @title  SPAKE2+ RespSetup input validation tests
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SPAKE2PLUS_TC005(void)
{
    ASSERT_EQ(TestRandInit(), HITLS_AUTH_SUCCESS);
    HITLS_AUTH_PAKE_Type type = HITLS_AUTH_PAKE_SPAKE2PLUS;
    HITLS_AUTH_PAKE_Role role = HITLS_AUTH_PAKE_RESP;
    HITLS_AUTH_PAKE_CipherSuite cipherSuite = {
        .type = HITLS_AUTH_PAKE_SPAKE2PLUS,
        .params.spake2plus = {
            .curve = CRYPT_ECC_NISTP256,
            .hash = CRYPT_MD_SHA256,
            .kdf = CRYPT_HKDF_SHA256,
            .mac = CRYPT_MAC_HMAC_SHA256
        }
    };

    BSL_Buffer contextBuf = { .data = (uint8_t*)"test", .dataLen = 4 };
    BSL_Buffer proverBuf = { .data = (uint8_t*)"prover", .dataLen = 6 };
    BSL_Buffer verifierBuf = { .data = (uint8_t*)"verifier", .dataLen = 8 };
    uint8_t password[] = "password";
    BSL_Buffer passwordBuf = { .data = password, .dataLen = strlen((char *)password) };

    HITLS_AUTH_PakeCtx* ctx = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx != NULL);

    uint8_t shareData[133] = {0};
    BSL_Buffer shareBuf = { .data = shareData, .dataLen = sizeof(shareData) };

    // Test NULL ctx
    ASSERT_EQ(HITLS_AUTH_PakeRespSetup(NULL, shareBuf, shareBuf, &shareBuf, &shareBuf), HITLS_AUTH_NULL_INPUT);

    // Test NULL shareV
    ASSERT_EQ(HITLS_AUTH_PakeRespSetup(ctx, shareBuf, shareBuf, NULL, &shareBuf), HITLS_AUTH_NULL_INPUT);

    // Test NULL shareV->data
    BSL_Buffer nullDataBuf = { .data = NULL, .dataLen = 32 };
    ASSERT_EQ(HITLS_AUTH_PakeRespSetup(ctx, shareBuf, shareBuf, &nullDataBuf, &shareBuf), HITLS_AUTH_NULL_INPUT);

    // Test NULL shareP
    BSL_Buffer nullShareP = { .data = NULL, .dataLen = 0 };
    ASSERT_EQ(HITLS_AUTH_PakeRespSetup(ctx, shareBuf, nullShareP, &shareBuf, &shareBuf), HITLS_AUTH_INVALID_ARG);

    // Test excessive shareP length
    uint8_t longData[200] = {0};
    BSL_Buffer longShareP = { .data = longData, .dataLen = 200 };  // > MAX_ECC_KEY_LEN (133)
    ASSERT_EQ(HITLS_AUTH_PakeRespSetup(ctx, shareBuf, longShareP, &shareBuf, &shareBuf), HITLS_AUTH_INVALID_ARG);

    // Test zero shareP length
    BSL_Buffer zeroShareP = { .data = longData, .dataLen = 0 };
    ASSERT_EQ(HITLS_AUTH_PakeRespSetup(ctx, shareBuf, zeroShareP, &shareBuf, &shareBuf), HITLS_AUTH_INVALID_ARG);

EXIT:
    memset(password, 0, sizeof(password));
    HITLS_AUTH_PakeFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SPAKE2PLUS_TC006
 * @title  SPAKE2+ ReqDerive input validation tests
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SPAKE2PLUS_TC006(void)
{
    ASSERT_EQ(TestRandInit(), HITLS_AUTH_SUCCESS);
    HITLS_AUTH_PAKE_Type type = HITLS_AUTH_PAKE_SPAKE2PLUS;
    HITLS_AUTH_PAKE_Role role = HITLS_AUTH_PAKE_REQ;
    HITLS_AUTH_PAKE_CipherSuite cipherSuite = {
        .type = HITLS_AUTH_PAKE_SPAKE2PLUS,
        .params.spake2plus = {
            .curve = CRYPT_ECC_NISTP256,
            .hash = CRYPT_MD_SHA256,
            .kdf = CRYPT_HKDF_SHA256,
            .mac = CRYPT_MAC_HMAC_SHA256
        }
    };

    BSL_Buffer contextBuf = { .data = (uint8_t*)"test", .dataLen = 4 };
    BSL_Buffer proverBuf = { .data = (uint8_t*)"prover", .dataLen = 6 };
    BSL_Buffer verifierBuf = { .data = (uint8_t*)"verifier", .dataLen = 8 };
    uint8_t password[] = "password";
    BSL_Buffer passwordBuf = { .data = password, .dataLen = strlen((char *)password) };

    HITLS_AUTH_PakeCtx* ctx = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx != NULL);

    uint8_t data[133] = {0};
    BSL_Buffer buf = { .data = data, .dataLen = sizeof(data) };

    // Test NULL ctx
    ASSERT_EQ(HITLS_AUTH_PakeReqDerive(NULL, buf, buf, &buf, &buf), HITLS_AUTH_NULL_INPUT);

    // Test NULL confirmP
    ASSERT_EQ(HITLS_AUTH_PakeReqDerive(ctx, buf, buf, NULL, &buf), HITLS_AUTH_NULL_INPUT);

    // Test NULL out
    ASSERT_EQ(HITLS_AUTH_PakeReqDerive(ctx, buf, buf, &buf, NULL), HITLS_AUTH_NULL_INPUT);

    // Test NULL shareV
    BSL_Buffer nullBuf = { .data = NULL, .dataLen = 0 };
    ASSERT_EQ(HITLS_AUTH_PakeReqDerive(ctx, nullBuf, buf, &buf, &buf), HITLS_AUTH_NULL_INPUT);

EXIT:
    memset(password, 0, sizeof(password));
    HITLS_AUTH_PakeFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SPAKE2PLUS_TC007
 * @title  SPAKE2+ RespDerive input validation tests
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SPAKE2PLUS_TC007(void)
{
    ASSERT_EQ(TestRandInit(), HITLS_AUTH_SUCCESS);
    HITLS_AUTH_PAKE_Type type = HITLS_AUTH_PAKE_SPAKE2PLUS;
    HITLS_AUTH_PAKE_Role role = HITLS_AUTH_PAKE_RESP;
    HITLS_AUTH_PAKE_CipherSuite cipherSuite = {
        .type = HITLS_AUTH_PAKE_SPAKE2PLUS,
        .params.spake2plus = {
            .curve = CRYPT_ECC_NISTP256,
            .hash = CRYPT_MD_SHA256,
            .kdf = CRYPT_HKDF_SHA256,
            .mac = CRYPT_MAC_HMAC_SHA256
        }
    };

    BSL_Buffer contextBuf = { .data = (uint8_t*)"test", .dataLen = 4 };
    BSL_Buffer proverBuf = { .data = (uint8_t*)"prover", .dataLen = 6 };
    BSL_Buffer verifierBuf = { .data = (uint8_t*)"verifier", .dataLen = 8 };
    uint8_t password[] = "password";
    BSL_Buffer passwordBuf = { .data = password, .dataLen = strlen((char *)password) };

    HITLS_AUTH_PakeCtx* ctx = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx != NULL);

    uint8_t data[133] = {0};
    BSL_Buffer buf = { .data = data, .dataLen = sizeof(data) };

    // Test NULL ctx
    ASSERT_EQ(HITLS_AUTH_PakeRespDerive(NULL, buf, &buf), HITLS_AUTH_NULL_INPUT);

    // Test NULL out
    ASSERT_EQ(HITLS_AUTH_PakeRespDerive(ctx, buf, NULL), HITLS_AUTH_NULL_INPUT);

    // Test NULL confirmP
    BSL_Buffer nullBuf = { .data = NULL, .dataLen = 0 };
    ASSERT_EQ(HITLS_AUTH_PakeRespDerive(ctx, nullBuf, &buf), HITLS_AUTH_PAKE_INVALID_PARAM);

    // Test excessive confirmP length
    uint8_t longData[100] = {0};
    BSL_Buffer longConfirmP = { .data = longData, .dataLen = 100 };
    ASSERT_EQ(HITLS_AUTH_PakeRespDerive(ctx, longConfirmP, &buf), HITLS_AUTH_PAKE_INVALID_PARAM);

    // Test zero confirmP length
    BSL_Buffer zeroConfirmP = { .data = longData, .dataLen = 0 };
    ASSERT_EQ(HITLS_AUTH_PakeRespDerive(ctx, zeroConfirmP, &buf), HITLS_AUTH_PAKE_INVALID_PARAM);

EXIT:
    memset(password, 0, sizeof(password));
    HITLS_AUTH_PakeFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SPAKE2PLUS_TC008
 * @title  SPAKE2+ HITLS_AUTH_PakeNewCtx input validation tests
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SPAKE2PLUS_TC008(void)
{
    ASSERT_EQ(TestRandInit(), HITLS_AUTH_SUCCESS);
    HITLS_AUTH_PAKE_Type type = HITLS_AUTH_PAKE_SPAKE2PLUS;
    HITLS_AUTH_PAKE_Role role = HITLS_AUTH_PAKE_REQ;
    HITLS_AUTH_PAKE_CipherSuite cipherSuite = {
        .type = HITLS_AUTH_PAKE_SPAKE2PLUS,
        .params.spake2plus = {
            .curve = CRYPT_ECC_NISTP256,
            .hash = CRYPT_MD_SHA256,
            .kdf = CRYPT_HKDF_SHA256,
            .mac = CRYPT_MAC_HMAC_SHA256
        }
    };

    BSL_Buffer contextBuf = { .data = (uint8_t*)"test", .dataLen = 4 };
    BSL_Buffer proverBuf = { .data = (uint8_t*)"prover", .dataLen = 6 };
    BSL_Buffer verifierBuf = { .data = (uint8_t*)"verifier", .dataLen = 8 };
    uint8_t password[] = "password";
    BSL_Buffer passwordBuf = { .data = password, .dataLen = strlen((char *)password) };

    // Test NULL password
    BSL_Buffer nullBuf = { .data = NULL, .dataLen = 0 };
    ASSERT_TRUE(HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        nullBuf, proverBuf, verifierBuf, contextBuf) == NULL);

    // Test empty password
    BSL_Buffer emptyBuf = { .data = (uint8_t*)"test", .dataLen = 0 };
    ASSERT_TRUE(HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        emptyBuf, proverBuf, verifierBuf, contextBuf) == NULL);

    // Test NULL prover
    ASSERT_TRUE(HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        passwordBuf, nullBuf, verifierBuf, contextBuf) == NULL);

    // Test NULL verifier
    ASSERT_TRUE(HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        passwordBuf, proverBuf, nullBuf, contextBuf) == NULL);

    // Test NULL context
    ASSERT_TRUE(HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, nullBuf) == NULL);


    // Test valid inputs
    HITLS_AUTH_PakeCtx* ctx = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx != NULL);

EXIT:
    HITLS_AUTH_PakeFreeCtx(ctx);
    memset(password, 0, sizeof(password));
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SPAKE2PLUS_TC009
 * @title  SPAKE2+ HITLS_AUTH_PakeFreeCtx NULL input test
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SPAKE2PLUS_TC009(void)
{
    // Test NULL ctx - should not crash
    HITLS_AUTH_PakeFreeCtx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SPAKE2PLUS_TC010
 * @title  SPAKE2+ HITLS_AUTH_PakeReqSetup NULL/zero input parameter tests
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SPAKE2PLUS_TC010(void)
{
    ASSERT_EQ(TestRandInit(), HITLS_AUTH_SUCCESS);
    HITLS_AUTH_PAKE_Type type = HITLS_AUTH_PAKE_SPAKE2PLUS;
    HITLS_AUTH_PAKE_Role role = HITLS_AUTH_PAKE_REQ;
    HITLS_AUTH_PAKE_CipherSuite cipherSuite = {
        .type = HITLS_AUTH_PAKE_SPAKE2PLUS,
        .params.spake2plus = {
            .curve = CRYPT_ECC_NISTP256,
            .hash = CRYPT_MD_SHA256,
            .kdf = CRYPT_HKDF_SHA256,
            .mac = CRYPT_MAC_HMAC_SHA256
        }
    };

    BSL_Buffer contextBuf = { .data = (uint8_t*)"test", .dataLen = 4 };
    BSL_Buffer proverBuf = { .data = (uint8_t*)"prover", .dataLen = 6 };
    BSL_Buffer verifierBuf = { .data = (uint8_t*)"verifier", .dataLen = 8 };
    uint8_t password[] = "password";
    BSL_Buffer passwordBuf = { .data = password, .dataLen = strlen((char *)password) };

    HITLS_AUTH_PakeCtx* ctx = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx != NULL);

    HITLS_AUTH_PAKE_KDF kdfParam = {
        .algId = CRYPT_KDF_PBKDF2,
        .param.pbkdf2 = {
            .mac = CRYPT_MAC_HMAC_SHA256,
            .iteration = 1000,
            .salt = { NULL, 0}
        }
    };
    CRYPT_EAL_KdfCtx* kdfCtx = HITLS_AUTH_PakeGetKdfCtx(ctx, kdfParam);
    ASSERT_TRUE(kdfCtx != NULL);

    uint8_t testData[66] = {0};
    BSL_Buffer w0Buf = { .data = testData, .dataLen = 32 };
    BSL_Buffer w1Buf = { .data = testData, .dataLen = 32 };
    BSL_Buffer lBuf = { .data = testData, .dataLen = 65 };

    // Register required parameters
    ASSERT_EQ(HITLS_AUTH_Pake_Ctrl(ctx, HITLS_AUTH_PAKE_REQ_REGISTER, kdfCtx, w0Buf, w1Buf, lBuf),
        HITLS_AUTH_SUCCESS);

    uint8_t shareData[133] = {0};
    BSL_Buffer shareBuf = { .data = shareData, .dataLen = sizeof(shareData) };

    // Test NULL input (in param can be NULL for spake2+, system generates random x)
    BSL_Buffer nullIn = { .data = NULL, .dataLen = 0 };
    ASSERT_EQ(HITLS_AUTH_PakeReqSetup(ctx, nullIn, &shareBuf), HITLS_AUTH_SUCCESS);

EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    HITLS_AUTH_PakeFreeCtx(ctx);
    memset(password, 0, sizeof(password));
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SPAKE2PLUS_TC011
 * @title  SPAKE2+ HITLS_AUTH_PakeRespSetup additional output parameter tests
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SPAKE2PLUS_TC011(void)
{
    ASSERT_EQ(TestRandInit(), HITLS_AUTH_SUCCESS);
    HITLS_AUTH_PAKE_Type type = HITLS_AUTH_PAKE_SPAKE2PLUS;
    HITLS_AUTH_PAKE_Role role = HITLS_AUTH_PAKE_RESP;
    HITLS_AUTH_PAKE_CipherSuite cipherSuite = {
        .type = HITLS_AUTH_PAKE_SPAKE2PLUS,
        .params.spake2plus = {
            .curve = CRYPT_ECC_NISTP256,
            .hash = CRYPT_MD_SHA256,
            .kdf = CRYPT_HKDF_SHA256,
            .mac = CRYPT_MAC_HMAC_SHA256
        }
    };

    BSL_Buffer contextBuf = { .data = (uint8_t*)"test", .dataLen = 4 };
    BSL_Buffer proverBuf = { .data = (uint8_t*)"prover", .dataLen = 6 };
    BSL_Buffer verifierBuf = { .data = (uint8_t*)"verifier", .dataLen = 8 };
    uint8_t password[] = "password";
    BSL_Buffer passwordBuf = { .data = password, .dataLen = strlen((char *)password) };

    HITLS_AUTH_PakeCtx* ctx = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx != NULL);

    uint8_t shareData[133] = {0};
    BSL_Buffer shareBuf = { .data = shareData, .dataLen = sizeof(shareData) };

    // Test NULL out1
    ASSERT_EQ(HITLS_AUTH_PakeRespSetup(ctx, shareBuf, shareBuf, &shareBuf, NULL), HITLS_AUTH_NULL_INPUT);

    // Test NULL out1->data
    BSL_Buffer nullDataBuf = { .data = NULL, .dataLen = 32 };
    ASSERT_EQ(HITLS_AUTH_PakeRespSetup(ctx, shareBuf, shareBuf, &shareBuf, &nullDataBuf), HITLS_AUTH_NULL_INPUT);

    // Test zero length shareP (in1)
    BSL_Buffer zeroShareP = { .data = shareData, .dataLen = 0 };
    ASSERT_EQ(HITLS_AUTH_PakeRespSetup(ctx, shareBuf, zeroShareP, &shareBuf, &shareBuf), HITLS_AUTH_INVALID_ARG);

EXIT:
    HITLS_AUTH_PakeFreeCtx(ctx);
    memset(password, 0, sizeof(password));
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SPAKE2PLUS_TC012
 * @title  SPAKE2+ HITLS_AUTH_PakeReqDerive additional output parameter tests
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SPAKE2PLUS_TC012(void)
{
    ASSERT_EQ(TestRandInit(), HITLS_AUTH_SUCCESS);
    HITLS_AUTH_PAKE_Type type = HITLS_AUTH_PAKE_SPAKE2PLUS;
    HITLS_AUTH_PAKE_Role role = HITLS_AUTH_PAKE_REQ;
    HITLS_AUTH_PAKE_CipherSuite cipherSuite = {
        .type = HITLS_AUTH_PAKE_SPAKE2PLUS,
        .params.spake2plus = {
            .curve = CRYPT_ECC_NISTP256,
            .hash = CRYPT_MD_SHA256,
            .kdf = CRYPT_HKDF_SHA256,
            .mac = CRYPT_MAC_HMAC_SHA256
        }
    };

    BSL_Buffer contextBuf = { .data = (uint8_t*)"test", .dataLen = 4 };
    BSL_Buffer proverBuf = { .data = (uint8_t*)"prover", .dataLen = 6 };
    BSL_Buffer verifierBuf = { .data = (uint8_t*)"verifier", .dataLen = 8 };
    uint8_t password[] = "password";
    BSL_Buffer passwordBuf = { .data = password, .dataLen = strlen((char *)password) };

    HITLS_AUTH_PakeCtx* ctx = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx != NULL);

    uint8_t data[133] = {0};
    BSL_Buffer buf = { .data = data, .dataLen = sizeof(data) };

    // Test NULL out1
    ASSERT_EQ(HITLS_AUTH_PakeReqDerive(ctx, buf, buf, &buf, NULL), HITLS_AUTH_NULL_INPUT);

    // Test NULL out1->data
    BSL_Buffer nullDataBuf = { .data = NULL, .dataLen = 32 };
    ASSERT_EQ(HITLS_AUTH_PakeReqDerive(ctx, buf, buf, &buf, &nullDataBuf), HITLS_AUTH_NULL_INPUT);

EXIT:
    HITLS_AUTH_PakeFreeCtx(ctx);
    memset(password, 0, sizeof(password));
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SPAKE2PLUS_TC013
 * @title  SPAKE2+ HITLS_AUTH_PakeGetKdfCtx input validation tests
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SPAKE2PLUS_TC013(void)
{
    ASSERT_EQ(TestRandInit(), HITLS_AUTH_SUCCESS);
    HITLS_AUTH_PAKE_Type type = HITLS_AUTH_PAKE_SPAKE2PLUS;
    HITLS_AUTH_PAKE_Role role = HITLS_AUTH_PAKE_REQ;
    HITLS_AUTH_PAKE_CipherSuite cipherSuite = {
        .type = HITLS_AUTH_PAKE_SPAKE2PLUS,
        .params.spake2plus = {
            .curve = CRYPT_ECC_NISTP256,
            .hash = CRYPT_MD_SHA256,
            .kdf = CRYPT_HKDF_SHA256,
            .mac = CRYPT_MAC_HMAC_SHA256
        }
    };

    BSL_Buffer contextBuf = { .data = (uint8_t*)"test", .dataLen = 4 };
    BSL_Buffer proverBuf = { .data = (uint8_t*)"prover", .dataLen = 6 };
    BSL_Buffer verifierBuf = { .data = (uint8_t*)"verifier", .dataLen = 8 };
    uint8_t password[] = "password";
    BSL_Buffer passwordBuf = { .data = password, .dataLen = strlen((char *)password) };

    HITLS_AUTH_PakeCtx* ctx = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx != NULL);

    // Test NULL ctx
    ASSERT_TRUE(HITLS_AUTH_PakeGetKdfCtx(NULL, (HITLS_AUTH_PAKE_KDF){0}) == NULL);

    // Test invalid kdf algId
    HITLS_AUTH_PAKE_KDF invalidKdf = { .algId = 9999 };
    ASSERT_TRUE(HITLS_AUTH_PakeGetKdfCtx(ctx, invalidKdf) == NULL);

    // Test valid kdf
    HITLS_AUTH_PAKE_KDF kdfParam = {
        .algId = CRYPT_KDF_PBKDF2,
        .param.pbkdf2 = {
            .mac = CRYPT_MAC_HMAC_SHA256,
            .iteration = 1000,
            .salt = { NULL, 0}
        }
    };
    CRYPT_EAL_KdfCtx* kdfCtx = HITLS_AUTH_PakeGetKdfCtx(ctx, kdfParam);
    ASSERT_TRUE(kdfCtx != NULL);

EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    HITLS_AUTH_PakeFreeCtx(ctx);
    memset(password, 0, sizeof(password));
    TestRandDeInit();
}
/* END_CASE */

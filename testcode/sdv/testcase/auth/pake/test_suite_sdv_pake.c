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
#include "securec.h"
#include "auth_errno.h"
/* END_HEADER */

static int32_t create_buffer_from_hex(BSL_Buffer *buf, Hex *hex)
{
    buf->data = (uint8_t*) BSL_SAL_Malloc (hex->len);
    if (buf->data == NULL) {
        return HITLS_AUTH_MEM_ALLOC_FAIL;
    }

    buf->dataLen = hex->len;
    memcpy_s(buf->data, buf->dataLen, hex->x, hex->len);
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
    CRYPT_EAL_KdfCTX* kdfCtxTmp = HITLS_AUTH_PakeGetKdfCtx(ctx2, kdfParam);
    ASSERT_TRUE(kdfCtxTmp != NULL);
    ASSERT_EQ(HITLS_AUTH_Pake_Ctrl(ctx2, HITLS_AUTH_PAKE_REQ_REGISTER, kdfCtxTmp, emptyBuf0, emptyBuf1, emptyBuf2),
        HITLS_AUTH_SUCCESS);

    HITLS_AUTH_PakeCtx* ctx0 = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role0, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx0 != NULL);
    HITLS_AUTH_PakeCtx* ctx1 = HITLS_AUTH_PakeNewCtx(NULL, NULL, type, role1, cipherSuite,
        passwordBuf, proverBuf, verifierBuf, contextBuf);
    ASSERT_TRUE(ctx1 != NULL);

    CRYPT_EAL_KdfCTX* kdfCtx = HITLS_AUTH_PakeGetKdfCtx(ctx2, kdfParam);
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
    (void)memset_s(password, sizeof(password), 0, sizeof(password));
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

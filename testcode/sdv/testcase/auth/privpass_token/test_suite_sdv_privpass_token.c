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
#include <stdint.h>
#include "privpass_token.h"
#include "auth_privpass_token.h"
#include "auth_errno.h"
#include "auth_params.h"
#include "crypt_util_rand.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_codecs.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "securec.h"

/* END_HEADER */

#define MAX_LEN 512

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_SERIALIZATION_TC001
 * @spec Private Pass Token Serialization
 * @title Test serialization and deserialization of Private Pass Token objects
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_SERIALIZATION_TC001(int type, Hex *buffer)
{
    TestRandInit();
    uint8_t output[MAX_LEN];
    uint32_t outputLen = 0;
    HITLS_AUTH_PrivPassToken *challenge = NULL;
    HITLS_AUTH_PrivPassCtx *ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);
    // Test deserialization
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, type, buffer->x, buffer->len, &challenge), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, challenge, NULL, &outputLen), HITLS_AUTH_SUCCESS);
    outputLen--;
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, challenge, output, &outputLen),
        HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH);
    outputLen++;
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, challenge, output, &outputLen), HITLS_AUTH_SUCCESS);
    // Test serialization
    ASSERT_COMPARE("compare token", output, outputLen, buffer->x, buffer->len);
EXIT:
    HITLS_AUTH_PrivPassFreeToken(challenge);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_SERIALIZATION_TC002
 * @spec Private Pass Token challenge serialization
 * @title Test serialization of Private Pass Token challenge
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_SERIALIZATION_TC002(Hex *tokenType, Hex *issuerName, Hex *redemption, Hex *originInfo)
{
    HITLS_AUTH_PrivPassCtx *ctx = NULL;
    HITLS_AUTH_PrivPassToken *tokenChallenge1 = NULL;
    HITLS_AUTH_PrivPassToken *tokenChallenge2 = NULL;
    HITLS_AUTH_PrivPassToken *tokenChallenge3 = NULL;
    HITLS_AUTH_PrivPassToken *tokenChallenge4 = NULL;
    HITLS_AUTH_PrivPassToken *tokenChallenge3_1 = NULL;
    HITLS_AUTH_PrivPassToken *tokenChallenge4_1 = NULL;
    uint8_t output1[MAX_LEN >> 1];
    uint32_t outputLen1 = MAX_LEN >> 1;
    uint8_t output2[MAX_LEN >> 1];
    uint32_t outputLen2 = MAX_LEN >> 1;
    uint8_t output3[MAX_LEN >> 1];
    uint32_t outputLen3 = MAX_LEN >> 1;
    uint8_t output4[MAX_LEN >> 1];
    uint32_t outputLen4 = MAX_LEN >> 1;
    uint16_t tokenTypeValue = tokenType->x[0] << 8 | tokenType->x[1];
    BSL_Param param1[5] = {
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE, BSL_PARAM_TYPE_UINT16, &tokenTypeValue, 2, 2},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ISSUERNAME, BSL_PARAM_TYPE_OCTETS_PTR, issuerName->x, issuerName->len,
            issuerName->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REDEMPTION, BSL_PARAM_TYPE_OCTETS_PTR, redemption->x, redemption->len,
            redemption->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ORIGININFO, BSL_PARAM_TYPE_OCTETS_PTR, originInfo->x, originInfo->len,
            originInfo->len},
        BSL_PARAM_END};
    BSL_Param param2[5] = {
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ISSUERNAME, BSL_PARAM_TYPE_OCTETS_PTR, issuerName->x, issuerName->len,
            issuerName->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE, BSL_PARAM_TYPE_UINT16, &tokenTypeValue, 2, 2},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ORIGININFO, BSL_PARAM_TYPE_OCTETS_PTR, originInfo->x, originInfo->len,
            originInfo->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REDEMPTION, BSL_PARAM_TYPE_OCTETS_PTR, redemption->x, redemption->len,
            redemption->len},
        BSL_PARAM_END};
    BSL_Param param3[5] = {
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ISSUERNAME, BSL_PARAM_TYPE_OCTETS_PTR, issuerName->x, issuerName->len,
            issuerName->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ORIGININFO, BSL_PARAM_TYPE_OCTETS_PTR, originInfo->x, originInfo->len,
            originInfo->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REDEMPTION, BSL_PARAM_TYPE_OCTETS_PTR, 0, 0, 0},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE, BSL_PARAM_TYPE_UINT16, &tokenTypeValue, 2, 2}, BSL_PARAM_END};
    BSL_Param param4[4] = {
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ISSUERNAME, BSL_PARAM_TYPE_OCTETS_PTR, issuerName->x, issuerName->len,
            issuerName->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REDEMPTION, BSL_PARAM_TYPE_OCTETS_PTR, redemption->x, redemption->len,
            redemption->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE, BSL_PARAM_TYPE_UINT16, &tokenTypeValue, 2, 2}, BSL_PARAM_END};

    TestRandInit();
    ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenChallenge(ctx, param1, &tokenChallenge1), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, tokenChallenge1, output1, &outputLen1), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenChallenge(ctx, param2, &tokenChallenge2), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, tokenChallenge2, output2, &outputLen2), HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare token", output1, outputLen1, output2, outputLen2);

    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenChallenge(ctx, param3, &tokenChallenge3), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, tokenChallenge3, output3, &outputLen3), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE, output3, outputLen3,
        &tokenChallenge3_1), HITLS_AUTH_SUCCESS);

    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenChallenge(ctx, param4, &tokenChallenge4), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, tokenChallenge4, output4, &outputLen4), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE, output4, outputLen4,
        &tokenChallenge4_1), HITLS_AUTH_SUCCESS);
EXIT:
    CRYPT_EAL_RandDeinit();
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge1);
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge2);
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge3);
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge4);
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge3_1);
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge4_1);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_SERIALIZATION_INVALID_TC001
 * @spec Private Pass Token Serialization Invalid Parameters
 * @title Test serialization and deserialization with invalid parameters
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_SERIALIZATION_INVALID_TC001()
{
    uint8_t output[MAX_LEN];
    uint32_t outputLen = MAX_LEN;
    HITLS_AUTH_PrivPassToken *token = NULL;
    uint8_t dummyData[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    HITLS_AUTH_PrivPassCtx *ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);

    // Test NULL parameters
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE,
        NULL, sizeof(dummyData), &token), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE,
        dummyData, 0, &token), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE,
        dummyData, sizeof(dummyData), NULL), HITLS_AUTH_PRIVPASS_INVALID_INPUT);

    // Test invalid token type
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, 999, dummyData,
        sizeof(dummyData), &token), HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
    // Test serialization with NULL parameters
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, NULL, output, &outputLen), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, token, NULL, &outputLen), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, token, output, NULL), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
EXIT:
    HITLS_AUTH_PrivPassFreeToken(token);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_SERIALIZATION_INVALID_TC002
 * @spec Private Pass Token Invalid Serialization
 * @title Test deserialization with invalid token data
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_SERIALIZATION_INVALID_TC002(int type, Hex *buffer)
{
    HITLS_AUTH_PrivPassToken *token = NULL;
    HITLS_AUTH_PrivPassCtx *ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);
    ASSERT_NE(HITLS_AUTH_PrivPassDeserialization(ctx, type, buffer->x, buffer->len, &token), HITLS_AUTH_SUCCESS);
EXIT:
    HITLS_AUTH_PrivPassFreeToken(token);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
    CRYPT_EAL_RandDeinit();
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_SERIALIZATION_INVALID_TC003
 * @spec Private Pass Token Invalid Serialization
 * @title Test serialization with invalid data
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_SERIALIZATION_INVALID_TC003(int type, Hex *buffer)
{
    HITLS_AUTH_PrivPassToken *token = NULL;
    HITLS_AUTH_PrivPassToken *token2 = NULL;
    uint8_t output[MAX_LEN];
    uint32_t outputLen = MAX_LEN;
    HITLS_AUTH_PrivPassCtx *ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, type, buffer->x, buffer->len, &token), HITLS_AUTH_SUCCESS);
    if (type == HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE) {
        token->st.tokenChallenge->tokenType = 0x0001; // support prv type
        ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, token, output, &outputLen), HITLS_AUTH_SUCCESS);
    }
    if (type == HITLS_AUTH_PRIVPASS_TOKEN_REQUEST) {
        token->st.tokenRequest->tokenType = 0x0001; // not support prv type
        ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, token, output, &outputLen),
            HITLS_AUTH_PRIVPASS_INVALID_TOKEN_REQUEST);
    }
    if (type == HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE) {
        ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, type, buffer->x, buffer->len - 1, &token2),
            HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
        token->st.tokenResponse->type = 0; // not support prv type
        ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, token, output, &outputLen),
            HITLS_AUTH_PRIVPASS_INVALID_TOKEN_RESPONSE);
        token->st.tokenResponse->type = 1;
    }
    if (type == HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE) {
        token->st.token->tokenType = 0; // not support prv type
        ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, token, output, &outputLen),
            HITLS_AUTH_PRIVPASS_INVALID_TOKEN_INSTANCE);
    }
EXIT:
    HITLS_AUTH_PrivPassFreeToken(token);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
    CRYPT_EAL_RandDeinit();
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_GEN_PROCESS_TC001
 * @spec Private Pass Token Generation Process
 * @title Test complete token generation process including challenge, request, response and verification
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_GEN_PROCESS_TC001(Hex *pki, Hex *ski, Hex *tokenType, Hex *issuerName,
    Hex *redemption, Hex *originInfo)
{
    HITLS_AUTH_PrivPassCtx *client = NULL;
    HITLS_AUTH_PrivPassCtx *issuer = NULL;
    HITLS_AUTH_PrivPassCtx *server = NULL;
    HITLS_AUTH_PrivPassToken *tokenChallenge = NULL;
    HITLS_AUTH_PrivPassToken *tokenChallenge2 = NULL;
    HITLS_AUTH_PrivPassToken *tokenRequest = NULL;
    HITLS_AUTH_PrivPassToken *tokenResponse = NULL;
    HITLS_AUTH_PrivPassToken *finalToken = NULL;
    uint8_t output[MAX_LEN];
    uint32_t outputLen = MAX_LEN;
    uint16_t tokenTypeValue = tokenType->x[0] << 8 | tokenType->x[1];
    BSL_Param param[5] = {
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE, BSL_PARAM_TYPE_UINT16, &tokenTypeValue, 2, 2},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ISSUERNAME, BSL_PARAM_TYPE_OCTETS_PTR, issuerName->x, issuerName->len,
            issuerName->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REDEMPTION, BSL_PARAM_TYPE_OCTETS_PTR, redemption->x, redemption->len,
            redemption->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ORIGININFO, BSL_PARAM_TYPE_OCTETS_PTR, originInfo->x, originInfo->len,
            originInfo->len},
        BSL_PARAM_END};

    TestRandInit();
    // Create context
    client = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(client, NULL);
    issuer = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(issuer, NULL);
    server = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(server, NULL);
    // Set keys
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPubkey(client, pki->x, pki->len), HITLS_AUTH_SUCCESS);
    // issuer needs pub and prv key
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPrvkey(issuer, NULL, ski->x, ski->len), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPubkey(issuer, pki->x, pki->len), HITLS_AUTH_SUCCESS);
    // server
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPubkey(server, pki->x, pki->len), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenChallenge(server, param, &tokenChallenge), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(server, tokenChallenge, output, &outputLen), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(client, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE, output,
        outputLen, &tokenChallenge2), HITLS_AUTH_SUCCESS);

    // Generate token request
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenReq(client, tokenChallenge, &tokenRequest), HITLS_AUTH_SUCCESS);
    // Generate token response
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenResponse(issuer, tokenRequest, &tokenResponse), HITLS_AUTH_SUCCESS);
    // Generate final token
    ASSERT_EQ(HITLS_AUTH_PrivPassGenToken(client, tokenChallenge, tokenResponse, &finalToken), HITLS_AUTH_SUCCESS);
    // Verify token
    ASSERT_EQ(HITLS_AUTH_PrivPassVerifyToken(server, tokenChallenge, finalToken), HITLS_AUTH_SUCCESS);
EXIT:
    CRYPT_EAL_RandDeinit();
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge);
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge2);
    HITLS_AUTH_PrivPassFreeToken(tokenRequest);
    HITLS_AUTH_PrivPassFreeToken(tokenResponse);
    HITLS_AUTH_PrivPassFreeToken(finalToken);
    HITLS_AUTH_PrivPassFreeCtx(client);
    HITLS_AUTH_PrivPassFreeCtx(issuer);
    HITLS_AUTH_PrivPassFreeCtx(server);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_GEN_TOKEN_CHALLENGE_TC001
 * @spec Private Pass Token gen invalid token challenge
 * @title Test gen invalid token challenge
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_GEN_TOKEN_CHALLENGE_TC001(Hex *tokenType, Hex *issuerName, Hex *redemption,
    Hex *originInfo)
{
    HITLS_AUTH_PrivPassCtx *ctx = NULL;
    HITLS_AUTH_PrivPassToken *tokenChallenge = NULL;
    uint16_t invaliedTokenType = 3;
    uint16_t tokenTypeValue = tokenType->x[0] << 8 | tokenType->x[1];
    BSL_Param param1[5] = {
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ISSUERNAME, BSL_PARAM_TYPE_OCTETS_PTR, issuerName->x, issuerName->len,
            issuerName->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE, BSL_PARAM_TYPE_UINT16, &invaliedTokenType, 2, 2},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ORIGININFO, BSL_PARAM_TYPE_OCTETS_PTR, originInfo->x, originInfo->len,
            originInfo->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REDEMPTION, BSL_PARAM_TYPE_OCTETS_PTR, redemption->x, redemption->len,
            redemption->len},
        BSL_PARAM_END};
    BSL_Param param2[4] = {
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE, BSL_PARAM_TYPE_UINT16, &tokenTypeValue, 2, 2},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ORIGININFO, BSL_PARAM_TYPE_OCTETS_PTR, originInfo->x, originInfo->len,
            originInfo->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REDEMPTION, BSL_PARAM_TYPE_OCTETS_PTR, redemption->x, redemption->len,
            redemption->len},
        BSL_PARAM_END};
    BSL_Param param3[4] = {
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE, BSL_PARAM_TYPE_UINT16, &tokenTypeValue, 2, 2},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ISSUERNAME, BSL_PARAM_TYPE_OCTETS_PTR, issuerName->x,
            PRIVPASS_MAX_ISSUER_NAME_LEN + 1, PRIVPASS_MAX_ISSUER_NAME_LEN + 1},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REDEMPTION, BSL_PARAM_TYPE_OCTETS_PTR, redemption->x, redemption->len,
            redemption->len},
        BSL_PARAM_END};
    BSL_Param param4[5] = {
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE, BSL_PARAM_TYPE_UINT16, &tokenTypeValue, 2, 2},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ISSUERNAME, BSL_PARAM_TYPE_OCTETS_PTR, issuerName->x, issuerName->len,
            issuerName->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REDEMPTION, BSL_PARAM_TYPE_OCTETS_PTR, redemption->x, redemption->len,
            redemption->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ORIGININFO, BSL_PARAM_TYPE_OCTETS_PTR, originInfo->x,
            PRIVPASS_MAX_ISSUER_NAME_LEN + 1, PRIVPASS_MAX_ORIGIN_INFO_LEN + 1},
        BSL_PARAM_END};
    BSL_Param param5[4] = {
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE, BSL_PARAM_TYPE_UINT16, &tokenTypeValue, 2, 2},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ISSUERNAME, BSL_PARAM_TYPE_OCTETS_PTR, issuerName->x, issuerName->len,
            issuerName->len},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REDEMPTION, BSL_PARAM_TYPE_OCTETS_PTR, redemption->x,
            PRIVPASS_MAX_ISSUER_NAME_LEN + 1, PRIVPASS_REDEMPTION_LEN + 1},
        BSL_PARAM_END};

    ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenChallenge(ctx, param1, &tokenChallenge),
        HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenChallenge(ctx, param2, &tokenChallenge),
        HITLS_AUTH_PRIVPASS_NO_TOKEN_CHALLENGE_ISSUERNAME);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenChallenge(ctx, param3, &tokenChallenge),
        HITLS_AUTH_PRIVPASS_INVALID_ISSUER_NAME);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenChallenge(ctx, param4, &tokenChallenge),
        HITLS_AUTH_PRIVPASS_INVALID_ORIGIN_INFO);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenChallenge(ctx, param5, &tokenChallenge),
        HITLS_AUTH_PRIVPASS_INVALID_REDEMPTION);
EXIT:
    CRYPT_EAL_RandDeinit();
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
}
/* END_CASE */

static uint8_t *g_nonceBuf;
static uint32_t g_nonceLen;
static uint8_t *g_saltBuf;
static uint32_t g_saltLen;
static uint8_t *g_blindBuf;
static uint32_t g_blindLen;
static int32_t ref = 0;

static int32_t STUB_ReplaceRandom(uint8_t *r, uint32_t randLen)
{
    if (ref == 0) {
        for (uint32_t i = 0; i < randLen; i++) {
            r[i] = g_nonceBuf[i];
        }
        ref++;
    } else if (ref == 1) {
        for (uint32_t i = 0; i < randLen; i++) {
            r[i] = g_saltBuf[i];
        }
        ref++;
    } else if (ref == 2) {
        for (uint32_t i = 0; i < randLen; i++) {
            r[i] = g_blindBuf[i];
        }
    }
    return 0;
}

static int32_t STUB_ReplaceRandomWEx(void *libCtx, uint8_t *r, uint32_t randLen)
{
    (void) libCtx;
    return STUB_ReplaceRandom(r, randLen);
}

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_VECTOR_TEST_TC001
 * @spec Private Pass Token Vector Testing
 * @title Test token generation process with predefined test vectors
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_VECTOR_TEST_TC001(Hex *ski, Hex *pki, Hex *challenge, Hex *nonce, Hex *blind, Hex *salt,
    Hex *request, Hex *response, Hex *token)
{
    ref = 0;
    TestRandInit();
    uint8_t tokenChallengeBuffer[MAX_LEN];
    uint32_t tokenChallengeBufferLen = MAX_LEN;
    uint8_t tokenRequestBuffer[MAX_LEN];
    uint32_t tokenRequestBufferLen = MAX_LEN;
    uint8_t tokenResponseBuffer[MAX_LEN];
    uint32_t tokenResponseBufferLen = MAX_LEN;
    uint8_t finalTokenBuffer[MAX_LEN];
    uint32_t finalTokenBufferLen = MAX_LEN;
    uint8_t nonceBuff[MAX_LEN];
    uint32_t nonceLen = MAX_LEN;
    HITLS_AUTH_PrivPassCtx *ctx = NULL;
    HITLS_AUTH_PrivPassToken *tokenChallenge = NULL;
    HITLS_AUTH_PrivPassToken *tokenRequest = NULL;
    HITLS_AUTH_PrivPassToken *tokenResponse = NULL;
    HITLS_AUTH_PrivPassToken *finalToken = NULL;
    g_nonceBuf = (uint8_t *)nonce->x;
    g_saltBuf = (uint8_t *)salt->x;
    g_nonceLen = nonce->len;
    g_saltLen = salt->len;
    g_blindBuf = (uint8_t *)blind->x;
    g_blindLen = blind->len;
    BSL_Param param[2] = {
        {AUTH_PARAM_PRIVPASS_TOKEN_NONCE, BSL_PARAM_TYPE_OCTETS_PTR, nonceBuff, nonceLen, 0}, BSL_PARAM_END};

    // Create context
    ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ctx->method.random = STUB_ReplaceRandom;
    ASSERT_NE(ctx, NULL);
    // Set keys
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPubkey(ctx, pki->x, pki->len), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPrvkey(ctx, NULL, ski->x, ski->len), HITLS_AUTH_SUCCESS);

    CRYPT_RandRegist(STUB_ReplaceRandom);
    CRYPT_RandRegistEx(STUB_ReplaceRandomWEx);
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE, challenge->x, challenge->len,
        &tokenChallenge), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, tokenChallenge, tokenChallengeBuffer, &tokenChallengeBufferLen),
        HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare tokenchallenge", tokenChallengeBuffer, tokenChallengeBufferLen,
        challenge->x, challenge->len);
    // Generate token request
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenReq(ctx, tokenChallenge, &tokenRequest), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, tokenRequest, tokenRequestBuffer, &tokenRequestBufferLen),
        HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare tokenrequest", tokenRequestBuffer, tokenRequestBufferLen, request->x, request->len);
    // Generate token response
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenResponse(ctx, tokenRequest, &tokenResponse), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, tokenResponse, tokenResponseBuffer, &tokenResponseBufferLen),
        HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare tokenresponse", tokenResponseBuffer, tokenResponseBufferLen, response->x, response->len);
    // Generate final token
    ASSERT_EQ(HITLS_AUTH_PrivPassGenToken(ctx, tokenChallenge, tokenResponse, &finalToken), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, finalToken, finalTokenBuffer, &finalTokenBufferLen),
        HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare finaltoken", finalTokenBuffer, finalTokenBufferLen, token->x, token->len);
    // Verify token
    ASSERT_EQ(HITLS_AUTH_PrivPassVerifyToken(ctx, tokenChallenge, finalToken), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(finalToken, HITLS_AUTH_PRIVPASS_GET_TOKEN_NONCE, param, 0),
        HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare nonce", param->value, param->useLen, nonce->x, nonce->len);

EXIT:
    TestRandDeInit();
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge);
    HITLS_AUTH_PrivPassFreeToken(tokenRequest);
    HITLS_AUTH_PrivPassFreeToken(tokenResponse);
    HITLS_AUTH_PrivPassFreeToken(finalToken);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_CHALLENGE_OBTAIN_TC001
 * @spec Private Pass Token Challenge Parameters
 * @title Test obtaining and validating token challenge parameters
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_CHALLENGE_OBTAIN_TC001(Hex *challenge)
{
    uint8_t tokenChallengeBuffer[MAX_LEN];
    uint32_t tokenChallengeBufferLen = MAX_LEN;
    uint16_t tokenType;
    uint8_t issuerNameBuffer[MAX_LEN];
    uint32_t issuerNameBufferLen = MAX_LEN;
    uint8_t redemptionBuffer[MAX_LEN];
    uint32_t redemptionBufferLen = MAX_LEN;
    uint8_t originInfoBuffer[MAX_LEN];
    uint32_t originInfoBufferLen = MAX_LEN;
    HITLS_AUTH_PrivPassToken *tokenChallenge1 = NULL;
    HITLS_AUTH_PrivPassToken *tokenChallenge2 = NULL;
    HITLS_AUTH_PrivPassCtx *ctx = NULL;
    BSL_Param param1[5] = {
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE, BSL_PARAM_TYPE_UINT16, &tokenType, 2, 0},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ISSUERNAME, BSL_PARAM_TYPE_OCTETS_PTR, issuerNameBuffer,
            issuerNameBufferLen, 0},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REDEMPTION, BSL_PARAM_TYPE_OCTETS_PTR, redemptionBuffer,
            redemptionBufferLen, 0},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ORIGININFO, BSL_PARAM_TYPE_OCTETS_PTR, originInfoBuffer,
            originInfoBufferLen, 0},
        BSL_PARAM_END};
    BSL_Param param2[5] = {
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE, BSL_PARAM_TYPE_UINT16, &tokenType, 2, 0},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ISSUERNAME, BSL_PARAM_TYPE_OCTETS_PTR, issuerNameBuffer, 0, 0},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REDEMPTION, BSL_PARAM_TYPE_OCTETS_PTR, redemptionBuffer, 0, 0},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ORIGININFO, BSL_PARAM_TYPE_OCTETS_PTR, originInfoBuffer, 0, 0},
        BSL_PARAM_END};
    // Create context
    ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);

    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE, challenge->x, challenge->len,
        &tokenChallenge1), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenChallenge1, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_TYPE, param1, 0),
        HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenChallenge1, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_REDEMPTION,
        param1, 0),
        HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenChallenge1, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_ORIGININFO,
        param1, 0),
        HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenChallenge1, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_ISSUERNAME,
        param1, 0),
        HITLS_AUTH_SUCCESS);
    param2[0].valueLen = param1[0].useLen;
    param2[1].valueLen = param1[1].useLen;
    param2[2].valueLen = param1[2].useLen;
    param2[3].valueLen = param1[3].useLen;
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenChallenge(ctx, param2, &tokenChallenge2), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, tokenChallenge2, tokenChallengeBuffer,
        &tokenChallengeBufferLen), HITLS_AUTH_SUCCESS);

    ASSERT_COMPARE("compare token challenge", tokenChallengeBuffer, tokenChallengeBufferLen, challenge->x,
        challenge->len);
EXIT:
    CRYPT_EAL_RandDeinit();
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge1);
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge2);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
}
/* END_CASE */

void *NewPkeyCtxTmp(void *libCtx, int algId)
{
    (void)libCtx;
    (void)algId;
    return NULL;
}

/**
 * @test SDV_AUTH_PRIVPASS_TEST_SET_CRYPTO_CB_TC001
 * @brief Test setting and validating crypto callback functionality
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TEST_SET_CRYPTO_CB_TC001(Hex *ski, Hex *pki)
{
    TestRandInit();
    HITLS_AUTH_PrivPassCtx *ctx = NULL;
    HITLS_AUTH_PrivPassToken *tokenChallenge = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE);
    HITLS_AUTH_PrivPassToken *tokenRequest = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_REQUEST);
    HITLS_AUTH_PrivPassToken *tokenResponse = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE);
    HITLS_AUTH_PrivPassToken *finalToken = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE);
    HITLS_AUTH_PrivPassToken *tokenRequest1 = NULL;
    HITLS_AUTH_PrivPassToken *tokenResponse1 = NULL;
    HITLS_AUTH_PrivPassToken *finalToken1 = NULL;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    ASSERT_NE(tokenChallenge, NULL);
    ASSERT_NE(tokenRequest, NULL);
    ASSERT_NE(tokenResponse, NULL);
    ASSERT_NE(finalToken, NULL);
    ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPubkey(ctx, pki->x, pki->len), 0);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPrvkey(ctx, NULL, ski->x, ski->len), 0);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenReq(ctx, tokenChallenge, &tokenRequest1),
        HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenResponse(ctx, tokenRequest, &tokenResponse1),
        HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenToken(ctx, tokenChallenge, tokenResponse, &finalToken1),
        HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
    ASSERT_EQ(HITLS_AUTH_PrivPassVerifyToken(ctx, tokenChallenge, finalToken), HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);

    pkeyCtx = ctx->method.newPkeyCtx(NULL, NULL, HITLS_AUTH_PRIVPASS_CRYPTO_RSA);
    ASSERT_NE(pkeyCtx, NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGetId(pkeyCtx), CRYPT_PKEY_RSA);
    ctx->method.freePkeyCtx(pkeyCtx);
    pkeyCtx = NULL;
    ASSERT_EQ(HITLS_AUTH_PrivPassSetCryptCb(ctx, HITLS_AUTH_PRIVPASS_NEW_PKEY_CTX_CB - 1, NewPkeyCtxTmp),
        HITLS_AUTH_PRIVPASS_INVALID_CRYPTO_CALLBACK_TYPE);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetCryptCb(ctx, HITLS_AUTH_PRIVPASS_NEW_PKEY_CTX_CB, NewPkeyCtxTmp),
        HITLS_AUTH_SUCCESS);
    pkeyCtx = ctx->method.newPkeyCtx(NULL, NULL, HITLS_AUTH_PRIVPASS_CRYPTO_RSA);
    ASSERT_EQ(pkeyCtx, NULL);
EXIT:
    HITLS_AUTH_PrivPassFreeCtx(ctx);
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge);
    HITLS_AUTH_PrivPassFreeToken(tokenRequest);
    HITLS_AUTH_PrivPassFreeToken(tokenResponse);
    HITLS_AUTH_PrivPassFreeToken(finalToken);
    TestRandDeInit();
}
/* END_CASE */

/**
* @test SDV_AUTH_PRIVPASS_SET_KEY_TC001
 * @brief Test case for setting public and private keys in PrivPass context
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_SET_KEY_TC001(Hex *ski, Hex *pki)
{
    TestRandInit();
    HITLS_AUTH_PrivPassCtx *ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);
    // Test NULL pointer parameters
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPubkey(NULL, pki->x, pki->len), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPubkey(ctx, NULL, pki->len), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPrvkey(NULL, NULL, ski->x, ski->len), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPrvkey(ctx, NULL, NULL, ski->len), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    // Test zero length
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPubkey(ctx, pki->x, 0), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPrvkey(ctx, NULL, ski->x, 0), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
     // Test duplicate key setting
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPubkey(ctx, pki->x, pki->len), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPubkey(ctx, pki->x, pki->len), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPrvkey(ctx, NULL, ski->x, ski->len), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPrvkey(ctx, NULL, ski->x, ski->len), HITLS_AUTH_SUCCESS);
    ctx->method.checkKeyPair = NULL;
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPrvkey(ctx, NULL, ski->x, ski->len), HITLS_AUTH_PRIVPASS_NO_KEYPAIR_CHECK_CALLBACK);

EXIT:
    HITLS_AUTH_PrivPassFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_SET_KEY_TC002
 * @brief Test case for validating that mismatched public/private key pairs are rejected
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_SET_KEY_TC002()
{
    TestRandInit();
    uint8_t e[] = {1, 0, 1};
    BSL_Buffer pubBuffer = {0};
    BSL_Buffer prvBuffer = {0};
    CRYPT_EAL_PkeyPara para = {0};
    HITLS_AUTH_PrivPassCtx *ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    CRYPT_EAL_PkeyCtx *pkey1 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    CRYPT_EAL_PkeyCtx *pkey2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    CRYPT_MD_AlgId mdId = CRYPT_MD_SHA384;
    uint32_t saltLen = 0;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0}, BSL_PARAM_END};
    ASSERT_NE(ctx, NULL);
    ASSERT_NE(pkey1, NULL);
    ASSERT_NE(pkey2, NULL);
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.e = e;
    para.para.rsaPara.eLen = 3;
    para.para.rsaPara.bits = 2048;
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey1, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey2, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey2), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey1, CRYPT_CTRL_SET_RSA_EMSA_PSS, &pssParam, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey2, CRYPT_CTRL_SET_RSA_EMSA_PSS, &pssParam, 0) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkey1, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &pubBuffer), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkey2, NULL, BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &prvBuffer),
        CRYPT_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPubkey(ctx, pubBuffer.data, pubBuffer.dataLen), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPrvkey(ctx, NULL, prvBuffer.data, prvBuffer.dataLen),
        HITLS_AUTH_PRIVPASS_CHECK_KEYPAIR_FAILED);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
    ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPrvkey(ctx, NULL, prvBuffer.data, prvBuffer.dataLen),
        HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassSetPubkey(ctx, pubBuffer.data, pubBuffer.dataLen),
        HITLS_AUTH_PRIVPASS_CHECK_KEYPAIR_FAILED);
EXIT:
    BSL_SAL_Free(pubBuffer.data);
    BSL_SAL_Free(prvBuffer.data);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_GEN_INVALID_TC001
 * @spec Private Pass Token Generation Invalid Cases
 * @title Test token generation process with invalid parameters and states
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_INVALID_INTERACTION_TC001()
{
    HITLS_AUTH_PrivPassCtx *ctx = NULL;
    HITLS_AUTH_PrivPassToken *tokenChallenge = NULL;
    HITLS_AUTH_PrivPassToken *tokenRequest = NULL;
    HITLS_AUTH_PrivPassToken *tokenResponse = NULL;
    HITLS_AUTH_PrivPassToken *finalToken = NULL;

    TestRandInit();
    // Test with NULL context
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenReq(NULL, tokenChallenge, &tokenRequest), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenResponse(NULL, tokenRequest, &tokenResponse),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenToken(NULL, tokenChallenge, tokenResponse, &finalToken),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassVerifyToken(NULL, tokenChallenge, finalToken), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    // Create context but don't set keys
    ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenReq(ctx, tokenChallenge, &tokenRequest), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenResponse(ctx, tokenRequest, &tokenResponse),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenToken(ctx, tokenChallenge, tokenResponse, &finalToken),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassVerifyToken(ctx, tokenChallenge, finalToken), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    // Test with NULL tokens
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenReq(ctx, NULL, &tokenRequest), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenResponse(ctx, NULL, &tokenResponse), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenToken(ctx, NULL, tokenResponse, &finalToken), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassVerifyToken(ctx, NULL, finalToken), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
EXIT:
    TestRandDeInit();
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge);
    HITLS_AUTH_PrivPassFreeToken(tokenRequest);
    HITLS_AUTH_PrivPassFreeToken(tokenResponse);
    HITLS_AUTH_PrivPassFreeToken(finalToken);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_GEN_INVALID_TC001
 * @brief Test case to verify error handling for invalid PrivPass token interactions
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_INVALID_INTERACTION_TC002(Hex *challenge, Hex *request, Hex *response, Hex *token)
{
    TestRandInit();
    HITLS_AUTH_PrivPassCtx *ctx = NULL;
    HITLS_AUTH_PrivPassToken *tokenChallenge = NULL;
    HITLS_AUTH_PrivPassToken *tokenRequest = NULL;
    HITLS_AUTH_PrivPassToken *tokenResponse = NULL;
    HITLS_AUTH_PrivPassToken *finalToken = NULL;
    HITLS_AUTH_PrivPassToken *tokenRequest1 = NULL;
    HITLS_AUTH_PrivPassToken *tokenResponse1 = NULL;
    HITLS_AUTH_PrivPassToken *finalToken1 = NULL;
    // Create a new PrivPass context
    ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE, challenge->x, challenge->len,
        &tokenChallenge), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_REQUEST, request->x, request->len,
        &tokenRequest), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE, response->x, response->len,
        &tokenResponse), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE, token->x, token->len,
        &finalToken), HITLS_AUTH_SUCCESS);

    // The entered token object does not match the expected value
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenReq(ctx, finalToken, &tokenRequest), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenResponse(ctx, finalToken, &tokenResponse), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenToken(ctx, tokenResponse, tokenResponse, &finalToken),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenToken(ctx, tokenChallenge, tokenChallenge, &finalToken),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassVerifyToken(ctx, tokenResponse, finalToken), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    // When the output != NULL
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenReq(ctx, tokenChallenge, &tokenRequest), HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenResponse(ctx, tokenRequest, &tokenResponse),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenToken(ctx, tokenChallenge, tokenResponse, &finalToken),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    // There is no key info
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenReq(ctx, tokenChallenge, &tokenRequest1), HITLS_AUTH_PRIVPASS_NO_PUBKEY_INFO);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenTokenResponse(ctx, tokenRequest, &tokenResponse1),
        HITLS_AUTH_PRIVPASS_NO_PRVKEY_INFO);
    ASSERT_EQ(HITLS_AUTH_PrivPassGenToken(ctx, tokenChallenge, tokenResponse, &finalToken1),
        HITLS_AUTH_PRIVPASS_NO_PUBKEY_INFO);
    ASSERT_EQ(HITLS_AUTH_PrivPassVerifyToken(ctx, tokenChallenge, finalToken), HITLS_AUTH_PRIVPASS_NO_PUBKEY_INFO);
EXIT:
    TestRandDeInit();
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge);
    HITLS_AUTH_PrivPassFreeToken(tokenRequest);
    HITLS_AUTH_PrivPassFreeToken(tokenResponse);
    HITLS_AUTH_PrivPassFreeToken(finalToken);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_CHALLENGEREQUEST_OBTAIN_TC001
 * @spec Private Pass Token challenge Request Parameters
 * @title Test obtaining and validating token challenge request parameters obtain
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_CHALLENGEREQUEST_OBTAIN_TC001(Hex *challRequest)
{
    uint8_t challengeRequestBuffer[MAX_LEN];
    HITLS_AUTH_PrivPassToken *challengeRequest = NULL;
    HITLS_AUTH_PrivPassCtx *ctx = NULL;
    BSL_Param param[3] = {
        {AUTH_PARAM_PRIVPASS_TOKEN, BSL_PARAM_TYPE_OCTETS_PTR, challengeRequestBuffer,
            MAX_LEN, MAX_LEN},
        {AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REQUEST, BSL_PARAM_TYPE_OCTETS_PTR, challengeRequestBuffer,
            MAX_LEN, MAX_LEN},
        BSL_PARAM_END};
    // Create context
    ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);

    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE_REQUEST, challRequest->x,
        challRequest->len, &challengeRequest), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(challengeRequest, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGEREQUEST_INFO,
        param, 0), HITLS_AUTH_SUCCESS);

    ASSERT_COMPARE("compare token challenge request", challengeRequestBuffer, param[1].useLen, challRequest->x,
        challRequest->len);
EXIT:
    HITLS_AUTH_PrivPassFreeToken(challengeRequest);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_REQUEST_OBTAIN_TC001
 * @spec Private Pass Token challenge Request Parameters
 * @title Test obtaining and validating token challenge request parameters obtain
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_REQUEST_OBTAIN_TC001(Hex *request)
{
    uint8_t tokenRequestBuffer[MAX_LEN];
    uint32_t tokenRequestBufferLen = MAX_LEN;
    uint16_t tokenType;
    uint8_t truncatedTokenKeyId;
    uint8_t blindedMsgBuffer[MAX_LEN];
    uint32_t blindedMsgBufferLen = MAX_LEN;
    HITLS_AUTH_PrivPassToken *tokenRequest1 = NULL;
    HITLS_AUTH_PrivPassToken *tokenRequest2 = NULL;
    HITLS_AUTH_PrivPassCtx *ctx = NULL;
    PrivPass_TokenRequest *tmpRequest = NULL;
    BSL_Param param[4] = {
        {AUTH_PARAM_PRIVPASS_TOKENREQUEST_BLINDEDMSG, BSL_PARAM_TYPE_OCTETS_PTR, blindedMsgBuffer, blindedMsgBufferLen, 0},
        {AUTH_PARAM_PRIVPASS_TOKENREQUEST_TRUNCATEDTOKENKEYID, BSL_PARAM_TYPE_UINT8, &truncatedTokenKeyId, 1, 0},
        {AUTH_PARAM_PRIVPASS_TOKENREQUEST_TYPE, BSL_PARAM_TYPE_UINT16, &tokenType, 2, 0},
        BSL_PARAM_END
    };

    // Create context
    ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_TRUE(ctx != NULL);

    // Deserialize the request
    ASSERT_TRUE(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_REQUEST, request->x, request->len,
        &tokenRequest1) == HITLS_AUTH_SUCCESS);

    // Extract parameters
    ASSERT_TRUE(HITLS_AUTH_PrivPassTokenCtrl(tokenRequest1, HITLS_AUTH_PRIVPASS_GET_TOKENREQUEST_TYPE, param, 0)
        == HITLS_AUTH_SUCCESS);
    ASSERT_TRUE(HITLS_AUTH_PrivPassTokenCtrl(tokenRequest1, HITLS_AUTH_PRIVPASS_GET_TOKENREQUEST_TRUNCATEDTOKENKEYID,
        param, 0) == HITLS_AUTH_SUCCESS);
    ASSERT_TRUE(HITLS_AUTH_PrivPassTokenCtrl(tokenRequest1, HITLS_AUTH_PRIVPASS_GET_TOKENREQUEST_BLINDEDMSG, param,
        0) == HITLS_AUTH_SUCCESS);

    // Create new token request
    tokenRequest2 = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_REQUEST);
    tmpRequest = tokenRequest2->st.tokenRequest;
    tmpRequest->tokenType = tokenType;
    tmpRequest->truncatedTokenKeyId = truncatedTokenKeyId;
    tmpRequest->blindedMsg.data = blindedMsgBuffer;
    tmpRequest->blindedMsg.dataLen = param[0].useLen;
    // Serialize and compare
    ASSERT_TRUE(HITLS_AUTH_PrivPassSerialization(ctx, tokenRequest2, tokenRequestBuffer, &tokenRequestBufferLen)
        == HITLS_AUTH_SUCCESS);
    ASSERT_TRUE(memcmp(tokenRequestBuffer, request->x, request->len) == 0);
    ASSERT_COMPARE("compare token request", tokenRequestBuffer, tokenRequestBufferLen, request->x, request->len);
EXIT:
    tmpRequest->blindedMsg.data = NULL;
    HITLS_AUTH_PrivPassFreeToken(tokenRequest1);
    HITLS_AUTH_PrivPassFreeToken(tokenRequest2);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_INSTANCE_OBTAIN_TC001
 * @spec Private Pass Token Instance Parameters
 * @title Test obtaining and validating token instance parameters
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_INSTANCE_OBTAIN_TC001(Hex *token)
{
    uint8_t tokenInstanceBuffer[MAX_LEN];
    uint32_t tokenInstanceBufferLen = MAX_LEN;
    uint16_t tokenType;
    uint8_t nonceBuffer[MAX_LEN];
    uint32_t nonceBufferLen = MAX_LEN;
    uint8_t challengeDigestBuffer[MAX_LEN];
    uint32_t challengeDigestBufferLen = MAX_LEN;
    uint8_t tokenKeyIdBuffer[MAX_LEN];
    uint32_t tokenKeyIdBufferLen = MAX_LEN;
    uint8_t authenticatorBuffer[MAX_LEN];
    uint32_t authenticatorBufferLen = MAX_LEN;
    HITLS_AUTH_PrivPassToken *tokenInstance1 = NULL;
    HITLS_AUTH_PrivPassToken *tokenInstance2 = NULL;
    HITLS_AUTH_PrivPassCtx *ctx = NULL;
    PrivPass_TokenInstance *tmpToken = NULL;
    BSL_Param param[6] = {
        {AUTH_PARAM_PRIVPASS_TOKEN_NONCE, BSL_PARAM_TYPE_OCTETS_PTR, nonceBuffer, nonceBufferLen, 0},
        {AUTH_PARAM_PRIVPASS_TOKEN_AUTHENTICATOR, BSL_PARAM_TYPE_OCTETS_PTR, authenticatorBuffer,
            authenticatorBufferLen, 0},
        {AUTH_PARAM_PRIVPASS_TOKEN_TYPE, BSL_PARAM_TYPE_UINT16, &tokenType, 2, 0},
        {AUTH_PARAM_PRIVPASS_TOKEN_CHALLENGEDIGEST, BSL_PARAM_TYPE_OCTETS_PTR, challengeDigestBuffer,
            challengeDigestBufferLen, 0},
        {AUTH_PARAM_PRIVPASS_TOKEN_TOKENKEYID, BSL_PARAM_TYPE_OCTETS_PTR, tokenKeyIdBuffer, tokenKeyIdBufferLen, 0},
        BSL_PARAM_END
    };

    // Create context
    ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);

    // Deserialize the token instance
    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE, token->x, token->len, 
        &tokenInstance1), HITLS_AUTH_SUCCESS);

    // Extract parameters
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenInstance1, HITLS_AUTH_PRIVPASS_GET_TOKEN_TYPE, param, 0),
        HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenInstance1, HITLS_AUTH_PRIVPASS_GET_TOKEN_NONCE, param, 0),
        HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenInstance1, HITLS_AUTH_PRIVPASS_GET_TOKEN_CHALLENGEDIGEST, param, 0),
        HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenInstance1, HITLS_AUTH_PRIVPASS_GET_TOKEN_TOKENKEYID, param, 0),
        HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenInstance1, HITLS_AUTH_PRIVPASS_GET_TOKEN_AUTHENTICATOR, param, 0),
        HITLS_AUTH_SUCCESS);

    // Create new token instance
    tokenInstance2 = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE);
    tmpToken = tokenInstance2->st.token;
    tmpToken->tokenType = tokenType;
    (void)memcpy_s(tmpToken->nonce, param[0].useLen, nonceBuffer, param[0].useLen);
    (void)memcpy_s(tmpToken->challengeDigest, param[3].useLen, challengeDigestBuffer, param[3].useLen);
    (void)memcpy_s(tmpToken->tokenKeyId, param[4].useLen, tokenKeyIdBuffer, param[4].useLen);
    tmpToken->authenticator.data = authenticatorBuffer;
    tmpToken->authenticator.dataLen = param[1].useLen;
    // Serialize and compare
    ASSERT_EQ(HITLS_AUTH_PrivPassSerialization(ctx, tokenInstance2, tokenInstanceBuffer, &tokenInstanceBufferLen),
        HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare token instance", tokenInstanceBuffer, tokenInstanceBufferLen, token->x, token->len);
EXIT:
    tmpToken->authenticator.data = NULL;
    HITLS_AUTH_PrivPassFreeToken(tokenInstance1);
    HITLS_AUTH_PrivPassFreeToken(tokenInstance2);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_RESPONSE_OBTAIN_TC001
 * @spec Private Pass Token Response Parameters
 * @title Test obtaining and validating token response parameters obtain
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_RESPONSE_OBTAIN_TC001(Hex *response)
{
    uint8_t responseBuffer[MAX_LEN];
    uint32_t responseBufferLen = MAX_LEN;
    HITLS_AUTH_PrivPassToken *responseToken = NULL;
    HITLS_AUTH_PrivPassCtx *ctx = NULL;
    BSL_Param param[3] = {
        {AUTH_PARAM_PRIVPASS_TOKEN, BSL_PARAM_TYPE_OCTETS_PTR, responseBuffer, responseBufferLen, 0},
        {AUTH_PARAM_PRIVPASS_TOKENRESPONSE_INFO, BSL_PARAM_TYPE_OCTETS_PTR, responseBuffer, responseBufferLen, 0},
        BSL_PARAM_END};
    // Create context
    ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(HITLS_AUTH_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE, response->x,
        response->len, &responseToken), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(responseToken, HITLS_AUTH_PRIVPASS_GET_TOKENRESPONSE_INFO, param, 0),
        HITLS_AUTH_SUCCESS);

    ASSERT_COMPARE("compare token response", responseBuffer, param[1].useLen, response->x,
        response->len);
EXIT:
    HITLS_AUTH_PrivPassFreeToken(responseToken);
    HITLS_AUTH_PrivPassFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_CTRL_INVALIED_TEST_TC001
 * @spec Private Pass Token Ctrl Invalid Test
 * @title Test obtaining and validating token ctrl invalid test
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_CTRL_INVALIED_TEST_TC001()
{
    uint8_t buffer[MAX_LEN];
    uint32_t bufferLen = MAX_LEN;
    BSL_Param param[4] = {
        {AUTH_PARAM_PRIVPASS_TOKENREQUEST_BLINDEDMSG, BSL_PARAM_TYPE_OCTETS_PTR, buffer, bufferLen, 0},
        {AUTH_PARAM_PRIVPASS_TOKENRESPONSE_INFO, BSL_PARAM_TYPE_OCTETS_PTR, buffer, bufferLen, 0},
        {AUTH_PARAM_PRIVPASS_TOKEN_AUTHENTICATOR, BSL_PARAM_TYPE_OCTETS_PTR, buffer, bufferLen, 0},
        BSL_PARAM_END};
    HITLS_AUTH_PrivPassToken *tokenChallReq = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE_REQUEST);
    HITLS_AUTH_PrivPassToken *tokenChallenge = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE);
    HITLS_AUTH_PrivPassToken *tokenRequest = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_REQUEST);
    HITLS_AUTH_PrivPassToken *tokenResponse = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE);
    HITLS_AUTH_PrivPassToken *tokenInstance = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE);
    ASSERT_TRUE(tokenChallReq != NULL);
    ASSERT_TRUE(tokenChallenge != NULL);
    ASSERT_TRUE(tokenRequest != NULL);
    ASSERT_TRUE(tokenResponse != NULL);
    ASSERT_TRUE(tokenInstance != NULL);

    // for test invailed token challenge request
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(NULL, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGEREQUEST_INFO, param, 0),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenChallReq, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGEREQUEST_INFO, NULL, 0),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenChallReq, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGEREQUEST_INFO, param, 0),
        HITLS_AUTH_PRIVPASS_NO_TOKEN_CHALLENGE_REQUEST);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenChallenge, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGEREQUEST_INFO, param,
        0), HITLS_AUTH_PRIVPASS_INVALID_INPUT);

    // for test invailed token challenge
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenChallenge, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_TYPE, NULL, 0),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenChallenge, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_ISSUERNAME, param, 0),
        HITLS_AUTH_PRIVPASS_NO_ISSUERNAME);

    // for test invailed token request
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenRequest, HITLS_AUTH_PRIVPASS_GET_TOKENREQUEST_TYPE, NULL, 0),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenRequest, HITLS_AUTH_PRIVPASS_GET_TOKENREQUEST_BLINDEDMSG, param, 0),
        HITLS_AUTH_PRIVPASS_NO_BLINDEDMSG);

    // for test invailed token response
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(NULL, HITLS_AUTH_PRIVPASS_GET_TOKENRESPONSE_INFO, param, 0),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenResponse, HITLS_AUTH_PRIVPASS_GET_TOKENRESPONSE_INFO, param, 0),
        HITLS_AUTH_PRIVPASS_NO_RESPONSE_INFO);

    // for test invailed token
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(NULL, HITLS_AUTH_PRIVPASS_GET_TOKEN_TYPE, param, 0),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassTokenCtrl(tokenInstance, HITLS_AUTH_PRIVPASS_GET_TOKEN_AUTHENTICATOR, param, 0),
        HITLS_AUTH_PRIVPASS_NO_AUTHENTICATOR);

EXIT:
    HITLS_AUTH_PrivPassFreeToken(tokenChallReq);
    HITLS_AUTH_PrivPassFreeToken(tokenChallenge);
    HITLS_AUTH_PrivPassFreeToken(tokenRequest);
    HITLS_AUTH_PrivPassFreeToken(tokenResponse);
    HITLS_AUTH_PrivPassFreeToken(tokenInstance);
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_CTX_DATA_OBTAIN_TC001
 * @spec Private Pass ctx data obtain
 * @title Test obtaining and validating ctx data obtain
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_CTX_DATA_OBTAIN_TC001(Hex *pki, Hex *nonce)
{
    uint8_t nonceBuffer[MAX_LEN];
    uint32_t nonceBufferLen = MAX_LEN;
    uint8_t truncatedTokenKeyId;
    uint8_t tokenKeyIdBuffer[MAX_LEN];
    uint32_t tokenKeyIdBufferLen = MAX_LEN;
    uint8_t hashBuffer[PRIVPASS_TOKEN_SHA256_SIZE];
    uint32_t hashBufferLen = PRIVPASS_TOKEN_SHA256_SIZE;
    HITLS_AUTH_PrivPassCtx *ctx = NULL;
    BSL_Param param[4] = {
        {AUTH_PARAM_PRIVPASS_CTX_NONCE, BSL_PARAM_TYPE_OCTETS_PTR, nonceBuffer, nonceBufferLen, 0},
        {AUTH_PARAM_PRIVPASS_CTX_TOKENKEYID, BSL_PARAM_TYPE_OCTETS_PTR, tokenKeyIdBuffer, tokenKeyIdBufferLen, 0},
        {AUTH_PARAM_PRIVPASS_CTX_TRUNCATEDTOKENKEYID, BSL_PARAM_TYPE_UINT8, &truncatedTokenKeyId, 1, 0},
        BSL_PARAM_END
    };
    ctx = HITLS_AUTH_PrivPassNewCtx(HITLS_AUTH_PRIVPASS_PUB_VERIFY_TOKENS);
    ASSERT_NE(ctx, NULL);

    ASSERT_EQ(HITLS_AUTH_PrivPassCtxCtrl(NULL, HITLS_AUTH_PRIVPASS_GET_CTX_TOKENKEYID, param, 0),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassCtxCtrl(ctx, HITLS_AUTH_PRIVPASS_GET_CTX_TOKENKEYID, NULL, 0),
        HITLS_AUTH_PRIVPASS_INVALID_INPUT);
    ASSERT_EQ(HITLS_AUTH_PrivPassCtxCtrl(ctx, HITLS_AUTH_PRIVPASS_GET_CTX_TOKENKEYID, param, 0),
        HITLS_AUTH_PRIVPASS_NO_PUBKEY_INFO);
    ASSERT_EQ(HITLS_AUTH_PrivPassCtxCtrl(ctx, HITLS_AUTH_PRIVPASS_GET_CTX_TRUNCATEDTOKENKEYID, param, 0),
        HITLS_AUTH_PRIVPASS_NO_PUBKEY_INFO);

    ASSERT_EQ(HITLS_AUTH_PrivPassSetPubkey(ctx, pki->x, pki->len), HITLS_AUTH_SUCCESS);
    (void)memcpy_s(ctx->nonce, nonce->len, nonce->x, nonce->len);
    ASSERT_EQ(HITLS_AUTH_PrivPassCtxCtrl(ctx, HITLS_AUTH_PRIVPASS_GET_CTX_NONCE, param, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassCtxCtrl(ctx, HITLS_AUTH_PRIVPASS_GET_CTX_TOKENKEYID, param, 0), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_AUTH_PrivPassCtxCtrl(ctx, HITLS_AUTH_PRIVPASS_GET_CTX_TRUNCATEDTOKENKEYID, param, 0),
        HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare ctx nonce", nonceBuffer, param[0].useLen, nonce->x, nonce->len);
    ASSERT_EQ(CRYPT_EAL_Md(CRYPT_MD_SHA256, pki->x, pki->len, hashBuffer, &hashBufferLen), HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare token key id", hashBuffer, hashBufferLen, tokenKeyIdBuffer, param[1].useLen);
    ASSERT_EQ(truncatedTokenKeyId, hashBuffer[PRIVPASS_TOKEN_SHA256_SIZE - 1]);

EXIT:
    HITLS_AUTH_PrivPassFreeCtx(ctx);
}
/* END_CASE */
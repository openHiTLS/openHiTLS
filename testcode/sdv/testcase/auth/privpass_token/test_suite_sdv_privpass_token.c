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
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "privpass_token.h"
#include "bsl_sal.h"
#include "auth_privpass_token.h"
#include "auth_errno.h"
#include "auth_params.h"
#include "crypt_util_rand.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_encode.h"
#include "crypt_errno.h"
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
    HITLS_Auth_PrivPassToken *challenge = NULL;
    HITLS_Auth_PrivPassCtx *ctx = NULL;
    ctx = HITLS_Auth_PrivPassCtxNew();
    ASSERT_NE(ctx, NULL);
    // Test deserialization
    ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(ctx, type, buffer->x, buffer->len, &challenge), HITLS_AUTH_SUCCESS);

    ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, challenge, NULL, &outputLen), HITLS_AUTH_SUCCESS);
    outputLen--;
    ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, challenge, output, &outputLen), HITLS_AUTH_BUFFER_NOT_ENOUGH);
    outputLen++;
    ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, challenge, output, &outputLen), HITLS_AUTH_SUCCESS);

    // Test serialization
    ASSERT_COMPARE("compare token", output, outputLen, buffer->x, buffer->len);

exit:
    HITLS_Auth_PrivPassTokenFree(challenge);
    HITLS_Auth_PrivPassCtxFree(ctx);
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
    HITLS_Auth_PrivPassToken *token = NULL;
    HITLS_Auth_PrivPassCtx *ctx = NULL;
    uint8_t dummyData[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    ctx = HITLS_Auth_PrivPassCtxNew();
    ASSERT_NE(ctx, NULL);

    // Test NULL parameters
    ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(NULL, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE, 
        dummyData, sizeof(dummyData), &token), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE, 
        NULL, sizeof(dummyData), &token), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE, 
        dummyData, 0, &token), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE, 
        dummyData, sizeof(dummyData), NULL), HITLS_AUTH_INVALID_INPUT);

    // Test invalid token type
    ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(ctx, 999, dummyData, 
        sizeof(dummyData), &token), HITLS_AUTH_INVALID_TOKEN_TYPE);

    // Test serialization with NULL parameters
    ASSERT_EQ(HITLS_Auth_PrivPassSerialization(NULL, token, output, &outputLen), 
        HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, NULL, output, &outputLen), 
        HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, token, NULL, &outputLen), 
        HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, token, output, NULL), 
        HITLS_AUTH_INVALID_INPUT);
exit:
    HITLS_Auth_PrivPassTokenFree(token);
    HITLS_Auth_PrivPassCtxFree(ctx);
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
    HITLS_Auth_PrivPassToken *token = NULL;
    HITLS_Auth_PrivPassCtx *ctx = HITLS_Auth_PrivPassCtxNew();
    ASSERT_NE(ctx, NULL);

    ASSERT_NE(HITLS_Auth_PrivPassDeserialization(ctx, type, buffer->x, buffer->len, &token), HITLS_AUTH_SUCCESS);
exit:
    HITLS_Auth_PrivPassTokenFree(token);
    HITLS_Auth_PrivPassCtxFree(ctx);
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
    HITLS_Auth_PrivPassCtx *ctx = HITLS_Auth_PrivPassCtxNew();
    ASSERT_NE(ctx, NULL);
    HITLS_Auth_PrivPassToken *token = NULL;
    HITLS_Auth_PrivPassToken *token2 = NULL;

    uint8_t output[MAX_LEN];
    uint32_t outputLen = MAX_LEN;
    ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(ctx, type, buffer->x, buffer->len, &token), HITLS_AUTH_SUCCESS);
    if (type == HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE) {
        token->st.tokenChallenge->tokenType = 0x0001;
        // support prv type
        ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, token, output, &outputLen), HITLS_AUTH_SUCCESS);
    }
    if (type == HITLS_AUTH_PRIVPASS_TOKEN_REQUEST) {
        token->st.tokenRequest->tokenType = 0x0001;
        // not support prv type
        ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, token, output, &outputLen), HITLS_AUTH_INVALID_TOKEN_REQUEST);
    }
    if (type == HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE) {
        ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(ctx, type, buffer->x, buffer->len - 1, &token2),
            HITLS_AUTH_INVALID_TOKEN_TYPE);
        // not support prv type
        token->st.tokenResponse->type = 0;
        ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, token, output, &outputLen), HITLS_AUTH_INVALID_TOKEN_RESPONSE);
        token->st.tokenResponse->type = 1;
    }
    if (type == HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE) {
        // not support prv type
        token->st.token->tokenType = 0;
        ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, token, output, &outputLen), HITLS_AUTH_INVALID_TOKEN_INSTANCE);
    }
exit:
    HITLS_Auth_PrivPassTokenFree(token);
    HITLS_Auth_PrivPassCtxFree(ctx);
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
    HITLS_Auth_PrivPassCtx *client = NULL;
    HITLS_Auth_PrivPassCtx *issuer = NULL;
    HITLS_Auth_PrivPassCtx *server = NULL;

    HITLS_Auth_PrivPassToken *tokenChallenge = NULL;
    HITLS_Auth_PrivPassToken *tokenChallenge2 = NULL;
    HITLS_Auth_PrivPassToken *tokenRequest = NULL;
    HITLS_Auth_PrivPassToken *tokenResponse = NULL;
    HITLS_Auth_PrivPassToken *finalToken = NULL;
    uint8_t output[MAX_LEN];
    uint32_t outputLen = MAX_LEN;
    uint16_t tokenTypeValue = tokenType->x[0] << 8 | tokenType->x[1];
    BSL_Param param[5] = {
        {AUTH_PARAM_PRIV_PASS_TOKENTYPE, BSL_PARAM_TYPE_UINT16, &tokenTypeValue, 2, 2},
        {AUTH_PARAM_PRIV_PASS_ISSUERNAME, BSL_PARAM_TYPE_OCTETS_PTR, issuerName->x, issuerName->len, issuerName->len},
        {AUTH_PARAM_PRIV_PASS_REDEMPTION, BSL_PARAM_TYPE_OCTETS_PTR, redemption->x, redemption->len, redemption->len},
        {AUTH_PARAM_PRIV_PASS_ORIGININFO, BSL_PARAM_TYPE_OCTETS_PTR, originInfo->x, originInfo->len, originInfo->len},
        BSL_PARAM_END
    };

    TestRandInit();
    // Create context
    client = HITLS_Auth_PrivPassCtxNew();
    ASSERT_NE(client, NULL);
    issuer = HITLS_Auth_PrivPassCtxNew();
    ASSERT_NE(issuer, NULL);
    server = HITLS_Auth_PrivPassCtxNew();
    ASSERT_NE(server, NULL);

    // Set keys
    ASSERT_EQ(HITLS_Auth_PrivPassSetPubkey(client, pki->x, pki->len), HITLS_AUTH_SUCCESS);
    // issuer needs pub and prv key
    ASSERT_EQ(HITLS_Auth_PrivPassSetPrvkey(issuer, ski->x, ski->len), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPubkey(issuer, pki->x, pki->len), HITLS_AUTH_SUCCESS);
    // server
    ASSERT_EQ(HITLS_Auth_PrivPassSetPubkey(server, pki->x, pki->len), HITLS_AUTH_SUCCESS);

    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenChallenge(server, param, &tokenChallenge), HITLS_AUTH_SUCCESS);

    ASSERT_EQ(HITLS_Auth_PrivPassSerialization(server, tokenChallenge, output, &outputLen), HITLS_AUTH_SUCCESS);

    ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(client, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE, output,
        outputLen, &tokenChallenge2), HITLS_AUTH_SUCCESS);

    // Generate token request
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenReq(client, tokenChallenge, &tokenRequest), HITLS_AUTH_SUCCESS);

    // Generate token response
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenResponse(issuer, tokenRequest, &tokenResponse), HITLS_AUTH_SUCCESS);

    // Generate final token
    ASSERT_EQ(HITLS_Auth_PrivPassGenToken(client, tokenChallenge, tokenResponse, &finalToken), HITLS_AUTH_SUCCESS);

    // Verify token
    ASSERT_EQ(HITLS_Auth_PrivPassVerifyToken(server, tokenChallenge, finalToken), HITLS_AUTH_SUCCESS);

exit:
    CRYPT_EAL_RandDeinit();
    HITLS_Auth_PrivPassTokenFree(tokenChallenge);
    HITLS_Auth_PrivPassTokenFree(tokenChallenge2);
    HITLS_Auth_PrivPassTokenFree(tokenRequest);
    HITLS_Auth_PrivPassTokenFree(tokenResponse);
    HITLS_Auth_PrivPassTokenFree(finalToken);
    HITLS_Auth_PrivPassCtxFree(client);
    HITLS_Auth_PrivPassCtxFree(issuer);
    HITLS_Auth_PrivPassCtxFree(server);
}
/* END_CASE */

static uint8_t *g_NonceBuf;
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
            r[i] = g_NonceBuf[i];
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
    HITLS_Auth_PrivPassCtx *ctx = NULL;
    HITLS_Auth_PrivPassToken *tokenChallenge = NULL;
    HITLS_Auth_PrivPassToken *tokenRequest = NULL;
    HITLS_Auth_PrivPassToken *tokenResponse = NULL;
    HITLS_Auth_PrivPassToken *finalToken = NULL;
    g_NonceBuf = (uint8_t *)nonce->x;
    g_saltBuf = (uint8_t *)salt->x;
    g_nonceLen = nonce->len;
    g_saltLen = salt->len;
    g_blindBuf = (uint8_t *)blind->x;
    g_blindLen = blind->len;
    BSL_Param param[2] = {
        {AUTH_PARAM_PRIV_PASS_TOKENNONCE, BSL_PARAM_TYPE_OCTETS_PTR, nonceBuff, nonceLen, 0},
        BSL_PARAM_END
    };
    CRYPT_RandRegist(STUB_ReplaceRandom);
    // Create context
    ctx = HITLS_Auth_PrivPassCtxNew();
    ASSERT_NE(ctx, NULL);
    // Set keys
    ASSERT_EQ(HITLS_Auth_PrivPassSetPubkey(ctx, pki->x, pki->len), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPrvkey(ctx, ski->x, ski->len), HITLS_AUTH_SUCCESS);

    ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE, challenge->x, challenge->len,
        &tokenChallenge), HITLS_AUTH_SUCCESS);

    ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, tokenChallenge, tokenChallengeBuffer, &tokenChallengeBufferLen),
        HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare tokenchallenge", tokenChallengeBuffer, tokenChallengeBufferLen,
        challenge->x, challenge->len);

    // Generate token request
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenReq(ctx, tokenChallenge, &tokenRequest), HITLS_AUTH_SUCCESS);

    ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, tokenRequest, tokenRequestBuffer, &tokenRequestBufferLen),
        HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare tokenrequest", tokenRequestBuffer, tokenRequestBufferLen, request->x, request->len);

    // Generate token response
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenResponse(ctx, tokenRequest, &tokenResponse), HITLS_AUTH_SUCCESS);

    ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, tokenResponse, tokenResponseBuffer, &tokenResponseBufferLen),
        HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare tokenresponse", tokenResponseBuffer, tokenResponseBufferLen, response->x, response->len);

    // Generate final token
    ASSERT_EQ(HITLS_Auth_PrivPassGenToken(ctx, tokenChallenge, tokenResponse, &finalToken), HITLS_AUTH_SUCCESS);

    ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, finalToken, finalTokenBuffer, &finalTokenBufferLen),
        HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare finaltoken", finalTokenBuffer, finalTokenBufferLen, token->x, token->len);

    // Verify token
    ASSERT_EQ(HITLS_Auth_PrivPassVerifyToken(ctx, tokenChallenge, finalToken), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassCtrl(finalToken, HITLS_AUTH_PRIVPASS_GET_TOKEN_NONCE, param, 0), HITLS_AUTH_SUCCESS);
    ASSERT_COMPARE("compare nonce", param->value, param->useLen, nonce->x, nonce->len);

exit:
    CRYPT_EAL_RandDeinit();
    HITLS_Auth_PrivPassTokenFree(tokenChallenge);
    HITLS_Auth_PrivPassTokenFree(tokenRequest);
    HITLS_Auth_PrivPassTokenFree(tokenResponse);
    HITLS_Auth_PrivPassTokenFree(finalToken);
    HITLS_Auth_PrivPassCtxFree(ctx);
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
    HITLS_Auth_PrivPassToken *tokenChallenge1 = NULL;
    HITLS_Auth_PrivPassToken *tokenChallenge2 = NULL;

    HITLS_Auth_PrivPassCtx *ctx = NULL;
    BSL_Param param[5] = {
        {AUTH_PARAM_PRIV_PASS_TOKENTYPE, BSL_PARAM_TYPE_UINT16, &tokenType, 2, 0},
        {AUTH_PARAM_PRIV_PASS_ISSUERNAME, BSL_PARAM_TYPE_OCTETS_PTR, issuerNameBuffer, issuerNameBufferLen, 0},
        {AUTH_PARAM_PRIV_PASS_REDEMPTION, BSL_PARAM_TYPE_OCTETS_PTR, redemptionBuffer, redemptionBufferLen, 0},
        {AUTH_PARAM_PRIV_PASS_ORIGININFO, BSL_PARAM_TYPE_OCTETS_PTR, originInfoBuffer, originInfoBufferLen, 0},
        BSL_PARAM_END
    };
    // Create context
    ctx = HITLS_Auth_PrivPassCtxNew();
    ASSERT_NE(ctx, NULL);

    ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE, challenge->x, challenge->len,
        &tokenChallenge1), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassCtrl(tokenChallenge1, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_TYPE, param, 0),
        HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassCtrl(tokenChallenge1, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_REDEMPTION, param, 0),
        HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassCtrl(tokenChallenge1, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_ORIGININFO, param, 0),
        HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassCtrl(tokenChallenge1, HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_ISSUERNAME, param, 0),
        HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenChallenge(ctx, param, &tokenChallenge2), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassSerialization(ctx, tokenChallenge2, tokenChallengeBuffer,
        &tokenChallengeBufferLen), HITLS_AUTH_SUCCESS);

    ASSERT_COMPARE("compare token challenge", tokenChallengeBuffer, tokenChallengeBufferLen, challenge->x,
        challenge->len);

exit:
    CRYPT_EAL_RandDeinit();
    HITLS_Auth_PrivPassTokenFree(tokenChallenge1);
    HITLS_Auth_PrivPassTokenFree(tokenChallenge2);
    HITLS_Auth_PrivPassCtxFree(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TEST_SET_CRYPTO_CB_TC001
 * @brief Test setting and validating crypto callback functionality
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TEST_SET_CRYPTO_CB_TC001(Hex *ski, Hex *pki)
{
    int32_t ret;
    TestRandInit();
    HITLS_Auth_PrivPassCtx *ctx = NULL;
    HiTLS_Auth_PrivPassCryptCb methodBk = {0};
    HiTLS_Auth_PrivPassCryptCb method = {0};
    HITLS_Auth_PrivPassToken *tokenChallenge = HITLS_Auth_PrivPassTokenNew(HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE);
    HITLS_Auth_PrivPassToken *tokenRequest = HITLS_Auth_PrivPassTokenNew(HITLS_AUTH_PRIVPASS_TOKEN_REQUEST);
    HITLS_Auth_PrivPassToken *tokenResponse = HITLS_Auth_PrivPassTokenNew(HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE);
    HITLS_Auth_PrivPassToken *finalToken = HITLS_Auth_PrivPassTokenNew(HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE);
    HITLS_Auth_PrivPassToken *tokenRequest1 = NULL;
    HITLS_Auth_PrivPassToken *tokenResponse1 = NULL;
    HITLS_Auth_PrivPassToken *finalToken1 = NULL;
    ASSERT_NE(tokenChallenge, NULL);
    ASSERT_NE(tokenRequest, NULL);
    ASSERT_NE(tokenResponse, NULL);
    ASSERT_NE(finalToken, NULL);
    ctx = HITLS_Auth_PrivPassCtxNew();
    ASSERT_NE(ctx, NULL);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPubkey(ctx, pki->x, pki->len), 0);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPrvkey(ctx, ski->x, ski->len), 0);
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenReq(ctx, tokenChallenge, &tokenRequest1), HITLS_AUTH_INVALID_TOKEN_TYPE);
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenResponse(ctx, tokenRequest, &tokenResponse1), HITLS_AUTH_INVALID_TOKEN_TYPE);
    ASSERT_EQ(HITLS_Auth_PrivPassGenToken(ctx, tokenChallenge, tokenResponse, &finalToken1),
        HITLS_AUTH_INVALID_TOKEN_TYPE);
    ASSERT_EQ(HITLS_Auth_PrivPassVerifyToken(ctx, tokenChallenge, finalToken), HITLS_AUTH_INVALID_TOKEN_TYPE);

    methodBk = ctx->method;
    ret = HITLS_Auth_PrivPassSetCryptCb(ctx, &method);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPubkey(ctx, pki->x, pki->len), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPrvkey(ctx, ski->x, ski->len), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenReq(ctx, tokenChallenge, &tokenRequest1), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenResponse(ctx, tokenRequest, &tokenResponse1), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassGenToken(ctx, tokenChallenge, tokenResponse, &finalToken1), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassVerifyToken(ctx, tokenChallenge, finalToken), HITLS_AUTH_INVALID_INPUT);
    ret = HITLS_Auth_PrivPassSetCryptCb(ctx, &methodBk);
    ASSERT_EQ(ret, 0);
exit:
    HITLS_Auth_PrivPassCtxFree(ctx);
    HITLS_Auth_PrivPassTokenFree(tokenChallenge);
    HITLS_Auth_PrivPassTokenFree(tokenRequest);
    HITLS_Auth_PrivPassTokenFree(tokenResponse);
    HITLS_Auth_PrivPassTokenFree(finalToken);
    CRYPT_EAL_RandDeinit();
}
/* END_CASE */

/**
* @test SDV_AUTH_PRIVPASS_SET_KEY_TC001
 * @brief Test case for setting public and private keys in PrivPass context
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_SET_KEY_TC001(Hex *ski, Hex *pki)
{
    HITLS_Auth_PrivPassCtx *ctx = HITLS_Auth_PrivPassCtxNew();
    ASSERT_NE(ctx, NULL);

    // Test NULL pointer parameters
    ASSERT_EQ(HITLS_Auth_PrivPassSetPubkey(NULL, pki->x, pki->len), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPubkey(ctx, NULL, pki->len), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPrvkey(NULL, ski->x, ski->len), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPrvkey(ctx, NULL, ski->len), HITLS_AUTH_INVALID_INPUT);

    // Test zero length
    ASSERT_EQ(HITLS_Auth_PrivPassSetPubkey(ctx, pki->x, 0), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPrvkey(ctx, ski->x, 0), HITLS_AUTH_INVALID_INPUT);

     // Test duplicate key setting
    ASSERT_EQ(HITLS_Auth_PrivPassSetPubkey(ctx, pki->x, pki->len), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPubkey(ctx, pki->x, pki->len), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPrvkey(ctx, ski->x, ski->len), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPrvkey(ctx, ski->x, ski->len), HITLS_AUTH_SUCCESS);

    ctx->method.checkKeyPair = NULL;
    ASSERT_EQ(HITLS_Auth_PrivPassSetPrvkey(ctx, ski->x, ski->len), HITLS_AUTH_NO_KEYPAIR_CHECK_CALLBACK);

exit:
    HITLS_Auth_PrivPassCtxFree(ctx);
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
    HITLS_Auth_PrivPassCtx *ctx = HITLS_Auth_PrivPassCtxNew();
    CRYPT_EAL_PkeyCtx *pkey1 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    CRYPT_EAL_PkeyCtx *pkey2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
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
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkey1, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &pubBuffer), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkey2, NULL, BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &prvBuffer),
        CRYPT_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPubkey(ctx, pubBuffer.data, pubBuffer.dataLen), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPrvkey(ctx, prvBuffer.data, prvBuffer.dataLen), HITLS_AUTH_CHECK_KEYPAIR_FAILED);
    HITLS_Auth_PrivPassCtxFree(ctx);
    ctx = HITLS_Auth_PrivPassCtxNew();
    ASSERT_NE(ctx, NULL);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPrvkey(ctx, prvBuffer.data, prvBuffer.dataLen), HITLS_AUTH_SUCCESS);
    ASSERT_EQ(HITLS_Auth_PrivPassSetPubkey(ctx, pubBuffer.data, pubBuffer.dataLen), HITLS_AUTH_CHECK_KEYPAIR_FAILED);

exit:
    BSL_SAL_Free(pubBuffer.data);
    BSL_SAL_Free(prvBuffer.data);
    HITLS_Auth_PrivPassCtxFree(ctx);
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    CRYPT_EAL_RandDeinit();
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
    HITLS_Auth_PrivPassCtx *ctx = NULL;
    HITLS_Auth_PrivPassToken *tokenChallenge = NULL;
    HITLS_Auth_PrivPassToken *tokenRequest = NULL;
    HITLS_Auth_PrivPassToken *tokenResponse = NULL;
    HITLS_Auth_PrivPassToken *finalToken = NULL;

    TestRandInit();
    // Test with NULL context
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenReq(NULL, tokenChallenge, &tokenRequest), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenResponse(NULL, tokenRequest, &tokenResponse), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassGenToken(NULL, tokenChallenge, tokenResponse, &finalToken), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassVerifyToken(NULL, tokenChallenge, finalToken), HITLS_AUTH_INVALID_INPUT);

    // Create context but don't set keys
    ctx = HITLS_Auth_PrivPassCtxNew();
    ASSERT_NE(ctx, NULL);

    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenReq(ctx, tokenChallenge, &tokenRequest), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenResponse(ctx, tokenRequest, &tokenResponse), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassGenToken(ctx, tokenChallenge, tokenResponse, &finalToken), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassVerifyToken(ctx, tokenChallenge, finalToken), HITLS_AUTH_INVALID_INPUT);

    // Test with NULL tokens
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenReq(ctx, NULL, &tokenRequest), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenResponse(ctx, NULL, &tokenResponse), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassGenToken(ctx, NULL, tokenResponse, &finalToken), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassVerifyToken(ctx, NULL, finalToken), HITLS_AUTH_INVALID_INPUT);
exit:
    CRYPT_EAL_RandDeinit();
    HITLS_Auth_PrivPassTokenFree(tokenChallenge);
    HITLS_Auth_PrivPassTokenFree(tokenRequest);
    HITLS_Auth_PrivPassTokenFree(tokenResponse);
    HITLS_Auth_PrivPassTokenFree(finalToken);
    HITLS_Auth_PrivPassCtxFree(ctx);
}
/* END_CASE */

/**
 * @test SDV_AUTH_PRIVPASS_TOKEN_GEN_INVALID_TC001
 * @brief Test case to verify error handling for invalid PrivPass token interactions
 */
/* BEGIN_CASE */
void SDV_AUTH_PRIVPASS_TOKEN_INVALID_INTERACTION_TC002(Hex *challenge, Hex *request, Hex *response, Hex *token)
{
    HITLS_Auth_PrivPassCtx *ctx = NULL;
    HITLS_Auth_PrivPassToken *tokenChallenge = NULL;
    HITLS_Auth_PrivPassToken *tokenRequest = NULL;
    HITLS_Auth_PrivPassToken *tokenResponse = NULL;
    HITLS_Auth_PrivPassToken *finalToken = NULL;
    HITLS_Auth_PrivPassToken *tokenRequest1 = NULL;
    HITLS_Auth_PrivPassToken *tokenResponse1 = NULL;
    HITLS_Auth_PrivPassToken *finalToken1 = NULL;

    // Create a new PrivPass context
    ctx = HITLS_Auth_PrivPassCtxNew();
    ASSERT_NE(ctx, NULL);

    ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE, challenge->x, challenge->len,
        &tokenChallenge), HITLS_AUTH_SUCCESS);

    ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_REQUEST, request->x, request->len,
        &tokenRequest), HITLS_AUTH_SUCCESS);

    ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE, response->x, response->len,
        &tokenResponse), HITLS_AUTH_SUCCESS);

    ASSERT_EQ(HITLS_Auth_PrivPassDeserialization(ctx, HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE, token->x, token->len,
        &finalToken), HITLS_AUTH_SUCCESS);

    // The entered token object does not match the expected value
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenReq(ctx, finalToken, &tokenRequest), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenResponse(ctx, finalToken, &tokenResponse), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassGenToken(ctx, tokenResponse, tokenResponse, &finalToken), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassGenToken(ctx, tokenChallenge, tokenChallenge, &finalToken), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassVerifyToken(ctx, tokenResponse, finalToken), HITLS_AUTH_INVALID_INPUT);
    // When the output != NULL
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenReq(ctx, tokenChallenge, &tokenRequest), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenResponse(ctx, tokenRequest, &tokenResponse), HITLS_AUTH_INVALID_INPUT);
    ASSERT_EQ(HITLS_Auth_PrivPassGenToken(ctx, tokenChallenge, tokenResponse, &finalToken), HITLS_AUTH_INVALID_INPUT);
    // There is no key info
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenReq(ctx, tokenChallenge, &tokenRequest1), HITLS_AUTH_NO_PUBKEY_INFO);
    ASSERT_EQ(HITLS_Auth_PrivPassGenTokenResponse(ctx, tokenRequest, &tokenResponse1), HITLS_AUTH_NO_PRVKEY_INFO);
    ASSERT_EQ(HITLS_Auth_PrivPassGenToken(ctx, tokenChallenge, tokenResponse, &finalToken1), HITLS_AUTH_NO_PUBKEY_INFO);
    ASSERT_EQ(HITLS_Auth_PrivPassVerifyToken(ctx, tokenChallenge, finalToken), HITLS_AUTH_NO_PUBKEY_INFO);

exit:
    CRYPT_EAL_RandDeinit();
    HITLS_Auth_PrivPassTokenFree(tokenChallenge);
    HITLS_Auth_PrivPassTokenFree(tokenRequest);
    HITLS_Auth_PrivPassTokenFree(tokenResponse);
    HITLS_Auth_PrivPassTokenFree(finalToken);
    HITLS_Auth_PrivPassCtxFree(ctx);
}
/* END_CASE */

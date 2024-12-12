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
#include <stdint.h>
#include "securec.h"
#include "bsl_errno.h"
#include "auth_errno.h"
#include "auth_privpass_token.h"
#include "crypt_algid.h"
#include "bsl_err_internal.h"
#include "privpass_token.h"
#include "bsl_sal.h"

// Helper functions for multi-byte encoding/decoding
void PrivPassWriteUint(uint8_t *buffer, uint32_t value, uint8_t bytes)
{
    for (int i = 0; i < bytes; i++) {
        buffer[i] = (uint8_t)(value >> ((bytes - 1 - i) * 8));
    }
}

uint32_t PrivPassReadUint(const uint8_t *buffer, uint8_t bytes)
{
    uint32_t value = 0;
    for (int i = 0; i < bytes; i++) {
        value = (value << 8) | buffer[i];
    }
    return value;
}

static int32_t DecodeTokenChallengeReq(PrivPass_TokenChallengeReq *tokenChallengeReq, const uint8_t *buffer,
    uint32_t buffLen)
{
    // Allocate memory for the new buffer
    uint8_t *data = (uint8_t *)BSL_SAL_Malloc(buffLen);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    (void)memcpy_s(data, buffLen, buffer, buffLen);
    tokenChallengeReq->challengeReq = data;
    tokenChallengeReq->challengeReqLen = buffLen;
    return HITLS_AUTH_SUCCESS;
}

static int32_t EncodeTokenChallengeReq(const PrivPass_TokenChallengeReq *tokenChallengeReq, uint8_t *buffer,
    uint32_t *buffLen)
{
    if (buffer == NULL) {
        *buffLen = tokenChallengeReq->challengeReqLen;
        return HITLS_AUTH_SUCCESS;
    }
    if (*buffLen < tokenChallengeReq->challengeReqLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_BUFFER_NOT_ENOUGH;
    }
    memcpy_s(buffer, tokenChallengeReq->challengeReqLen, tokenChallengeReq->challengeReq,
        tokenChallengeReq->challengeReqLen);
    *buffLen = tokenChallengeReq->challengeReqLen;
    return HITLS_AUTH_SUCCESS;
}

static int32_t CheckTokenType(uint16_t tokenType)
{
    if ((int32_t)tokenType != PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_TYPE);
        return HITLS_AUTH_INVALID_TOKEN_TYPE;
    }
    return HITLS_AUTH_SUCCESS;
}

static int32_t DecodeTokenChallenge(HiTLS_Auth_PrivPassCtx *ctx, PrivPass_TokenChallenge *challenge,
    const uint8_t *buffer, uint32_t buffLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    if (buffLen < 7) { // 2(tokenType) + 2(IssuerNameLen) + 1(redemptionContext) + 2(originInfoLen)
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_CHALLENGE);
        return HITLS_AUTH_INVALID_TOKEN_CHALLENGE;
    }
    int32_t ret;
    uint8_t *redemption= NULL;
    uint8_t redemptionLen= 0;
    uint8_t *issueName = NULL; 
    uint8_t *originInfo = NULL;
    uint16_t tokenType = 0;
    uint16_t issuerNameLen = 0;
    uint16_t originInfoLen = 0;
    uint32_t digestLen = PRIVPASS_TOKEN_SHA256_SIZE;
    const uint8_t *curr = buffer;
    int32_t remainLen = buffLen;
    if (ctx->method.digest == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_CRYPTO_METHOD);
        return HITLS_AUTH_INVALID_CRYPTO_METHOD;
    }
    // Read tokenType (2 bytes)
    if (remainLen < 2) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_CHALLENGE);
        return HITLS_AUTH_INVALID_TOKEN_CHALLENGE;
    }
    tokenType = (uint16_t)PrivPassReadUint(curr, 2);
    ret = CheckTokenType(tokenType);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    curr += 2;
    remainLen -= 2;

    // Read IssuerName length (2 bytes)
    if (remainLen < 2) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_BUFFER_NOT_ENOUGH;
    }
    issuerNameLen = (uint16_t)PrivPassReadUint(curr, 2);
    curr += 2;
    remainLen -= 2;

    if (remainLen < issuerNameLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_CHALLENGE);
        return HITLS_AUTH_INVALID_TOKEN_CHALLENGE;
    }

    if (issuerNameLen > 0) {
        issueName = BSL_SAL_Dump(curr, issuerNameLen);
        if (issueName == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        curr += issuerNameLen;
        remainLen -= issuerNameLen;
    }

    // Read redemptionContext (1 byte)
    if (remainLen < 1) {
        ret = HITLS_AUTH_INVALID_TOKEN_CHALLENGE;
        goto ERR;
    }
    redemptionLen = *curr;
    curr += 1;
    remainLen -= 1;
    if (remainLen < redemptionLen) {
        ret = HITLS_AUTH_INVALID_TOKEN_CHALLENGE;
        goto ERR;
    }
    if (redemptionLen > 0) { // redemption could be 0
        redemption = BSL_SAL_Dump(curr, redemptionLen);
        if (redemption == NULL) {
            ret = HITLS_AUTH_INVALID_TOKEN_CHALLENGE;
            goto ERR;
        }
        curr += redemptionLen;
        remainLen -= redemptionLen;
    }

    // deal originInfo
    if (remainLen == 0) {
        goto ERR; // no originInfo
    }
    if (remainLen == 1) {
        ret = HITLS_AUTH_INVALID_TOKEN_CHALLENGE;
        goto ERR;
    }
    originInfoLen = (uint16_t)PrivPassReadUint(curr, 2);
    curr += 2;
    remainLen -= 2;

    if (remainLen < originInfoLen) {
        ret = HITLS_AUTH_INVALID_TOKEN_CHALLENGE;
        goto ERR;
    }

    if (originInfoLen > 0) {
        originInfo = BSL_SAL_Dump(curr, originInfoLen);
        if (originInfo == NULL) {
            ret = HITLS_AUTH_INVALID_TOKEN_CHALLENGE;
            goto ERR;
        }
    }
    ret = ctx->method.digest(CRYPT_MD_SHA256, buffer, buffLen, ctx->challengeDigest, &digestLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        ret = HITLS_AUTH_INVALID_TOKEN_CHALLENGE;
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_CRYPTO_METHOD);
        goto ERR;
    }
    challenge->tokenType = tokenType;
    challenge->issuerName.data = issueName;
    challenge->issuerName.dataLen = issuerNameLen;
    challenge->originInfo.data = originInfo;
    challenge->originInfo.dataLen = originInfoLen;
    challenge->redemption.data = redemption;
    challenge->redemption.dataLen = redemptionLen;
    return HITLS_AUTH_SUCCESS;
ERR:
    BSL_SAL_FREE(issueName);
    BSL_SAL_FREE(originInfo);
    BSL_SAL_FREE(redemption);
    return ret;
}

static int32_t EncodeTokenChallenge(HiTLS_Auth_PrivPassCtx *ctx, const PrivPass_TokenChallenge *challenge,
    uint8_t *buffer, uint32_t *outBuffLen)
{
    if (ctx == NULL || ctx->method.digest == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    // Calculate total length:
    //2(tokenType) + 2(issuerNameLen) + issuerNameLen + 1(redemptionLen) + redemptionLen
    // + 2(originInfoLen) + originInfoLen
    uint32_t totalLen = 2 + 2 + challenge->issuerName.dataLen + 1 + challenge->redemption.dataLen + 2 +
        challenge->originInfo.dataLen;
    if (buffer == NULL) {
        *outBuffLen = totalLen;
        return HITLS_AUTH_SUCCESS;
    }
    if (*outBuffLen < totalLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_BUFFER_NOT_ENOUGH;
    }

    uint8_t *tmp = BSL_SAL_Malloc(totalLen);
    if (tmp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint8_t *curr = tmp;
    // Write tokenType (2 bytes)
    PrivPassWriteUint(curr, challenge->tokenType, 2);
    curr += 2;
    
    // Write IssuerName length (2 bytes) and data
    PrivPassWriteUint(curr, challenge->issuerName.dataLen, 2);
    curr += 2;
    
    if (challenge->issuerName.dataLen > 0 && challenge->issuerName.data != NULL) {
        (void)memcpy_s(curr, challenge->issuerName.dataLen, challenge->issuerName.data, 
            challenge->issuerName.dataLen);
        curr += challenge->issuerName.dataLen;
    }

    // Write redemptionContext (1 byte)
    PrivPassWriteUint(curr, challenge->redemption.dataLen, 1);
    curr += 1;
    if (challenge->redemption.dataLen > 0 && challenge->redemption.data != NULL) {
        (void)memcpy_s(curr, challenge->redemption.dataLen, challenge->redemption.data, 
            challenge->redemption.dataLen);
        curr += challenge->redemption.dataLen;
    }

    // Write originInfo length (2 bytes) and data
    PrivPassWriteUint(curr, challenge->originInfo.dataLen, 2);
    curr += 2;

    if (challenge->originInfo.dataLen > 0 && challenge->originInfo.data != NULL) {
        (void)memcpy_s(curr, challenge->originInfo.dataLen, challenge->originInfo.data,
            challenge->originInfo.dataLen);
        curr += challenge->originInfo.dataLen;
    }
    uint32_t digestLen = PRIVPASS_TOKEN_SHA256_SIZE;
    int32_t ret = ctx->method.digest(CRYPT_MD_SHA256, tmp, totalLen, ctx->challengeDigest, &digestLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_SAL_FREE(tmp);
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_CRYPTO_METHOD);
        return HITLS_AUTH_INVALID_CRYPTO_METHOD;
    }
    (void)memcpy_s(buffer, totalLen, tmp, totalLen);
    *outBuffLen = totalLen;
    BSL_SAL_FREE(tmp);
    return HITLS_AUTH_SUCCESS;
}

static uint32_t ObtainAuthenticatorLen(uint16_t tokenType)
{
    if ((int32_t)tokenType == PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        return (uint32_t)PRIVPASS_TOKEN_NK;
    }
    return 0;
}

static int32_t DecodeTokenRequest(PrivPass_TokenRequest *tokenRequest, const uint8_t *buffer, uint32_t buffLen)
{
    // Check minimum length for tokenType (2 bytes)
    if (buffLen < 2) {
        return HITLS_AUTH_BUFFER_NOT_ENOUGH;
    }

    // Decode and verify tokenType first (2 bytes, network byte order)
    uint16_t tokenType = PrivPassReadUint(buffer, 2);
    if (tokenType != PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_REQUEST);
        return HITLS_AUTH_INVALID_TOKEN_REQUEST;
    }
    uint32_t blindedMsgLen = ObtainAuthenticatorLen(tokenType);
    // Now check the complete buffer length: 2(tokenType) + 1(truncatedTokenKeyId) + blindedMsgLen
    if (buffLen < (2 + 1 + blindedMsgLen)) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_BUFFER_NOT_ENOUGH;
    }

    int32_t offset = 2;  // Skip tokenType which we've already processed

    // Decode truncatedTokenKeyId (1 byte)
    uint8_t truncatedTokenKeyId = PrivPassReadUint(buffer + offset, 1);
    offset += 1;

    // Decode blindedMsg
    uint8_t *blindedMsg = (uint8_t *)BSL_SAL_Malloc(blindedMsgLen);
    if (blindedMsg == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    (void)memcpy_s(blindedMsg, blindedMsgLen, buffer + offset, blindedMsgLen);
    tokenRequest->tokenType = tokenType;
    tokenRequest->blindedMsg.data = blindedMsg;
    tokenRequest->blindedMsg.dataLen = blindedMsgLen;
    tokenRequest->truncatedTokenKeyId = truncatedTokenKeyId;
    return HITLS_AUTH_SUCCESS;
}

static int32_t CheckTokenRequest(const PrivPass_TokenRequest *request)
{
    if (request->tokenType == PRIVPASS_PUBLIC_VERIFY_TOKENTYPE && request->blindedMsg.dataLen == PRIVPASS_TOKEN_NK) {
        return HITLS_AUTH_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_REQUEST);
    return HITLS_AUTH_INVALID_TOKEN_REQUEST;
}

static int32_t EncodeTokenRequest(const PrivPass_TokenRequest *request, uint8_t *buffer, uint32_t *outBuffLen)
{
    // Verify tokenType
    int32_t ret = CheckTokenRequest(request);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }
    uint32_t authenticatorLen = ObtainAuthenticatorLen(request->tokenType);
    // Calculate total length: 2(tokenType) + 1(truncatedTokenKeyId) + (blindedMsg)
    uint32_t totalLen = 2 + 1 + authenticatorLen;
    if (buffer == NULL) {
        *outBuffLen = totalLen;
        return HITLS_AUTH_SUCCESS;
    }
    if (*outBuffLen < totalLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_BUFFER_NOT_ENOUGH;
    }

    // Encode data
    int32_t offset = 0;
    // Encode tokenType (2 bytes, network byte order)
    PrivPassWriteUint(buffer, request->tokenType, 2);
    offset += 2;
    // Encode truncatedTokenKeyId (1 byte)
    PrivPassWriteUint(buffer + offset, request->truncatedTokenKeyId, 1);
    offset += 1;
    // Encode blindedMsg
    memcpy_s(buffer + offset, request->blindedMsg.dataLen, request->blindedMsg.data, request->blindedMsg.dataLen);
    *outBuffLen = totalLen;
    return HITLS_AUTH_SUCCESS;
}

static int32_t DecodePubTokenResp(PrivPass_TokenResponse *tokenResp, const uint8_t *buffer, uint32_t buffLen)
{
    // Allocate memory for the new buffer
    tokenResp->pubResp.blindSig = (uint8_t *)BSL_SAL_Malloc(buffLen);
    if (tokenResp->pubResp.blindSig == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    // Deep copy the buffer data
    (void)memcpy_s(tokenResp->pubResp.blindSig, buffLen, buffer, buffLen);
    tokenResp->pubResp.blindSigLen = buffLen;
    tokenResp->type = HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE_PUB;
    return HITLS_AUTH_SUCCESS;
}

static int32_t DecodeTokenResp(PrivPass_TokenResponse *tokenResp, const uint8_t *buffer, uint32_t buffLen)
{
    if (buffLen == PRIVPASS_TOKEN_NK) {
        return DecodePubTokenResp(tokenResp, buffer, buffLen);
    }
    BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_TYPE);
    return HITLS_AUTH_INVALID_TOKEN_TYPE;
}

static int32_t EncodeTokenPubResp(const PrivPass_TokenPubResponse *resp, uint8_t *buffer, uint32_t *buffLen)
{
    if (resp->blindSigLen != PRIVPASS_TOKEN_NK) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_RESPONSE);
        return HITLS_AUTH_INVALID_TOKEN_RESPONSE;
    }
    if (buffer == NULL) {
        *buffLen = resp->blindSigLen;
        return HITLS_AUTH_SUCCESS;
    }
    // Check buffer length
    if (*buffLen < resp->blindSigLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_BUFFER_NOT_ENOUGH;
    }

    // Copy token data to buffer
    (void)memcpy_s(buffer, resp->blindSigLen, resp->blindSig, resp->blindSigLen);
    *buffLen = resp->blindSigLen;
    return HITLS_AUTH_SUCCESS;
}

static int32_t EncodeTokenResp(const PrivPass_TokenResponse *resp, uint8_t *buffer, uint32_t *buffLen)
{
    if (resp->type == HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE_PUB) {
        return EncodeTokenPubResp(&resp->pubResp, buffer, buffLen);
    }
    BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_RESPONSE);
    return HITLS_AUTH_INVALID_TOKEN_RESPONSE;
}

static int32_t CheckToken(const PrivPass_TokenInstance *token)
{
    if (token->tokenType == PRIVPASS_PUBLIC_VERIFY_TOKENTYPE && token->authenticator.dataLen == PRIVPASS_TOKEN_NK) {
        return HITLS_AUTH_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_INSTANCE);
    return HITLS_AUTH_INVALID_TOKEN_INSTANCE;
}

static int32_t EncodeToken(const PrivPass_TokenInstance *token, uint8_t *buffer, uint32_t *outBuffLen)
{
    // Verify tokenType
    int32_t ret = CheckToken(token);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }
    // Calculate total length: 2(tokenType) + 32(nonce) + 32(challengeDigest) + 32(tokenKeyId) + authenticatorLen
    uint32_t totalLen = 2 + PRIVPASS_TOKEN_SHA256_SIZE + PRIVPASS_TOKEN_SHA256_SIZE + PRIVPASS_TOKEN_SHA256_SIZE +
        token->authenticator.dataLen;
    if (buffer == NULL) {
        *outBuffLen = totalLen;
        return HITLS_AUTH_SUCCESS;
    }
    if (*outBuffLen < totalLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_BUFFER_NOT_ENOUGH;
    }

    int32_t offset = 0;

    // Encode tokenType (network byte order)
    PrivPassWriteUint(buffer, token->tokenType, 2);
    offset += 2;
    // Encode nonce
    (void)memcpy_s(buffer + offset, PRIVPASS_TOKEN_SHA256_SIZE, token->nonce, PRIVPASS_TOKEN_SHA256_SIZE);
    offset += PRIVPASS_TOKEN_SHA256_SIZE;

    // Encode challengeDigest
    (void)memcpy_s(buffer + offset, PRIVPASS_TOKEN_SHA256_SIZE, token->challengeDigest, PRIVPASS_TOKEN_SHA256_SIZE);
    offset += PRIVPASS_TOKEN_SHA256_SIZE;

    // Encode tokenKeyId
    (void)memcpy_s(buffer + offset, PRIVPASS_TOKEN_SHA256_SIZE, token->tokenKeyId, PRIVPASS_TOKEN_SHA256_SIZE);
    offset += PRIVPASS_TOKEN_SHA256_SIZE;

    // Encode authenticator
    (void)memcpy_s(buffer + offset, token->authenticator.dataLen, token->authenticator.data,
        token->authenticator.dataLen);

    *outBuffLen = totalLen;
    return HITLS_AUTH_SUCCESS;
}

static int32_t DecodeToken(PrivPass_TokenInstance *token, const uint8_t *buffer, uint32_t buffLen)
{
    // First check if there are enough bytes to read tokenType
    if (buffLen < 2) {
        return HITLS_AUTH_BUFFER_NOT_ENOUGH;
    }

    // Decode and verify tokenType first (network byte order)
    uint16_t tokenType = PrivPassReadUint(buffer, 2);
    if (tokenType != PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_TYPE);
        return HITLS_AUTH_INVALID_TOKEN_TYPE;
    }
    token->tokenType = tokenType;
    uint32_t authenticatorLen = ObtainAuthenticatorLen(tokenType);
    // Calculate total length: 2(tokenType) + 32(nonce) + 32(challengeDigest) + 32(tokenKeyId) + authenticatorLen
    if (buffLen < 2 + PRIVPASS_TOKEN_SHA256_SIZE + PRIVPASS_TOKEN_SHA256_SIZE + PRIVPASS_TOKEN_SHA256_SIZE
        + authenticatorLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_BUFFER_NOT_ENOUGH;
    }

    int32_t offset = 2; // Skip tokenType which we've already read
    // Decode nonce
    (void)memcpy_s(token->nonce, PRIVPASS_TOKEN_SHA256_SIZE, buffer + offset, PRIVPASS_TOKEN_SHA256_SIZE);
    offset += PRIVPASS_TOKEN_SHA256_SIZE;

    // Decode challengeDigest
    (void)memcpy_s(token->challengeDigest, PRIVPASS_TOKEN_SHA256_SIZE , buffer + offset, PRIVPASS_TOKEN_SHA256_SIZE);
    offset += PRIVPASS_TOKEN_SHA256_SIZE;

    // Decode tokenKeyId
    (void)memcpy_s(token->tokenKeyId, PRIVPASS_TOKEN_SHA256_SIZE, buffer + offset, PRIVPASS_TOKEN_SHA256_SIZE);
    offset += PRIVPASS_TOKEN_SHA256_SIZE;

    // Decode authenticator
    token->authenticator.data = (uint8_t *)BSL_SAL_Malloc(authenticatorLen);
    if (token->authenticator.data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    (void)memcpy_s(token->authenticator.data, authenticatorLen, buffer + offset, authenticatorLen);
    token->authenticator.dataLen = authenticatorLen;
    return HITLS_AUTH_SUCCESS;
}

static int32_t CheckDeserializationInput(int32_t tokenType, const uint8_t *buffer, uint32_t outBuffLen,
    HiTLS_Auth_PrivPassToken **object)
{
    if (buffer == NULL || outBuffLen == 0 || object == NULL || *object != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    switch (tokenType) {
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE_REQUEST:
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE:
        case HITLS_AUTH_PRIVPASS_TOKEN_REQUEST:
        case HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE:
        case HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE:
            return HITLS_AUTH_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_TYPE);
            return HITLS_AUTH_INVALID_TOKEN_TYPE;
    }
}

int32_t HiTLS_Auth_PrivPassDeserialization(HiTLS_Auth_PrivPassCtx *ctx, int32_t tokenType, const uint8_t *buffer,
    uint32_t outBuffLen, HiTLS_Auth_PrivPassToken **object)
{
    int32_t ret = CheckDeserializationInput(tokenType, buffer, outBuffLen, object);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }
    // Allocate the token object
    HiTLS_Auth_PrivPassToken *output = HiTLS_Auth_PrivPassTokenNew(tokenType);
    if (output == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    switch (tokenType) {
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE_REQUEST:
            ret = DecodeTokenChallengeReq(output->st.tokenChallengeReq, buffer, outBuffLen);
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE:
            ret = DecodeTokenChallenge(ctx, output->st.tokenChallenge, buffer, outBuffLen);
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_REQUEST:
            ret = DecodeTokenRequest(output->st.tokenRequest, buffer, outBuffLen);
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE:
            ret = DecodeTokenResp(output->st.tokenResponse, buffer, outBuffLen);
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE:
            ret = DecodeToken(output->st.token, buffer, outBuffLen);
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_TYPE);
            ret = HITLS_AUTH_INVALID_TOKEN_TYPE;
            break;
    }

    if (ret != HITLS_AUTH_SUCCESS) {
        HiTLS_Auth_PrivPassTokenFree(output);
        return ret;
    }

    *object = output;
    return HITLS_AUTH_SUCCESS;
}

int32_t HiTLS_Auth_PrivPassSerialization(HiTLS_Auth_PrivPassCtx *ctx, HiTLS_Auth_PrivPassToken *object,
    uint8_t *buffer, uint32_t *outBuffLen)
{
    if (object == NULL || outBuffLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    switch (object->type) {
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE_REQUEST:
            return EncodeTokenChallengeReq(object->st.tokenChallengeReq, buffer, outBuffLen);
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE:
            return EncodeTokenChallenge(ctx, object->st.tokenChallenge, buffer, outBuffLen);
        case HITLS_AUTH_PRIVPASS_TOKEN_REQUEST:
            return EncodeTokenRequest(object->st.tokenRequest, buffer, outBuffLen);
        case HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE:
            return EncodeTokenResp(object->st.tokenResponse, buffer, outBuffLen);
        case HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE:
            return EncodeToken(object->st.token, buffer, outBuffLen);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_TYPE);
            return HITLS_AUTH_INVALID_TOKEN_TYPE;
    }
}

HiTLS_Auth_PrivPassToken *HiTLS_Auth_PrivPassTokenNew(int32_t tokenType)
{
    HiTLS_Auth_PrivPassToken *object = (HiTLS_Auth_PrivPassToken *)BSL_SAL_Calloc(1u, sizeof(HiTLS_Auth_PrivPassToken));
    if (object == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    switch (tokenType) {
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE_REQUEST:
            object->st.tokenChallengeReq = (PrivPass_TokenChallengeReq *)BSL_SAL_Calloc(1u,
                sizeof(PrivPass_TokenChallengeReq));
            if (object->st.tokenChallengeReq == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                BSL_SAL_Free(object);
                return NULL;
            }
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE:
            object->st.tokenChallenge = (PrivPass_TokenChallenge *)BSL_SAL_Calloc(1u, sizeof(PrivPass_TokenChallenge));
            if (object->st.tokenChallenge == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                BSL_SAL_Free(object);
                return NULL;
            }
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_REQUEST:
            object->st.tokenRequest = (PrivPass_TokenRequest *)BSL_SAL_Calloc(1u, sizeof(PrivPass_TokenRequest));
            if (object->st.tokenRequest == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                BSL_SAL_Free(object);
                return NULL;
            }
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE:
            object->st.tokenResponse = (PrivPass_TokenResponse *)BSL_SAL_Calloc(1u, sizeof(PrivPass_TokenResponse));
            if (object->st.tokenResponse == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                BSL_SAL_Free(object);
                return NULL;
            }
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE:
            object->st.token = (PrivPass_TokenInstance *)BSL_SAL_Calloc(1u, sizeof(PrivPass_TokenInstance));
            if (object->st.token == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                BSL_SAL_Free(object);
                return NULL;
            }
            break;
        default:
            BSL_SAL_Free(object);
            return NULL;
    }
    object->type = tokenType;
    return object;
}

static void FreeTokenChallengeReq(PrivPass_TokenChallengeReq *challengeReq)
{
    if (challengeReq == NULL) {
        return;
    }
    BSL_SAL_FREE(challengeReq->challengeReq);
    BSL_SAL_FREE(challengeReq);
}

static void FreeTokenChallenge(PrivPass_TokenChallenge *challenge)
{
    if (challenge == NULL) {
        return;
    }
    BSL_SAL_FREE(challenge->issuerName.data);
    BSL_SAL_FREE(challenge->originInfo.data);
    BSL_SAL_FREE(challenge->redemption.data);
    BSL_SAL_FREE(challenge);
}

static void FreeTokenResponse(PrivPass_TokenResponse *response)
{
    if (response == NULL) {
        return;
    }
    if (response->type == HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE_PUB) {
        BSL_SAL_FREE(response->pubResp.blindSig);
    }
    BSL_SAL_FREE(response);
}


static void FreeTokenRequest(PrivPass_TokenRequest *request)
{
    if (request == NULL) {
        return;
    }
    BSL_SAL_FREE(request->blindedMsg.data);
    BSL_SAL_FREE(request);
}

static void FreeToken(PrivPass_TokenInstance *token)
{
    if (token == NULL) {
        return;
    }
    BSL_SAL_FREE(token->authenticator.data);
    BSL_SAL_FREE(token);
}

void HiTLS_Auth_PrivPassTokenFree(HiTLS_Auth_PrivPassToken *object)
{
    if (object == NULL) {
        return;
    }
    switch (object->type) {
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE_REQUEST:
            FreeTokenChallengeReq(object->st.tokenChallengeReq);
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE:
            FreeTokenChallenge(object->st.tokenChallenge);
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_REQUEST:
            FreeTokenRequest(object->st.tokenRequest);
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE:
            FreeTokenResponse(object->st.tokenResponse);
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE:
            FreeToken(object->st.token);
            break;
        default:
            break;
    }
    BSL_SAL_Free(object);
}

HiTLS_Auth_PrivPassCtx *HiTLS_Auth_PrivPassCtxNew(void)
{
    HiTLS_Auth_PrivPassCtx *ctx = (HiTLS_Auth_PrivPassCtx *)BSL_SAL_Calloc(1u, sizeof(HiTLS_Auth_PrivPassCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    ctx->method = PrivPassCryptDefaultCb();
    return ctx;
}

void HiTLS_Auth_PrivPassCtxFree(HiTLS_Auth_PrivPassCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->method.freePkeyCtx != NULL) {
        if (ctx->prvKeyCtx != NULL) {
            ctx->method.freePkeyCtx(ctx->prvKeyCtx);
        }
        if (ctx->pubKeyCtx != NULL) {
            ctx->method.freePkeyCtx(ctx->pubKeyCtx);
        }
    }
    BSL_SAL_Free(ctx);
}

int32_t HiTLS_Auth_PrivPassSetCryptCb(HiTLS_Auth_PrivPassCtx *ctx, HiTLS_Auth_PrivPassCryptCb *cryptCb)
{
    if (ctx == NULL || cryptCb == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    ctx->method.blind = cryptCb->blind;
    ctx->method.unblind = cryptCb->unblind;
    ctx->method.signData = cryptCb->signData;
    ctx->method.verify = cryptCb->verify;
    ctx->method.decodePubKey = cryptCb->decodePubKey;
    ctx->method.decodePrvKey = cryptCb->decodePrvKey;
    ctx->method.checkKeyPair = cryptCb->checkKeyPair;
    ctx->method.digest = cryptCb->digest;
    ctx->method.newPkeyCtx = cryptCb->newPkeyCtx;
    ctx->method.freePkeyCtx = cryptCb->freePkeyCtx;
    return HITLS_AUTH_SUCCESS;
}
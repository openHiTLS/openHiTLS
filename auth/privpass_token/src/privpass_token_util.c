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
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "privpass_token.h"

static int32_t DecodeTokenChallengeReq(PrivPass_TokenChallengeReq *tokenChallengeReq, const uint8_t *buffer,
    uint32_t buffLen)
{
    // Allocate memory for the new buffer
    uint8_t *data = (uint8_t *)BSL_SAL_Dump(buffer, buffLen);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    tokenChallengeReq->challengeReq = data;
    tokenChallengeReq->challengeReqLen = buffLen;
    return HITLS_AUTH_SUCCESS;
}

static int32_t EncodeTokenChallengeReq(const PrivPass_TokenChallengeReq *tokenChallengeReq, uint8_t *buffer,
    uint32_t *buffLen)
{
    if (tokenChallengeReq->challengeReqLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE_REQ);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE_REQ;
    }
    if (buffer == NULL) {
        *buffLen = tokenChallengeReq->challengeReqLen;
        return HITLS_AUTH_SUCCESS;
    }
    if (*buffLen < tokenChallengeReq->challengeReqLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH;
    }
    (void)memcpy_s(buffer, tokenChallengeReq->challengeReqLen, tokenChallengeReq->challengeReq,
        tokenChallengeReq->challengeReqLen);
    *buffLen = tokenChallengeReq->challengeReqLen;
    return HITLS_AUTH_SUCCESS;
}

static int32_t ValidateInitialParams(HITLS_AUTH_PrivPassCtx *ctx, uint32_t remainLen)
{
    (void)ctx;
    // MinLength: tokenType(2) + issuerNameLen(2) + redemptionLen(1) + originInfoLen(2)
    if (remainLen < 2 + 2 + 1 + 2) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE;
    }
    return HITLS_AUTH_SUCCESS;
}

static int32_t DecodeTokenTypeAndValidate(const uint8_t **curr, uint32_t *remainLen, uint16_t *tokenType)
{
    *tokenType = BSL_ByteToUint16(*curr);
    if (*tokenType != PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE;
    }
    *curr += 2; // offset 2 bytes.
    *remainLen -= 2;
    return HITLS_AUTH_SUCCESS;
}

static int32_t DecodeIssuerName(uint8_t **issueName, uint16_t *issuerNameLen, const uint8_t **curr, uint32_t *remainLen)
{
    *issuerNameLen = BSL_ByteToUint16(*curr);
    *curr += 2; // offset 2 bytes.
    *remainLen -= 2;

    if (*remainLen < *issuerNameLen || *issuerNameLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE;
    }

    *issueName = BSL_SAL_Dump(*curr, *issuerNameLen);
    if (*issueName == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }

    *curr += *issuerNameLen;
    *remainLen -= *issuerNameLen;
    return HITLS_AUTH_SUCCESS;
}

static int32_t DecodeRedemption(uint8_t **redemption, uint8_t *redemptionLen, const uint8_t **curr, uint32_t *remainLen)
{
    if (*remainLen < 1) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE;
    }

    *redemptionLen = **curr;
    *curr += 1;
    *remainLen -= 1;

    if (*remainLen < *redemptionLen || (*redemptionLen != PRIVPASS_REDEMPTION_LEN && *redemptionLen != 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE;
    }

    if (*redemptionLen != 0) {
        *redemption = BSL_SAL_Dump(*curr, *redemptionLen);
        if (*redemption == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        *curr += *redemptionLen;
        *remainLen -= *redemptionLen;
    }
    return HITLS_AUTH_SUCCESS;
}

static int32_t DecodeOriginInfo(uint8_t **originInfo, uint16_t *originInfoLen, const uint8_t **curr,
    uint32_t *remainLen)
{
    if (*remainLen < 2) { // len needs 2 bytes to store.
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE;
    }

    *originInfoLen = BSL_ByteToUint16(*curr);
    *curr += 2; // offset 2 bytes.
    *remainLen -= 2;
    if (*remainLen != *originInfoLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE;
    }

    if (*originInfoLen > 0) {
        *originInfo = BSL_SAL_Dump(*curr, *originInfoLen);
        if (*originInfo == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE);
            return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE;
        }
    }
    return HITLS_AUTH_SUCCESS;
}

static int32_t DecodeTokenChallenge(HITLS_AUTH_PrivPassCtx *ctx, PrivPass_TokenChallenge *challenge,
    const uint8_t *buffer, uint32_t buffLen)
{
    int32_t ret = ValidateInitialParams(ctx, buffLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }

    const uint8_t *curr = buffer;
    uint32_t remainLen = buffLen;
    uint8_t *redemption = NULL;
    uint8_t *issueName = NULL;
    uint8_t *originInfo = NULL;
    uint8_t redemptionLen = 0;
    uint16_t issuerNameLen = 0;
    uint16_t originInfoLen = 0;
    uint16_t tokenType = 0;
    // Decode each component
    ret = DecodeTokenTypeAndValidate(&curr, &remainLen, &tokenType);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = DecodeIssuerName(&issueName, &issuerNameLen, &curr, &remainLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = DecodeRedemption(&redemption, &redemptionLen, &curr, &remainLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    ret = DecodeOriginInfo(&originInfo, &originInfoLen, &curr, &remainLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        goto ERR;
    }
    // Set challenge fields
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

static int32_t CheckTokenChallengeParam(HITLS_AUTH_PrivPassCtx *ctx, const PrivPass_TokenChallenge *challenge)
{
    (void)ctx;
    if (challenge->issuerName.dataLen == 0 || challenge->issuerName.dataLen > PRIVPASS_MAX_ISSUER_NAME_LEN ||
        challenge->originInfo.dataLen > PRIVPASS_MAX_ORIGIN_INFO_LEN ||
        (challenge->redemption.dataLen != 0 && challenge->redemption.dataLen != PRIVPASS_REDEMPTION_LEN)) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE;
    }
    return HITLS_AUTH_SUCCESS;
}

static int32_t EncodeTokenChallenge(HITLS_AUTH_PrivPassCtx *ctx, const PrivPass_TokenChallenge *challenge,
    uint8_t *buffer, uint32_t *outBuffLen)
{
    int32_t ret = CheckTokenChallengeParam(ctx, challenge);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }
    // 2(tokenType) + 2(issuerNameLen) + issuerName + 1(redemptionLen) + redemption + 2(originInfoLen) + originInfo
    uint64_t totalLen = 2 + 2 + challenge->issuerName.dataLen + 1 + challenge->redemption.dataLen + 2 +
        (uint64_t)challenge->originInfo.dataLen;
    if (totalLen > UINT32_MAX) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE;
    }
    if (buffer == NULL) {
        *outBuffLen = (uint32_t)totalLen;
        return HITLS_AUTH_SUCCESS;
    }
    if (*outBuffLen < (uint32_t)totalLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH;
    }

    uint8_t *curr = buffer;
    BSL_Uint16ToByte(challenge->tokenType, curr); // Write tokenType (2 bytes)
    BSL_Uint16ToByte(challenge->issuerName.dataLen, curr + 2); // Write IssuerName length (2 bytes) and data
    curr += 4; // offset 4 bytes.

    if (challenge->issuerName.dataLen > 0 && challenge->issuerName.data != NULL) {
        (void)memcpy_s(curr, challenge->issuerName.dataLen, challenge->issuerName.data,
            challenge->issuerName.dataLen);
        curr += challenge->issuerName.dataLen;
    }

    // Write redemptionContext (1 byte)
    *curr++ = challenge->redemption.dataLen;
    if (challenge->redemption.dataLen > 0 && challenge->redemption.data != NULL) {
        (void)memcpy_s(curr, challenge->redemption.dataLen, challenge->redemption.data,
            challenge->redemption.dataLen);
        curr += challenge->redemption.dataLen;
    }

    // Write originInfo length (2 bytes) and data
    BSL_Uint16ToByte(challenge->originInfo.dataLen, curr);
    curr += 2; // offset 2 bytes.
    if (challenge->originInfo.dataLen > 0 && challenge->originInfo.data != NULL) {
        (void)memcpy_s(curr, challenge->originInfo.dataLen, challenge->originInfo.data,
            challenge->originInfo.dataLen);
    }
    *outBuffLen = (uint32_t)totalLen;
    return HITLS_AUTH_SUCCESS;
}

static uint32_t ObtainAuthenticatorLen(uint16_t tokenType)
{
    if (tokenType == PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        return (uint32_t)PRIVPASS_TOKEN_NK;
    }
    return 0;
}

static int32_t DecodeTokenRequest(PrivPass_TokenRequest *tokenRequest, const uint8_t *buffer, uint32_t buffLen)
{
    // Check minimum length for tokenType (2 bytes)
    if (buffLen < 2) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH;
    }

    // Decode and verify tokenType first (2 bytes, network byte order)
    uint16_t tokenType = BSL_ByteToUint16(buffer);
    if (tokenType != PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_REQUEST);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_REQUEST;
    }
    uint32_t blindedMsgLen = ObtainAuthenticatorLen(tokenType);
    // Now check the complete buffer length: 2(tokenType) + 1(truncatedTokenKeyId) + blindedMsgLen
    if (buffLen != (2 + 1 + blindedMsgLen)) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH;
    }

    int32_t offset = 2;  // Skip tokenType which we've already processed
    // Decode truncatedTokenKeyId (1 byte)
    uint8_t truncatedTokenKeyId = buffer[offset];
    offset += 1;

    // Decode blindedMsg
    uint8_t *blindedMsg = (uint8_t *)BSL_SAL_Dump(buffer + offset, blindedMsgLen);
    if (blindedMsg == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    tokenRequest->tokenType = tokenType;
    tokenRequest->blindedMsg.data = blindedMsg;
    tokenRequest->blindedMsg.dataLen = blindedMsgLen;
    tokenRequest->truncatedTokenKeyId = truncatedTokenKeyId;
    return HITLS_AUTH_SUCCESS;
}

static int32_t CheckTokenRequest(const PrivPass_TokenRequest *request)
{
    if (request->tokenType == PRIVPASS_PUBLIC_VERIFY_TOKENTYPE &&
        (request->blindedMsg.data != NULL && request->blindedMsg.dataLen == PRIVPASS_TOKEN_NK)) {
        return HITLS_AUTH_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_REQUEST);
    return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_REQUEST;
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
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH;
    }

    // Encode data
    int32_t offset = 0;
    // Encode tokenType (2 bytes, network byte order)
    BSL_Uint16ToByte(request->tokenType, buffer);
    offset += 2; // offset 2 bytes.
    // Encode truncatedTokenKeyId (1 byte)
    buffer[offset] = request->truncatedTokenKeyId;
    offset += 1;
    // Encode blindedMsg
    (void)memcpy_s(buffer + offset, authenticatorLen, request->blindedMsg.data, authenticatorLen);
    *outBuffLen = totalLen;
    return HITLS_AUTH_SUCCESS;
}

static int32_t DecodePubTokenResp(PrivPass_TokenResponse *tokenResp, const uint8_t *buffer, uint32_t buffLen)
{
    // Allocate memory for the new buffer
    tokenResp->st.pubResp.blindSig = (uint8_t *)BSL_SAL_Dump(buffer, buffLen);
    if (tokenResp->st.pubResp.blindSig == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }

    tokenResp->st.pubResp.blindSigLen = buffLen;
    tokenResp->type = HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE_PUB;
    return HITLS_AUTH_SUCCESS;
}

static int32_t DecodeTokenResp(PrivPass_TokenResponse *tokenResp, const uint8_t *buffer, uint32_t buffLen)
{
    if (buffLen == PRIVPASS_TOKEN_NK) {
        return DecodePubTokenResp(tokenResp, buffer, buffLen);
    }
    BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
    return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE;
}

static int32_t EncodeTokenPubResp(const PrivPass_TokenPubResponse *resp, uint8_t *buffer, uint32_t *buffLen)
{
    if (resp->blindSig == NULL || resp->blindSigLen != PRIVPASS_TOKEN_NK) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_RESPONSE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_RESPONSE;
    }
    if (buffer == NULL) {
        *buffLen = resp->blindSigLen;
        return HITLS_AUTH_SUCCESS;
    }
    // Check buffer length
    if (*buffLen < resp->blindSigLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH;
    }

    // Copy token data to buffer
    (void)memcpy_s(buffer, resp->blindSigLen, resp->blindSig, resp->blindSigLen);
    *buffLen = resp->blindSigLen;
    return HITLS_AUTH_SUCCESS;
}

static int32_t EncodeTokenResp(const PrivPass_TokenResponse *resp, uint8_t *buffer, uint32_t *buffLen)
{
    if (resp->type == HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE_PUB) {
        return EncodeTokenPubResp(&resp->st.pubResp, buffer, buffLen);
    }
    BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_RESPONSE);
    return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_RESPONSE;
}

static int32_t CheckToken(const PrivPass_TokenInstance *token)
{
    if (token->tokenType == PRIVPASS_PUBLIC_VERIFY_TOKENTYPE &&
        (token->authenticator.data != NULL && token->authenticator.dataLen == PRIVPASS_TOKEN_NK)) {
        return HITLS_AUTH_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_INSTANCE);
    return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_INSTANCE;
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
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH;
    }

    int32_t offset = 0;

    // Encode tokenType (network byte order)
    BSL_Uint16ToByte(token->tokenType, buffer);
    offset += 2; // offset 2 bytes.
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
    // First check if there are enough bytes to read tokenType(2 bytes).
    if (buffLen < 2) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH;
    }

    // Decode and verify tokenType first (network byte order)
    uint16_t tokenType = BSL_ByteToUint16(buffer);
    if (tokenType != PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE;
    }
    token->tokenType = tokenType;
    uint32_t authenticatorLen = ObtainAuthenticatorLen(tokenType);
    // Calculate total length: 2(tokenType) + 32(nonce) + 32(challengeDigest) + 32(tokenKeyId) + authenticatorLen
    if (buffLen != (2 + PRIVPASS_TOKEN_SHA256_SIZE + PRIVPASS_TOKEN_SHA256_SIZE + PRIVPASS_TOKEN_SHA256_SIZE +
        authenticatorLen)) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH);
        return HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH;
    }

    int32_t offset = 2; // Skip tokenType which we've already read
    // Decode nonce
    (void)memcpy_s(token->nonce, PRIVPASS_TOKEN_SHA256_SIZE, buffer + offset, PRIVPASS_TOKEN_SHA256_SIZE);
    offset += PRIVPASS_TOKEN_SHA256_SIZE;

    // Decode challengeDigest
    (void)memcpy_s(token->challengeDigest, PRIVPASS_TOKEN_SHA256_SIZE, buffer + offset, PRIVPASS_TOKEN_SHA256_SIZE);
    offset += PRIVPASS_TOKEN_SHA256_SIZE;

    // Decode tokenKeyId
    (void)memcpy_s(token->tokenKeyId, PRIVPASS_TOKEN_SHA256_SIZE, buffer + offset, PRIVPASS_TOKEN_SHA256_SIZE);
    offset += PRIVPASS_TOKEN_SHA256_SIZE;

    // Decode authenticator
    token->authenticator.data = (uint8_t *)BSL_SAL_Dump(buffer + offset, authenticatorLen);
    if (token->authenticator.data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    token->authenticator.dataLen = authenticatorLen;
    return HITLS_AUTH_SUCCESS;
}

static int32_t CheckDeserializationInput(int32_t tokenType, const uint8_t *buffer, uint32_t buffLen,
    HITLS_AUTH_PrivPassToken **object)
{
    if (buffer == NULL || buffLen == 0 || object == NULL || *object != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    switch (tokenType) {
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE_REQUEST:
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE:
        case HITLS_AUTH_PRIVPASS_TOKEN_REQUEST:
        case HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE:
        case HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE:
            return HITLS_AUTH_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
            return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE;
    }
}

int32_t HITLS_AUTH_PrivPassDeserialization(HITLS_AUTH_PrivPassCtx *ctx, int32_t tokenType, const uint8_t *buffer,
    uint32_t buffLen, HITLS_AUTH_PrivPassToken **object)
{
    int32_t ret = CheckDeserializationInput(tokenType, buffer, buffLen, object);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }
    // Allocate the token object
    HITLS_AUTH_PrivPassToken *output = HITLS_AUTH_PrivPassNewToken(tokenType);
    if (output == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    switch (tokenType) {
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE_REQUEST:
            ret = DecodeTokenChallengeReq(output->st.tokenChallengeReq, buffer, buffLen);
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE:
            ret = DecodeTokenChallenge(ctx, output->st.tokenChallenge, buffer, buffLen);
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_REQUEST:
            ret = DecodeTokenRequest(output->st.tokenRequest, buffer, buffLen);
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE:
            ret = DecodeTokenResp(output->st.tokenResponse, buffer, buffLen);
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE:
            ret = DecodeToken(output->st.token, buffer, buffLen);
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
            ret = HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE;
            break;
    }

    if (ret != HITLS_AUTH_SUCCESS) {
        HITLS_AUTH_PrivPassFreeToken(output);
        return ret;
    }

    *object = output;
    return HITLS_AUTH_SUCCESS;
}

int32_t HITLS_AUTH_PrivPassSerialization(HITLS_AUTH_PrivPassCtx *ctx, const HITLS_AUTH_PrivPassToken *object,
    uint8_t *buffer, uint32_t *outBuffLen)
{
    if (object == NULL || outBuffLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
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
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
            return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE;
    }
}

HITLS_AUTH_PrivPassToken *HITLS_AUTH_PrivPassNewToken(int32_t tokenType)
{
    HITLS_AUTH_PrivPassToken *object = (HITLS_AUTH_PrivPassToken *)BSL_SAL_Calloc(1u, sizeof(HITLS_AUTH_PrivPassToken));
    if (object == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    switch (tokenType) {
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE_REQUEST:
            object->st.tokenChallengeReq = (PrivPass_TokenChallengeReq *)BSL_SAL_Calloc(1u,
                sizeof(PrivPass_TokenChallengeReq));
            if (object->st.tokenChallengeReq == NULL) {
                goto ERR;
            }
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE:
            object->st.tokenChallenge = (PrivPass_TokenChallenge *)BSL_SAL_Calloc(1u, sizeof(PrivPass_TokenChallenge));
            if (object->st.tokenChallenge == NULL) {
                goto ERR;
            }
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_REQUEST:
            object->st.tokenRequest = (PrivPass_TokenRequest *)BSL_SAL_Calloc(1u, sizeof(PrivPass_TokenRequest));
            if (object->st.tokenRequest == NULL) {
                goto ERR;
            }
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE:
            object->st.tokenResponse = (PrivPass_TokenResponse *)BSL_SAL_Calloc(1u, sizeof(PrivPass_TokenResponse));
            if (object->st.tokenResponse == NULL) {
                goto ERR;
            }
            break;
        case HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE:
            object->st.token = (PrivPass_TokenInstance *)BSL_SAL_Calloc(1u, sizeof(PrivPass_TokenInstance));
            if (object->st.token == NULL) {
                goto ERR;
            }
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
            BSL_SAL_Free(object);
            return NULL;
    }
    object->type = tokenType;
    return object;
ERR:
    BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
    BSL_SAL_Free(object);
    return NULL;
}

static void FreeTokenChallengeReq(PrivPass_TokenChallengeReq *challengeReq)
{
    if (challengeReq == NULL) {
        return;
    }
    BSL_SAL_FREE(challengeReq->challengeReq);
    BSL_SAL_Free(challengeReq);
}

static void FreeTokenChallenge(PrivPass_TokenChallenge *challenge)
{
    if (challenge == NULL) {
        return;
    }
    BSL_SAL_FREE(challenge->issuerName.data);
    BSL_SAL_FREE(challenge->originInfo.data);
    BSL_SAL_FREE(challenge->redemption.data);
    BSL_SAL_Free(challenge);
}

static void FreeTokenResponse(PrivPass_TokenResponse *response)
{
    if (response == NULL) {
        return;
    }
    if (response->type == HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE_PUB) {
        BSL_SAL_FREE(response->st.pubResp.blindSig);
    }
    BSL_SAL_Free(response);
}

static void FreeTokenRequest(PrivPass_TokenRequest *request)
{
    if (request == NULL) {
        return;
    }
    BSL_SAL_FREE(request->blindedMsg.data);
    BSL_SAL_Free(request);
}

static void FreeToken(PrivPass_TokenInstance *token)
{
    if (token == NULL) {
        return;
    }
    BSL_SAL_FREE(token->authenticator.data);
    BSL_SAL_Free(token);
}

void HITLS_AUTH_PrivPassFreeToken(HITLS_AUTH_PrivPassToken *object)
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

HITLS_AUTH_PrivPassCtx *HITLS_AUTH_PrivPassNewCtx(int32_t protocolType)
{
    if (protocolType != HITLS_AUTH_PRIV_PASS_PUB_VERIFY_TOKENS) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOEKN_PROTOCOL_TYPE);
        return NULL;
    }
    HITLS_AUTH_PrivPassCtx *ctx = (HITLS_AUTH_PrivPassCtx *)BSL_SAL_Calloc(1u, sizeof(HITLS_AUTH_PrivPassCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    ctx->method = PrivPassCryptPubCb();
    return ctx;
}

void HITLS_AUTH_PrivPassFreeCtx(HITLS_AUTH_PrivPassCtx *ctx)
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

int32_t HITLS_AUTH_PrivPassSetCryptCb(HITLS_AUTH_PrivPassCtx *ctx, int32_t cbType, void *cryptCb)
{
    if (ctx == NULL || cryptCb == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    switch (cbType) {
        case HITLS_AUTH_PRIVPASS_NEW_PKEY_CTX_CB:
            ctx->method.newPkeyCtx = (HITLS_AUTH_PrivPassNewPkeyCtx)cryptCb;
            break;
        case HITLS_AUTH_PRIVPASS_FREE_PKEY_CTX_CB:
            ctx->method.freePkeyCtx = (HITLS_AUTH_PrivPassFreePkeyCtx)cryptCb;
            break;
        case HITLS_AUTH_PRIVPASS_DIGEST_CB:
            ctx->method.digest = (HITLS_AUTH_PrivPassDigest)cryptCb;
            break;
        case HITLS_AUTH_PRIVPASS_BLIND_CB:
            ctx->method.blind = (HITLS_AUTH_PrivPassBlind)cryptCb;
            break;
        case HITLS_AUTH_PRIVPASS_UNBLIND_CB:
            ctx->method.unBlind = (HITLS_AUTH_PrivPassUnblind)cryptCb;
            break;
        case HITLS_AUTH_PRIVPASS_SIGNDATA_CB:
            ctx->method.signData = (HITLS_AUTH_PrivPassSignData)cryptCb;
            break;
        case HITLS_AUTH_PRIVPASS_VERIFY_CB:
            ctx->method.verify = (HITLS_AUTH_PrivPassVerify)cryptCb;
            break;
        case HITLS_AUTH_PRIVPASS_DECODE_PUBKEY_CB:
            ctx->method.decodePubKey = (HITLS_AUTH_PrivPassDecodePubKey)cryptCb;
            break;
        case HITLS_AUTH_PRIVPASS_DECODE_PRVKEY_CB:
            ctx->method.decodePrvKey = (HITLS_AUTH_PrivPassDecodePrvKey)cryptCb;
            break;
        case HITLS_AUTH_PRIVPASS_CHECK_KEYPAIR_CB:
            ctx->method.checkKeyPair = (HITLS_AUTH_PrivPassCheckKeyPair)cryptCb;
            break;
        case HITLS_AUTH_PRIVPASS_RANDOM_CB:
            ctx->method.random = (HITLS_AUTH_PrivPassRandom)cryptCb;
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_CRYPTO_CALLBACK_TYPE);
            return HITLS_AUTH_PRIVPASS_INVALID_CRYPTO_CALLBACK_TYPE;
    }
    return HITLS_AUTH_SUCCESS;
}
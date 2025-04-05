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
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "auth_errno.h"
#include "auth_params.h"
#include "auth_privpass_token.h"
#include "privpass_token.h"

#define PRIVPASS_TOKEN_MAX_ENCODE_PUBKEY_LEN 1024

static int32_t SetAndValidateTokenType(const BSL_Param *param, PrivPass_TokenChallenge *tokenChallenge)
{
    const BSL_Param *temp = BSL_PARAM_FindConstParam(param, AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE);
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_NO_TOKEN_CHALLENGE_TYPE);
        return HITLS_AUTH_PRIVPASS_NO_TOKEN_CHALLENGE_TYPE;
    }

    uint32_t tokenTypeLen = (uint32_t)sizeof(tokenChallenge->tokenType);
    uint16_t tokenType = 0;
    int32_t ret = BSL_PARAM_GetValue(temp, AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE, BSL_PARAM_TYPE_UINT16,
        &tokenType, &tokenTypeLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (tokenType != PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE;
    }
    tokenChallenge->tokenType = tokenType;
    return HITLS_AUTH_SUCCESS;
}

static int32_t SetIssuerName(const BSL_Param *param, PrivPass_TokenChallenge *tokenChallenge)
{
    const BSL_Param *temp = BSL_PARAM_FindConstParam(param, AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ISSUERNAME);
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_NO_TOKEN_CHALLENGE_ISSUERNAME);
        return HITLS_AUTH_PRIVPASS_NO_TOKEN_CHALLENGE_ISSUERNAME;
    }

    if (temp->useLen == 0 || temp->useLen > PRIVPASS_MAX_ISSUER_NAME_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_ISSUER_NAME);
        return HITLS_AUTH_PRIVPASS_INVALID_ISSUER_NAME;
    }

    tokenChallenge->issuerName.data = BSL_SAL_Dump(temp->value, temp->useLen);
    if (tokenChallenge->issuerName.data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    tokenChallenge->issuerName.dataLen = temp->useLen;
    return HITLS_AUTH_SUCCESS;
}

static int32_t SetOptionalFields(const BSL_Param *param, PrivPass_TokenChallenge *tokenChallenge)
{
    // Set redemption
    const BSL_Param *temp = BSL_PARAM_FindConstParam(param, AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REDEMPTION);
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_NO_TOKEN_CHALLENGE_REDEMPTION);
        return HITLS_AUTH_PRIVPASS_NO_TOKEN_CHALLENGE_REDEMPTION;
    }
    if (temp->useLen != 0) {
        if (temp->useLen != PRIVPASS_REDEMPTION_LEN) {
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_REDEMPTION);
            return HITLS_AUTH_PRIVPASS_INVALID_REDEMPTION;
        }
        tokenChallenge->redemption.data = BSL_SAL_Dump(temp->value, temp->useLen);
        if (tokenChallenge->redemption.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        tokenChallenge->redemption.dataLen = temp->useLen;
    }

    // Set originInfo (optional)
    temp = BSL_PARAM_FindConstParam(param, AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ORIGININFO);
    if (temp != NULL && temp->useLen > 0) {
        if (temp->useLen > PRIVPASS_MAX_ORIGIN_INFO_LEN) {
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_ORIGIN_INFO);
            return HITLS_AUTH_PRIVPASS_INVALID_ORIGIN_INFO;
        }
        tokenChallenge->originInfo.data = BSL_SAL_Dump(temp->value, temp->useLen);
        if (tokenChallenge->originInfo.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        tokenChallenge->originInfo.dataLen = temp->useLen;
    }
    return HITLS_AUTH_SUCCESS;
}

int32_t HITLS_AUTH_PrivPassGenTokenChallenge(HITLS_AUTH_PrivPassCtx *ctx, const BSL_Param *param,
    HITLS_AUTH_PrivPassToken **challenge)
{
    (void)ctx;
    if (param == NULL || challenge == NULL || *challenge != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }

    HITLS_AUTH_PrivPassToken *output = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE);
    if (output == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint64_t challengeLen;
    PrivPass_TokenChallenge *tokenChallenge = output->st.tokenChallenge;
    int32_t ret = SetAndValidateTokenType(param, tokenChallenge);
    if (ret != HITLS_AUTH_SUCCESS) {
        HITLS_AUTH_PrivPassFreeToken(output);
        return ret;
    }

    ret = SetIssuerName(param, tokenChallenge);
    if (ret != HITLS_AUTH_SUCCESS) {
        HITLS_AUTH_PrivPassFreeToken(output);
        return ret;
    }

    ret = SetOptionalFields(param, tokenChallenge);
    if (ret != HITLS_AUTH_SUCCESS) {
        HITLS_AUTH_PrivPassFreeToken(output);
        return ret;
    }
    challengeLen = sizeof(tokenChallenge->tokenType) + tokenChallenge->issuerName.dataLen +
        tokenChallenge->redemption.dataLen + tokenChallenge->originInfo.dataLen;
    if (challengeLen > UINT32_MAX) {
        HITLS_AUTH_PrivPassFreeToken(output);
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE_PARAM);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE_PARAM;
    }
    *challenge = output;
    return HITLS_AUTH_SUCCESS;
}

static int32_t ParamCheckOfGenTokenReq(HITLS_AUTH_PrivPassCtx *ctx, const HITLS_AUTH_PrivPassToken *tokenChallenge,
    HITLS_AUTH_PrivPassToken **tokenRequest)
{
    if (ctx == NULL || ctx->method.blind == NULL || ctx->method.digest == NULL || ctx->method.random == NULL ||
        tokenChallenge == NULL || tokenChallenge->type != HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE ||
        tokenRequest == NULL || *tokenRequest != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    if (tokenChallenge->st.tokenChallenge->tokenType != PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE;
    }
    if (ctx->pubKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_NO_PUBKEY_INFO);
        return HITLS_AUTH_PRIVPASS_NO_PUBKEY_INFO;
    }
    return HITLS_AUTH_SUCCESS;
}

static uint32_t ObtainAuthenticatorLen(uint16_t tokenType)
{
    if (tokenType == PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        return (uint32_t)PRIVPASS_TOKEN_NK;
    }
    return 0;
}

static int32_t GenerateChallengeDigest(HITLS_AUTH_PrivPassCtx *ctx, const HITLS_AUTH_PrivPassToken *tokenChallenge,
    uint8_t *challengeDigest)
{
    uint8_t *challenge = NULL;
    uint32_t challengeLen = 0;
    uint32_t challengeDigestLen = PRIVPASS_TOKEN_SHA256_SIZE;
    int32_t ret = HITLS_AUTH_PrivPassSerialization(ctx, tokenChallenge, NULL, &challengeLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    challenge = BSL_SAL_Malloc(challengeLen);
    if (challenge == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ret = HITLS_AUTH_PrivPassSerialization(ctx, tokenChallenge, challenge, &challengeLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_SAL_Free(challenge);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = ctx->method.digest(NULL, NULL, HITLS_AUTH_PRIVPASS_CRYPTO_SHA256, challenge, challengeLen, challengeDigest,
        &challengeDigestLen);
    BSL_SAL_Free(challenge);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t HITLS_AUTH_PrivPassGenTokenReq(HITLS_AUTH_PrivPassCtx *ctx, const HITLS_AUTH_PrivPassToken *tokenChallenge,
    HITLS_AUTH_PrivPassToken **tokenRequest)
{
    int32_t ret = ParamCheckOfGenTokenReq(ctx, tokenChallenge, tokenRequest);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }
    HITLS_AUTH_PrivPassToken *output = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_REQUEST);
    if (output == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint8_t challengeDigest[PRIVPASS_TOKEN_SHA256_SIZE];
    const PrivPass_TokenChallenge *challenge = tokenChallenge->st.tokenChallenge;
    PrivPass_TokenRequest *request = output->st.tokenRequest;
    uint32_t authenticatorLen = ObtainAuthenticatorLen(challenge->tokenType); // challenge->tokenType has been checked.
    // Construct token_input = concat(token_type, nonce, challenge_digest, token_key_id)
    uint8_t tokenInput[HITLS_AUTH_PRIVPASS_TOKEN_INPUT_LEN];
    size_t offset = 0;
    // Copy token type from challenge
    request->tokenType = challenge->tokenType;
    request->truncatedTokenKeyId = ctx->tokenKeyId[PRIVPASS_TOKEN_SHA256_SIZE - 1];
    // cal tokenChallengeDigest
    ret = GenerateChallengeDigest(ctx, tokenChallenge, challengeDigest);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // Generate nonce
    ret = ctx->method.random(ctx->nonce, PRIVPASS_TOKEN_NONCE_LEN);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    // Add token type (2 bytes)
    BSL_Uint16ToByte(challenge->tokenType, tokenInput);
    offset += 2; // offset 2 bytes.
    // Add nonce
    (void)memcpy_s(tokenInput + offset, PRIVPASS_TOKEN_NONCE_LEN, ctx->nonce, PRIVPASS_TOKEN_NONCE_LEN);
    offset += PRIVPASS_TOKEN_NONCE_LEN;
    // Add challenge digest
    (void)memcpy_s(tokenInput + offset, PRIVPASS_TOKEN_SHA256_SIZE, challengeDigest, PRIVPASS_TOKEN_SHA256_SIZE);
    offset += PRIVPASS_TOKEN_SHA256_SIZE;
    // Add token key id
    (void)memcpy_s(tokenInput + offset, PRIVPASS_TOKEN_SHA256_SIZE, ctx->tokenKeyId, PRIVPASS_TOKEN_SHA256_SIZE);

    // Calculate blinded message
    request->blindedMsg.data = BSL_SAL_Malloc(authenticatorLen);
    if (request->blindedMsg.data == NULL) {
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        goto ERR;
    }
    request->blindedMsg.dataLen = authenticatorLen;
    ret = ctx->method.blind(ctx->pubKeyCtx, HITLS_AUTH_PRIVPASS_CRYPTO_SHA384, tokenInput,
        HITLS_AUTH_PRIVPASS_TOKEN_INPUT_LEN, request->blindedMsg.data, &request->blindedMsg.dataLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    *tokenRequest = output;
    return HITLS_AUTH_SUCCESS;
ERR:
    HITLS_AUTH_PrivPassFreeToken(output);
    return ret;
}

static int32_t ParamCheckOfGenTokenResp(HITLS_AUTH_PrivPassCtx *ctx, const HITLS_AUTH_PrivPassToken *tokenRequest,
    HITLS_AUTH_PrivPassToken **tokenResponse)
{
    if (ctx == NULL || ctx->method.signData == NULL ||
        tokenRequest == NULL || tokenRequest->type != HITLS_AUTH_PRIVPASS_TOKEN_REQUEST ||
        tokenResponse == NULL || *tokenResponse != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    if (tokenRequest->st.tokenRequest->tokenType != PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE;
    }

    if (ctx->prvKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_NO_PRVKEY_INFO);
        return HITLS_AUTH_PRIVPASS_NO_PRVKEY_INFO;
    }
    if (ctx->pubKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_NO_PUBKEY_INFO);
        return HITLS_AUTH_PRIVPASS_NO_PUBKEY_INFO;
    }
    return HITLS_AUTH_SUCCESS;
}

int32_t HITLS_AUTH_PrivPassGenTokenResponse(HITLS_AUTH_PrivPassCtx *ctx, const HITLS_AUTH_PrivPassToken *tokenRequest,
    HITLS_AUTH_PrivPassToken **tokenResponse)
{
    int32_t ret = ParamCheckOfGenTokenResp(ctx, tokenRequest, tokenResponse);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }

    const PrivPass_TokenRequest *request = tokenRequest->st.tokenRequest;
    uint32_t authenticatorLen = ObtainAuthenticatorLen(request->tokenType); // request->tokenType has been checked.
    if (request->truncatedTokenKeyId != ctx->tokenKeyId[PRIVPASS_TOKEN_SHA256_SIZE - 1]) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_KEYID);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_KEYID;
    }
    if (request->blindedMsg.dataLen != authenticatorLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_BLINDED_MSG);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_BLINDED_MSG;
    }
    HITLS_AUTH_PrivPassToken *output = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE);
    if (output == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    PrivPass_TokenResponse *response = output->st.tokenResponse;
    // Calculate blind signature
    response->st.pubResp.blindSig = BSL_SAL_Malloc(authenticatorLen);
    if (response->st.pubResp.blindSig == NULL) {
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        goto ERR;
    }
    response->st.pubResp.blindSigLen = authenticatorLen;

    ret = ctx->method.signData(ctx->prvKeyCtx, request->blindedMsg.data, request->blindedMsg.dataLen,
        response->st.pubResp.blindSig, &response->st.pubResp.blindSigLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    output->st.tokenResponse->type = HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE_PUB;
    *tokenResponse = output;
    return HITLS_AUTH_SUCCESS;

ERR:
    HITLS_AUTH_PrivPassFreeToken(output);
    return ret;
}

static int32_t ParamCheckOfGenToken(HITLS_AUTH_PrivPassCtx *ctx, const HITLS_AUTH_PrivPassToken *tokenChallenge,
    const HITLS_AUTH_PrivPassToken *tokenResponse, HITLS_AUTH_PrivPassToken **token)
{
    if (ctx == NULL || ctx->method.unBlind == NULL ||
        tokenChallenge == NULL || tokenChallenge->type != HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE ||
        tokenResponse == NULL || tokenResponse->type != HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE ||
        token == NULL || *token != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    if (ctx->pubKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_NO_PUBKEY_INFO);
        return HITLS_AUTH_PRIVPASS_NO_PUBKEY_INFO;
    }
    if (tokenChallenge->st.tokenChallenge->tokenType == PRIVPASS_PUBLIC_VERIFY_TOKENTYPE &&
        tokenResponse->st.tokenResponse->type == HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE_PUB) {
        return HITLS_AUTH_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
    return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE;
}

int32_t HITLS_AUTH_PrivPassGenToken(HITLS_AUTH_PrivPassCtx *ctx, const HITLS_AUTH_PrivPassToken *tokenChallenge,
    const HITLS_AUTH_PrivPassToken *tokenResponse, HITLS_AUTH_PrivPassToken **token)
{
    int32_t ret = ParamCheckOfGenToken(ctx, tokenChallenge, tokenResponse, token);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }

    HITLS_AUTH_PrivPassToken *output = HITLS_AUTH_PrivPassNewToken(HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE);
    if (output == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint8_t challengeDigest[PRIVPASS_TOKEN_SHA256_SIZE];
    PrivPass_TokenInstance *finalToken = output->st.token;
    const PrivPass_TokenChallenge *challenge = tokenChallenge->st.tokenChallenge;
    const PrivPass_TokenResponse *response = tokenResponse->st.tokenResponse;
    uint32_t outputLen = ObtainAuthenticatorLen(challenge->tokenType);
    // Copy token type from challenge
    finalToken->tokenType = challenge->tokenType;
    // cal tokenChallengeDigest
    ret = GenerateChallengeDigest(ctx, tokenChallenge, challengeDigest);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // Copy nonce from ctx
    (void)memcpy_s(finalToken->nonce, PRIVPASS_TOKEN_NONCE_LEN, ctx->nonce, PRIVPASS_TOKEN_NONCE_LEN);

    // Copy challenge digest from ctx
    (void)memcpy_s(finalToken->challengeDigest, PRIVPASS_TOKEN_SHA256_SIZE,
        challengeDigest, PRIVPASS_TOKEN_SHA256_SIZE);

    // Copy token key ID from ctx
    (void)memcpy_s(finalToken->tokenKeyId, PRIVPASS_TOKEN_SHA256_SIZE, ctx->tokenKeyId, PRIVPASS_TOKEN_SHA256_SIZE);

    // Copy authenticator from tokenResponse
    finalToken->authenticator.data = BSL_SAL_Malloc(outputLen);
    if (finalToken->authenticator.data == NULL) {
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        goto ERR;
    }
    ret = ctx->method.unBlind(ctx->pubKeyCtx, response->st.pubResp.blindSig, response->st.pubResp.blindSigLen,
        finalToken->authenticator.data, &outputLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    finalToken->authenticator.dataLen = outputLen;
    *token = output;
    return HITLS_AUTH_SUCCESS;

ERR:
    HITLS_AUTH_PrivPassFreeToken(output);
    return ret;
}

static int32_t ParamCheckOfVerifyToken(HITLS_AUTH_PrivPassCtx *ctx, const HITLS_AUTH_PrivPassToken *tokenChallenge,
    const HITLS_AUTH_PrivPassToken *token)
{
    if (ctx == NULL || ctx->method.verify == NULL ||
        tokenChallenge == NULL || tokenChallenge->type != HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE ||
        token == NULL || token->type != HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    if (tokenChallenge->st.tokenChallenge->tokenType != token->st.token->tokenType) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    if (tokenChallenge->st.tokenChallenge->tokenType != PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE;
    }
    if (ctx->pubKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_NO_PUBKEY_INFO);
        return HITLS_AUTH_PRIVPASS_NO_PUBKEY_INFO;
    }
    PrivPass_TokenInstance *finalToken = token->st.token;
    if (memcmp(finalToken->tokenKeyId, ctx->tokenKeyId, PRIVPASS_TOKEN_SHA256_SIZE) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_KEYID);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_KEYID;
    }
    uint8_t challengeDigest[PRIVPASS_TOKEN_SHA256_SIZE];
    int32_t ret = GenerateChallengeDigest(ctx, tokenChallenge, challengeDigest);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (memcmp(finalToken->challengeDigest, challengeDigest, PRIVPASS_TOKEN_SHA256_SIZE) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE_DIGEST);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE_DIGEST;
    }
    return HITLS_AUTH_SUCCESS;
}

int32_t HITLS_AUTH_PrivPassVerifyToken(HITLS_AUTH_PrivPassCtx *ctx, const HITLS_AUTH_PrivPassToken *tokenChallenge,
    const HITLS_AUTH_PrivPassToken *token)
{
    int32_t ret = ParamCheckOfVerifyToken(ctx, tokenChallenge, token);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }
    PrivPass_TokenInstance *finalToken = token->st.token;
    uint32_t authenticatorLen = ObtainAuthenticatorLen(finalToken->tokenType);
    if (finalToken->authenticator.data == NULL || authenticatorLen != finalToken->authenticator.dataLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_TOKEN_INSTANCE);
        return HITLS_AUTH_PRIVPASS_INVALID_TOKEN_INSTANCE;
    }
    // Construct token_input = concat(token_type, nonce, challenge_digest, token_key_id)
    uint8_t tokenInput[HITLS_AUTH_PRIVPASS_TOKEN_INPUT_LEN];
    size_t offset = 0;

    // Add token type (2 bytes)
    BSL_Uint16ToByte(finalToken->tokenType, tokenInput);
    offset += 2; // offset 2 bytes.

    // Add nonce
    (void)memcpy_s(tokenInput + offset, PRIVPASS_TOKEN_NONCE_LEN, finalToken->nonce, PRIVPASS_TOKEN_NONCE_LEN);
    offset += PRIVPASS_TOKEN_NONCE_LEN;

    // Add challenge digest
    (void)memcpy_s(tokenInput + offset, PRIVPASS_TOKEN_SHA256_SIZE,
        finalToken->challengeDigest, PRIVPASS_TOKEN_SHA256_SIZE);
    offset += PRIVPASS_TOKEN_SHA256_SIZE;

    // Add token key id
    (void)memcpy_s(tokenInput + offset, PRIVPASS_TOKEN_SHA256_SIZE, finalToken->tokenKeyId, PRIVPASS_TOKEN_SHA256_SIZE);

    // Verify the token using ctx's verify method
    ret = ctx->method.verify(ctx->pubKeyCtx, HITLS_AUTH_PRIVPASS_CRYPTO_SHA384, tokenInput,
        HITLS_AUTH_PRIVPASS_TOKEN_INPUT_LEN, finalToken->authenticator.data, PRIVPASS_TOKEN_NK);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t HITLS_AUTH_PrivPassSetPubkey(HITLS_AUTH_PrivPassCtx *ctx, uint8_t *pki, uint32_t pkiLen)
{
    if (ctx == NULL || ctx->method.decodePubKey == NULL || ctx->method.freePkeyCtx == NULL ||
        ctx->method.digest == NULL || pki == NULL || pkiLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    uint32_t tokenKeyIdLen = PRIVPASS_TOKEN_SHA256_SIZE;
    void *pubKeyCtx = NULL;
    int32_t ret = ctx->method.decodePubKey(NULL, NULL, pki, pkiLen, &pubKeyCtx);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ctx->prvKeyCtx != NULL) {
        if (ctx->method.checkKeyPair == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_NO_KEYPAIR_CHECK_CALLBACK);
            ret = HITLS_AUTH_PRIVPASS_NO_KEYPAIR_CHECK_CALLBACK;
            goto ERR;
        }

        ret = ctx->method.checkKeyPair(pubKeyCtx, ctx->prvKeyCtx);
        if (ret != HITLS_AUTH_SUCCESS) {
            ret = HITLS_AUTH_PRIVPASS_CHECK_KEYPAIR_FAILED;
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_CHECK_KEYPAIR_FAILED);
            goto ERR;
        }
    }
    ret = ctx->method.digest(NULL, NULL, HITLS_AUTH_PRIVPASS_CRYPTO_SHA256, pki, pkiLen, ctx->tokenKeyId,
        &tokenKeyIdLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (ctx->pubKeyCtx != NULL) {
        ctx->method.freePkeyCtx(ctx->pubKeyCtx);
    }
    ctx->pubKeyCtx = pubKeyCtx;
    return HITLS_AUTH_SUCCESS;

ERR:
    ctx->method.freePkeyCtx(pubKeyCtx);
    return ret;
}

int32_t HITLS_AUTH_PrivPassSetPrvkey(HITLS_AUTH_PrivPassCtx *ctx, void *param, uint8_t *ski, uint32_t skiLen)
{
    if (ctx == NULL || ctx->method.decodePrvKey == NULL || ctx->method.freePkeyCtx == NULL ||
        ski == NULL || skiLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_INVALID_INPUT);
        return HITLS_AUTH_PRIVPASS_INVALID_INPUT;
    }
    void *prvKeyCtx = NULL;
    int32_t ret = ctx->method.decodePrvKey(NULL, NULL, param, ski, skiLen, &prvKeyCtx);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ctx->pubKeyCtx != NULL) {
        if (ctx->method.checkKeyPair == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_NO_KEYPAIR_CHECK_CALLBACK);
            ret = HITLS_AUTH_PRIVPASS_NO_KEYPAIR_CHECK_CALLBACK;
            goto ERR;
        }
        ret = ctx->method.checkKeyPair(ctx->pubKeyCtx, prvKeyCtx);
        if (ret != HITLS_AUTH_SUCCESS) {
            ret = HITLS_AUTH_PRIVPASS_CHECK_KEYPAIR_FAILED;
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_PRIVPASS_CHECK_KEYPAIR_FAILED);
            goto ERR;
        }
    }
    if (ctx->prvKeyCtx != NULL) {
        ctx->method.freePkeyCtx(ctx->prvKeyCtx);
    }
    ctx->prvKeyCtx = prvKeyCtx;
    return HITLS_AUTH_SUCCESS;

ERR:
    ctx->method.freePkeyCtx(prvKeyCtx);
    return ret;
}

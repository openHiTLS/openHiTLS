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
#include "auth_errno.h"
#include "auth_params.h"
#include "auth_privpass_token.h"
#include "privpass_token.h"
#include "bsl_sal.h"
#include "crypt_utils.h"
#include "crypt_util_rand.h"
#include "crypt_eal_encode.h"

#define PRIVPASS_TOKEN_MAX_ENCODE_PUBKEY_LEN 1024

int32_t HiTLS_Auth_PrivPassGenTokenChallenge(HiTLS_Auth_PrivPassCtx *ctx, BSL_Param *param,
    HiTLS_Auth_PrivPassToken **challenge)
{
    if (ctx == NULL || param == NULL || challenge == NULL || *challenge != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    int32_t ret;
    HiTLS_Auth_PrivPassToken *output = HiTLS_Auth_PrivPassTokenNew(HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE);
    if (output == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    const BSL_Param *temp = NULL;
    PrivPass_TokenChallenge *tokenChallenge = output->st.tokenChallenge;
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_PRIV_PASS_TOKENTYPE)) != NULL) {
        uint32_t tokenTypeLen = (uint32_t)sizeof(tokenChallenge->tokenType);
        ret = BSL_PARAM_GetValue(param, CRYPT_PARAM_PRIV_PASS_TOKENTYPE, BSL_PARAM_TYPE_UINT16,
            &tokenChallenge->tokenType, &tokenTypeLen);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
    } else {
        ret = HITLS_AUTH_NO_TOKEN_CHALLENGE_TYPE;
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NO_TOKEN_CHALLENGE_TYPE);
        goto ERR;
    }

    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_PRIV_PASS_ISSUERNAME)) != NULL && temp->useLen > 0) {
        tokenChallenge->issuerName.data = BSL_SAL_Dump(temp->value, temp->useLen);
        if (tokenChallenge->issuerName.data == NULL) {
            ret = BSL_DUMP_FAIL;
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            goto ERR;
        }
        tokenChallenge->issuerName.dataLen = temp->useLen;
    } else {
        ret = HITLS_AUTH_NO_TOKEN_CHALLENGE_REDEMPTION;
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NO_TOKEN_CHALLENGE_REDEMPTION);
        goto ERR;
    }
    // redemption can be NULL.
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_PRIV_PASS_REDEMPTION)) != NULL && temp->useLen > 0) {
        tokenChallenge->redemption.data = BSL_SAL_Dump(temp->value, temp->useLen);
        if (tokenChallenge->redemption.data == NULL) {
            ret = BSL_DUMP_FAIL;
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            goto ERR;
        }
        tokenChallenge->redemption.dataLen = temp->useLen;
    }
    // originInfo can be NULL.
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_PRIV_PASS_ORIGININFO)) != NULL && temp->useLen > 0) {
        tokenChallenge->originInfo.data = BSL_SAL_Dump(temp->value, temp->useLen);
        if (tokenChallenge->originInfo.data == NULL) {
            ret = BSL_DUMP_FAIL;
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            goto ERR;
        }
        tokenChallenge->originInfo.dataLen = temp->useLen;
    }
    *challenge = output;
    return HITLS_AUTH_SUCCESS;
ERR:
    HiTLS_Auth_PrivPassTokenFree(output);
    return ret;
}

static int32_t ParamCheckOfGenTokenReq(HiTLS_Auth_PrivPassCtx *ctx, const HiTLS_Auth_PrivPassToken *tokenChallenge,
    HiTLS_Auth_PrivPassToken **tokenRequest)
{
    if (ctx == NULL || tokenChallenge == NULL || tokenChallenge->type != HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE
        || tokenRequest == NULL || *tokenRequest != NULL || ctx->method.blind == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    if (tokenChallenge->st.tokenChallenge->tokenType != PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_TYPE);
        return HITLS_AUTH_INVALID_TOKEN_TYPE;
    }
    if (ctx->pubKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NO_PUBKEY_INFO);
        return HITLS_AUTH_NO_PUBKEY_INFO;
    }
    return HITLS_AUTH_SUCCESS;
}

static uint32_t ObtainAuthenticatorLen(uint16_t tokenType)
{
    if ((int32_t)tokenType == PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        return (uint32_t)PRIVPASS_TOKEN_NK;
    }
    return 0;
}

int32_t HiTLS_Auth_PrivPassGenTokenReq(HiTLS_Auth_PrivPassCtx *ctx, const HiTLS_Auth_PrivPassToken *tokenChallenge,
    HiTLS_Auth_PrivPassToken **tokenRequest)
{
    int32_t ret = ParamCheckOfGenTokenReq(ctx, tokenChallenge, tokenRequest);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }
    HiTLS_Auth_PrivPassToken *output = HiTLS_Auth_PrivPassTokenNew(HITLS_AUTH_PRIVPASS_TOKEN_REQUEST);
    if (output == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    const PrivPass_TokenChallenge *challenge = tokenChallenge->st.tokenChallenge;
    PrivPass_TokenRequest *request = output->st.tokenRequest;
    uint32_t authenticatorLen = ObtainAuthenticatorLen(challenge->tokenType); // challenge->tokenType has been checked.
    // Copy token type from challenge
    request->tokenType = challenge->tokenType;
    request->truncatedTokenKeyId = ctx->tokenKeyId[PRIVPASS_TOKEN_SHA256_SIZE - 1];
    // Generate nonce
    ret = CRYPT_Rand(ctx->nonce, PRIVPASS_TOKEN_NONCE_LEN);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // Construct token_input = concat(token_type, nonce, challenge_digest, token_key_id)
    uint8_t tokenInput[HITLS_AUTH_PRIVPASS_TOKEN_INPUT_LEN];
    size_t offset = 0;

    // Add token type (2 bytes)
    PrivPassWriteUint(tokenInput, challenge->tokenType, 2);
    offset += 2;
    // Add nonce
    (void)memcpy_s(tokenInput + offset, PRIVPASS_TOKEN_NONCE_LEN, ctx->nonce, PRIVPASS_TOKEN_NONCE_LEN);
    offset += PRIVPASS_TOKEN_NONCE_LEN;

    // Add challenge digest
    (void)memcpy_s(tokenInput + offset, PRIVPASS_TOKEN_SHA256_SIZE, ctx->challengeDigest, PRIVPASS_TOKEN_SHA256_SIZE);
    offset += PRIVPASS_TOKEN_SHA256_SIZE;

    // Add token key id
    (void)memcpy_s(tokenInput + offset, PRIVPASS_TOKEN_SHA256_SIZE, ctx->tokenKeyId, PRIVPASS_TOKEN_SHA256_SIZE);

    // Calculate blinded message
    request->blindedMsg.data = BSL_SAL_Malloc(authenticatorLen);
    if (request->blindedMsg.data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        goto ERR;
    }
    request->blindedMsg.dataLen = authenticatorLen;
    ret = ctx->method.blind(ctx->pubKeyCtx, CRYPT_MD_SHA384, tokenInput, HITLS_AUTH_PRIVPASS_TOKEN_INPUT_LEN,
        request->blindedMsg.data, &request->blindedMsg.dataLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    *tokenRequest = output;
    return HITLS_AUTH_SUCCESS;
ERR:
    HiTLS_Auth_PrivPassTokenFree(output);
    return ret;
}

static int32_t ParamCheckOfGenTokenResp(HiTLS_Auth_PrivPassCtx *ctx, const HiTLS_Auth_PrivPassToken *tokenRequest,
    HiTLS_Auth_PrivPassToken **tokenResponse)
{
    if (ctx == NULL || tokenRequest == NULL || tokenRequest->type != HITLS_AUTH_PRIVPASS_TOKEN_REQUEST
        || tokenResponse == NULL || *tokenResponse != NULL || ctx->method.signData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    if (tokenRequest->st.tokenRequest->tokenType != PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_TYPE);
        return HITLS_AUTH_INVALID_TOKEN_TYPE;
    }

    if (ctx->prvKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NO_PRVKEY_INFO);
        return HITLS_AUTH_NO_PRVKEY_INFO;
    }
    return HITLS_AUTH_SUCCESS;
}

int32_t HiTLS_Auth_PrivPassGenTokenResponse(HiTLS_Auth_PrivPassCtx *ctx, HiTLS_Auth_PrivPassToken *tokenRequest,
    HiTLS_Auth_PrivPassToken **tokenResponse)
{
    int32_t ret = ParamCheckOfGenTokenResp(ctx, tokenRequest, tokenResponse);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }
    HiTLS_Auth_PrivPassToken *output = HiTLS_Auth_PrivPassTokenNew(HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE);
    if (output == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    PrivPass_TokenResponse *response = output->st.tokenResponse;
    const PrivPass_TokenRequest *request = tokenRequest->st.tokenRequest;
    uint32_t authenticatorLen = ObtainAuthenticatorLen(request->tokenType); // request->tokenType has been checked.
    if (request->truncatedTokenKeyId != ctx->tokenKeyId[PRIVPASS_TOKEN_SHA256_SIZE - 1]) {
        ret = HITLS_AUTH_INVALID_TOKEN_KEYID;
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_KEYID);
        goto ERR;
    }
    if (request->blindedMsg.dataLen != authenticatorLen) {
        ret = HITLS_AUTH_INVALID_TOKEN_BLINDED_MSG;
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_BLINDED_MSG);
        goto ERR;
    }
    // Calculate blind signature
    response->pubResp.blindSig = BSL_SAL_Malloc(authenticatorLen);
    if (response->pubResp.blindSig == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        goto ERR;
    }
    response->pubResp.blindSigLen = authenticatorLen;

    ret = ctx->method.signData(ctx->prvKeyCtx, request->blindedMsg.data, request->blindedMsg.dataLen,
        response->pubResp.blindSig, &response->pubResp.blindSigLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    output->st.tokenResponse->type = HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE_PUB;
    *tokenResponse = output;
    return HITLS_AUTH_SUCCESS;

ERR:
    HiTLS_Auth_PrivPassTokenFree(output);
    return ret;
}

static int32_t ParamCheckOfGenToken(HiTLS_Auth_PrivPassCtx *ctx, const HiTLS_Auth_PrivPassToken *tokenChallenge,
    const HiTLS_Auth_PrivPassToken *tokenResponse, HiTLS_Auth_PrivPassToken **token)
{
    if (ctx == NULL || tokenChallenge == NULL || tokenChallenge->type != HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE
        || tokenResponse == NULL || tokenResponse->type != HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE
        || token == NULL || *token != NULL || ctx->method.unblind == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    if (ctx->pubKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NO_PUBKEY_INFO);
        return HITLS_AUTH_NO_PUBKEY_INFO;
    }
    if (tokenChallenge->st.tokenChallenge->tokenType == PRIVPASS_PUBLIC_VERIFY_TOKENTYPE &&
        tokenResponse->st.tokenResponse->type == HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE_PUB) {
        return HITLS_AUTH_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_TYPE);
    return HITLS_AUTH_INVALID_TOKEN_TYPE;
}

int32_t HiTLS_Auth_PrivPassGenToken(HiTLS_Auth_PrivPassCtx *ctx, HiTLS_Auth_PrivPassToken *tokenChallenge,
    HiTLS_Auth_PrivPassToken *tokenResponse, HiTLS_Auth_PrivPassToken **token)
{
    int32_t ret = ParamCheckOfGenToken(ctx, tokenChallenge, tokenResponse, token);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }

    HiTLS_Auth_PrivPassToken *output = HiTLS_Auth_PrivPassTokenNew(HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE);
    if (output == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    PrivPass_TokenInstance *finalToken = output->st.token;
    const PrivPass_TokenChallenge *challenge = tokenChallenge->st.tokenChallenge;
    const PrivPass_TokenResponse *response = tokenResponse->st.tokenResponse;
    uint32_t outputLen = ObtainAuthenticatorLen(challenge->tokenType);
    // Copy token type from challenge
    finalToken->tokenType = challenge->tokenType;

    // Copy nonce from ctx
    (void)memcpy_s(finalToken->nonce, PRIVPASS_TOKEN_NONCE_LEN, ctx->nonce, PRIVPASS_TOKEN_NONCE_LEN);

    // Copy challenge digest from ctx
    (void)memcpy_s(finalToken->challengeDigest, PRIVPASS_TOKEN_SHA256_SIZE,
        ctx->challengeDigest, PRIVPASS_TOKEN_SHA256_SIZE);

    // Copy token key ID from ctx
    (void)memcpy_s(finalToken->tokenKeyId, PRIVPASS_TOKEN_SHA256_SIZE,
        ctx->tokenKeyId, PRIVPASS_TOKEN_SHA256_SIZE);

    // Copy authenticator from tokenResponse
    finalToken->authenticator.data = BSL_SAL_Malloc(outputLen);
    if (finalToken->authenticator.data == NULL) {
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        goto ERR;
    }
    
    ret = ctx->method.unblind(ctx->pubKeyCtx, response->pubResp.blindSig, response->pubResp.blindSigLen,
        finalToken->authenticator.data, &outputLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }   
    finalToken->authenticator.dataLen = outputLen;
    *token = output;
    return HITLS_AUTH_SUCCESS;

ERR:
    HiTLS_Auth_PrivPassTokenFree(output);
    return ret;
}

static int32_t ParamCheckOfVerifyToken(HiTLS_Auth_PrivPassCtx *ctx, HiTLS_Auth_PrivPassToken *tokenChallenge,
    HiTLS_Auth_PrivPassToken *token)
{
    if (ctx == NULL || tokenChallenge == NULL || tokenChallenge->type != HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE
        || token == NULL || token->type != HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE
        || ctx->method.verify == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    if (tokenChallenge->st.tokenChallenge->tokenType != token->st.token->tokenType) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    if (tokenChallenge->st.tokenChallenge->tokenType != PRIVPASS_PUBLIC_VERIFY_TOKENTYPE) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_TYPE);
        return HITLS_AUTH_INVALID_TOKEN_TYPE;
    }
    if (ctx->pubKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NO_PUBKEY_INFO);
        return HITLS_AUTH_NO_PUBKEY_INFO;
    }
    PrivPass_TokenInstance *finalToken = token->st.token;
    if (memcmp(finalToken->tokenKeyId, ctx->tokenKeyId, PRIVPASS_TOKEN_SHA256_SIZE) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_KEYID);
        return HITLS_AUTH_INVALID_TOKEN_KEYID;
    }
    if (memcmp(finalToken->challengeDigest, ctx->challengeDigest, PRIVPASS_TOKEN_SHA256_SIZE) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_TOKEN_CHALLENGE_DIGEST);
        return HITLS_AUTH_INVALID_TOKEN_CHALLENGE_DIGEST;
    }
    return HITLS_AUTH_SUCCESS;
}

int32_t HiTLS_Auth_PrivPassVerifyToken(HiTLS_Auth_PrivPassCtx *ctx, HiTLS_Auth_PrivPassToken *tokenChallenge,
    HiTLS_Auth_PrivPassToken *token)
{
    int32_t ret = ParamCheckOfVerifyToken(ctx, tokenChallenge, token);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }
    PrivPass_TokenInstance *finalToken = token->st.token;
    // Construct token_input = concat(token_type, nonce, challenge_digest, token_key_id)
    uint8_t tokenInput[HITLS_AUTH_PRIVPASS_TOKEN_INPUT_LEN];
    size_t offset = 0;

    // Add token type (2 bytes)
    PrivPassWriteUint(tokenInput, finalToken->tokenType, 2);
    offset += 2;

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
    ret = ctx->method.verify(ctx->pubKeyCtx, CRYPT_MD_SHA384, tokenInput, HITLS_AUTH_PRIVPASS_TOKEN_INPUT_LEN,
        finalToken->authenticator.data, PRIVPASS_TOKEN_NK);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return HITLS_AUTH_SUCCESS;
}

int32_t HiTLS_Auth_PrivPassSetPubkey(HiTLS_Auth_PrivPassCtx *ctx, uint8_t *pki, uint32_t pkiLen)
{
    if (ctx == NULL || pki == NULL || pkiLen == 0 || ctx->method.decodePubKey == NULL || ctx->method.digest == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    uint32_t tokenKeyIdLen = PRIVPASS_TOKEN_SHA256_SIZE;
    void *pubKeyCtx = NULL;
    int32_t ret = ctx->method.decodePubKey(&pubKeyCtx, pki, pkiLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (ctx->prvKeyCtx != NULL) {
        if (ctx->method.checkKeyPair == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_NO_KEYPAIR_CHECK_CALLBACK);
            ret = HITLS_AUTH_NO_KEYPAIR_CHECK_CALLBACK;
            goto ERR;
        }

        ret = ctx->method.checkKeyPair(pubKeyCtx, ctx->prvKeyCtx);
        if (ret != HITLS_AUTH_SUCCESS) {
            ret = HITLS_AUTH_CHECK_KEYPAIR_FAILED;
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_CHECK_KEYPAIR_FAILED);
            goto ERR;
        }
    }
    ret = ctx->method.digest(CRYPT_MD_SHA256, pki, pkiLen, ctx->tokenKeyId, &tokenKeyIdLen);
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
    if (ctx->method.freePkeyCtx != NULL) {
        ctx->method.freePkeyCtx(pubKeyCtx);
    }
    return ret;
}

int32_t HiTLS_Auth_PrivPassSetPrvkey(HiTLS_Auth_PrivPassCtx *ctx, uint8_t *ski, uint32_t skiLen)
{
    if (ctx == NULL || ski == NULL || skiLen == 0 || ctx->method.decodePrvKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    void *prvKeyCtx = NULL;
    int32_t ret = ctx->method.decodePrvKey(&prvKeyCtx, ski, skiLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        return ret;
    }
    if (ctx->pubKeyCtx != NULL) {
        if (ctx->method.checkKeyPair == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_NO_KEYPAIR_CHECK_CALLBACK);
            ret = HITLS_AUTH_NO_KEYPAIR_CHECK_CALLBACK;
            goto ERR;
        }
        
        ret = ctx->method.checkKeyPair(ctx->pubKeyCtx, prvKeyCtx);
        if (ret != HITLS_AUTH_SUCCESS) {
            ret = HITLS_AUTH_CHECK_KEYPAIR_FAILED;
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_CHECK_KEYPAIR_FAILED);
            goto ERR;
        }
    }
    if (ctx->prvKeyCtx != NULL) {
        ctx->method.freePkeyCtx(ctx->prvKeyCtx);
    }
    ctx->prvKeyCtx = prvKeyCtx;
    return HITLS_AUTH_SUCCESS;

ERR:
    if (ctx->method.freePkeyCtx != NULL) {
        ctx->method.freePkeyCtx(prvKeyCtx);
    }
    return ret;
}

static int32_t PrivPassGetTokenChallengeRequest(HiTLS_Auth_PrivPassToken *ctx, BSL_Param *param)
{
    if (param == NULL || ctx->st.tokenChallengeReq == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    uint32_t outputLen = ctx->st.tokenChallengeReq->challengeReqLen;
    if (outputLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_NO_TOKEN_CHALLENGE_REQUEST);
        return HITLS_AUTH_NO_TOKEN_CHALLENGE_REQUEST;
    }
    
    BSL_Param *output = BSL_PARAM_FindParam(param, CRYPT_PARAM_PRIV_PASS_TOKENCHALLENGE_REQUEST);
    if (output == NULL || output->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    if (param->valueLen < ctx->st.tokenChallengeReq->challengeReqLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    (void)memcpy_s(param->value, param->valueLen, ctx->st.tokenChallengeReq->challengeReq,
        ctx->st.tokenChallengeReq->challengeReqLen);
    param->useLen = ctx->st.tokenChallengeReq->challengeReqLen;
    return HITLS_AUTH_SUCCESS;
}

static int32_t PrivPassGetTokenNonce(HiTLS_Auth_PrivPassToken *ctx, BSL_Param *param)
{
    if (param == NULL || ctx->st.token == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }

    BSL_Param *output = BSL_PARAM_FindParam(param, CRYPT_PARAM_PRIV_PASS_TOKENNONCE);
    if (output == NULL || output->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    if (param->valueLen < PRIVPASS_TOKEN_NONCE_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    (void)memcpy_s(param->value, param->valueLen, ctx->st.token->nonce, PRIVPASS_TOKEN_NONCE_LEN);
    param->useLen = PRIVPASS_TOKEN_NONCE_LEN;
    return HITLS_AUTH_SUCCESS;
}

static int32_t PrivPassGetTokenChallengeContent(HiTLS_Auth_PrivPassToken *ctx, int32_t cmd, BSL_Param *param)
{
    if (param == NULL || ctx->st.tokenChallenge == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    PrivPass_TokenChallenge *challenge = ctx->st.tokenChallenge;
    int32_t target = 0;
    uint8_t *targetBuff = 0;
    uint32_t targetLen = 0;
    switch (cmd) {
        case HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_TYPE:
            target = CRYPT_PARAM_PRIV_PASS_TOKENTYPE;
            targetLen = (uint32_t)sizeof(challenge->tokenType);
            break;
        case HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_ISSUERNAME:
            target = CRYPT_PARAM_PRIV_PASS_ISSUERNAME;
            targetBuff = challenge->issuerName.data;
            targetLen = challenge->issuerName.dataLen;
            break;
        case HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_REDEMPTION:
            target = CRYPT_PARAM_PRIV_PASS_REDEMPTION;
            targetBuff = challenge->redemption.data;
            targetLen = challenge->redemption.dataLen;
            break;
        default:
            target = CRYPT_PARAM_PRIV_PASS_ORIGININFO;
            targetBuff = challenge->originInfo.data;
            targetLen = challenge->originInfo.dataLen;
            break;
    }
    BSL_Param *output = BSL_PARAM_FindParam(param, target);
    if (target == CRYPT_PARAM_PRIV_PASS_TOKENTYPE) {
        if (output != NULL && output->valueType == BSL_PARAM_TYPE_UINT16) {
            return BSL_PARAM_SetValue(output, target, BSL_PARAM_TYPE_UINT16, &challenge->tokenType, targetLen);
        } else {
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
            return HITLS_AUTH_INVALID_INPUT;
        }
    }
    if (output == NULL || output->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    if (output->valueLen < targetLen) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    (void)memcpy_s(output->value, output->valueLen, targetBuff, targetLen);
    output->useLen = targetLen;
    return HITLS_AUTH_SUCCESS;
}

int32_t HiTLS_Auth_PrivPassCtrl(void *object, int32_t cmd, void *param, uint32_t paramLen)
{
    if (object == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_INPUT);
        return HITLS_AUTH_INVALID_INPUT;
    }
    (void)paramLen;
    switch (cmd) {
        case HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_REQUEST:
            return PrivPassGetTokenChallengeRequest(object, param);
        case HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_TYPE:
        case HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_ISSUERNAME:
        case HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_REDEMPTION:
        case HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_ORIGININFO:
            return PrivPassGetTokenChallengeContent(object, cmd, param);
        case HITLS_AUTH_PRIVPASS_GET_TOKEN_NONCE:
            return PrivPassGetTokenNonce(object, param);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_INVALID_CMD);
            return HITLS_AUTH_INVALID_CMD;
    }
}

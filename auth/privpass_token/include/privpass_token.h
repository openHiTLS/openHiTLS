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

#ifndef PRIVPASS_TOKEN_H
#define PRIVPASS_TOKEN_H

#include <stdint.h>
#include "bsl_types.h"
#include "bsl_params.h"
#include "auth_params.h"
#include "auth_privpass_token.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Constants for Private Pass Token */
#define PRIVPASS_PUBLIC_VERIFY_TOKENTYPE ((uint16_t)0x0002)
#define PRIVPASS_TOKEN_NK 256 // RSA-2048 key size in bytes
#define PRIVPASS_TOKEN_SHA256_SIZE 32 // SHA256 hash size in bytes
#define PRIVPASS_TOKEN_NONCE_LEN 32 // Random nonce length
#define PRIVPASS_MAX_ISSUER_NAME_LEN 65535
#define PRIVPASS_REDEMPTION_LEN 32
#define PRIVPASS_MAX_ORIGIN_INFO_LEN 65535

// 2(tokenType) + 32(nonce) + 32(challengeDigest) + 32(tokenKeyId)
#define HITLS_AUTH_PRIVPASS_TOKEN_INPUT_LEN (2 + 32 + 32 + 32)

/* Structure for token challenge request */
typedef struct {
    uint8_t *challengeReq;      // Challenge request data
    uint32_t challengeReqLen;   // Length of challenge request
} PrivPass_TokenChallengeReq;

/* Structure for token challenge from server */
typedef struct {
    uint16_t tokenType;     // Token type (e.g., Blind RSA 2048-bit)
    BSL_Buffer issuerName;  // Name of the token issuer
    BSL_Buffer redemption;  // Redemption information
    BSL_Buffer originInfo;  // Origin information
} PrivPass_TokenChallenge;

typedef struct {
    uint16_t tokenType;
    uint8_t truncatedTokenKeyId;
    BSL_Buffer blindedMsg;
}   PrivPass_TokenRequest;

typedef struct {
    uint8_t *blindSig;
    uint32_t blindSigLen;
} PrivPass_TokenPubResponse;

typedef enum {
    HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE_PUB = 1,
} PrivPass_TokenResponseType;

typedef struct {
    int32_t type;
    union {
        PrivPass_TokenPubResponse pubResp;
    } st;
} PrivPass_TokenResponse;

typedef struct {
    uint16_t tokenType;
    uint8_t nonce[PRIVPASS_TOKEN_NONCE_LEN];
    uint8_t challengeDigest[PRIVPASS_TOKEN_SHA256_SIZE];
    uint8_t tokenKeyId[PRIVPASS_TOKEN_SHA256_SIZE];
    BSL_Buffer authenticator;
} PrivPass_TokenInstance;

struct PrivPass_Token {
    int32_t type;
    union {
        PrivPass_TokenChallengeReq *tokenChallengeReq;
        PrivPass_TokenChallenge *tokenChallenge;
        PrivPass_TokenRequest *tokenRequest;
        PrivPass_TokenResponse *tokenResponse;
        PrivPass_TokenInstance *token;
    } st;
};

typedef struct {
    HITLS_AUTH_PrivPassNewPkeyCtx newPkeyCtx;
    HITLS_AUTH_PrivPassFreePkeyCtx freePkeyCtx;
    HITLS_AUTH_PrivPassDigest digest;
    HITLS_AUTH_PrivPassBlind blind;
    HITLS_AUTH_PrivPassUnblind unBlind;
    HITLS_AUTH_PrivPassSignData signData;
    HITLS_AUTH_PrivPassVerify verify;
    HITLS_AUTH_PrivPassDecodePubKey decodePubKey;
    HITLS_AUTH_PrivPassDecodePrvKey decodePrvKey;
    HITLS_AUTH_PrivPassCheckKeyPair checkKeyPair;
    HITLS_AUTH_PrivPassRandom random;
} PrivPassCryptCb;

/* Main context structure for Private Pass operations */
struct PrivPass_Ctx {
    void *prvKeyCtx;        // Private key context
    void *pubKeyCtx;        // Public key context
    uint8_t tokenKeyId[PRIVPASS_TOKEN_SHA256_SIZE];      // Token key identifier
    uint8_t nonce[PRIVPASS_TOKEN_NONCE_LEN];             // Random nonce
    PrivPassCryptCb method;                   // Cryptographic callbacks
};

/**
 * @brief   Get the default cryptographic callback functions.
 * @retval  PrivPassCryptCb structure containing default callbacks.
 */
PrivPassCryptCb PrivPassCryptPubCb(void);

#ifdef __cplusplus
}
#endif

#endif // PRIVPASS_TOKEN_H

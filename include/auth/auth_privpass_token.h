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

#ifndef AUTH_PRIVPASS_TOKEN_H
#define AUTH_PRIVPASS_TOKEN_H

#include <stdint.h>
#include "bsl_params.h"
#include "bsl_obj.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup auth_privpass
 *
 * priv pass context structure.
 */
typedef struct PrivPass_Ctx HITLS_Auth_PrivPassCtx;

/**
 * @ingroup auth_privpass
 *
 * priv pass token structure.
 */
typedef struct PrivPass_Token HITLS_Auth_PrivPassToken;

/**
 * @ingroup auth_privpass
 *
 * priv pass crypt callback structure.
 */
typedef struct PrivPassCryptCb HITLS_Auth_PrivPassCryptCb;

/* Token types for different stages of the Private Pass protocol */
typedef enum {
    HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE_REQUEST = 1, // Initial request for challenge
    HITLS_AUTH_PRIVPASS_TOKEN_CHALLENGE = 2,         // Challenge from server
    HITLS_AUTH_PRIVPASS_TOKEN_REQUEST = 3,           // Token request with blinded message
    HITLS_AUTH_PRIVPASS_TOKEN_RESPONSE = 4,          // Server's response with blind signature
    HITLS_AUTH_PRIVPASS_TOKEN_INSTANCE = 5,          // Final token instance
} HITLS_Auth_PrivPassTokenType;

/* Token types for different stages of the Private Pass protocol */
typedef enum {
    HITLS_AUTH_PRIV_PASS_PRV_VERIFY_TOKENS = 1, // Private key verification tokens
    HITLS_AUTH_PRIV_PASS_PUB_VERIFY_TOKENS = 2, // Public key verification tokens
} HITLS_Auth_PrivPassType;

/* Commands for token operations and parameter retrieval */
typedef enum {
    HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_REQUEST = 1,    /** Get the token challenge request data */
    HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_TYPE = 2,    /** Get the type of token challenge */
    HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_ISSUERNAME = 3,    /** Get the issuer name from token challenge */
    HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_REDEMPTION = 4,    /** Get the redemption information from token challenge */
    HITLS_AUTH_PRIVPASS_GET_TOKENCHALLENGE_ORIGININFO = 5,    /** Get the origin information from token challenge */
    HITLS_AUTH_PRIVPASS_GET_TOKEN_NONCE = 6,    /** Get the nonce value from token */
} HITLS_Auth_PrivPassCmd;

typedef enum {
    HITLS_AUTH_PRIVPASS_CRYPTO_RSA = BSL_CID_RSA,
    HITLS_AUTH_PRIVPASS_CRYPTO_SHA256 = BSL_CID_SHA256,
    HITLS_AUTH_PRIVPASS_CRYPTO_SHA384 = BSL_CID_SHA384,
} HITLS_Auth_PrivPassCryptAlgId;

typedef enum {
    HITLS_AUTH_PRIVPASS_INVALID_CRYPTO_CB_TYPE = 0,
    HITLS_AUTH_PRIVPASS_NEW_PKEY_CTX = 1,
    HITLS_AUTH_PRIVPASS_FREE_PKEY_CTX = 2,
    HITLS_AUTH_PRIVPASS_DIGEST = 3,
    HITLS_AUTH_PRIVPASS_BLIND = 4,
    HITLS_AUTH_PRIVPASS_UNBLIND = 5,
    HITLS_AUTH_PRIVPASS_SIGNDATA = 6,
    HITLS_AUTH_PRIVPASS_VERIFY = 7,
    HITLS_AUTH_PRIVPASS_DECODE_PUBKEY = 8,
    HITLS_AUTH_PRIVPASS_DECODE_PRVKEY = 9,
    HITLS_AUTH_PRIVPASS_CHECK_KEY_PAIR = 10,
    HITLS_AUTH_PRIVPASS_RANDOM = 11,
} HITLS_Auth_PrivPassCryptCbType;

/**
 * @ingroup auth_privpass
 * @brief Creates a new public/private key context for the specified algorithm.
 *
 * @param   libCtx [IN] Library context
 * @param   attrName [IN] Specify expected attribute values
 * @param   algId [IN] Algorithm identifier, defined in HITLS_Auth_PrivPassCryptAlgId.
 *
 * @retval  Pointer to the created key context.
 *          NULL, if the operation fails.
 */
typedef void *(*HITLS_Auth_PrivPassNewPkeyCtx)(void *libCtx, const char *attrName, int32_t algId);

/**
 * @ingroup auth_privpass
 * @brief Frees a previously allocated key context.
 *
 * @param   pkeyCtx [IN] Key context to be freed
 */
typedef void (*HITLS_Auth_PrivPassFreePkeyCtx)(void *pkeyCtx);

/**
 * @ingroup auth_privpass
 * @brief Computes a cryptographic digest of the input data.
 * @param   libCtx [IN] Library context
 * @param   attrName [IN] Specify expected attribute values
 * @param   algId [IN] Algorithm identifier, defined in HITLS_Auth_PrivPassCryptAlgId.
 * @param   input [IN] Input data to be hashed
 * @param   inputLen [IN] Length of input data
 * @param   digest [OUT] Buffer to store the computed digest
 * @param   digestLen [IN/OUT] Size of digest buffer/Length of computed digest
 *
 * @retval  #0, if successful.
 *          other error codes, failed.
 */
typedef int32_t (*HITLS_Auth_PrivPassDigest)(void *libCtx, const char *attrName, int32_t algId, const uint8_t *input,
    uint32_t inputLen, uint8_t *digest, uint32_t *digestLen);

/**
 * @ingroup auth_privpass
 * @brief Blinds data using the key context and hash algorithm for blind signature protocol. The default algorithm
 *        callback implementation is supported only from RSASSA-PSS.
 *
 * @param   pkeyCtx [IN] Key context
 * @param   algId [IN] hash algorithm identifier
 * @param   data [IN] Data to be blinded
 * @param   dataLen [IN] Length of input data
 * @param   blindedData [OUT] Buffer to store blinded data
 * @param   blindedDataLen [IN/OUT] Size of buffer/Length of blinded data
 *
 * @retval  #0, if successful.
 *          other error codes, failed.
 */
typedef int32_t (*HITLS_Auth_PrivPassBlind)(void *pkeyCtx, int32_t algId, const uint8_t *data,
    uint32_t dataLen, uint8_t *blindedData, uint32_t *blindedDataLen);

/**
 * @ingroup auth_privpass
 * @brief Unblinds previously blinded data to reveal the actual signature. The default algorithm callback
 *        implementation is supported only from RSASSA-PSS.
 *
 * @param   pkeyCtx [IN] Key context
 * @param   blindedData [IN] Blinded data to be unblinded
 * @param   blindedDataLen [IN] Length of blinded data
 * @param   data [OUT] Buffer to store unblinded data
 * @param   dataLen [IN/OUT] Size of buffer/Length of unblinded data
 *
 * @retval  #0, if successful.
 *          other error codes, failed.
 */
typedef int32_t (*HITLS_Auth_PrivPassUnblind)(void *pkeyCtx, const uint8_t *blindedData,
    uint32_t blindedDataLen, uint8_t *data, uint32_t *dataLen);

/**
 * @ingroup auth_privpass
 * @brief Signs data using the private key context.
 *
 * @param   pkeyCtx [IN] Private key context
 * @param   data [IN] Data to be signed
 * @param   dataLen [IN] Length of input data
 * @param   sign [OUT] Buffer to store signature
 * @param   signLen [IN/OUT] Size of buffer/Length of signature
 *
 * @retval  #0, if successful.
 *          other error codes, failed.
 */
typedef int32_t (*HITLS_Auth_PrivPassSignData)(void *pkeyCtx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen);

/**
 * @ingroup auth_privpass
 * @brief Verifies a signature using the public key context.
 *
 * @param   pkeyCtx [IN] Public key context
 * @param   algId [IN] hash algorithm identifier
 * @param   data [IN] Original data
 * @param   dataLen [IN] Length of data
 * @param   sign [IN] Signature to verify
 * @param   signLen [IN] Length of signature
 *
 * @retval  #0, if successful.
 *          other error codes, failed.
 */
typedef int32_t (*HITLS_Auth_PrivPassVerify)(void *pkeyCtx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen);

/**
 * @ingroup auth_privpass
 * @brief Decodes a public key and gen a key ctx. The default algorithm callback implementation is supported only from
 *        a DER-encoded SubjectPublicKeyInfo (SPKI) object using the RSASSA-PSS OID.
 *
 * @param   libCtx [IN] Library context
 * @param   attrName [IN] Specify expected attribute values
 * @param   pubKey [IN] A DER-encoded SubjectPublicKeyInfo (SPKI) object using the RSASSA-PSS OID
 * @param   pubKeyLen [IN] Length of public key data
 * @param   pkeyCtx [OUT] Pointer to store created key context
 *
 * @retval  #0, if successful.
 *          other error codes, failed.
 */
typedef int32_t (*HITLS_Auth_PrivPassDecodePubKey)(void *libCtx, const char *attrName, uint8_t *pubKey,
    uint32_t pubKeyLen, void **pkeyCtx);

/**
 * @ingroup auth_privpass
 * @brief Decodes a private key and gen a key ctx. The default algorithm callback implementation is supported only from
 *        PEM-encoded PKCS #8 unencrypted RSA issuer private key.
 *
 * @param   libCtx [IN] Library context
 * @param   attrName [IN] Specify expected attribute values
 * @param   param [IN] Parameters may need by private key decoding.
 * @param   prvKey [IN] A PEM-encoded PKCS #8 RSA unencrypted issuer private Key
 * @param   prvKeyLen [IN] Length of private key data
 * @param   pkeyCtx [OUT] Pointer to store created key context
 *
 * @retval  #0, if successful.
 *          other error codes, failed.
 */
typedef int32_t (*HITLS_Auth_PrivPassDecodePrvKey)(void *libCtx, const char *attrName, void *param, uint8_t *prvKey,
    uint32_t prvKeyLen, void **pkeyCtx);

/**
 * @ingroup auth_privpass
 * @brief Verifies that a public/private key pair matches.
 *
 * @param   pubKeyCtx [IN] Public key context
 * @param   prvKeyCtx [IN] Private key context
 *
 * @retval  #0, if successful.
 *          other error codes, failed.
 */
typedef int32_t (*HITLS_Auth_PrivPassCheckKeyPair)(void *pubKeyCtx, void *prvKeyCtx);

/**
 * @ingroup auth_privpass
 * @brief Generates random bytes.
 *
 * @param   buffer [IN] Buffer to store random bytes
 * @param   bufferLen [IN] Length of buffer
 *
 * @retval  #0, if successful.
 *          other error codes, failed.
 */
typedef int32_t (*HITLS_Auth_PrivPassRandom)(uint8_t *buffer, uint32_t bufferLen);

/**
 * @ingroup auth_privpass
 * @brief   Create a new PrivPass context object, all library callbacks by default are setted when created.
 * @param   tokenType [IN] Type of token to create, defined in HITLS_Auth_PrivPassTokenType.
 *
 * @retval  HITLS_Auth_PrivPassCtx pointer.
 *          NULL, if the operation fails.
 */
HITLS_Auth_PrivPassCtx *HITLS_Auth_PrivPassNewCtx(int32_t protocolType);

/**
 * @ingroup auth_privpass
 * @brief   Free a PrivPass context object.
 *
 * @param   ctx [IN] Context to be freed
 */
void HITLS_Auth_PrivPassFreeCtx(HITLS_Auth_PrivPassCtx *ctx);
/**
 * @ingroup auth_privpass
 * @brief   Create a new PrivPass token object.
 *
 * @param   tokenType [IN] Type of token to create, defined in HITLS_Auth_PrivPassTokenType.
 *
 * @retval  HITLS_Auth_PrivPassToken pointer.
 *          NULL, if the operation fails.
 */
HITLS_Auth_PrivPassToken *HITLS_Auth_PrivPassNewToken(int32_t tokenType);

/**
 * @ingroup auth_privpass
 * @brief   Free a PrivPass token object.
 *
 * @param   object [IN] Token to be freed
 */
void HITLS_Auth_PrivPassFreeToken(HITLS_Auth_PrivPassToken *object);

/**
 * @ingroup auth_privpass
 * @brief   Set cryptographic callback functions for the context. When setting callbacks,
 *          the input callbacks will be checked. Non-NULL callbacks will override the default callbacks.
 *
 * @param   ctx [IN/OUT] PrivPass context
 * @param   cbType [IN] Callback type, defined in PrivPassCryptCbType
 * @param   cryptCb [IN] Callback functions to be set
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t HITLS_Auth_PrivPassSetCryptCb(HITLS_Auth_PrivPassCtx *ctx, int32_t cbType, void *cryptCb);

/**
 * @ingroup auth_privpass
 * @brief   Serialize a PrivPass token object to binary format, If the object == NULL, outbufferlen returns
 *          the length required for serialization
 *
 * @param   ctx [IN] PrivPass context
 * @param   object [IN] Token to serialize
 * @param   buffer [OUT] Buffer to store serialized data
 * @param   outBuffLen [IN/OUT] Length of the serialized data
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t HITLS_Auth_PrivPassSerialization(HITLS_Auth_PrivPassCtx *ctx, const HITLS_Auth_PrivPassToken *object,
    uint8_t *buffer, uint32_t *outBuffLen);

/**
 * @ingroup auth_privpass
 * @brief   Deserialize binary data into a PrivPass token object. The object needs to be freed by the caller
 *          using HITLS_Auth_PrivPassFreeToken
 *
 * @param   ctx [IN] PrivPass context
 * @param   tokenType [IN] Expected token type
 * @param   buffer [IN] Serialized data buffer
 * @param   buffLen [IN] Length of serialized data
 * @param   object [OUT] Pointer to store deserialized token
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t HITLS_Auth_PrivPassDeserialization(HITLS_Auth_PrivPassCtx *ctx, int32_t tokenType, const uint8_t *buffer,
    uint32_t buffLen, HITLS_Auth_PrivPassToken **object);

/**
 * @ingroup auth_privpass
 * @brief   Generate a token challenge. The challenge token is generated based on
 *          the input param. The construct of param refer to auth_params.h.
 * @param   ctx [IN] PrivPass context
 * @param   param [IN] Parameters for challenge generation, the param is limited to the library specification,
 *          the argument passed by the caller should ensure that the serialized length cannot exceed the upper limit.
 * @param   challenge [OUT] Generated challenge token
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t HITLS_Auth_PrivPassGenTokenChallenge(HITLS_Auth_PrivPassCtx *ctx, const BSL_Param *param,
    HITLS_Auth_PrivPassToken **challenge);

/**
 * @ingroup auth_privpass
 * @brief   Generate a token request.
 *
 * @param   ctx [IN] PrivPass context
 * @param   tokenChallenge [IN] Challenge token
 * @param   tokenRequest [OUT] Generated request token
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t HITLS_Auth_PrivPassGenTokenReq(HITLS_Auth_PrivPassCtx *ctx, const HITLS_Auth_PrivPassToken *tokenChallenge,
    HITLS_Auth_PrivPassToken **tokenRequest);

/**
 * @ingroup auth_privpass
 * @brief   Generate a token response.
 *
 * @param   ctx [IN] PrivPass context
 * @param   tokenRequest [IN] Request token
 * @param   tokenResponse [OUT] Generated response token
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t HITLS_Auth_PrivPassGenTokenResponse(HITLS_Auth_PrivPassCtx *ctx, const HITLS_Auth_PrivPassToken *tokenRequest,
    HITLS_Auth_PrivPassToken **tokenResponse);

/**
 * @ingroup auth_privpass
 * @brief   Generate final token.
 *
 * @param   ctx [IN] PrivPass context
 * @param   tokenChallenge [IN] Challenge token
 * @param   tokenResponse [IN] Response token
 * @param   token [OUT] Generated final token
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t HITLS_Auth_PrivPassGenToken(HITLS_Auth_PrivPassCtx *ctx, const HITLS_Auth_PrivPassToken *tokenChallenge,
    const HITLS_Auth_PrivPassToken *tokenResponse, HITLS_Auth_PrivPassToken **token);

/**
 * @ingroup auth_privpass
 * @brief   Verify the validity of a token.
 *
 * @param   ctx [IN] PrivPass context
 * @param   tokenChallenge [IN] Challenge token
 * @param   token [IN] Token to verify
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t HITLS_Auth_PrivPassVerifyToken(HITLS_Auth_PrivPassCtx *ctx, const HITLS_Auth_PrivPassToken *tokenChallenge,
    const HITLS_Auth_PrivPassToken *token);

/**
 * @ingroup auth_privpass
 * @brief   Set the public key for the ctx. We support the repeated setting of the public key. If the ctx
 *          contains the private key when the public key is set, we will check whether the public key
 *          matches the private key. If its not match, an exception is returned.
 *
 * @param   ctx [IN] PrivPass context
 * @param   pki [IN] A DER-encoded SubjectPublicKeyInfo (SPKI) object using the RSASSA-PSS OID
 * @param   pkiLen [IN] Length of public key data
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t HITLS_Auth_PrivPassSetPubkey(HITLS_Auth_PrivPassCtx *ctx, uint8_t *pki, uint32_t pkiLen);

/**
 * @ingroup auth_privpass
 * @brief   Set the private key for the ctx. We support the repeated setting of the private key. If the ctx
 *          contains the public key when the private key is set, we will check whether the private key
 *          matches the public key. If its not match, an exception is returned.
 * @note    ski: pem encoded private keys must end in '\0'
 * @param   ctx [IN] PrivPass context
 * @param   param [IN] Parameters may need by private key decoding.
 * @param   ski [IN] A PEM-encoded PKCS #8 RSA unencrypted issuer private key
 * @param   skiLen [IN] Length of private key data
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t HITLS_Auth_PrivPassSetPrvkey(HITLS_Auth_PrivPassCtx *ctx, void *param, uint8_t *ski, uint32_t skiLen);

/**
 * @ingroup auth_privpass
 * @brief   Control interface for getting/setting various parameters in token object.
 *
 * @param   object [IN] token object
 * @param   cmd [IN] Command to execute, defined in HITLS_Auth_PrivPassCmd
 * @param   param [IN/OUT] Command parameters
 * @param   paramLen [IN] Length of parameters
 *
 * @retval  #CRYPT_SUCCESS, if successful.
 *          For other error codes, see crypt_errno.h.
 */
int32_t HITLS_Auth_PrivPassTokenCtrl(HITLS_Auth_PrivPassToken *object, int32_t cmd, void *param, uint32_t paramLen);

#ifdef __cplusplus
}
#endif

#endif // AUTH_PRIVPASS_TOKEN_H

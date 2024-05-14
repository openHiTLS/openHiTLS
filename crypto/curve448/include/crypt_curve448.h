/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_CURVE448_H
#define CRYPT_CURVE448_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CURVE448

#include <stdint.h>
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ED448_KEY_LEN 57
#define X448_KEY_LEN 56
#define ED448_SIGN_LEN 114

#define ED448_CONTEXT_MAX_LEN 255

typedef struct CryptCurve448Ctx CRYPT_CURVE448_Ctx;

/**
 * @ingroup curve448
 * @brief curve448 Create a key pair structure and allocate memory space.
 *
 * @retval (CRYPT_CURVE448_Ctx *) Pointer to the key pair structure
 * @retval NULL Invalid null pointer
 */
CRYPT_CURVE448_Ctx *CRYPT_CURVE448_NewCtx(void);

/**
 * @ingroup curve448
 * @brief Copy the curve448 context. After the duplication is complete,
 *        call the CRYPT_CURVE448_FreeCtx to release the memory.
 *
 * @param ctx [IN] Source curve448 Context
 *
 * @return CRYPT_CURVE448_Ctx curve448 Context pointer
 *         If the operation fails, null is returned.
 */
CRYPT_CURVE448_Ctx *CRYPT_CURVE448_DupCtx(CRYPT_CURVE448_Ctx *ctx);

/**
 * @ingroup curve448
 * @brief clear curve448 key pair data and releases memory.
 *
 * @param pkey [IN] curve448 Key pair structure. The pkey is set NULL by the invoker.
 */
void CRYPT_CURVE448_FreeCtx(CRYPT_CURVE448_Ctx *pkey);

#ifdef HITLS_CRYPTO_ED448
/**
 * @ingroup curve448
 * @brief Obtain the ed448 Private key.
 *
 * @param pkey [IN] curve448 Key pair structure
 * @param pub  [OUT] Private key
 *
 * @retval CRYPT_SUCCESS                obtained successfully.
 * @retval CRYPT_NULL_INPUT             If any input parameter is empty
 * @retval CRYPT_CURVE448_NO_PRVKEY     The key pair has no Private key.
 * @retval CRYPT_CURVE448_KEYLEN_ERROR  prvKeyLen is less than the length of the ed448 Private key.
 */
int32_t CRYPT_ED448_GetPrvKey(const CRYPT_CURVE448_Ctx *pkey, CRYPT_Curve448Prv *prv);

/**
 * @ingroup curve448
 * @brief Obtain the ed448 public key.
 *
 * @param pkey [IN] curve448 Key pair structure
 * @param pub  [OUT] Public key
 *
 * @retval CRYPT_SUCCESS                obtained successfully.
 * @retval CRYPT_NULL_INPUT             If any input parameter is empty
 * @retval CRYPT_CURVE448_NO_PUBKEY     The key pair has no public key.
 * @retval CRYPT_CURVE448_KEYLEN_ERROR  pubKeyLen is less than the length of the ed448 public key.
 */
int32_t CRYPT_ED448_GetPubKey(const CRYPT_CURVE448_Ctx *pkey, CRYPT_Curve448Pub *pub);

/**
 * @ingroup curve448
 * @brief ed448 Set the private key.
 *
 * @param pkey [IN/OUT] curve448 Key pair structure
 * @param prv  [IN] Private key
 *
 * @retval CRYPT_SUCCESS                set successfully.
 * @retval CRYPT_NULL_INPUT             If any input parameter is empty
 * @retval CRYPT_CURVE448_KEYLEN_ERROR  prvKeyLen is not equal to the length of the ed448 private key.
 */
int32_t CRYPT_ED448_SetPrvKey(CRYPT_CURVE448_Ctx *pkey, const CRYPT_Curve448Prv *prv);

/**
 * @ingroup curve448
 * @brief ed448 Set the public key.
 *
 * @param pkey [IN/OUT] curve448 Key pair structure
 * @param pub  [IN] Public key
 *
 * @retval CRYPT_SUCCESS                set successfully.
 * @retval CRYPT_NULL_INPUT             If any input parameter is empty
 * @retval CRYPT_CURVE448_KEYLEN_ERROR  pubKeyLen is not equal to the length of the ed448 public key.
 */
int32_t CRYPT_ED448_SetPubKey(CRYPT_CURVE448_Ctx *pkey, const CRYPT_Curve448Pub *pub);

/**
 * @ingroup curve448
 * @brief ed448 Generate a key pair (public and private keys).
 *
 * @param pkey [IN/OUT] curve448 Key pair structure/Key pair structure containing public and private keys
 *
 * @retval CRYPT_SUCCESS                 generated successfully.
 * @retval CRYPT_NO_REGIST_RAND          Unregistered random number
 * @retval Error code of the hash module. An internal shake256 operation error occurs.
 * @retval Error code of the registered random number module. Failed to obtain the random number.
 * @retval CRYPT_CURVE448_NO_HASH_METHOD No hash method is set.
 * @retval CRYPT_NULL_INPUT             The input parameter is empty.
 */
int32_t CRYPT_ED448_GenKey(CRYPT_CURVE448_Ctx *pkey);

/**
 * @ingroup curve448
 * @brief curve448 Obtain the signature length, in bytes.
 *
 * @param pkey [IN] curve448 Key pair structure
 *
 * @retval Signature length
 */
int32_t CRYPT_ED448_GetSignLen(const CRYPT_CURVE448_Ctx *pkey);

/**
 * @ingroup curve448
 * @brief ed448 Obtain the key length, in bits.
 *
 * @param pkey [IN] curve448 Key pair structure
 *
 * @retval Key length
 */
int32_t CRYPT_ED448_GetBits(const CRYPT_CURVE448_Ctx *pkey);


/**
 * @ingroup curve448
 * @brief curve448 Sign
 *
 * @param pkey    [IN/OUT] curve448 Key pair structure. A private key is required for signature.
 *                         After signature, a public key is generated.
 * @param msg     [IN] Data to be signed
 * @param msgLen  [IN] Data length
 * @param sign    [OUT] Signature
 * @param signLen [IN/OUT] Length of the signature buffer (the length must be <= 114 bytes)/Length of the signature
 *
 * @retval CRYPT_SUCCESS                 generated successfully.
 * @retval CRYPT_CURVE448_NO_PRVKEY      The key pair has no private key.
 * @retval CRYPT_NULL_INPUT              If any input parameter is empty
 * @retval Error code of the hash module. An internal shake256 operation error occurs.
 * @retval CRYPT_CURVE448_NO_HASH_METHOD No hash method is set.
 * @retval CRYPT_CURVE448_SIGNLEN_ERROR  signLen is less than the signature length of curve448
 */
int32_t CRYPT_CURVE448_Sign(CRYPT_CURVE448_Ctx *pkey, const uint8_t *msg,
    uint32_t msgLen, uint8_t *sign, uint32_t *signLen);

/**
 * @ingroup curve448
 * @brief   curve448 Verify
 *
 * @param pkey    [IN] curve448 Key pair structure. A public key is required for signature verification.
 * @param msg     [IN] Data
 * @param msgLen  [IN] Data length
 * @param sign    [IN] Signature
 * @param signLen [IN] Signature length, which must be 114 bytes
 *
 * @retval CRYPT_SUCCESS                        The signature is verified successfully.
 * @retval CRYPT_CURVE448_NO_PUBKEY             The key pair does not have a public key.
 * @retval CRYPT_NULL_INPUT                     If any input parameter is empty
 * @retval Error code of the hash module.       An internal shake256 operation error occurs.
 * @retval CRYPT_CURVE448_VERIFY_FAIL           The signature is incorrect. Failed to verify the signature.
 * @retval CRYPT_CURVE448_INVALID_PUBKEY        Invalid public key.
 * @retval CRYPT_CURVE448_SIGNLEN_ERROR         signLen is not equal to curve448 signature length
 * @retval CRYPT_CURVE448_NO_HASH_METHOD        No hash method is set.
 */
int32_t CRYPT_CURVE448_Verify(const CRYPT_CURVE448_Ctx *pkey, const uint8_t *msg,
    uint32_t msgLen, const uint8_t *sign, uint32_t signLen);

#endif /* HITLS_CRYPTO_ED448 */

#ifdef HITLS_CRYPTO_X448
/**
 * @ingroup curve448
 * @brief x448 Obtain the private key.
 *
 * @param pkey [IN] curve448 Key pair structure
 * @param prv  [OUT] Private key
 *
 * @retval CRYPT_SUCCESS                obtained successfully.
 * @retval CRYPT_NULL_INPUT             If any input parameter is empty
 * @retval CRYPT_CURVE448_NO_PRVKEY     The key pair has no private key.
 * @retval CRYPT_CURVE448_KEYLEN_ERROR  prvKeyLen is less than x448 private key length
 */
int32_t CRYPT_X448_GetPrvKey(const CRYPT_CURVE448_Ctx *pkey, CRYPT_Curve448Prv *prv);

/**
 * @ingroup curve448
 * @brief x448 Obtain the public key.
 *
 * @param pkey [IN] curve448 Key pair structure
 * @param pub  [OUT] Public key
 *
 * @retval CRYPT_SUCCESS                obtained successfully.
 * @retval CRYPT_NULL_INPUT             If any input parameter is empty
 * @retval CRYPT_CURVE448_NO_PUBKEY     The key pair has no public key.
 * @retval CRYPT_CURVE448_KEYLEN_ERROR  pubKeyLen is less than x448 public key length
 */
int32_t CRYPT_X448_GetPubKey(const CRYPT_CURVE448_Ctx *pkey, CRYPT_Curve448Pub *pub);

/**
 * @ingroup curve448
 * @brief x448 Set the private key.
 *
 * @param pkey [IN/OUT] curve448 Key pair structure
 * @param prv  [IN] Private key
 *
 * @retval CRYPT_SUCCESS                set successfully.
 * @retval CRYPT_NULL_INPUT             If any input parameter is empty
 * @retval CRYPT_CURVE448_KEYLEN_ERROR  prvKeyLen is not equal to x448 private key length
 */
int32_t CRYPT_X448_SetPrvKey(CRYPT_CURVE448_Ctx *pkey, const CRYPT_Curve448Prv *prv);

/**
 * @ingroup curve448
 * @brief x448 Set the public key.
 *
 * @param pkey [IN/OUT] curve448 Key pair structure
 * @param pub  [IN] Public key
 *
 * @retval CRYPT_SUCCESS                set successfully.
 * @retval CRYPT_NULL_INPUT             If any input parameter is empty
 * @retval CRYPT_CURVE448_KEYLEN_ERROR  pubKeyLen is not equal to x448 public key length
 */
int32_t CRYPT_X448_SetPubKey(CRYPT_CURVE448_Ctx *pkey, const CRYPT_Curve448Pub *pub);

/**
 * @ingroup curve448
 * @brief x448 Generate a key pair (public and private keys).
 *
 * @param pkey [IN/OUT] curve448 Key pair structure/Key pair structure containing public and private keys
 *
 * @retval CRYPT_SUCCESS                generated successfully.
 * @retval CRYPT_NO_REGIST_RAND         Unregistered random number
 * @retval Error code of the registered random number module. Failed to obtain the random number.
 * @retval CRYPT_NULL_INPUT             The input parameter is empty.
 */
int32_t CRYPT_X448_GenKey(CRYPT_CURVE448_Ctx *pkey);

/**
 * @ingroup curve448
 * @brief x448 Obtain the key length, in bits.
 *
 * @param pkey [IN] curve448 Key pair structure
 *
 * @retval Key length
 */
int32_t CRYPT_X448_GetBits(const CRYPT_CURVE448_Ctx *pkey);

/**
 * @ingroup curve448
 * @brief x448 Calculate the shared key based on the private key of the local end and the public key of the peer end.
 *
 * @param prvKey      [IN] curve448 Key pair structure, local private key
 * @param pubKey      [IN] curve448 Key pair structure, peer public key
 * @param sharedKey   [OUT] Shared key
 * @param shareKeyLen [IN/OUT] Shared key length
 *
 * @retval CRYPT_SUCCESS                        generated successfully.
 * @retval CRYPT_CURVE448_KEY_COMPUTE_FAILED    Failed to generate the shared key.
 */
int32_t CRYPT_X448_ComputeSharedKey(CRYPT_CURVE448_Ctx *prvKey, CRYPT_CURVE448_Ctx *pubKey,
    uint8_t *sharedKey, uint32_t *shareKeyLen);

#endif /* HITLS_CRYPTO_X448 */

/**
 * @ingroup curve448
 * @brief curve448 Control interface
 *
 * @param pkey [IN/OUT] curve448 Key pair structure
 * @param val  [IN] Hash method. The value must be SHAKE256.
 * @param opt  [IN] Operation mode
 * @param len  [IN] val length
 *
 * @retval CRYPT_SUCCESS                                set successfully.
 * @retval CRYPT_NULL_INPUT                             If any input parameter is empty
 * @retval CRYPT_CURVE448_UNSUPPORTED_CTRL_OPTION       opt mode not supported
 * @retval CRYPT_CURVE448_CONTEXT_TOO_LONG              context exceeds 255 characters.
 */
int32_t CRYPT_CURVE448_Ctrl(CRYPT_CURVE448_Ctx *pkey, CRYPT_PkeyCtrl opt, const void *val, uint32_t len);

/**
 * @ingroup curve448
 * @brief curve448 Public key comparison
 *
 * @param a [IN] curve448 Context structure
 * @param b [IN] curve448 Context structure
 *
 * @retval CRYPT_SUCCESS                    is the same
 * @retval CRYPT_NULL_INPUT                 Error null pointer input
 * @retval CRYPT_CURVE448_NO_PUBKEY         No public key
 * @retval CRYPT_CURVE448_PUBKEY_NOT_EQUAL  Inconsistent public keys
 */
int32_t CRYPT_CURVE448_Cmp(const CRYPT_CURVE448_Ctx *a, const CRYPT_CURVE448_Ctx *b);

/**
 * @ingroup curve448
 * @brief curve448 get security bits
 *
 * @param ctx [IN] curve448 Context structure
 *
 * @retval security bits
 */
int32_t CRYPT_CURVE448_GetSecBits(const CRYPT_CURVE448_Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_CURVE448

#endif // CRYPT_CURVE448_H

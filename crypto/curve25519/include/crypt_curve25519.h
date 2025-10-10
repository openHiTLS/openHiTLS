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

#ifndef CRYPT_CURVE25519_H
#define CRYPT_CURVE25519_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CURVE25519

#include <stdint.h>
#include "crypt_local_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPT_CURVE25519_KEYLEN 32
#define CRYPT_CURVE25519_SIGNLEN 64

typedef struct CryptCurve25519Ctx CRYPT_CURVE25519_Ctx;

#ifdef HITLS_CRYPTO_X25519
/**
 * @ingroup curve25519
 * @brief curve25519 Create a key pair structure and allocate memory space.
 *
 * @retval (CRYPT_CURVE25519_Ctx *) Pointer to the key pair structure
 * @retval NULL                     Invalid null pointer
 */
CRYPT_CURVE25519_Ctx *CRYPT_X25519_NewCtx(void);

/**
 * @ingroup curve25519
 * @brief curve25519 Create a key pair structure and allocate memory space.
 *
 * @param libCtx [IN] Library context
 *
 * @retval (CRYPT_CURVE25519_Ctx *) Pointer to the key pair structure
 * @retval NULL                     Invalid null pointer
 */
CRYPT_CURVE25519_Ctx *CRYPT_X25519_NewCtxEx(void *libCtx);
#endif

#ifdef HITLS_CRYPTO_ED25519
/**
 * @ingroup ed25519
 * @brief curve25519 Create a key pair structure for ED25519 algorithm and allocate memory space.
 *
 * @retval (CRYPT_CURVE25519_Ctx *) Pointer to the key pair structure
 * @retval NULL                     Invalid null pointer
 */
CRYPT_CURVE25519_Ctx *CRYPT_ED25519_NewCtx(void);

/**
 * @ingroup ed25519
 * @brief curve25519 Create a key pair structure for ED25519 algorithm and allocate memory space.
 *
 * @param libCtx [IN] Library context
 *
 * @retval (CRYPT_CURVE25519_Ctx *) Pointer to the key pair structure
 * @retval NULL                     Invalid null pointer
 */
CRYPT_CURVE25519_Ctx *CRYPT_ED25519_NewCtxEx(void *libCtx);
#endif

/**
 * @ingroup curve25519
 * @brief Copy the curve25519 context. The memory management of the return value is handed over to the caller.
 *
 * @param ctx [IN] Source curve25519 context. The CTX is set NULL by the invoker.
 *
 * @return CRYPT_CURVE25519_Ctx curve25519 Context pointer
 *         If the operation fails, null is returned.
 */
CRYPT_CURVE25519_Ctx *CRYPT_CURVE25519_DupCtx(CRYPT_CURVE25519_Ctx *ctx);

/**
 * @ingroup curve25519
 * @brief Clear the curve25519 key pair data and releases memory.
 *
 * @param pkey [IN] curve25519 Key pair structure. The pkey is set NULL by the invoker.
 */
void CRYPT_CURVE25519_FreeCtx(CRYPT_CURVE25519_Ctx *pkey);

/**
 * @ingroup curve25519
 * @brief curve25519 Control interface
 *
 * @param pkey [IN/OUT] curve25519 Key pair structure
 * @param val  [IN] Hash method, which must be SHA512.
 * @param opt  [IN] Operation mode
 * @param len  [IN] val length
 *
 * @retval CRYPT_SUCCESS                            set successfully.
 * @retval CRYPT_NULL_INPUT                         If any input parameter is empty
 * @retval CRYPT_CURVE25519_UNSUPPORTED_CTRL_OPTION The opt mode is not supported.
 * @retval CRYPT_CURVE25519_HASH_METH_ERROR         The hash method is not SHA512
 */
int32_t CRYPT_CURVE25519_Ctrl(CRYPT_CURVE25519_Ctx *pkey, int32_t opt, void *val, uint32_t len);

/**
 * @ingroup curve25519
 * @brief curve25519 Set the public key.
 *
 * @param pkey [IN] curve25519 Key pair structure
 * @param pub  [IN] Public key
 *
 * @retval CRYPT_SUCCESS                        set successfully.
 * @retval CRYPT_NULL_INPUT                     If any input parameter is empty
 * @retval CRYPT_CURVE25519_KEYLEN_ERROR        pubKeyLen is not equal to curve25519 public key length
 */
int32_t CRYPT_CURVE25519_SetPubKey(CRYPT_CURVE25519_Ctx *pkey, const CRYPT_Curve25519Pub *pub);

/**
 * @ingroup curve25519
* @brief curve25519 Obtain the public key.
 *
 * @param pkey [IN] curve25519 Key pair structure
 * @param pub  [OUT] Public key
 *
 * @retval CRYPT_SUCCESS                        set successfully.
 * @retval CRYPT_NULL_INPUT                     If any input parameter is empty
 * @retval CRYPT_CURVE25519_NO_PUBKEY           The key pair has no public key.
 * @retval CRYPT_CURVE25519_KEYLEN_ERROR        pubKeyLen is less than curve25519 public key length.
 */
int32_t CRYPT_CURVE25519_GetPubKey(const CRYPT_CURVE25519_Ctx *pkey, CRYPT_Curve25519Pub *pub);

/**
 * @ingroup curve25519
 * @brief curve25519 Set the private key.
 *
 * @param pkey [IN] curve25519 Key pair structure
 * @param prv  [IN] Private key
 *
 * @retval CRYPT_SUCCESS                        set successfully.
 * @retval CRYPT_NULL_INPUT                     If any input parameter is empty
 * @retval CRYPT_CURVE25519_KEYLEN_ERROR        prvKeyLen is not equal to curve25519 private key length
 */
int32_t CRYPT_CURVE25519_SetPrvKey(CRYPT_CURVE25519_Ctx *pkey, const CRYPT_Curve25519Prv *prv);

/**
 * @ingroup curve25519
* @brief curve25519 Obtain the private key.
 *
 * @param pkey [IN] curve25519 Key pair structure
 * @param prv [OUT] private key
 *
 * @retval CRYPT_SUCCESS                        successfully set.
 * @retval CRYPT_NULL_INPUT                     Any input parameter is empty.
 * @retval CRYPT_CURVE25519_NO_PRVKEY           The key pair has no private key.
 * @retval CRYPT_CURVE25519_KEYLEN_ERROR        prvKeyLen is less than the private key length of curve25519.
 */
int32_t CRYPT_CURVE25519_GetPrvKey(const CRYPT_CURVE25519_Ctx *pkey, CRYPT_Curve25519Prv *prv);

#ifdef HITLS_BSL_PARAMS
/**
 * @ingroup curve25519
 * @brief curve25519 Set the public key.
 *
 * @param pkey [IN] curve25519 Key pair structure
 * @param para  [IN] Public key
 *
 * @retval CRYPT_SUCCESS                        set successfully.
 * @retval CRYPT_NULL_INPUT                     If any input parameter is empty
 * @retval CRYPT_CURVE25519_KEYLEN_ERROR        pubKeyLen is not equal to curve25519 public key length
 */
int32_t CRYPT_CURVE25519_SetPubKeyEx(CRYPT_CURVE25519_Ctx *pkey, const BSL_Param *para);

/**
 * @ingroup curve25519
 * @brief curve25519 Set the private key.
 *
 * @param pkey [IN] curve25519 Key pair structure
 * @param para  [IN] Private key
 *
 * @retval CRYPT_SUCCESS                        set successfully.
 * @retval CRYPT_NULL_INPUT                     If any input parameter is empty
 * @retval CRYPT_CURVE25519_KEYLEN_ERROR        prvKeyLen is not equal to curve25519 private key length
 */
int32_t CRYPT_CURVE25519_SetPrvKeyEx(CRYPT_CURVE25519_Ctx *pkey, const BSL_Param *para);

/**
 * @ingroup curve25519
* @brief curve25519 Obtain the public key.
 *
 * @param pkey [IN] curve25519 Key pair structure
 * @param para  [OUT] Public key
 *
 * @retval CRYPT_SUCCESS                        set successfully.
 * @retval CRYPT_NULL_INPUT                     If any input parameter is empty
 * @retval CRYPT_CURVE25519_NO_PUBKEY           The key pair has no public key.
 * @retval CRYPT_CURVE25519_KEYLEN_ERROR        pubKeyLen is less than curve25519 public key length.
 */
int32_t CRYPT_CURVE25519_GetPubKeyEx(const CRYPT_CURVE25519_Ctx *pkey, BSL_Param *para);

/**
 * @ingroup curve25519
* @brief curve25519 Obtain the private key.
 *
 * @param pkey [IN] curve25519 Key pair structure
 * @param para [OUT] private key
 *
 * @retval CRYPT_SUCCESS                        successfully set.
 * @retval CRYPT_NULL_INPUT                     Any input parameter is empty.
 * @retval CRYPT_CURVE25519_NO_PRVKEY           The key pair has no private key.
 * @retval CRYPT_CURVE25519_KEYLEN_ERROR        prvKeyLen is less than the private key length of curve25519.
 */
int32_t CRYPT_CURVE25519_GetPrvKeyEx(const CRYPT_CURVE25519_Ctx *pkey, BSL_Param *para);
#endif

/**
 * @ingroup curve25519
 * @brief curve25519 Obtain the key length, in bits.
 *
 * @param pkey [IN] curve25519 Key pair structure
 *
 * @retval Key length
 */
int32_t CRYPT_CURVE25519_GetBits(const CRYPT_CURVE25519_Ctx *pkey);

#ifdef HITLS_CRYPTO_ED25519
/**
 * @ingroup curve25519
 * @brief curve25519 Sign
 *
 * @param pkey       [IN/OUT] curve25519 Key pair structure. A private key is required for signature.
 *                            After signature, a public key is generated.
 * @param algId      [IN] md algId
 * @param msg        [IN] Data to be signed
 * @param msgLen     [IN] Data length: 0 <= msgLen <= (2^125 - 64) bytes
 * @param hashMethod [IN] SHA512 method
 * @param sign       [OUT] Signature
 * @param signLen    [IN/OUT] Length of the signature buffer (must be greater than 64 bytes)/Length of the signature
 *
 * @retval CRYPT_SUCCESS                        generated successfully.
 * @retval CRYPT_CURVE25519_NO_PRVKEY           The key pair has no private key.
 * @retval CRYPT_NULL_INPUT                     If any input parameter is empty
 * @retval Error code of the hash module.       An error occurs in the sha512 operation.
 * @retval CRYPT_CURVE25519_NO_HASH_METHOD      No hash method is set.
 * @retval CRYPT_CURVE25519_SIGNLEN_ERROR       signLen is less than the signature length of curve25519.
 */
int32_t CRYPT_CURVE25519_Sign(CRYPT_CURVE25519_Ctx *pkey, int32_t algId, const uint8_t *msg,
    uint32_t msgLen, uint8_t *sign, uint32_t *signLen);

/**
 * @ingroup curve25519
 * @brief curve25519 Obtain the signature length, in bytes.
 *
 * @param pkey [IN] curve25519 Key pair structure
 *
 * @retval Signature length
 */
int32_t CRYPT_CURVE25519_GetSignLen(const CRYPT_CURVE25519_Ctx *pkey);

/**
 * @ingroup curve25519
 * @brief curve25519 Verification
 *
 * @param pkey    [IN] curve25519 Key pair structure. A public key is required for signature verification.
 * @param algId   [IN] md algId
 * @param msg     [IN] Data
 * @param msgLen  [IN] Data length: 0 <= msgLen <= (2^125 - 64) bytes
 * @param sign    [IN] Signature
 * @param signLen [IN] Signature length, which must be 64 bytes
 *
 * @retval CRYPT_SUCCESS                    The signature verification is successful.
 * @retval CRYPT_CURVE25519_NO_PUBKEY       The key pair has no public key.
 * @retval CRYPT_NULL_INPUT                 If any input parameter is empty
 * @retval Error code of the hash module.   An error occurs in the sha512 operation.
 * @retval CRYPT_CURVE25519_VERIFY_FAIL     Failed to verify the signature.
 * @retval CRYPT_CURVE25519_INVALID_PUBKEY  Invalid public key.
 * @retval CRYPT_CURVE25519_SIGNLEN_ERROR   signLen is not equal to curve25519 signature length
 * @retval CRYPT_CURVE25519_NO_HASH_METHOD  No hash method is set.
 */
int32_t CRYPT_CURVE25519_Verify(const CRYPT_CURVE25519_Ctx *pkey, int32_t algId, const uint8_t *msg,
    uint32_t msgLen, const uint8_t *sign, uint32_t signLen);

/**
 * @ingroup curve25519
 * @brief ed25519 Generate a key pair (public and private keys).
 *
 * @param pkey [IN/OUT] curve25519 Key pair structure/Key pair structure containing public and private keys
 *
 * @retval CRYPT_SUCCESS                        generated successfully.
 * @retval CRYPT_NO_REGIST_RAND                 Unregistered random number
 * @retval Error code of the hash module.       An error occurs during the SHA512 operation.
 * @retval Error code of the registered random number module. Failed to obtain the random number.
 * @retval CRYPT_CURVE25519_NO_HASH_METHOD      No hash method is set.
 * @retval CRYPT_NULL_INPUT                     The input parameter is empty.
 */
int32_t CRYPT_ED25519_GenKey(CRYPT_CURVE25519_Ctx *pkey);
#endif /* HITLS_CRYPTO_ED25519 */

#ifdef HITLS_CRYPTO_X25519
/**
 * @ingroup curve25519
 * @brief x25519 Calculate the shared key based on the private key of the local end and the public key of the peer end.
 *
 * @param prvKey      [IN] curve25519 Key pair structure, local private key
 * @param pubKey      [IN] curve25519 Key pair structure, peer public key
 * @param sharedKey   [OUT] Shared key
 * @param shareKeyLen [IN/OUT] Shared key length
 *
 * @retval CRYPT_SUCCESS                        generated successfully.
 * @retval CRYPT_CURVE25519_KEY_COMPUTE_FAILED  Failed to generate the shared key.
 */
int32_t CRYPT_CURVE25519_ComputeSharedKey(CRYPT_CURVE25519_Ctx *prvKey, CRYPT_CURVE25519_Ctx *pubKey,
    uint8_t *sharedKey, uint32_t *shareKeyLen);

/**
 * @ingroup curve25519
 * @brief x25519 Generate a key pair (public and private keys).
 *
 * @param pkey [IN/OUT] curve25519 Key pair structure/Key pair structure containing public and private keys
 *
 * @retval CRYPT_SUCCESS                        generated successfully.
 * @retval CRYPT_NO_REGIST_RAND                 Unregistered random number callback
 * @retval Error code of the registered random number module. Failed to obtain the random number.
 * @retval CRYPT_NULL_INPUT                     The input parameter is empty.
 */
int32_t CRYPT_X25519_GenKey(CRYPT_CURVE25519_Ctx *pkey);
#endif /* HITLS_CRYPTO_X25519 */

#ifdef HITLS_CRYPTO_CURVE25519_CMP
/**
 * @ingroup curve25519
 * @brief curve25519 Public key comparison
 *
 * @param a [IN] curve25519 Context structure
 * @param b [IN] curve25519 Context structure
 *
 * @retval CRYPT_SUCCESS                        is the same
 * @retval CRYPT_NULL_INPUT                     Invalid null pointer input
 * @retval CRYPT_CURVE25519_PUBKEY_NOT_EQUAL    Public Keys are not equal
 */
int32_t CRYPT_CURVE25519_Cmp(const CRYPT_CURVE25519_Ctx *a, const CRYPT_CURVE25519_Ctx *b);
#else
#define CRYPT_CURVE25519_Cmp NULL
#endif

/**
 * @ingroup curve25519
 * @brief curve25519 get security bits
 *
 * @param ctx [IN] curve25519 Context structure
 *
 * @retval security bits
 */
int32_t CRYPT_CURVE25519_GetSecBits(const CRYPT_CURVE25519_Ctx *ctx);

#ifdef HITLS_CRYPTO_KEY_DECODE_CHAIN
/**
 * @ingroup curve25519
 * @brief curve25519 import key
 *
 * @param ctx [IN/OUT] curve25519 context structure
 * @param params [IN] parameters
 */
int32_t CRYPT_CURVE25519_Import(CRYPT_CURVE25519_Ctx *ctx, const BSL_Param *params);

/**
 * @ingroup curve25519
 * @brief curve25519 export key
 *
 * @param ctx [IN] curve25519 context structure
 * @param params [IN/OUT] key parameters
 */
int32_t CRYPT_CURVE25519_Export(const CRYPT_CURVE25519_Ctx *ctx, BSL_Param *params);
#endif // HITLS_CRYPTO_KEY_DECODE_CHAIN

#ifdef HITLS_CRYPTO_ED25519_CHECK

/**
 * @ingroup ed25519
 * @brief ed25519 check key pair
 *
 * @param checkType [IN] check type
 * @param pkey1 [IN] ed25519 context structure
 * @param pkey2 [IN] ed25519 context structure
 *
 * @retval CRYPT_SUCCESS                        successfully.
 * @retval other                                error.
 */
int32_t CRYPT_ED25519_Check(uint32_t checkType, const CRYPT_CURVE25519_Ctx *pkey1, const CRYPT_CURVE25519_Ctx *pkey2);
#endif // HITLS_CRYPTO_ED25519_CHECK

#ifdef HITLS_CRYPTO_X25519_CHECK
/**
 * @ingroup x25519
 * @brief x25519 check key pair
 *
 * @param checkType [IN] check type
 * @param pkey1 [IN] x25519 context structure
 * @param pkey2 [IN] x25519 context structure
 *
 * @retval CRYPT_SUCCESS                        successfully.
 * @retval other                                error.
 */
int32_t CRYPT_X25519_Check(uint32_t checkType, const CRYPT_CURVE25519_Ctx *pkey1, const CRYPT_CURVE25519_Ctx *pkey2);

#endif // HITLS_CRYPTO_X25519_CHECK

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_CURVE25519

#endif // CRYPT_CURVE25519_H

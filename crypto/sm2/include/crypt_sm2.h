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

#ifndef CRYPT_SM2_H
#define CRYPT_SM2_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM2

#include <stdint.h>
#include "crypt_types.h"
#include "crypt_ecc.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef struct SM2_Ctx CRYPT_SM2_Ctx;
/* SM2 parameter structure */
typedef struct EccPara CRYPT_Sm2Para;

/**
 * @ingroup sm2
 * @brief sm2 Allocate the context memory space.
 *
 * @retval (CRYPT_SM2_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL              Invalid null pointer.
 */
CRYPT_SM2_Ctx *CRYPT_SM2_NewCtx(void);

/**
 * @ingroup sm2
 * @brief sm2 Allocate the context memory space.
 *
 * @param libCtx [IN] Library context
 *
 * @retval (CRYPT_SM2_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL              Invalid null pointer.
 */
CRYPT_SM2_Ctx *CRYPT_SM2_NewCtxEx(void *libCtx);

/**
 * @ingroup sm2
 * @brief Copy the sm2 context. After the duplication is complete, invoke the CRYPT_SM2_FreeCtx to release the memory.
 *
 * @param ctx [IN] Source SM2 context
 *
 * @return CRYPT_SM2_Ctx SM2 context pointer=
 */
CRYPT_SM2_Ctx *CRYPT_SM2_DupCtx(CRYPT_SM2_Ctx *ctx);

/**
 * @ingroup sm2
 * @brief release sm2 key context structure
 *
 * @param ctx [IN] Context structure to be released.
 */
void CRYPT_SM2_FreeCtx(CRYPT_SM2_Ctx *ctx);

/**
 * @ingroup sm2
 * @brief sm2 Obtain the key length.
 *
 * @param ctx [IN] sm2 context structure
 *
 * @retval 0        The input is incorrect or the corresponding key structure does not contain valid key length.
 * @retval uint32_t Valid key length
 */
uint32_t CRYPT_SM2_GetBits(const CRYPT_SM2_Ctx *ctx);

/**
 * @ingroup sm2
 * @brief Generate the SM2 key pair.
 *
 * @param ctx [IN/OUT] sm2 context structure
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval ECC error code.      An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS        The key pair is successfully generated.
 */
int32_t CRYPT_SM2_Gen(CRYPT_SM2_Ctx *ctx);

#ifdef HITLS_CRYPTO_SM2_SIGN
/**
 * @ingroup sm2
 * @brief sm2 obtain the length of the signature data, in bytes.
 *
 * @param ctx [IN] sm2 context structure
 *
 * @retval 0        The input is incorrect or the corresponding key structure does not contain valid parameter data.
 * @retval uint32_t Length required for valid signature data
 */
uint32_t CRYPT_SM2_GetSignLen(const CRYPT_SM2_Ctx *ctx);

/**
 * @ingroup sm2
 * @brief SM2 Signature
 *
 * @param ctx [IN] sm2 context structure
 * @param algId [IN] md algId
 * @param data [IN] Data to be signed
 * @param dataLen [IN] Length of the data to be signed
 * @param sign [OUT] Signature data
 * @param signLen [IN/OUT] The input parameter is the space length of the sign,
 *                         and the output parameter is the valid length of the sign.
 *                         The required space can be obtained by calling CRYPT_SM2_GetSignLen.
 *
 * @retval CRYPT_NULL_INPUT                 Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval CRYPT_SM2_ERR_EMPTY_KEY          The key cannot be empty.
 * @retval CRYPT_SM2_BUFF_LEN_NOT_ENOUGH    The buffer length is insufficient.
 * @retval BN error.                        An error occurs in the internal BigNum operation.
 * @retval ECC error.                       An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS                    Signed successfully.
 */
int32_t CRYPT_SM2_Sign(const CRYPT_SM2_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen);

/**
 * @ingroup sm2
 * @brief SM2 Verify the signature.
 *
 * @param ctx [IN] sm2 context structure
 * @param algId [IN] md algId
 * @param data [IN] Data to be signed
 * @param dataLen [IN] Length of the data to be signed
 * @param sign [IN] Signature data
 * @param signLen [IN] Valid length of the sign
 *
 * @retval CRYPT_NULL_INPUT         Invalid null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval CRYPT_SM2_VERIFY_FAIL    Failed to verify the signature.
 * @retval BN error.                An error occurs in the internal BigNum operation.
 * @retval ECC error.               An error occurred in the internal ECC calculation.
 * @retval DSA error.               An error occurs in the DSA encoding and decoding part.
 * @retval CRYPT_SUCCESS            The signature verification is successful.
 */
int32_t CRYPT_SM2_Verify(const CRYPT_SM2_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen);
#endif

/**
 * @ingroup sm2
 * @brief SM2 Set the private key data.
 *
 * @param ctx [OUT] sm2 context structure
 * @param prv [IN] External private key data
 *
 * @retval CRYPT_NULL_INPUT     Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval ECC error.           An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS        set successfully.
 */
int32_t CRYPT_SM2_SetPrvKey(CRYPT_SM2_Ctx *ctx, const CRYPT_Sm2Prv *prv);

/**
 * @ingroup sm2
 * @brief SM2 Set the public key data.
 *
 * @param ctx [OUT] sm2 context structure
 * @param pub [IN] External public key data
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval ECC error.           An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS        set successfully.
 */
int32_t CRYPT_SM2_SetPubKey(CRYPT_SM2_Ctx *ctx, const CRYPT_Sm2Pub *pub);

/**
 * @ingroup sm2
 * @brief SM2 Obtain the private key data.
 *
 * @param ctx [IN] sm2 context structure
 * @param prv [OUT] External private key data
 *
 * @retval CRYPT_NULL_INPUT             Error null pointer input
 * @retval CRYPT_ECC_PKEY_ERR_EMPTY_KEY The key is empty.
 * @retval ECC error.                   An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS                obtained successfully.
 */
int32_t CRYPT_SM2_GetPrvKey(const CRYPT_SM2_Ctx *ctx, CRYPT_Sm2Prv *prv);

/**
 * @ingroup sm2
 * @brief SM2 Obtain the public key data.
 *
 * @param ctx [IN] sm2 context structure
 * @param pub [OUT] External public key data
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval CRYPT_ECC_PKEY_ERR_EMPTY_KEY The key is empty.
 * @retval ECC error.                   An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS                Obtained successfully.
 */
int32_t CRYPT_SM2_GetPubKey(const CRYPT_SM2_Ctx *ctx, CRYPT_Sm2Pub *pub);

#ifdef HITLS_BSL_PARAMS
/**
 * @ingroup sm2
 * @brief SM2 Set the private key data.
 *
 * @param ctx [OUT] sm2 context structure
 * @param para [IN] External private key data
 *
 * @retval CRYPT_NULL_INPUT     Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval ECC error.           An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS        set successfully.
 */
int32_t CRYPT_SM2_SetPrvKeyEx(CRYPT_SM2_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup sm2
 * @brief SM2 Set the public key data.
 *
 * @param ctx [OUT] sm2 context structure
 * @param para [IN] External public key data
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval ECC error.           An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS        set successfully.
 */
int32_t CRYPT_SM2_SetPubKeyEx(CRYPT_SM2_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup sm2
 * @brief SM2 Obtain the private key data.
 *
 * @param ctx [IN] sm2 context structure
 * @param para [OUT] External private key data
 *
 * @retval CRYPT_NULL_INPUT             Error null pointer input
 * @retval CRYPT_ECC_PKEY_ERR_EMPTY_KEY The key is empty.
 * @retval ECC error.                   An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS                obtained successfully.
 */
int32_t CRYPT_SM2_GetPrvKeyEx(const CRYPT_SM2_Ctx *ctx, BSL_Param *para);

/**
 * @ingroup sm2
 * @brief SM2 Obtain the public key data.
 *
 * @param ctx [IN] sm2 context structure
 * @param para [OUT] External public key data
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval CRYPT_ECC_PKEY_ERR_EMPTY_KEY The key is empty.
 * @retval ECC error.                   An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS                Obtained successfully.
 */
int32_t CRYPT_SM2_GetPubKeyEx(const CRYPT_SM2_Ctx *ctx, BSL_Param *para);
#endif

/**
 * @ingroup sm2
 * @brief sm2 control interface
 *
 * @param ctx [IN/OUT] sm2 context structure
 * @param opt [IN] Operation mode. For details, see ECC_CtrlType.
 * @param val [IN] Input parameter
 * @param len [IN] val Length
 *
 * @retval CRYPT_SUCCESS        set successfully.
 * @retval CRYPT_NULL_INPUT     If any input parameter is empty
 * @retval For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_SM2_Ctrl(CRYPT_SM2_Ctx *ctx, int32_t opt, void *val, uint32_t len);

#ifdef HITLS_CRYPTO_SM2_EXCH
/**
 * @ingroup sm2
 * @brief sm2 Generate the shared key.
 *
 * @param selfCtx [IN] Local context structure
 * @param peerCtx [IN] Peer context structure
 * @param out [OUT] Generated shared key
 * @param outlen [IN/OUT] Length of the generated shared key
 *
 * @retval CRYPT_SUCCESS        secceeded.
 * @retval CRYPT_NULL_INPUT     If any input parameter is empty
 * @retval For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_SM2_KapComputeKey(const CRYPT_SM2_Ctx *selfCtx, const CRYPT_SM2_Ctx *peerCtx, uint8_t *out,
    uint32_t *outlen);
#endif

#ifdef HITLS_CRYPTO_SM2_CRYPT
/**
 * @ingroup sm2
 * @brief sm2 Encryption
 * @param ctx [IN] Context structure
 * @param data [IN] Plaintext
 * @param datalen [IN] Plaintext length
 * @param out [OUT] Output ciphertext
 * @param outlen [OUT] Ciphertext length
 *
 * @retval CRYPT_SUCCESS        secceeded.
 * @retval CRYPT_NULL_INPUT     If any input parameter is empty
 * @retval For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_SM2_Encrypt(CRYPT_SM2_Ctx *ctx, const uint8_t *data, uint32_t datalen, uint8_t *out, uint32_t *outlen);

/**
 * @ingroup sm2
 * @brief sm2 Decryption
 * @param ctx [IN] Context structure
 * @param data [IN] Received ciphertext
 * @param datalen [IN] Ciphertext length
 * @param out [OUT] Output plaintext after decryption
 * @param outlen [OUT] Length of the decrypted plaintext
 *
 * @retval CRYPT_SUCCESS        secceeded.
 * @retval CRYPT_NULL_INPUT     If any input parameter is empty
 * @retval For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_SM2_Decrypt(CRYPT_SM2_Ctx *ctx, const uint8_t *data, uint32_t datalen, uint8_t *out, uint32_t *outlen);
#endif

#ifdef HITLS_CRYPTO_SM2_CMP
/**
 * @ingroup sm2
 * @brief sm2 Compare the public key and parameters.
 *
 * @param a [IN] sm2 context structure
 * @param b [IN] sm2 context structure
 *
 * @retval CRYPT_SUCCESS is the same
 * For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_SM2_Cmp(const CRYPT_SM2_Ctx *a, const CRYPT_SM2_Ctx *b);
#else
#define CRYPT_SM2_Cmp NULL
#endif

/**
 * @ingroup sm2
 * @brief sm2 get security bits
 *
 * @param ctx [IN] sm2 Context structure
 *
 * @retval security bits
 */
int32_t CRYPT_SM2_GetSecBits(const CRYPT_SM2_Ctx *ctx);

#ifdef HITLS_CRYPTO_KEY_DECODE_CHAIN
/**
 * @ingroup sm2
 * @brief sm2 import key
 *
 * @param ctx [IN/OUT] sm2 context structure
 * @param params [IN] key parameters
 */
int32_t CRYPT_SM2_Import(CRYPT_SM2_Ctx *ctx, const BSL_Param *params);

/**
 * @ingroup sm2
 * @brief sm2 export key
 *
 * @param ctx [IN] sm2 context structure
 * @param params [IN/OUT] key parameters
 */
int32_t CRYPT_SM2_Export(const CRYPT_SM2_Ctx *ctx, BSL_Param *params);
#endif

#ifdef HITLS_CRYPTO_SM2_CHECK
/**
 * @ingroup sm2
 * @brief sm2 check public key
 *
 * @param checkType [IN] check type
 * @param pkey1 [IN] sm2 context structure
 * @param pkey2 [IN] sm2 context structure
 *
 * @retval CRYPT_SUCCESS    is the same
 * Others. For details, see error code in errno.
 */
int32_t CRYPT_SM2_Check(uint32_t checkType, const CRYPT_SM2_Ctx *pkey1, const CRYPT_SM2_Ctx *pkey2);

#endif // HITLS_CRYPTO_SM2_CHECK

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM2

#endif // CRYPT_SM2_H

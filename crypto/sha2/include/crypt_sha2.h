/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_SHA2_H
#define CRYPT_SHA2_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SHA2

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

/** @defgroup LLF SHA2 Low level function */

#ifdef HITLS_CRYPTO_SHA224
#define CRYPT_SHA2_224_BLOCKSIZE  64
#define CRYPT_SHA2_224_DIGESTSIZE 28
#endif // HITLS_CRYPTO_SHA224

#ifdef HITLS_CRYPTO_SHA256
#define CRYPT_SHA2_256_BLOCKSIZE  64
#define CRYPT_SHA2_256_DIGESTSIZE 32
#endif // HITLS_CRYPTO_SHA256

#ifdef HITLS_CRYPTO_SHA384
#define CRYPT_SHA2_384_BLOCKSIZE  128
#define CRYPT_SHA2_384_DIGESTSIZE 48
#endif // HITLS_CRYPTO_SHA384

#ifdef HITLS_CRYPTO_SHA512
#define CRYPT_SHA2_512_BLOCKSIZE  128
#define CRYPT_SHA2_512_DIGESTSIZE 64
#endif // HITLS_CRYPTO_SHA512

#ifdef HITLS_CRYPTO_SHA256
typedef struct {
    uint32_t h[CRYPT_SHA2_256_DIGESTSIZE / sizeof(uint32_t)]; /* 256 bits for SHA256 state */
    uint32_t block[CRYPT_SHA2_256_BLOCKSIZE / sizeof(uint32_t)]; /* 512 bits block cache */
    uint32_t lNum, hNum;                                           /* input bits counter, max 2^64 bits */
    uint32_t blocklen;                                     /* block length */
    uint32_t outlen;                                       /* digest output length */
    uint32_t errorCode; /* error Code */
} CRYPT_SHA2_256_Ctx;
#endif // HITLS_CRYPTO_SHA256

#ifdef HITLS_CRYPTO_SHA224
typedef CRYPT_SHA2_256_Ctx CRYPT_SHA2_224_Ctx;
#endif // HITLS_CRYPTO_SHA224

#ifdef HITLS_CRYPTO_SHA512
typedef struct {
    uint64_t h[CRYPT_SHA2_512_DIGESTSIZE / sizeof(uint64_t)];
    uint8_t block[CRYPT_SHA2_512_BLOCKSIZE];
    uint64_t lNum, hNum;
    uint32_t num, mdlen;
    uint32_t errorCode; /* error Code */
} CRYPT_SHA2_512_Ctx;
#endif // HITLS_CRYPTO_SHA512

#ifdef HITLS_CRYPTO_SHA384
typedef CRYPT_SHA2_512_Ctx CRYPT_SHA2_384_Ctx;
#endif // HITLS_CRYPTO_SHA384

#ifdef HITLS_CRYPTO_SHA224
/**
 * @defgroup CRYPT_SHA2_224_Init
 * @ingroup LLF Low Level Functions
 * @par Prototype
 * @code
 * int32_t CRYPT_SHA2_224_Init(CRYPT_SHA2_224_Ctx *ctx)
 * @endcode
 *
 * @par Purpose
 * This is used to initialize the SHA224 ctx for a digest operation.
 *
 * @par Description
 * CRYPT_SHA2_224_Init function initializes the ctx for a digest operation. This function must be called before
 * CRYPT_SHA2_224_Update or CRYPT_SHA2_224_Final operations. This function will not allocate memory for any of the
 * ctx variables. Instead the caller is expected to pass a ctx pointer pointing to a valid memory location
 * (either locally or dynamically allocated).
 *
 * @param[in] ctx The sha224 ctx
 *
 * @retval #CRYPT_SUCCESS ctx is initialized
 * @retval #CRYPT_NULL_INPUT ctx is NULL
 */
int32_t CRYPT_SHA2_224_Init(CRYPT_SHA2_224_Ctx *ctx);

/**
 * @defgroup CRYPT_SHA2_224_Update
 * @ingroup LLF Low Level Functions
 * @par Prototype
 * @code
 * int32_t CRYPT_SHA2_224_Update(CRYPT_SHA2_224_Ctx *ctx, const uint8_t *data, usize_t nbytes)
 * @endcode
 *
 * @par Purpose
 * This is used to perform sha224 digest operation on chunks of data.
 *
 * @par Description
 * CRYPT_SHA2_224_Update function performs digest operation on chunks of data. This method of digesting is used when
 * data is present in multiple buffers or not available all at once. CRYPT_SHA2_224_Init must have been called before
 * calling this function.
 *
 * @param[in] ctx The sha224 ctx
 * @param[in] data The input data
 * @param[in] nbytes The input data length
 *
 * @retval #CRYPT_SUCCESS If partial digest is calculated
 * @retval #CRYPT_NULL_INPUT input arguments is NULL
 * @retval #CRYPT_SHA2_ERR_OVERFLOW input message is overflow
 */
int32_t CRYPT_SHA2_224_Update(CRYPT_SHA2_224_Ctx *ctx, const uint8_t *data, uint32_t nbytes);

/**
 * @defgroup CRYPT_SHA2_224_Final
 * @ingroup LLF Low Level Functions
 * @par Prototype
 * @code
 * int32_t CRYPT_SHA2_224_Final(CRYPT_SHA2_224_Ctx *ctx, uint8_t *digest, uint32_t *len)
 * @endcode
 *
 * @par Purpose
 * This is used to complete sha224 digest operation on remaining data, and is
 * called at the end of digest operation.
 *
 * @par Description
 * CRYPT_SHA2_224_Final function completes digest operation on remaining data, and is called at the end of digest
 * operation. CRYPT_SHA2_224_Init must have been called before calling this function. This function calculates the
 * digest. The memory for digest must already have been allocated.
 *
 * @param[in] ctx The sha224 ctx
 * @param[out] digest The digest
 *
 * @retval #CRYPT_SUCCESS If partial digest is calculated
 * @retval #CRYPT_NULL_INPUT input arguments is NULL
 * @retval #CRYPT_SHA2_ERR_OVERFLOW input message is overflow
 * @retval #CRYPT_SHA2_OUT_BUFF_LEN_NOT_ENOUGH output buffer is not enough
 */
int32_t CRYPT_SHA2_224_Final(CRYPT_SHA2_224_Ctx *ctx, uint8_t *digest, uint32_t *len);
#endif // HITLS_CRYPTO_SHA224

#ifdef HITLS_CRYPTO_SHA256
/**
 * @defgroup CRYPT_SHA2_256_Init
 * @ingroup LLF Low Level Functions
 * @par Prototype
 * @code
 * int32_t CRYPT_SHA2_256_Init(CRYPT_SHA2_256_Ctx *ctx)
 * @endcode
 *
 * @par Purpose
 * This is used to initialize the SHA256 ctx for a digest operation.
 *
 * @par Description
 * CRYPT_SHA2_256_Init function initializes the ctx for
 * a digest operation. This function must be called before
 * CRYPT_SHA2_256_Update or CRYPT_SHA2_256_Final operations. This function will not
 * allocate memory for any of the ctx variables. Instead the caller is
 * expected to pass a ctx pointer pointing to a valid memory location
 * (either locally or dynamically allocated).
 *
 * @param[in] ctx The sha256 ctx
 *
 * @retval #CRYPT_SUCCESS ctx is initialized
 * @retval #CRYPT_NULL_INPUT ctx is NULL
 */
int32_t CRYPT_SHA2_256_Init(CRYPT_SHA2_256_Ctx *ctx);

/**
 * @defgroup CRYPT_SHA2_256_Update
 * @ingroup LLF Low Level Functions
 * @par Prototype
 * @code
 * int32_t CRYPT_SHA2_256_Update(CRYPT_SHA2_256_Ctx *ctx, const uint8_t *data, usize_t nbytes)
 * @endcode
 *
 * @par Purpose
 * This is used to perform sha256 digest operation on chunks of data.
 *
 * @par Description
 * CRYPT_SHA2_256_Update function performs digest operation on
 * chunks of data. This method of digesting is used when data is
 * present in multiple buffers or not available all at once.
 * CRYPT_SHA2_256_Init must have been called before calling this
 * function.
 *
 * @param[in] ctx The sha256 ctx
 * @param[in] data The input data
 * @param[in] nbytes The input data length
 *
 * @retval #CRYPT_SUCCESS If partial digest is calculated
 * @retval #CRYPT_NULL_INPUT input arguments is NULL
 * @retval #CRYPT_SHA2_ERR_OVERFLOW input message is overflow
 */
int32_t CRYPT_SHA2_256_Update(CRYPT_SHA2_256_Ctx *ctx, const uint8_t *data, uint32_t nbytes);

/**
 * @defgroup CRYPT_SHA2_256_Final
 * @ingroup LLF Low Level Functions
 * @par Prototype
 * @code
 * int32_t CRYPT_SHA2_256_Final(CRYPT_SHA2_256_Ctx *ctx, uint8_t *digest, uint32_t *len)
 * @endcode
 *
 * @par Purpose
 * This is used to complete sha256 digest operation on remaining data, and is
 * called at the end of digest operation.
 *
 * @par Description
 * CRYPT_SHA2_256_Final function completes digest operation on remaining data, and
 * is called at the end of digest operation.
 * CRYPT_SHA2_256_Init must have been called before calling this function. This
 * function calculates the digest. The memory for digest must
 * already have been allocated.
 *
 * @param[in] ctx The sha256 ctx
 * @param[out] digest The digest
 *
 * @retval #CRYPT_SUCCESS If partial digest is calculated
 * @retval #CRYPT_NULL_INPUT input arguments is NULL
 * @retval #CRYPT_SHA2_ERR_OVERFLOW input message is overflow
 * @retval #CRYPT_SHA2_OUT_BUFF_LEN_NOT_ENOUGH output buffer is not enough
 */
int32_t CRYPT_SHA2_256_Final(CRYPT_SHA2_256_Ctx *ctx, uint8_t *digest, uint32_t *outlen);
#endif // HITLS_CRYPTO_SHA256

#ifdef HITLS_CRYPTO_SHA384
/**
 * @ingroup LLF Low Level Functions
 * @par Prototype
 * @code
 * int32_t CRYPT_SHA2_384_Init(CRYPT_SHA2_384_Ctx *ctx)
 * @endcode
 *
 * @par Purpose
 * This is used to initialize the SHA384 ctx for a digest operation.
 *
 * @par Description
 * CRYPT_SHA2_384_Init function initializes the ctx for a digest operation. This function must be called before
 * CRYPT_SHA2_384_Update or CRYPT_SHA2_384_Final operations. This function will not allocate memory for any of the
 * ctx variables. Instead the caller is expected to pass a ctx pointer pointing to a valid memory location
 * (either locally or dynamically allocated).
 *
 * @param[in,out] ctx The sha384 ctx
 *
 * @retval #CRYPT_SUCCESS ctx is initialized
 * @retval #CRYPT_NULL_INPUT ctx is NULL
 */
int32_t CRYPT_SHA2_384_Init(CRYPT_SHA2_384_Ctx *ctx);

/**
 * @ingroup LLF Low Level Functions
 * @par Prototype
 * @code
 * int32_t CRYPT_SHA2_384_Update(CRYPT_SHA2_384_Ctx *ctx, const uint8_t *data, uint32_t nbytes)
 * @endcode
 *
 * @par Purpose
 * This is used to perform sha384 digest operation on chunks of data.
 *
 * @par Description
 * CRYPT_SHA2_384_Update function performs digest operation on chunks of data. This method of digesting is used when
 * data is present in multiple buffers or not available all at once. CRYPT_SHA2_384_Init must have been called before
 * calling this function.
 *
 * @param[in,out] ctx The sha384 ctx
 * @param[in] data The input data
 * @param[in] nbytes The input data length
 *
 * @retval #CRYPT_SUCCESS If partial digest is calculated
 * @retval #CRYPT_NULL_INPUT input arguments is NULL
 * @retval #CRYPT_SHA2_INPUT_OVERFLOW input message is overflow
 * @retval #CRYPT_SECUREC_FAIL secure c function fail.
 */
int32_t CRYPT_SHA2_384_Update(CRYPT_SHA2_384_Ctx *ctx, const uint8_t *data, uint32_t nbytes);
/**
 * @ingroup LLF Low Level Functions
 * @par Prototype
 * @code
 * int32_t CRYPT_SHA2_384_Final(CRYPT_SHA2_384_Ctx *ctx, uint8_t *digest, uint32_t *len)
 * @endcode
 *
 * @par Purpose
 * This is used to complete sha384 digest operation on remaining data, and is
 * called at the end of digest operation.
 *
 * @par Description
 * CRYPT_SHA2_384_Final function completes digest operation on remaining data, and is called at the end of digest
 * operation. CRYPT_SHA2_384_Init must have been called before calling this function. This function calculates the
 * digest. The memory for digest must already have been allocated.
 *
 * @param[in,out] ctx The sha384 ctx
 * @param[out] digest The digest
 * @param[in,out] len length of buffer
 *
 * @retval #CRYPT_SUCCESS If partial digest is calculated
 * @retval #CRYPT_NULL_INPUT input arguments is NULL
 * @retval #CRYPT_SHA2_INPUT_OVERFLOW input message is overflow
 * @retval #CRYPT_SHA2_OUT_BUFF_LEN_NOT_ENOUGH output buffer is not enough
 */
int32_t CRYPT_SHA2_384_Final(CRYPT_SHA2_384_Ctx *ctx, uint8_t *digest, uint32_t *len);
#endif // HITLS_CRYPTO_SHA384

#ifdef HITLS_CRYPTO_SHA512
/**
 * @ingroup LLF Low Level Functions
 * @par Prototype
 * @code
 * int32_t CRYPT_SHA2_512_Init(CRYPT_SHA2_512_Ctx *ctx)
 * @endcode
 *
 * @par Purpose
 * This is used to initialize the SHA512 ctx for a digest operation.
 *
 * @par Description
 * CRYPT_SHA2_512_Init function initializes the ctx for a digest operation. This function must be called before
 * CRYPT_SHA2_512_Update or CRYPT_SHA2_512_Final operations. This function will not allocate memory for any of the
 * ctx variable. Instead the caller is expected to pass a ctx pointer pointing to a valid memory location
 * (either locally or dynamically allocated).
 *
 * @param[in,out] ctx The sha512 ctx
 *
 * @retval #CRYPT_SUCCESS ctx is initialized
 * @retval #CRYPT_NULL_INPUT ctx is NULL
 */
int32_t CRYPT_SHA2_512_Init(CRYPT_SHA2_512_Ctx *ctx);

/**
 * @ingroup LLF Low Level Functions
 * @par Prototype
 * @code
 * int32_t CRYPT_SHA2_512_Update(CRYPT_SHA2_512_Ctx *ctx, const uint8_t *data, usize_t nbytes)
 * @endcode
 *
 * @par Purpose
 * This is used to perform sha512 digest operation on chunks of data.
 *
 * @par Description
 * CRYPT_SHA2_512_Update function performs digest operation on chunks of data. This method of digesting is used when
 * data is present in multiple buffers or not available all at once. CRYPT_SHA2_512_Init must have been called before
 * calling this function.
 *
 * @param[in,out] ctx The sha512 ctx
 * @param[in] data The input data
 * @param[in] nbytes The input data length
 *
 * @retval #CRYPT_SUCCESS If partial digest is calculated
 * @retval #CRYPT_NULL_INPUT input arguments is NULL
 * @retval #CRYPT_SHA2_INPUT_OVERFLOW input message is overflow
 * @retval #CRYPT_SECUREC_FAIL secure c function fail.
 */
int32_t CRYPT_SHA2_512_Update(CRYPT_SHA2_512_Ctx *ctx, const uint8_t *data, uint32_t nbytes);

/**
 * @ingroup LLF Low Level Functions
 * @par Prototype
 * @code
 * int32_t CRYPT_SHA2_512_Final(CRYPT_SHA2_512_Ctx *ctx, uint8_t *digest, uint32_t *len)
 * @endcode
 *
 * @par Purpose
 * This is used to complete sha512 digest operation on remaining data, and is called at the end of digest operation.
 *
 * @par Description
 * CRYPT_SHA2_512_Final function completes digest operation on remaining data, and is called at the end of digest
 * operation. CRYPT_SHA2_512_Init must have been called before calling this function. This function calculates the
 * digest. The memory for digest must already have been allocated.
 *
 * @param[in,out] ctx The sha512 ctx
 * @param[out] digest The digest
 * @param[in,out] len length of buffer
 *
 * @retval #CRYPT_SUCCESS If partial digest is calculated
 * @retval #CRYPT_NULL_INPUT input arguments is NULL
 * @retval #CRYPT_SHA2_INPUT_OVERFLOW input message is overflow
 * @retval #CRYPT_SHA2_OUT_BUFF_LEN_NOT_ENOUGH output buffer is not enough
 */
int32_t CRYPT_SHA2_512_Final(CRYPT_SHA2_512_Ctx *ctx, uint8_t *digest, uint32_t *len);
#endif // HITLS_CRYPTO_SHA512

#ifdef HITLS_CRYPTO_SHA224
/**
 * @ingroup LLF Low Level Functions
 *
 * @brief SHA224 deinit function
 *
 * @param[in,out] ctx The SHA224 ctx
 */
void CRYPT_SHA2_224_Deinit(CRYPT_SHA2_224_Ctx *ctx);

int32_t CRYPT_SHA2_224_CopyCtx(CRYPT_SHA2_224_Ctx *dst, CRYPT_SHA2_224_Ctx *src);
#endif // HITLS_CRYPTO_SHA224

#ifdef HITLS_CRYPTO_SHA256
/**
 * @ingroup LLF Low Level Functions
 *
 * @brief SHA256 deinit function
 *
 * @param[in,out] ctx The SHA256 ctx
 */
void CRYPT_SHA2_256_Deinit(CRYPT_SHA2_256_Ctx *ctx);

int32_t CRYPT_SHA2_256_CopyCtx(CRYPT_SHA2_256_Ctx *dst, CRYPT_SHA2_256_Ctx *src);
#endif // HITLS_CRYPTO_SHA256

#ifdef HITLS_CRYPTO_SHA384
/**
 * @ingroup LLF Low Level Functions
 *
 * @brief SHA384 deinit function
 *
 * @param[in,out] ctx The SHA384 ctx
 */
void CRYPT_SHA2_384_Deinit(CRYPT_SHA2_384_Ctx *ctx);

int32_t CRYPT_SHA2_384_CopyCtx(CRYPT_SHA2_384_Ctx *dst, CRYPT_SHA2_384_Ctx *src);
#endif // HITLS_CRYPTO_SHA384

#ifdef HITLS_CRYPTO_SHA512
/**
 * @ingroup LLF Low Level Functions
 *
 * @brief SHA512 deinit function
 *
 * @param[in,out] ctx The SHA512 ctx
 */
void CRYPT_SHA2_512_Deinit(CRYPT_SHA2_512_Ctx *ctx);

int32_t CRYPT_SHA2_512_CopyCtx(CRYPT_SHA2_512_Ctx *dst, CRYPT_SHA2_512_Ctx *src);
#endif // HITLS_CRYPTO_SHA512

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA2

#endif // CRYPT_SHA2_H

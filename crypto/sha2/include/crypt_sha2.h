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

#ifndef CRYPT_SHA2_H
#define CRYPT_SHA2_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SHA2

#include <stdint.h>
#include <stdlib.h>
#include "crypt_types.h"
#include "bsl_params.h"

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
#define CRYPT_SHA256_STATE_SIZE   8
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
/* SHA2 256 ctx */
typedef struct CryptSha256Ctx {
    uint32_t h[CRYPT_SHA256_STATE_SIZE]; /* 256 bits for SHA256 state */
    uint32_t block[CRYPT_SHA2_256_BLOCKSIZE / sizeof(uint32_t)]; /* 512 bits block cache */
    uint32_t lNum, hNum;                                           /* input bits counter, max 2^64 bits */
    uint32_t blocklen;                                     /* block length */
    uint32_t outlen;                                       /* digest output length */
    uint32_t errorCode; /* error Code */
} CRYPT_SHA2_256_Ctx;
#endif

#ifdef HITLS_CRYPTO_SHA224
/* SHA2 224 ctx */
typedef struct CryptSha256Ctx CRYPT_SHA2_224_Ctx;
#endif

#ifdef HITLS_CRYPTO_SHA512
/* SHA2 512 ctx */
typedef struct CryptSha2512Ctx {
    uint64_t h[CRYPT_SHA2_512_DIGESTSIZE / sizeof(uint64_t)];
    uint8_t block[CRYPT_SHA2_512_BLOCKSIZE];
    uint64_t lNum, hNum;
    uint32_t num, mdlen;
    uint32_t errorCode; /* error Code */
} CRYPT_SHA2_512_Ctx;
#endif

#ifdef HITLS_CRYPTO_SHA384
/* SHA2 384 ctx */
typedef struct CryptSha2512Ctx CRYPT_SHA2_384_Ctx;
#endif

#define CRYPT_SHA2_224_Squeeze NULL
#define CRYPT_SHA2_256_Squeeze NULL
#define CRYPT_SHA2_384_Squeeze NULL
#define CRYPT_SHA2_512_Squeeze NULL

#ifdef HITLS_CRYPTO_SHA224

#define CRYPT_SHA2_224_NewCtx CRYPT_SHA2_256_NewCtx
#define CRYPT_SHA2_224_NewCtxEx CRYPT_SHA2_256_NewCtxEx
#define CRYPT_SHA2_224_FreeCtx CRYPT_SHA2_256_FreeCtx
#define CRYPT_SHA2_224_Deinit CRYPT_SHA2_256_Deinit
#define CRYPT_SHA2_224_CopyCtx CRYPT_SHA2_256_CopyCtx
#define CRYPT_SHA2_224_DupCtx CRYPT_SHA2_256_DupCtx
#define CRYPT_SHA2_224_Update CRYPT_SHA2_256_Update
#define CRYPT_SHA2_224_Final CRYPT_SHA2_256_Final

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
 * @param *param [in] Pointer to the parameter.
 *
 * @retval #CRYPT_SUCCESS ctx is initialized
 * @retval #CRYPT_NULL_INPUT ctx is NULL
 */
int32_t CRYPT_SHA2_224_Init(CRYPT_SHA2_224_Ctx *ctx);

/**
 * @ingroup SHA224
 * @brief This API is used to initialize the SHA224 context.
 *
 * @param ctx [in,out] Pointer to the SHA224 context.
 * @param param [in] param.
 *
 * @retval #CRYPT_SUCCESS       Initialization succeeded.
 * @retval #CRYPT_NULL_INPUT    Pointer ctx is NULL
 */
int32_t CRYPT_SHA2_224_InitEx(CRYPT_SHA2_224_Ctx *ctx, void *param);

#ifdef HITLS_CRYPTO_PROVIDER
/**
 * @ingroup SHA224
 * @brief SHA224 get param function
 * @param ctx [in]   Pointer to the SHA224 context.
 * @param param [in]   Pointer to the parameter.
 *
 * @retval #CRYPT_SUCCESS       Success.
 * @retval #CRYPT_NULL_INPUT    Pointer param is NULL
 * @retval #CRYPT_INVALID_ARG   Pointer param is invalid
 */
int32_t CRYPT_SHA2_224_GetParam(CRYPT_SHA2_224_Ctx *ctx, BSL_Param *param);
#else
#define CRYPT_SHA2_224_GetParam NULL
#endif

#endif // HITLS_CRYPTO_SHA224

#ifdef HITLS_CRYPTO_SHA256

/**
 * @ingroup SHA2_256
 * @brief Generate md context.
 *
 * @retval Success: sha256 ctx.
 *         Fails: NULL.
 */
CRYPT_SHA2_256_Ctx *CRYPT_SHA2_256_NewCtx(void);

/**
 * @ingroup SHA2_256
 * @brief Generate md context.
 *
 * @param libCtx [IN] library context
 * @param algId [IN] algorithm id
 *
 * @retval Success: sha256 ctx.
 *         Fails: NULL.
 */
CRYPT_SHA2_256_Ctx *CRYPT_SHA2_256_NewCtxEx(void *libCtx, int32_t algId);

/**
 * @ingroup SHA2_256
 * @brief free md context.
 *
 * @param ctx [IN] md handle
 */
void CRYPT_SHA2_256_FreeCtx(CRYPT_SHA2_256_Ctx *ctx);

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
 * @param *param [in] Pointer to the parameter.
 *
 * @retval #CRYPT_SUCCESS ctx is initialized
 * @retval #CRYPT_NULL_INPUT ctx is NULL
 */
int32_t CRYPT_SHA2_256_Init(CRYPT_SHA2_256_Ctx *ctx);

/**
 * @ingroup SHA256
 * @brief This API is used to initialize the SHA256 context.
 *
 * @param ctx [in,out] Pointer to the SHA256 context.
 * @param param [in] param.
 *
 * @retval #CRYPT_SUCCESS       Initialization succeeded.
 * @retval #CRYPT_NULL_INPUT    Pointer ctx is NULL
 */
int32_t CRYPT_SHA2_256_InitEx(CRYPT_SHA2_256_Ctx *ctx, void *param);

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

typedef struct {
    uint32_t num;
    CRYPT_SHA2_256_Ctx *ctxs;
} CRYPT_SHA2_256_MB_Ctx;

/**
 * @ingroup SHA256
 * @brief   Create a SHA256 multi-buffer context.
 *
 * Notes:
 * - Currently only supports num == 2.
 *
 * @param   num [IN] Number of parallel messages/contexts.
 *
 * @retval  Pointer to multi-buffer context on success.
 * @retval  NULL on failure (invalid num or memory allocation failure).
 */
CRYPT_SHA2_256_MB_Ctx *CRYPT_SHA256_MBNewCtx(uint32_t num);

/**
 * @ingroup SHA256
 * @brief   Free a SHA256 multi-buffer context.
 *
 * @param   ctx [IN] Multi-buffer context pointer (can be NULL).
 */
void CRYPT_SHA256_MBFreeCtx(CRYPT_SHA2_256_MB_Ctx *ctx);

/**
 * @ingroup SHA256
 * @brief   Initialize a SHA256 multi-buffer context.
 *
 * Notes:
 * - Currently only supports ctx->num == 2.
 *
 * @param   ctx [IN/OUT] Multi-buffer context.
 *
 * @retval  #CRYPT_SUCCESS Success.
 * @retval  #CRYPT_NULL_INPUT ctx is NULL.
 * @retval  #CRYPT_NOT_SUPPORT Not supported (e.g. ctx->num != 2 or platform capability missing).
 */
int32_t CRYPT_SHA256_MBInit(CRYPT_SHA2_256_MB_Ctx *ctx);

/**
 * @ingroup SHA256
 * @brief   Update SHA256 multi-buffer context with message fragments.
 *
 * Notes:
 * - Each update processes one fragment per message, where data[i] is the fragment for lane i.
 * - nbytes[i] is the fragment length for lane i. Currently requires nbytes[0] == nbytes[1],
 *   otherwise returns #CRYPT_NOT_SUPPORT.
 * - Currently only supports num == 2.
 *
 * @param   ctx [IN/OUT] Multi-buffer context.
 * @param   data [IN] Input pointer array. data[i] is fragment pointer for lane i.
 * @param   nbytes [IN] Input length array. nbytes[i] is fragment length for lane i.
 * @param   num [IN] Number of lanes/messages.
 *
 * @retval  #CRYPT_SUCCESS Success.
 * @retval  #CRYPT_NULL_INPUT Invalid input pointer.
 * @retval  #CRYPT_NOT_SUPPORT Not supported (e.g. num != 2 or per-lane lengths are not equal).
 * @retval  Other error codes, see crypt_errno.h.
 */
int32_t CRYPT_SHA256_MBUpdate(CRYPT_SHA2_256_MB_Ctx *ctx, const uint8_t *data[], uint32_t nbytes[], uint32_t num);

/**
 * @ingroup SHA256
 * @brief   Finalize SHA256 multi-buffer context and output digests.
 *
 * Notes:
 * - Currently only supports num == 2.
 * - outlen indicates output buffer size on input and returns actual digest length on output.
 *
 * @param   ctx [IN/OUT] Multi-buffer context.
 * @param   digest [OUT] Digest buffer pointer array. digest[i] is output buffer for lane i.
 * @param   outlen [IN/OUT] Output buffer length / output digest length.
 * @param   num [IN] Number of lanes/messages.
 *
 * @retval  #CRYPT_SUCCESS Success.
 * @retval  #CRYPT_NULL_INPUT Invalid input pointer.
 * @retval  #CRYPT_NOT_SUPPORT Not supported (e.g. num != 2 or platform capability missing).
 * @retval  Other error codes, see crypt_errno.h.
 */
int32_t CRYPT_SHA256_MBFinal(CRYPT_SHA2_256_MB_Ctx *ctx, uint8_t *digest[], uint32_t *outlen, uint32_t num);

/**
 * @ingroup SHA256
 * @brief   SHA256 dual-lane compression for full blocks.
 *
 * This function compresses nblocks full SHA256 blocks for two independent states in parallel.
 * It does not handle padding or length encoding.
 *
 * @param   state1 [IN/OUT] SHA256 state for lane 0. Array size is #CRYPT_SHA256_STATE_SIZE.
 * @param   state2 [IN/OUT] SHA256 state for lane 1. Array size is #CRYPT_SHA256_STATE_SIZE.
 * @param   block1 [IN] Input block pointer for lane 0 (must contain nblocks * 64 bytes).
 * @param   block2 [IN] Input block pointer for lane 1 (must contain nblocks * 64 bytes).
 * @param   nblocks [IN] Number of full 64-byte blocks to compress.
 */
void CRYPT_SHA256x2_Compress(uint32_t state1[CRYPT_SHA256_STATE_SIZE], uint32_t state2[CRYPT_SHA256_STATE_SIZE],
                             const uint8_t *block1, const uint8_t *block2, uint32_t nblocks);

/**
 * @ingroup SHA256
 * @brief   SHA256 multi-buffer one-shot hashing.
 *
 * Notes:
 * - Currently only supports num == 2.
 * - nbytes is the same length for all lanes in this one-shot API.
 *
 * @param   data [IN] Input pointer array. data[i] is message pointer for lane i.
 * @param   nbytes [IN] Input length in bytes.
 * @param   digest [OUT] Digest buffer pointer array. digest[i] is output buffer for lane i.
 * @param   outlen [IN/OUT] Output buffer length / output digest length.
 * @param   num [IN] Number of lanes/messages.
 *
 * @retval  #CRYPT_SUCCESS Success.
 * @retval  #CRYPT_NULL_INPUT Invalid input pointer.
 * @retval  #CRYPT_NOT_SUPPORT Not supported (e.g. num != 2 or platform capability missing).
 * @retval  Other error codes, see crypt_errno.h.
 */
int32_t CRYPT_SHA256_MB(const uint8_t *data[], uint32_t nbytes, uint8_t *digest[], uint32_t *outlen, uint32_t num);

/**
 * @ingroup SHA256
 * @brief   SHA256 dual-lane one-shot hashing with initial states.
 *
 * This function computes SHA256 digests for two messages in parallel, starting from the provided
 * SHA256 states.
 *
 * Notes:
 * - This API is intended for internal acceleration paths.
 *
 * @param   state1 [IN/OUT] SHA256 state for lane 0. Array size is #CRYPT_SHA256_STATE_SIZE.
 * @param   state2 [IN/OUT] SHA256 state for lane 1. Array size is #CRYPT_SHA256_STATE_SIZE.
 * @param   data1 [IN] Input message pointer for lane 0.
 * @param   data2 [IN] Input message pointer for lane 1.
 * @param   nbytes [IN] Input length in bytes for both lanes.
 * @param   dgst1 [OUT] Digest output buffer for lane 0 (size #CRYPT_SHA2_256_DIGESTSIZE).
 * @param   dgst2 [OUT] Digest output buffer for lane 1 (size #CRYPT_SHA2_256_DIGESTSIZE).
 *
 * @retval  #CRYPT_SUCCESS Success.
 * @retval  #CRYPT_NOT_SUPPORT Not supported on this platform/build.
 */
int32_t CRYPT_SHA256x2(uint32_t state1[CRYPT_SHA256_STATE_SIZE], uint32_t state2[CRYPT_SHA256_STATE_SIZE],
                       const uint8_t *data1, const uint8_t *data2, uint32_t nbytes,
                       uint8_t dgst1[CRYPT_SHA2_256_DIGESTSIZE], uint8_t dgst2[CRYPT_SHA2_256_DIGESTSIZE]);

/**
 * @ingroup LLF Low Level Functions
 *
 * @brief SHA256 deinit function
 *
 * @param[in,out] ctx The SHA256 ctx
 *
 * @retval #CRYPT_SUCCESS       initialization succeeded.
 * @retval #CRYPT_NULL_INPUT    Pointer ctx is NULL
 */
int32_t CRYPT_SHA2_256_Deinit(CRYPT_SHA2_256_Ctx *ctx);

/**
 * @ingroup SHA256
 * @brief SHA256 copy CTX function
 * @param dst [out]  Pointer to the new SHA256 context.
 * @param src [in]   Pointer to the original SHA256 context.
 */
int32_t CRYPT_SHA2_256_CopyCtx(CRYPT_SHA2_256_Ctx *dst, const CRYPT_SHA2_256_Ctx *src);

/**
 * @ingroup SHA256
 * @brief SHA256 dup CTX function
 * @param src [in]   Pointer to the original SHA256 context.
 */
CRYPT_SHA2_256_Ctx *CRYPT_SHA2_256_DupCtx(const CRYPT_SHA2_256_Ctx *src);

#ifdef HITLS_CRYPTO_PROVIDER
/**
 * @ingroup SHA256
 * @brief SHA256 get param function
 * @param ctx [in]   Pointer to the SHA256 context.
 * @param param [in]   Pointer to the parameter.
 *
 * @retval #CRYPT_SUCCESS       Success.
 * @retval #CRYPT_NULL_INPUT    Pointer param is NULL
 * @retval #CRYPT_INVALID_ARG   Pointer param is invalid
 */
int32_t CRYPT_SHA2_256_GetParam(CRYPT_SHA2_256_Ctx *ctx, BSL_Param *param);
#else
#define CRYPT_SHA2_256_GetParam NULL
#endif
#endif // HITLS_CRYPTO_SHA256

#ifdef HITLS_CRYPTO_SHA384

#define CRYPT_SHA2_384_NewCtx CRYPT_SHA2_512_NewCtx
#define CRYPT_SHA2_384_NewCtxEx CRYPT_SHA2_512_NewCtxEx
#define CRYPT_SHA2_384_FreeCtx CRYPT_SHA2_512_FreeCtx
#define CRYPT_SHA2_384_Deinit CRYPT_SHA2_512_Deinit
#define CRYPT_SHA2_384_CopyCtx CRYPT_SHA2_512_CopyCtx
#define CRYPT_SHA2_384_DupCtx CRYPT_SHA2_512_DupCtx
#define CRYPT_SHA2_384_Update CRYPT_SHA2_512_Update
#define CRYPT_SHA2_384_Final CRYPT_SHA2_512_Final

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
 * @param *param [in] Pointer to the parameter.
 *
 * @retval #CRYPT_SUCCESS ctx is initialized
 * @retval #CRYPT_NULL_INPUT ctx is NULL
 */
int32_t CRYPT_SHA2_384_Init(CRYPT_SHA2_384_Ctx *ctx);

/**
 * @ingroup SHA384
 * @brief This API is used to initialize the SHA384 context.
 *
 * @param ctx [in,out] Pointer to the SHA384 context.
 * @param param [in] param.
 *
 * @retval #CRYPT_SUCCESS       Initialization succeeded.
 * @retval #CRYPT_NULL_INPUT    Pointer ctx is NULL
 */
int32_t CRYPT_SHA2_384_InitEx(CRYPT_SHA2_384_Ctx *ctx, void *param);

#ifdef HITLS_CRYPTO_PROVIDER
/**
 * @ingroup SHA512
 * @brief SHA512 get param function
 * @param ctx [in]   Pointer to the SHA512 context.
 * @param param [in]   Pointer to the parameter.
 *
 * @retval #CRYPT_SUCCESS       Success.
 * @retval #CRYPT_NULL_INPUT    Pointer param is NULL
 * @retval #CRYPT_INVALID_ARG   Pointer param is invalid
 */
int32_t CRYPT_SHA2_384_GetParam(CRYPT_SHA2_384_Ctx *ctx, BSL_Param *param);
#else
#define CRYPT_SHA2_384_GetParam NULL
#endif

#endif // HITLS_CRYPTO_SHA384

#ifdef HITLS_CRYPTO_SHA512

/**
 * @ingroup SHA2_512
 * @brief Generate md context.
 *
 * @retval Success: sha512 ctx.
 *         Fails: NULL.
 */
CRYPT_SHA2_512_Ctx *CRYPT_SHA2_512_NewCtx(void);

/**
 * @ingroup SHA2_512
 * @brief Generate md context.
 *
 * @param libCtx [IN] library context
 * @param algId [IN] algorithm id
 *
 * @retval Success: sha512 ctx.
 *         Fails: NULL.
 */
CRYPT_SHA2_512_Ctx *CRYPT_SHA2_512_NewCtxEx(void *libCtx, int32_t algId);

/**
 * @ingroup SHA2_512
 * @brief free md context.
 *
 * @param ctx [IN] md handle
 */
void CRYPT_SHA2_512_FreeCtx(CRYPT_SHA2_512_Ctx *ctx);

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
 * @param *param [in] Pointer to the parameter.
 *
 * @retval #CRYPT_SUCCESS ctx is initialized
 * @retval #CRYPT_NULL_INPUT ctx is NULL
 */
int32_t CRYPT_SHA2_512_Init(CRYPT_SHA2_512_Ctx *ctx);

/**
 * @ingroup SHA512
 * @brief This API is used to initialize the SHA512 context.
 *
 * @param ctx [in,out] Pointer to the SHA512 context.
 * @param param [in] param.
 *
 * @retval #CRYPT_SUCCESS       Initialization succeeded.
 * @retval #CRYPT_NULL_INPUT    Pointer ctx is NULL
 */
int32_t CRYPT_SHA2_512_InitEx(CRYPT_SHA2_512_Ctx *ctx, void *param);

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

/**
 * @ingroup LLF Low Level Functions
 *
 * @brief SHA512 deinit function
 *
 * @param[in,out] ctx The SHA512 ctx
 *
 * @retval #CRYPT_SUCCESS       initialization succeeded.
 * @retval #CRYPT_NULL_INPUT    Pointer ctx is NULL
 */
int32_t CRYPT_SHA2_512_Deinit(CRYPT_SHA2_512_Ctx *ctx);

/**
 * @ingroup SHA512
 * @brief SHA512 copy CTX function
 * @param dst [out]  Pointer to the new SHA512 context.
 * @param src [in]   Pointer to the original SHA512 context.
 */
int32_t CRYPT_SHA2_512_CopyCtx(CRYPT_SHA2_512_Ctx *dst, const CRYPT_SHA2_512_Ctx *src);

/**
 * @ingroup SHA512
 * @brief SHA512 dup CTX function
 * @param src [in]   Pointer to the original SHA512 context.
 */
CRYPT_SHA2_512_Ctx *CRYPT_SHA2_512_DupCtx(const CRYPT_SHA2_512_Ctx *src);

#ifdef HITLS_CRYPTO_PROVIDER
/**
 * @ingroup SHA512
 * @brief SHA512 get param function
 * @param ctx [in]   Pointer to the SHA512 context.
 * @param param [in]   Pointer to the parameter.
 *
 * @retval #CRYPT_SUCCESS       Success.
 * @retval #CRYPT_NULL_INPUT    Pointer param is NULL
 * @retval #CRYPT_INVALID_ARG   Pointer param is invalid
 */
int32_t CRYPT_SHA2_512_GetParam(CRYPT_SHA2_512_Ctx *ctx, BSL_Param *param);
#else
#define CRYPT_SHA2_512_GetParam NULL
#endif
#endif // HITLS_CRYPTO_SHA512

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA2

#endif // CRYPT_SHA2_H

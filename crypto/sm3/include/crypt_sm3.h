/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_SM3_H
#define CRYPT_SM3_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM3

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define CRYPT_SM3_BLOCKSIZE 64
#define CRYPT_SM3_DIGESTSIZE 32

typedef struct {
    uint32_t h[CRYPT_SM3_DIGESTSIZE / sizeof(uint32_t)];  /* store the intermediate data of the hash value */
    uint32_t hNum, lNum;                                  /* input data counter, maximum value 2 ^ 64 bits */
    uint8_t block[CRYPT_SM3_BLOCKSIZE];                   /* store the remaining data which less than one block */
    /* Number of remaining bytes in 'block' arrary that are stored less than one block */
    uint32_t num;
} CRYPT_SM3_Ctx;

/**
 * @ingroup SM3
 * @brief This API is used to initialize the SM3 context.
 *
 * @param ctx [in,out] SM3 context pointer.
 *
 * @retval #CRYPT_SUCCESS    initialization succeeded.
 * @retval #CRYPT_NULL_INPUT Pointer ctx is NULL
 */
int32_t CRYPT_SM3_Init(CRYPT_SM3_Ctx *ctx);

/**
 * @ingroup SM3
 * @brief Encode the text and update the message digest.
 *
 * @param ctx [in,out] SM3 context pointer.
 * @param in [in] Pointer to the data to be calculated
 * @param len [in] Length of the data to be calculated
 *
 * @retval #CRYPT_SUCCESS               succeeded in updating the internal status of the digest.
 * @retval #CRYPT_NULL_INPUT            The input parameter is NULL.
 * @retval #CRYPT_SM3_INPUT_OVERFLOW    Accumulated input data length exceeds the maximum (2^64 bits).
 */
int32_t CRYPT_SM3_Update(CRYPT_SM3_Ctx *ctx, const uint8_t *in, uint32_t len);

/**
 * @ingroup SM3
 * @brief Obtain the message digest based on the passed SM3 text.
 *
 * @param ctx [in,out] SM3 context pointer.
 * @param out [in] digest buffer
 * @param outLen [in,out] digest buffer size
 *
 * @retval #CRYPT_SUCCESS                       succeeded in updating the internal status of the digest.
 * @retval #CRYPT_NULL_INPUT                    The input parameter is NULL.
 * @retval #CRYPT_SM3_OUT_BUFF_LEN_NOT_ENOUGH   The output buffer is insufficient.
 */
int32_t CRYPT_SM3_Final(CRYPT_SM3_Ctx *ctx, uint8_t *out, uint32_t *outLen);

/**
 * @ingroup SM3
 * @brief SM3 Deinitialization API
 * @param ctx [in,out]   SM3 context pointer.
 */
void CRYPT_SM3_Deinit(CRYPT_SM3_Ctx *ctx);

/**
 * @ingroup SM3
 * @brief Copy SM3 CTX function
 * @param dst [out]   SM3 context pointer.
 * @param src [in]   Pointer to the original SM3 context.
 */
int32_t CRYPT_SM3_CopyCtx(CRYPT_SM3_Ctx *dst, const CRYPT_SM3_Ctx *src);

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif // HITLS_CRYPTO_SM3

#endif // CRYPT_SM3_H

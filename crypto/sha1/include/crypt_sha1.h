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

#ifndef CRYPT_SHA1_H
#define CRYPT_SHA1_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SHA1

#include <stdint.h>
#include <stdlib.h>
#include "crypt_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

/* Length of the message digest buffer. */
#define CRYPT_SHA1_DIGESTSIZE 20

/* Message processing block size */
#define CRYPT_SHA1_BLOCKSIZE   64

typedef struct CryptSha1Ctx CRYPT_SHA1_Ctx;
/**
 * @ingroup SHA1
 * @brief Generate md context.
 *
 * @retval Success: cipher ctx.
 *         Fails: NULL.
 */
CRYPT_SHA1_Ctx *CRYPT_SHA1_NewCtx(void);

/**
 * @ingroup SHA1
 * @brief free md context.
 *
 * @param ctx [IN] md handle
 */
void CRYPT_SHA1_FreeCtx(CRYPT_SHA1_Ctx *ctx);

/**
 * @ingroup SHA1
 * @brief This API is invoked to initialize the SHA-1 context.
 *
 * @param *ctx [in,out] Pointer to the SHA-1 context.
 * @param *param [in] Pointer to the parameter.
 *
 * @retval #CRYPT_SUCCESS       initialization succeeded.
 * @retval #CRYPT_NULL_INPUT    Pointer ctx is NULL
 */
int32_t CRYPT_SHA1_Init(CRYPT_SHA1_Ctx *ctx, BSL_Param *param);

/**
 * @ingroup SHA1
 * @brief Encode the input text and update the message digest.
 *
 * @param *ctx [in,out] Pointer to the SHA-1 context.
 * @param *in [in] Pointer to the data to be calculated
 * @param len [in] Length of the data to be calculated
 *
 * @retval #CRYPT_SUCCESS               succeeded in updating the internal status of the digest.
 * @retval #CRYPT_NULL_INPUT            The input parameter is NULL.
 * @retval #CRYPT_SHA1_ERR_OVERFLOW     input data length exceeds the maximum (2^64 bits)
 */
int32_t CRYPT_SHA1_Update(CRYPT_SHA1_Ctx *ctx, const uint8_t *in, uint32_t len);

/**
 * @ingroup SHA1
 * @brief Obtain the message digest based on the passed SHA-1 text.
 *
 * @param *ctx [in,out] Pointer to the SHA-1 context.
 * @param *out [in] Digest buffer
 * @param *len [in,out] Digest buffer size
 *
 * @retval #CRYPT_SUCCESS                       succeeded in obtaining the computed digest.
 * @retval #CRYPT_NULL_INPUT                    The input parameter is NULL.
 * @retval #CRYPT_SHA1_ERR_OVERFLOW             Input data length exceeds the maximum (2^64 bits).
 * @retval #CRYPT_SHA1_OUT_BUFF_LEN_NOT_ENOUGH  The output buffer is insufficient.
 */
int32_t CRYPT_SHA1_Final(CRYPT_SHA1_Ctx *ctx, uint8_t *out, uint32_t *len);

/**
 * @ingroup SHA1
 * @brief SHA1 deinitialization API
 * @param *ctx [in,out]     Pointer to the SHA-1 context.
 */
void CRYPT_SHA1_Deinit(CRYPT_SHA1_Ctx *ctx);

/**
 * @ingroup SHA1
 * @brief SHA1 copy CTX function
 * @param dest [out]  Pointer to the dest SHA1 context.
 * @param src [in]   Pointer to the original SHA1 context.
 */
int32_t CRYPT_SHA1_CopyCtx(CRYPT_SHA1_Ctx *dst, const CRYPT_SHA1_Ctx *src);

/**
 * @ingroup SHA1
 * @brief SHA1 dup CTX function
 * @param src [in]   Pointer to the original SHA1 context.
 */
CRYPT_SHA1_Ctx *CRYPT_SHA1_DupCtx(const CRYPT_SHA1_Ctx *src);

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif // HITLS_CRYPTO_SHA1

#endif // CRYPT_SHA1_H

/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef ENTROPY_H
#define ENTROPY_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ENTROPY

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__linux__)
#ifndef ENTROPY_USE_DEVRANDOM
#define ENTROPY_USE_DEVRANDOM
#endif
#endif

typedef int32_t (*ExternalConditioningFunction)(uint32_t algId, uint8_t *in, uint32_t inLen, uint8_t *out,
    uint32_t *outLen);

typedef struct EntropyCtx {
    uint32_t algId;
    ExternalConditioningFunction conFunc;
} EntropyCtx;

/**
 * @brief Obtain the entropy source handle.
 *
 * @param conFunc external conditioning function
 * @param algId   ID of Algorithm
 * @return  Success: EntropyCtx
 */
EntropyCtx *ENTROPY_GetCtx(ExternalConditioningFunction conFunc, uint32_t algId);

/**
 * @brief Obtain random number using the default system entropy source
 *
 * @param data data
 * @param len  length
 * @return  Success: CRYPT_SUCCESS
 */
int32_t ENTROPY_GetRandom(uint8_t *data, uint32_t len);

/**
 * @brief Obtain the full entropy output.
 *
 * @param ctx  context
 * @param data random number
 * @param len  length
 * @return  Success: CRYPT_SUCCESS
 */
int32_t ENTROPY_GetFullEntropyInput(void *ctx, uint8_t *data, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_ENTROPY

#endif // ENTROPY_H

/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef SHA3_CORE_H
#define SHA3_CORE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SHA3

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

const uint8_t *SHA3_Absorb(uint8_t *state, const uint8_t *in, uint32_t inLen, uint32_t r);
void SHA3_Squeeze(uint8_t *state, uint8_t *out, uint32_t outLen, uint32_t r);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA3

#endif // SHA3_CORE_H

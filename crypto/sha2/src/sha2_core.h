/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef SHA2_CORE_H
#define SHA2_CORE_H
#include <stdint.h>
#include "hitls_build.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef U64
#define U64(v) (uint64_t)(v)
#endif

#ifdef HITLS_CRYPTO_SHA256
void SHA256CompressMultiBlocks(uint32_t hash[8], const uint8_t *in, uint32_t num);
#endif

#ifdef HITLS_CRYPTO_SHA512
void SHA512CompressMultiBlocks(uint64_t hash[8], const uint8_t *bl, uint32_t bcnt);
#endif

#ifdef __cplusplus
}
#endif

#endif // SHA2_CORE_H

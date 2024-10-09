/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef SHA1_CORE_H
#define SHA1_CORE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SHA1

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

const uint8_t *SHA1_Step(const uint8_t *input, uint32_t len, uint32_t *h);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA1

#endif // SHA1_CORE_H

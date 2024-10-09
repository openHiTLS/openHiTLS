/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef MD5_CORE_H
#define MD5_CORE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MD5

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void MD5_Compress(uint32_t state[4], const uint8_t *data, uint32_t blockCnt);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_MD5

#endif // MD5_CORE_H

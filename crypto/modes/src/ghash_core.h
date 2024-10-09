/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#ifndef GHASH_CORE_H
#define GHASH_CORE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_GCM

#include "crypt_modes_gcm.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void GcmTableGen4bitAsm(const MODES_GCM_GF128 *H, MODES_GCM_GF128 hTable[16]);

void GcmMultH4bitAsm(uint8_t t[GCM_BLOCKSIZE], const MODES_GCM_GF128 hTable[16]);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif
#endif
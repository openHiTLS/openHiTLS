/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CHACHA20_LOCAL_H
#define CHACHA20_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CHACHA20

#include "crypt_chacha20.h"

void CHACHA20_Block(CRYPT_CHACHA20_Ctx *ctx);

void CHACHA20_Update(CRYPT_CHACHA20_Ctx *ctx, const uint8_t *in,
    uint8_t *out, uint32_t len);

#endif // HITLS_CRYPTO_CHACHA20

#endif // CHACHA20_LOCAL_H

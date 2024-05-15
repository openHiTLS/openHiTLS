/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef POLY1305_CORE_H
#define POLY1305_CORE_H


#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CHACHA20POLY1305

#include "crypt_modes_chacha20poly1305.h"


#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define POLY1305_BLOCKSIZE 16
#define POLY1305_TAGSIZE   16
#define POLY1305_KEYSIZE   32

uint32_t Poly1305Block(Poly1305Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t padbit);
void Poly1305Last(Poly1305Ctx *ctx, uint8_t mac[POLY1305_TAGSIZE]);
void Poly1305CleanRegister(void);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CHACHA20POLY1305

#endif // POLY1305_CORE_H
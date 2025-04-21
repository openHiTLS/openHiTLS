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

#ifndef POLY1305_CORE_H
#define POLY1305_CORE_H


#include "hitls_build.h"
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)

#include "crypt_modes_chacha20poly1305.h"
#include "modes_local.h"


#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define POLY1305_BLOCKSIZE 16
#define POLY1305_TAGSIZE   16
#define POLY1305_KEYSIZE   32

void Poly1305InitForAsm(Poly1305Ctx *ctx);
uint32_t Poly1305Block(Poly1305Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t padbit);
void Poly1305Last(Poly1305Ctx *ctx, uint8_t mac[POLY1305_TAGSIZE]);
void Poly1305CleanRegister(void);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CHACHA20POLY1305

#endif // POLY1305_CORE_H
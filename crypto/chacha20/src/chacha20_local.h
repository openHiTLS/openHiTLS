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

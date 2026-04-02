/*
 *
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

#ifndef AARCH64_SHA3_H
#define AARCH64_SHA3_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SHA3

#include <stddef.h>
#include <arm_neon.h>
#include "crypt_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64x2_t v128;
typedef v128 Keccakx2State[25]; // 1600x2
void Shake256x2(uint8_t *dgst0, uint8_t *dgst1, size_t dgstLen, const uint8_t *in0, const uint8_t *in1, size_t inlen);
void Keccakx2Absorb(Keccakx2State state, size_t rate, const uint8_t *in0, const uint8_t *in1,
                    size_t inlen, uint8_t domain);
void Keccakx2Squeeze(uint8_t *out0, uint8_t *out1, size_t nblocks, unsigned int r, Keccakx2State s);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA3
#endif // AARCH64_SHA3_H

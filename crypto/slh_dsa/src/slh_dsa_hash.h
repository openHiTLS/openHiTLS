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

#ifndef SLH_DSA_HASH_H
#define SLH_DSA_HASH_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SLH_DSA

#include <stdint.h>
#include "bsl_params.h"
#include "crypt_slh_dsa.h"

// The length "out" is n, the max length is SLH_DSA_MAX_N
typedef int32_t (*SlhDsaPrf)(const CryptSlhDsaCtx *ctx, const SlhDsaAdrs *adrs, uint8_t *out);

typedef int32_t (*SlhDsaTl)(const CryptSlhDsaCtx *ctx, const SlhDsaAdrs *adrs, const uint8_t *msg, uint32_t msgLen,
                            uint8_t *out);

typedef int32_t (*SlhDsaH)(const CryptSlhDsaCtx *ctx, const SlhDsaAdrs *adrs, const uint8_t *msg, uint32_t msgLen,
                           uint8_t *out);

typedef int32_t (*SlhDsaF)(const CryptSlhDsaCtx *ctx, const SlhDsaAdrs *adrs, const uint8_t *msg, uint32_t msgLen,
                           uint8_t *out);

// The length of "prf", "rand" and "out" is n, the max length is SLH_DSA_MAX_N
typedef int32_t (*SlhDsaPrfMsg)(const CryptSlhDsaCtx *ctx, const uint8_t *rand, const uint8_t *msg, uint32_t msgLen,
                                uint8_t *out);

// The length of "r", "seed" and "root" is n, the max length is SLH_DSA_MAX_N
// the max length of "out" is SLH_DSA_MAX_M
typedef int32_t (*SlhDsaHmsg)(const CryptSlhDsaCtx *ctx, const uint8_t *r, const uint8_t *msg, uint32_t msgLen,
                              uint8_t *out);
struct HashFuncs {
    SlhDsaPrf prf;
    SlhDsaTl tl;
    SlhDsaH h;
    SlhDsaF f;
    SlhDsaPrfMsg prfmsg;
    SlhDsaHmsg hmsg;
};

void SlhDsaInitHashFuncs(CryptSlhDsaCtx *ctx);

#endif // HITLS_CRYPTO_SLH_DSA
#endif // SLH_DSA_HASH_H
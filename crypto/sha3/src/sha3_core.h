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

#ifndef SHA3_CORE_H
#define SHA3_CORE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SHA3

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

const uint8_t *SHA3_Absorb(uint8_t *state, const uint8_t *in, uint32_t inLen, uint32_t r);
void SHA3_Squeeze(uint8_t *state, uint8_t *out, uint32_t outLen, uint32_t r, bool isNeedKeccak);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA3

#endif // SHA3_CORE_H

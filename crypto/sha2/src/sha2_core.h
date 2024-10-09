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

#ifndef SHA2_CORE_H
#define SHA2_CORE_H
#include <stdint.h>
#include "hitls_build.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef U64
#define U64(v) (uint64_t)(v)
#endif

#ifdef HITLS_CRYPTO_SHA256
void SHA256CompressMultiBlocks(uint32_t hash[8], const uint8_t *in, uint32_t num);
#endif

#ifdef HITLS_CRYPTO_SHA512
void SHA512CompressMultiBlocks(uint64_t hash[8], const uint8_t *bl, uint32_t bcnt);
#endif

#ifdef __cplusplus
}
#endif

#endif // SHA2_CORE_H

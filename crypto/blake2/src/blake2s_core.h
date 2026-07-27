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

#ifndef BLAKE2S_CORE_H
#define BLAKE2S_CORE_H

#include <stdint.h>
#include "hitls_build.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HITLS_CRYPTO_BLAKE2S256
#define CRYPT_BLAKE2s_COMPRESS_STATE_SIZE 16

void BLAKE2S_Compress(uint32_t h[8], const uint8_t block[64], uint64_t counter, uint32_t flag);
#endif

#ifdef __cplusplus
}
#endif

#endif // BLAKE2S_CORE_H

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

#ifndef MD5_CORE_H
#define MD5_CORE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MD5

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void MD5_Compress(uint32_t state[4], const uint8_t *data, uint32_t blockCnt);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_MD5

#endif // MD5_CORE_H

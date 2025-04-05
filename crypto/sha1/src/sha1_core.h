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

#ifndef SHA1_CORE_H
#define SHA1_CORE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SHA1

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

const uint8_t *SHA1_Step(const uint8_t *input, uint32_t len, uint32_t *h);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA1

#endif // SHA1_CORE_H

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
#ifndef GHASH_CORE_H
#define GHASH_CORE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_GCM

#include "crypt_modes_gcm.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void GcmTableGen4bitAsm(const MODES_GCM_GF128 *H, MODES_GCM_GF128 hTable[16]);

void GcmMultH4bitAsm(uint8_t t[GCM_BLOCKSIZE], const MODES_GCM_GF128 hTable[16]);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif
#endif
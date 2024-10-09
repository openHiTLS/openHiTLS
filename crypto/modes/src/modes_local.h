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

#ifndef MODES_LOCAL_H
#define MODES_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_GCM

#include <stdint.h>
#include <stdbool.h>
#include "crypt_modes_gcm.h"

void GcmTableGen4bit(uint8_t key[GCM_BLOCKSIZE], MODES_GCM_GF128 hTable[16]);

void GcmHashMultiBlock(uint8_t t[GCM_BLOCKSIZE], const MODES_GCM_GF128 hTable[16], const uint8_t *in, uint32_t inLen);

int32_t CryptLenCheckAndRefresh(MODES_GCM_Ctx *ctx, uint32_t len);

uint32_t LastHandle(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, bool enc);

#endif
#endif

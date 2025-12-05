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

#ifndef CRYPT_AES_SBOX_H
#define CRYPT_AES_SBOX_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_AES) && !defined(HITLS_CRYPTO_AES_PRECALC_TABLES)
#include "crypt_aes.h"

void SetAesKeyExpansionSbox(CRYPT_AES_Key *ctx, uint32_t keyLenBits, const uint8_t *key);

void CRYPT_AES_EncryptSbox(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

void CRYPT_AES_DecryptSbox(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

#endif /* HITLS_CRYPTO_AES && !HITLS_CRYPTO_AES_PRECALC_TABLES */
#endif
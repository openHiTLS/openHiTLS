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

#ifndef CRYPT_AES_LOCAL_H
#define CRYPT_AES_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_AES

#include "crypt_aes.h"

void SetEncryptKey128(CRYPT_AES_Key *ctx, const uint8_t *key);

void SetEncryptKey192(CRYPT_AES_Key *ctx, const uint8_t *key);

void SetEncryptKey256(CRYPT_AES_Key *ctx, const uint8_t *key);

void SetDecryptKey128(CRYPT_AES_Key *ctx, const uint8_t *key);

void SetDecryptKey192(CRYPT_AES_Key *ctx, const uint8_t *key);

void SetDecryptKey256(CRYPT_AES_Key *ctx, const uint8_t *key);

#endif // HITLS_CRYPTO_AES

#endif // CRYPT_AES_LOCAL_H

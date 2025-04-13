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

#ifndef CRYPT_SM4_ARMV8_H
#define CRYPT_SM4_ARMV8_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4

#include <stdint.h>
#include <stddef.h>

#define XTS_KEY_LEN 32
#define SM4_KEY_LEN 16

typedef struct SM4_KEY_st {
    uint32_t rk[XTS_KEY_LEN];
} SM4_KEY;

void Vpsm4SetEncryptKey(const unsigned char *userKey, SM4_KEY *key);

void Vpsm4SetDecryptKey(const unsigned char *userKey, SM4_KEY *key);

#ifdef HITLS_CRYPTO_XTS
void Vpsm4XtsEncrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key1,
                     const SM4_KEY *key2, const uint8_t *iv);

void Vpsm4XtsDecrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key1,
                     const SM4_KEY *key2, const uint8_t *iv);

void Vpsm4XtsCipher(const unsigned char *in, unsigned char *out, uint32_t length, const SM4_KEY *key1,
                    const SM4_KEY *key2, const uint8_t *iv, uint32_t enc);
#endif

#ifdef HITLS_CRYPTO_CBC
void Vpsm4CbcEncrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key, uint8_t *iv, const int enc);
#endif

#ifdef HITLS_CRYPTO_ECB
void Vpsm4EcbEncrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key);
#endif

#ifdef HITLS_CRYPTO_CFB
void Vpsm4Cfb128Encrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key, uint8_t *iv, int *num);
void Vpsm4Cfb128Decrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key, uint8_t *iv, int *num);
#endif

#if defined(HITLS_CRYPTO_CTR) || defined(HITLS_CRYPTO_GCM)
void Vpsm4Ctr32EncryptBlocks(const uint8_t *in, uint8_t *out, uint64_t blocks, const uint32_t *key, uint8_t *iv);
#endif

#endif // HITLS_CRYPTO_SM4

#endif
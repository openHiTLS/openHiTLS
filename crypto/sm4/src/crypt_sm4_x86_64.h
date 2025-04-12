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

#ifndef CRYPT_SM4_X86_64_H
#define CRYPT_SM4_X86_64_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4

#include <stdint.h>

void SM4_SetEncKey(const uint8_t *key, uint32_t *rk);

void SM4_SetDecKey(const uint8_t *key, uint32_t *rk);

void SM4_Encrypt(const uint8_t *in, uint8_t *out, const uint32_t *key);

#define SM4_Decrypt SM4_Encrypt

// SM4 XTS
void SM4_XTS_Encrypt_Blocks(const uint8_t *in, uint8_t *out, uint32_t len,
                            const uint32_t *key, uint8_t *t);

void SM4_ECB_Encrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key);
void SM4_CBC_Encrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key, uint8_t *iv, const int enc);
void SM4_OFB_Encrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key, uint8_t *iv, int *num);
void SM4_CFB128_Encrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key, uint8_t *iv, int *num);
void SM4_CFB128_Decrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key, uint8_t *iv, int *num);
void SM4_CTR_EncryptBlocks(const uint8_t *in, uint8_t *out, uint64_t blocks, const uint32_t *key, const uint8_t *iv);

#endif /* HITLS_CRYPTO_SM4 */
#endif
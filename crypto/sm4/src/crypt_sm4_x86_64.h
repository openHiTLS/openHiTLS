/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_SM4_X86_64_H
#define CRYPT_SM4_X86_64_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4

#include <stdint.h>

void SM4_SetKey(uint32_t *rk, const uint8_t *key);

void SM4_SetDecKey(uint32_t *rk, const uint8_t *key);

void SM4_Encrypt(uint8_t *cipher, const uint8_t *plain, const uint32_t *rk);

void SM4_Decrypt(uint8_t *plain, const uint8_t *cipher, const uint32_t *rk);

// SM4 XTS
void SM4_XTS_16_EncryptBlock1st(uint8_t* cipher, const uint8_t* plain, const uint32_t* ecb_rk,
                                uint8_t* t);

void SM4_XTS_16_EncryptBlock(uint8_t* cipher, const uint8_t* plain, const uint32_t* ecb_rk,
                             uint8_t* t);

void SM4_XTS_16_DecryptBlock1st(uint8_t* plain, const uint8_t* cipher, const uint32_t* ecb_rk,
                                uint8_t* t);

void SM4_XTS_16_DecryptBlock(uint8_t* plain, const uint8_t* cipher, const uint32_t* ecb_rk,
                             uint8_t* t);

void SM4_ECB_Encrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key);
void SM4_CBC_Encrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key, uint8_t *iv, const int enc);
void SM4_OFB_Encrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key, uint8_t *iv, int *num);
void SM4_CFB128_Encrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key, uint8_t *iv, int *num);
void SM4_CFB128_Decrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key, uint8_t *iv, int *num);
void SM4_CTR_EncryptBlocks(const uint8_t *in, uint8_t *out, uint64_t blocks, const uint32_t *key, const uint8_t *iv);

#endif /* HITLS_CRYPTO_SM4 */
#endif
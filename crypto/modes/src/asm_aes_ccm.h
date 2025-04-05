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

#ifndef ASM_AES_CCM_H
#define ASM_AES_CCM_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_CCM)

#include "crypt_utils.h"
#include "modes_local.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void AesCcmEncryptAsm(void *key, uint8_t *nonce, const uint8_t *in, uint8_t *out, uint32_t len);
void AesCcmDecryptAsm(void *key, uint8_t *nonce, const uint8_t *in, uint8_t *out, uint32_t len);
void XorInDecrypt(XorCryptData *data, uint32_t len);
void XorInEncrypt(XorCryptData *data, uint32_t len);
void XorInEncryptBlock(XorCryptData *data);
void XorInDecryptBlock(XorCryptData *data);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif

#endif

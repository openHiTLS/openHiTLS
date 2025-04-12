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

#ifndef ASM_AES_GCM_H
#define ASM_AES_GCM_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_GCM)
 
#include "crypt_modes_gcm.h"
#include "modes_local.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
uint32_t AES_GCM_EncryptBlockAsm(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, void *key);
uint32_t AES_GCM_DecryptBlockAsm(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, void *key);
void AES_GCM_Encrypt16BlockAsm(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, void *key);
void AES_GCM_Decrypt16BlockAsm(MODES_CipherGCMCtx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, void *key);
void AES_GCM_ClearAsm(void);
#ifdef __cplusplus
}
#endif // __cplusplus
#endif
#endif

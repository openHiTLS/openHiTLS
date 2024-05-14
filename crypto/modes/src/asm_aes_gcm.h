/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef ASM_AES_GCM_H
#define ASM_AES_GCM_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_GCM)
 
#include "crypt_modes_gcm.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
uint32_t AES_GCM_EncryptBlockAsm(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, void *key);
uint32_t AES_GCM_DecryptBlockAsm(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, void *key);
void AES_GCM_Encrypt16BlockAsm(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, void *key);
void AES_GCM_Decrypt16BlockAsm(MODES_GCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, void *key);
void AES_GCM_ClearAsm(void);
#ifdef __cplusplus
}
#endif // __cplusplus
#endif
#endif

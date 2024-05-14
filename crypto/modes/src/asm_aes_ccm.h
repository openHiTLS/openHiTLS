/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#ifndef ASM_AES_CCM_H
#define ASM_AES_CCM_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_AES) && defined(HITLS_CRYPTO_CCM)

#include "crypt_utils.h"
#include "crypt_modes.h"
#include "crypt_modes_ccm.h"

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

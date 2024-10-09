/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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

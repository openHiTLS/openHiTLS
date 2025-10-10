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

#ifndef CRYPT_MODES_CTR_H
#define CRYPT_MODES_CTR_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CTR

#include "crypt_types.h"
#include "crypt_modes.h"
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// CTR mode universal implementation
#define MODES_CTR_NewCtx MODES_CipherNewCtx
#define MODES_CTR_NewCtxEx MODES_CipherNewCtxEx

int32_t MODES_CTR_InitCtx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc);

int32_t MODES_CTR_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int32_t MODES_CTR_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen);
int32_t MODES_CTR_DeInitCtx(MODES_CipherCtx *modeCtx);
int32_t MODES_CTR_Ctrl(MODES_CipherCtx *modeCtx, int32_t cmd, void *val, uint32_t valLen);
void MODES_CTR_FreeCtx(MODES_CipherCtx *modeCtx);

// AES CTR optimization implementation
int32_t AES_CTR_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

// SM4 CTR optimization implementation
int32_t SM4_CTR_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int32_t SM4_CTR_InitCtx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc);

int32_t MODES_CTR_InitCtxEx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc);

int32_t MODES_CTR_UpdateEx(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CTR

#endif // CRYPT_MODES_CTR_H

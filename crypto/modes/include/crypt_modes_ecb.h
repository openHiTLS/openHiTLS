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

#ifndef CRYPT_MODES_ECB_H
#define CRYPT_MODES_ECB_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ECB

#include "crypt_types.h"
#include "crypt_modes.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// ECB mode universal implementation
#define MODES_ECB_NewCtx MODES_CipherNewCtx
#define MODES_ECB_NewCtxEx MODES_CipherNewCtxEx

int32_t MODES_ECB_InitCtx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc);

int32_t MODES_ECB_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int32_t MODES_ECB_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen);
int32_t MODES_ECB_DeinitCtx(MODES_CipherCtx *modeCtx);
int32_t MODES_ECB_Ctrl(MODES_CipherCtx *modeCtx, int32_t cmd, void *val, uint32_t valLen);
void MODES_ECB_FreeCtx(MODES_CipherCtx *modeCtx);

// AES ECB optimization implementation
int32_t AES_ECB_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int32_t AES_ECB_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen);

// SM4 ECB optimization implementation
int32_t SM4_ECB_InitCtx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc);
int32_t SM4_ECB_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int32_t SM4_ECB_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen);

int32_t MODES_ECB_InitCtxEx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc);

int32_t MODES_ECB_UpdateEx(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int32_t MODES_ECB_FinalEx(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen);
#ifdef __cplusplus
}
#endif // __cplusplus
#endif
#endif
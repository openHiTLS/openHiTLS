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

#ifndef CRYPT_MODES_OFB_H
#define CRYPT_MODES_OFB_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_OFB

#include "crypt_types.h"
#include "crypt_modes.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// OFB mode universal implementation
#define MODES_OFB_NewCtx MODES_CipherNewCtx
#define MODES_OFB_NewCtxEx MODES_CipherNewCtxEx

int32_t MODES_OFB_InitCtx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc);

int32_t MODES_OFB_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int32_t MODES_OFB_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen);
int32_t MODES_OFB_DeInitCtx(MODES_CipherCtx *modeCtx);
int32_t MODES_OFB_Ctrl(MODES_CipherCtx *modeCtx, int32_t cmd, void *val, uint32_t valLen);
void MODES_OFB_FreeCtx(MODES_CipherCtx *modeCtx);

// SM4 OFB optimization implementation
int32_t SM4_OFB_InitCtx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc);
int32_t SM4_OFB_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

int32_t MODES_OFB_InitCtxEx(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc);

int32_t MODES_OFB_UpdateEx(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_OFB

#endif // CRYPT_MODES_OFB_H

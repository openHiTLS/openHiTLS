/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 * http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef CRYPT_MODES_HCTR_H
#define CRYPT_MODES_HCTR_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HCTR

#include "crypt_modes.h"
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct MODES_HCTR_Buffer {
    uint8_t *buffer;    // Pointer to the data buffer.
    uint32_t bufSize;   // The allocated size of the buffer.
    uint32_t dataLen;   // The current length of the data stored in the buffer.
} MODES_HCTR_Buffer;

// HCTR mode universal implementation
void *MODES_HCTR_NewCtx(void *provCtx, int32_t algId);
int32_t MODES_HCTR_Init(MODES_CipherCtx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc);
int32_t MODES_HCTR_Update(MODES_CipherCtx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int32_t MODES_HCTR_Final(MODES_CipherCtx *modeCtx, uint8_t *out, uint32_t *outLen);
int32_t MODES_HCTR_DeInit(MODES_CipherCtx *modeCtx);
int32_t MODES_HCTR_Ctrl(MODES_CipherCtx *modeCtx, int32_t cmd, void *val, uint32_t valLen);
void MODES_HCTR_Free(MODES_CipherCtx *modeCtx);
MODES_CipherCtx *MODES_HCTR_DupCtx(const MODES_CipherCtx *modeCtx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_HCTR */
#endif /* CRYPT_MODES_HCTR_H */
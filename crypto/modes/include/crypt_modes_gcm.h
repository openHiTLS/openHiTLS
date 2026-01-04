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

#ifndef CRYPT_MODES_GCM_H
#define CRYPT_MODES_GCM_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_GCM

#include "crypt_types.h"
#include "crypt_modes.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
#define GCM_MAX_COMBINED_LENGTH     (((uint64_t)1 << 36) - 32)
#define GCM_MAX_INVOCATIONS_TIMES   ((uint32_t)(-1))
#define GCM_BLOCK_MASK (0xfffffff0)
typedef struct {
    uint64_t h;
    uint64_t l;
} MODES_GCM_GF128;
#define GCM_BLOCKSIZE 16
typedef struct {
    uint8_t iv[GCM_BLOCKSIZE];      // Processed IV information. The length is 16 bytes.
    uint8_t ghash[GCM_BLOCKSIZE];   // Intermediate data for tag calculation.
    MODES_GCM_GF128 hTable[16]; // The window uses 4 bits, 2 ^ 4 = 16 entries need to be pre-calculated.
    void *ciphCtx; // Context defined by each symmetric algorithm.
    const EAL_SymMethod *ciphMeth; // algorithm method
    uint8_t tagLen;
    uint32_t cryptCnt; // Indicate the number of encryption times that the key can be used.
    uint8_t last[GCM_BLOCKSIZE];    // ctr mode last
    uint8_t remCt[GCM_BLOCKSIZE];     // Remaining ciphertext
    uint8_t ek0[GCM_BLOCKSIZE];     // ek0
    uint64_t plaintextLen;  // use for calc tag
    uint32_t aadLen;        // use for calc tag
    uint32_t lastLen;       // ctr mode lastLen
} MODES_CipherGCMCtx;

struct ModesGcmCtx {
    int32_t algId;
    MODES_CipherGCMCtx gcmCtx;
    bool enc;
};

typedef struct ModesGcmCtx MODES_GCM_Ctx;

// GCM mode universal implementation
MODES_GCM_Ctx *MODES_GCM_NewCtx(int32_t algId);
MODES_GCM_Ctx *MODES_GCM_NewCtxEx(void *libCtx, int32_t algId);
int32_t MODES_GCM_InitCtx(MODES_GCM_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc);

int32_t MODES_GCM_Update(MODES_GCM_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int32_t MODES_GCM_Final(MODES_GCM_Ctx *modeCtx, uint8_t *out, uint32_t *outLen);
int32_t MODES_GCM_DeInitCtx(MODES_GCM_Ctx *modeCtx);
int32_t MODES_GCM_Ctrl(MODES_GCM_Ctx *modeCtx, int32_t cmd, void *val, uint32_t len);
void MODES_GCM_FreeCtx(MODES_GCM_Ctx *modeCtx);

// AES GCM optimization implementation
int32_t AES_GCM_Update(MODES_GCM_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

// SM4 GCM optimization implementation
int32_t SM4_GCM_InitCtx(MODES_GCM_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc);
int32_t SM4_GCM_Update(MODES_GCM_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

int32_t MODES_GCM_InitCtxEx(MODES_GCM_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc);

int32_t MODES_GCM_UpdateEx(MODES_GCM_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

int32_t MODES_GCM_InitHashTable(MODES_CipherGCMCtx *ctx);
int32_t MODES_GCM_SetKey(MODES_CipherGCMCtx *ctx, const uint8_t *key, uint32_t len);
MODES_GCM_Ctx *MODES_GCM_DupCtx(const MODES_GCM_Ctx *modeCtx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_GCM

#endif // CRYPT_MODES_GCM_H

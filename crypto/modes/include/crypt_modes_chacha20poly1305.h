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

#ifndef CRYPT_MODES_CHACHA20POLY1305_H
#define CRYPT_MODES_CHACHA20POLY1305_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)

#include "crypt_types.h"
#include "crypt_modes.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct {
    uint32_t acc[6];    // The intermediate data of the acc, must be greater than 130 bits.
    uint32_t r[4];      // Key information r, 16 bytes, that is, 4 * sizeof(uint32_t)
    uint32_t s[4];      // Key information s, 16 bytes, that is, 4 * sizeof(uint32_t)
    uint32_t table[36]; // Indicates the table used to accelerate the assembly calculation.
    uint8_t last[16];   // A block 16 bytes are cached for the last unprocessed data.
    uint32_t lastLen;   // Indicates the remaining length of the last data.
    uint32_t flag;      // Used to save the assembly status information.
} Poly1305Ctx;

typedef struct {
    void *key; // Handle for the method.
    const EAL_SymMethod *method; // algorithm method
    Poly1305Ctx polyCtx;
    uint64_t aadLen; // Status, indicating whether identification data is set.
    uint64_t cipherTextLen; // status, indicating whether the identification data is set.
} MODES_CipherChaChaPolyCtx;

struct ModesChaChaCtx {
    int32_t algId;
    MODES_CipherChaChaPolyCtx chachaCtx;
    bool enc;
};

typedef struct ModesChaChaCtx MODES_CHACHAPOLY_Ctx;

MODES_CHACHAPOLY_Ctx *MODES_CHACHA20POLY1305_NewCtx(int32_t algId);
MODES_CHACHAPOLY_Ctx *MODES_CHACHA20POLY1305_NewCtxEx(void *libCtx, int32_t algId);
int32_t MODES_CHACHA20POLY1305_InitCtx(MODES_CHACHAPOLY_Ctx *modeCtx, const uint8_t *key,
    uint32_t keyLen, const uint8_t *iv, uint32_t ivLen, void *param, bool enc);

int32_t MODES_CHACHA20POLY1305_Update(MODES_CHACHAPOLY_Ctx *modeCtx, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);
int32_t MODES_CHACHA20POLY1305_Final(MODES_CHACHAPOLY_Ctx *modeCtx, uint8_t *out, uint32_t *outLen);
int32_t MODES_CHACHA20POLY1305_DeInitCtx(MODES_CHACHAPOLY_Ctx *modeCtx);
int32_t MODES_CHACHA20POLY1305_Ctrl(MODES_CHACHAPOLY_Ctx *modeCtx, int32_t cmd, void *val, uint32_t len);
void MODES_CHACHA20POLY1305_FreeCtx(MODES_CHACHAPOLY_Ctx *modeCtx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CHACHA20POLY1305

#endif // CRYPT_MODES_CHACHA20POLY1305_H

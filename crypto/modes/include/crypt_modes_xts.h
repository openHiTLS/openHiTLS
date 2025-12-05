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

#ifndef CRYPT_MODES_XTS_H
#define CRYPT_MODES_XTS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_XTS

#include "crypt_types.h"
#include "crypt_modes.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct {
    void *ciphCtx;                    /* Key defined by each algorithm  */
    const EAL_SymMethod *ciphMeth; /* corresponding to the encrypt and decrypt in the bottom layer, operate keyctx */
    uint8_t iv[MODES_MAX_IV_LENGTH];  /* The length is blocksize */
    uint8_t tweak[MODES_MAX_IV_LENGTH]; /* The length is blocksize */
    uint8_t blockSize;                  /* Save the block size. */
} MODES_CipherXTSCtx;

struct ModesXTSCtx {
    int32_t algId;
    MODES_CipherXTSCtx xtsCtx;
    uint8_t data[EAL_MAX_BLOCK_LENGTH];             /**< last data block that may not be processed */
    uint8_t dataLen;                                /**< size of the last data block that may not be processed. */
    CRYPT_PaddingType pad;
    bool enc;
};

typedef struct ModesXTSCtx MODES_XTS_Ctx;

// XTS mode universal implementation
MODES_XTS_Ctx *MODES_XTS_NewCtx(int32_t algId);
MODES_XTS_Ctx *MODES_XTS_NewCtxEx(void *libCtx, int32_t algId);
int32_t MODES_XTS_InitCtx(MODES_XTS_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc);

int32_t MODES_XTS_Update(MODES_XTS_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int32_t MODES_XTS_Final(MODES_XTS_Ctx *modeCtx, uint8_t *out, uint32_t *outLen);
int32_t MODES_XTS_DeInitCtx(MODES_XTS_Ctx *modeCtx);
int32_t MODES_XTS_Ctrl(MODES_XTS_Ctx *modeCtx, int32_t cmd, void *val, uint32_t len);
void MODES_XTS_FreeCtx(MODES_XTS_Ctx *modeCtx);

// XTS mode universal implementation
int32_t SM4_XTS_Update(MODES_XTS_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int32_t SM4_XTS_InitCtx(MODES_XTS_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc);
int32_t SM4_XTS_Final(MODES_XTS_Ctx *modeCtx, uint8_t *out, uint32_t *outLen);

int32_t MODES_XTS_InitCtxEx(MODES_XTS_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc);

int32_t MODES_XTS_UpdateEx(MODES_XTS_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

int32_t AES_XTS_Update(MODES_XTS_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

int32_t AES_XTS_Final(MODES_XTS_Ctx *modeCtx, uint8_t *out, uint32_t *outLen);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_XTS

#endif // CRYPT_MODES_XTS_H

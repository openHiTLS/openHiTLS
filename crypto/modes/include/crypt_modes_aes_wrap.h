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

#ifndef CRYPT_MODES_AES_WRAP_H
#define CRYPT_MODES_AES_WRAP_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_WRAP

#include <stdint.h>
#include "crypt_eal_cipher.h"
#include "crypt_types.h"
#include "crypt_algid.h"
#include "crypt_local_types.h"
#include "crypt_modes.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define CRYPT_WRAP_BLOCKSIZE 8
#define CRYPT_WRAP_AIV_SIZE 4
#define CRYPT_WRAP_MAX_INPUT_LEN (UINT32_MAX - 2 * CRYPT_WRAP_BLOCKSIZE)

typedef struct {
    void *ciphCtx;                       /* AES context */
    const EAL_SymMethod *ciphMeth;  /* Functions of AES */
    uint8_t iv[CRYPT_WRAP_BLOCKSIZE];    /* Processed IV information. The length is 8 bytes. */
    bool flagPad;                        /* Indicates whether to support padding. */
    uint8_t blockSize;                   /* Save the block size. */
} MODES_CipherWRAPCtx;

struct ModesWRAPCtx {
    int32_t algId;
    MODES_CipherWRAPCtx wrapCtx;
    bool enc;
};

typedef struct ModesWRAPCtx MODES_WRAP_Ctx;

MODES_WRAP_Ctx *MODES_WRAP_PadNewCtx(int32_t algId);

MODES_WRAP_Ctx *MODES_WRAP_NoPadNewCtx(int32_t algId);

int32_t MODES_WRAP_InitCtx(MODES_WRAP_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc);

int32_t MODES_WRAP_Update(MODES_WRAP_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

int32_t MODES_WRAP_Final(MODES_WRAP_Ctx *modeCtx, uint8_t *out, uint32_t *outLen);

int32_t MODE_WRAP_Ctrl(MODES_WRAP_Ctx *modeCtx, int32_t opt, void *val, uint32_t len);

int32_t MODE_WRAP_DeInitCtx(MODES_WRAP_Ctx *modeCtx);

void MODES_WRAP_FreeCtx(MODES_WRAP_Ctx *modeCtx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_WRAP

#endif // CRYPT_MODES_AES_WRAP_H

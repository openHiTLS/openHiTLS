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

#ifndef CRYPT_MODES_CFB_H
#define CRYPT_MODES_CFB_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CFB

#include "crypt_types.h"
#include "crypt_modes.h"
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define DES_BLOCK_BYTE_NUM 8
typedef struct {
    MODES_CipherCommonCtx modeCtx;
    uint8_t feedbackBits;  /* Save the FeedBack length. */
    uint8_t cipherCache[3][DES_BLOCK_BYTE_NUM];
    uint8_t cacheIndex;   /* Used by the TDES that has 3IV. Indicate which cache is being used. */
} MODES_CipherCFBCtx;
struct ModesCFBCtx {
    int32_t algId;
    MODES_CipherCFBCtx cfbCtx;
    bool enc;
};
typedef struct ModesCFBCtx MODES_CFB_Ctx;

// CFB mode universal implementation
MODES_CFB_Ctx *MODES_CFB_NewCtx(int32_t algId);
int32_t MODES_CFB_InitCtx(MODES_CFB_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc);

int32_t MODES_CFB_Update(MODES_CFB_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int32_t MODES_CFB_Final(MODES_CFB_Ctx *modeCtx, uint8_t *out, uint32_t *outLen);
int32_t MODES_CFB_DeInitCtx(MODES_CFB_Ctx *modeCtx);
int32_t MODES_CFB_Ctrl(MODES_CFB_Ctx *modeCtx, int32_t opt, void *val, uint32_t len);
void MODES_CFB_FreeCtx(MODES_CFB_Ctx *modeCtx);

// AES CFB optimization implementation
int32_t AES_CFB_Update(MODES_CFB_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

// SM4 CFB optimization implementation
int32_t SM4_CFB_InitCtx(MODES_CFB_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, bool enc);
int32_t SM4_CFB_Update(MODES_CFB_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);


int32_t MODES_CFB_InitCtxEx(MODES_CFB_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, void *param, bool enc);
int32_t MODES_CFB_UpdateEx(MODES_CFB_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
MODES_CFB_Ctx *MODES_CFB_DupCtx(const MODES_CFB_Ctx *modeCtx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CFB

#endif // CRYPT_MODES_CFB_H

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

#ifndef CRYPT_MODES_H
#define CRYPT_MODES_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MODES

#include <stdint.h>
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define MODES_MAX_IV_LENGTH 24
#define MODES_MAX_BUF_LENGTH 24
#define MODES_IV_LENGTH 16
#define EAL_MAX_BLOCK_LENGTH 32
typedef struct {
    void *ciphCtx;  /* Context defined by each algorithm  */
    const EAL_SymMethod *ciphMeth; /* Corresponding to the related methods for each symmetric algorithm */
    uint8_t iv[MODES_MAX_IV_LENGTH];   /* IV information */
    uint8_t buf[MODES_MAX_BUF_LENGTH]; /* Cache the information of the previous block. */
    uint8_t blockSize;                 /* Save the block size. */
    uint8_t offset;
    uint8_t flag3Iv;                   /* Indicates whether three IVs are used. */
    uint32_t ivIndex;            /* Indicates the sequence number of the IV block to be used. TDES may have three IV. */
} MODES_CipherCommonCtx;

struct ModesCipherCtx {
    MODES_CipherCommonCtx commonCtx;
    int32_t algId;
    uint8_t data[EAL_MAX_BLOCK_LENGTH];             /**< last data block that may not be processed */
    uint8_t dataLen;                                /**< size of the last data block that may not be processed. */
    CRYPT_PaddingType pad;                          /**< padding type */
    bool enc;
};
typedef struct ModesCipherCtx MODES_CipherCtx;

typedef struct {
    const uint8_t *in;
    uint8_t *out;
    const uint8_t *ctr;
    uint8_t *tag;
} XorCryptData;
void MODES_Clean(MODES_CipherCommonCtx *ctx);
int32_t MODES_SetIv(MODES_CipherCommonCtx *ctx, const uint8_t *val, uint32_t len);
int32_t MODES_GetIv(MODES_CipherCommonCtx *ctx, uint8_t *val, uint32_t len);

MODES_CipherCtx *MODES_CipherNewCtx(int32_t algId);
MODES_CipherCtx *MODES_CipherNewCtxEx(void *libCtx, int32_t algId);
MODES_CipherCtx *MODES_CipherDupCtx(const MODES_CipherCtx *modeCtx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_MODES

#endif // CRYPT_MODES_H

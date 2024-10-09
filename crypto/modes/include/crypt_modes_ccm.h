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

#ifndef CRYPT_MODES_CCM_H
#define CRYPT_MODES_CCM_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CCM

#include <stdint.h>
#include "crypt_local_types.h"
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define CCM_BLOCKSIZE 16

typedef struct {
    void *ciphCtx;  /* Context defined by each algorithm  */
    const EAL_CipherMethod *ciphMeth;  /* Corresponding to the related methods for each symmetric algorithm */

    uint8_t nonce[CCM_BLOCKSIZE];  /* Data nonce, ctr encrypted data */
    uint8_t tag[CCM_BLOCKSIZE];    /* Data tag, intermediate data encrypted by the CBC */
    uint8_t last[CCM_BLOCKSIZE];   /* Previous data block in ctr mode */
    uint64_t msgLen;    /* The message length */
    uint8_t lastLen;    /* Unused data length of the previous data block in ctr mode. */
    uint8_t tagLen;     /* The length of the tag is 16 by default. The tag is reset each time the key is set. */
    uint8_t tagInit;    /* Indicate whether the tag is initialized. */
} MODES_CCM_Ctx;

int32_t MODES_CCM_InitCtx(MODES_CCM_Ctx *ctx, const struct EAL_CipherMethod *m);

void MODES_CCM_DeinitCtx(MODES_CCM_Ctx *ctx);

void MODES_CCM_Clean(MODES_CCM_Ctx *ctx);

int32_t MODES_CCM_Ctrl(MODES_CCM_Ctx *ctx, CRYPT_CipherCtrl opt, void *val, uint32_t len);

int32_t MODES_CCM_SetKey(MODES_CCM_Ctx *ctx, const uint8_t *key, uint32_t len);

int32_t MODES_CCM_Encrypt(MODES_CCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

int32_t MODES_CCM_Decrypt(MODES_CCM_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CCM

#endif // CRYPT_MODES_CCM_H

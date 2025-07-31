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

#ifndef CRYPT_HYBRIDKEM_H
#define CRYPT_HYBRIDKEM_H
#include <stdint.h>
#include "crypt_types.h"

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ECDH

typedef struct HybridKemCtx CRYPT_HybridKemCtx;

CRYPT_HybridKemCtx *CRYPT_HYBRID_KEM_NewCtx(void);

CRYPT_HybridKemCtx *CRYPT_HYBRID_KEM_NewCtxEx(void *libCtx);

void CRYPT_HYBRID_KEM_FreeCtx(CRYPT_HybridKemCtx *ctx);

int32_t CRYPT_HYBRID_KEM_KeyCtrl(CRYPT_HybridKemCtx *ctx, int32_t opt, void *val, uint32_t len);

int32_t CRYPT_HYBRID_KEM_GenKey(CRYPT_HybridKemCtx *ctx);

int32_t CRYPT_HYBRID_KEM_SetEncapsKey(CRYPT_HybridKemCtx *ctx, const CRYPT_KemEncapsKey *ek);
int32_t CRYPT_HYBRID_KEM_SetDecapsKey(CRYPT_HybridKemCtx *ctx, const CRYPT_KemDecapsKey *dk);

int32_t CRYPT_HYBRID_KEM_GetEncapsKey(const CRYPT_HybridKemCtx *ctx, CRYPT_KemEncapsKey *ek);
int32_t CRYPT_HYBRID_KEM_GetDecapsKey(const CRYPT_HybridKemCtx *ctx, CRYPT_KemDecapsKey *dk);

int32_t CRYPT_HYBRID_KEM_GetEncapsKeyEx(const CRYPT_HybridKemCtx *ctx, BSL_Param *para);
int32_t CRYPT_HYBRID_KEM_GetDecapsKeyEx(const CRYPT_HybridKemCtx *ctx, BSL_Param *para);

int32_t CRYPT_HYBRID_KEM_SetEncapsKeyEx(CRYPT_HybridKemCtx *ctx, const BSL_Param *para);
int32_t CRYPT_HYBRID_KEM_SetDecapsKeyEx(CRYPT_HybridKemCtx *ctx, const BSL_Param *para);

int32_t CRYPT_HYBRID_KEM_Encaps(const CRYPT_HybridKemCtx *ctx, uint8_t *cipher, uint32_t *cipherLen,
    uint8_t *share, uint32_t *shareLen);

int32_t CRYPT_HYBRID_KEM_Decaps(const CRYPT_HybridKemCtx *ctx, uint8_t *cipher, uint32_t cipherLen,
    uint8_t *share, uint32_t *shareLen);

#endif
#endif    // CRYPT_HYBRIDKEM_H

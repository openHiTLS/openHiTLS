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

#ifndef CRYPT_ASCONAEAD_H
#define CRYPT_ASCONAEAD_H

#include "hitls_build.h"

#ifdef HITLS_CRYPTO_ASCONAEAD

#include <stdint.h>
#include "crypt_types.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* ============ Variant Enumeration ============ */
typedef enum {
    ASCON_VARIANT_128 = 0,    /* default */
    ASCON_VARIANT_128A = 1,
    ASCON_VARIANT_80PQ = 2,
    ASCON_VARIANT_MAX
} ASCON_VARIANT_E;


/* ============ Configuration List ============ */
typedef struct {
    ASCON_VARIANT_E variant;
    uint8_t  keyLen;           /* 16 or 20 */
    uint8_t  nonceLen;         /* always 16 */
    uint8_t  tagLen;           /* always 16 */
    uint8_t  rate;             /* 8 or 16 (bytes) */
    uint8_t  rounds_ad;        /* 6 (128/80pq) or 8 (128a) */
    uint8_t  rounds_init;      /* always 12 */
    uint64_t iv_const;         /* variant-specific IV */
    
    int (*encrypt)(uint8_t*, uint64_t*, const uint8_t*, uint64_t,
                   const uint8_t*, uint64_t, const uint8_t*, 
                   const uint8_t*, const uint8_t*);
    int (*decrypt)(uint8_t*, uint64_t*, uint8_t*, const uint8_t*, uint64_t,
                   const uint8_t*, uint64_t, const uint8_t*, const uint8_t*);
} ASCON_VariantConfig;


/* ============ Internal Context ============ */
typedef struct {
    const ASCON_VariantConfig *config;
 
    uint8_t key[20];
    uint8_t nonce[16];
 
    uint8_t *aad;
    uint32_t aadLen;
    uint8_t *in;
    uint32_t inLen;
    uint32_t inCap;

    /* Tag verification (for decrypt) and tag buffer (for internal use) */
    uint8_t vfyTag[16];      /* expected tag set by user via CRYPT_CTRL_SET_TAG */
    uint32_t vfyTagLen;      /* length of expected tag */
    uint8_t tagBuf[16];      /* computed tag (available after encryption Final) */
    bool tagValid;            /* true if tagBuf contains valid tag */
 
    bool enc;
    bool initialized;
    bool aadSet;
 
    void *libCtx;
} CRYPT_ASCONAEAD_Ctx;


/* ============ API Definition ============ */
CRYPT_ASCONAEAD_Ctx *CRYPT_ASCONAEAD_NewCtx(int32_t algId);

CRYPT_ASCONAEAD_Ctx *CRYPT_ASCONAEAD_NewCtxEx(void *libCtx, int32_t algId);

int32_t CRYPT_ASCONAEAD_InitCtx(CRYPT_ASCONAEAD_Ctx *ctx, const uint8_t *key, uint32_t keyLen,
                                const uint8_t *iv, uint32_t ivLen, 
                                void *param, bool enc);

int32_t CRYPT_ASCONAEAD_Update(CRYPT_ASCONAEAD_Ctx *ctx, const uint8_t *in, uint32_t inLen,
                               uint8_t *out, uint32_t *outLen);

int32_t CRYPT_ASCONAEAD_Final(CRYPT_ASCONAEAD_Ctx *ctx, uint8_t *out, uint32_t *outLen);

int32_t CRYPT_ASCONAEAD_DeInitCtx(CRYPT_ASCONAEAD_Ctx *ctx);

int32_t CRYPT_ASCONAEAD_Ctrl(CRYPT_ASCONAEAD_Ctx *ctx, int32_t cmd, void *val, uint32_t len);

void CRYPT_ASCONAEAD_FreeCtx(CRYPT_ASCONAEAD_Ctx *ctx);

CRYPT_ASCONAEAD_Ctx *CRYPT_ASCONAEAD_DupCtx(const CRYPT_ASCONAEAD_Ctx *src);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* HITLS_CRYPTO_ASCONAEAD */

#endif /* CRYPT_ASCONAEAD_H */

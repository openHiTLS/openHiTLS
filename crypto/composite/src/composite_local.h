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

#ifndef CRYPT_COMPOSITE_LOCAL_H
#define CRYPT_COMPOSITE_LOCAL_H

#if defined(HITLS_CRYPTO_COMPOSITE_SIGN) || defined(HITLS_CRYPTO_COMPOSITE_KEM)
#include "crypt_composite.h"
#include "sal_atomic.h"
#include "bsl_types.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COMPOSITE_SIGNATURE_PREFIX_LEN 32
#define COMPOSITE_MAX_CTX_BYTES 255
#define BITS_TO_BYTES(x) (((x) + 7) >> 3)


typedef enum { CRYPT_COMPOSITE_KIND_SIGN = 1, CRYPT_COMPOSITE_KIND_KEM = 2 } CRYPT_COMPOSITE_Kind;

typedef struct {
    CRYPT_MD_AlgId hashId;
    CRYPT_MD_AlgId tradHashId;
    uint32_t pqcSigLen;
} COMPOSITE_SIGN_INFO;

typedef struct {
    uint32_t pqcCipherLen;
    uint32_t tradCipherLen;
    uint32_t tradSharedLen;
    uint32_t sharedLen;
    CRYPT_MD_AlgId combinerHashId;
} COMPOSITE_KEM_INFO;

typedef struct {
    int32_t paramId;
    CRYPT_COMPOSITE_Kind kind;
    const char *label;
    int32_t pqcAlg;
    int32_t pqcParam;
    int32_t tradAlg;
    int32_t tradParam;
    uint32_t bits;
    uint32_t pubKeyLen;
    uint32_t prvKeyLen;
    uint32_t pqcPubkeyLen;
    uint32_t pqcPrvkeyLen;
    union {
        COMPOSITE_SIGN_INFO sign;
        COMPOSITE_KEM_INFO kem;
    } alg;
} COMPOSITE_ALG_INFO;

struct CompositeCtx {
    void *pqcCtx;
    void *tradCtx;
    uint32_t pubLen;
    uint32_t prvLen;
    const COMPOSITE_ALG_INFO *info;
    uint8_t *ctxInfo;
    uint32_t ctxLen;
    BSL_SAL_RefCount references;
    void *libCtx;
};

int32_t CRYPT_CompositeSetRsaPadding(CRYPT_CompositeCtx *ctx);
#ifdef HITLS_CRYPTO_COMPOSITE_KEM
int32_t CRYPT_CompositePrepareTradPubKey(CRYPT_CompositeCtx *ctx);
#endif

int32_t CRYPT_CompositeGetPqcPrvKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t CRYPT_CompositeGetPqcPubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t CRYPT_CompositeSetPqcPrvKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t CRYPT_CompositeSetPqcPubKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t CRYPT_CompositeGetTradPrvKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t CRYPT_CompositeGetTradPubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t CRYPT_CompositeSetTradPrvKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode);
int32_t CRYPT_CompositeSetTradPubKey(CRYPT_CompositeCtx *ctx, BSL_Buffer *encode);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_COMPOSITE_SIGN || HITLS_CRYPTO_COMPOSITE_KEM
#endif // CRYPT_COMPOSITE_LOCAL_H

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

#ifdef HITLS_CRYPTO_COMPOSITE
#include "crypt_composite.h"
#include "sal_atomic.h"
#include "bsl_types.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COMPOSITE_SIGNATURE_PREFIX_LEN 32
#define COMPOSITE_MAX_CTX_BYTES 255
#define MD_SHA256_SIZE 32
#define MD_SHA512_SIZE 64
#define BITS_TO_BYTES(x) (((x) + 7) >> 3)


typedef struct {
    int32_t paramId;
    const char *label;
    int32_t pqcAlg;
    int32_t pqcParam;
    int32_t tradAlg;
    int32_t tradParam;
    CRYPT_MD_AlgId hashId;
    CRYPT_MD_AlgId tradHashId;
    uint32_t bits;
    uint32_t pubKeyLen;
    uint32_t prvKeyLen;
    uint32_t pqcPubkeyLen;
    uint32_t pqcPrvkeyLen;
    uint32_t pqcSigLen;
} COMPOSITE_ALG_INFO;

struct CompositeCtx {
    void *pqcCtx;
    void *tradCtx;
    uint8_t *pubKey;
    uint32_t pubLen;
    uint8_t *prvKey;
    uint32_t prvLen;
    uint8_t *e;
    uint32_t eLen;
    const EAL_PkeyMethod *pqcMethod;
    const EAL_PkeyMethod *tradMethod;
    const COMPOSITE_ALG_INFO *info;
    uint8_t *ctxInfo;
    uint32_t ctxLen;
    BSL_SAL_RefCount references;
    void *libCtx;
};

int32_t CRYPT_CompositeSetRsaPadding(CRYPT_CompositeCtx *ctx);
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

#endif // HITLS_CRYPTO_COMPOSITE
#endif // CRYPT_COMPOSITE_LOCAL_H

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

#ifndef XMSS_LOCAL_H
#define XMSS_LOCAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT)

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "bsl_params.h"
#include "crypt_algid.h"
#include "hbs_wots.h"
#include "hbs_tree.h"
#include "xmss_params.h"
#include "xmss_address.h"

typedef struct XmssCtxCommon XmssCtxCommon;
typedef int32_t (*XmssBdsExportStateCb)(const XmssCtxCommon *ctx, const void *bdsCtx, const void *params,
                                        uint8_t *out, uint32_t *outLen);
typedef int32_t (*XmssBdsImportStateCb)(const XmssCtxCommon *ctx, void *bdsCtx, const void *params,
                                        const uint8_t *in, uint32_t inLen);
typedef void (*XmssBdsFreeStateCb)(void *bdsCtx);

#include "xmss_bds.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t seed[XMSS_MAX_SEED_SIZE]; // Private seed (SK.seed)
    uint8_t prf[XMSS_MAX_SEED_SIZE]; // PRF key (SK.prf)
    uint64_t idx; // Next unused leaf index
    uint8_t root[XMSS_MAX_MDSIZE]; // Tree root (PK.root)
    uint8_t pubSeed[XMSS_MAX_SEED_SIZE]; // Public seed (PK.seed)
} XmssKey;

/*
 * Common runtime state shared by XMSS and XMSSMT implementations.
 *
 * Algorithm geometry lives in the concrete XMSS/XMSSMT parameter tables. This
 * common part keeps only key material and hash inputs needed by shared helpers.
 * Algorithm-specific BDS state is owned by the concrete XMSS/XMSSMT context.
 */
struct XmssCtxCommon {
    uint32_t n; // Security parameter used by shared hash/tree helpers.

    CRYPT_MD_AlgId mdId; // Message digest selected by the concrete XMSS/XMSSMT parameter set.

    uint32_t paddingLen; // Domain-separation padding length for the selected digest.

    const XmssFamilyHashFuncs *hashFuncs; // Hash function table (pointer to static table)

    XmssFamilyAdrsOps adrsOps; // Generic address operation function pointers

    XmssKey key;

    bool hasPrivateKey; // Whether key.seed/prf/idx contain usable private signing state.

    /* Library context */
    void *libCtx;
};

#ifdef HITLS_CRYPTO_XMSS
/*
 * XMSS runtime context. The parameter pointer selects the single-tree
 * parameter namespace used by XMSS-specific entry points.
 */
typedef struct CryptXmssCtx {
    const XmssParams *params;
    XmssCtxCommon *common;
    XmssBdsCtx bds;
} CryptXmssCtx;
#endif

#ifdef HITLS_CRYPTO_XMSSMT
/*
 * XMSSMT runtime context. The parameter pointer selects the hypertree
 * decomposition used by XMSSMT-specific entry points.
 */
typedef struct CryptXmssmtCtx {
    const XmssmtParams *params;
    XmssCtxCommon *common;
    XmssmtBdsCtx bds;
} CryptXmssmtCtx;
#endif

/*
 * Initialize XMSS context
 *
 * @param ctx     XMSS context to initialize
 * @param params  XMSS parameters
 *
 * @return CRYPT_SUCCESS on success
 */
int32_t XmssInitInternal(XmssCtxCommon *ctx, uint32_t n, CRYPT_MD_AlgId mdId, uint32_t paddingLen);

XmssCtxCommon *XmssCommonNew(void);

void XmssCommonFree(XmssCtxCommon *ctx);

int32_t XmssCheckGenReady(const XmssCtxCommon *ctx, bool hasParams);

int32_t XmssGenerateKeyMaterial(XmssCtxCommon *ctx, uint32_t n);

/*
 * Initialize HbsTreeCtx from an XMSS single-tree context.
 *
 * Used by xmss_core.c to populate HBS tree context before calling HbsTree_*.
 *
 * @param treeCtx [out] Tree context to initialize
 * @param ctx     [in]  XMSS context
 */
#ifdef HITLS_CRYPTO_XMSS
void HbsTreeCtx_InitForXmss(HbsTreeCtx *treeCtx, const CryptXmssCtx *ctx);
#endif

#ifdef HITLS_CRYPTO_XMSSMT
void HbsTreeCtx_InitForXmssmt(HbsTreeCtx *treeCtx, const CryptXmssmtCtx *ctx);
#endif

int32_t XmssGetPubkeyLen(const XmssCtxCommon *ctx, void *val, uint32_t len, bool hasParams);

int32_t XmssGetSignatureLen(void *val, uint32_t len, uint32_t sigBytes, bool hasParams);

int32_t XmssGetParaId(void *val, uint32_t len, CRYPT_PKEY_ParaId algId, bool hasParams);

int32_t XmssGetXdrAlgBuff(void *val, uint32_t len, const uint8_t *xdrAlgId, bool hasParams);

int32_t XmssCheckSignReady(const XmssCtxCommon *ctx, const uint8_t *data, const uint8_t *sign,
                           const uint32_t *signLen, bool hasParams);

typedef struct {
    XmssCtxCommon *ctx;
    const uint8_t *msg;
    uint32_t msgLen;
    uint32_t idxBytes;
    uint32_t h;
    uint32_t sigBytes;
    uint8_t *sig;
    uint32_t *sigLen;
} XmssSignPrepareInput;

typedef struct {
    uint64_t index;
    uint32_t offset;
    uint8_t digest[XMSS_MAX_MDSIZE];
    bool idxConsumed;
} XmssSignPrepareResult;

int32_t XmssPrepareSignData(const XmssSignPrepareInput *input, XmssSignPrepareResult *result);

int32_t XmssCheckVerifyReady(const XmssCtxCommon *ctx, const uint8_t *data, const uint8_t *sign, bool hasParams);

int32_t XmssBuildVerifyDigest(const XmssCtxCommon *ctx, const uint8_t *msg, uint32_t msgLen, const uint8_t *sig,
                              uint32_t sigLen, uint32_t idxBytes, uint64_t *index, uint32_t *offset, uint8_t *digest,
                              uint32_t sigBytes);

int32_t XmssCheckRoot(const uint8_t *actual, const uint8_t *expected, uint32_t n);

int32_t XmssGetPubKeyCommon(const XmssCtxCommon *ctx, BSL_Param *para, const uint8_t *xdrAlgId);

int32_t XmssGetPrvKeyCommon(const XmssCtxCommon *ctx, BSL_Param *para, const void *bdsCtx,
                            const void *bdsParams, XmssBdsExportStateCb exportState);

int32_t XmssSetPubKeyCommon(XmssCtxCommon *ctx, const BSL_Param *para, const uint8_t *xdrAlgId);

int32_t XmssSetPrvKeyCommon(XmssCtxCommon *ctx, const BSL_Param *para, void *bdsCtx, void *tmpBdsCtx,
                            uint32_t bdsCtxLen, const void *bdsParams, XmssBdsImportStateCb importState,
                            XmssBdsFreeStateCb freeState);

#if defined(HITLS_CRYPTO_XMSS_CHECK) || defined(HITLS_CRYPTO_XMSSMT_CHECK)
int32_t XmssCheckKeyPairRoot(const XmssCtxCommon *pubKey, const XmssCtxCommon *prvKey, const HbsTreeCtx *treeCtx,
                             const XmssAdrs *adrs);

int32_t XmssCheckPrvKeyBasic(const XmssCtxCommon *prvKey, bool hasParams, CRYPT_PKEY_ParaId algId);
#endif

#ifdef __cplusplus
}
#endif

#endif /* defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT) */
#endif /* XMSS_LOCAL_H */

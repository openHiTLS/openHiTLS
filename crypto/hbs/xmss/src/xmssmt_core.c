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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_XMSSMT

#include <string.h>
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_local_types.h"
#include "crypt_utils.h"
#include "crypt_xmssmt.h"
#include "xmss_bds.h"
#include "xmss_local.h"
#include "xmssmt_params.h"

CryptXmssmtCtx *CRYPT_XMSSMT_NewCtx(void)
{
    CryptXmssmtCtx *ctx = (CryptXmssmtCtx *)BSL_SAL_Calloc(sizeof(CryptXmssmtCtx), 1);
    if (ctx != NULL) {
        ctx->common = XmssCommonNew();
    }
    if (ctx == NULL || ctx->common == NULL) {
        CRYPT_XMSSMT_FreeCtx(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ctx = NULL;
    }
    return ctx;
}

CryptXmssmtCtx *CRYPT_XMSSMT_NewCtxEx(void *libCtx)
{
    CryptXmssmtCtx *ctx = CRYPT_XMSSMT_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->common->libCtx = libCtx;
    return ctx;
}

void CRYPT_XMSSMT_FreeCtx(CryptXmssmtCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    XmssmtBds_Free(&ctx->bds);
    XmssCommonFree(ctx->common);
    BSL_SAL_ClearFree(ctx, sizeof(CryptXmssmtCtx));
}

static int32_t XmssmtInitWithParams(CryptXmssmtCtx *ctx, const XmssmtParams *params)
{
    XmssmtBds_Free(&ctx->bds);
    int32_t ret = XmssInitInternal(ctx->common, params->n, params->mdId, params->paddingLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ctx->params = params;
    return CRYPT_SUCCESS;
}

void HbsTreeCtx_InitForXmssmt(HbsTreeCtx *treeCtx, const CryptXmssmtCtx *ctx)
{
    const XmssCtxCommon *common = ctx->common;

    treeCtx->n = common->n;
    treeCtx->hp = ctx->params->hp;
    treeCtx->d = ctx->params->d;
    treeCtx->otsLen = ctx->params->wotsLen;

    treeCtx->pubSeed = common->key.pubSeed;
    treeCtx->skSeed = common->key.seed;
    treeCtx->root = common->key.root;

    treeCtx->hashFuncs.xmss = common->hashFuncs;
    treeCtx->adrsOps = &common->adrsOps;
    treeCtx->originalCtx = (const void *)common;
    treeCtx->algoType = HBS_ALGO_XMSS;
}

static int32_t XmssmtExportBdsState(const XmssCtxCommon *ctx, const void *bdsCtx, const void *params,
                                    uint8_t *out, uint32_t *outLen)
{
    return XmssmtBds_ExportHyperTreeState(ctx, (const XmssmtBdsCtx *)bdsCtx, (const XmssmtParams *)params,
                                          out, outLen);
}

static int32_t XmssmtImportBdsState(const XmssCtxCommon *ctx, void *bdsCtx, const void *params, const uint8_t *in,
                                    uint32_t inLen)
{
    return XmssmtBds_ImportHyperTreeState(ctx, (XmssmtBdsCtx *)bdsCtx, (const XmssmtParams *)params, in, inLen);
}

static void XmssmtFreeBdsState(void *bdsCtx)
{
    XmssmtBds_Free((XmssmtBdsCtx *)bdsCtx);
}

#ifdef HITLS_CRYPTO_XMSSMT_CHECK
static int32_t XmssmtKeyPairCheck(const CryptXmssmtCtx *pubKey, const CryptXmssmtCtx *prvKey)
{
    if (pubKey == NULL || prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->common == NULL || prvKey->common == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->params == NULL || prvKey->params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    if (pubKey->params->algId != prvKey->params->algId) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_XMSS_PAIRWISE_CHECK_FAIL;
    }

    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitForXmssmt(&treeCtx, prvKey);

    XmssAdrs adrs;
    memset(&adrs, 0, sizeof(adrs));
    prvKey->common->adrsOps.setLayerAddr(&adrs, prvKey->params->d - 1U);
    prvKey->common->adrsOps.setTreeAddr(&adrs, 0);
    return XmssCheckKeyPairRoot(pubKey->common, prvKey->common, &treeCtx, &adrs);
}
#endif

static int32_t XmssmtSetParaId(CryptXmssmtCtx *ctx, void *val, uint32_t len)
{
    if (ctx->params != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_CTRL_INIT_REPEATED);
        return CRYPT_XMSS_CTRL_INIT_REPEATED;
    }
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    const XmssmtParams *params = XmssmtParams_FindByAlgId((CRYPT_PKEY_ParaId)(*(int32_t *)val));
    if (params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_ALGID);
        return CRYPT_XMSS_ERR_INVALID_ALGID;
    }
    return XmssmtInitWithParams(ctx, params);
}

static int32_t XmssmtSetXdrAlgId(CryptXmssmtCtx *ctx, void *val, uint32_t len)
{
    if (ctx->params != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_CTRL_INIT_REPEATED);
        return CRYPT_XMSS_CTRL_INIT_REPEATED;
    }
    if (len < HASH_SIGN_XDR_ALG_TYPE_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint32_t xdrId = GET_UINT32_BE((const uint8_t *)val, 0);
    const XmssmtParams *params = XmssmtParams_FindByXdrId(xdrId);
    if (params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_XDR_ID);
        return CRYPT_XMSS_ERR_INVALID_XDR_ID;
    }
    return XmssmtInitWithParams(ctx, params);
}

/* Return a low-bits mask while avoiding undefined 64-bit shifts. */
static uint64_t XmssmtMaskForBits(uint32_t bits)
{
    return bits >= 64U ? UINT64_MAX : ((1ULL << bits) - 1ULL);
}

/* Return true when signing globalIdx consumes the final leaf through layer. */
static bool XmssmtIsLayerBoundary(uint64_t globalIdx, uint32_t hp, uint32_t layer)
{
    return ((globalIdx + 1U) & XmssmtMaskForBits((layer + 1U) * hp)) == 0;
}

/* Return whether another tree exists after treeIdx at an XMSSMT layer. */
static bool XmssmtHasNextTree(uint32_t h, uint32_t hp, uint32_t layer, uint64_t treeIdx)
{
    uint32_t bitsAbove = h - (layer + 1U) * hp;
    if (bitsAbove == 0) {
        return false;
    }
    return treeIdx + 1U < (1ULL << bitsAbove);
}

/*
 * XMSSMT BDS initialization is a hypertree precomputation step: build the
 * current tree for every layer, cache upper-layer WOTS signatures over lower
 * roots, and prepare empty next-tree states for later tree switches.
 */
static int32_t XmssmtInitBds(CryptXmssmtCtx *ctx)
{
    XmssCtxCommon *common = ctx == NULL ? NULL : ctx->common;
    if (common == NULL || ctx->params == NULL || common->n == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->params->d <= 1U) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    int32_t ret = XmssmtBds_Alloc(&ctx->bds, ctx->params->d, common->n, ctx->params->wotsLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint32_t d = ctx->params->d;
    uint32_t n = common->n;
    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitForXmssmt(&treeCtx, ctx);

    for (uint32_t layer = 0; layer < d; layer++) {
        ret = XmssBds_InitTreeState(&ctx->bds.states[layer], layer, 0, &treeCtx);
        if (ret != CRYPT_SUCCESS) {
            XmssmtBds_Free(&ctx->bds);
            return ret;
        }
        if (layer + 1U < d) {
            uint8_t *wotsSig = ctx->bds.wotsSigs + layer * ctx->params->wotsLen * n;
            ret = XmssBds_SignWotsLayer(ctx->bds.states[layer].root, n, layer + 1U, 0, 0, &treeCtx, wotsSig);
            if (ret != CRYPT_SUCCESS) {
                XmssmtBds_Free(&ctx->bds);
                return ret;
            }
        }
    }

    for (uint32_t i = 0; i + 1U < d; i++) {
        XmssBds_ResetState(&ctx->bds.states[d + i], ctx->params->hp);
    }
    memcpy(common->key.root, ctx->bds.states[d - 1U].root, n);
    ctx->bds.enabled = true;
    return CRYPT_SUCCESS;
}

/*
 * Refresh the cached WOTS signature that authenticates the newly active lower
 * tree root at its parent layer.
 */
static int32_t XmssmtRefreshUpperWotsSig(XmssCtxCommon *common, XmssmtBdsCtx *bds, const XmssmtParams *params,
                                         uint32_t layer, uint64_t globalIdx, const HbsTreeCtx *treeCtx)
{
    uint32_t n = common->n;
    uint32_t hp = params->hp;
    uint64_t upperTreeAddr = (globalIdx + 1U) >> ((layer + 2U) * hp);
    uint32_t upperLeaf = (uint32_t)(((globalIdx >> ((layer + 1U) * hp)) + 1U) & XmssmtMaskForBits(hp));
    uint8_t *wotsSig = bds->wotsSigs + layer * params->wotsLen * n;
    return XmssBds_SignWotsLayer(bds->states[layer].root, n, layer + 1U, upperTreeAddr, upperLeaf, treeCtx, wotsSig);
}

/*
 * XMSSMT-specific post-sign update. The update budget is shared across active
 * treehash work and incremental next-tree construction. At a layer boundary,
 * the prepared next tree is promoted, its parent WOTS cache is refreshed, and
 * the old next-tree slot is reset for future use.
 */
static int32_t XmssmtBdsPostSignUpdate(XmssCtxCommon *common, XmssmtBdsCtx *bds, const XmssmtParams *params,
                                       uint64_t globalIdx, const HbsTreeCtx *treeCtx)
{
    uint32_t d = params->d;
    uint32_t hp = params->hp;
    uint32_t updates = XmssBds_GetTreehashUpdateBudget(hp);
    int32_t needSwapUpTo = -1;
    uint64_t maxIdx = (params->h == 64U) ? (UINT64_MAX - 1U) : ((1ULL << params->h) - 1U);

    uint64_t bottomTree = globalIdx >> hp;
    if (XmssmtHasNextTree(params->h, hp, 0, bottomTree)) {
        int32_t ret = XmssBds_NextTreeUpdate(&bds->states[d], 0, bottomTree + 1U, treeCtx);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    for (uint32_t layer = 0; layer < d; layer++) {
        uint32_t idxLeaf = (uint32_t)((globalIdx >> (hp * layer)) & XmssmtMaskForBits(hp));
        uint64_t idxTree = globalIdx >> (hp * (layer + 1U));
        if (!XmssmtIsLayerBoundary(globalIdx, hp, layer)) {
            if (layer == (uint32_t)(needSwapUpTo + 1)) {
                int32_t ret = XmssBds_TreeRound(&bds->states[layer], idxLeaf, layer, idxTree, treeCtx);
                if (ret != CRYPT_SUCCESS) {
                    return ret;
                }
            }
            int32_t ret = XmssBds_TreehashUpdates(&bds->states[layer], updates, layer, idxTree, treeCtx, &updates);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            if (layer > 0 && layer + 1U < d && updates > 0 &&
                XmssmtHasNextTree(params->h, hp, layer, idxTree)) {
                ret = XmssBds_NextTreeUpdate(&bds->states[d + layer], layer, idxTree + 1U, treeCtx);
                if (ret != CRYPT_SUCCESS) {
                    return ret;
                }
                updates--;
            }
            continue;
        }

        if (globalIdx >= maxIdx || layer + 1U >= d) {
            continue;
        }
        if (!bds->states[d + layer].initialized) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        int32_t ret = XmssBds_StateSwap(&bds->states[layer], &bds->states[d + layer]);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        ret = XmssmtRefreshUpperWotsSig(common, bds, params, layer, globalIdx, treeCtx);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        XmssBds_ResetState(&bds->states[d + layer], hp);
        if (updates > 0) {
            updates--;
        }
        needSwapUpTo = (int32_t)layer;
    }
    return CRYPT_SUCCESS;
}

/*
 * BDS accelerated XMSSMT signing emits the bottom-layer signature over digest,
 * copies cached upper-layer WOTS signatures and auth paths, then performs the
 * hypertree state transition for precomputation and tree switching.
 */
static int32_t XmssmtSignWithBds(CryptXmssmtCtx *ctx, const uint8_t *digest, uint32_t digestLen, uint64_t index,
                                 uint8_t *sign, uint32_t *signLen)
{
    XmssCtxCommon *common = ctx == NULL ? NULL : ctx->common;
    if (common == NULL || ctx->params == NULL || digest == NULL || sign == NULL || signLen == NULL ||
        common->n == 0 || ctx->bds.states == NULL || !ctx->bds.enabled) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->params->d <= 1U) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint32_t n = common->n;
    uint32_t d = ctx->params->d;
    uint32_t hp = ctx->params->hp;
    uint32_t layerSigLen = (ctx->params->wotsLen + hp) * n;
    uint32_t totalSigLen = layerSigLen * d;
    if (*signLen < totalSigLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_SIG_LEN);
        return CRYPT_XMSS_ERR_INVALID_SIG_LEN;
    }

    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitForXmssmt(&treeCtx, ctx);

    uint8_t *sigPtr = sign;
    uint64_t treeIdx = index >> hp;
    uint32_t leafIdx = (uint32_t)(index & XmssmtMaskForBits(hp));
    uint32_t oneLayerLen = layerSigLen;
    int32_t ret = XmssBds_WriteLayerSignature(&ctx->bds.states[0], digest, digestLen, leafIdx, 0, treeIdx,
                                              &treeCtx, sigPtr, &oneLayerLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    sigPtr += oneLayerLen;

    for (uint32_t layer = 1; layer < d; layer++) {
        memcpy(sigPtr, ctx->bds.wotsSigs + (layer - 1U) * ctx->params->wotsLen * n, ctx->params->wotsLen * n);
        ret = XmssBds_CopyAuthPath(&ctx->bds.states[layer], sigPtr + ctx->params->wotsLen * n, hp, n);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        sigPtr += layerSigLen;
    }

    ret = XmssmtBdsPostSignUpdate(common, &ctx->bds, ctx->params, index, &treeCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    *signLen = totalSigLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_XMSSMT_Gen(CryptXmssmtCtx *ctx)
{
    XmssCtxCommon *common = ctx == NULL ? NULL : ctx->common;
    int32_t ret = XmssCheckGenReady(common, ctx != NULL && ctx->params != NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = XmssGenerateKeyMaterial(common, ctx->params->n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = XmssmtInitBds(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    common->hasPrivateKey = true;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_XMSSMT_Sign(CryptXmssmtCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                          uint8_t *sign, uint32_t *signLen)
{
    (void)algId;
    XmssCtxCommon *common = ctx == NULL ? NULL : ctx->common;
    int32_t ret = XmssCheckSignReady(common, data, sign, signLen, ctx != NULL && ctx->params != NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint32_t signBufLen = *signLen;
    uint32_t idxBytes = (ctx->params->h + 7) / 8;
    XmssSignPrepareInput prepareInput = {
        common,
        data,
        dataLen,
        idxBytes,
        ctx->params->h,
        ctx->params->sigBytes,
        sign,
        signLen
    };
    XmssSignPrepareResult prepareResult = {0};
    ret = XmssPrepareSignData(&prepareInput, &prepareResult);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }

    uint32_t hp = ctx->params->hp;
    uint32_t leafIdx = (uint32_t)(prepareResult.index & (((uint64_t)1 << hp) - 1));
    uint64_t treeIdx = prepareResult.index >> hp;
    uint32_t treeSigLen = *signLen - prepareResult.offset;
    if (ctx->bds.enabled) {
        ret = XmssmtSignWithBds(ctx, prepareResult.digest, ctx->params->n, prepareResult.index,
                                sign + prepareResult.offset, &treeSigLen);
    } else {
        HbsTreeCtx treeCtx;
        HbsTreeCtx_InitForXmssmt(&treeCtx, ctx);
        ret = HbsHyperTree_Sign(prepareResult.digest, ctx->params->n, treeIdx, leafIdx, &treeCtx,
                                sign + prepareResult.offset, &treeSigLen);
    }
    BSL_SAL_CleanseData(prepareResult.digest, sizeof(prepareResult.digest));
    if (ret != CRYPT_SUCCESS) {
        goto ERR_CLEAN_SIG;
    }

    *signLen = prepareResult.offset + treeSigLen;
    return CRYPT_SUCCESS;

ERR:
    BSL_SAL_CleanseData(prepareResult.digest, sizeof(prepareResult.digest));
ERR_CLEAN_SIG:
    if (prepareResult.idxConsumed) {
        XmssmtBds_Free(&ctx->bds);
        BSL_SAL_CleanseData(sign, signBufLen);
        *signLen = 0;
    }
    BSL_ERR_PUSH_ERROR(ret);
    return ret;
}

int32_t CRYPT_XMSSMT_Verify(const CryptXmssmtCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                            const uint8_t *sign, uint32_t signLen)
{
    (void)algId;
    const XmssCtxCommon *common = ctx == NULL ? NULL : ctx->common;
    int32_t ret = XmssCheckVerifyReady(common, data, sign, ctx != NULL && ctx->params != NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint64_t index = 0;
    uint32_t offset = 0;
    uint8_t digest[XMSS_MAX_MDSIZE] = {0};
    uint32_t idxBytes = (ctx->params->h + 7) / 8;
    ret = XmssBuildVerifyDigest(common, data, dataLen, sign, signLen, idxBytes, &index, &offset, digest,
                                ctx->params->sigBytes);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(digest, sizeof(digest));
        return ret;
    }

    uint32_t hp = ctx->params->hp;
    uint32_t leafIdx = (uint32_t)(index & (((uint64_t)1 << hp) - 1));
    uint64_t treeIdx = index >> hp;
    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitForXmssmt(&treeCtx, ctx);
    ret = HbsHyperTree_Verify(digest, ctx->params->n, sign + offset, signLen - offset, treeIdx, leafIdx, &treeCtx);
    BSL_SAL_CleanseData(digest, sizeof(digest));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_XMSSMT_Ctrl(CryptXmssmtCtx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            return XmssmtSetParaId(ctx, val, len);
        case CRYPT_CTRL_GET_PARAID:
            return XmssGetParaId(val, len, ctx->params == NULL ? 0 : ctx->params->algId, ctx->params != NULL);
        case CRYPT_CTRL_GET_XMSS_XDR_ALG_TYPE:
            return XmssGetXdrAlgBuff(val, len, ctx->params == NULL ? NULL : ctx->params->xdrAlgId,
                                     ctx->params != NULL);
        case CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE:
            return XmssmtSetXdrAlgId(ctx, val, len);
        case CRYPT_CTRL_GET_SIGNLEN:
            return XmssGetSignatureLen(val, len, ctx->params == NULL ? 0 : ctx->params->sigBytes,
                                       ctx->params != NULL);
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            return XmssGetPubkeyLen(ctx->common, val, len, ctx->params != NULL);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

int32_t CRYPT_XMSSMT_GetPubKey(const CryptXmssmtCtx *ctx, BSL_Param *para)
{
    return XmssGetPubKeyCommon(ctx == NULL ? NULL : ctx->common, para, ctx == NULL || ctx->params == NULL ?
        NULL : ctx->params->xdrAlgId);
}

int32_t CRYPT_XMSSMT_GetPrvKey(const CryptXmssmtCtx *ctx, BSL_Param *para)
{
    return XmssGetPrvKeyCommon(ctx == NULL ? NULL : ctx->common, para, ctx == NULL ? NULL : &ctx->bds,
                               ctx == NULL ? NULL : ctx->params, XmssmtExportBdsState);
}

int32_t CRYPT_XMSSMT_SetPubKey(CryptXmssmtCtx *ctx, const BSL_Param *para)
{
    int32_t ret = XmssSetPubKeyCommon(ctx == NULL ? NULL : ctx->common, para, ctx == NULL || ctx->params == NULL ?
        NULL : ctx->params->xdrAlgId);
    if (ret == CRYPT_SUCCESS) {
        XmssmtBds_Free(&ctx->bds);
    }
    return ret;
}

int32_t CRYPT_XMSSMT_SetPrvKey(CryptXmssmtCtx *ctx, const BSL_Param *para)
{
    XmssmtBdsCtx tmpBds = {0};
    return XmssSetPrvKeyCommon(ctx == NULL ? NULL : ctx->common, para, ctx == NULL ? NULL : &ctx->bds, &tmpBds,
                               sizeof(tmpBds), ctx == NULL ? NULL : ctx->params, XmssmtImportBdsState,
                               XmssmtFreeBdsState);
}

CryptXmssmtCtx *CRYPT_XMSSMT_DupCtx(CryptXmssmtCtx *ctx)
{
    if (ctx == NULL || ctx->common == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CryptXmssmtCtx *newCtx = CRYPT_XMSSMT_NewCtx();
    if (newCtx == NULL) {
        return NULL;
    }
    newCtx->params = ctx->params;
    newCtx->common->libCtx = ctx->common->libCtx;
    newCtx->common->n = ctx->common->n;
    newCtx->common->mdId = ctx->common->mdId;
    newCtx->common->paddingLen = ctx->common->paddingLen;
    newCtx->common->hashFuncs = ctx->common->hashFuncs;
    newCtx->common->adrsOps = ctx->common->adrsOps;
    memcpy(newCtx->common->key.pubSeed, ctx->common->key.pubSeed, XMSS_MAX_SEED_SIZE);
    memcpy(newCtx->common->key.root, ctx->common->key.root, XMSS_MAX_MDSIZE);
    return newCtx;
}

#ifdef HITLS_CRYPTO_XMSSMT_CHECK
int32_t CRYPT_XMSSMT_Check(uint32_t checkType, const CryptXmssmtCtx *pkey1, const CryptXmssmtCtx *pkey2)
{
    switch (checkType) {
        case CRYPT_PKEY_CHECK_KEYPAIR: {
            return XmssmtKeyPairCheck(pkey1, pkey2);
        }
        case CRYPT_PKEY_CHECK_PRVKEY:
            return XmssCheckPrvKeyBasic(pkey1 == NULL ? NULL : pkey1->common, pkey1 != NULL && pkey1->params != NULL,
                                        pkey1 == NULL || pkey1->params == NULL ? 0 : pkey1->params->algId);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
}
#endif /* HITLS_CRYPTO_XMSSMT_CHECK */

#endif /* HITLS_CRYPTO_XMSSMT */

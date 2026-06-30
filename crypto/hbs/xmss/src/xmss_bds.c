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
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT)

#include <string.h>
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "hbs_address.h"
#include "hbs_wots.h"
#include "xmss_bds.h"
#include "xmss_local.h"

#define XMSS_BDS_BLOB_HEADER_LEN    (7U * (uint32_t)sizeof(uint32_t) + (uint32_t)sizeof(uint64_t))
#define XMSS_BDS_TREEHASH_META_LEN  (3U * (uint32_t)sizeof(uint32_t) + 1U)

/*
 * BDS state layout:
 *   - XMSS uses one active tree state and no cached WOTS signatures.
 *   - XMSSMT states[0, d) hold current tree states for every layer.
 *   - XMSSMT states[d, 2d - 1) incrementally build next trees for non-top layers.
 *   - XMSSMT wotsSigs caches upper-layer WOTS signatures over lower-layer roots.
 *
 * Persisted state uses a fixed-field big-endian encoding. Only active hp-by-n
 * portions of fixed-capacity arrays are encoded, so the blob is independent of
 * compiler padding and the in-memory XmssBdsState layout.
 */

/* Return the number of current-tree and next-tree BDS states required by the parameter set. */
static uint32_t ExpectedStateCount(uint32_t d)
{
    return 2U * d - 1U;
}

/* Return the number of bytes required for cached upper-layer WOTS signatures. */
static uint32_t ExpectedWotsSigsLen(uint32_t n, uint32_t d, uint32_t wotsLen)
{
    if (d <= 1U) {
        return 0;
    }
    return (d - 1U) * wotsLen * n;
}

/*
 * Select BDS parameter k. RFC-compatible BDS traversal requires h' - k to be even;
 * this implementation caps k at XMSS_BDS_K to keep retain storage bounded.
 */
static uint32_t GetBdsK(uint32_t hp)
{
    uint32_t k = hp < XMSS_BDS_K ? hp : XMSS_BDS_K;
    if (((hp - k) & 1U) != 0 && k > 0) {
        k--;
    }
    return k;
}

/* Return the number of lower tree levels maintained by treehash instances. */
static uint32_t GetTreehashCount(uint32_t hp)
{
    return hp - GetBdsK(hp);
}

/* Return the number of treehash update steps assigned after one signature. */
uint32_t XmssBds_GetTreehashUpdateBudget(uint32_t hp)
{
    return GetTreehashCount(hp) >> 1U;
}

/*
 * Calculate the encoded length of one XmssBdsState for the active parameter set.
 * The result includes active nodes, stack metadata, treehash metadata and flags.
 */
static uint32_t GetEncodedStateLen(const XmssCtxCommon *ctx, uint32_t hp)
{
    uint32_t n = ctx->n;
    uint32_t keepCount = (hp + 1U) >> 1U;
    uint32_t stackCount = hp + 1U;
    uint32_t nodeCount = hp + keepCount + stackCount + hp + XMSS_BDS_MAX_RETAIN + 1U;
    return nodeCount * n + stackCount + 2U * (uint32_t)sizeof(uint32_t) + hp * XMSS_BDS_TREEHASH_META_LEN + 1U;
}

/* Encode count fixed-capacity nodes, copying only the active n bytes from each node. */
static void EncodeNodes(uint8_t **pos, const uint8_t nodes[][XMSS_MAX_MDSIZE], uint32_t count, uint32_t n)
{
    for (uint32_t i = 0; i < count; i++) {
        memcpy(*pos, nodes[i], n);
        *pos += n;
    }
}

/* Decode count n-byte nodes into fixed-capacity XmssBdsState node arrays. */
static void DecodeNodes(const uint8_t **pos, uint8_t nodes[][XMSS_MAX_MDSIZE], uint32_t count, uint32_t n)
{
    for (uint32_t i = 0; i < count; i++) {
        memcpy(nodes[i], *pos, n);
        *pos += n;
    }
}

/*
 * Validate fields that later control array indexes, stack traversal and leaf generation.
 *
 * This prevents malformed state from driving out-of-bounds operations and rejects
 * impossible BDS state-machine combinations. It does not authenticate node values
 * or prevent rollback.
 */
static bool IsStateValid(const XmssBdsState *state, uint32_t hp)
{
    uint32_t stackCount = hp + 1U;
    uint32_t leafCount = 1U << hp;
    if (state->stackOffset > stackCount || (state->initialized && state->nextLeaf != leafCount) ||
        (!state->initialized && state->nextLeaf >= leafCount) ||
        (!state->initialized && state->stackOffset == stackCount)) {
        return false;
    }
    for (uint32_t i = 0; i < state->stackOffset; i++) {
        if (state->stackLevels[i] > hp) {
            return false;
        }
    }
    for (uint32_t i = 0; i < hp; i++) {
        const XmssBdsTreehash *treehash = &state->treehash[i];
        if (treehash->height != i || treehash->nextIdx > leafCount || treehash->stackUsage > state->stackOffset) {
            return false;
        }
    }
    return true;
}

/*
 * Encode one BDS tree state in a stable field order.
 *
 * Integer fields are big-endian and boolean fields are exactly one byte. The
 * caller must provide a buffer sized by GetEncodedStateLen().
 */
static void EncodeState(uint8_t **pos, const XmssBdsState *state, uint32_t hp, uint32_t n)
{
    uint32_t keepCount = (hp + 1U) >> 1U;
    uint32_t stackCount = hp + 1U;
    EncodeNodes(pos, state->auth, hp, n);
    EncodeNodes(pos, state->keep, keepCount, n);
    EncodeNodes(pos, state->stack, stackCount, n);
    memcpy(*pos, state->stackLevels, stackCount);
    *pos += stackCount;
    PUT_UINT32_BE(state->stackOffset, *pos, 0);
    *pos += sizeof(uint32_t);
    for (uint32_t i = 0; i < hp; i++) {
        const XmssBdsTreehash *treehash = &state->treehash[i];
        PUT_UINT32_BE(treehash->height, *pos, 0);
        *pos += sizeof(uint32_t);
        PUT_UINT32_BE(treehash->nextIdx, *pos, 0);
        *pos += sizeof(uint32_t);
        PUT_UINT32_BE(treehash->stackUsage, *pos, 0);
        *pos += sizeof(uint32_t);
        *(*pos)++ = treehash->completed ? 1U : 0U;
        memcpy(*pos, treehash->node, n);
        *pos += n;
    }
    EncodeNodes(pos, state->retain, XMSS_BDS_MAX_RETAIN, n);
    PUT_UINT32_BE(state->nextLeaf, *pos, 0);
    *pos += sizeof(uint32_t);
    memcpy(*pos, state->root, n);
    *pos += n;
    *(*pos)++ = state->initialized ? 1U : 0U;
}

/*
 * Decode and structurally validate one fixed-field BDS tree state.
 *
 * The enclosing import function validates the total input length before calling
 * this function, so each field read is bounded by the parameter-derived blob size.
 */
static int32_t DecodeState(const uint8_t **pos, XmssBdsState *state, uint32_t hp, uint32_t n)
{
    uint32_t keepCount = (hp + 1U) >> 1U;
    uint32_t stackCount = hp + 1U;
    DecodeNodes(pos, state->auth, hp, n);
    DecodeNodes(pos, state->keep, keepCount, n);
    DecodeNodes(pos, state->stack, stackCount, n);
    memcpy(state->stackLevels, *pos, stackCount);
    *pos += stackCount;
    state->stackOffset = GET_UINT32_BE(*pos, 0);
    *pos += sizeof(uint32_t);
    for (uint32_t i = 0; i < hp; i++) {
        XmssBdsTreehash *treehash = &state->treehash[i];
        treehash->height = GET_UINT32_BE(*pos, 0);
        *pos += sizeof(uint32_t);
        treehash->nextIdx = GET_UINT32_BE(*pos, 0);
        *pos += sizeof(uint32_t);
        treehash->stackUsage = GET_UINT32_BE(*pos, 0);
        *pos += sizeof(uint32_t);
        if (**pos > 1U) {
            return CRYPT_INVALID_ARG;
        }
        treehash->completed = (*(*pos)++ != 0);
        memcpy(treehash->node, *pos, n);
        *pos += n;
    }
    DecodeNodes(pos, state->retain, XMSS_BDS_MAX_RETAIN, n);
    state->nextLeaf = GET_UINT32_BE(*pos, 0);
    *pos += sizeof(uint32_t);
    memcpy(state->root, *pos, n);
    *pos += n;
    if (**pos > 1U) {
        return CRYPT_INVALID_ARG;
    }
    state->initialized = (*(*pos)++ != 0);
    return IsStateValid(state, hp) ? CRYPT_SUCCESS : CRYPT_INVALID_ARG;
}

/*
 * Map a completed upper-level node identified by tree row to its compact retain slot.
 * Retain stores nodes above the treehash-managed levels for future auth-path updates.
 */
static uint32_t RetainOffsetFromRow(uint32_t hp, uint32_t height, uint32_t row)
{
    return (1U << (hp - 1U - height)) + height - hp + ((row - 3U) >> 1U);
}

/* Map the next authentication-path node at height to its compact retain slot. */
static uint32_t RetainOffsetForAuth(uint32_t hp, uint32_t height, uint32_t leafIdx)
{
    uint32_t base = (1U << (hp - 1U - height)) + height - hp;
    uint32_t row = ((leafIdx >> height) - 1U) >> 1U;
    return base + row;
}

/*
 * Copy one retained node into an authentication path.
 *
 * Returns CRYPT_INVALID_ARG if the derived retain offset is outside the fixed
 * retain array, otherwise returns CRYPT_SUCCESS.
 */
static int32_t CopyRetainNode(uint8_t *dst, const XmssBdsState *state, uint32_t hp, uint32_t height, uint32_t leafIdx,
                              uint32_t n)
{
    uint32_t offset = RetainOffsetForAuth(hp, height, leafIdx);
    if (offset >= XMSS_BDS_MAX_RETAIN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    memcpy(dst, state->retain[offset], n);
    return CRYPT_SUCCESS;
}

/*
 * Classify a node produced during full-tree initialization and store it in the
 * initial auth path, a treehash result slot, or the compact retain array.
 */
static int32_t StoreInitialBdsNode(XmssBdsState *state, uint32_t nodeHeight, uint32_t nodeRow, const uint8_t *node,
                                   uint32_t hp, uint32_t n)
{
    if (nodeHeight >= hp) {
        return CRYPT_SUCCESS;
    }
    if (nodeRow == 1U) {
        memcpy(state->auth[nodeHeight], node, n);
        return CRYPT_SUCCESS;
    }

    uint32_t treehashCount = GetTreehashCount(hp);
    if (nodeRow == 3U && nodeHeight < treehashCount) {
        memcpy(state->treehash[nodeHeight].node, node, n);
        return CRYPT_SUCCESS;
    }
    if (nodeHeight >= treehashCount && nodeRow >= 3U) {
        uint32_t offset = RetainOffsetFromRow(hp, nodeHeight, nodeRow);
        if (offset >= XMSS_BDS_MAX_RETAIN) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        memcpy(state->retain[offset], node, n);
    }
    return CRYPT_SUCCESS;
}

/* Validate common pointers and parameter bounds used by BDS tree operations. */
static int32_t CheckTreeInput(const XmssBdsState *state, const HbsTreeCtx *treeCtx)
{
    if (state == NULL || treeCtx == NULL || treeCtx->hashFuncs.xmss == NULL ||
        treeCtx->hashFuncs.xmss->nodeHash == NULL || treeCtx->adrsOps == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (treeCtx->n == 0 || treeCtx->n > XMSS_MAX_MDSIZE || treeCtx->hp == 0 || treeCtx->hp > XMSS_BDS_MAX_HP ||
        treeCtx->algoType != HBS_ALGO_XMSS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_SUCCESS;
}

/*
 * Build the layer/tree portion of an XMSS address. Callers copy this base and
 * then set the address type and type-specific fields for WOTS or tree hashing.
 */
static void BuildBaseAdrs(void *adrs, uint32_t layer, uint64_t treeAddr, const HbsTreeCtx *treeCtx)
{
    memset(adrs, 0, HBS_MAX_ADRS_SIZE);
    treeCtx->adrsOps->setLayerAddr(adrs, layer);
    treeCtx->adrsOps->setTreeAddr(adrs, treeAddr);
}

/* Build the private WOTS+ view required to generate leaves and cached signatures. */
static void BuildWotsCtxFromTreeCtx(HbsWotsCtx *wotsCtx, const HbsTreeCtx *treeCtx)
{
    wotsCtx->coreCtx = treeCtx->originalCtx;
    wotsCtx->n = treeCtx->n;
    wotsCtx->otsLen = treeCtx->otsLen;
    wotsCtx->hashFuncs = treeCtx->hashFuncs.xmss;
    wotsCtx->adrsOps = treeCtx->adrsOps;
    wotsCtx->pubSeed = treeCtx->pubSeed;
    wotsCtx->skSeed = treeCtx->skSeed;
    wotsCtx->algoType = treeCtx->algoType;
}

/*
 * Generate leaf idx as the WOTS+ public key at the supplied layer and tree address.
 * The caller supplies a validated tree context and an n-byte output buffer.
 */
static int32_t GenerateLeaf(uint8_t *node, uint32_t idx, const uint8_t *baseAdrs, const HbsTreeCtx *treeCtx)
{
    uint8_t adrs[HBS_MAX_ADRS_SIZE];
    memcpy(adrs, baseAdrs, sizeof(adrs));
    treeCtx->adrsOps->setType(adrs, HBS_ADRS_TYPE_OTS);
    treeCtx->adrsOps->setKeyPairAddr(adrs, idx);

    HbsWotsCtx wotsCtx;
    BuildWotsCtxFromTreeCtx(&wotsCtx, treeCtx);
    return HbsWots_GeneratePublicKey(node, adrs, &wotsCtx);
}

/*
 * Hash two n-byte child nodes into their parent at the specified tree height and index.
 * The base address is copied so type-specific address updates do not affect callers.
 */
static int32_t HashParent(uint8_t *node, const uint8_t *left, const uint8_t *right, uint32_t height, uint32_t index,
                          const uint8_t *baseAdrs, const HbsTreeCtx *treeCtx)
{
    uint32_t n = treeCtx->n;
    uint8_t adrs[HBS_MAX_ADRS_SIZE];
    uint8_t tmp[XMSS_MAX_MDSIZE * 2U];

    memcpy(adrs, baseAdrs, sizeof(adrs));
    treeCtx->adrsOps->setType(adrs, HBS_ADRS_TYPE_HASH);
    treeCtx->adrsOps->setTreeHeight(adrs, height);
    treeCtx->adrsOps->setTreeIndex(adrs, index);
    memcpy(tmp, left, n);
    memcpy(tmp + n, right, n);
    return treeCtx->hashFuncs.xmss->nodeHash(treeCtx->originalCtx, adrs, tmp, 2U * n, node);
}

/*
 * Initialize dormant treehash slots. A completed slot requires no update until
 * XmssBds_TreeRound restarts it for a future authentication-path node.
 */
static void InitCompletedTreehash(XmssBdsState *state, uint32_t hp)
{
    for (uint32_t i = 0; i < hp; i++) {
        state->treehash[i].height = i;
        state->treehash[i].nextIdx = 0;
        state->treehash[i].stackUsage = 0;
        state->treehash[i].completed = true;
    }
}

/* Clear one current/next-tree state and restore its dormant treehash metadata. */
void XmssBds_ResetState(XmssBdsState *state, uint32_t hp)
{
    memset(state, 0, sizeof(*state));
    InitCompletedTreehash(state, hp);
}

/*
 * Allocate the one BDS tree state owned by an XMSS context.
 */
int32_t XmssBds_Alloc(XmssBdsCtx *bds)
{
    if (bds == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    XmssBds_Free(bds);
    bds->state = (XmssBdsState *)BSL_SAL_Calloc(1U, sizeof(XmssBdsState));
    if (bds->state == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

/*
 * Clear and release single-tree BDS allocation, then reset BDS metadata.
 * Accepting NULL keeps context cleanup paths simple.
 */
void XmssBds_Free(XmssBdsCtx *bds)
{
    if (bds == NULL) {
        return;
    }
    if (bds->state != NULL) {
        BSL_SAL_ClearFree(bds->state, sizeof(XmssBdsState));
    }
    memset(bds, 0, sizeof(*bds));
}

/*
 * Allocate all BDS state owned by an XMSSMT context: d current states, d - 1
 * next-tree states and d - 1 cached WOTS signatures.
 */
int32_t XmssmtBds_Alloc(XmssmtBdsCtx *bds, uint32_t d, uint32_t n, uint32_t wotsLen)
{
    if (bds == NULL || n == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (d == 0 || d > XMSS_BDS_MAX_D || n > XMSS_MAX_MDSIZE || wotsLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    XmssmtBds_Free(bds);
    uint32_t stateCount = ExpectedStateCount(d);
    bds->states = (XmssBdsState *)BSL_SAL_Calloc(stateCount, sizeof(XmssBdsState));
    if (bds->states == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    bds->stateCount = stateCount;

    bds->wotsSigsLen = ExpectedWotsSigsLen(n, d, wotsLen);
    if (bds->wotsSigsLen != 0) {
        bds->wotsSigs = (uint8_t *)BSL_SAL_Calloc(bds->wotsSigsLen, 1U);
        if (bds->wotsSigs == NULL) {
            XmssmtBds_Free(bds);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    return CRYPT_SUCCESS;
}

/*
 * Clear and release every XMSSMT BDS allocation, then reset BDS metadata.
 * Accepting NULL keeps context cleanup paths simple.
 */
void XmssmtBds_Free(XmssmtBdsCtx *bds)
{
    if (bds == NULL) {
        return;
    }
    if (bds->states != NULL) {
        BSL_SAL_ClearFree(bds->states, bds->stateCount * (uint32_t)sizeof(XmssBdsState));
    }
    if (bds->wotsSigs != NULL) {
        BSL_SAL_ClearFree(bds->wotsSigs, bds->wotsSigsLen);
    }
    memset(bds, 0, sizeof(*bds));
}

/*
 * Return the complete persisted BDS blob length for a valid enabled context.
 * Return zero when no exportable BDS state is present.
 */
static uint32_t XmssBds_GetStateLen(const XmssCtxCommon *ctx, const XmssBdsState *states, uint32_t stateCount,
                                    bool enabled, uint32_t wotsSigsLen, uint32_t d, uint32_t hp, uint32_t wotsLen)
{
    if (ctx == NULL || ctx->n == 0 || states == NULL || !enabled || stateCount != ExpectedStateCount(d) ||
        wotsSigsLen != ExpectedWotsSigsLen(ctx->n, d, wotsLen)) {
        return 0;
    }
    uint32_t stateBytes = stateCount * GetEncodedStateLen(ctx, hp);
    return XMSS_BDS_BLOB_HEADER_LEN + stateBytes + wotsSigsLen;
}

/*
 * Export parameter metadata, the private-key index, every BDS tree state and
 * cached WOTS signatures using the fixed-field encoding.
 *
 * If out is NULL or too short, outLen receives the required length. Runtime
 * state is structurally validated before any blob is emitted.
 */
static int32_t BdsExportStateCommon(const XmssCtxCommon *ctx, const XmssBdsState *states, uint32_t stateCount,
                                    const uint8_t *wotsSigs, uint32_t wotsSigsLen, bool enabled,
                                    CRYPT_PKEY_ParaId algId, uint32_t h, uint32_t d, uint32_t hp,
                                    uint32_t wotsLen, uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (algId == 0 || h == 0 || d == 0 || hp == 0 || wotsLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint32_t required = XmssBds_GetStateLen(ctx, states, stateCount, enabled, wotsSigsLen, d, hp, wotsLen);
    if (required == 0) {
        *outLen = 0;
        return CRYPT_SUCCESS;
    }
    if (out == NULL || *outLen < required) {
        *outLen = required;
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_LEN_NOT_ENOUGH);
        return CRYPT_XMSS_LEN_NOT_ENOUGH;
    }
    for (uint32_t i = 0; i < stateCount; i++) {
        if (!IsStateValid(&states[i], hp)) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
    }

    /*
     * The header binds the blob to the active parameter set and private-key
     * index. Array lengths are derived from these fields during import.
     */
    uint8_t *pos = out;
    PUT_UINT32_BE((uint32_t)algId, pos, 0);
    pos += sizeof(uint32_t);
    Uint64ToBeBytes(ctx->key.idx, pos);
    pos += sizeof(uint64_t);
    PUT_UINT32_BE(ctx->n, pos, 0);
    pos += sizeof(uint32_t);
    PUT_UINT32_BE(h, pos, 0);
    pos += sizeof(uint32_t);
    PUT_UINT32_BE(d, pos, 0);
    pos += sizeof(uint32_t);
    PUT_UINT32_BE(hp, pos, 0);
    pos += sizeof(uint32_t);
    PUT_UINT32_BE(stateCount, pos, 0);
    pos += sizeof(uint32_t);
    PUT_UINT32_BE(wotsSigsLen, pos, 0);
    pos += sizeof(uint32_t);

    for (uint32_t i = 0; i < stateCount; i++) {
        EncodeState(&pos, &states[i], hp, ctx->n);
    }
    if (wotsSigsLen != 0) {
        if (wotsSigs == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
            return CRYPT_NULL_INPUT;
        }
        memcpy(pos, wotsSigs, wotsSigsLen);
        pos += wotsSigsLen;
    }
    *outLen = (uint32_t)(pos - out);
    return CRYPT_SUCCESS;
}

/*
 * Import a fixed-field BDS blob for the private key already staged in ctx.
 *
 * Header values must match the active parameter set and private-key index.
 * Decoding is performed into a temporary context; existing BDS state is replaced
 * only after every state passes structural and semantic validation.
 */
static int32_t BdsImportStateCommon(const XmssCtxCommon *ctx, XmssmtBdsCtx *tmpBds, CRYPT_PKEY_ParaId expectedAlgId,
                                    uint32_t expectedH, uint32_t expectedD, uint32_t expectedHp,
                                    uint32_t expectedWotsLen, const uint8_t *in, uint32_t inLen)
{
    if (ctx == NULL || tmpBds == NULL || ctx->n == 0 || in == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (expectedAlgId == 0 || expectedH == 0 || expectedD == 0 || expectedHp == 0 || expectedWotsLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (inLen < XMSS_BDS_BLOB_HEADER_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    /* Parse the fixed-size header before allocating any replacement state. */
    const uint8_t *pos = in;
    uint32_t algId = GET_UINT32_BE(pos, 0);
    pos += sizeof(uint32_t);
    uint64_t idx = Uint64FromBeBytes(pos);
    pos += sizeof(uint64_t);
    uint32_t n = GET_UINT32_BE(pos, 0);
    pos += sizeof(uint32_t);
    uint32_t h = GET_UINT32_BE(pos, 0);
    pos += sizeof(uint32_t);
    uint32_t d = GET_UINT32_BE(pos, 0);
    pos += sizeof(uint32_t);
    uint32_t hp = GET_UINT32_BE(pos, 0);
    pos += sizeof(uint32_t);
    uint32_t stateCount = GET_UINT32_BE(pos, 0);
    pos += sizeof(uint32_t);
    uint32_t wotsSigsLen = GET_UINT32_BE(pos, 0);
    pos += sizeof(uint32_t);

    /*
     * Header fields are trusted only after they match the already selected
     * parameter set and the private key staged by SetPrvKey.
     */
    uint32_t expectedStateCount = ExpectedStateCount(expectedD);
    uint32_t expectedWotsSigsLen = ExpectedWotsSigsLen(ctx->n, expectedD, expectedWotsLen);
    if (algId != (uint32_t)expectedAlgId || idx != ctx->key.idx || n != ctx->n ||
        h != expectedH || d != expectedD || hp != expectedHp || stateCount != expectedStateCount ||
        wotsSigsLen != expectedWotsSigsLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint32_t stateBytes = stateCount * GetEncodedStateLen(ctx, expectedHp);
    uint32_t expectedLen = XMSS_BDS_BLOB_HEADER_LEN + stateBytes + wotsSigsLen;
    if (expectedLen != inLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    /*
     * Decode into temporary ownership. A malformed state leaves caller-owned
     * BDS state unchanged.
     */
    int32_t ret = XmssmtBds_Alloc(tmpBds, expectedD, ctx->n, expectedWotsLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    for (uint32_t i = 0; i < stateCount; i++) {
        ret = DecodeState(&pos, &tmpBds->states[i], hp, n);
        if (ret != CRYPT_SUCCESS) {
            XmssmtBds_Free(tmpBds);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (i < d && !tmpBds->states[i].initialized) {
            XmssmtBds_Free(tmpBds);
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
    }
    if (memcmp(tmpBds->states[d - 1U].root, ctx->key.root, n) != 0) {
        XmssmtBds_Free(tmpBds);
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (wotsSigsLen != 0) {
        memcpy(tmpBds->wotsSigs, pos, wotsSigsLen);
    }
    tmpBds->enabled = true;
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_XMSS
int32_t XmssBds_ExportTreeState(const XmssCtxCommon *ctx, const XmssBdsCtx *bds, const XmssParams *params,
                                uint8_t *out, uint32_t *outLen)
{
    if (bds == NULL || params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return BdsExportStateCommon(ctx, bds->state, 1U, NULL, 0, bds->enabled, params->algId, params->h, 1U,
                                params->h, params->wotsLen, out, outLen);
}

int32_t XmssBds_ImportTreeState(const XmssCtxCommon *ctx, XmssBdsCtx *bds, const XmssParams *params,
                                const uint8_t *in, uint32_t inLen)
{
    if (bds == NULL || params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    XmssmtBdsCtx tmpBds = {0};
    int32_t ret = BdsImportStateCommon(ctx, &tmpBds, params->algId, params->h, 1U, params->h, params->wotsLen,
                                       in, inLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    XmssBds_Free(bds);
    bds->state = tmpBds.states;
    bds->enabled = tmpBds.enabled;
    tmpBds.states = NULL;
    tmpBds.stateCount = 0;
    tmpBds.enabled = false;
    XmssmtBds_Free(&tmpBds);
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_XMSSMT
int32_t XmssmtBds_ExportHyperTreeState(const XmssCtxCommon *ctx, const XmssmtBdsCtx *bds,
                                       const XmssmtParams *params, uint8_t *out, uint32_t *outLen)
{
    if (bds == NULL || params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return BdsExportStateCommon(ctx, bds->states, bds->stateCount, bds->wotsSigs, bds->wotsSigsLen,
                                bds->enabled, params->algId, params->h, params->d, params->hp,
                                params->wotsLen, out, outLen);
}

int32_t XmssmtBds_ImportHyperTreeState(const XmssCtxCommon *ctx, XmssmtBdsCtx *bds, const XmssmtParams *params,
                                       const uint8_t *in, uint32_t inLen)
{
    if (bds == NULL || params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    XmssmtBdsCtx tmpBds = {0};
    int32_t ret = BdsImportStateCommon(ctx, &tmpBds, params->algId, params->h, params->d, params->hp,
                                       params->wotsLen, in, inLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    XmssmtBds_Free(bds);
    *bds = tmpBds;
    memset(&tmpBds, 0, sizeof(tmpBds));
    return CRYPT_SUCCESS;
}
#endif

/* Serialize the current hp-node authentication path into a layer signature. */
int32_t XmssBds_CopyAuthPath(const XmssBdsState *state, uint8_t *out, uint32_t hp, uint32_t n)
{
    if (state == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    for (uint32_t i = 0; i < hp; i++) {
        memcpy(out + i * n, state->auth[i], n);
    }
    return CRYPT_SUCCESS;
}

/* Generate the WOTS+ signature for one XMSS tree layer without updating BDS state. */
int32_t XmssBds_SignWotsLayer(const uint8_t *msg, uint32_t msgLen, uint32_t layer, uint64_t treeAddr,
                              uint32_t leafIdx, const HbsTreeCtx *treeCtx, uint8_t *sig)
{
    uint8_t adrs[HBS_MAX_ADRS_SIZE];
    BuildBaseAdrs(adrs, layer, treeAddr, treeCtx);
    treeCtx->adrsOps->setType(adrs, HBS_ADRS_TYPE_OTS);
    treeCtx->adrsOps->setKeyPairAddr(adrs, leafIdx);

    HbsWotsCtx wotsCtx;
    BuildWotsCtxFromTreeCtx(&wotsCtx, treeCtx);
    uint32_t wotsSigLen = treeCtx->otsLen * treeCtx->n;
    return HbsWots_Sign(sig, &wotsSigLen, msg, msgLen, adrs, &wotsCtx);
}

/*
 * Write one XMSS layer signature as WOTS+ signature followed by the current
 * authentication path. This function intentionally does not advance BDS state.
 */
int32_t XmssBds_WriteLayerSignature(const XmssBdsState *state, const uint8_t *msg, uint32_t msgLen,
                                    uint32_t leafIdx, uint32_t layer, uint64_t treeAddr,
                                    const HbsTreeCtx *treeCtx, uint8_t *sig, uint32_t *sigLen)
{
    if (state == NULL || msg == NULL || sig == NULL || sigLen == NULL || !state->initialized ||
        leafIdx >= (1U << treeCtx->hp)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint32_t n = treeCtx->n;
    uint32_t layerSigLen = (treeCtx->otsLen + treeCtx->hp) * n;
    if (*sigLen < layerSigLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_SIG_LEN);
        return CRYPT_XMSS_ERR_INVALID_SIG_LEN;
    }

    int32_t ret = XmssBds_SignWotsLayer(msg, msgLen, layer, treeAddr, leafIdx, treeCtx, sig);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = XmssBds_CopyAuthPath(state, sig + treeCtx->otsLen * n, treeCtx->hp, n);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    *sigLen = layerSigLen;
    return CRYPT_SUCCESS;
}

/*
 * Fully initialize one current-tree BDS state.
 *
 * Leaves are generated from left to right and merged on the shared stack.
 * StoreInitialBdsNode records the initial auth, treehash and retain nodes while
 * the final stack root becomes the state root.
 */
int32_t XmssBds_InitTreeState(XmssBdsState *state, uint32_t layer, uint64_t treeAddr, const HbsTreeCtx *treeCtx)
{
    int32_t ret = CheckTreeInput(state, treeCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint32_t n = treeCtx->n;
    uint32_t hp = treeCtx->hp;
    uint8_t baseAdrs[HBS_MAX_ADRS_SIZE];
    BuildBaseAdrs(baseAdrs, layer, treeAddr, treeCtx);

    memset(state, 0, sizeof(*state));
    InitCompletedTreehash(state, hp);

    /*
     * The shared stack builds the full Merkle tree. Nodes are recorded for BDS
     * immediately before they are merged into their parent.
     */
    uint32_t leafCount = 1U << hp;
    for (uint32_t leaf = 0; leaf < leafCount; leaf++) {
        ret = GenerateLeaf(state->stack[state->stackOffset], leaf, baseAdrs, treeCtx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        state->stackLevels[state->stackOffset++] = 0;

        if (leaf == 1U) {
            memcpy(state->auth[0], state->stack[state->stackOffset - 1U], n);
        }
        while (state->stackOffset > 1U &&
               state->stackLevels[state->stackOffset - 1U] == state->stackLevels[state->stackOffset - 2U]) {
            uint32_t nodeHeight = state->stackLevels[state->stackOffset - 1U];
            uint32_t nodeIndex = leaf >> (nodeHeight + 1U);
            uint32_t nodeRow = leaf >> nodeHeight;

            ret = StoreInitialBdsNode(state, nodeHeight, nodeRow, state->stack[state->stackOffset - 1U], hp, n);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }

            ret = HashParent(state->stack[state->stackOffset - 2U], state->stack[state->stackOffset - 2U],
                             state->stack[state->stackOffset - 1U], nodeHeight, nodeIndex, baseAdrs, treeCtx);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            state->stackLevels[state->stackOffset - 2U]++;
            state->stackOffset--;
        }
    }

    memcpy(state->root, state->stack[0], n);
    state->stackOffset = 0;
    state->nextLeaf = leafCount;
    state->initialized = true;
    return CRYPT_SUCCESS;
}

/*
 * Return the height of the first zero bit in leafIdx.
 * This is the level at which the authentication path changes after signing leafIdx.
 */
static uint32_t GetTau(uint32_t leafIdx, uint32_t hp)
{
    for (uint32_t i = 0; i < hp; i++) {
        if (((leafIdx >> i) & 1U) == 0) {
            return i;
        }
    }
    return hp;
}

/*
 * Advance one initialized tree state from leafIdx to leafIdx + 1.
 *
 * The round computes auth[tau], restores lower auth nodes from treehash/retain,
 * and restarts treehash instances needed by future rounds. Treehash work itself
 * is scheduled separately by XmssBds_TreehashUpdates.
 */
int32_t XmssBds_TreeRound(XmssBdsState *state, uint32_t leafIdx, uint32_t layer, uint64_t treeAddr,
                          const HbsTreeCtx *treeCtx)
{
    int32_t ret = CheckTreeInput(state, treeCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (!state->initialized || leafIdx >= ((1U << treeCtx->hp) - 1U)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint32_t n = treeCtx->n;
    uint32_t hp = treeCtx->hp;
    uint32_t tau = GetTau(leafIdx, hp);
    uint8_t baseAdrs[HBS_MAX_ADRS_SIZE];
    uint8_t left[XMSS_MAX_MDSIZE];
    uint8_t right[XMSS_MAX_MDSIZE];

    BuildBaseAdrs(baseAdrs, layer, treeAddr, treeCtx);

    /*
     * Save the two children needed to calculate the new auth[tau] before any
     * authentication-path slot is overwritten.
     */
    if (tau > 0) {
        memcpy(left, state->auth[tau - 1U], n);
        memcpy(right, state->keep[(tau - 1U) >> 1U], n);
    }

    /* Preserve an auth node that a later round will need as a right child. */
    if (!(((leafIdx >> (tau + 1U)) & 1U) != 0) && tau < hp - 1U) {
        memcpy(state->keep[tau >> 1U], state->auth[tau], n);
    }

    /* At level zero, the next authentication node is the current leaf itself. */
    if (tau == 0) {
        ret = GenerateLeaf(state->auth[0], leafIdx, baseAdrs, treeCtx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        return CRYPT_SUCCESS;
    }

    uint8_t parent[XMSS_MAX_MDSIZE];
    ret = HashParent(parent, left, right, tau - 1U, leafIdx >> tau, baseAdrs, treeCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    memcpy(state->auth[tau], parent, n);

    /*
     * Lower auth nodes come from completed treehash instances. Higher nodes,
     * which are needed less frequently, come from retain storage.
     */
    uint32_t treehashCount = GetTreehashCount(hp);
    for (uint32_t i = 0; i < tau; i++) {
        if (i < treehashCount) {
            if (!state->treehash[i].completed) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            memcpy(state->auth[i], state->treehash[i].node, n);
        } else {
            ret = CopyRetainNode(state->auth[i], state, hp, i, leafIdx, n);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
        }
    }

    /* Restart the treehash instances consumed by this authentication update. */
    uint32_t restartCount = tau < treehashCount ? tau : treehashCount;
    for (uint32_t i = 0; i < restartCount; i++) {
        uint32_t startIdx = leafIdx + 1U + 3U * (1U << i);
        state->treehash[i].height = i;
        state->treehash[i].nextIdx = startIdx;
        state->treehash[i].stackUsage = 0;
        state->treehash[i].completed = (startIdx >= (1U << hp));
    }

    return CRYPT_SUCCESS;
}

/*
 * Return the scheduling priority of one treehash instance.
 * Lower unfinished stack heights are updated before higher ones; completed
 * instances return hp so they are excluded from scheduling.
 */
static uint32_t TreehashMinHeight(const XmssBdsState *state, const XmssBdsTreehash *treehash, uint32_t hp)
{
    if (treehash->completed) {
        return hp;
    }
    if (treehash->stackUsage == 0) {
        return treehash->height;
    }
    uint32_t minHeight = hp;
    for (uint32_t i = 0; i < treehash->stackUsage; i++) {
        uint32_t pos = state->stackOffset - i - 1U;
        if (state->stackLevels[pos] < minHeight) {
            minHeight = state->stackLevels[pos];
        }
    }
    return minHeight;
}

/*
 * Execute one leaf-generation step for a treehash instance.
 *
 * The generated leaf is merged with stack nodes owned by this treehash. Once
 * target height is reached, the result is stored in treehash->node; otherwise
 * the partial node is pushed back onto the shared state stack.
 */
static int32_t TreehashUpdateOne(XmssBdsState *state, XmssBdsTreehash *treehash, const uint8_t *baseAdrs,
                                 const HbsTreeCtx *treeCtx)
{
    uint32_t hp = treeCtx->hp;
    uint32_t n = treeCtx->n;
    if (treehash->completed || treehash->nextIdx >= (1U << hp)) {
        treehash->completed = true;
        return CRYPT_SUCCESS;
    }

    uint8_t node[XMSS_MAX_MDSIZE];
    uint8_t parent[XMSS_MAX_MDSIZE];
    uint32_t nodeHeight = 0;
    uint32_t leafIdx = treehash->nextIdx;

    int32_t ret = GenerateLeaf(node, leafIdx, baseAdrs, treeCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    while (treehash->stackUsage > 0 && state->stackOffset > 0 &&
           state->stackLevels[state->stackOffset - 1U] == nodeHeight) {
        ret = HashParent(parent, state->stack[state->stackOffset - 1U], node, nodeHeight, leafIdx >> (nodeHeight + 1U),
                         baseAdrs, treeCtx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        memcpy(node, parent, n);
        nodeHeight++;
        treehash->stackUsage--;
        state->stackOffset--;
    }

    if (nodeHeight == treehash->height) {
        memcpy(treehash->node, node, n);
        treehash->completed = true;
    } else {
        if (state->stackOffset >= XMSS_BDS_MAX_HP + 1U) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        memcpy(state->stack[state->stackOffset], node, n);
        state->stackLevels[state->stackOffset] = (uint8_t)nodeHeight;
        state->stackOffset++;
        treehash->stackUsage++;
        treehash->nextIdx++;
    }
    return CRYPT_SUCCESS;
}

/*
 * Spend up to updates treehash steps on the initialized tree state.
 *
 * Each step selects the unfinished treehash instance with the lowest current
 * height. unusedUpdates receives any budget left after all instances complete.
 */
int32_t XmssBds_TreehashUpdates(XmssBdsState *state, uint32_t updates, uint32_t layer, uint64_t treeAddr,
                                const HbsTreeCtx *treeCtx, uint32_t *unusedUpdates)
{
    int32_t ret = CheckTreeInput(state, treeCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (!state->initialized) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint32_t used = 0;
    uint32_t hp = treeCtx->hp;
    uint32_t treehashCount = GetTreehashCount(hp);
    uint8_t baseAdrs[HBS_MAX_ADRS_SIZE];
    BuildBaseAdrs(baseAdrs, layer, treeAddr, treeCtx);

    for (; used < updates; used++) {
        uint32_t level = treehashCount;
        uint32_t minHeight = hp;
        for (uint32_t i = 0; i < treehashCount; i++) {
            uint32_t low = TreehashMinHeight(state, &state->treehash[i], hp);
            if (low < minHeight) {
                level = i;
                minHeight = low;
            }
        }
        if (level == treehashCount) {
            break;
        }
        ret = TreehashUpdateOne(state, &state->treehash[level], baseAdrs, treeCtx);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    if (unusedUpdates != NULL) {
        *unusedUpdates = updates - used;
    }
    return CRYPT_SUCCESS;
}

/*
 * Incrementally build one leaf of a future XMSSMT layer tree.
 *
 * Repeated calls eventually produce a fully initialized next-tree state. This
 * spreads expensive future-tree construction across signatures of the current tree.
 */
int32_t XmssBds_NextTreeUpdate(XmssBdsState *nextState, uint32_t layer, uint64_t treeAddr,
                               const HbsTreeCtx *treeCtx)
{
    int32_t ret = CheckTreeInput(nextState, treeCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint32_t hp = treeCtx->hp;
    uint32_t n = treeCtx->n;
    uint32_t leafCount = 1U << hp;
    if (nextState->initialized) {
        return CRYPT_SUCCESS;
    }
    if (nextState->nextLeaf >= leafCount) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (nextState->nextLeaf == 0 && nextState->stackOffset == 0) {
        InitCompletedTreehash(nextState, hp);
    }

    /*
     * A next-tree state uses the same stack construction as full initialization,
     * but consumes exactly one leaf per call.
     */
    uint8_t baseAdrs[HBS_MAX_ADRS_SIZE];
    BuildBaseAdrs(baseAdrs, layer, treeAddr, treeCtx);
    uint32_t leaf = nextState->nextLeaf;
    ret = GenerateLeaf(nextState->stack[nextState->stackOffset], leaf, baseAdrs, treeCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    nextState->stackLevels[nextState->stackOffset++] = 0;

    if (leaf == 1U) {
        memcpy(nextState->auth[0], nextState->stack[nextState->stackOffset - 1U], n);
    }
    while (nextState->stackOffset > 1U &&
           nextState->stackLevels[nextState->stackOffset - 1U] == nextState->stackLevels[nextState->stackOffset - 2U]) {
        uint32_t nodeHeight = nextState->stackLevels[nextState->stackOffset - 1U];
        uint32_t nodeIndex = leaf >> (nodeHeight + 1U);
        uint32_t nodeRow = leaf >> nodeHeight;

        ret = StoreInitialBdsNode(nextState, nodeHeight, nodeRow, nextState->stack[nextState->stackOffset - 1U], hp, n);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }

        ret = HashParent(nextState->stack[nextState->stackOffset - 2U], nextState->stack[nextState->stackOffset - 2U],
                         nextState->stack[nextState->stackOffset - 1U], nodeHeight, nodeIndex, baseAdrs, treeCtx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        nextState->stackLevels[nextState->stackOffset - 2U]++;
        nextState->stackOffset--;
    }

    nextState->nextLeaf++;
    if (nextState->nextLeaf == leafCount && nextState->stackOffset == 1U && nextState->stackLevels[0] == hp) {
        memcpy(nextState->root, nextState->stack[0], n);
        nextState->stackOffset = 0;
        nextState->initialized = true;
    }
    return CRYPT_SUCCESS;
}

/* Swap a finished next-tree state into the active-tree slot without allocating memory. */
int32_t XmssBds_StateSwap(XmssBdsState *a, XmssBdsState *b)
{
    if (a == NULL || b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    XmssBdsState tmp = *a;
    *a = *b;
    *b = tmp;
    return CRYPT_SUCCESS;
}

#endif /* defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT) */

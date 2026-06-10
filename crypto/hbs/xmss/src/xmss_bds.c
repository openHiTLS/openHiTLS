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
 *   - states[0, d) hold the current tree state for each XMSSMT layer.
 *   - states[d, 2d - 1) incrementally build the next tree for each non-top layer.
 *   - wotsSigs caches upper-layer WOTS signatures over the current lower-layer roots.
 *
 * Persisted state uses a fixed-field big-endian encoding. Only active hp-by-n
 * portions of fixed-capacity arrays are encoded, so the blob is independent of
 * compiler padding and the in-memory XmssBdsState layout.
 */

/* Return the number of current-tree and next-tree BDS states required by the parameter set. */
static uint32_t ExpectedStateCount(const CryptXmssCtx *ctx)
{
    return 2U * ctx->params->d - 1U;
}

/* Return the number of bytes required for cached upper-layer WOTS signatures. */
static uint32_t ExpectedWotsSigsLen(const CryptXmssCtx *ctx)
{
    if (ctx->params->d <= 1U) {
        return 0;
    }
    return (ctx->params->d - 1U) * ctx->params->wotsLen * ctx->params->n;
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
static uint32_t GetTreehashUpdateBudget(uint32_t hp)
{
    return GetTreehashCount(hp) >> 1U;
}

/*
 * Calculate the encoded length of one XmssBdsState for the active parameter set.
 * The result includes active nodes, stack metadata, treehash metadata and flags.
 */
static uint32_t GetEncodedStateLen(const CryptXmssCtx *ctx)
{
    uint32_t hp = ctx->params->hp;
    uint32_t n = ctx->params->n;
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
 * This is structural validation only. It prevents malformed state from driving
 * out-of-bounds operations, but does not authenticate node values or prevent rollback.
 */
static bool IsStateValid(const XmssBdsState *state, uint32_t hp)
{
    uint32_t stackCount = hp + 1U;
    uint32_t leafCount = 1U << hp;
    if (state->stackOffset > stackCount || state->nextLeaf > leafCount ||
        (!state->initialized && state->nextLeaf < leafCount && state->stackOffset == stackCount)) {
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
static void ResetSingleState(XmssBdsState *state, uint32_t hp)
{
    memset(state, 0, sizeof(*state));
    InitCompletedTreehash(state, hp);
}

/*
 * Allocate all BDS state owned by ctx.
 *
 * Existing BDS allocations are released first. XMSS uses one state; XMSSMT uses
 * d current states, d - 1 next-tree states and d - 1 cached WOTS signatures.
 */
static int32_t XmssBds_Alloc(CryptXmssCtx *ctx)
{
    if (ctx == NULL || ctx->params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t d = ctx->params->d;
    if (d == 0 || d > XMSS_BDS_MAX_D || ctx->params->hp == 0 || ctx->params->hp > XMSS_BDS_MAX_HP) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    XmssBds_Free(ctx);
    uint32_t stateCount = 2U * d - 1U;
    ctx->bds.states = (XmssBdsState *)BSL_SAL_Calloc(stateCount, sizeof(XmssBdsState));
    if (ctx->bds.states == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->bds.stateCount = stateCount;

    if (d > 1U) {
        ctx->bds.wotsSigsLen = (d - 1U) * ctx->params->wotsLen * ctx->params->n;
        ctx->bds.wotsSigs = (uint8_t *)BSL_SAL_Calloc(ctx->bds.wotsSigsLen, 1U);
        if (ctx->bds.wotsSigs == NULL) {
            XmssBds_Free(ctx);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    return CRYPT_SUCCESS;
}

/*
 * Clear and release every BDS allocation owned by ctx, then reset BDS metadata.
 * Accepting NULL keeps context cleanup paths simple.
 */
void XmssBds_Free(CryptXmssCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->bds.states != NULL) {
        BSL_SAL_ClearFree(ctx->bds.states, ctx->bds.stateCount * (uint32_t)sizeof(XmssBdsState));
    }
    if (ctx->bds.wotsSigs != NULL) {
        BSL_SAL_ClearFree(ctx->bds.wotsSigs, ctx->bds.wotsSigsLen);
    }
    memset(&ctx->bds, 0, sizeof(ctx->bds));
}

/*
 * Return the complete persisted BDS blob length for a valid enabled context.
 * Return zero when no exportable BDS state is present.
 */
static uint32_t XmssBds_GetStateLen(const CryptXmssCtx *ctx)
{
    if (ctx == NULL || ctx->params == NULL || ctx->bds.states == NULL || !ctx->bds.enabled ||
        ctx->bds.stateCount != ExpectedStateCount(ctx) || ctx->bds.wotsSigsLen != ExpectedWotsSigsLen(ctx)) {
        return 0;
    }
    uint32_t stateBytes = ctx->bds.stateCount * GetEncodedStateLen(ctx);
    return XMSS_BDS_BLOB_HEADER_LEN + stateBytes + ctx->bds.wotsSigsLen;
}

/*
 * Export parameter metadata, the private-key index, every BDS tree state and
 * cached WOTS signatures using the fixed-field encoding.
 *
 * If out is NULL or too short, outLen receives the required length. Runtime
 * state is structurally validated before any blob is emitted.
 */
int32_t XmssBds_ExportState(const CryptXmssCtx *ctx, uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint32_t required = XmssBds_GetStateLen(ctx);
    if (required == 0) {
        *outLen = 0;
        return CRYPT_SUCCESS;
    }
    if (out == NULL || *outLen < required) {
        *outLen = required;
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_LEN_NOT_ENOUGH);
        return CRYPT_XMSS_LEN_NOT_ENOUGH;
    }
    for (uint32_t i = 0; i < ctx->bds.stateCount; i++) {
        if (!IsStateValid(&ctx->bds.states[i], ctx->params->hp)) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
    }

    /*
     * The header binds the blob to the active parameter set and private-key
     * index. Array lengths are derived from these fields during import.
     */
    uint8_t *pos = out;
    PUT_UINT32_BE((uint32_t)ctx->params->algId, pos, 0);
    pos += sizeof(uint32_t);
    Uint64ToBeBytes(ctx->key.idx, pos);
    pos += sizeof(uint64_t);
    PUT_UINT32_BE(ctx->params->n, pos, 0);
    pos += sizeof(uint32_t);
    PUT_UINT32_BE(ctx->params->h, pos, 0);
    pos += sizeof(uint32_t);
    PUT_UINT32_BE(ctx->params->d, pos, 0);
    pos += sizeof(uint32_t);
    PUT_UINT32_BE(ctx->params->hp, pos, 0);
    pos += sizeof(uint32_t);
    PUT_UINT32_BE(ctx->bds.stateCount, pos, 0);
    pos += sizeof(uint32_t);
    PUT_UINT32_BE(ctx->bds.wotsSigsLen, pos, 0);
    pos += sizeof(uint32_t);

    for (uint32_t i = 0; i < ctx->bds.stateCount; i++) {
        EncodeState(&pos, &ctx->bds.states[i], ctx->params->hp, ctx->params->n);
    }
    if (ctx->bds.wotsSigsLen != 0) {
        memcpy(pos, ctx->bds.wotsSigs, ctx->bds.wotsSigsLen);
        pos += ctx->bds.wotsSigsLen;
    }
    *outLen = (uint32_t)(pos - out);
    return CRYPT_SUCCESS;
}

/*
 * Import a fixed-field BDS blob for the private key already staged in ctx.
 *
 * Header values must match the active parameter set and private-key index.
 * Decoding is performed into a temporary context; existing BDS state is replaced
 * only after every state passes structural validation.
 */
int32_t XmssBds_ImportState(CryptXmssCtx *ctx, const uint8_t *in, uint32_t inLen)
{
    if (ctx == NULL || ctx->params == NULL || in == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
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
    uint32_t expectedStateCount = ExpectedStateCount(ctx);
    uint32_t expectedWotsSigsLen = ExpectedWotsSigsLen(ctx);
    if (algId != (uint32_t)ctx->params->algId || idx != ctx->key.idx || n != ctx->params->n ||
        h != ctx->params->h || d != ctx->params->d || hp != ctx->params->hp || stateCount != expectedStateCount ||
        wotsSigsLen != expectedWotsSigsLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint32_t stateBytes = stateCount * GetEncodedStateLen(ctx);
    uint32_t expectedLen = XMSS_BDS_BLOB_HEADER_LEN + stateBytes + wotsSigsLen;
    if (expectedLen != inLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    /*
     * Decode into temporary ownership. A malformed state leaves ctx and its
     * existing BDS state unchanged.
     */
    CryptXmssCtx tmpCtx = {0};
    tmpCtx.params = ctx->params;
    int32_t ret = XmssBds_Alloc(&tmpCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    for (uint32_t i = 0; i < stateCount; i++) {
        ret = DecodeState(&pos, &tmpCtx.bds.states[i], hp, n);
        if (ret != CRYPT_SUCCESS) {
            XmssBds_Free(&tmpCtx);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if (wotsSigsLen != 0) {
        memcpy(tmpCtx.bds.wotsSigs, pos, wotsSigsLen);
    }
    /* All validation passed; replace the old state in one commit step. */
    tmpCtx.bds.enabled = true;
    XmssBds_Free(ctx);
    ctx->bds = tmpCtx.bds;
    memset(&tmpCtx.bds, 0, sizeof(tmpCtx.bds));
    return CRYPT_SUCCESS;
}

/* Serialize the current hp-node authentication path into a layer signature. */
static int32_t CopyAuthPath(const XmssBdsState *state, uint8_t *out, uint32_t hp, uint32_t n)
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
static int32_t WotsSignLayer(const uint8_t *msg, uint32_t msgLen, uint32_t layer, uint64_t treeAddr, uint32_t leafIdx,
                             const HbsTreeCtx *treeCtx, uint8_t *sig)
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
static int32_t WriteLayerSignatureNoUpdate(const XmssBdsState *state, const uint8_t *msg, uint32_t msgLen,
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

    int32_t ret = WotsSignLayer(msg, msgLen, layer, treeAddr, leafIdx, treeCtx, sig);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CopyAuthPath(state, sig + treeCtx->otsLen * n, treeCtx->hp, n);
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
static int32_t XmssBds_TreeInit(XmssBdsState *state, uint32_t layer, uint64_t treeAddr, const HbsTreeCtx *treeCtx)
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
static int32_t XmssBds_TreeRound(XmssBdsState *state, uint32_t leafIdx, uint32_t layer, uint64_t treeAddr,
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
static int32_t XmssBds_TreehashUpdates(XmssBdsState *state, uint32_t updates, uint32_t layer, uint64_t treeAddr,
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
static int32_t XmssBds_NextTreeUpdate(XmssBdsState *nextState, uint32_t layer, uint64_t treeAddr,
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
static int32_t XmssBds_StateSwap(XmssBdsState *a, XmssBdsState *b)
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

/*
 * Initialize BDS acceleration for a newly generated XMSS/XMSSMT private key.
 *
 * Current trees for every layer are built immediately. XMSSMT also caches the
 * upper-layer WOTS signatures and prepares empty next-tree states. Any failure
 * releases the partially initialized BDS context.
 */
int32_t XmssBds_HyperTreeInit(CryptXmssCtx *ctx)
{
    if (ctx == NULL || ctx->params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = XmssBds_Alloc(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint32_t d = ctx->params->d;
    uint32_t n = ctx->params->n;
    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitFromXmss(&treeCtx, ctx);

    for (uint32_t layer = 0; layer < d; layer++) {
        ret = XmssBds_TreeInit(&ctx->bds.states[layer], layer, 0, &treeCtx);
        if (ret != CRYPT_SUCCESS) {
            XmssBds_Free(ctx);
            return ret;
        }
        if (layer + 1U < d) {
            uint8_t *wotsSig = ctx->bds.wotsSigs + layer * ctx->params->wotsLen * n;
            ret = WotsSignLayer(ctx->bds.states[layer].root, n, layer + 1U, 0, 0, &treeCtx, wotsSig);
            if (ret != CRYPT_SUCCESS) {
                XmssBds_Free(ctx);
                return ret;
            }
        }
    }

    for (uint32_t i = 0; i + 1U < d; i++) {
        ResetSingleState(&ctx->bds.states[d + i], ctx->params->hp);
    }
    memcpy(ctx->key.root, ctx->bds.states[d - 1U].root, n);
    ctx->bds.enabled = true;
    return CRYPT_SUCCESS;
}

/* Return a low-bits mask while avoiding undefined 64-bit shifts. */
static uint64_t MaskForBits(uint32_t bits)
{
    return bits >= 64U ? UINT64_MAX : ((1ULL << bits) - 1ULL);
}

/* Return true when signing globalIdx consumes the final leaf through the specified layer. */
static bool IsLayerBoundary(uint64_t globalIdx, uint32_t hp, uint32_t layer)
{
    return ((globalIdx + 1U) & MaskForBits((layer + 1U) * hp)) == 0;
}

/* Return whether another tree exists after treeIdx at the specified XMSSMT layer. */
static bool HasNextTree(const CryptXmssCtx *ctx, uint32_t layer, uint64_t treeIdx)
{
    uint32_t bitsAbove = ctx->params->h - (layer + 1U) * ctx->params->hp;
    if (bitsAbove == 0) {
        return false;
    }
    return treeIdx + 1U < (1ULL << bitsAbove);
}

/*
 * Refresh the cached WOTS signature that authenticates the newly active tree
 * root at the layer immediately above it.
 */
static int32_t RefreshUpperWotsSig(CryptXmssCtx *ctx, uint32_t layer, uint64_t globalIdx, const HbsTreeCtx *treeCtx)
{
    uint32_t hp = ctx->params->hp;
    uint32_t n = ctx->params->n;
    uint64_t upperTreeAddr = (globalIdx + 1U) >> ((layer + 2U) * hp);
    uint32_t upperLeaf = (uint32_t)(((globalIdx >> ((layer + 1U) * hp)) + 1U) & MaskForBits(hp));
    uint8_t *wotsSig = ctx->bds.wotsSigs + layer * ctx->params->wotsLen * n;
    return WotsSignLayer(ctx->bds.states[layer].root, n, layer + 1U, upperTreeAddr, upperLeaf, treeCtx, wotsSig);
}

/*
 * Advance all XMSSMT BDS states after signing globalIdx.
 *
 * The update budget is shared across active-tree treehash work and incremental
 * next-tree construction. At a layer boundary, the completed next tree is
 * swapped in, its upper WOTS cache is refreshed and its old slot is reset.
 */
static int32_t HyperTreePostSignUpdate(CryptXmssCtx *ctx, uint64_t globalIdx, const HbsTreeCtx *treeCtx)
{
    uint32_t d = ctx->params->d;
    uint32_t hp = ctx->params->hp;
    uint32_t updates = GetTreehashUpdateBudget(hp);
    int32_t needSwapUpTo = -1;
    uint64_t maxIdx = (ctx->params->h == 64U) ? (UINT64_MAX - 1U) : ((1ULL << ctx->params->h) - 1U);

    /*
     * The bottom next tree gets one construction step on every signature while
     * such a tree still exists.
     */
    if (d > 1U) {
        uint64_t bottomTree = globalIdx >> hp;
        if (HasNextTree(ctx, 0, bottomTree)) {
            int32_t ret = XmssBds_NextTreeUpdate(&ctx->bds.states[d], 0, bottomTree + 1U, treeCtx);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
        }
    }

    /*
     * Walk bottom-up, spending the remaining update budget on active treehash
     * work and higher-layer next-tree construction. Boundaries swap in a
     * completed next tree and may cause the following layer to advance too.
     */
    for (uint32_t layer = 0; layer < d; layer++) {
        uint32_t idxLeaf = (uint32_t)((globalIdx >> (hp * layer)) & MaskForBits(hp));
        uint64_t idxTree = globalIdx >> (hp * (layer + 1U));
        if (!IsLayerBoundary(globalIdx, hp, layer)) {
            /* This layer remains active; advance its auth path only when needed. */
            if (layer == (uint32_t)(needSwapUpTo + 1)) {
                int32_t ret = XmssBds_TreeRound(&ctx->bds.states[layer], idxLeaf, layer, idxTree, treeCtx);
                if (ret != CRYPT_SUCCESS) {
                    return ret;
                }
            }
            int32_t ret = XmssBds_TreehashUpdates(&ctx->bds.states[layer], updates, layer, idxTree, treeCtx, &updates);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            if (layer > 0 && layer + 1U < d && updates > 0 && HasNextTree(ctx, layer, idxTree)) {
                ret = XmssBds_NextTreeUpdate(&ctx->bds.states[d + layer], layer, idxTree + 1U, treeCtx);
                if (ret != CRYPT_SUCCESS) {
                    return ret;
                }
                updates--;
            }
            continue;
        }

        /* The active tree is exhausted at this layer; promote its prepared successor. */
        if (globalIdx >= maxIdx || layer + 1U >= d) {
            continue;
        }
        if (!ctx->bds.states[d + layer].initialized) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        int32_t ret = XmssBds_StateSwap(&ctx->bds.states[layer], &ctx->bds.states[d + layer]);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        ret = RefreshUpperWotsSig(ctx, layer, globalIdx, treeCtx);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        ResetSingleState(&ctx->bds.states[d + layer], hp);
        if (updates > 0) {
            updates--;
        }
        needSwapUpTo = (int32_t)layer;
    }
    return CRYPT_SUCCESS;
}

/*
 * Generate one XMSS/XMSSMT hypertree signature from the current BDS state.
 *
 * The bottom layer signs digest directly. Upper layers emit cached WOTS
 * signatures and current authentication paths. After output is complete, the
 * function advances either the single XMSS tree or all affected XMSSMT layers.
 */
int32_t XmssBds_HyperTreeSign(CryptXmssCtx *ctx, const uint8_t *digest, uint32_t digestLen, uint64_t globalIdx,
                              uint8_t *sig, uint32_t *sigLen)
{
    if (ctx == NULL || digest == NULL || sig == NULL || sigLen == NULL || ctx->params == NULL ||
        ctx->bds.states == NULL || !ctx->bds.enabled) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint32_t n = ctx->params->n;
    uint32_t d = ctx->params->d;
    uint32_t hp = ctx->params->hp;
    uint32_t layerSigLen = (ctx->params->wotsLen + hp) * n;
    uint32_t totalSigLen = layerSigLen * d;
    if (*sigLen < totalSigLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_SIG_LEN);
        return CRYPT_XMSS_ERR_INVALID_SIG_LEN;
    }

    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitFromXmss(&treeCtx, ctx);
    uint8_t *sigPtr = sig;
    uint64_t treeIdx = globalIdx >> hp;
    uint32_t leafIdx = (uint32_t)(globalIdx & MaskForBits(hp));

    /* The bottom layer signs the caller-provided digest directly. */
    uint32_t oneLayerLen = layerSigLen;
    int32_t ret = WriteLayerSignatureNoUpdate(&ctx->bds.states[0], digest, digestLen, leafIdx, 0, treeIdx, &treeCtx,
                                              sigPtr, &oneLayerLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    sigPtr += oneLayerLen;

    for (uint32_t layer = 1; layer < d; layer++) {
        /*
         * Upper-layer WOTS signatures are precomputed in wotsSigs for the
         * current lower-tree root. Signing only emits that cached WOTS
         * signature plus the BDS auth path for this layer.
         */
        memcpy(sigPtr, ctx->bds.wotsSigs + (layer - 1U) * ctx->params->wotsLen * n, ctx->params->wotsLen * n);
        ret = CopyAuthPath(&ctx->bds.states[layer], sigPtr + ctx->params->wotsLen * n, hp, n);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        sigPtr += layerSigLen;
    }

    /*
     * State advances only after the complete signature has been emitted. XMSS
     * updates one tree; XMSSMT coordinates all current and next-tree states.
     */
    if (d == 1U) {
        if (globalIdx < ((1ULL << hp) - 1U)) {
            ret = XmssBds_TreeRound(&ctx->bds.states[0], (uint32_t)globalIdx, 0, 0, &treeCtx);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
            ret = XmssBds_TreehashUpdates(&ctx->bds.states[0], GetTreehashUpdateBudget(hp), 0, 0, &treeCtx, NULL);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
        }
    } else {
        ret = HyperTreePostSignUpdate(ctx, globalIdx, &treeCtx);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    *sigLen = totalSigLen;
    return CRYPT_SUCCESS;
}

#endif /* defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT) */

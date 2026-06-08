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
#include "hbs_address.h"
#include "hbs_wots.h"
#include "xmss_bds.h"
#include "xmss_local.h"

#define XMSS_BDS_BLOB_MAGIC      0x58424453U
#define XMSS_BDS_BLOB_HEADER_LEN (10U * (uint32_t)sizeof(uint32_t) + (uint32_t)sizeof(uint64_t))

static void StoreU32(uint8_t **pos, uint32_t value)
{
    (*pos)[0] = (uint8_t)(value >> 24);
    (*pos)[1] = (uint8_t)(value >> 16);
    (*pos)[2] = (uint8_t)(value >> 8);
    (*pos)[3] = (uint8_t)value;
    *pos += sizeof(uint32_t);
}

static void StoreU64(uint8_t **pos, uint64_t value)
{
    for (uint32_t i = 0; i < sizeof(uint64_t); i++) {
        (*pos)[i] = (uint8_t)(value >> (56U - 8U * i));
    }
    *pos += sizeof(uint64_t);
}

static uint32_t LoadU32(const uint8_t **pos)
{
    uint32_t value =
        ((uint32_t)(*pos)[0] << 24) | ((uint32_t)(*pos)[1] << 16) | ((uint32_t)(*pos)[2] << 8) | (uint32_t)(*pos)[3];
    *pos += sizeof(uint32_t);
    return value;
}

static uint64_t LoadU64(const uint8_t **pos)
{
    uint64_t value = 0;
    for (uint32_t i = 0; i < sizeof(uint64_t); i++) {
        value = (value << 8) | (*pos)[i];
    }
    *pos += sizeof(uint64_t);
    return value;
}

static uint32_t ExpectedStateCount(const CryptXmssCtx *ctx)
{
    return 2U * ctx->params->d - 1U;
}

static uint32_t ExpectedWotsSigsLen(const CryptXmssCtx *ctx)
{
    if (ctx->params->d <= 1U) {
        return 0;
    }
    return (ctx->params->d - 1U) * ctx->params->wotsLen * ctx->params->n;
}

static uint32_t GetBdsK(uint32_t hp)
{
    uint32_t k = hp < XMSS_BDS_K ? hp : XMSS_BDS_K;
    if (((hp - k) & 1U) != 0 && k > 0) {
        k--;
    }
    return k;
}

static uint32_t GetTreehashCount(uint32_t hp)
{
    return hp - GetBdsK(hp);
}

static uint32_t GetTreehashUpdateBudget(uint32_t hp)
{
    return GetTreehashCount(hp) >> 1U;
}

static uint32_t RetainOffsetFromRow(uint32_t hp, uint32_t height, uint32_t row)
{
    return (1U << (hp - 1U - height)) + height - hp + ((row - 3U) >> 1U);
}

static uint32_t RetainOffsetForAuth(uint32_t hp, uint32_t height, uint32_t leafIdx)
{
    uint32_t base = (1U << (hp - 1U - height)) + height - hp;
    uint32_t row = ((leafIdx >> height) - 1U) >> 1U;
    return base + row;
}

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

static void BuildBaseAdrs(void *adrs, uint32_t layer, uint64_t treeAddr, const HbsTreeCtx *treeCtx)
{
    memset(adrs, 0, HBS_MAX_ADRS_SIZE);
    treeCtx->adrsOps->setLayerAddr(adrs, layer);
    treeCtx->adrsOps->setTreeAddr(adrs, treeAddr);
}

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

static int32_t GenerateLeaf(uint8_t *node, uint32_t idx, const uint8_t *baseAdrs, const HbsTreeCtx *treeCtx)
{
    uint8_t adrs[HBS_MAX_ADRS_SIZE] = {0};
    memcpy(adrs, baseAdrs, sizeof(adrs));
    treeCtx->adrsOps->setType(adrs, HBS_ADRS_TYPE_OTS);
    treeCtx->adrsOps->setKeyPairAddr(adrs, idx);

    HbsWotsCtx wotsCtx;
    BuildWotsCtxFromTreeCtx(&wotsCtx, treeCtx);
    return HbsWots_GeneratePublicKey(node, adrs, &wotsCtx);
}

static int32_t HashParent(uint8_t *node, const uint8_t *left, const uint8_t *right, uint32_t height, uint32_t index,
                          const uint8_t *baseAdrs, const HbsTreeCtx *treeCtx)
{
    uint32_t n = treeCtx->n;
    uint8_t adrs[HBS_MAX_ADRS_SIZE] = {0};
    uint8_t tmp[XMSS_MAX_MDSIZE * 2U] = {0};

    memcpy(adrs, baseAdrs, sizeof(adrs));
    treeCtx->adrsOps->setType(adrs, HBS_ADRS_TYPE_HASH);
    treeCtx->adrsOps->setTreeHeight(adrs, height);
    treeCtx->adrsOps->setTreeIndex(adrs, index);
    memcpy(tmp, left, n);
    memcpy(tmp + n, right, n);
    return treeCtx->hashFuncs.xmss->nodeHash(treeCtx->originalCtx, adrs, tmp, 2U * n, node);
}

static void InitCompletedTreehash(XmssBdsState *state, uint32_t hp)
{
    for (uint32_t i = 0; i < hp; i++) {
        state->treehash[i].height = i;
        state->treehash[i].nextIdx = 0;
        state->treehash[i].stackUsage = 0;
        state->treehash[i].completed = true;
    }
}

static void ResetSingleState(XmssBdsState *state, uint32_t hp)
{
    memset(state, 0, sizeof(*state));
    InitCompletedTreehash(state, hp);
}

int32_t XmssBds_Alloc(CryptXmssCtx *ctx)
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

void XmssBds_Reset(CryptXmssCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->bds.states != NULL) {
        BSL_SAL_CleanseData(ctx->bds.states, ctx->bds.stateCount * (uint32_t)sizeof(XmssBdsState));
    }
    if (ctx->bds.wotsSigs != NULL) {
        BSL_SAL_CleanseData(ctx->bds.wotsSigs, ctx->bds.wotsSigsLen);
    }
    ctx->bds.enabled = false;
}

uint32_t XmssBds_GetStateLen(const CryptXmssCtx *ctx)
{
    if (ctx == NULL || ctx->params == NULL || ctx->bds.states == NULL || !ctx->bds.enabled ||
        ctx->bds.stateCount == 0) {
        return 0;
    }
    uint32_t stateBytes = ctx->bds.stateCount * (uint32_t)sizeof(XmssBdsState);
    return XMSS_BDS_BLOB_HEADER_LEN + stateBytes + ctx->bds.wotsSigsLen;
}

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

    uint8_t *pos = out;
    StoreU32(&pos, XMSS_BDS_BLOB_MAGIC);
    StoreU32(&pos, ctx->bds.enabled ? 1U : 0U);
    StoreU32(&pos, (uint32_t)ctx->params->algId);
    StoreU64(&pos, ctx->key.idx);
    StoreU32(&pos, ctx->params->n);
    StoreU32(&pos, ctx->params->h);
    StoreU32(&pos, ctx->params->d);
    StoreU32(&pos, ctx->params->hp);
    StoreU32(&pos, ctx->bds.stateCount);
    StoreU32(&pos, ctx->bds.wotsSigsLen);
    StoreU32(&pos, (uint32_t)sizeof(XmssBdsState));

    uint32_t stateBytes = ctx->bds.stateCount * (uint32_t)sizeof(XmssBdsState);
    memcpy(pos, ctx->bds.states, stateBytes);
    pos += stateBytes;
    if (ctx->bds.wotsSigsLen != 0) {
        memcpy(pos, ctx->bds.wotsSigs, ctx->bds.wotsSigsLen);
        pos += ctx->bds.wotsSigsLen;
    }
    *outLen = (uint32_t)(pos - out);
    return CRYPT_SUCCESS;
}

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

    const uint8_t *pos = in;
    uint32_t magic = LoadU32(&pos);
    uint32_t enabled = LoadU32(&pos);
    uint32_t algId = LoadU32(&pos);
    uint64_t idx = LoadU64(&pos);
    uint32_t n = LoadU32(&pos);
    uint32_t h = LoadU32(&pos);
    uint32_t d = LoadU32(&pos);
    uint32_t hp = LoadU32(&pos);
    uint32_t stateCount = LoadU32(&pos);
    uint32_t wotsSigsLen = LoadU32(&pos);
    uint32_t stateSize = LoadU32(&pos);

    uint32_t expectedStateCount = ExpectedStateCount(ctx);
    uint32_t expectedWotsSigsLen = ExpectedWotsSigsLen(ctx);
    if (magic != XMSS_BDS_BLOB_MAGIC || enabled > 1U || algId != (uint32_t)ctx->params->algId || idx != ctx->key.idx ||
        n != ctx->params->n || h != ctx->params->h || d != ctx->params->d || hp != ctx->params->hp ||
        stateCount != expectedStateCount || wotsSigsLen != expectedWotsSigsLen ||
        stateSize != (uint32_t)sizeof(XmssBdsState)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint32_t stateBytes = stateCount * stateSize;
    uint32_t expectedLen = XMSS_BDS_BLOB_HEADER_LEN + stateBytes + wotsSigsLen;
    if (expectedLen != inLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    int32_t ret = XmssBds_Alloc(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    memcpy(ctx->bds.states, pos, stateBytes);
    pos += stateBytes;
    if (wotsSigsLen != 0) {
        memcpy(ctx->bds.wotsSigs, pos, wotsSigsLen);
    }
    ctx->bds.enabled = (enabled != 0);
    return CRYPT_SUCCESS;
}

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

static int32_t WotsSignLayer(const uint8_t *msg, uint32_t msgLen, uint32_t layer, uint64_t treeAddr, uint32_t leafIdx,
                             const HbsTreeCtx *treeCtx, uint8_t *sig)
{
    uint8_t adrs[HBS_MAX_ADRS_SIZE] = {0};
    BuildBaseAdrs(adrs, layer, treeAddr, treeCtx);
    treeCtx->adrsOps->setType(adrs, HBS_ADRS_TYPE_OTS);
    treeCtx->adrsOps->setKeyPairAddr(adrs, leafIdx);

    HbsWotsCtx wotsCtx;
    BuildWotsCtxFromTreeCtx(&wotsCtx, treeCtx);
    uint32_t wotsSigLen = treeCtx->otsLen * treeCtx->n;
    return HbsWots_Sign(sig, &wotsSigLen, msg, msgLen, adrs, &wotsCtx);
}

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

int32_t XmssBds_TreeInit(XmssBdsState *state, uint32_t layer, uint64_t treeAddr, const HbsTreeCtx *treeCtx)
{
    int32_t ret = CheckTreeInput(state, treeCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint32_t n = treeCtx->n;
    uint32_t hp = treeCtx->hp;
    uint8_t baseAdrs[HBS_MAX_ADRS_SIZE] = {0};
    BuildBaseAdrs(baseAdrs, layer, treeAddr, treeCtx);

    memset(state, 0, sizeof(*state));
    InitCompletedTreehash(state, hp);

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

static uint32_t GetTau(uint32_t leafIdx, uint32_t hp)
{
    for (uint32_t i = 0; i < hp; i++) {
        if (((leafIdx >> i) & 1U) == 0) {
            return i;
        }
    }
    return hp;
}

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
    uint8_t baseAdrs[HBS_MAX_ADRS_SIZE] = {0};
    uint8_t left[XMSS_MAX_MDSIZE] = {0};
    uint8_t right[XMSS_MAX_MDSIZE] = {0};

    BuildBaseAdrs(baseAdrs, layer, treeAddr, treeCtx);
    if (tau > 0) {
        memcpy(left, state->auth[tau - 1U], n);
        memcpy(right, state->keep[(tau - 1U) >> 1U], n);
    }

    if (!(((leafIdx >> (tau + 1U)) & 1U) != 0) && tau < hp - 1U) {
        memcpy(state->keep[tau >> 1U], state->auth[tau], n);
    }

    if (tau == 0) {
        ret = GenerateLeaf(state->auth[0], leafIdx, baseAdrs, treeCtx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        return CRYPT_SUCCESS;
    }

    uint8_t parent[XMSS_MAX_MDSIZE] = {0};
    ret = HashParent(parent, left, right, tau - 1U, leafIdx >> tau, baseAdrs, treeCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    memcpy(state->auth[tau], parent, n);

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

static int32_t TreehashUpdateOne(XmssBdsState *state, XmssBdsTreehash *treehash, const uint8_t *baseAdrs,
                                 const HbsTreeCtx *treeCtx)
{
    uint32_t hp = treeCtx->hp;
    uint32_t n = treeCtx->n;
    if (treehash->completed || treehash->nextIdx >= (1U << hp)) {
        treehash->completed = true;
        return CRYPT_SUCCESS;
    }

    uint8_t node[XMSS_MAX_MDSIZE] = {0};
    uint8_t parent[XMSS_MAX_MDSIZE] = {0};
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
    uint8_t baseAdrs[HBS_MAX_ADRS_SIZE] = {0};
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

int32_t XmssBds_TreeSign(XmssBdsState *state, const uint8_t *msg, uint32_t msgLen, uint32_t leafIdx, uint32_t layer,
                         uint64_t treeAddr, const HbsTreeCtx *treeCtx, uint8_t *sig, uint32_t *sigLen)
{
    int32_t ret = CheckTreeInput(state, treeCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = WriteLayerSignatureNoUpdate(state, msg, msgLen, leafIdx, layer, treeAddr, treeCtx, sig, sigLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (leafIdx < (1U << treeCtx->hp) - 1U) {
        ret = XmssBds_TreeRound(state, leafIdx, layer, treeAddr, treeCtx);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        ret = XmssBds_TreehashUpdates(state, GetTreehashUpdateBudget(treeCtx->hp), layer, treeAddr, treeCtx, NULL);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    return CRYPT_SUCCESS;
}

int32_t XmssBds_NextTreeUpdate(XmssBdsState *nextState, uint32_t layer, uint64_t treeAddr, const HbsTreeCtx *treeCtx)
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

    uint8_t baseAdrs[HBS_MAX_ADRS_SIZE] = {0};
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

static uint64_t MaskForBits(uint32_t bits)
{
    return bits >= 64U ? UINT64_MAX : ((1ULL << bits) - 1ULL);
}

static bool IsLayerBoundary(uint64_t globalIdx, uint32_t hp, uint32_t layer)
{
    return ((globalIdx + 1U) & MaskForBits((layer + 1U) * hp)) == 0;
}

static bool HasNextTree(const CryptXmssCtx *ctx, uint32_t layer, uint64_t treeIdx)
{
    uint32_t bitsAbove = ctx->params->h - (layer + 1U) * ctx->params->hp;
    if (bitsAbove == 0) {
        return false;
    }
    return treeIdx + 1U < (1ULL << bitsAbove);
}

static int32_t RefreshUpperWotsSig(CryptXmssCtx *ctx, uint32_t layer, uint64_t globalIdx, const HbsTreeCtx *treeCtx)
{
    uint32_t hp = ctx->params->hp;
    uint32_t n = ctx->params->n;
    uint64_t upperTreeAddr = (globalIdx + 1U) >> ((layer + 2U) * hp);
    uint32_t upperLeaf = (uint32_t)(((globalIdx >> ((layer + 1U) * hp)) + 1U) & MaskForBits(hp));
    uint8_t *wotsSig = ctx->bds.wotsSigs + layer * ctx->params->wotsLen * n;
    return WotsSignLayer(ctx->bds.states[layer].root, n, layer + 1U, upperTreeAddr, upperLeaf, treeCtx, wotsSig);
}

static int32_t HyperTreePostSignUpdate(CryptXmssCtx *ctx, uint64_t globalIdx, const HbsTreeCtx *treeCtx)
{
    uint32_t d = ctx->params->d;
    uint32_t hp = ctx->params->hp;
    uint32_t updates = GetTreehashUpdateBudget(hp);
    int32_t needSwapUpTo = -1;
    uint64_t maxIdx = (ctx->params->h == 64U) ? (UINT64_MAX - 1U) : ((1ULL << ctx->params->h) - 1U);

    if (d > 1U) {
        uint64_t bottomTree = globalIdx >> hp;
        if (HasNextTree(ctx, 0, bottomTree)) {
            int32_t ret = XmssBds_NextTreeUpdate(&ctx->bds.states[d], 0, bottomTree + 1U, treeCtx);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
        }
    }

    for (uint32_t layer = 0; layer < d; layer++) {
        uint32_t idxLeaf = (uint32_t)((globalIdx >> (hp * layer)) & MaskForBits(hp));
        uint64_t idxTree = globalIdx >> (hp * (layer + 1U));
        if (!IsLayerBoundary(globalIdx, hp, layer)) {
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

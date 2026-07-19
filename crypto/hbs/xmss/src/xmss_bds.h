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

#ifndef XMSS_BDS_H
#define XMSS_BDS_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT)

#include <stdbool.h>
#include <stdint.h>
#include "hbs_tree.h"
#include "xmss_params.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XMSS_BDS_MAX_HP       20U
#define XMSS_BDS_MAX_D        12U
#define XMSS_BDS_K            2U
#define XMSS_BDS_MAX_TREEHASH XMSS_BDS_MAX_HP
#define XMSS_BDS_MAX_RETAIN   ((1U << XMSS_BDS_K) - XMSS_BDS_K - 1U)

/** Treehash state used to incrementally compute one authentication-path node. */
typedef struct {
    uint32_t height;                  /* Target treehash height. */
    uint32_t nextIdx;                 /* Next leaf index to process. */
    uint32_t stackUsage;              /* Number of shared stack entries owned by this treehash. */
    bool completed;                   /* Whether node contains the completed target node. */
    uint8_t node[XMSS_MAX_MDSIZE];    /* Completed target node. */
} XmssBdsTreehash;

/** BDS traversal state for one XMSS tree. */
typedef struct {
    uint8_t auth[XMSS_BDS_MAX_HP][XMSS_MAX_MDSIZE];                 /* Current authentication path. */
    uint8_t keep[(XMSS_BDS_MAX_HP + 1U) / 2U][XMSS_MAX_MDSIZE];     /* Nodes retained for auth updates. */

    uint8_t stack[XMSS_BDS_MAX_HP + 1U][XMSS_MAX_MDSIZE];           /* Shared tree construction stack. */
    uint8_t stackLevels[XMSS_BDS_MAX_HP + 1U];                      /* Height of each active stack node. */
    uint32_t stackOffset;                                           /* Number of active stack entries. */

    XmssBdsTreehash treehash[XMSS_BDS_MAX_TREEHASH];                /* Treehash update states. */
    uint8_t retain[XMSS_BDS_MAX_RETAIN][XMSS_MAX_MDSIZE];           /* Upper auth nodes retained by BDS. */

    uint32_t nextLeaf;                                               /* Next leaf for incremental tree init. */
    uint8_t root[XMSS_MAX_MDSIZE];                                   /* Root of this layer tree. */
    bool initialized;                                                /* Whether the layer tree is complete. */
} XmssBdsState;

/** BDS acceleration state owned by an XMSS or XMSSMT private-key context. */
typedef struct {
    XmssBdsState *state;             /* Single active tree state. */
    bool enabled;                    /* Whether signing uses BDS state. */
} XmssBdsCtx;

/** BDS acceleration state owned by an XMSSMT private-key context. */
typedef struct {
    XmssBdsState *states;            /* Current states followed by next-tree states. */
    uint8_t *wotsSigs;               /* Cached upper-layer WOTS signatures. */
    uint32_t stateCount;             /* Number of entries in states. */
    uint32_t wotsSigsLen;            /* Length of wotsSigs in bytes. */
    bool enabled;                    /* Whether signing uses BDS state. */
} XmssmtBdsCtx;

struct XmssCtxCommon;

/**
 * Release all single-tree XMSS BDS acceleration state.
 *
 * @param bds  XMSS BDS context, or NULL.
 */
void XmssBds_Free(XmssBdsCtx *bds);

/**
 * Allocate the single BDS tree state used by XMSS.
 *
 * Existing XMSS BDS state is released first.
 */
int32_t XmssBds_Alloc(XmssBdsCtx *bds);

/**
 * Release all XMSSMT BDS acceleration state.
 *
 * @param bds  XMSSMT BDS context, or NULL.
 */
void XmssmtBds_Free(XmssmtBdsCtx *bds);

/**
 * Allocate BDS states for a concrete XMSSMT parameter set.
 *
 * Existing XMSSMT BDS state is released first. The allocation contains d
 * current states, d - 1 next-tree states and d - 1 cached upper-layer WOTS
 * signatures.
 *
 * @param bds      XMSSMT BDS context.
 * @param d        Number of active layers.
 * @param n        Security parameter in bytes.
 * @param wotsLen  Number of n-byte strings in one WOTS+ signature.
 */
int32_t XmssmtBds_Alloc(XmssmtBdsCtx *bds, uint32_t d, uint32_t n, uint32_t wotsLen);

/**
 * Reset one BDS tree state to an empty, reusable state.
 *
 * Treehash slots are marked dormant/completed so later incremental
 * construction can restart only the slots it needs.
 */
void XmssBds_ResetState(XmssBdsState *state, uint32_t hp);

/**
 * Return the number of treehash update steps scheduled after a signature.
 */
uint32_t XmssBds_GetTreehashUpdateBudget(uint32_t hp);

/**
 * Initialize one complete BDS state for a concrete layer tree.
 *
 * @param state    State to initialize.
 * @param layer    XMSS/XMSSMT layer number.
 * @param treeAddr Tree address inside the layer.
 * @param treeCtx  HBS tree context for the concrete algorithm.
 */
int32_t XmssBds_InitTreeState(XmssBdsState *state, uint32_t layer, uint64_t treeAddr, const HbsTreeCtx *treeCtx);

/**
 * Write one layer signature from an existing BDS state without advancing it.
 *
 * The output is WOTS+ signature followed by the current authentication path.
 */
int32_t XmssBds_WriteLayerSignature(const XmssBdsState *state, const uint8_t *msg, uint32_t msgLen,
                                    uint32_t leafIdx, uint32_t layer, uint64_t treeAddr,
                                    const HbsTreeCtx *treeCtx, uint8_t *sig, uint32_t *sigLen);

/**
 * Copy the current authentication path of one BDS state.
 */
int32_t XmssBds_CopyAuthPath(const XmssBdsState *state, uint8_t *out, uint32_t hp, uint32_t n);

/**
 * Produce the WOTS+ signature used by an upper XMSSMT layer.
 */
int32_t XmssBds_SignWotsLayer(const uint8_t *msg, uint32_t msgLen, uint32_t layer, uint64_t treeAddr,
                              uint32_t leafIdx, const HbsTreeCtx *treeCtx, uint8_t *sig);

/**
 * Advance one initialized BDS state to the next leaf within its tree.
 */
int32_t XmssBds_TreeRound(XmssBdsState *state, uint32_t leafIdx, uint32_t layer, uint64_t treeAddr,
                          const HbsTreeCtx *treeCtx);

/**
 * Spend treehash update work on one initialized BDS state.
 */
int32_t XmssBds_TreehashUpdates(XmssBdsState *state, uint32_t updates, uint32_t layer, uint64_t treeAddr,
                                const HbsTreeCtx *treeCtx, uint32_t *remaining);

/**
 * Spend one construction step on a future XMSSMT tree state.
 */
int32_t XmssBds_NextTreeUpdate(XmssBdsState *nextState, uint32_t layer, uint64_t treeAddr,
                               const HbsTreeCtx *treeCtx);

/**
 * Swap an active tree state with a prepared next-tree state.
 */
int32_t XmssBds_StateSwap(XmssBdsState *a, XmssBdsState *b);

/**
 * Export BDS state for single-tree XMSS private-key persistence.
 *
 * The blob must be persisted atomically with the private key index. It does not
 * provide authentication, anti-rollback protection, or synchronization.
 */
#ifdef HITLS_CRYPTO_XMSS
int32_t XmssBds_ExportTreeState(const struct XmssCtxCommon *ctx, const XmssBdsCtx *bds, const XmssParams *params,
                                uint8_t *out, uint32_t *outLen);

/**
 * Import and structurally validate single-tree XMSS BDS state.
 *
 * The caller must authenticate the persisted private state, prevent rollback,
 * and synchronize import/export with signing. A failed import leaves the
 * existing BDS state unchanged.
 */
int32_t XmssBds_ImportTreeState(const struct XmssCtxCommon *ctx, XmssBdsCtx *bds, const XmssParams *params,
                                const uint8_t *in, uint32_t inLen);
#endif

/**
 * Export BDS state for XMSSMT hypertree private-key persistence.
 */
#ifdef HITLS_CRYPTO_XMSSMT
int32_t XmssmtBds_ExportHyperTreeState(const struct XmssCtxCommon *ctx, const XmssmtBdsCtx *bds,
                                       const XmssmtParams *params, uint8_t *out, uint32_t *outLen);

/**
 * Import and structurally validate XMSSMT hypertree BDS state.
 */
int32_t XmssmtBds_ImportHyperTreeState(const struct XmssCtxCommon *ctx, XmssmtBdsCtx *bds,
                                       const XmssmtParams *params, const uint8_t *in, uint32_t inLen);
#endif

#ifdef __cplusplus
}
#endif

#endif /* defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT) */
#endif /* XMSS_BDS_H */

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

typedef struct {
    uint32_t height;
    uint32_t nextIdx;
    uint32_t stackUsage;
    bool completed;
    uint8_t node[XMSS_MAX_MDSIZE];
} XmssBdsTreehash;

typedef struct {
    uint8_t auth[XMSS_BDS_MAX_HP][XMSS_MAX_MDSIZE];
    uint8_t keep[(XMSS_BDS_MAX_HP + 1U) / 2U][XMSS_MAX_MDSIZE];

    uint8_t stack[XMSS_BDS_MAX_HP + 1U][XMSS_MAX_MDSIZE];
    uint8_t stackLevels[XMSS_BDS_MAX_HP + 1U];
    uint32_t stackOffset;

    XmssBdsTreehash treehash[XMSS_BDS_MAX_TREEHASH];
    uint8_t retain[XMSS_BDS_MAX_RETAIN][XMSS_MAX_MDSIZE];

    uint32_t nextLeaf;
    uint8_t root[XMSS_MAX_MDSIZE];
    bool initialized;
} XmssBdsState;

typedef struct {
    XmssBdsState *states;
    uint8_t *wotsSigs;
    uint32_t stateCount;
    uint32_t wotsSigsLen;
    bool enabled;
} XmssBdsCtx;

struct CryptXmssCtx;

int32_t XmssBds_Alloc(struct CryptXmssCtx *ctx);
void XmssBds_Free(struct CryptXmssCtx *ctx);
void XmssBds_Reset(struct CryptXmssCtx *ctx);

int32_t XmssBds_TreeInit(XmssBdsState *state, uint32_t layer, uint64_t treeAddr, const HbsTreeCtx *treeCtx);

int32_t XmssBds_TreeSign(XmssBdsState *state, const uint8_t *msg, uint32_t msgLen, uint32_t leafIdx, uint32_t layer,
                         uint64_t treeAddr, const HbsTreeCtx *treeCtx, uint8_t *sig, uint32_t *sigLen);

int32_t XmssBds_TreeRound(XmssBdsState *state, uint32_t leafIdx, uint32_t layer, uint64_t treeAddr,
                          const HbsTreeCtx *treeCtx);

int32_t XmssBds_TreehashUpdates(XmssBdsState *state, uint32_t updates, uint32_t layer, uint64_t treeAddr,
                                const HbsTreeCtx *treeCtx, uint32_t *unusedUpdates);

int32_t XmssBds_NextTreeUpdate(XmssBdsState *nextState, uint32_t layer, uint64_t treeAddr, const HbsTreeCtx *treeCtx);

int32_t XmssBds_StateSwap(XmssBdsState *a, XmssBdsState *b);

int32_t XmssBds_HyperTreeInit(struct CryptXmssCtx *ctx);

int32_t XmssBds_HyperTreeSign(struct CryptXmssCtx *ctx, const uint8_t *digest, uint32_t digestLen, uint64_t globalIdx,
                              uint8_t *sig, uint32_t *sigLen);

uint32_t XmssBds_GetStateLen(const struct CryptXmssCtx *ctx);

int32_t XmssBds_ExportState(const struct CryptXmssCtx *ctx, uint8_t *out, uint32_t *outLen);

int32_t XmssBds_ImportState(struct CryptXmssCtx *ctx, const uint8_t *in, uint32_t inLen);

#ifdef __cplusplus
}
#endif

#endif /* defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT) */
#endif /* XMSS_BDS_H */

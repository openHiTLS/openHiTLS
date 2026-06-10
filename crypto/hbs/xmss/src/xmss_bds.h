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
    XmssBdsState *states;            /* Current and next layer-tree states. */
    uint8_t *wotsSigs;               /* Cached upper-layer WOTS signatures. */
    uint32_t stateCount;             /* Number of entries in states. */
    uint32_t wotsSigsLen;            /* Length of wotsSigs in bytes. */
    bool enabled;                    /* Whether signing uses BDS state. */
} XmssBdsCtx;

struct CryptXmssCtx;

/**
 * Release all BDS acceleration state owned by an XMSS context.
 *
 * @param ctx  XMSS context, or NULL.
 */
void XmssBds_Free(struct CryptXmssCtx *ctx);

/**
 * Initialize all BDS layer states for a newly generated XMSS private key.
 *
 * @param ctx  XMSS context containing the private seed and parameters.
 *
 * @return CRYPT_SUCCESS on success, or an error code otherwise.
 */
int32_t XmssBds_HyperTreeInit(struct CryptXmssCtx *ctx);

/**
 * Sign a digest using the current BDS state and advance that state.
 *
 * @param ctx        XMSS context containing initialized BDS state.
 * @param digest     Digest to sign.
 * @param digestLen  Digest length.
 * @param globalIdx  Current global XMSS leaf index.
 * @param sig        Output hypertree signature.
 * @param sigLen     Input buffer length; receives signature length.
 *
 * @return CRYPT_SUCCESS on success, or an error code otherwise.
 */
int32_t XmssBds_HyperTreeSign(struct CryptXmssCtx *ctx, const uint8_t *digest, uint32_t digestLen, uint64_t globalIdx,
                              uint8_t *sig, uint32_t *sigLen);

/**
 * Export BDS acceleration state using a fixed-field, big-endian encoding.
 *
 * The blob must be persisted atomically with the private key index. It does not
 * provide authentication, anti-rollback protection, or synchronization.
 *
 * @param ctx     XMSS context containing initialized BDS state.
 * @param out     Output buffer.
 * @param outLen  Input buffer length; receives encoded length.
 *
 * @return CRYPT_SUCCESS on success, or an error code otherwise.
 */
int32_t XmssBds_ExportState(const struct CryptXmssCtx *ctx, uint8_t *out, uint32_t *outLen);

/**
 * Import and structurally validate fixed-field BDS acceleration state.
 *
 * The caller must authenticate the persisted private state, prevent rollback,
 * and synchronize import/export with signing. A failed import leaves the
 * existing BDS state unchanged.
 *
 * @param ctx    XMSS context whose key index must match the encoded index.
 * @param in     Encoded BDS state.
 * @param inLen  Length of encoded BDS state.
 *
 * @return CRYPT_SUCCESS on success, or an error code otherwise.
 */
int32_t XmssBds_ImportState(struct CryptXmssCtx *ctx, const uint8_t *in, uint32_t inLen);

#ifdef __cplusplus
}
#endif

#endif /* defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT) */
#endif /* XMSS_BDS_H */

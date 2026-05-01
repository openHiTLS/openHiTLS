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
#ifdef HITLS_CRYPTO_SLH_DSA

#include <stdint.h>
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "slh_dsa_local.h"
#include "slh_dsa_hypertree.h"

void HbsTreeCtx_InitFromSlhDsa(HbsTreeCtx *treeCtx, const CryptSlhDsaCtx *ctx)
{
    treeCtx->n = ctx->para.n;
    treeCtx->hp = ctx->para.hp;
    treeCtx->d = ctx->para.d;
    treeCtx->otsLen = 2 * ctx->para.n + 3;

    treeCtx->pubSeed = ctx->prvKey.pub.seed;
    treeCtx->skSeed = ctx->prvKey.seed;
    treeCtx->root = ctx->prvKey.pub.root;

    treeCtx->hashFuncs.xmss = ctx->hashFuncs;
    treeCtx->adrsOps = &ctx->adrsOps;
    treeCtx->originalCtx = (void *)(uintptr_t)ctx;
    treeCtx->algoType = HBS_ALGO_SLH_DSA;
}

int32_t HypertreeSign(const uint8_t *msg, uint32_t msgLen, uint64_t treeIdx, uint32_t leafIdx,
                      const CryptSlhDsaCtx *ctx, uint8_t *sig, uint32_t *sigLen)
{
    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitFromSlhDsa(&treeCtx, ctx);
    return HbsHyperTree_Sign(msg, msgLen, treeIdx, leafIdx, &treeCtx, sig, sigLen);
}

int32_t HypertreeVerify(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, uint64_t treeIdx,
                        uint32_t leafIdx, const CryptSlhDsaCtx *ctx)
{
    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitFromSlhDsa(&treeCtx, ctx);
    return HbsHyperTree_Verify(msg, msgLen, sig, sigLen, treeIdx, leafIdx, &treeCtx);
}

#endif /* HITLS_CRYPTO_SLH_DSA */

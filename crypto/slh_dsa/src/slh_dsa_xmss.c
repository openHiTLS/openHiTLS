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
#include <stddef.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "slh_dsa_local.h"
#include "slh_dsa_xmss.h"
#include "slh_dsa_wots.h"

int32_t XmssNode(uint8_t *node, uint32_t idx, uint32_t height, SlhDsaAdrs *adrs, const CryptSlhDsaCtx *ctx)
{
    int32_t ret;
    if (node == NULL || adrs == NULL || ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    uint32_t n = ctx->para.n;

    // If height is 0, compute WOTS+ public key
    if (height == 0) {
        ctx->adrsOps.setType(adrs, WOTS_HASH);
        ctx->adrsOps.setKeyPairAddr(adrs, idx);
        return WotsGeneratePublicKey(node, adrs, ctx);
    }
    // Compute internal node
    uint8_t leftNode[SLH_DSA_MAX_N] = {0};
    uint8_t rightNode[SLH_DSA_MAX_N] = {0};

    // Compute left child
    ret = XmssNode(leftNode, 2 * idx, height - 1, adrs, ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // Compute right child
    ret = XmssNode(rightNode, 2 * idx + 1, height - 1, adrs, ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // Hash children to get parent node
    ctx->adrsOps.setType(adrs, TREE);
    ctx->adrsOps.setTreeHeight(adrs, height);
    ctx->adrsOps.setTreeIndex(adrs, idx);

    uint8_t tmp[SLH_DSA_MAX_N * 2];
    (void)memcpy_s(tmp, SLH_DSA_MAX_N * 2, leftNode, n);
    (void)memcpy_s(tmp + n, SLH_DSA_MAX_N, rightNode, n);

    return ctx->hashFuncs.h(ctx, adrs, tmp, 2 * n, node);
}

int32_t XmssSign(const uint8_t *msg, size_t msgLen, uint32_t idx, SlhDsaAdrs *adrs, const CryptSlhDsaCtx *ctx,
                 uint8_t *sig, uint32_t *sigLen)
{
    int32_t ret;

    uint32_t n = ctx->para.n;
    uint32_t hp = ctx->para.hp;
    uint32_t len = 2 * n + 3;

    if (*sigLen < (len + hp) * n) {
        return CRYPT_SLHDSA_ERR_SIG_LEN_NOT_ENOUGH;
    }

    for (uint32_t j = 0; j < hp; j++) {
        uint32_t k = (idx >> j) ^ 1;
        uint8_t node[SLH_DSA_MAX_N] = {0};
        ret = XmssNode(node, k, j, adrs, ctx);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        (void)memcpy_s((sig + (len + j) * n), n, node, n);
    }

    ctx->adrsOps.setType(adrs, WOTS_HASH);
    ctx->adrsOps.setKeyPairAddr(adrs, idx);
    uint32_t tmpLen = len * n;
    ret = WotsSign(sig, &tmpLen, msg, msgLen, adrs, ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    *sigLen = (len + hp) * n;
    return CRYPT_SUCCESS;
}

int32_t XmssPkFromSig(uint32_t idx, const uint8_t *sig, uint32_t sigLen, const uint8_t *msg, uint32_t msgLen,
                      SlhDsaAdrs *adrs, const CryptSlhDsaCtx *ctx, uint8_t *pk)
{
    int32_t ret;

    uint32_t n = ctx->para.n;
    uint32_t hp = ctx->para.hp;
    uint32_t len = 2 * n + 3;

    if (sigLen < (len + hp) * n) {
        return CRYPT_SLHDSA_ERR_SIG_LEN_NOT_ENOUGH;
    }

    ctx->adrsOps.setType(adrs, WOTS_HASH);
    ctx->adrsOps.setKeyPairAddr(adrs, idx);
    uint8_t node0[SLH_DSA_MAX_N] = {0};
    uint8_t node1[SLH_DSA_MAX_N] = {0};
    ret = WotsPubKeyFromSig(msg, msgLen, sig, sigLen, adrs, ctx, node0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ctx->adrsOps.setType(adrs, TREE);
    ctx->adrsOps.setTreeIndex(adrs, idx);
    for (uint32_t k = 0; k < hp; k++) {
        ctx->adrsOps.setTreeHeight(adrs, k + 1);
        uint8_t tmp[SLH_DSA_MAX_N * 2];
        if ((idx >> k) & 1) {
            (void)memcpy_s(tmp, sizeof(tmp), sig + (len + k) * n, n);
            (void)memcpy_s(tmp + n, sizeof(tmp) - n, node0, n);
            ctx->adrsOps.setTreeIndex(adrs, (ctx->adrsOps.getTreeIndex(adrs) - 1) >> 1);

        } else {
            (void)memcpy_s(tmp, sizeof(tmp), node0, n);
            (void)memcpy_s(tmp + n, sizeof(tmp) - n, sig + (len + k) * n, n);
            ctx->adrsOps.setTreeIndex(adrs, ctx->adrsOps.getTreeIndex(adrs) >> 1);
        }
        ret = ctx->hashFuncs.h(ctx, adrs, tmp, 2 * n, node1);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        (void)memcpy_s(node0, sizeof(node0), node1, sizeof(node1));
    }
    (void)memcpy_s(pk, n, node0, n);
    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_SLH_DSA
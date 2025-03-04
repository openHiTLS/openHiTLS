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
#include "slh_dsa.h"
#include "slh_dsa_fors.h"

int32_t ForsSign(const uint8_t *md, uint32_t mdLen, SlhDsaAdrs *adrs, const SlhDsaCtx *ctx, uint8_t *sig,
                      uint32_t *sigLen)
{
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint32_t a = ctx->para.a;
    uint32_t k = ctx->para.k;

    if (md == NULL || adrs == NULL || ctx == NULL || sig == NULL || sigLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (*sigLen < (a + 1) * n * k) {
        return CRYPT_SLHDSA_ERR_SIG_LEN_NOT_ENOUGH;
    }

    uint32_t *indices = (uint32_t *)BSL_SAL_Malloc(k * sizeof(uint32_t));
    if (indices == NULL) {
        return BSL_MALLOC_FAIL;
    }

    BaseB(md, mdLen, a, indices, k);
    uint32_t offset = 0;
    for (uint32_t i = 0; i < k; i++) {
        uint32_t left = *sigLen;
        ret = ForsGenPrvKey(adrs, indices[i] + (i << a), ctx, sig + offset, &left);
        if (ret != 0) {
            goto ERR;
        }
        offset += left;
        for (uint32_t j = 0; j < a; j++) {
            left = *sigLen - offset;
            uint32_t s = (indices[i] >> j) ^ 1;
            ret = ForsNode((i << (a - j)) + s, j, adrs, ctx, sig + offset, &left);
            if (ret != 0) {
                goto ERR;
            }
            offset += left;
        }
    }
    *sigLen = offset;
ERR:
    BSL_SAL_Free(indices);
    return ret;
}

int32_t ForsPkFromSig(const uint8_t *sig, uint32_t sigLen, const uint8_t *md, uint32_t mdLen, SlhDsaAdrs *adrs,
                      const SlhDsaCtx *ctx, uint8_t *pk, uint32_t *pkLen)
{
    int32_t ret;
    uint32_t *indices = NULL;
    uint8_t *root = NULL;
    uint32_t n = ctx->para.n;
    uint32_t a = ctx->para.a;
    uint32_t k = ctx->para.k;

    if (sig == NULL || md == NULL || adrs == NULL || ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (sigLen < (a + 1) * n * k) {
        return CRYPT_SLHDSA_ERR_SIG_LEN_NOT_ENOUGH;
    }

    indices = (uint32_t *)BSL_SAL_Malloc(k * sizeof(uint32_t));
    if (indices == NULL) {
        ret = BSL_MALLOC_FAIL;
        goto ERR;
    }
    root = (uint8_t *)BSL_SAL_Malloc(n * k);
    if (root == NULL) {
        ret = BSL_MALLOC_FAIL;
        goto ERR;
    }

    BaseB(md, mdLen, a, indices, k);

    SlhDsaN node0, node1;
    node0.len = sizeof(node0.bytes);
    node1.len = sizeof(node1.bytes);

    for (uint32_t i = 0; i < k; i++) {
        ctx->adrsOps.setTreeHeight(adrs, 0);
        ctx->adrsOps.setTreeIndex(adrs, (i << a) + indices[i]);

        ret = ctx->pthf(ctx, false, ctx->prvkey.pub.seed, n, adrs, sig + (a + 1) * n * i, n, node0.bytes, &node0.len);
        if (ret != 0) {
            goto ERR;
        }
        const uint8_t *auth = sig + (a + 1) * n * i + n;
        for (uint32_t j = 0; j < a; j++) {
            uint8_t tmp[SLH_DSA_MAX_N * 2];
            ctx->adrsOps.setTreeHeight(adrs, j + 1);
            if (((indices[i] >> j) & 1) == 1) {
                ctx->adrsOps.setTreeIndex(adrs, (ctx->adrsOps.getTreeIndex(adrs) - 1) >> 1);
                (void)memcpy_s(tmp, sizeof(tmp), auth + j * n, n);
                (void)memcpy_s(tmp + n, sizeof(tmp) - n, node0.bytes, n);
            } else {
                ctx->adrsOps.setTreeIndex(adrs, ctx->adrsOps.getTreeIndex(adrs) >> 1);
                (void)memcpy_s(tmp, sizeof(tmp), node0.bytes, n);
                (void)memcpy_s(tmp + n, sizeof(tmp) - n, auth + j * n, n);
            }
            ret = ctx->pthf(ctx, true, ctx->prvkey.pub.seed, n, adrs, tmp, 2 * n, node1.bytes, &node1.len);
            if (ret != 0) {
                goto ERR;
            }
            node0 = node1;
        }
        (void)memcpy_s(root + i * n, (k - i) * n, node0.bytes, n);
    }

    SlhDsaAdrs forspkAdrs = *adrs;
    ctx->adrsOps.setType(&forspkAdrs, FORS_ROOTS);
    ctx->adrsOps.copyKeyPairAddr(&forspkAdrs, adrs);
    ret = ctx->pthf(ctx, true, ctx->prvkey.pub.seed, n, &forspkAdrs, root, n * k, pk, pkLen);
    if (ret != 0) {
        goto ERR;
    }

ERR:
    BSL_SAL_Free(indices);
    BSL_SAL_Free(root);
    return ret;
}

int32_t ForsGenPrvKey(const SlhDsaAdrs *adrs, uint32_t idx, const SlhDsaCtx *ctx, uint8_t *sk, uint32_t *skLen)
{
    if (sk == NULL || adrs == NULL || ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    uint32_t n = ctx->para.n;

    SlhDsaAdrs skadrs = *adrs;
    ctx->adrsOps.setType(&skadrs, FORS_PRF);
    ctx->adrsOps.copyKeyPairAddr(&skadrs, adrs);
    ctx->adrsOps.setTreeIndex(&skadrs, idx);
    return ctx->pthf(ctx, false, ctx->prvkey.pub.seed, n, &skadrs, ctx->prvkey.seed, n, sk, skLen);
}

int32_t ForsNode(uint32_t idx, uint32_t height, SlhDsaAdrs *adrs, const SlhDsaCtx *ctx, uint8_t *node,
                 uint32_t *nodeLen)
{
    int32_t ret;
    uint32_t n = ctx->para.n;

    if (node == NULL || adrs == NULL || ctx == NULL || nodeLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (height == 0) {
        uint8_t sk[SLH_DSA_MAX_N];
        uint32_t skLen = sizeof(sk);
        ret = ForsGenPrvKey(adrs, idx, ctx, sk, &skLen);
        if (ret != 0) {
            return ret;
        }
        ctx->adrsOps.setTreeHeight(adrs, height);
        ctx->adrsOps.setTreeIndex(adrs, idx);
        return ctx->pthf(ctx, false, ctx->prvkey.pub.seed, n, adrs, sk, skLen, node, nodeLen);
    }

    uint8_t dnode[SLH_DSA_MAX_N * 2];
    uint32_t dnodeLen = (uint32_t)sizeof(dnode);
    ret = ForsNode(idx * 2, height - 1, adrs, ctx, dnode, &dnodeLen);
    if (ret != 0) {
        return ret;
    }
    dnodeLen = (uint32_t)sizeof(dnode) - dnodeLen;
    ret = ForsNode(idx * 2 + 1, height - 1, adrs, ctx, dnode + n, &dnodeLen);
    if (ret != 0) {
        return ret;
    }
    ctx->adrsOps.setTreeHeight(adrs, height);
    ctx->adrsOps.setTreeIndex(adrs, idx);
    return ctx->pthf(ctx, true, ctx->prvkey.pub.seed, n, adrs, dnode, 2 * n, node, nodeLen);
}
#endif // HITLS_CRYPTO_SLH_DSA

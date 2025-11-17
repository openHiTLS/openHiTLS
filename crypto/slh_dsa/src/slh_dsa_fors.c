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
#include "slh_dsa_fors.h"

int32_t ForsSign(const uint8_t *md, uint32_t mdLen, SlhDsaAdrs *adrs, const CryptSlhDsaCtx *ctx, uint8_t *sig,
                 uint32_t *sigLen)
{
    int32_t ret = CRYPT_SLHDSA_ERR_INVALID_SIG_LEN;
    uint32_t n = ctx->para.n;
    uint32_t a = ctx->para.a;
    uint32_t k = ctx->para.k;

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
        ret = ForsGenPrvKey(adrs, indices[i] + (i << a), ctx, sig + offset);
        if (ret != 0) {
            goto ERR;
        }
        offset += n;
        for (uint32_t j = 0; j < a; j++) {
            uint32_t s = (indices[i] >> j) ^ 1;
            ret = ForsNode((i << (a - j)) + s, j, adrs, ctx, sig + offset);
            if (ret != 0) {
                goto ERR;
            }
            offset += n;
        }
    }
    *sigLen = offset;
ERR:
    BSL_SAL_Free(indices);
    return ret;
}

int32_t ForsPkFromSig(const uint8_t *sig, uint32_t sigLen, const uint8_t *md, uint32_t mdLen, SlhDsaAdrs *adrs,
                      const CryptSlhDsaCtx *ctx, uint8_t *pk)
{
    int32_t ret;
    uint32_t *indices = NULL;
    uint8_t *root = NULL;
    uint32_t n = ctx->para.n;
    uint32_t a = ctx->para.a;
    uint32_t k = ctx->para.k;

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

    uint8_t node0[SLH_DSA_MAX_N] = {0};
    uint8_t node1[SLH_DSA_MAX_N] = {0};

    for (uint32_t i = 0; i < k; i++) {
        ctx->adrsOps.setTreeHeight(adrs, 0);
        ctx->adrsOps.setTreeIndex(adrs, (i << a) + indices[i]);

        ret = ctx->hashFuncs.f(ctx, adrs, sig + (a + 1) * n * i, n, node0);
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
                (void)memcpy_s(tmp + n, sizeof(tmp) - n, node0, n);
            } else {
                ctx->adrsOps.setTreeIndex(adrs, ctx->adrsOps.getTreeIndex(adrs) >> 1);
                (void)memcpy_s(tmp, sizeof(tmp), node0, n);
                (void)memcpy_s(tmp + n, sizeof(tmp) - n, auth + j * n, n);
            }

            ret = ctx->hashFuncs.h(ctx, adrs, tmp, 2 * n, node1);
            if (ret != 0) {
                goto ERR;
            }
            (void)memcpy_s(node0, sizeof(node0), node1, sizeof(node1));
        }
        (void)memcpy_s(root + i * n, (k - i) * n, node0, n);
    }

    SlhDsaAdrs forspkAdrs = *adrs;
    ctx->adrsOps.setType(&forspkAdrs, FORS_ROOTS);
    ctx->adrsOps.copyKeyPairAddr(&forspkAdrs, adrs);

    ret = ctx->hashFuncs.tl(ctx, &forspkAdrs, root, n * k, pk);
    if (ret != 0) {
        goto ERR;
    }

ERR:
    BSL_SAL_Free(indices);
    BSL_SAL_Free(root);
    return ret;
}

int32_t ForsGenPrvKey(const SlhDsaAdrs *adrs, uint32_t idx, const CryptSlhDsaCtx *ctx, uint8_t *sk)
{
    SlhDsaAdrs skadrs = *adrs;
    ctx->adrsOps.setType(&skadrs, FORS_PRF);
    ctx->adrsOps.copyKeyPairAddr(&skadrs, adrs);
    ctx->adrsOps.setTreeIndex(&skadrs, idx);

    return ctx->hashFuncs.prf(ctx, &skadrs, sk);
}

int32_t ForsNode(uint32_t idx, uint32_t height, SlhDsaAdrs *adrs, const CryptSlhDsaCtx *ctx, uint8_t *node)
{
    int32_t ret;
    uint32_t n = ctx->para.n;

    if (height == 0) {
        uint8_t sk[SLH_DSA_MAX_N] = {0};
        ret = ForsGenPrvKey(adrs, idx, ctx, sk);
        if (ret != 0) {
            return ret;
        }
        ctx->adrsOps.setTreeHeight(adrs, height);
        ctx->adrsOps.setTreeIndex(adrs, idx);
        ret = ctx->hashFuncs.f(ctx, adrs, sk, n, node);
        (void)BSL_SAL_CleanseData(sk, SLH_DSA_MAX_N);
        return ret;
    }

    uint8_t dnode[SLH_DSA_MAX_N * 2];
    ret = ForsNode(idx * 2, height - 1, adrs, ctx, dnode);
    if (ret != 0) {
        return ret;
    }
    ret = ForsNode(idx * 2 + 1, height - 1, adrs, ctx, dnode + n);
    if (ret != 0) {
        return ret;
    }
    ctx->adrsOps.setTreeHeight(adrs, height);
    ctx->adrsOps.setTreeIndex(adrs, idx);
    return ctx->hashFuncs.h(ctx, adrs, dnode, 2 * n, node);
}
#endif // HITLS_CRYPTO_SLH_DSA

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
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "slh_dsa_local.h"
#include "slh_dsa_xmss.h"
#include "slh_dsa_hypertree.h"

int32_t HypertreeSign(const uint8_t *msg, uint32_t msgLen, uint64_t treeIdx, uint32_t leafIdx,
                      const CryptSlhDsaCtx *ctx, uint8_t *sig, uint32_t *sigLen)
{
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint32_t hp = ctx->para.hp;
    uint32_t d = ctx->para.d;
    uint32_t len = 2 * n + 3;
    uint32_t retLen = (len + hp) * n * d;
    uint32_t leafIdxTmp = leafIdx;
    uint64_t treeIdxTmp = treeIdx;

    if (*sigLen < retLen) {
        return CRYPT_SLHDSA_ERR_SIG_LEN_NOT_ENOUGH;
    }

    SlhDsaAdrs adrs = {0};

    uint32_t offset = 0;
    uint32_t tmpLen = *sigLen;
    uint8_t root[MAX_MDSIZE] = {0};
    // the msgLen is actually n.
    (void)memcpy_s(root, sizeof(root), msg, msgLen);

    for (uint32_t j = 0; j < d; j++) {
        if (j != 0) {
            leafIdxTmp = (uint32_t)(treeIdxTmp & ((1UL << hp) - 1));
            treeIdxTmp = treeIdxTmp >> hp;
            ctx->adrsOps.setLayerAddr(&adrs, j);
        }
        ctx->adrsOps.setTreeAddr(&adrs, treeIdxTmp);
        tmpLen = retLen - offset;
        ret = XmssSign(root, n, leafIdxTmp, &adrs, ctx, sig + offset, &tmpLen, root);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        offset += tmpLen;
    }
    *sigLen = retLen;
    return CRYPT_SUCCESS;
}

int32_t HypertreeVerify(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, uint64_t treeIdx,
                        uint32_t leafIdx, const CryptSlhDsaCtx *ctx)
{
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint32_t hp = ctx->para.hp;
    uint32_t d = ctx->para.d;
    uint32_t len = 2 * n + 3;
    uint32_t retLen = (len + hp) * n * d;
    uint32_t leafIdxTmp = leafIdx;
    uint64_t treeIdxTmp = treeIdx;

    if (sigLen < retLen) {
        return CRYPT_SLHDSA_ERR_SIG_LEN_NOT_ENOUGH;
    }

    SlhDsaAdrs adrs = {0};
    uint32_t offset = 0;

    uint8_t node[MAX_MDSIZE] = {0};
    // the msgLen is actually n.
    (void)memcpy_s(node, sizeof(node), msg, msgLen);
    for (uint32_t j = 0; j < d; j++) {
        if (j != 0) {
            leafIdxTmp = (uint32_t)(treeIdxTmp & ((1UL << hp) - 1));
            treeIdxTmp = treeIdxTmp >> hp;
            ctx->adrsOps.setLayerAddr(&adrs, j);
        }
        ctx->adrsOps.setTreeAddr(&adrs, treeIdxTmp);
        ret = XmssPkFromSig(leafIdxTmp, sig + offset, sigLen - offset, node, n, &adrs, ctx, node);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        offset += (len + hp) * n;
    }

    if (memcmp(node, ctx->prvKey.pub.root, n) != 0) {
        return CRYPT_SLHDSA_ERR_HYPERTREE_VERIFY_FAIL;
    }
    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_SLH_DSA

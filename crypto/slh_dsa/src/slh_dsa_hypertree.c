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
#include "slh_dsa_hypertree.h"

int32_t HypertreeSign(const uint8_t *msg, uint32_t msgLen, uint64_t treeIdx, uint32_t leafIdx,
                      const CryptSlhDsaCtx *ctx, uint8_t *sig, uint32_t *sigLen)
{
    TreeCtx treeCtx;
    InitTreeCtxFromSlhDsaCtx(&treeCtx, ctx);
    return HyperTree_Sign(msg, msgLen, treeIdx, leafIdx, &treeCtx, sig, sigLen);
}

int32_t HypertreeVerify(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, uint64_t treeIdx,
                        uint32_t leafIdx, const CryptSlhDsaCtx *ctx)
{
    TreeCtx treeCtx;
    InitTreeCtxFromSlhDsaCtx(&treeCtx, ctx);
    return HyperTree_Verify(msg, msgLen, sig, sigLen, treeIdx, leafIdx, &treeCtx);
}

#endif // HITLS_CRYPTO_SLH_DSA

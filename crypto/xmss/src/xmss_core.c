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
#ifdef HITLS_CRYPTO_XMSS

#include "securec.h"
#include "crypt_errno.h"
#include "crypt_util_rand.h"
#include "crypt_utils.h"
#include "xmss_local.h"
#include "xmss_wots.h"
#include "xmss_tree.h"
#include "xmss_hash.h"

int32_t CRYPT_XMSS_InitInternal(CryptXmssCtx *ctx, const XmssParams *params)
{
    /* Store pointer to parameters (from global param table) */
    ctx->params = params;

    /* Initialize hash functions */
    int32_t ret = XmssInitHashFuncs(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Initialize address operations */
    ret = XmssAdrsOps_Init(&ctx->adrsOps);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Initialize key structure to zero */
    (void)memset_s(&ctx->key, sizeof(ctx->key), 0, sizeof(ctx->key));

    return CRYPT_SUCCESS;
}

int32_t CRYPT_XMSS_KeyGenInternal(CryptXmssCtx *ctx)
{
    int32_t ret;
    uint32_t n = ctx->params->n;
    uint32_t d = ctx->params->d;
    uint32_t hp = ctx->params->hp;

    /* Generate random private seed */
    ret = CRYPT_RandEx(ctx->libCtx, ctx->key.seed, n);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Generate random PRF key */
    ret = CRYPT_RandEx(ctx->libCtx, ctx->key.prf, n);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Generate random public seed */
    ret = CRYPT_RandEx(ctx->libCtx, ctx->key.pubSeed, n);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    XmssAdrs adrs = {0};
    ctx->adrsOps.setLayerAddr(&adrs, d - 1);
    TreeCtx treeCtx;
    InitTreeCtxFromXmssCtx(&treeCtx, ctx);
    uint8_t node[XMSS_MAX_MDSIZE] = {0};
    ret = XmssTree_ComputeNode(node, 0, hp, &adrs, &treeCtx, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memcpy_s(ctx->key.root, n, node, n);
    ctx->key.idx = 0;
    return CRYPT_SUCCESS;
}

/* integer to big-endian bytes */
static void U64toBytes(uint8_t *out, uint32_t outlen, uint64_t in)
{
    for (int32_t i = outlen - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}

int32_t CRYPT_XMSS_SignInternal(CryptXmssCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint8_t *sig, uint32_t *sigLen)
{
    int32_t ret;
    uint32_t n = ctx->params->n;
    uint32_t h = ctx->params->h;
    uint32_t d = ctx->params->d;
    uint32_t hp = ctx->params->hp;
    if (*sigLen < ctx->params->sigBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_SIG_LEN);
        return CRYPT_XMSS_ERR_INVALID_SIG_LEN;
    }
    /* Check key expiration before incrementing to avoid wrap-around and ensure valid range */
    uint64_t max_idx = (h == 64) ? (UINT64_MAX - 1) : ((1ULL << h) - 1);
    if (ctx->key.idx > max_idx) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_KEY_EXPIRED);
        return CRYPT_XMSS_ERR_KEY_EXPIRED;
    }
    /* Get current index and increment */
    uint64_t index = ctx->key.idx++;
    /* XMSS: 4-bytes index_bytes, XMSSMT: (ceil(h / 8))-bytes index_bytes */
    uint32_t idxBytes = (d == 1) ? 4 : (h + 7) / 8;
    uint32_t offset = 0;

    /* Write index (big-endian) */
    U64toBytes(sig, idxBytes, index);
    offset += idxBytes;

    uint8_t idx[XMSS_MAX_MDSIZE] = {0};
    PUT_UINT64_BE(index, idx, sizeof(idx) - 8); // Put index in last 8 bytes

    ret = ctx->hashFuncs->prfmsg(ctx, idx + sizeof(idx) - 32, NULL, 0, sig + offset);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t digest[XMSS_MAX_MDSIZE] = {0};
    ret = ctx->hashFuncs->hmsg(ctx, sig + offset, msg, msgLen, idx + sizeof(idx) - n, digest);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += n;
    uint32_t left = *sigLen - offset;
    uint32_t leafIdx = (uint32_t)(index & ((1ULL << hp) - 1));
    uint64_t treeIdx = index >> hp;
    TreeCtx treeCtx;
    InitTreeCtxFromXmssCtx(&treeCtx, ctx);
    ret = HyperTree_Sign(digest, n, treeIdx, leafIdx, &treeCtx, sig + offset, &left);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    *sigLen = offset + left;
    return CRYPT_SUCCESS;
}

/* big-endian bytes to integer. */
static uint64_t BytestoU64(const uint8_t *in, uint32_t inlen)
{
    uint64_t ret = 0;
    for (; inlen > 0; in++, inlen--) {
        ret = ret << 8;
        ret |= in[0];
    }
    return ret;
}

int32_t CRYPT_XMSS_VerifyInternal(const CryptXmssCtx *ctx, const uint8_t *msg, uint32_t msgLen, const uint8_t *sig,
                                  uint32_t sigLen)
{
    // RFC 8391 mandates exact signature length match
    if (sigLen != ctx->params->sigBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_SIG_LEN);
        return CRYPT_XMSS_ERR_INVALID_SIG_LEN;
    }
    int32_t ret;
    uint32_t n = ctx->params->n;
    uint32_t d = ctx->params->d;
    uint32_t hp = ctx->params->hp;
    uint32_t offset = 0;
    uint32_t h = ctx->params->h;
    uint32_t idxBytes = (d == 1) ? 4 : (h + 7) / 8;
    uint64_t index = BytestoU64(sig, idxBytes);
    offset += idxBytes;
    uint8_t idx[XMSS_MAX_MDSIZE] = {0};
    PUT_UINT64_BE(index, idx, sizeof(idx) - 8);
    uint8_t digest[XMSS_MAX_MDSIZE] = {0};
    ret = ctx->hashFuncs->hmsg(ctx, sig + offset, msg, msgLen, idx + sizeof(idx) - n, digest);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += n;
    // Force 64-bit arithmetic with 1ULL to avoid potential overflow on 32-bit systems
    uint32_t leafIdx = (uint32_t)(index & ((1ULL << hp) - 1));
    uint64_t treeIdx = index >> hp;
    TreeCtx treeCtx;
    InitTreeCtxFromXmssCtx(&treeCtx, ctx);
    return HyperTree_Verify(digest, n, sig + offset, sigLen - offset, treeIdx, leafIdx, &treeCtx);
}
#endif // HITLS_CRYPTO_XMSS

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
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT)

#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "eal_md_local.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "xmss_hash.h"
#include "xmss_local.h"
#include "xmss_address.h"
#include "hbs_wots.h"

/* Padding types for domain separation */
#define PADDING_F          0
#define PADDING_H          1
#define PADDING_HASH       2
#define PADDING_PRF        3
#define PADDING_PRF_KEYGEN 4

int32_t CalcMultiMsgHash(CRYPT_MD_AlgId mdId, const CRYPT_ConstData *hashData, uint32_t hashDataLen, uint8_t *out,
                         uint32_t outLen)
{
    /* tmp is the hash output buffer; skDerive writes WOTS+ private key elements
     * into tmp, sigRandGen writes signing randomness into tmp — cleanse to
     * prevent secret residue on the stack before return. */
    uint8_t tmp[XMSS_MAX_MDSIZE] = {0};
    uint32_t tmpLen = sizeof(tmp);
    int32_t ret = CRYPT_CalcHash(NULL, EAL_MdFindDefaultMethod(mdId), hashData, hashDataLen, tmp, &tmpLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_CleanseData(tmp, sizeof(tmp));
        return ret;
    }
    memcpy(out, tmp, outLen);
    BSL_SAL_CleanseData(tmp, sizeof(tmp));
    return CRYPT_SUCCESS;
}

/*
 * Generic hash function implementations
 * These functions read algorithm parameters (mdId, paddingLen) from ctx->params
 * at runtime, eliminating the need for macro-based code generation.
 */

/* skDerive - Pseudorandom Function for key generation (PRF_keygen)
 * Derives a single WOTS+ private key element from skSeed and address structure.
 * Corresponds to XmssFamilyHashFuncs.skDerive (formerly: prf / XPrfGeneric) */
static int32_t XmssSkDerive(const void *vctx, const void *vadrs, uint8_t *out)
{
    const CryptXmssCtx *ctx = (const CryptXmssCtx *)vctx;
    const XmssAdrs *adrs = (const XmssAdrs *)vadrs;
    uint32_t n = ctx->params->n;
    uint32_t paddingLen = ctx->params->paddingLen;
    CRYPT_MD_AlgId mdId = ctx->params->mdId;

    uint8_t padding[XMSS_MAX_MDSIZE] = {0};
    const CRYPT_ConstData hashData[] = {
        {padding, paddingLen}, {ctx->key.seed, n}, {ctx->key.pubSeed, n}, {adrs->bytes, 32}};
    PUT_UINT32_BE(PADDING_PRF_KEYGEN, padding, paddingLen - 4);
    return CalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);
}

/* sigRandGen - PRF for message randomization (PRF_msg)
 * Generates the per-signature randomness r used in message hashing.
 * Corresponds to XmssFamilyHashFuncs.sigRandGen (formerly: prfmsg / PrfmsgGeneric) */
static int32_t XmssSignRandGen(const void *vctx, const uint8_t *idx, const uint8_t *msg, uint32_t msgLen, uint8_t *out)
{
    (void)msg;
    (void)msgLen;
    const CryptXmssCtx *ctx = (const CryptXmssCtx *)vctx;
    uint32_t n = ctx->params->n;
    uint32_t paddingLen = ctx->params->paddingLen;
    CRYPT_MD_AlgId mdId = ctx->params->mdId;

    uint8_t padding[XMSS_MAX_MDSIZE] = {0};
    const CRYPT_ConstData hashData[] = {{padding, paddingLen}, {ctx->key.prf, n}, {idx, 32}};
    PUT_UINT32_BE(PADDING_PRF, padding, paddingLen - 4);
    return CalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);
}

/* msgHash - Message hash with randomization (H_msg)
 * Randomized message hash binding message to r, tree root and index.
 * Corresponds to XmssFamilyHashFuncs.msgHash (formerly: hmsg / HmsgGeneric) */
static int32_t XmssMsgHash(const void *vctx, const uint8_t *r, const uint8_t *msg, uint32_t msgLen, const uint8_t *idx,
                           uint8_t *out)
{
    (void)idx;
    const CryptXmssCtx *ctx = (const CryptXmssCtx *)vctx;
    uint32_t n = ctx->params->n;
    uint32_t paddingLen = ctx->params->paddingLen;
    CRYPT_MD_AlgId mdId = ctx->params->mdId;

    uint8_t padding[XMSS_MAX_MDSIZE] = {0};
    const CRYPT_ConstData hashData[] = {{padding, paddingLen}, {r, n}, {ctx->key.root, n}, {idx, n}, {msg, msgLen}};
    PUT_UINT32_BE(PADDING_HASH, padding, paddingLen - 4);
    return CalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);
}

/* chainHash - WOTS+ chaining function (F)
 * Single step of WOTS+ chain iteration with bitmask XOR.
 * Corresponds to XmssFamilyHashFuncs.chainHash (formerly: f / XFGeneric) */
static int32_t XmssChainHash(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen, uint8_t *out)
{
    (void)msgLen;
    int32_t ret;
    const CryptXmssCtx *ctx = (const CryptXmssCtx *)vctx;
    XmssAdrs xadrs = *(const XmssAdrs *)vadrs;
    uint32_t n = ctx->params->n;
    uint32_t paddingLen = ctx->params->paddingLen;
    CRYPT_MD_AlgId mdId = ctx->params->mdId;

    uint8_t padding[XMSS_MAX_MDSIZE] = {0};
    uint8_t key[XMSS_MAX_MDSIZE];
    uint8_t bitmask[XMSS_MAX_MDSIZE];

    const CRYPT_ConstData hashData[] = {{padding, paddingLen}, {ctx->key.pubSeed, n}, {xadrs.bytes, 32}};
    const CRYPT_ConstData hashData1[] = {{padding, paddingLen}, {key, n}, {bitmask, n}};

    PUT_UINT32_BE(PADDING_PRF, padding, paddingLen - 4);

    /* Generate n-byte key */
    XmssAdrs_SetKeyAndMask(&xadrs, 0);
    ret = CalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), key, n);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Generate n-byte bitmask */
    XmssAdrs_SetKeyAndMask(&xadrs, 1);
    ret = CalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), bitmask, n);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* XOR message with bitmask */
    for (uint32_t i = 0; i < n; i++) {
        bitmask[i] = msg[i] ^ bitmask[i];
    }

    PUT_UINT32_BE(PADDING_F, padding, paddingLen - 4);
    ret = CalcMultiMsgHash(mdId, hashData1, sizeof(hashData1) / sizeof(hashData1[0]), out, n);
    BSL_SAL_CleanseData(key, n);
    return ret;
}

/* nodeHash - Tree hash function (RAND_HASH / H)
 * Merges two child nodes into a parent node using bitmask XOR.
 * Corresponds to XmssFamilyHashFuncs.nodeHash (formerly: h / XHGeneric) */
static int32_t XmssNodeHash(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen, uint8_t *out)
{
    (void)msgLen;
    const CryptXmssCtx *ctx = (const CryptXmssCtx *)vctx;
    XmssAdrs xadrs = *(const XmssAdrs *)vadrs;
    uint32_t n = ctx->params->n;
    uint32_t paddingLen = ctx->params->paddingLen;
    CRYPT_MD_AlgId mdId = ctx->params->mdId;

    uint8_t padding[XMSS_MAX_MDSIZE] = {0};
    uint8_t key[XMSS_MAX_MDSIZE];
    uint8_t bitmask[2 * XMSS_MAX_MDSIZE];

    const CRYPT_ConstData hashData[] = {{padding, paddingLen}, {ctx->key.pubSeed, n}, {xadrs.bytes, 32}};
    const CRYPT_ConstData hashData1[] = {{padding, paddingLen}, {key, n}, {bitmask, 2 * n}};

    PUT_UINT32_BE(PADDING_PRF, padding, paddingLen - 4);

    /* Generate n-byte key */
    XmssAdrs_SetKeyAndMask(&xadrs, 0);
    int32_t ret = CalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), key, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(key, n);
        return ret;
    }

    /* Generate n-byte BM_0 */
    XmssAdrs_SetKeyAndMask(&xadrs, 1);
    ret = CalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), bitmask, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(key, n);
        return ret;
    }

    /* Generate n-byte BM_1 */
    XmssAdrs_SetKeyAndMask(&xadrs, 2);
    ret = CalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), bitmask + n, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(key, n);
        return ret;
    }

    /* XOR input with bitmasks */
    for (uint32_t i = 0; i < 2 * n; i++) {
        bitmask[i] = msg[i] ^ bitmask[i];
    }

    PUT_UINT32_BE(PADDING_H, padding, paddingLen - 4);
    ret = CalcMultiMsgHash(mdId, hashData1, sizeof(hashData1) / sizeof(hashData1[0]), out, n);
    BSL_SAL_CleanseData(key, n);
    return ret;
}

/* pkCompress - L-tree compression (T_l)
 * Compresses a WOTS+ public key (multiple n-byte chain ends) to a single leaf node via L-tree.
 * Corresponds to XmssFamilyHashFuncs.pkCompress (formerly: tl / XTlGeneric) */
static int32_t XmssPkCompress(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen, uint8_t *out)
{
    XmssAdrs xadrs = *(const XmssAdrs *)vadrs;
    const CryptXmssCtx *ctx = (const CryptXmssCtx *)vctx;
    uint32_t n = ctx->params->n;
    uint32_t len = 2 * n + 3;

    /* Allocate node buffer: uint8_t node[len][n] */
    if (n == 0 || len > SIZE_MAX / n) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint8_t *node = (uint8_t *)BSL_SAL_Malloc((size_t)len * n);
    if (node == NULL) {
        return BSL_MALLOC_FAIL;
    }

    memcpy(node, msg, msgLen);
    int32_t ret;
    for (uint32_t h = 0; len > 1; h++) {
        ctx->adrsOps.setTreeHeight(&xadrs, h);
        for (uint32_t i = 0; i < len / 2; i++) {
            ctx->adrsOps.setTreeIndex(&xadrs, i);
            /* Compute parent node from children */
            ret = XmssNodeHash(vctx, &xadrs, node + (i * 2 * n), 2 * n, node + (i * n));
            if (ret != CRYPT_SUCCESS) {
                goto ERR;
            }
        }
        /* Handle unbalanced L-tree */
        if (len & 1) {
            memcpy(node + (len / 2 * n), node + (len - 1) * n, n);
            len = len / 2 + 1;
        } else {
            len = len / 2;
        }
    }

    memcpy(out, node, n);
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_Free(node);
    return ret;
}

/* Static hash function table - shared by all XMSS algorithms.
 * XMSS uses the generic HbsWots_Chain fallback (chain = NULL). */
static const XmssFamilyHashFuncs g_xmssGenericHashFuncs = {
    .skDerive = XmssSkDerive,
    .chainHash = XmssChainHash,
    .nodeHash = XmssNodeHash,
    .pkCompress = XmssPkCompress,
    .sigRandGen = XmssSignRandGen,
    .msgHash = XmssMsgHash,
    .chain = NULL,
};

int32_t XmssInitHashFuncs(CryptXmssCtx *ctx)
{
    if (ctx == NULL || ctx->params == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Validate that algorithm parameters are set correctly */
    if (ctx->params->mdId == 0 || ctx->params->paddingLen == 0) {
        return CRYPT_XMSS_ERR_INVALID_ALGID;
    }

    /* All algorithms use the same generic hash functions */
    ctx->hashFuncs = &g_xmssGenericHashFuncs;

    return CRYPT_SUCCESS;
}

#endif /* defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT) */

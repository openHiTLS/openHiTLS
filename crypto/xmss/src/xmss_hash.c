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
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "eal_md_local.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "xmss_hash.h"
#include "xmss_local.h"
#include "xmss_address.h"

/* Padding types for domain separation */
#define PADDING_F          0
#define PADDING_H          1
#define PADDING_HASH       2
#define PADDING_PRF        3
#define PADDING_PRF_KEYGEN 4

int32_t CalcMultiMsgHash(CRYPT_MD_AlgId mdId, const CRYPT_ConstData *hashData, uint32_t hashDataLen, uint8_t *out,
                         uint32_t outLen)
{
    uint8_t tmp[XMSS_MAX_MDSIZE] = {0};
    uint32_t tmpLen = sizeof(tmp);
    int32_t ret = CRYPT_CalcHash(NULL, EAL_MdFindDefaultMethod(mdId), hashData, hashDataLen, tmp, &tmpLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memcpy_s(out, outLen, tmp, outLen);
    return CRYPT_SUCCESS;
}

/*
 * Generic hash function implementations
 * These functions read algorithm parameters (mdId, paddingLen) from ctx->params
 * at runtime, eliminating the need for macro-based code generation.
 */

/* PRF - Pseudorandom Function for key generation */
static int32_t XPrfGeneric(const void *vctx, const void *vadrs, uint8_t *out)
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

/* PRFmsg - PRF for message randomization */
static int32_t PrfmsgGeneric(const void *vctx, const uint8_t *idx, const uint8_t *msg, uint32_t msgLen, uint8_t *out)
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

/* Hmsg - Message hash with randomization */
static int32_t HmsgGeneric(const void *vctx, const uint8_t *r, const uint8_t *msg, uint32_t msgLen, const uint8_t *idx,
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

/* F - WOTS+ chaining function */
static int32_t XFGeneric(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen, uint8_t *out)
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
    return CalcMultiMsgHash(mdId, hashData1, sizeof(hashData1) / sizeof(hashData1[0]), out, n);
}

/* H - Tree hash function (RAND_HASH) */
static int32_t XHGeneric(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen, uint8_t *out)
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
        return ret;
    }

    /* Generate n-byte BM_0 */
    XmssAdrs_SetKeyAndMask(&xadrs, 1);
    ret = CalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), bitmask, n);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Generate n-byte BM_1 */
    XmssAdrs_SetKeyAndMask(&xadrs, 2);
    ret = CalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), bitmask + n, n);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* XOR input with bitmasks */
    for (uint32_t i = 0; i < 2 * n; i++) {
        bitmask[i] = msg[i] ^ bitmask[i];
    }

    PUT_UINT32_BE(PADDING_H, padding, paddingLen - 4);
    return CalcMultiMsgHash(mdId, hashData1, sizeof(hashData1) / sizeof(hashData1[0]), out, n);
}

/* TL - L-tree compression (compress WOTS+ public key to leaf node) */
static int32_t XTlGeneric(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen, uint8_t *out)
{
    XmssAdrs xadrs = *(const XmssAdrs *)vadrs;
    const CryptXmssCtx *ctx = (const CryptXmssCtx *)vctx;
    uint32_t n = ctx->params->n;
    uint32_t len = 2 * n + 3;

    /* Allocate node buffer: uint8_t node[len][n] */
    uint8_t *node = (uint8_t *)BSL_SAL_Malloc(len * n);
    if (node == NULL) {
        return BSL_MALLOC_FAIL;
    }

    (void)memcpy_s(node, len * n, msg, msgLen);
    int32_t ret;
    for (uint32_t h = 0; len > 1; h++) {
        ctx->adrsOps.setTreeHeight(&xadrs, h);
        for (uint32_t i = 0; i < len / 2; i++) {
            ctx->adrsOps.setTreeIndex(&xadrs, i);
            /* Compute parent node from children */
            ret = XHGeneric(vctx, &xadrs, node + (i * 2 * n), 2 * n, node + (i * n));
            if (ret != CRYPT_SUCCESS) {
                goto ERR;
            }
        }
        /* Handle unbalanced L-tree */
        if (len & 1) {
            (void)memcpy_s(node + (len / 2 * n), (len * n) - (len / 2 * n), node + (len - 1) * n, n);
            len = len / 2 + 1;
        } else {
            len = len / 2;
        }
    }

    (void)memcpy_s(out, n, node, n);
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_Free(node);
    return ret;
}

/* Static hash function table - shared by all XMSS algorithms */
static const CryptHashFuncs g_xmssGenericHashFuncs = {
    .prf = XPrfGeneric,
    .f = XFGeneric,
    .h = XHGeneric,
    .tl = XTlGeneric,
    .prfmsg = PrfmsgGeneric,
    .hmsg = HmsgGeneric,
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

#endif // HITLS_CRYPTO_XMSS

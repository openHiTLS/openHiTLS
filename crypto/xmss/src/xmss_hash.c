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
#include "eal_md_local.h"
#include "crypt_xmss.h"
#include "crypt_algid.h"
#include "xmss_hash.h"
#include "slh_dsa_local.h"

#define PADDING_F          0
#define PADDING_H          1
#define PADDING_HASH       2
#define PADDING_PRF        3
#define PADDING_PRF_KEYGEN 4

static int32_t XCalcMultiMsgHash(CRYPT_MD_AlgId mdId, const CRYPT_ConstData *hashData, uint32_t hashDataLen,
                                 uint8_t *out, uint32_t outLen)
{
    uint8_t tmp[MAX_MDSIZE] = {0};
    uint32_t tmpLen = sizeof(tmp);
    int32_t ret = CRYPT_CalcHash(NULL, EAL_MdFindDefaultMethod(mdId), hashData, hashDataLen, tmp, &tmpLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memcpy_s(out, outLen, tmp, outLen);
    return CRYPT_SUCCESS;
}

# define IMPLEMENT_XHashFuncs(name, mdId, padding_len)                                                          \
static int32_t XPrf##name(const CryptXmssCtx *ctx, const XmssAdrs *adrs, uint8_t *out)                          \
{                                                                                                               \
    uint32_t n = ctx->para.n;                                                                                   \
    uint8_t padding[MAX_MDSIZE] = {0};                                                                          \
    const CRYPT_ConstData hashData[] = {{padding, padding_len},                                                 \
                                        {ctx->prvKey.seed, n},                                                  \
                                        {ctx->prvKey.pub.seed, n},                                              \
                                        {adrs->bytes, ctx->adrsOps.getAdrsLen()}};                              \
    PUT_UINT32_BE(PADDING_PRF_KEYGEN, padding, padding_len - 4);                                                \
    return XCalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);                   \
}                                                                                                               \
static int32_t Prfmsg##name(const CryptXmssCtx *ctx, const uint8_t *idx, const uint8_t *msg, uint32_t msgLen,   \
                            uint8_t *out)                                                                       \
{                                                                                                               \
    (void)msg;                                                                                                  \
    (void)msgLen;                                                                                               \
    uint32_t n = ctx->para.n;                                                                                   \
    uint8_t padding[MAX_MDSIZE] = {0};                                                                          \
    const CRYPT_ConstData hashData[] = {{padding, padding_len},                                                 \
                                        {ctx->prvKey.prf, n},                                                   \
                                        {idx, 32}};                                                             \
    PUT_UINT32_BE(PADDING_PRF, padding, padding_len - 4);                                                       \
    return XCalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);                   \
}                                                                                                               \
static int32_t Hmsg##name(const CryptXmssCtx *ctx, const uint8_t *r, const uint8_t *msg, uint32_t msgLen,       \
                          const uint8_t *idx, uint8_t *out)                                                     \
{                                                                                                               \
    uint32_t n = ctx->para.n;                                                                                   \
    uint8_t padding[MAX_MDSIZE] = {0};                                                                          \
    const CRYPT_ConstData hashData[] = {{padding, padding_len},                                                 \
                                        {r, n},                                                                 \
                                        {ctx->prvKey.pub.root, n},                                              \
                                        {idx, n},                                                               \
                                        {msg, msgLen}};                                                         \
    PUT_UINT32_BE(PADDING_HASH, padding, padding_len - 4);                                                      \
    return XCalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);                   \
}                                                                                                               \
/* A step of Chaining Function */                                                                               \
static int32_t XF##name(const CryptXmssCtx *ctx, const XmssAdrs *adrs, const uint8_t *msg, uint32_t msgLen,     \
                        uint8_t *out)                                                                           \
{                                                                                                               \
    (void)msgLen;                                                                                               \
    int32_t ret;                                                                                                \
    XmssAdrs xadrs = *adrs;                                                                                     \
    uint32_t n = ctx->para.n;                                                                                   \
    uint8_t padding[MAX_MDSIZE] = {0};                                                                          \
    uint8_t key[MAX_MDSIZE];                                                                                    \
    uint8_t bitmask[MAX_MDSIZE];                                                                                \
    const CRYPT_ConstData hashData[] = {{padding, padding_len},                                                 \
                                        {ctx->prvKey.pub.seed, n},                                              \
                                        {xadrs.bytes, ctx->adrsOps.getAdrsLen()}};                              \
    const CRYPT_ConstData hashData1[] = {{padding, padding_len},                                                \
                                         {key, n},                                                              \
                                         {bitmask, n}};                                                         \
    PUT_UINT32_BE(PADDING_PRF, padding, padding_len - 4);                                                       \
    /* n-byte key */                                                                                            \
    ctx->adrsOps.setKeyAndMask(&xadrs, 0);                                                                      \
    ret = XCalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), key, n);                    \
    if (ret != CRYPT_SUCCESS) {                                                                                 \
        return ret;                                                                                             \
    }                                                                                                           \
    /* n-byte BM */                                                                                             \
    ctx->adrsOps.setKeyAndMask(&xadrs, 1);                                                                      \
    ret = XCalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), bitmask, n);                \
    if (ret != CRYPT_SUCCESS) {                                                                                 \
        return ret;                                                                                             \
    }                                                                                                           \
    PUT_UINT32_BE(PADDING_F, padding, padding_len - 4);                                                         \
    for (uint32_t i = 0; i < n; i++) {                                                                          \
        bitmask[i] = msg[i] ^ bitmask[i];                                                                       \
    }                                                                                                           \
    return XCalcMultiMsgHash(mdId, hashData1, sizeof(hashData1) / sizeof(hashData1[0]), out, n);                \
}                                                                                                               \
/* RAND_HASH : compress Left child node and Right child node to parent node */                                  \
static int32_t XH##name(const CryptXmssCtx *ctx, const XmssAdrs *adrs, const uint8_t *msg, uint32_t msgLen,     \
                        uint8_t *out)                                                                           \
{                                                                                                               \
    (void)msgLen;                                                                                               \
    int32_t ret;                                                                                                \
    XmssAdrs xadrs = *adrs;                                                                                     \
    uint32_t n = ctx->para.n;                                                                                   \
    uint8_t padding[MAX_MDSIZE] = {0};                                                                          \
    uint8_t key[MAX_MDSIZE];                                                                                    \
    uint8_t bitmask[2 * MAX_MDSIZE];                                                                            \
    const CRYPT_ConstData hashData[] = {{padding, padding_len},                                                 \
                                        {ctx->prvKey.pub.seed, n},                                              \
                                        {xadrs.bytes, ctx->adrsOps.getAdrsLen()}};                              \
    const CRYPT_ConstData hashData1[] = {{padding, padding_len},                                                \
                                         {key, n},                                                              \
                                         {bitmask, 2 * n}};                                                     \
    PUT_UINT32_BE(PADDING_PRF, padding, padding_len - 4);                                                       \
    /* n-byte key */                                                                                            \
    ctx->adrsOps.setKeyAndMask(&xadrs, 0);                                                                      \
    ret = XCalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), key, n);                    \
    if (ret != CRYPT_SUCCESS) {                                                                                 \
        return ret;                                                                                             \
    }                                                                                                           \
    /* n-byte BM_0 */                                                                                           \
    ctx->adrsOps.setKeyAndMask(&xadrs, 1);                                                                      \
    ret = XCalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), bitmask, n);                \
    if (ret != CRYPT_SUCCESS) {                                                                                 \
        return ret;                                                                                             \
    }                                                                                                           \
    /* n-byte BM_1 */                                                                                           \
    ctx->adrsOps.setKeyAndMask(&xadrs, 2);                                                                      \
    ret = XCalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), bitmask + n, n);            \
    if (ret != CRYPT_SUCCESS) {                                                                                 \
        return ret;                                                                                             \
    }                                                                                                           \
    PUT_UINT32_BE(PADDING_H, padding, padding_len - 4);                                                         \
    for (uint32_t i = 0; i < 2 * n; i++) {                                                                      \
        bitmask[i] = msg[i] ^ bitmask[i];                                                                       \
    }                                                                                                           \
    return XCalcMultiMsgHash(mdId, hashData1, sizeof(hashData1) / sizeof(hashData1[0]), out, n);                \
}

/* L-tree : compress len * n-bytes WOTS+ public key to n-bytes leaf node of main hash tree */
static int32_t XTl(const CryptXmssCtx *ctx, const XmssAdrs *adrs, const uint8_t *msg, uint32_t msgLen,
                   uint8_t *out)
{
    int32_t ret;
    XmssAdrs xadrs = *adrs;
    uint32_t n = ctx->para.n;
    uint32_t len = 2 * n + 3;

    /* uint8_t node[len][n] */
    uint8_t *node = (uint8_t *)BSL_SAL_Malloc(len * n);
    if (node == NULL) {
        return BSL_MALLOC_FAIL;
    }

    (void)memcpy_s(node, len * n, msg, msgLen);

    for (uint32_t h = 0; len > 1; h++) {
        ctx->adrsOps.setTreeHeight(&xadrs, h);
        for (uint32_t i = 0; i < len/2; i++) {
            ctx->adrsOps.setTreeIndex(&xadrs, i);
            /*          node[i][0]
             *           /    \
             *          /      \
             *         /        \
             *        /          \
             * node[i*2][0]  node[i*2+1][0] */
            ret = ctx->hashFuncs.h(ctx, &xadrs, node + (i * 2 * n), 2 * n, node + (i * n));
            if (ret != CRYPT_SUCCESS) {
                goto ERR;
            }
        }
        /* An L-tree is an unbalanced binary hash tree */
        if (len & 1) {
            (void)memcpy_s(node + (len/2 * n), (len * n) - (len/2 * n), 
                           node + (len - 1) * n, n);
            len = len/2 + 1;
        } else {
            len = len/2;
        }
    }

    (void)memcpy_s(out, n, node, n);
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_Free(node);
    return ret;
}

IMPLEMENT_XHashFuncs(Sha256, CRYPT_MD_SHA256, 32)
IMPLEMENT_XHashFuncs(Sha256_192, CRYPT_MD_SHA256, 4)
IMPLEMENT_XHashFuncs(Sha512, CRYPT_MD_SHA512, 64)
IMPLEMENT_XHashFuncs(Shake128, CRYPT_MD_SHAKE128, 32)
IMPLEMENT_XHashFuncs(Shake256, CRYPT_MD_SHAKE256, 64)
IMPLEMENT_XHashFuncs(Shake256_256, CRYPT_MD_SHAKE256, 32)
IMPLEMENT_XHashFuncs(Shake256_192, CRYPT_MD_SHAKE256, 4)

int32_t XmssInitHashFuncs(CryptXmssCtx *ctx)
{
    static const XmssHashFuncs XHashFuncsSha256 = {
        .prf = XPrfSha256,
        .tl = XTl,
        .h = XHSha256,
        .f = XFSha256,
        .prfmsg = PrfmsgSha256,
        .hmsg = HmsgSha256,
    };
    static const XmssHashFuncs XHashFuncsSha256_192 = {
        .prf = XPrfSha256_192,
        .tl = XTl,
        .h = XHSha256_192,
        .f = XFSha256_192,
        .prfmsg = PrfmsgSha256_192,
        .hmsg = HmsgSha256_192,
    };
    static const XmssHashFuncs XHashFuncsSha512 = {
        .prf = XPrfSha512,
        .tl = XTl,
        .h = XHSha512,
        .f = XFSha512,
        .prfmsg = PrfmsgSha512,
        .hmsg = HmsgSha512,
    };
    static const XmssHashFuncs XHashFuncsShake128 = {
        .prf = XPrfShake128,
        .tl = XTl,
        .h = XHShake128,
        .f = XFShake128,
        .prfmsg = PrfmsgShake128,
        .hmsg = HmsgShake128,
    };
    static const XmssHashFuncs XHashFuncsShake256 = {
        .prf = XPrfShake256,
        .tl = XTl,
        .h = XHShake256,
        .f = XFShake256,
        .prfmsg = PrfmsgShake256,
        .hmsg = HmsgShake256,
    };
    static const XmssHashFuncs XHashFuncsShake256_256 = {
        .prf = XPrfShake256_256,
        .tl = XTl,
        .h = XHShake256_256,
        .f = XFShake256_256,
        .prfmsg = PrfmsgShake256_256,
        .hmsg = HmsgShake256_256,
    };
    static const XmssHashFuncs XHashFuncsShake256_192 = {
        .prf = XPrfShake256_192,
        .tl = XTl,
        .h = XHShake256_192,
        .f = XFShake256_192,
        .prfmsg = PrfmsgShake256_192,
        .hmsg = HmsgShake256_192,
    };
    CRYPT_PKEY_ParaId algId = ctx->para.algId;

    switch (algId) {
        case CRYPT_XMSS_SHA2_10_256:
        case CRYPT_XMSS_SHA2_16_256:
        case CRYPT_XMSS_SHA2_20_256:
            ctx->hashFuncs = XHashFuncsSha256;
            break;
        
        case CRYPT_XMSS_SHA2_10_512:
        case CRYPT_XMSS_SHA2_16_512:
        case CRYPT_XMSS_SHA2_20_512:
            ctx->hashFuncs = XHashFuncsSha512;
            break;

        case CRYPT_XMSS_SHAKE_10_256:
        case CRYPT_XMSS_SHAKE_16_256:
        case CRYPT_XMSS_SHAKE_20_256:
            ctx->hashFuncs = XHashFuncsShake128;
            break;
        
        case CRYPT_XMSS_SHAKE_10_512:
        case CRYPT_XMSS_SHAKE_16_512:
        case CRYPT_XMSS_SHAKE_20_512:
            ctx->hashFuncs = XHashFuncsShake256;
            break;

        case CRYPT_XMSS_SHA2_10_192:
        case CRYPT_XMSS_SHA2_16_192:
        case CRYPT_XMSS_SHA2_20_192:
            ctx->hashFuncs = XHashFuncsSha256_192;
            break;

        case CRYPT_XMSS_SHAKE256_10_256:
        case CRYPT_XMSS_SHAKE256_16_256:
        case CRYPT_XMSS_SHAKE256_20_256:
            ctx->hashFuncs = XHashFuncsShake256_256;
            break;
        
        case CRYPT_XMSS_SHAKE256_10_192:
        case CRYPT_XMSS_SHAKE256_16_192:
        case CRYPT_XMSS_SHAKE256_20_192:
            ctx->hashFuncs = XHashFuncsShake256_192;
            break;

        case CRYPT_XMSSMT_SHA2_20_2_256:
        case CRYPT_XMSSMT_SHA2_20_4_256:
        case CRYPT_XMSSMT_SHA2_40_2_256:
        case CRYPT_XMSSMT_SHA2_40_4_256:
        case CRYPT_XMSSMT_SHA2_40_8_256:
        case CRYPT_XMSSMT_SHA2_60_3_256:
        case CRYPT_XMSSMT_SHA2_60_6_256:
        case CRYPT_XMSSMT_SHA2_60_12_256:
            ctx->hashFuncs = XHashFuncsSha256;
            break;

        case CRYPT_XMSSMT_SHA2_20_2_512:
        case CRYPT_XMSSMT_SHA2_20_4_512:
        case CRYPT_XMSSMT_SHA2_40_2_512:
        case CRYPT_XMSSMT_SHA2_40_4_512:
        case CRYPT_XMSSMT_SHA2_40_8_512:
        case CRYPT_XMSSMT_SHA2_60_3_512:
        case CRYPT_XMSSMT_SHA2_60_6_512:
        case CRYPT_XMSSMT_SHA2_60_12_512:
            ctx->hashFuncs = XHashFuncsSha512;
            break;

        case CRYPT_XMSSMT_SHAKE_20_2_256:
        case CRYPT_XMSSMT_SHAKE_20_4_256:
        case CRYPT_XMSSMT_SHAKE_40_2_256:
        case CRYPT_XMSSMT_SHAKE_40_4_256:
        case CRYPT_XMSSMT_SHAKE_40_8_256:
        case CRYPT_XMSSMT_SHAKE_60_3_256:
        case CRYPT_XMSSMT_SHAKE_60_6_256:
        case CRYPT_XMSSMT_SHAKE_60_12_256:
            ctx->hashFuncs = XHashFuncsShake128;
            break;

        case CRYPT_XMSSMT_SHAKE_20_2_512:
        case CRYPT_XMSSMT_SHAKE_20_4_512:
        case CRYPT_XMSSMT_SHAKE_40_2_512:
        case CRYPT_XMSSMT_SHAKE_40_4_512:
        case CRYPT_XMSSMT_SHAKE_40_8_512:
        case CRYPT_XMSSMT_SHAKE_60_3_512:
        case CRYPT_XMSSMT_SHAKE_60_6_512:
        case CRYPT_XMSSMT_SHAKE_60_12_512:
            ctx->hashFuncs = XHashFuncsShake256;
            break;

        case CRYPT_XMSSMT_SHA2_20_2_192:
        case CRYPT_XMSSMT_SHA2_20_4_192:
        case CRYPT_XMSSMT_SHA2_40_2_192:
        case CRYPT_XMSSMT_SHA2_40_4_192:
        case CRYPT_XMSSMT_SHA2_40_8_192:
        case CRYPT_XMSSMT_SHA2_60_3_192:
        case CRYPT_XMSSMT_SHA2_60_6_192:
        case CRYPT_XMSSMT_SHA2_60_12_192:
            ctx->hashFuncs = XHashFuncsSha256_192;
            break;

        case CRYPT_XMSSMT_SHAKE256_20_2_256:
        case CRYPT_XMSSMT_SHAKE256_20_4_256:
        case CRYPT_XMSSMT_SHAKE256_40_2_256:
        case CRYPT_XMSSMT_SHAKE256_40_4_256:
        case CRYPT_XMSSMT_SHAKE256_40_8_256:
        case CRYPT_XMSSMT_SHAKE256_60_3_256:
        case CRYPT_XMSSMT_SHAKE256_60_6_256:
        case CRYPT_XMSSMT_SHAKE256_60_12_256:
            ctx->hashFuncs = XHashFuncsShake256_256;
            break;
        
        case CRYPT_XMSSMT_SHAKE256_20_2_192:
        case CRYPT_XMSSMT_SHAKE256_20_4_192:
        case CRYPT_XMSSMT_SHAKE256_40_2_192:
        case CRYPT_XMSSMT_SHAKE256_40_4_192:
        case CRYPT_XMSSMT_SHAKE256_40_8_192:
        case CRYPT_XMSSMT_SHAKE256_60_3_192:
        case CRYPT_XMSSMT_SHAKE256_60_6_192:
        case CRYPT_XMSSMT_SHAKE256_60_12_192:
            ctx->hashFuncs = XHashFuncsShake256_192;
            break;

        default:
            return CRYPT_XMSS_ERR_INVALID_ALGID;
    }
    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_XMSS

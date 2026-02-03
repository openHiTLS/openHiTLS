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

#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_algid.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
#include "eal_md_local.h"
#include "slh_dsa_local.h"
#include "slh_dsa_hash.h"
#include "xmss_common.h"

#define SHA256_PADDING_LEN 64
#define SHA512_PADDING_LEN 128

static int32_t PrfmsgShake256(const void *vctx, const uint8_t *rand, const uint8_t *msg, uint32_t msgLen,
                              uint8_t *out)
{
    const CryptSlhDsaCtx *ctx = (const CryptSlhDsaCtx *)vctx;
    uint32_t n = ctx->para.n;
    const CRYPT_ConstData hashData[] = {{ctx->prvKey.prf, n}, {rand, n}, {msg, msgLen}};
    return CalcMultiMsgHash(CRYPT_MD_SHAKE256, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);
}

static int32_t HmsgShake256(const void *vctx, const uint8_t *r, const uint8_t *msg, uint32_t msgLen,
                            const uint8_t *idx, uint8_t *out)
{
    (void)idx;
    const CryptSlhDsaCtx *ctx = (const CryptSlhDsaCtx *)vctx;
    uint32_t n = ctx->para.n;
    uint32_t m = ctx->para.m;
    const CRYPT_ConstData hashData[] = {{r, n}, {ctx->prvKey.pub.seed, n}, {ctx->prvKey.pub.root, n}, {msg, msgLen}};
    return CalcMultiMsgHash(CRYPT_MD_SHAKE256, hashData, sizeof(hashData) / sizeof(hashData[0]), out, m);
}

static int32_t PrfShake256(const void *vctx, const void *vadrs, uint8_t *out)
{
    const CryptSlhDsaCtx *ctx = (const CryptSlhDsaCtx *)vctx;
    const SlhDsaAdrs *adrs = (const SlhDsaAdrs *)vadrs;
    uint32_t n = ctx->para.n;
    const CRYPT_ConstData hashData[] = {
        {ctx->prvKey.pub.seed, n}, {adrs->bytes, ctx->adrsOps.getAdrsLen()}, {ctx->prvKey.seed, n}};
    return CalcMultiMsgHash(CRYPT_MD_SHAKE256, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);
}

static int32_t HShake256(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen,
                         uint8_t *out)
{
    const CryptSlhDsaCtx *ctx = (const CryptSlhDsaCtx *)vctx;
    const SlhDsaAdrs *adrs = (const SlhDsaAdrs *)vadrs;
    uint32_t n = ctx->para.n;
    const CRYPT_ConstData hashData[] = {
        {ctx->prvKey.pub.seed, n}, {adrs->bytes, ctx->adrsOps.getAdrsLen()}, {msg, msgLen}};
    return CalcMultiMsgHash(CRYPT_MD_SHAKE256, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);
}

static int32_t TlShake256(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen,
                          uint8_t *out)
{
    return HShake256(vctx, vadrs, msg, msgLen, out);
}

static int32_t FShake256(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen,
                         uint8_t *out)
{
    return HShake256(vctx, vadrs, msg, msgLen, out);
}

static int32_t Prfmsg(const CryptSlhDsaCtx *ctx, const uint8_t *rand, const uint8_t *msg, uint32_t msgLen, uint8_t *out,
                      CRYPT_MAC_AlgId macId)
{
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint8_t tmp[MAX_MDSIZE] = {0};
    uint32_t tmpLen = sizeof(tmp);
    CRYPT_EAL_MacCtx *mdCtx = CRYPT_EAL_MacNewCtx(macId);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF_EX(CRYPT_EAL_MacInit(mdCtx, ctx->prvKey.prf, n), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MacUpdate(mdCtx, rand, n), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MacUpdate(mdCtx, msg, msgLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MacFinal(mdCtx, tmp, &tmpLen), ret);
    (void)memcpy_s(out, n, tmp, n);
ERR:
    CRYPT_EAL_MacFreeCtx(mdCtx);
    return ret;
}

static int32_t PrfmsgSha256(const void *vctx, const uint8_t *rand, const uint8_t *msg, uint32_t msgLen,
                            uint8_t *out)
{
    return Prfmsg((const CryptSlhDsaCtx *)vctx, rand, msg, msgLen, out, CRYPT_MAC_HMAC_SHA256);
}

static int32_t PrfmsgSha512(const void *vctx, const uint8_t *rand, const uint8_t *msg, uint32_t msgLen,
                            uint8_t *out)
{
    return Prfmsg((const CryptSlhDsaCtx *)vctx, rand, msg, msgLen, out, CRYPT_MAC_HMAC_SHA512);
}

static int32_t HmsgSha(const CryptSlhDsaCtx *ctx, const uint8_t *r, const uint8_t *seed, const uint8_t *root,
                       const uint8_t *msg, uint32_t msgLen, uint8_t *out, CRYPT_MD_AlgId mdId)
{
    int32_t ret;
    uint32_t m = ctx->para.m;
    uint32_t n = ctx->para.n;
    uint32_t tmpLen;

    uint8_t tmpSeed[2 * SLH_DSA_MAX_N + MAX_MDSIZE] = {0}; // 2 is for double
    uint32_t tmpSeedLen = 0;
    (void)memcpy_s(tmpSeed, sizeof(tmpSeed), r, n);
    (void)memcpy_s(tmpSeed + n, sizeof(tmpSeed) - n, seed, n);
    tmpSeedLen = n + n;
    tmpLen = CRYPT_EAL_MdGetDigestSize(mdId);

    const CRYPT_ConstData hashData[] = {{tmpSeed, tmpSeedLen}, {root, n}, {msg, msgLen}};
    ret = CalcMultiMsgHash(mdId, hashData, sizeof(hashData) / sizeof(hashData[0]), tmpSeed + tmpSeedLen, tmpLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    tmpSeedLen += tmpLen;
    return CRYPT_Mgf1(NULL, EAL_MdFindDefaultMethod(mdId), tmpSeed, tmpSeedLen, out, m);
}

static int32_t HmsgSha256(const void *vctx, const uint8_t *r, const uint8_t *msg, uint32_t msgLen,
                          const uint8_t *idx, uint8_t *out)
{
    const CryptSlhDsaCtx *ctx = (const CryptSlhDsaCtx *)vctx;
    (void)idx;
    return HmsgSha(ctx, r, ctx->prvKey.pub.seed, ctx->prvKey.pub.root, msg, msgLen, out, CRYPT_MD_SHA256);
}

static int32_t HmsgSha512(const void *vctx, const uint8_t *r, const uint8_t *msg, uint32_t msgLen,
                          const uint8_t *idx, uint8_t *out)
{
    const CryptSlhDsaCtx *ctx = (const CryptSlhDsaCtx *)vctx;
    (void)idx;
    return HmsgSha(ctx, r, ctx->prvKey.pub.seed, ctx->prvKey.pub.root, msg, msgLen, out, CRYPT_MD_SHA512);
}

static int32_t PrfSha256(const void *vctx, const void *vadrs, uint8_t *out)
{
    const CryptSlhDsaCtx *ctx = (const CryptSlhDsaCtx *)vctx;
    const SlhDsaAdrs *adrs = (const SlhDsaAdrs *)vadrs;
    uint32_t n = ctx->para.n;
    uint8_t padding[SHA256_PADDING_LEN] = {0};
    const CRYPT_ConstData hashData[] = {{ctx->prvKey.pub.seed, n},
                                        {padding, sizeof(padding) - n},
                                        {adrs->bytes, ctx->adrsOps.getAdrsLen()},
                                        {ctx->prvKey.seed, n}};
    return CalcMultiMsgHash(CRYPT_MD_SHA256, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);
}

static int32_t HSha256(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen,
                       uint8_t *out)
{
    const CryptSlhDsaCtx *ctx = (const CryptSlhDsaCtx *)vctx;
    const SlhDsaAdrs *adrs = (const SlhDsaAdrs *)vadrs;
    uint32_t n = ctx->para.n;
    uint8_t padding[SHA256_PADDING_LEN] = {0};
    const CRYPT_ConstData hashData[] = {{ctx->prvKey.pub.seed, n},
                                        {padding, sizeof(padding) - n},
                                        {adrs->bytes, ctx->adrsOps.getAdrsLen()},
                                        {msg, msgLen}};
    return CalcMultiMsgHash(CRYPT_MD_SHA256, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);
}

static int32_t FSha256(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen,
                       uint8_t *out)
{
    return HSha256(vctx, vadrs, msg, msgLen, out);
}

static int32_t TlSha256(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen,
                        uint8_t *out)
{
    return HSha256(vctx, vadrs, msg, msgLen, out);
}

static int32_t HSha512(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen,
                       uint8_t *out)
{
    const CryptSlhDsaCtx *ctx = (const CryptSlhDsaCtx *)vctx;
    const SlhDsaAdrs *adrs = (const SlhDsaAdrs *)vadrs;
    uint32_t n = ctx->para.n;
    uint8_t padding[SHA512_PADDING_LEN] = {0};
    const CRYPT_ConstData hashData[] = {{ctx->prvKey.pub.seed, n},
                                        {padding, sizeof(padding) - n},
                                        {adrs->bytes, ctx->adrsOps.getAdrsLen()},
                                        {msg, msgLen}};
    return CalcMultiMsgHash(CRYPT_MD_SHA512, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);
}

static int32_t TlSha512(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen,
                        uint8_t *out)
{
    return HSha512(vctx, vadrs, msg, msgLen, out);
}

/* Static hash function tables for SLH-DSA */
static const CryptHashFuncs g_slhDsaSha256Funcs = {
    .prf = PrfSha256,
    .f = FSha256,
    .h = HSha256,
    .tl = TlSha256,
    .hmsg = HmsgSha256,
    .prfmsg = PrfmsgSha256,
};

static const CryptHashFuncs g_slhDsaSha512Funcs = {
    .prf = PrfSha256,
    .f = FSha256,
    .h = HSha512,
    .tl = TlSha512,
    .hmsg = HmsgSha512,
    .prfmsg = PrfmsgSha512,
};

static const CryptHashFuncs g_slhDsaShake256Funcs = {
    .prf = PrfShake256,
    .f = FShake256,
    .h = HShake256,
    .tl = TlShake256,
    .hmsg = HmsgShake256,
    .prfmsg = PrfmsgShake256,
};

void SlhDsaInitHashFuncs(CryptSlhDsaCtx *ctx)
{
    CRYPT_PKEY_ParaId algId = ctx->para.algId;

    if (algId == CRYPT_SLH_DSA_SHA2_128S || algId == CRYPT_SLH_DSA_SHA2_128F || algId == CRYPT_SLH_DSA_SHA2_192S ||
        algId == CRYPT_SLH_DSA_SHA2_192F || algId == CRYPT_SLH_DSA_SHA2_256S || algId == CRYPT_SLH_DSA_SHA2_256F) {
        ctx->para.isCompressed = true;
        if (ctx->para.secCategory == 1) {
            ctx->hashFuncs = &g_slhDsaSha256Funcs;
        } else {
            ctx->hashFuncs = &g_slhDsaSha512Funcs;
        }
    } else {
        ctx->para.isCompressed = false;
        ctx->hashFuncs = &g_slhDsaShake256Funcs;
    }
}

#endif // HITLS_CRYPTO_SLH_DSA

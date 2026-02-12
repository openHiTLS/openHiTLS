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

#include <string.h>
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
#include "crypt_sha2.h"
#include "crypt_sha3.h"
#include "sha2_core.h"
#include "sha3_core.h"
#include "xmss_wots.h"


#define SHA256_PADDING_LEN 64
#define SHA512_PADDING_LEN 128

static int32_t CalcHashByCtx(void *mdCtxIn, const EAL_MdMethod *hashMethod, const CRYPT_ConstData *hashData,
                             uint32_t size, uint8_t *out, uint32_t *outlen)
{
    void *mdCtx = hashMethod->dupCtx(mdCtxIn);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret;
    for (uint32_t i = 0; i < size; i++) {
        ret = hashMethod->update(mdCtx, hashData[i].data, hashData[i].len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
    }
    ret = hashMethod->final(mdCtx, out, outlen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

static int32_t CalcMultiMsgHashByCtx(CRYPT_MD_AlgId mdId, void *mdCtxIn, const CRYPT_ConstData *hashData,
                                     uint32_t hashDataLen, uint8_t *out, uint32_t outLen)
{
    uint8_t tmp[XMSS_MAX_MDSIZE];
    uint32_t tmpLen = sizeof(tmp);
    int32_t ret = CalcHashByCtx(mdCtxIn, EAL_MdFindDefaultMethod(mdId), hashData, hashDataLen, tmp, &tmpLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memcpy(out, tmp, outLen);
    return CRYPT_SUCCESS;
}

static int32_t CreateMdCtxAndUpdata(void **out, const EAL_MdMethod *hashMethod, const CRYPT_ConstData *hashData,
                                    uint32_t size)
{
    void *mdCtx = hashMethod->newCtx(NULL, hashMethod->id);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = hashMethod->init(mdCtx, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        hashMethod->freeCtx(mdCtx);
        return ret;
    }
    for (uint32_t i = 0; i < size; i++) {
        ret = hashMethod->update(mdCtx, hashData[i].data, hashData[i].len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            hashMethod->freeCtx(mdCtx);
            return ret;
        }
    }
    *out = mdCtx;
    return ret;
}

int32_t InitMdCtx(CryptSlhDsaCtx *ctx)
{
    FreeMdCtx(ctx);

    if (!ctx->para.isCompressed) {
        return CRYPT_SUCCESS;
    }
    
    uint32_t n = ctx->para.n;
    uint8_t padding[SHA512_PADDING_LEN] = {0};
    const CRYPT_ConstData hashData256[] = {{ctx->prvKey.pub.seed, n}, {padding, SHA256_PADDING_LEN - n}};
    const EAL_MdMethod *hashMethod256 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
    int ret = CreateMdCtxAndUpdata(&ctx->sha256MdCtx, hashMethod256, hashData256,
                                   sizeof(hashData256) / sizeof(hashData256[0]));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    const CRYPT_ConstData hashData512[] = {{ctx->prvKey.pub.seed, n}, {padding, SHA512_PADDING_LEN - n}};
    const EAL_MdMethod *hashMethod512 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA512);
    ret = CreateMdCtxAndUpdata(&ctx->sha512MdCtx, hashMethod512, hashData512,
                               sizeof(hashData512) / sizeof(hashData512[0]));
    if (ret != CRYPT_SUCCESS) {
        hashMethod256->freeCtx(ctx->sha256MdCtx);
        ctx->sha256MdCtx = NULL;
    }
    return ret;
}

void DupMdCtx(CryptSlhDsaCtx *dest, CryptSlhDsaCtx *src)
{
    const EAL_MdMethod *hashMethod256 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
    const EAL_MdMethod *hashMethod512 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA512);
    dest->sha256MdCtx = hashMethod256->dupCtx(src->sha256MdCtx);
    if (dest->sha256MdCtx == NULL) {
        return;
    }
    dest->sha512MdCtx = hashMethod512->dupCtx(src->sha512MdCtx);
    if (dest->sha512MdCtx == NULL) {
        hashMethod256->freeCtx(dest->sha256MdCtx);
        dest->sha256MdCtx = NULL;
    }
}

void FreeMdCtx(CryptSlhDsaCtx *ctx)
{
    if (ctx->para.isCompressed) {
        const EAL_MdMethod *hashMethod256 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
        const EAL_MdMethod *hashMethod512 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA512);
        if (ctx->sha256MdCtx != NULL) {
            hashMethod256->freeCtx(ctx->sha256MdCtx);
            ctx->sha256MdCtx = NULL;
        }
        if (ctx->sha512MdCtx != NULL) {
            hashMethod512->freeCtx(ctx->sha512MdCtx);
            ctx->sha512MdCtx = NULL;
        }
    }
}

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
    memcpy(out, tmp, n);
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
    memcpy(tmpSeed, r, n);
    memcpy(tmpSeed + n, seed, n);
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
    const CRYPT_ConstData hashData[] = {{adrs->bytes, ctx->adrsOps.getAdrsLen()},
                                        {ctx->prvKey.seed, n}};
    return CalcMultiMsgHashByCtx(CRYPT_MD_SHA256, ctx->sha256MdCtx, hashData,
                                 sizeof(hashData) / sizeof(hashData[0]), out, n);
}

static int32_t HSha256(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen,
                       uint8_t *out)
{
    const CryptSlhDsaCtx *ctx = (const CryptSlhDsaCtx *)vctx;
    const SlhDsaAdrs *adrs = (const SlhDsaAdrs *)vadrs;
    uint32_t n = ctx->para.n;
    const CRYPT_ConstData hashData[] = {{adrs->bytes, ctx->adrsOps.getAdrsLen()},
                                        {msg, msgLen}};
    return CalcMultiMsgHashByCtx(CRYPT_MD_SHA256, ctx->sha256MdCtx, hashData,
                                 sizeof(hashData) / sizeof(hashData[0]), out, n);
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
    const CRYPT_ConstData hashData[] = {{adrs->bytes, ctx->adrsOps.getAdrsLen()},
                                        {msg, msgLen}};
    return CalcMultiMsgHashByCtx(CRYPT_MD_SHA512, ctx->sha512MdCtx, hashData,
                                 sizeof(hashData) / sizeof(hashData[0]), out, n);
}

static int32_t TlSha512(const void *vctx, const void *vadrs, const uint8_t *msg, uint32_t msgLen,
                        uint8_t *out)
{
    return HSha512(vctx, vadrs, msg, msgLen, out);
}

static void Sha256FinalPad(CRYPT_SHA2_256_Ctx *ctx)
{
    uint8_t *p = (uint8_t *)ctx->block;
    uint32_t n = ctx->blocklen;

    p[n++] = 0x80;
    if (n > (CRYPT_SHA2_256_BLOCKSIZE - 8)) { /* 8 bytes to save bits of input */
        memset(p + n, 0, CRYPT_SHA2_256_BLOCKSIZE - n);
        n = 0;
        SHA256CompressMultiBlocks(ctx->h, p, 1);
    }
    memset(p + n, 0, CRYPT_SHA2_256_BLOCKSIZE - 8 - n); /* 8 bytes to save bits of input */

    p += CRYPT_SHA2_256_BLOCKSIZE - 8; /* 8 bytes to save bits of input */
    PUT_UINT32_BE(ctx->hNum, p, 0);
    p += sizeof(uint32_t);
    PUT_UINT32_BE(ctx->lNum, p, 0);
}

static int32_t ChainSha256(const uint8_t *x, uint32_t xLen, uint32_t start, uint32_t steps, const uint8_t *pubSeed,
                           void *adrs, const void *ctx, uint8_t *output)
{
    (void)pubSeed; // Parameter kept for API compatibility
    if (steps == 0) {
        (void)memcpy(output, x, xLen);
        return CRYPT_SUCCESS;
    }
    const XmssWotsCtx *xmssWotsCtx = (const XmssWotsCtx *)ctx;
    int32_t ret;
    const CryptSlhDsaCtx *slhDsaCtx = (const CryptSlhDsaCtx *)xmssWotsCtx->coreCtx;
    CRYPT_SHA2_256_Ctx *sha256Ctx = CRYPT_SHA2_256_DupCtx(slhDsaCtx->sha256MdCtx);
    CRYPT_SHA2_256_Ctx *sha256CtxIn = (CRYPT_SHA2_256_Ctx *)slhDsaCtx->sha256MdCtx;
    if (sha256Ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t adrsLen = slhDsaCtx->adrsOps.getAdrsLen();
    SlhDsaAdrs *adrsCtx = (SlhDsaAdrs *)adrs;
    slhDsaCtx->adrsOps.setHashAddr(adrsCtx, start);
    uint32_t n = slhDsaCtx->para.n;
    // do first hash
    ret = CRYPT_SHA2_256_Update(sha256Ctx, adrsCtx->bytes, adrsLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = CRYPT_SHA2_256_Update(sha256Ctx, x, xLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    if (steps == 1) {
        uint8_t tmp[CRYPT_SHA2_256_DIGESTSIZE];
        uint32_t tmpLen = CRYPT_SHA2_256_DIGESTSIZE;
        ret = CRYPT_SHA2_256_Final(sha256Ctx, tmp, &tmpLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        (void)memcpy(output, tmp, n);
        goto EXIT;
    }
    // block: |---ADRS---|--MSG--|0X80|-----|hNum|lNum|
    Sha256FinalPad(sha256Ctx);
    SHA256CompressMultiBlocks(sha256Ctx->h, (uint8_t *)sha256Ctx->block, 1);
    uint32_t num = n / sizeof(uint32_t);
    for (uint32_t i = 1; i < steps; ++i) {
        for (uint32_t j = 0; j < num; ++j) {
            PUT_UINT32_BE(sha256Ctx->h[j], (uint8_t *)sha256Ctx->block + adrsLen, sizeof(uint32_t) * j);
        }
        // 18 = layerAddrLen + treeAddrLen + typeLen + hashAddressOffset = 1 + 8 + 1 + 8
        PUT_UINT32_BE(start + i, (uint8_t *)sha256Ctx->block, 18); // offset 18
        (void)memcpy(sha256Ctx->h, sha256CtxIn->h, sizeof(sha256Ctx->h));
        SHA256CompressMultiBlocks(sha256Ctx->h, (uint8_t *)sha256Ctx->block, 1);
    }
    for (uint32_t j = 0; j < num; ++j) {
        PUT_UINT32_BE(sha256Ctx->h[j], output, sizeof(uint32_t) * j);
    }
EXIT:
    CRYPT_SHA2_256_FreeCtx(sha256Ctx);
    return ret;
}

static int32_t ChainShake256(const uint8_t *x, uint32_t xLen, uint32_t start, uint32_t steps, const uint8_t *pubSeed,
                             void *adrs, const void *ctx, uint8_t *output)
{
    (void)pubSeed; // Parameter kept for API compatibility
    if (steps == 0) {
        (void)memcpy(output, x, xLen);
        return CRYPT_SUCCESS;
    }
    const XmssWotsCtx *xmssWotsCtx = (const XmssWotsCtx *)ctx;
    const CryptSlhDsaCtx *slhDsaCtx = (const CryptSlhDsaCtx *)xmssWotsCtx->coreCtx;
    SlhDsaAdrs *adrsCtx = (SlhDsaAdrs *)adrs;
    uint32_t n = slhDsaCtx->para.n;
    uint32_t nQwords = n >> 3; // pkSeed u64 num
    uint32_t msgOffset = nQwords + 4; // 4 = ((adrsLen = 32) >> 3)
    uint32_t padOffset = msgOffset + nQwords;
    uint32_t byteNum = padOffset << 3;
    uint32_t i;
    uint32_t j;
    // state: |---pkseed--|--adrs--|--msg--|0x1f|-----|
    // n + 32 + n <= 96 < CRYPT_SHAKE256_BLOCKSIZE = 136
    uint8_t state[200] = {0}; // State array, 200bytes is 1600bits
    uint64_t *pSt = (uint64_t *)(uintptr_t)state;
    for (j = 0; j < nQwords; ++j) {
        pSt[msgOffset + j] = GET_UINT64_LE(x, j << 3);
    }
    
    for (i = 0; i < steps; ++i) {
        if (i > 0) {
            (void)memcpy(pSt + msgOffset, pSt, n);
        }

        slhDsaCtx->adrsOps.setHashAddr(adrsCtx, start + i);

        for (j = 0; j < nQwords; ++j) {
            pSt[j] = GET_UINT64_LE(pubSeed, j << 3);
        }

        for (j = 0; j < 4; ++j) { // 4 = ((adrsLen = 32) >> 3)
            pSt[nQwords + j] = GET_UINT64_LE(adrsCtx->bytes, j << 3);
        }
        
        for (j = padOffset; j < 25; ++j) { // 25 = 200 / 8
            pSt[j] = 0;
        }

        state[byteNum] = 0x1f; // char for padding, sha3_* use 0x06 and shake_* use 0x1f
        state[CRYPT_SHAKE256_BLOCKSIZE - 1] = 0x80; // 0x80 is the last 1 of pad 10*1 mode
        SHA3_Keccak(state);
    }
    for (j = 0; j < nQwords; ++j) {
        PUT_UINT64_LE(pSt[j], output, j << 3);
    }
    return CRYPT_SUCCESS;
}

/* Static hash function tables for SLH-DSA */
static const CryptHashFuncs g_slhDsaSha256Funcs = {
    .prf = PrfSha256,
    .f = FSha256,
    .h = HSha256,
    .tl = TlSha256,
    .hmsg = HmsgSha256,
    .prfmsg = PrfmsgSha256,
    .chain = ChainSha256,
};

static const CryptHashFuncs g_slhDsaSha512Funcs = {
    .prf = PrfSha256,
    .f = FSha256,
    .h = HSha512,
    .tl = TlSha512,
    .hmsg = HmsgSha512,
    .prfmsg = PrfmsgSha512,
    .chain = ChainSha256,
};

static const CryptHashFuncs g_slhDsaShake256Funcs = {
    .prf = PrfShake256,
    .f = FShake256,
    .h = HShake256,
    .tl = TlShake256,
    .hmsg = HmsgShake256,
    .prfmsg = PrfmsgShake256,
    .chain = ChainShake256,
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

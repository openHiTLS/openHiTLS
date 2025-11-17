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
#include <string.h>
#include "securec.h"
#include "bsl_errno.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "slh_dsa_local.h"
#include "slh_dsa_wots.h"

static int32_t MsgToBaseW(const CryptSlhDsaCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint32_t *out)
{
    uint32_t n = ctx->para.n;
    uint32_t len1 = 2 * n;
    uint32_t len2 = 3;

    BaseB(msg, msgLen, SLH_DSA_LGW, out, len1);

    uint64_t csum = 0;
    for (uint32_t i = 0; i < len1; i++) {
        csum += SLH_DSA_W - 1 - out[i];
    }
    csum <<= SLH_DSA_LGW;
    uint8_t csumBytes[2];
    csumBytes[0] = (uint8_t)(csum >> 8);
    csumBytes[1] = (uint8_t)csum;

    BaseB(csumBytes, 2, SLH_DSA_LGW, out + len1, len2);
    return 0;
}

int32_t WotsChain(const uint8_t *x, uint32_t xLen, uint32_t start, uint32_t end, const uint8_t *seed, SlhDsaAdrs *adrs,
                  const CryptSlhDsaCtx *ctx, uint8_t *output)
{
    (void)seed;
    int32_t ret;
    uint8_t tmp[SLH_DSA_MAX_N];
    (void)memcpy_s(tmp, sizeof(tmp), x, xLen);
    uint32_t tmpLen = xLen;

    for (uint32_t i = start; i < start + end; i++) {
        ctx->adrsOps.setHashAddr(adrs, i);
        ret = ctx->hashFuncs.f(ctx, adrs, tmp, tmpLen, tmp);
        if (ret != 0) {
            return ret;
        }
    }

    (void)memcpy_s(output, tmpLen, tmp, tmpLen);
    return 0;
}

int WotsGeneratePublicKey(uint8_t *pub, SlhDsaAdrs *adrs, const CryptSlhDsaCtx *ctx)
{
    int32_t ret;

    uint32_t n = ctx->para.n;
    uint32_t len = 2 * n + 3;
    SlhDsaAdrs skAdrs = *adrs;
    ctx->adrsOps.setType(&skAdrs, WOTS_PRF);
    ctx->adrsOps.copyKeyPairAddr(&skAdrs, adrs);

    uint8_t *tmp = (uint8_t *)BSL_SAL_Malloc(len * n);
    if (tmp == NULL) {
        return BSL_MALLOC_FAIL;
    }

    for (uint32_t i = 0; i < len; i++) {
        ctx->adrsOps.setChainAddr(&skAdrs, i);
        uint8_t sk[SLH_DSA_MAX_N] = {0};
        ret = ctx->hashFuncs.prf(ctx, &skAdrs, sk);
        if (ret != 0) {
            goto ERR;
        }
        ctx->adrsOps.setChainAddr(adrs, i);
        ret = WotsChain(sk, n, 0, SLH_DSA_W - 1, ctx->prvKey.pub.seed, adrs, ctx, (tmp + i * n));
        if (ret != 0) {
            goto ERR;
        }
    }

    // compress public key
    SlhDsaAdrs wotspk = *adrs;
    ctx->adrsOps.setType(&wotspk, WOTS_PK);
    ctx->adrsOps.copyKeyPairAddr(&wotspk, adrs);

    ret = ctx->hashFuncs.tl(ctx, &wotspk, tmp, len * n, pub);

ERR:
    BSL_SAL_Free(tmp);
    return ret;
}

int32_t WotsSign(uint8_t *sig, uint32_t *sigLen, const uint8_t *msg, uint32_t msgLen, SlhDsaAdrs *adrs,
                 const CryptSlhDsaCtx *ctx)
{
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint32_t len = 2 * n + 3;

    if (*sigLen < len * n) {
        return CRYPT_BN_BUFF_LEN_NOT_ENOUGH;
    }

    uint32_t *msgw = (uint32_t *)BSL_SAL_Malloc(len * sizeof(uint32_t));
    if (msgw == NULL) {
        return BSL_MALLOC_FAIL;
    }
    ret = MsgToBaseW(ctx, msg, msgLen, msgw);
    if (ret != 0) {
        goto ERR;
    }

    SlhDsaAdrs skAdrs = *adrs;
    ctx->adrsOps.setType(&skAdrs, WOTS_PRF);
    ctx->adrsOps.copyKeyPairAddr(&skAdrs, adrs);
    for (uint32_t i = 0; i < len; i++) {
        ctx->adrsOps.setChainAddr(&skAdrs, i);
        uint8_t sk[SLH_DSA_MAX_N] = {0};
        ret = ctx->hashFuncs.prf(ctx, &skAdrs, sk);
        if (ret != 0) {
            goto ERR;
        }
        ctx->adrsOps.setChainAddr(adrs, i);
        ret = WotsChain(sk, n, 0, msgw[i], ctx->prvKey.pub.seed, adrs, ctx, sig + i * n);
        BSL_SAL_CleanseData(sk, SLH_DSA_MAX_N);
        if (ret != 0) {
            goto ERR;
        }
    }
ERR:
    BSL_SAL_Free(msgw);
    *sigLen = len * n;
    return ret;
}

int32_t WotsPubKeyFromSig(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, SlhDsaAdrs *adrs,
                      const CryptSlhDsaCtx *ctx, uint8_t *pub)
{
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint32_t len = 2 * n + 3;
    uint32_t *msgw = NULL;
    uint8_t *tmp = NULL;

    if (sigLen < len * n) {
        return CRYPT_SLHDSA_ERR_SIG_LEN_NOT_ENOUGH;
    }

    msgw = (uint32_t *)BSL_SAL_Malloc(len * sizeof(uint32_t));
    if (msgw == NULL) {
        return BSL_MALLOC_FAIL;
    }
    ret = MsgToBaseW(ctx, msg, msgLen, msgw);
    if (ret != 0) {
        goto ERR;
    }
    tmp = (uint8_t *)BSL_SAL_Malloc(len * n);
    if (tmp == NULL) {
        ret = BSL_MALLOC_FAIL;
        goto ERR;
    }

    for (uint32_t i = 0; i < len; i++) {
        ctx->adrsOps.setChainAddr(adrs, i);
        ret = WotsChain(sig + i * n, n, msgw[i], SLH_DSA_W - 1 - msgw[i], ctx->prvKey.pub.seed, adrs, ctx, tmp + i * n);
        if (ret != 0) {
            goto ERR;
        }
    }
    SlhDsaAdrs wotspk = *adrs;
    ctx->adrsOps.setType(&wotspk, WOTS_PK);
    ctx->adrsOps.copyKeyPairAddr(&wotspk, adrs);
    ret = ctx->hashFuncs.tl(ctx, &wotspk, tmp, len * n, pub);

ERR:
    BSL_SAL_Free(msgw);
    if (tmp != NULL) {
        BSL_SAL_Free(tmp);
    }
    return ret;
}

#endif // HITLS_CRYPTO_SLH_DSA

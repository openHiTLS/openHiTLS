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
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_SLH_DSA)

#include <stdint.h>
#include <string.h>
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_sal.h"
#include "hbs_wots.h"

/* WOTS+ parameter */
#define XMSS_WOTS_W 16
#define BYTE_BITS   8

/* Address type constants (aligned with xmss_address.h and slh_dsa_local.h) */
#define XMSS_ADRS_TYPE_LTREE 1

/*
 * BaseB conversion utility
 *
 * Converts byte array to base b representation.
 * b can be 4, 6, 8, 9, 12, 14 (typically 4 for W=16)
 *
 * Security note: uses uint64_t intermediate accumulator to prevent
 * overflow when shifting 'o' left by BYTE_BITS (8) bits before adding
 * the next input byte. Without the wider type, large 'b' values could
 * cause undefined behaviour on 32-bit platforms.
 */
static void BaseB(const uint8_t *x, uint32_t xLen, uint32_t b, uint32_t *out, uint32_t outLen)
{
    /* Guard: b must be in [1, 16] and outLen non-zero to be meaningful */
    if (b == 0 || b > 16 || outLen == 0) {
        return;
    }

    uint64_t o = 0; /* wider type prevents shift overflow */
    uint32_t bit = 0;
    uint32_t xi = 0;
    for (uint32_t i = 0; i < outLen; i++) {
        while (bit < b && xi < xLen) {
            o = (o << BYTE_BITS) + x[xi];
            bit += 8;
            xi++;
        }
        bit -= b;
        out[i] = (uint32_t)(o >> bit);
        /* Keep the remaining bits */
        o &= ((uint64_t)1 << bit) - 1;
    }
}

/*
 * Convert message to base-W representation
 *
 * This is a helper function that converts a message digest into
 * an array of base-W values for WOTS+ signing.
 *
 * For W=16, each value is 4 bits, so we process 2 values per byte.
 */
static void HbsWots_MsgToBaseW(const HbsWotsCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint32_t *out)
{
    uint32_t n = ctx->n;
    uint32_t len1 = 2 * n;
    uint32_t len2 = 3;

    /* Convert message bytes to base-W */
    BaseB(msg, msgLen, 4, out, len1); /* log2(16) = 4 */

    /* Compute checksum */
    uint64_t csum = 0;
    for (uint32_t i = 0; i < len1; i++) {
        csum += XMSS_WOTS_W - 1 - out[i];
    }

    csum <<= 4; /* log2(W) = 4 */

    uint8_t csumBytes[2];
    csumBytes[0] = (uint8_t)(csum >> 8);
    csumBytes[1] = (uint8_t)csum;

    /* Convert checksum to base-W */
    BaseB(csumBytes, 2, 4, out + len1, len2);
}

/* Compute the WOTS+ chaining function: iterate the hash 'steps' times starting from position 'start'. */
int32_t HbsWots_Chain(const uint8_t *x, uint32_t xLen, uint32_t start, uint32_t steps, const uint8_t *pubSeed,
                      void *adrs, const HbsWotsCtx *ctx, uint8_t *output)
{
    /* If algorithm-specific optimized chain exists (e.g. ChainSha256/ChainShake256), delegate to it */
    if (ctx->hashFuncs->chain != NULL) {
        return ctx->hashFuncs->chain(x, xLen, start, steps, pubSeed, adrs, ctx, output);
    }

    /* Generic fallback: iterate chainHash step-by-step */
    (void)pubSeed; // Parameter kept for API compatibility
    int32_t ret;
    uint8_t tmp[HBS_MAX_MDSIZE];
    memcpy(tmp, x, xLen);
    uint32_t tmpLen = xLen;

    /* Iterate the F function 'steps' times starting from 'start' */
    for (uint32_t i = start; i < start + steps; i++) {
        ctx->adrsOps->setHashAddr(adrs, i);

        /* Call F function through hash function table */
        ret = ctx->hashFuncs->chainHash((const void *)ctx->coreCtx, adrs, tmp, tmpLen, tmp);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    memcpy(output, tmp, tmpLen);
    return CRYPT_SUCCESS;
}

/* Generate the WOTS+ public key by chaining each private key element to the end and compressing. */
int32_t HbsWots_GeneratePublicKey(uint8_t *pub, void *adrs, const HbsWotsCtx *ctx)
{
    int32_t ret;
    uint32_t n = ctx->n;
    uint32_t len = ctx->otsLen;

    /* Allocate temporary buffer for chaining results */
    uint8_t *tmp = (uint8_t *)BSL_SAL_Malloc(len * n);
    if (tmp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    uint8_t skAdrsBuffer[HBS_MAX_ADRS_SIZE] = {0};
    void *skAdrs = skAdrsBuffer;
    memcpy(skAdrs, adrs, sizeof(skAdrsBuffer));
    if (ctx->algoType != HBS_ALGO_XMSS) {
        ctx->adrsOps->setType(skAdrs, 5); // 5: WOTS_PRF
        ctx->adrsOps->copyKeyPairAddr(skAdrs, adrs);
    }

    for (uint32_t i = 0; i < len; i++) {
        ctx->adrsOps->setChainAddr(skAdrs, i);
        /* Generate private key element using PRF */
        uint8_t sk[HBS_MAX_MDSIZE] = {0};
        ret = ctx->hashFuncs->skDerive((const void *)ctx->coreCtx, skAdrs, sk);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_CleanseData(sk, HBS_MAX_MDSIZE);
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        ctx->adrsOps->setChainAddr(adrs, i);
        /* Chain the private key to get public key element */
        ret = HbsWots_Chain(sk, n, 0, XMSS_WOTS_W - 1, ctx->pubSeed, adrs, ctx, tmp + i * n);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_CleanseData(sk, HBS_MAX_MDSIZE);
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }

        /* Clear sensitive data */
        BSL_SAL_CleanseData(sk, HBS_MAX_MDSIZE);
    }

    /* Compress WOTS+ public key using tl */
    uint8_t wotspkBuffer[HBS_MAX_ADRS_SIZE] = {0};
    void *wotspk = wotspkBuffer;
    memcpy(wotspk, adrs, sizeof(wotspkBuffer));
    ctx->adrsOps->setType(wotspk, XMSS_ADRS_TYPE_LTREE); // slhdsa case is WOTS_PK, which is also 1
    ctx->adrsOps->copyKeyPairAddr(wotspk, adrs);

    ret = ctx->hashFuncs->pkCompress(ctx->coreCtx, wotspk, tmp, len * n, pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

ERR:
    BSL_SAL_Free(tmp);
    return ret;
}

/* Produce a WOTS+ signature over msg by chaining each private key element according to the message digits. */
int32_t HbsWots_Sign(uint8_t *sig, uint32_t *sigLen, const uint8_t *msg, uint32_t msgLen, void *adrs,
                     const HbsWotsCtx *ctx)
{
    int32_t ret = CRYPT_SUCCESS;
    uint32_t n = ctx->n;
    uint32_t len = ctx->otsLen;

    if (*sigLen < len * n) {
        int32_t err =
            ctx->algoType == HBS_ALGO_XMSS ? CRYPT_XMSS_ERR_INVALID_SIG_LEN : CRYPT_SLHDSA_ERR_INVALID_SIG_LEN;
        BSL_ERR_PUSH_ERROR(err);
        return err;
    }

    /* Convert message to base-W representation */
    uint32_t *msgw = (uint32_t *)BSL_SAL_Malloc(len * sizeof(uint32_t));
    if (msgw == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    HbsWots_MsgToBaseW(ctx, msg, msgLen, msgw);

    uint32_t adrsLen3 = ctx->adrsOps->getAdrsLen();
    uint8_t skAdrsBuffer[HBS_MAX_ADRS_SIZE] = {0};
    void *skAdrs = skAdrsBuffer;
    memcpy(skAdrs, adrs, adrsLen3);
    if (ctx->algoType != HBS_ALGO_XMSS) {
        ctx->adrsOps->setType(skAdrs, 5); // 5: WOTS_PRF
        ctx->adrsOps->copyKeyPairAddr(skAdrs, adrs);
    }

    for (uint32_t i = 0; i < len; i++) {
        /* Set chain address */
        ctx->adrsOps->setChainAddr(skAdrs, i);
        /* Generate private key element */
        uint8_t sk[HBS_MAX_MDSIZE] = {0};
        ret = ctx->hashFuncs->skDerive(ctx->coreCtx, skAdrs, sk);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_CleanseData(sk, HBS_MAX_MDSIZE);
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        ctx->adrsOps->setChainAddr(adrs, i);
        /* Chain private key element msgw[i] steps */
        ret = HbsWots_Chain(sk, n, 0, msgw[i], ctx->pubSeed, adrs, ctx, sig + i * n);
        BSL_SAL_CleanseData(sk, HBS_MAX_MDSIZE);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
    }

ERR:
    BSL_SAL_Free(msgw);
    *sigLen = len * n;
    return ret;
}

/* Reconstruct the WOTS+ public key from a signature by completing the remaining chain steps. */
int32_t HbsWots_PkFromSig(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, void *adrs,
                          const HbsWotsCtx *ctx, uint8_t *pub)
{
    int32_t ret;
    uint32_t n = ctx->n;
    uint32_t len = ctx->otsLen;
    uint32_t *msgw = NULL;
    uint8_t *tmp = NULL;

    if (sigLen < len * n) {
        int32_t err =
            ctx->algoType == HBS_ALGO_XMSS ? CRYPT_XMSS_ERR_INVALID_SIG_LEN : CRYPT_SLHDSA_ERR_INVALID_SIG_LEN;
        BSL_ERR_PUSH_ERROR(err);
        return err;
    }

    /* Convert message to base-W representation */
    msgw = (uint32_t *)BSL_SAL_Malloc(len * sizeof(uint32_t));
    if (msgw == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    HbsWots_MsgToBaseW(ctx, msg, msgLen, msgw);

    /* Allocate buffer for reconstructed public key elements */
    tmp = (uint8_t *)BSL_SAL_Malloc(len * n);
    if (tmp == NULL) {
        ret = BSL_MALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    for (uint32_t i = 0; i < len; i++) {
        /* Set chain address directly on adrs */
        ctx->adrsOps->setChainAddr(adrs, i);

        /* Complete the chain: chain from msgw[i] for (W-1-msgw[i]) steps */
        ret = HbsWots_Chain(sig + i * n, n, msgw[i], XMSS_WOTS_W - 1 - msgw[i], ctx->pubSeed, adrs, ctx, tmp + i * n);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
    }

    /* Compress reconstructed WOTS+ public key */
    uint8_t wotspkBuffer[HBS_MAX_ADRS_SIZE] = {0};
    void *wotspk = wotspkBuffer;
    memcpy(wotspk, adrs, sizeof(wotspkBuffer));
    ctx->adrsOps->setType(wotspk, XMSS_ADRS_TYPE_LTREE);
    ctx->adrsOps->copyKeyPairAddr(wotspk, adrs);
    ret = ctx->hashFuncs->pkCompress(ctx->coreCtx, wotspk, tmp, len * n, pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

ERR:
    BSL_SAL_Free(msgw);
    if (tmp != NULL) {
        BSL_SAL_Free(tmp);
    }
    return ret;
}

#endif /* HITLS_CRYPTO_XMSS || HITLS_CRYPTO_SLH_DSA */

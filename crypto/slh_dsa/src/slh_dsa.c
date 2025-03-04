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

#include <stddef.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_obj_internal.h"
#include "bsl_asn1.h"
#include "crypt_errno.h"
#include "crypt_util_rand.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
#include "crypt_rsa.h"
#include "eal_md_local.h"
#include "slh_dsa_fors.h"
#include "slh_dsa_xmss.h"
#include "slh_dsa_hypertree.h"
#include "slh_dsa.h"

#define MAX_MDSIZE 64
#define MAX_M      49

typedef struct {
    BSL_Param *pubSeed;
    BSL_Param *pubRoot;
} SlhDsaPubKeyParam;

typedef struct {
    BSL_Param *prvSeed;
    BSL_Param *prvPrf;
    BSL_Param *pubSeed;
    BSL_Param *pubRoot;
} SlhDsaPrvKeyParam;

static uint32_t g_slhDsaN[CRYPT_SLH_DSA_ALG_ID_MAX] = {16, 16, 16, 16, 24, 24, 24, 24, 32, 32, 32, 32};
static uint32_t g_slhDsaH[CRYPT_SLH_DSA_ALG_ID_MAX] = {63, 63, 66, 66, 63, 63, 66, 66, 64, 64, 68, 68};
static uint32_t g_slhDsaD[CRYPT_SLH_DSA_ALG_ID_MAX] = {7, 7, 22, 22, 7, 7, 22, 22, 8, 8, 17, 17};
static uint32_t g_slhDsaHp[CRYPT_SLH_DSA_ALG_ID_MAX] = {9, 9, 3, 3, 9, 9, 3, 3, 8, 8, 4, 4}; // xmss height
static uint32_t g_slhDsaA[CRYPT_SLH_DSA_ALG_ID_MAX] = {12, 12, 6, 6, 14, 14, 8, 8, 14, 14, 9, 9};
static uint32_t g_slhDsaK[CRYPT_SLH_DSA_ALG_ID_MAX] = {14, 14, 33, 33, 17, 17, 33, 33, 22, 22, 35, 35};
static uint32_t g_slhDsaM[CRYPT_SLH_DSA_ALG_ID_MAX] = {30, 30, 34, 34, 39, 39, 42, 42, 47, 47, 49, 49};
static uint32_t g_slhDsaPkBytes[CRYPT_SLH_DSA_ALG_ID_MAX] = {32, 32, 32, 32, 48, 48, 48, 48, 64, 64, 64, 64};
static uint32_t g_slhDsaSigBytes[CRYPT_SLH_DSA_ALG_ID_MAX] = {7856,  7856,  17088, 17088, 16224, 16224,
                                                              35664, 35664, 29792, 29792, 49856, 49856};
static uint8_t g_secCategory[] = {1, 1, 1, 1, 3, 3, 3, 3, 5, 5, 5, 5};

static void UCAdrsSetLayerAddr(SlhDsaAdrs *adrs, uint32_t layer)
{
    PUT_UINT32_BE(layer, adrs->uc.layerAddr, 0);
}

static void UCAdrsSetTreeAddr(SlhDsaAdrs *adrs, uint64_t tree)
{
    PUT_UINT64_BE(tree, adrs->uc.treeAddr, 4);
}

static void UCAdrsSetType(SlhDsaAdrs *adrs, AdrsType type)
{
    PUT_UINT32_BE(type, adrs->uc.type, 0);
    (void)memset_s(adrs->uc.padding, sizeof(adrs->uc.padding), 0, sizeof(adrs->uc.padding));
}

static void UCAdrsSetKeyPairAddr(SlhDsaAdrs *adrs, uint32_t keyPair)
{
    PUT_UINT32_BE(keyPair, adrs->uc.padding, 0);
}

static void UCAdrsSetChainAddr(SlhDsaAdrs *adrs, uint32_t chain)
{
    PUT_UINT32_BE(chain, adrs->uc.padding, 4);
}

static void UCAdrsSetTreeHeight(SlhDsaAdrs *adrs, uint32_t height)
{
    PUT_UINT32_BE(height, adrs->uc.padding, 4);
}

static void UCAdrsSetHashAddr(SlhDsaAdrs *adrs, uint32_t hash)
{
    PUT_UINT32_BE(hash, adrs->uc.padding, 8);
}

static void UCAdrsSetTreeIndex(SlhDsaAdrs *adrs, uint32_t index)
{
    PUT_UINT32_BE(index, adrs->uc.padding, 8);
}

static uint32_t UCAdrsGetTreeHeight(const SlhDsaAdrs *adrs)
{
    return GET_UINT32_BE(adrs->uc.padding, 0);
}

static uint32_t UCAdrsGetTreeIndex(const SlhDsaAdrs *adrs)
{
    return GET_UINT32_BE(adrs->uc.padding, 8);
}

static void UCAdrsCopyKeyPairAddr(SlhDsaAdrs *adrs, const SlhDsaAdrs *adrs2)
{
    (void)memcpy_s(adrs->uc.padding, sizeof(adrs->uc.padding), adrs2->uc.padding, 4);
}

static uint32_t UCAdrsGetAdrsLen()
{
    return SLH_DSA_ADRS_LEN;
}

static void CAdrsSetLayerAddr(SlhDsaAdrs *adrs, uint32_t layer)
{
    adrs->c.layerAddr = layer;
}

static void CAdrsSetTreeAddr(SlhDsaAdrs *adrs, uint64_t tree)
{
    PUT_UINT64_BE(tree, adrs->c.treeAddr, 0);
}

static void CAdrsSetType(SlhDsaAdrs *adrs, AdrsType type)
{
    adrs->c.type = type;
    (void)memset_s(adrs->c.padding, sizeof(adrs->c.padding), 0, sizeof(adrs->c.padding));
}

static void CAdrsSetKeyPairAddr(SlhDsaAdrs *adrs, uint32_t keyPair)
{
    PUT_UINT32_BE(keyPair, adrs->c.padding, 0);
}

static void CAdrsSetChainAddr(SlhDsaAdrs *adrs, uint32_t chain)
{
    PUT_UINT32_BE(chain, adrs->c.padding, 4);
}

static void CAdrsSetTreeHeight(SlhDsaAdrs *adrs, uint32_t height)
{
    PUT_UINT32_BE(height, adrs->c.padding, 4);
}

static void CAdrsSetHashAddr(SlhDsaAdrs *adrs, uint32_t hash)
{
    PUT_UINT32_BE(hash, adrs->c.padding, 8);
}

static void CAdrsSetTreeIndex(SlhDsaAdrs *adrs, uint32_t index)
{
    PUT_UINT32_BE(index, adrs->c.padding, 8);
}

static uint32_t CAdrsGetTreeHeight(const SlhDsaAdrs *adrs)
{
    return GET_UINT32_BE(adrs->c.padding, 0);
}

static uint32_t CAdrsGetTreeIndex(const SlhDsaAdrs *adrs)
{
    return GET_UINT32_BE(adrs->c.padding, 8);
}

static void CAdrsCopyKeyPairAddr(SlhDsaAdrs *adrs, const SlhDsaAdrs *adrs2)
{
    (void)memcpy_s(adrs->c.padding, sizeof(adrs->c.padding), adrs2->c.padding, 4);
}

static uint32_t CAdrsGetAdrsLen()
{
    return SLH_DSA_ADRS_COMPRESSED_LEN;
}

static AdrsOps g_adrsOps[2] = {{
                                   .setLayerAddr = UCAdrsSetLayerAddr,
                                   .setTreeAddr = UCAdrsSetTreeAddr,
                                   .setType = UCAdrsSetType,
                                   .setKeyPairAddr = UCAdrsSetKeyPairAddr,
                                   .setChainAddr = UCAdrsSetChainAddr,
                                   .setTreeHeight = UCAdrsSetTreeHeight,
                                   .setHashAddr = UCAdrsSetHashAddr,
                                   .setTreeIndex = UCAdrsSetTreeIndex,
                                   .getTreeHeight = UCAdrsGetTreeHeight,
                                   .getTreeIndex = UCAdrsGetTreeIndex,
                                   .copyKeyPairAddr = UCAdrsCopyKeyPairAddr,
                                   .getAdrsLen = UCAdrsGetAdrsLen,
                               },
                               {
                                   .setLayerAddr = CAdrsSetLayerAddr,
                                   .setTreeAddr = CAdrsSetTreeAddr,
                                   .setType = CAdrsSetType,
                                   .setKeyPairAddr = CAdrsSetKeyPairAddr,
                                   .setChainAddr = CAdrsSetChainAddr,
                                   .setTreeHeight = CAdrsSetTreeHeight,
                                   .setHashAddr = CAdrsSetHashAddr,
                                   .setTreeIndex = CAdrsSetTreeIndex,
                                   .getTreeHeight = CAdrsGetTreeHeight,
                                   .getTreeIndex = CAdrsGetTreeIndex,
                                   .copyKeyPairAddr = CAdrsCopyKeyPairAddr,
                                   .getAdrsLen = CAdrsGetAdrsLen,
                               }};

void BaseB(const uint8_t *x, uint32_t xLen, uint32_t b, uint32_t *out, uint32_t outLen)
{
    uint32_t bit = 0;
    uint32_t o = 0;
    uint32_t xi = 0;
    for (uint32_t i = 0; i < outLen; i++) {
        while (bit < b && xi < xLen) {
            o = (o << 8) + x[xi];
            bit += 8;
            xi++;
        }
        bit -= b;
        out[i] = o >> bit;
        // keep the remaining bits
        o &= (1 << bit) - 1;
    }
}

// ToInt(b[0:l]) mod 2^m
static uint64_t ToIntMod(const uint8_t *b, uint32_t l, uint32_t m)
{
    uint64_t ret = 0;
    for (uint32_t i = 0; i < l; i++) {
        ret = (ret << 8) + b[i];
    }
    // mod 2^m is same to ~(uint64_t)0 >> (64 - m)
    return ret & (~(uint64_t)0 >> (64 - m));
}

CryptSlhDsaCtx *CRYPT_SLH_DSA_NewCtx(void)
{
    CryptSlhDsaCtx *ctx = (CryptSlhDsaCtx *)BSL_SAL_Calloc(sizeof(CryptSlhDsaCtx), 1);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->para.algId = CRYPT_SLH_DSA_ALG_ID_MAX;
    ctx->prehashId = CRYPT_MD_MAX;
    ctx->isDeterministic = false;
    return ctx;
}

void CRYPT_SLH_DSA_FreeCtx(CryptSlhDsaCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_Free(ctx->context);
    BSL_SAL_Free(ctx->addrand);
    BSL_SAL_Free(ctx);
}

int32_t CRYPT_SLH_DSA_Gen(CryptSlhDsaCtx *ctx)
{
    int32_t ret;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para.algId >= CRYPT_SLH_DSA_ALG_ID_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
        return CRYPT_SLHDSA_ERR_INVALID_ALGID;
    }
    uint32_t n = ctx->para.n;
    uint32_t d = ctx->para.d;
    uint32_t hp = ctx->para.hp;
    ret = CRYPT_Rand(ctx->prvkey.seed, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = CRYPT_Rand(ctx->prvkey.prf, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = CRYPT_Rand(ctx->prvkey.pub.seed, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    SlhDsaAdrs adrs;
    (void)memset_s(&adrs, sizeof(SlhDsaAdrs), 0, sizeof(SlhDsaAdrs));
    ctx->adrsOps.setLayerAddr(&adrs, d - 1);
    SlhDsaN node;
    node.len = n;
    ret = XmssNode(&node, 0, hp, &adrs, ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memcpy(ctx->prvkey.pub.root, node.bytes, n);
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_SLH_DSA_SignInternal(SlhDsaCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint8_t *sig,
                                          uint32_t *sigLen)
{
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint32_t a = ctx->para.a;
    uint32_t k = ctx->para.k;
    uint32_t h = ctx->para.h;
    uint32_t d = ctx->para.d;
    uint32_t sigBytes = ctx->para.sigBytes;

    if (ctx == NULL || msg == NULL || msgLen == 0 || sig == NULL || sigLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (*sigLen < sigBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    SlhDsaAdrs adrs;
    (void)memset_s(&adrs, sizeof(SlhDsaAdrs), 0, sizeof(SlhDsaAdrs));
    uint32_t offset = 0;
    uint32_t left = *sigLen;
    if (!ctx->isDeterministic) {
        if (ctx->addrand == NULL) {
            ctx->addrand = (uint8_t *)BSL_SAL_Malloc(n);
            if (ctx->addrand == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            ret = CRYPT_Rand(ctx->addrand, n);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
        }
    } else {
        if (ctx->addrand == NULL) {
            // FIPS-204, Algorithm 19, line 2.
            // if is deterministic, use the public key seed as the random number.
            uint8_t *rand = (uint8_t *)BSL_SAL_Malloc(n);
            if (rand == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            (void)memcpy_s(rand, n, ctx->prvkey.pub.seed, n);
            ctx->addrand = rand;
        }
    }
    ret = ctx->prfmsg(ctx, ctx->prvkey.prf, n, ctx->addrand, n, msg, msgLen, sig, &left);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += left;
    left = *sigLen - offset;
    uint8_t digest[MAX_M] = {0};
    uint32_t digestLen = sizeof(digest);
    ret =
        ctx->hmsg(ctx, sig, offset, ctx->prvkey.pub.seed, n, ctx->prvkey.pub.root, n, msg, msgLen, digest, &digestLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t mdIdx = (k * a + 7) / 8;
    uint32_t treeIdxLen = (h - h / d + 7) / 8;
    uint32_t leafIdxLen = (h / d + 7) / 8;
    uint64_t treeIdx = ToIntMod(digest + mdIdx, treeIdxLen, h - h / d);
    uint32_t leafIdx = (uint32_t)ToIntMod(digest + mdIdx + treeIdxLen, leafIdxLen, h / d);

    ctx->adrsOps.setTreeAddr(&adrs, treeIdx);
    ctx->adrsOps.setType(&adrs, FORS_TREE);
    ctx->adrsOps.setKeyPairAddr(&adrs, leafIdx);
    ret = ForsSign(digest, mdIdx, &adrs, ctx, sig + offset, &left);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t pk[SLH_DSA_MAX_N] = {0};
    uint32_t pkLen = sizeof(pk);
    ret = ForsPkFromSig(sig + n, left, digest, mdIdx, &adrs, ctx, pk, &pkLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += left;
    left = *sigLen - offset;
    ret = HypertreeSign(pk, pkLen, treeIdx, leafIdx, ctx, sig + offset, &left);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *sigLen = offset + left;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_SLH_DSA_VerifyInternal(const SlhDsaCtx *ctx, const uint8_t *msg, uint32_t msgLen,
                                            const uint8_t *sig, uint32_t sigLen)
{
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint32_t a = ctx->para.a;
    uint32_t k = ctx->para.k;
    uint32_t h = ctx->para.h;
    uint32_t d = ctx->para.d;
    uint32_t sigBytes = ctx->para.sigBytes;

    if (ctx == NULL || msg == NULL || msgLen == 0 || sig == NULL || sigLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (sigLen != sigBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_SIG_LEN);
        return CRYPT_SLHDSA_ERR_INVALID_SIG_LEN;
    }

    SlhDsaAdrs adrs;
    (void)memset_s(&adrs, sizeof(SlhDsaAdrs), 0, sizeof(SlhDsaAdrs));
    uint32_t offset = 0;

    uint8_t digest[SLH_DSA_MAX_M] = {0};
    uint32_t digestLen = sizeof(digest);
    ret = ctx->hmsg(ctx, sig, n, ctx->prvkey.pub.seed, n, ctx->prvkey.pub.root, n, msg, msgLen, digest, &digestLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += n;
    uint32_t mdIdx = (k * a + 7) / 8;
    uint32_t treeIdxLen = (h - h / d + 7) / 8;
    uint32_t leafIdxLen = (h / d + 7) / 8;
    uint64_t treeIdx = ToIntMod(digest + mdIdx, treeIdxLen, h - h / d);
    uint32_t leafIdx = (uint32_t)ToIntMod(digest + mdIdx + treeIdxLen, leafIdxLen, h / d);

    ctx->adrsOps.setTreeAddr(&adrs, treeIdx);
    ctx->adrsOps.setType(&adrs, FORS_TREE);
    ctx->adrsOps.setKeyPairAddr(&adrs, leafIdx);
    uint8_t pk[SLH_DSA_MAX_N] = {0};
    uint32_t pkLen = sizeof(pk);
    ret = ForsPkFromSig(sig + offset, (1 + a) * k * n, digest, mdIdx, &adrs, ctx, pk, &pkLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += (1 + a) * k * n;
    ret = HypertreeVerify(pk, pkLen, sig + offset, sigLen - offset, treeIdx, leafIdx, ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_Sign(SlhDsaCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                           uint32_t *signLen)
{
    (void)algId;
    int32_t ret;

    if (ctx == NULL || data == NULL || dataLen == 0 || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint32_t mpLen = 2 + ctx->contextLen + dataLen;
    uint8_t *mp = (uint8_t *)BSL_SAL_Calloc(mpLen, 1);
    if (mp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    mp[1] = ctx->contextLen;
    (void)memcpy_s(mp + 2, mpLen - 2, ctx->context, ctx->contextLen);
    (void)memcpy_s(mp + 2 + ctx->contextLen, mpLen - 2 - ctx->contextLen, data, dataLen);
    ret = CRYPT_SLH_DSA_SignInternal(ctx, mp, mpLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_SAL_Free(mp);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_Verify(const SlhDsaCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                             const uint8_t *sign, uint32_t signLen)
{
    (void)algId;
    int32_t ret;
    if (ctx == NULL || data == NULL || dataLen == 0 || sign == NULL || signLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t mpLen = 2 + ctx->contextLen + dataLen;
    uint8_t *mp = (uint8_t *)BSL_SAL_Calloc(mpLen, 1);
    if (mp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    mp[1] = ctx->contextLen;
    (void)memcpy_s(mp + 2, mpLen - 2, ctx->context, ctx->contextLen);
    (void)memcpy_s(mp + 2 + ctx->contextLen, mpLen - 2 - ctx->contextLen, data, dataLen);
    ret = CRYPT_SLH_DSA_VerifyInternal(ctx, mp, mpLen, sign, signLen);
    BSL_SAL_Free(mp);
    return ret;
}

int32_t CRYPT_SLH_DSA_SignData(SlhDsaCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint8_t *sig, uint32_t *sigLen)
{
    int32_t ret;
    if (ctx == NULL || msg == NULL || msgLen == 0 || sig == NULL || sigLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BslOidString *oid = BSL_OBJ_GetOidFromCID((BslCid)ctx->prehashId);
    if (oid == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED);
        return CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED;
    }

    uint32_t mpLen = 2 + ctx->contextLen + oid->octetLen + msgLen;
    uint8_t *mp = (uint8_t *)BSL_SAL_Calloc(mpLen, 1);
    if (mp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t offset = 0;
    // sign pre-hash data
    mp[0] = 1;
    mp[1] = ctx->contextLen;
    offset += 2;
    (void)memcpy_s(mp + offset, mpLen - offset, ctx->context, ctx->contextLen);
    offset += ctx->contextLen;

    // asn1 encoding of hash oid
    (mp + offset)[0] = BSL_ASN1_TAG_OBJECT_ID;
    (mp + offset)[1] = oid->octetLen;
    (void)memcpy_s(mp + offset, mpLen - offset, oid->octs, oid->octetLen);
    offset += oid->octetLen;
    (void)memcpy_s(mp + offset, mpLen - offset, msg, msgLen);
    ret = CRYPT_SLH_DSA_SignInternal(ctx, mp, mpLen, sig, sigLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_SAL_Free(mp);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_VerifyData(const SlhDsaCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint8_t *sig,
                                 uint32_t sigLen)
{
    int32_t ret;
    if (ctx == NULL || msg == NULL || msgLen == 0 || sig == NULL || sigLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BslOidString *oid = BSL_OBJ_GetOidFromCID((BslCid)ctx->prehashId);
    if (oid == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED);
        return CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED;
    }

    uint32_t mpLen = 2 + ctx->contextLen + 2 + oid->octetLen + msgLen;
    uint8_t *mp = (uint8_t *)BSL_SAL_Malloc(mpLen);
    if (mp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t offset = 0;
    mp[0] = 1;
    mp[1] = ctx->contextLen;
    offset += 2;
    (void)memcpy_s(mp + offset, mpLen - offset, ctx->context, ctx->contextLen);
    offset += ctx->contextLen;

    // asn1 encoding of hash oid
    (mp + offset)[0] = BSL_ASN1_TAG_OBJECT_ID;
    (mp + offset)[1] = oid->octetLen;
    offset += 2;
    (void)memcpy_s(mp + offset, mpLen - offset, oid->octs, oid->octetLen);
    offset += oid->octetLen;
    (void)memcpy_s(mp + offset, mpLen - offset, msg, msgLen);
    ret = CRYPT_SLH_DSA_VerifyInternal(ctx, mp, mpLen, sig, sigLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_SAL_Free(mp);
    return CRYPT_SUCCESS;
}

static int32_t PrfmsgShake256(const SlhDsaCtx *ctx, const uint8_t *prf, uint32_t prfLen, const uint8_t *rand,
                              uint32_t randLen, const uint8_t *msg, uint32_t msgLen, uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint8_t tmp[MAX_MDSIZE] = {0};
    uint32_t tmpLen = n;
    CRYPT_EAL_MdCTX *mdCtx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHAKE256);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF_EX(CRYPT_EAL_MdInit(mdCtx), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, prf, prfLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, rand, randLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, msg, msgLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdFinal(mdCtx, tmp, &tmpLen), ret);
    (void)memcpy_s(out, *outLen, tmp, tmpLen);
    *outLen = tmpLen;
ERR:
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return ret;
}

static int32_t HmsgShake256(const SlhDsaCtx *ctx, const uint8_t *r, uint32_t rLen, const uint8_t *seed,
                            uint32_t seedLen, const uint8_t *root, uint32_t rootLen, const uint8_t *msg,
                            uint32_t msgLen, uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    uint32_t m = ctx->para.m;
    uint8_t tmp[MAX_MDSIZE] = {0};
    uint32_t tmpLen = m;
    CRYPT_EAL_MdCTX *mdCtx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHAKE256);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF_EX(CRYPT_EAL_MdInit(mdCtx), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, r, rLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, seed, seedLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, root, rootLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, msg, msgLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdFinal(mdCtx, tmp, &tmpLen), ret);
    (void)memcpy_s(out, *outLen, tmp, tmpLen);
    *outLen = tmpLen;
ERR:
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return ret;
}

static int32_t PthfShake256(const SlhDsaCtx *ctx, bool isHT, const uint8_t *seed, uint32_t seedLen,
                            const SlhDsaAdrs *adrs, const uint8_t *msg, uint32_t msgLen, uint8_t *out, uint32_t *outLen)
{
    (void)isHT;
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint8_t tmp[MAX_MDSIZE] = {0};
    uint32_t tmpLen = n;
    CRYPT_EAL_MdCTX *mdCtx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHAKE256);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF_EX(CRYPT_EAL_MdInit(mdCtx), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, seed, seedLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, adrs->bytes, ctx->adrsOps.getAdrsLen()), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, msg, msgLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdFinal(mdCtx, tmp, &tmpLen), ret);
    (void)memcpy_s(out, *outLen, tmp, tmpLen);
    *outLen = tmpLen;
ERR:
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return ret;
}

static int32_t PrfmsgSha256(const SlhDsaCtx *ctx, const uint8_t *prf, uint32_t prfLen, const uint8_t *rand,
                            uint32_t randLen, const uint8_t *msg, uint32_t msgLen, uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint8_t tmp[MAX_MDSIZE] = {0};
    uint32_t tmpLen = sizeof(tmp);
    CRYPT_EAL_MacCtx *mdCtx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_HMAC_SHA256);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF_EX(CRYPT_EAL_MacInit(mdCtx, prf, prfLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MacUpdate(mdCtx, rand, randLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MacUpdate(mdCtx, msg, msgLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MacFinal(mdCtx, tmp, &tmpLen), ret);
    (void)memcpy_s(out, *outLen, tmp, n);
    *outLen = n;
ERR:
    CRYPT_EAL_MacFreeCtx(mdCtx);
    return ret;
}

static int32_t HmsgSha256(const SlhDsaCtx *ctx, const uint8_t *r, uint32_t rLen, const uint8_t *seed, uint32_t seedLen,
                          const uint8_t *root, uint32_t rootLen, const uint8_t *msg, uint32_t msgLen, uint8_t *out,
                          uint32_t *outLen)
{
    int32_t ret;
    CRYPT_EAL_MdCTX *mdCtx = NULL;
    uint32_t m = ctx->para.m;
    uint32_t tmpLen;

    uint8_t tmpSeed[2 * SLH_DSA_MAX_N + MAX_MDSIZE] = {0};
    uint32_t tmpSeedLen = 0;
    (void)memcpy_s(tmpSeed, sizeof(tmpSeed), r, rLen);
    (void)memcpy_s(tmpSeed + rLen, sizeof(tmpSeed) - rLen, seed, seedLen);
    tmpSeedLen = rLen + seedLen;
    tmpLen = sizeof(tmpSeed) - tmpSeedLen;

    mdCtx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF_EX(CRYPT_EAL_MdInit(mdCtx), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, tmpSeed, tmpSeedLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, root, rootLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, msg, msgLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdFinal(mdCtx, tmpSeed + tmpSeedLen, &tmpLen), ret);
    tmpSeedLen += tmpLen;
    CRYPT_EAL_MdFreeCtx(mdCtx);
    *outLen = m;
    return CRYPT_Mgf1(EAL_MdFindMethod(CRYPT_MD_SHA256), tmpSeed, tmpSeedLen, out, m);
ERR:
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return ret;
}

static int32_t PthfSha2(const SlhDsaCtx *ctx, bool isHT, const uint8_t *seed, uint32_t seedLen, const SlhDsaAdrs *adrs,
                        const uint8_t *msg, uint32_t msgLen, uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint8_t tmp[MAX_MDSIZE] = {0};
    uint32_t tmpLen = sizeof(tmp);
    uint8_t padding[128] = {0};
    uint32_t paddingLen = (ctx->para.secCategory != 1 && isHT) ? (128 - n) : (64 - n);
    CRYPT_MD_AlgId mdId = (ctx->para.secCategory != 1 && isHT) ? CRYPT_MD_SHA512 : CRYPT_MD_SHA256;
    CRYPT_EAL_MdCTX *mdCtx = CRYPT_EAL_MdNewCtx(mdId);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF_EX(CRYPT_EAL_MdInit(mdCtx), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, seed, seedLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, padding, paddingLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, adrs->bytes, ctx->adrsOps.getAdrsLen()), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, msg, msgLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdFinal(mdCtx, tmp, &tmpLen), ret);
    (void)memcpy_s(out, *outLen, tmp, n);
    *outLen = n;
ERR:
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return ret;
}

static int32_t PrfmsgSha512(const SlhDsaCtx *ctx, const uint8_t *prf, uint32_t prfLen, const uint8_t *rand,
                            uint32_t randLen, const uint8_t *msg, uint32_t msgLen, uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint8_t tmp[MAX_MDSIZE] = {0};
    uint32_t tmpLen = sizeof(tmp);
    CRYPT_EAL_MacCtx *mdCtx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_HMAC_SHA512);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF_EX(CRYPT_EAL_MacInit(mdCtx, prf, prfLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MacUpdate(mdCtx, rand, randLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MacUpdate(mdCtx, msg, msgLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MacFinal(mdCtx, tmp, &tmpLen), ret);
    (void)memcpy_s(out, *outLen, tmp, n);
    *outLen = n;
ERR:
    CRYPT_EAL_MacFreeCtx(mdCtx);
    return ret;
}

static int32_t HmsgSha512(const SlhDsaCtx *ctx, const uint8_t *r, uint32_t rLen, const uint8_t *seed, uint32_t seedLen,
                          const uint8_t *root, uint32_t rootLen, const uint8_t *msg, uint32_t msgLen, uint8_t *out,
                          uint32_t *outLen)
{
    int32_t ret;
    CRYPT_EAL_MdCTX *mdCtx = NULL;
    uint32_t m = ctx->para.m;
    uint32_t tmpLen;

    uint8_t tmpSeed[2 * SLH_DSA_MAX_N + MAX_MDSIZE] = {0};
    uint32_t tmpSeedLen = 0;
    (void)memcpy_s(tmpSeed, sizeof(tmpSeed), r, rLen);
    (void)memcpy_s(tmpSeed + rLen, sizeof(tmpSeed) - rLen, seed, seedLen);
    tmpSeedLen = rLen + seedLen;
    tmpLen = sizeof(tmpSeed) - tmpSeedLen;

    mdCtx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA512);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF_EX(CRYPT_EAL_MdInit(mdCtx), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, tmpSeed, tmpSeedLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, root, rootLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdUpdate(mdCtx, msg, msgLen), ret);
    GOTO_ERR_IF_EX(CRYPT_EAL_MdFinal(mdCtx, tmpSeed + tmpSeedLen, &tmpLen), ret);
    tmpSeedLen += tmpLen;
    CRYPT_EAL_MdFreeCtx(mdCtx);
    *outLen = m;
    return CRYPT_Mgf1(EAL_MdFindMethod(CRYPT_MD_SHA512), tmpSeed, tmpSeedLen, out, m);
ERR:
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return ret;
}

static void SlhDsaSetAlgId(CryptSlhDsaCtx *ctx, CRYPT_SLH_DSA_AlgId algId)
{
    ctx->para.algId = algId;
    ctx->para.n = g_slhDsaN[algId];
    ctx->para.h = g_slhDsaH[algId];
    ctx->para.d = g_slhDsaD[algId];
    ctx->para.hp = g_slhDsaHp[algId];
    ctx->para.a = g_slhDsaA[algId];
    ctx->para.k = g_slhDsaK[algId];
    ctx->para.m = g_slhDsaM[algId];
    ctx->para.pkBytes = g_slhDsaPkBytes[algId];
    ctx->para.sigBytes = g_slhDsaSigBytes[algId];
    ctx->para.secCategory = g_secCategory[algId];
    if (algId == CRYPT_SLH_DSA_SHA2_128S || algId == CRYPT_SLH_DSA_SHA2_128F || algId == CRYPT_SLH_DSA_SHA2_192S ||
        algId == CRYPT_SLH_DSA_SHA2_192F || algId == CRYPT_SLH_DSA_SHA2_256S || algId == CRYPT_SLH_DSA_SHA2_256F) {
        ctx->para.isCompressed = true;
        ctx->pthf = PthfSha2;
        if (g_secCategory[algId] == 1) {
            ctx->prfmsg = PrfmsgSha256;
            ctx->hmsg = HmsgSha256;
        } else {
            ctx->prfmsg = PrfmsgSha512;
            ctx->hmsg = HmsgSha512;
        }
        ctx->adrsOps = g_adrsOps[1];
    } else {
        ctx->para.isCompressed = false;
        ctx->prfmsg = PrfmsgShake256;
        ctx->hmsg = HmsgShake256;
        ctx->pthf = PthfShake256;
        ctx->adrsOps = g_adrsOps[0];
    }
}

int32_t CRYPT_SLH_DSA_Ctrl(CryptSlhDsaCtx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_SET_SLH_DSA_ALG_ID:
            if (val == NULL || len != sizeof(CRYPT_SLH_DSA_AlgId)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            CRYPT_SLH_DSA_AlgId algId = *(CRYPT_SLH_DSA_AlgId *)val;
            if (algId >= CRYPT_SLH_DSA_ALG_ID_MAX) {
                BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
                return CRYPT_SLHDSA_ERR_INVALID_ALGID;
            }
            SlhDsaSetAlgId(ctx, algId);
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_SET_SLH_DSA_PREHASH_ID:
            if (val == NULL || len != sizeof(CRYPT_MD_AlgId)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            CRYPT_MD_AlgId prehashId = *(CRYPT_MD_AlgId *)val;
            if (prehashId == CRYPT_MD_MAX) {
                BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED);
                return CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED;
            }
            ctx->prehashId = prehashId;
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_SET_SLH_DSA_CONTEXT:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            if (len > 255) {
                BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_CONTEXT_LEN_OVERFLOW);
                return CRYPT_SLHDSA_ERR_CONTEXT_LEN_OVERFLOW;
            }
            ctx->contextLen = len;
            ctx->context = (uint8_t *)BSL_SAL_Malloc(len);
            if (ctx->context == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            (void)memcpy_s(ctx->context, len, val, len);
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_GET_SLH_DSA_KEY_LEN:
            if (val == NULL || len != sizeof(uint32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            *(uint32_t *)val = ctx->para.n;
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_SET_SLH_DSA_DETERMINISTIC:
            if (val == NULL || len != sizeof(bool)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            ctx->isDeterministic = *(bool *)val;
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_SET_SLH_DSA_ADDRAND:
            if (val == NULL || len != ctx->para.n) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            uint8_t *rand = (uint8_t *)BSL_SAL_Malloc(len);
            if (rand == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            (void)memcpy_s(rand, len, val, len);
            ctx->addrand = rand;
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

static int32_t PubKeyParamCheck(const SlhDsaCtx *ctx, BSL_Param *para, SlhDsaPubKeyParam *pub)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    pub->pubSeed = BSL_PARAM_FindParam(para, CRYPT_PARAM_SLH_DSA_PUB_SEED);
    pub->pubRoot = BSL_PARAM_FindParam(para, CRYPT_PARAM_SLH_DSA_PUB_ROOT);
    if (pub->pubSeed == NULL || pub->pubSeed->value == NULL || pub->pubRoot == NULL || pub->pubRoot->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pub->pubSeed->valueLen != ctx->para.n || pub->pubRoot->valueLen != ctx->para.n) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
        return CRYPT_SLHDSA_ERR_INVALID_KEYLEN;
    }
    return CRYPT_SUCCESS;
}

static int32_t PrvKeyParamCheck(const SlhDsaCtx *ctx, BSL_Param *para, SlhDsaPrvKeyParam *prv)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    prv->prvSeed = BSL_PARAM_FindParam(para, CRYPT_PARAM_SLH_DSA_PRV_SEED);
    prv->prvPrf = BSL_PARAM_FindParam(para, CRYPT_PARAM_SLH_DSA_PRV_PRF);
    prv->pubSeed = BSL_PARAM_FindParam(para, CRYPT_PARAM_SLH_DSA_PUB_SEED);
    prv->pubRoot = BSL_PARAM_FindParam(para, CRYPT_PARAM_SLH_DSA_PUB_ROOT);
    if (prv->prvSeed == NULL || prv->prvSeed->value == NULL || prv->prvPrf == NULL || prv->prvPrf->value == NULL ||
        prv->pubSeed == NULL || prv->pubSeed->value == NULL || prv->pubRoot == NULL || prv->pubRoot->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prv->prvSeed->valueLen != ctx->para.n || prv->prvPrf->valueLen != ctx->para.n ||
        prv->pubSeed->valueLen != ctx->para.n || prv->pubRoot->valueLen != ctx->para.n) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
        return CRYPT_SLHDSA_ERR_INVALID_KEYLEN;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_GetPubKey(const SlhDsaCtx *ctx, BSL_Param *para)
{
    SlhDsaPubKeyParam pub;
    int32_t ret = PubKeyParamCheck(ctx, para, &pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pub.pubSeed->useLen = pub.pubRoot->useLen = ctx->para.n;
    (void)memcpy_s(pub.pubSeed->value, pub.pubSeed->valueLen, ctx->prvkey.pub.seed, ctx->para.n);
    (void)memcpy_s(pub.pubRoot->value, pub.pubRoot->valueLen, ctx->prvkey.pub.root, ctx->para.n);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_GetPrvKey(const SlhDsaCtx *ctx, BSL_Param *para)
{
    SlhDsaPrvKeyParam prv;
    int32_t ret = PrvKeyParamCheck(ctx, para, &prv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    prv.prvSeed->useLen = prv.prvPrf->useLen = ctx->para.n;
    prv.pubSeed->useLen = prv.pubRoot->useLen = ctx->para.n;
    (void)memcpy_s(prv.prvSeed->value, prv.prvSeed->valueLen, ctx->prvkey.seed, ctx->para.n);
    (void)memcpy_s(prv.prvPrf->value, prv.prvPrf->valueLen, ctx->prvkey.prf, ctx->para.n);
    (void)memcpy_s(prv.pubSeed->value, prv.pubSeed->valueLen, ctx->prvkey.pub.seed, ctx->para.n);
    (void)memcpy_s(prv.pubRoot->value, prv.pubRoot->valueLen, ctx->prvkey.pub.root, ctx->para.n);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_SetPubKey(SlhDsaCtx *ctx, const BSL_Param *para)
{
    SlhDsaPubKeyParam pub;
    int32_t ret = PubKeyParamCheck(ctx, (BSL_Param *)(uintptr_t)para, &pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memcpy_s(ctx->prvkey.pub.seed, ctx->para.n, pub.pubSeed->value, ctx->para.n);
    (void)memcpy_s(ctx->prvkey.pub.root, ctx->para.n, pub.pubRoot->value, ctx->para.n);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_SetPrvKey(SlhDsaCtx *ctx, const BSL_Param *para)
{
    SlhDsaPrvKeyParam prv;
    int32_t ret = PrvKeyParamCheck(ctx, (BSL_Param *)(uintptr_t)para, &prv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    (void)memcpy_s(ctx->prvkey.seed, sizeof(ctx->prvkey.seed), prv.prvSeed->value, ctx->para.n);
    (void)memcpy_s(ctx->prvkey.prf, sizeof(ctx->prvkey.prf), prv.prvPrf->value, ctx->para.n);
    (void)memcpy_s(ctx->prvkey.pub.seed, sizeof(ctx->prvkey.pub.seed), prv.pubSeed->value, ctx->para.n);
    (void)memcpy_s(ctx->prvkey.pub.root, sizeof(ctx->prvkey.pub.root), prv.pubRoot->value, ctx->para.n);

    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_SLH_DSA
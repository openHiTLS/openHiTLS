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

/*
 * slh_dsa_core.c - SLH-DSA public API
 *
 * Moved from slh_dsa.c per HBS refactoring design §2.3.3:
 *   - NewCtx/FreeCtx/DupCtx/Gen/Sign/Verify/Ctrl/GetPubKey/SetPubKey/
 *     GetPrvKey/SetPrvKey (and Ex variants) -> here
 *   - UC/C address functions + g_adrsOps   -> slh_dsa_address.c
 *   - HbsTreeCtx_InitFromSlhDsa            -> slh_dsa_hypertree.c
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SLH_DSA

#include <stddef.h>
#include <string.h>
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_asn1_internal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_util_rand.h"
#include "eal_md_local.h"
#include "crypt_slh_dsa.h"
#include "slh_dsa_local.h"
#include "slh_dsa_hash.h"
#include "slh_dsa_fors.h"
#include "slh_dsa_hypertree.h"

#define MAX_DIGEST_SIZE            64
#define BYTE_BITS                  8
#define SLH_DSA_PREFIX_LEN         2
#define SPLIT_CEIL(a, b)           (((a) + (b) - 1) / (b))
#define SPLIT_BYTES(a)             SPLIT_CEIL(a, BYTE_BITS)
#define NUM_OF_SLH_DSA_MATH_PARAMS 12
#define NUM_OF_SLH_DSA_PROFILES    24

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

/* Reference: FIPS 205, Table 2. The order matches the twelve PureSLH-DSA identifiers. */
static const SlhDsaMathParams g_slhDsaMathParams[NUM_OF_SLH_DSA_MATH_PARAMS] = {
    {16, 63, 7, 9, 12, 14, 30, 1, 32, 7856, SLH_DSA_HASH_SHA2_128},
    {16, 63, 7, 9, 12, 14, 30, 1, 32, 7856, SLH_DSA_HASH_SHAKE},
    {16, 66, 22, 3, 6, 33, 34, 1, 32, 17088, SLH_DSA_HASH_SHA2_128},
    {16, 66, 22, 3, 6, 33, 34, 1, 32, 17088, SLH_DSA_HASH_SHAKE},
    {24, 63, 7, 9, 14, 17, 39, 3, 48, 16224, SLH_DSA_HASH_SHA2_192_256},
    {24, 63, 7, 9, 14, 17, 39, 3, 48, 16224, SLH_DSA_HASH_SHAKE},
    {24, 66, 22, 3, 8, 33, 42, 3, 48, 35664, SLH_DSA_HASH_SHA2_192_256},
    {24, 66, 22, 3, 8, 33, 42, 3, 48, 35664, SLH_DSA_HASH_SHAKE},
    {32, 64, 8, 8, 14, 22, 47, 5, 64, 29792, SLH_DSA_HASH_SHA2_192_256},
    {32, 64, 8, 8, 14, 22, 47, 5, 64, 29792, SLH_DSA_HASH_SHAKE},
    {32, 68, 17, 4, 9, 35, 49, 5, 64, 49856, SLH_DSA_HASH_SHA2_192_256},
    {32, 68, 17, 4, 9, 35, 49, 5, 64, 49856, SLH_DSA_HASH_SHAKE},
};

/* Reference: RFC 9909, Sections 2 and 3. */
static const SlhDsaProfileInfo g_slhDsaProfiles[NUM_OF_SLH_DSA_PROFILES] = {
    {CRYPT_SLH_DSA_SHA2_128S, &g_slhDsaMathParams[0], false, CRYPT_MD_MAX},
    {CRYPT_SLH_DSA_SHAKE_128S, &g_slhDsaMathParams[1], false, CRYPT_MD_MAX},
    {CRYPT_SLH_DSA_SHA2_128F, &g_slhDsaMathParams[2], false, CRYPT_MD_MAX},
    {CRYPT_SLH_DSA_SHAKE_128F, &g_slhDsaMathParams[3], false, CRYPT_MD_MAX},
    {CRYPT_SLH_DSA_SHA2_192S, &g_slhDsaMathParams[4], false, CRYPT_MD_MAX},
    {CRYPT_SLH_DSA_SHAKE_192S, &g_slhDsaMathParams[5], false, CRYPT_MD_MAX},
    {CRYPT_SLH_DSA_SHA2_192F, &g_slhDsaMathParams[6], false, CRYPT_MD_MAX},
    {CRYPT_SLH_DSA_SHAKE_192F, &g_slhDsaMathParams[7], false, CRYPT_MD_MAX},
    {CRYPT_SLH_DSA_SHA2_256S, &g_slhDsaMathParams[8], false, CRYPT_MD_MAX},
    {CRYPT_SLH_DSA_SHAKE_256S, &g_slhDsaMathParams[9], false, CRYPT_MD_MAX},
    {CRYPT_SLH_DSA_SHA2_256F, &g_slhDsaMathParams[10], false, CRYPT_MD_MAX},
    {CRYPT_SLH_DSA_SHAKE_256F, &g_slhDsaMathParams[11], false, CRYPT_MD_MAX},
    {CRYPT_HASH_SLH_DSA_SHA2_128S_WITH_SHA256, &g_slhDsaMathParams[0], true, CRYPT_MD_SHA256},
    {CRYPT_HASH_SLH_DSA_SHA2_128F_WITH_SHA256, &g_slhDsaMathParams[2], true, CRYPT_MD_SHA256},
    {CRYPT_HASH_SLH_DSA_SHA2_192S_WITH_SHA512, &g_slhDsaMathParams[4], true, CRYPT_MD_SHA512},
    {CRYPT_HASH_SLH_DSA_SHA2_192F_WITH_SHA512, &g_slhDsaMathParams[6], true, CRYPT_MD_SHA512},
    {CRYPT_HASH_SLH_DSA_SHA2_256S_WITH_SHA512, &g_slhDsaMathParams[8], true, CRYPT_MD_SHA512},
    {CRYPT_HASH_SLH_DSA_SHA2_256F_WITH_SHA512, &g_slhDsaMathParams[10], true, CRYPT_MD_SHA512},
    {CRYPT_HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128, &g_slhDsaMathParams[1], true, CRYPT_MD_SHAKE128},
    {CRYPT_HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128, &g_slhDsaMathParams[3], true, CRYPT_MD_SHAKE128},
    {CRYPT_HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256, &g_slhDsaMathParams[5], true, CRYPT_MD_SHAKE256},
    {CRYPT_HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256, &g_slhDsaMathParams[7], true, CRYPT_MD_SHAKE256},
    {CRYPT_HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256, &g_slhDsaMathParams[9], true, CRYPT_MD_SHAKE256},
    {CRYPT_HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256, &g_slhDsaMathParams[11], true, CRYPT_MD_SHAKE256},
};

/* ToInt(b[0:l]) mod 2^m */
static uint64_t ToIntMod(const uint8_t *b, uint32_t l, uint32_t m)
{
    uint64_t ret = 0;
    for (uint32_t i = 0; i < l; i++) {
        ret = (ret << BYTE_BITS) + b[i];
    }
    return ret & (~(uint64_t)0 >> (64 - m));
}

static const SlhDsaProfileInfo *SlhDsaFindProfile(int32_t algId)
{
    for (uint32_t i = 0; i < NUM_OF_SLH_DSA_PROFILES; i++) {
        if (g_slhDsaProfiles[i].profileId == algId) {
            return &g_slhDsaProfiles[i];
        }
    }
    return NULL;
}

CryptSlhDsaCtx *CRYPT_SLH_DSA_NewCtx(void)
{
    CryptSlhDsaCtx *ctx = (CryptSlhDsaCtx *)BSL_SAL_Calloc(sizeof(CryptSlhDsaCtx), 1);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    return ctx;
}

#ifdef HITLS_CRYPTO_PROVIDER
CryptSlhDsaCtx *CRYPT_SLH_DSA_NewCtxEx(void *libCtx)
{
    CryptSlhDsaCtx *ctx = CRYPT_SLH_DSA_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}
#endif /* HITLS_CRYPTO_PROVIDER */

void CRYPT_SLH_DSA_FreeCtx(CryptSlhDsaCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_Free(ctx->context);
    FreeMdCtx(ctx);
    BSL_SAL_ClearFree(ctx, sizeof(CryptSlhDsaCtx));
}

CryptSlhDsaCtx *CRYPT_SLH_DSA_DupCtx(CryptSlhDsaCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CryptSlhDsaCtx *newCtx = CRYPT_SLH_DSA_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    memcpy(newCtx, ctx, sizeof(CryptSlhDsaCtx));
    newCtx->context = NULL;
    newCtx->sha256MdCtx = NULL;
    newCtx->sha512MdCtx = NULL;
    if (ctx->context != NULL) {
        newCtx->context = BSL_SAL_Dump(ctx->context, ctx->contextLen);
        if (newCtx->context == NULL) {
            CRYPT_SLH_DSA_FreeCtx(newCtx);
            return NULL;
        }
    }
    if (ctx->sha256MdCtx != NULL && ctx->sha512MdCtx != NULL) {
        DupMdCtx(newCtx, ctx);
        if (newCtx->sha256MdCtx == NULL || newCtx->sha512MdCtx == NULL) {
            CRYPT_SLH_DSA_FreeCtx(newCtx);
            return NULL;
        }
    }

    return newCtx;
}

static void SlhDsaResetKeyMaterial(CryptSlhDsaCtx *ctx)
{
    FreeMdCtx(ctx);
    BSL_SAL_CleanseData(&ctx->prvKey, sizeof(ctx->prvKey));
    ctx->keyType = 0;
}

int32_t CRYPT_SLH_DSA_Gen(CryptSlhDsaCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->profile == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
        return CRYPT_SLHDSA_ERR_INVALID_ALGID;
    }
    const SlhDsaMathParams *math = ctx->profile->math;
    uint32_t n = math->n;
    uint32_t d = math->d;
    uint32_t hp = math->hp;
    int32_t ret = CRYPT_RandEx(ctx->libCtx, ctx->prvKey.seed, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        SlhDsaResetKeyMaterial(ctx);
        return ret;
    }
    ret = CRYPT_RandEx(ctx->libCtx, ctx->prvKey.prf, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        SlhDsaResetKeyMaterial(ctx);
        return ret;
    }
    ret = CRYPT_RandEx(ctx->libCtx, ctx->prvKey.pub.seed, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        SlhDsaResetKeyMaterial(ctx);
        return ret;
    }

    ret = InitMdCtx(ctx, ctx->prvKey.pub.seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        SlhDsaResetKeyMaterial(ctx);
        return ret;
    }

    SlhDsaAdrs adrs = {0};
    ctx->adrsOps.setLayerAddr(&adrs, d - 1);
    uint8_t node[SLH_DSA_MAX_N] = {0};
    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitFromSlhDsa(&treeCtx, ctx);
    ret = HbsTree_ComputeNode(node, 0, hp, &adrs, &treeCtx, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        SlhDsaResetKeyMaterial(ctx);
        return ret;
    }
    ctx->keyType = SLH_DSA_PRVKEY | SLH_DSA_PUBKEY;
    memcpy(ctx->prvKey.pub.root, node, n);
    return CRYPT_SUCCESS;
}

static int32_t GetAddRand(const CryptSlhDsaCtx *ctx, uint8_t *addrand)
{
    uint32_t n = ctx->profile->math->n;
    if (ctx->isDeterministic) {
        memcpy(addrand, ctx->prvKey.pub.seed, n);
        return CRYPT_SUCCESS;
    }
    return CRYPT_RandEx(ctx->libCtx, addrand, n);
}

static void GetTreeAndLeafIdx(const uint8_t *digest, const CryptSlhDsaCtx *ctx, uint64_t *treeIdx, uint32_t *leafIdx)
{
    const SlhDsaMathParams *math = ctx->profile->math;
    uint32_t a = math->a;
    uint32_t k = math->k;
    uint32_t h = math->h;
    uint32_t d = math->d;
    uint32_t mdIdx = SPLIT_BYTES(k * a);
    uint32_t treeIdxLen = SPLIT_BYTES(h - h / d);
    uint32_t leafIdxLen = SPLIT_BYTES(h / d);
    *treeIdx = ToIntMod(digest + mdIdx, treeIdxLen, h - h / d);
    *leafIdx = (uint32_t)ToIntMod(digest + mdIdx + treeIdxLen, leafIdxLen, h / d);
}

/* FIPS 205 Algorithm 19: slh_sign_internal(M, SK, addrnd). */
int32_t SlhDsaSignInternal(const CryptSlhDsaCtx *ctx, const uint8_t *msg, uint32_t msgLen, const uint8_t *addrand,
    uint8_t *sig, uint32_t *sigLen)
{
    const SlhDsaMathParams *math = ctx->profile->math;
    uint32_t n = math->n;
    uint32_t a = math->a;
    uint32_t k = math->k;
    uint32_t mdIdx = SPLIT_BYTES(k * a);
    uint64_t treeIdx;
    uint32_t leafIdx;

    SlhDsaAdrs adrs = {0};
    uint32_t offset = 0;
    uint32_t left = *sigLen;

    int32_t ret = ctx->hashFuncs->sigRandGen(ctx, addrand, msg, msgLen, sig);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += n;

    uint8_t digest[SLH_DSA_MAX_M] = {0};
    ret = ctx->hashFuncs->msgHash(ctx, sig, msg, msgLen, NULL, digest);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    GetTreeAndLeafIdx(digest, ctx, &treeIdx, &leafIdx);
    ctx->adrsOps.setTreeAddr(&adrs, treeIdx);
    ctx->adrsOps.setType(&adrs, FORS_TREE);
    ctx->adrsOps.setKeyPairAddr(&adrs, leafIdx);
    ret = ForsSign(digest, mdIdx, &adrs, ctx, sig + offset, &left);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t pk[SLH_DSA_MAX_N] = {0};
    ret = ForsPkFromSig(sig + n, left, digest, mdIdx, &adrs, ctx, pk);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += left;
    left = *sigLen - offset;

    ret = HypertreeSign(pk, n, treeIdx, leafIdx, ctx, sig + offset, &left);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *sigLen = offset + left;
    return CRYPT_SUCCESS;
}

int32_t SlhDsaVerifyInternal(const CryptSlhDsaCtx *ctx, const uint8_t *msg, uint32_t msgLen, const uint8_t *sig,
    uint32_t sigLen)
{
    const SlhDsaMathParams *math = ctx->profile->math;
    uint32_t n = math->n;
    uint32_t a = math->a;
    uint32_t k = math->k;
    uint32_t sigBytes = math->sigBytes;
    uint32_t mdIdx = SPLIT_BYTES(k * a);
    uint64_t treeIdx;
    uint32_t leafIdx;

    if (sigLen != sigBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_SIG_LEN);
        return CRYPT_SLHDSA_ERR_INVALID_SIG_LEN;
    }
    SlhDsaAdrs adrs = {0};
    uint32_t offset = 0;

    uint8_t digest[SLH_DSA_MAX_M] = {0};
    int32_t ret = ctx->hashFuncs->msgHash(ctx, sig, msg, msgLen, NULL, digest);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += n;

    GetTreeAndLeafIdx(digest, ctx, &treeIdx, &leafIdx);
    ctx->adrsOps.setTreeAddr(&adrs, treeIdx);
    ctx->adrsOps.setType(&adrs, FORS_TREE);
    ctx->adrsOps.setKeyPairAddr(&adrs, leafIdx);

    uint8_t pk[SLH_DSA_MAX_N] = {0};
    ret = ForsPkFromSig(sig + offset, (1 + a) * k * n, digest, mdIdx, &adrs, ctx, pk);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += (1 + a) * k * n;

    ret = HypertreeVerify(pk, n, sig + offset, sigLen - offset, treeIdx, leafIdx, ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

static uint32_t GetMdSize(const EAL_MdMethod *hashMethod, int32_t hashId)
{
    if (hashId == CRYPT_MD_SHAKE128) {
        return 32;
    }
    if (hashId == CRYPT_MD_SHAKE256) {
        return 64;
    }
    return hashMethod->mdSize;
}

static int32_t SafeAddU32(uint32_t base, uint32_t add, uint32_t *out)
{
    if (base > UINT32_MAX - add) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *out = base + add;
    return CRYPT_SUCCESS;
}

static int32_t MsgEncode(const CryptSlhDsaCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                         uint8_t **mpOut, uint32_t *mpLenOut)
{
    int32_t ret;
    BslOidString *oid = NULL;
    uint32_t offset = 0;
    uint8_t prehash[MAX_DIGEST_SIZE] = {0};
    uint32_t prehashLen = sizeof(prehash);
    uint32_t mpLen = SLH_DSA_PREFIX_LEN;
    RETURN_RET_IF_ERR(SafeAddU32(mpLen, ctx->contextLen, &mpLen), ret);
    if (ctx->profile->isPrehash) {
        if (algId != ctx->profile->prehashId) {
            BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED);
            return CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED;
        }
        const EAL_MdMethod *md = EAL_MdFindDefaultMethod(algId);
        if (md == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED);
            return CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED;
        }
        oid = BSL_OBJ_GetOID((BslCid)algId);
        if (oid == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED);
            return CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED;
        }
        RETURN_RET_IF_ERR(SafeAddU32(mpLen, 2 + oid->octetLen, &mpLen), ret);
        prehashLen = GetMdSize(md, algId);
        const CRYPT_ConstData constData = {data, dataLen};
        ret = CRYPT_CalcHash(NULL, md, &constData, 1, prehash, &prehashLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        RETURN_RET_IF_ERR(SafeAddU32(mpLen, prehashLen, &mpLen), ret);
    } else {
        RETURN_RET_IF_ERR(SafeAddU32(mpLen, dataLen, &mpLen), ret);
    }

    uint8_t *mp = (uint8_t *)BSL_SAL_Malloc(mpLen);
    if (mp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    mp[0] = ctx->profile->isPrehash ? 1 : 0;
    mp[1] = (uint8_t)ctx->contextLen;
    if (ctx->contextLen != 0) {
        memcpy(mp + SLH_DSA_PREFIX_LEN, ctx->context, ctx->contextLen);
    }
    offset += SLH_DSA_PREFIX_LEN + ctx->contextLen;
    if (ctx->profile->isPrehash) {
        (mp + offset)[0] = BSL_ASN1_TAG_OBJECT_ID;
        (mp + offset)[1] = (uint8_t)oid->octetLen;
        offset += 2;
        memcpy(mp + offset, oid->octs, oid->octetLen);
        offset += oid->octetLen;
        memcpy(mp + offset, prehash, prehashLen);
    } else {
        if (dataLen != 0) {
            memcpy(mp + offset, data, dataLen);
        }
    }
    *mpOut = mp;
    *mpLenOut = mpLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_Sign(CryptSlhDsaCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                           uint32_t *signLen)
{
    if (ctx == NULL || (data == NULL && dataLen != 0) || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->profile == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
        return CRYPT_SLHDSA_ERR_INVALID_ALGID;
    }
    if ((ctx->keyType & SLH_DSA_PRVKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_NO_PRVKEY);
        return CRYPT_SLHDSA_ERR_NO_PRVKEY;
    }
    uint32_t sigBytes = ctx->profile->math->sigBytes;
    if (*signLen < sigBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_SIG_LEN);
        return CRYPT_SLHDSA_ERR_INVALID_SIG_LEN;
    }
    uint8_t *mp = NULL;
    uint32_t mpLen = 0;
    int32_t ret = MsgEncode(ctx, algId, data, dataLen, &mp, &mpLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t addrand[SLH_DSA_MAX_N] = {0};
    ret = GetAddRand(ctx, addrand);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_Free(mp);
        return ret;
    }
    ret = SlhDsaSignInternal(ctx, mp, mpLen, addrand, sign, signLen);
    BSL_SAL_CleanseData(addrand, sizeof(addrand));
    BSL_SAL_Free(mp);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_CleanseData(sign, sigBytes);
    }
    return ret;
}

int32_t CRYPT_SLH_DSA_Verify(const CryptSlhDsaCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                             const uint8_t *sign, uint32_t signLen)
{
    if (ctx == NULL || (data == NULL && dataLen != 0) || sign == NULL || signLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->profile == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
        return CRYPT_SLHDSA_ERR_INVALID_ALGID;
    }
    if ((ctx->keyType & (SLH_DSA_PUBKEY | SLH_DSA_PRVKEY)) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_NO_PUBKEY);
        return CRYPT_SLHDSA_ERR_NO_PUBKEY;
    }
    uint8_t *mp = NULL;
    uint32_t mpLen = 0;
    int32_t ret = MsgEncode(ctx, algId, data, dataLen, &mp, &mpLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = SlhDsaVerifyInternal(ctx, mp, mpLen, sign, signLen);
    BSL_SAL_Free(mp);
    return ret;
}

static int32_t SlhDsaSetAlgId(CryptSlhDsaCtx *ctx, void *val, uint32_t len)
{
    if (val == NULL || len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx->profile != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_CTRL_INIT_REPEATED);
        return CRYPT_SLHDSA_CTRL_INIT_REPEATED;
    }
    int32_t algId = *(int32_t *)val;
    const SlhDsaProfileInfo *profile = SlhDsaFindProfile(algId);
    if (profile == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
        return CRYPT_SLHDSA_ERR_INVALID_ALGID;
    }
    const HbsHashFuncs *hashFuncs = NULL;
    HbsAdrsOps adrsOps;
    int32_t ret = SlhDsaResolveMathMethods(profile->math->hashFamily, &hashFuncs, &adrsOps);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ctx->profile = profile;
    ctx->hashFuncs = hashFuncs;
    ctx->adrsOps = adrsOps;
    return CRYPT_SUCCESS;
}

static int32_t SetContextInfo(CryptSlhDsaCtx *ctx, void *val, uint32_t len)
{
    if (val == NULL && len != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (len > 255) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_CONTEXT_LEN_OVERFLOW);
        return CRYPT_SLHDSA_ERR_CONTEXT_LEN_OVERFLOW;
    }
    uint8_t *newContext = NULL;
    if (len != 0) {
        newContext = BSL_SAL_Dump(val, len);
        if (newContext == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    BSL_SAL_FREE(ctx->context);
    ctx->contextLen = len;
    ctx->context = newContext;
    return CRYPT_SUCCESS;
}

static int32_t SlhDsaGetParaId(CryptSlhDsaCtx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(int32_t) || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx->profile == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
        return CRYPT_SLHDSA_ERR_INVALID_ALGID;
    }
    *(int32_t *)val = ctx->profile->profileId;
    return CRYPT_SUCCESS;
}

static int32_t GetSignLen(const CryptSlhDsaCtx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(uint32_t) || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx->profile == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
        return CRYPT_SLHDSA_ERR_INVALID_ALGID;
    }
    *(uint32_t *)val = ctx->profile->math->sigBytes;
    return CRYPT_SUCCESS;
}

static int32_t SlhDsaGetSecBits(const CryptSlhDsaCtx *ctx, void *val, uint32_t len)
{
    if (val == NULL || len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    // FIPS 205 Table 2: secCategory 1->128-bit, 3->192-bit, 5->256-bit
    if (ctx->profile == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
        return CRYPT_SLHDSA_ERR_INVALID_ALGID;
    }
    switch (ctx->profile->math->secCategory) {
        case 1:
            *(int32_t *)val = 128;
            break;
        case 3:
            *(int32_t *)val = 192;
            break;
        case 5:
            *(int32_t *)val = 256;
            break;
        default:
            return CRYPT_INVALID_ARG;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_Ctrl(CryptSlhDsaCtx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            return SlhDsaSetAlgId(ctx, val, len);
        case CRYPT_CTRL_GET_PARAID:
            return SlhDsaGetParaId(ctx, val, len);
        case CRYPT_CTRL_GET_SIGNLEN:
            return GetSignLen(ctx, val, len);
        case CRYPT_CTRL_SET_CTX_INFO:
            return SetContextInfo(ctx, val, len);
        case CRYPT_CTRL_GET_SLH_DSA_KEY_LEN:
            if (val == NULL || len != sizeof(uint32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            if (ctx->profile == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
                return CRYPT_SLHDSA_ERR_INVALID_ALGID;
            }
            *(uint32_t *)val = ctx->profile->math->n;
            return CRYPT_SUCCESS;
        /* Supports bidirectional switching between deterministic and non-deterministic modes. */
        case CRYPT_CTRL_SET_DETERMINISTIC_FLAG:
            if (val == NULL || len != sizeof(bool)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            ctx->isDeterministic = *(bool *)val;
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_CLEAN_PUB_KEY:
            BSL_SAL_CleanseData(ctx->prvKey.pub.seed, sizeof(ctx->prvKey.pub.seed));
            BSL_SAL_CleanseData(ctx->prvKey.pub.root, sizeof(ctx->prvKey.pub.root));
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_GET_SECBITS:
            return SlhDsaGetSecBits(ctx, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

static int32_t PubKeyParamCheck(const CryptSlhDsaCtx *ctx, BSL_Param *para, SlhDsaPubKeyParam *pub)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->profile == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
        return CRYPT_SLHDSA_ERR_INVALID_ALGID;
    }
    pub->pubSeed = EAL_FindParam(para, CRYPT_PARAM_SLH_DSA_PUB_SEED);
    pub->pubRoot = EAL_FindParam(para, CRYPT_PARAM_SLH_DSA_PUB_ROOT);
    if (pub->pubSeed == NULL || pub->pubSeed->value == NULL || pub->pubRoot == NULL || pub->pubRoot->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pub->pubSeed->valueLen != ctx->profile->math->n || pub->pubRoot->valueLen != ctx->profile->math->n) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
        return CRYPT_SLHDSA_ERR_INVALID_KEYLEN;
    }
    return CRYPT_SUCCESS;
}

static int32_t PrvKeyParamCheck(const CryptSlhDsaCtx *ctx, BSL_Param *para, SlhDsaPrvKeyParam *prv)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->profile == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
        return CRYPT_SLHDSA_ERR_INVALID_ALGID;
    }
    prv->prvSeed = EAL_FindParam(para, CRYPT_PARAM_SLH_DSA_PRV_SEED);
    prv->prvPrf = EAL_FindParam(para, CRYPT_PARAM_SLH_DSA_PRV_PRF);
    prv->pubSeed = EAL_FindParam(para, CRYPT_PARAM_SLH_DSA_PUB_SEED);
    prv->pubRoot = EAL_FindParam(para, CRYPT_PARAM_SLH_DSA_PUB_ROOT);
    if (prv->prvSeed == NULL || prv->prvSeed->value == NULL || prv->prvPrf == NULL || prv->prvPrf->value == NULL ||
        prv->pubSeed == NULL || prv->pubSeed->value == NULL || prv->pubRoot == NULL || prv->pubRoot->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t n = ctx->profile->math->n;
    if (prv->prvSeed->valueLen != n || prv->prvPrf->valueLen != n || prv->pubSeed->valueLen != n ||
        prv->pubRoot->valueLen != n) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
        return CRYPT_SLHDSA_ERR_INVALID_KEYLEN;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_GetPubKeyEx(const CryptSlhDsaCtx *ctx, BSL_Param *para)
{
    SlhDsaPubKeyParam pub;
    int32_t ret = PubKeyParamCheck(ctx, para, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if ((ctx->keyType & SLH_DSA_PUBKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_NO_PUBKEY);
        return CRYPT_SLHDSA_ERR_NO_PUBKEY;
    }
    uint32_t n = ctx->profile->math->n;
    pub.pubSeed->useLen = pub.pubRoot->useLen = n;
    memcpy(pub.pubSeed->value, ctx->prvKey.pub.seed, n);
    memcpy(pub.pubRoot->value, ctx->prvKey.pub.root, n);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_GetPrvKeyEx(const CryptSlhDsaCtx *ctx, BSL_Param *para)
{
    SlhDsaPrvKeyParam prv;
    int32_t ret = PrvKeyParamCheck(ctx, para, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if ((ctx->keyType & SLH_DSA_PRVKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_NO_PRVKEY);
        return CRYPT_SLHDSA_ERR_NO_PRVKEY;
    }
    uint32_t n = ctx->profile->math->n;
    prv.prvSeed->useLen = prv.prvPrf->useLen = prv.pubSeed->useLen = prv.pubRoot->useLen = n;
    memcpy(prv.prvSeed->value, ctx->prvKey.seed, n);
    memcpy(prv.prvPrf->value, ctx->prvKey.prf, n);
    memcpy(prv.pubSeed->value, ctx->prvKey.pub.seed, n);
    memcpy(prv.pubRoot->value, ctx->prvKey.pub.root, n);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_SetPubKeyEx(CryptSlhDsaCtx *ctx, const BSL_Param *para)
{
    SlhDsaPubKeyParam pub;
    int32_t ret = PubKeyParamCheck(ctx, (BSL_Param *)(uintptr_t)para, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t n = ctx->profile->math->n;
    if ((ctx->keyType & SLH_DSA_PUBKEY) != 0) {
        if (memcmp(ctx->prvKey.pub.seed, pub.pubSeed->value, n) != 0 ||
            memcmp(ctx->prvKey.pub.root, pub.pubRoot->value, n) != 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_KEY_EXISTS);
            return CRYPT_SLHDSA_ERR_KEY_EXISTS;
        }
        return CRYPT_SUCCESS;
    }
    ret = InitMdCtx(ctx, pub.pubSeed->value);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    memcpy(ctx->prvKey.pub.seed, pub.pubSeed->value, n);
    memcpy(ctx->prvKey.pub.root, pub.pubRoot->value, n);
    ctx->keyType |= SLH_DSA_PUBKEY;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_SetPrvKeyEx(CryptSlhDsaCtx *ctx, const BSL_Param *para)
{
    SlhDsaPrvKeyParam prv;
    int32_t ret = PrvKeyParamCheck(ctx, (BSL_Param *)(uintptr_t)para, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t n = ctx->profile->math->n;
    ret = InitMdCtx(ctx, prv.pubSeed->value);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    memcpy(ctx->prvKey.seed, prv.prvSeed->value, n);
    memcpy(ctx->prvKey.prf, prv.prvPrf->value, n);
    memcpy(ctx->prvKey.pub.seed, prv.pubSeed->value, n);
    memcpy(ctx->prvKey.pub.root, prv.pubRoot->value, n);
    ctx->keyType = SLH_DSA_PRVKEY | SLH_DSA_PUBKEY;
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_SLH_DSA_CHECK

static int32_t SlhDsaComputeRoot(const CryptSlhDsaCtx *prvKey, uint8_t *root)
{
    SlhDsaAdrs adrs = {0};
    const SlhDsaMathParams *math = prvKey->profile->math;
    prvKey->adrsOps.setLayerAddr(&adrs, math->d - 1);
    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitFromSlhDsa(&treeCtx, prvKey);
    return HbsTree_ComputeNode(root, 0, math->hp, &adrs, &treeCtx, NULL, 0);
}

static int32_t SlhDsaKeyPairCheck(const CryptSlhDsaCtx *pubKey, const CryptSlhDsaCtx *prvKey)
{
    if (pubKey == NULL || prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->profile == NULL || prvKey->profile == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
        return CRYPT_SLHDSA_ERR_INVALID_ALGID;
    }
    if (pubKey->profile != prvKey->profile) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_PAIRWISE_CHECK_FAIL);
        return CRYPT_SLHDSA_PAIRWISE_CHECK_FAIL;
    }
    if ((pubKey->keyType & SLH_DSA_PUBKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_NO_PUBKEY);
        return CRYPT_SLHDSA_ERR_NO_PUBKEY;
    }
    if ((prvKey->keyType & SLH_DSA_PRVKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_NO_PRVKEY);
        return CRYPT_SLHDSA_ERR_NO_PRVKEY;
    }
    const SlhDsaMathParams *math = prvKey->profile->math;
    if (memcmp(pubKey->prvKey.pub.seed, prvKey->prvKey.pub.seed, math->n) != 0 ||
        memcmp(pubKey->prvKey.pub.root, prvKey->prvKey.pub.root, math->n) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_PAIRWISE_CHECK_FAIL);
        return CRYPT_SLHDSA_PAIRWISE_CHECK_FAIL;
    }
    uint8_t node[SLH_DSA_MAX_N] = {0};
    int32_t ret = SlhDsaComputeRoot(prvKey, node);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (memcmp(node, prvKey->prvKey.pub.root, math->n) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_PAIRWISE_CHECK_FAIL);
        return CRYPT_SLHDSA_PAIRWISE_CHECK_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t SlhDsaPrvKeyCheck(const CryptSlhDsaCtx *prvKey)
{
    if (prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prvKey->profile == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
        return CRYPT_SLHDSA_ERR_INVALID_ALGID;
    }
    if ((prvKey->keyType & SLH_DSA_PRVKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_NO_PRVKEY);
        return CRYPT_SLHDSA_ERR_NO_PRVKEY;
    }
    uint8_t node[SLH_DSA_MAX_N] = {0};
    int32_t ret = SlhDsaComputeRoot(prvKey, node);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (memcmp(node, prvKey->prvKey.pub.root, prvKey->profile->math->n) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_ROOT_MISMATCH);
        return CRYPT_SLHDSA_ERR_ROOT_MISMATCH;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_Check(uint32_t checkType, const CryptSlhDsaCtx *pkey1, const CryptSlhDsaCtx *pkey2)
{
    switch (checkType) {
        case CRYPT_PKEY_CHECK_KEYPAIR:
            return SlhDsaKeyPairCheck(pkey1, pkey2);
        case CRYPT_PKEY_CHECK_PRVKEY:
            return SlhDsaPrvKeyCheck(pkey1);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
}

#endif /* HITLS_CRYPTO_SLH_DSA_CHECK */

#endif /* HITLS_CRYPTO_SLH_DSA */

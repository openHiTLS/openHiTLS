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

#include <string.h>
#include "crypt_errno.h"
#include "crypt_util_rand.h"
#include "crypt_utils.h"
#include "xmss_local.h"
#include "xmss_hash.h"

void HbsTreeCtx_InitFromXmss(HbsTreeCtx *treeCtx, const CryptXmssCtx *ctx)
{
    treeCtx->n = ctx->params->n;
    treeCtx->hp = ctx->params->hp;
    treeCtx->d = ctx->params->d;
    treeCtx->otsLen = ctx->params->wotsLen;

    treeCtx->pubSeed = ctx->key.pubSeed;
    treeCtx->skSeed = ctx->key.seed;
    treeCtx->root = ctx->key.root;

    treeCtx->hashFuncs.xmss = ctx->hashFuncs;
    treeCtx->adrsOps = &ctx->adrsOps;
    treeCtx->originalCtx = (const void *)ctx;
    treeCtx->algoType = HBS_ALGO_XMSS;
}

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
    memset(&ctx->key, 0, sizeof(ctx->key));

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
    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitFromXmss(&treeCtx, ctx);
    uint8_t node[XMSS_MAX_MDSIZE] = {0};
    ret = HbsTree_ComputeNode(node, 0, hp, &adrs, &treeCtx, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(node, sizeof(node));
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    memcpy(ctx->key.root, node, n);
    BSL_SAL_CleanseData(node, sizeof(node));
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
    /* Check key expiration; wrap-around safe for h == 64. */
    uint64_t max_idx = (h == 64) ? (UINT64_MAX - 1) : ((1ULL << h) - 1);
    if (ctx->key.idx > max_idx) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_KEY_EXPIRED);
        return CRYPT_XMSS_ERR_KEY_EXPIRED;
    }
    /*
     * Read the current index and advance ctx->key.idx BEFORE producing the
     * signature.  XMSS / XMSS^MT are stateful: each (idx, secret seed) pair is
     * a one-time WOTS+ key.  If we deferred the bump and the signing path
     * failed partway through (sigRandGen / msgHash / HbsHyperTree_Sign),
     * a caller that retries with a different message would reuse the same
     * (idx, seed) pair — that exposes the WOTS+ private key (RFC 8391 §1).
     * Persist the advance first; we trade one wasted leaf on failure for the
     * impossibility of one-time-key reuse.
     */
    uint64_t index = ctx->key.idx;
    ctx->key.idx = index + 1;
    /* XMSS: 4-bytes index_bytes, XMSSMT: (ceil(h / 8))-bytes index_bytes */
    uint32_t idxBytes = (d == 1) ? 4 : (h + 7) / 8;
    uint32_t offset = 0;

    /* Write index (big-endian) */
    U64toBytes(sig, idxBytes, index);
    offset += idxBytes;

    uint8_t idx[XMSS_MAX_MDSIZE] = {0};
    PUT_UINT64_BE(index, idx, sizeof(idx) - 8); // Put index in last 8 bytes

    ret = ctx->hashFuncs->sigRandGen(ctx, idx + sizeof(idx) - 32, NULL, 0, sig + offset);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t digest[XMSS_MAX_MDSIZE] = {0};
    ret = ctx->hashFuncs->msgHash(ctx, sig + offset, msg, msgLen, idx + sizeof(idx) - n, digest);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(digest, sizeof(digest));
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += n;
    if (offset > *sigLen) {
        BSL_SAL_CleanseData(digest, sizeof(digest));
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_SIG_LEN);
        return CRYPT_XMSS_ERR_INVALID_SIG_LEN;
    }
    uint32_t left = *sigLen - offset;
    uint32_t leafIdx = (uint32_t)(index & ((1ULL << hp) - 1));
    uint64_t treeIdx = index >> hp;
    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitFromXmss(&treeCtx, ctx);
    ret = HbsHyperTree_Sign(digest, n, treeIdx, leafIdx, &treeCtx, sig + offset, &left);
    BSL_SAL_CleanseData(digest, sizeof(digest));
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
    ret = ctx->hashFuncs->msgHash(ctx, sig + offset, msg, msgLen, idx + sizeof(idx) - n, digest);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += n;
    // Force 64-bit arithmetic with 1ULL to avoid potential overflow on 32-bit systems
    uint32_t leafIdx = (uint32_t)(index & ((1ULL << hp) - 1));
    uint64_t treeIdx = index >> hp;
    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitFromXmss(&treeCtx, ctx);
    ret = HbsHyperTree_Verify(digest, n, sig + offset, sigLen - offset, treeIdx, leafIdx, &treeCtx);
    BSL_SAL_CleanseData(digest, sizeof(digest));
    return ret;
}

/* --------------------------------------------------------------------------
 * Public API (moved from xmss.c per HBS refactoring design §2.3.2)
 * -------------------------------------------------------------------------- */

#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_params.h"
#include "crypt_algid.h"
#include "crypt_params_key.h"
#include "crypt_xmss.h"

typedef struct {
    BSL_Param *pubXdr;
    BSL_Param *pubSeed;
    BSL_Param *pubRoot;
} XmssPubKeyParam;

typedef struct {
    BSL_Param *prvIndex;
    BSL_Param *prvSeed;
    BSL_Param *prvPrf;
    BSL_Param *pubSeed;
    BSL_Param *pubRoot;
} XmssPrvKeyParam;

CryptXmssCtx *CRYPT_XMSS_NewCtx(void)
{
    CryptXmssCtx *ctx = (CryptXmssCtx *)BSL_SAL_Calloc(sizeof(CryptXmssCtx), 1);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    return ctx;
}

CryptXmssCtx *CRYPT_XMSS_NewCtxEx(void *libCtx)
{
    CryptXmssCtx *ctx = CRYPT_XMSS_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

void CRYPT_XMSS_FreeCtx(CryptXmssCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_ClearFree(ctx, sizeof(CryptXmssCtx));
}

CryptXmssCtx *CRYPT_XMSS_DupCtx(CryptXmssCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CryptXmssCtx *newCtx = CRYPT_XMSS_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    newCtx->libCtx = ctx->libCtx;
    newCtx->params = ctx->params;
    newCtx->hashFuncs = ctx->hashFuncs;
    newCtx->adrsOps = ctx->adrsOps;
    memcpy(newCtx->key.pubSeed, ctx->key.pubSeed, XMSS_MAX_SEED_SIZE);
    memcpy(newCtx->key.root, ctx->key.root, XMSS_MAX_MDSIZE);
    return newCtx;
}

static bool CheckNotXmssAlgId(int32_t algId)
{
    if (algId > CRYPT_XMSSMT_SHAKE256_60_12_192 || algId < CRYPT_XMSS_SHA2_10_256) {
        return true;
    }
    return false;
}

static int32_t XmssSetAlgId(CryptXmssCtx *ctx, CRYPT_PKEY_ParaId algId)
{
    const XmssParams *para = FindXmssPara(algId);
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_ALGID);
        return CRYPT_XMSS_ERR_INVALID_ALGID;
    }
    int32_t ret = CRYPT_XMSS_InitInternal(ctx, para);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_ALGID);
        return CRYPT_XMSS_ERR_INVALID_ALGID;
    }
    return CRYPT_SUCCESS;
}

static int32_t XmssSetParaId(CryptXmssCtx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t algId = *(int32_t *)val;
    if (CheckNotXmssAlgId(algId)) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_ALGID);
        return CRYPT_XMSS_ERR_INVALID_ALGID;
    }
    return XmssSetAlgId(ctx, algId);
}

static int32_t XmssGetPubkeyLen(CryptXmssCtx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *(uint32_t *)val = ctx->params->n * 2 + HASH_SIGN_XDR_ALG_TYPE_LEN;
    return CRYPT_SUCCESS;
}

static int32_t XmssGetSignatureLen(CryptXmssCtx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *(uint32_t *)val = ctx->params->sigBytes;
    return CRYPT_SUCCESS;
}

static int32_t XmssGetParaId(CryptXmssCtx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx->params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    *(int32_t *)val = (int32_t)ctx->params->algId;
    return CRYPT_SUCCESS;
}

static int32_t XmssGetXdrAlgBuff(CryptXmssCtx *ctx, void *val, uint32_t len)
{
    if (len < HASH_SIGN_XDR_ALG_TYPE_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx->params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    memcpy(val, ctx->params->xdrAlgId, HASH_SIGN_XDR_ALG_TYPE_LEN);
    return CRYPT_SUCCESS;
}

static int32_t XmssSetXdrAlgId(CryptXmssCtx *ctx, void *val, uint32_t len)
{
    if (val == NULL || len < HASH_SIGN_XDR_ALG_TYPE_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint32_t xdrId = GET_UINT32_BE((const uint8_t *)val, 0);
    const XmssParams *params = XmssParams_FindByXdrId(xdrId);
    if (params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_XDR_ID);
        return CRYPT_XMSS_ERR_INVALID_XDR_ID;
    }
    int32_t ret = CRYPT_XMSS_InitInternal(ctx, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_XMSS_Ctrl(CryptXmssCtx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            return XmssSetParaId(ctx, val, len);
        case CRYPT_CTRL_GET_PARAID:
            return XmssGetParaId(ctx, val, len);
        case CRYPT_CTRL_GET_XMSS_XDR_ALG_TYPE:
            return XmssGetXdrAlgBuff(ctx, val, len);
        case CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE:
            return XmssSetXdrAlgId(ctx, val, len);
        case CRYPT_CTRL_GET_SIGNLEN:
            return XmssGetSignatureLen(ctx, val, len);
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            return XmssGetPubkeyLen(ctx, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

int32_t CRYPT_XMSS_Gen(CryptXmssCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->params == NULL || CheckNotXmssAlgId(ctx->params->algId)) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_ALGID);
        return CRYPT_XMSS_ERR_INVALID_ALGID;
    }
    int32_t ret = CRYPT_XMSS_KeyGenInternal(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_XMSS_Sign(CryptXmssCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                        uint32_t *signLen)
{
    (void)algId;
    if (ctx == NULL || data == NULL || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_XMSS_SignInternal(ctx, data, dataLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_XMSS_Verify(const CryptXmssCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                          const uint8_t *sign, uint32_t signLen)
{
    (void)algId;
    if (ctx == NULL || data == NULL || sign == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_XMSS_VerifyInternal(ctx, data, dataLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

static int32_t XPubKeyParamCheck(BSL_Param *para, XmssPubKeyParam *pub)
{
    pub->pubSeed = BSL_PARAM_FindParam(para, CRYPT_PARAM_XMSS_PUB_SEED);
    pub->pubRoot = BSL_PARAM_FindParam(para, CRYPT_PARAM_XMSS_PUB_ROOT);
    pub->pubXdr = BSL_PARAM_FindParam(para, CRYPT_PARAM_XMSS_XDR_TYPE);
    if (pub->pubSeed == NULL || pub->pubSeed->value == NULL || pub->pubRoot == NULL || pub->pubRoot->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pub->pubXdr != NULL && (pub->pubXdr->value == NULL || pub->pubXdr->valueLen != HASH_SIGN_XDR_ALG_TYPE_LEN)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_KEY);
        return CRYPT_INVALID_KEY;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_XMSS_GetPubKey(const CryptXmssCtx *ctx, BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    XmssPubKeyParam pub;
    int32_t ret = XPubKeyParamCheck(para, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (pub.pubXdr != NULL) {
        if (HASH_SIGN_XDR_ALG_TYPE_LEN > pub.pubXdr->valueLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_XMSS_LEN_NOT_ENOUGH);
            return CRYPT_XMSS_LEN_NOT_ENOUGH;
        }
        memcpy(pub.pubXdr->value, ctx->params->xdrAlgId, HASH_SIGN_XDR_ALG_TYPE_LEN);
        pub.pubXdr->useLen = HASH_SIGN_XDR_ALG_TYPE_LEN;
    }
    if (ctx->params->n > pub.pubSeed->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_LEN_NOT_ENOUGH);
        return CRYPT_XMSS_LEN_NOT_ENOUGH;
    }
    memcpy(pub.pubSeed->value, ctx->key.pubSeed, ctx->params->n);
    pub.pubSeed->useLen = ctx->params->n;
    if (ctx->params->n > pub.pubRoot->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_LEN_NOT_ENOUGH);
        return CRYPT_XMSS_LEN_NOT_ENOUGH;
    }
    memcpy(pub.pubRoot->value, ctx->key.root, ctx->params->n);
    pub.pubRoot->useLen = ctx->params->n;
    return CRYPT_SUCCESS;
}

static int32_t XPrvKeyParamCheck(const CryptXmssCtx *ctx, BSL_Param *para, XmssPrvKeyParam *prv)
{
    prv->prvIndex = BSL_PARAM_FindParam(para, CRYPT_PARAM_XMSS_PRV_INDEX);
    prv->prvSeed = BSL_PARAM_FindParam(para, CRYPT_PARAM_XMSS_PRV_SEED);
    prv->prvPrf = BSL_PARAM_FindParam(para, CRYPT_PARAM_XMSS_PRV_PRF);
    prv->pubSeed = BSL_PARAM_FindParam(para, CRYPT_PARAM_XMSS_PUB_SEED);
    prv->pubRoot = BSL_PARAM_FindParam(para, CRYPT_PARAM_XMSS_PUB_ROOT);
    if (prv->prvIndex == NULL || prv->prvIndex->value == NULL || prv->prvSeed == NULL || prv->prvSeed->value == NULL ||
        prv->prvPrf == NULL || prv->prvPrf->value == NULL || prv->pubSeed == NULL || prv->pubSeed->value == NULL ||
        prv->pubRoot == NULL || prv->pubRoot->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prv->prvIndex->valueLen != sizeof(ctx->key.idx) || prv->prvSeed->valueLen != ctx->params->n ||
        prv->prvPrf->valueLen != ctx->params->n || prv->pubSeed->valueLen != ctx->params->n ||
        prv->pubRoot->valueLen != ctx->params->n) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_KEYLEN);
        return CRYPT_XMSS_ERR_INVALID_KEYLEN;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_XMSS_GetPrvKey(const CryptXmssCtx *ctx, BSL_Param *para)
{
    XmssPrvKeyParam prv;
    uint64_t index = ctx->key.idx;
    int32_t ret = XPrvKeyParamCheck(ctx, para, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    prv.prvSeed->useLen = ctx->params->n;
    prv.prvPrf->useLen = ctx->params->n;
    prv.pubSeed->useLen = ctx->params->n;
    prv.pubRoot->useLen = ctx->params->n;
    memcpy(prv.prvSeed->value, ctx->key.seed, ctx->params->n);
    memcpy(prv.prvPrf->value, ctx->key.prf, ctx->params->n);
    memcpy(prv.pubSeed->value, ctx->key.pubSeed, ctx->params->n);
    memcpy(prv.pubRoot->value, ctx->key.root, ctx->params->n);
    return BSL_PARAM_SetValue(prv.prvIndex, CRYPT_PARAM_XMSS_PRV_INDEX, BSL_PARAM_TYPE_UINT64, &index, sizeof(index));
}

int32_t CRYPT_XMSS_SetPubKey(CryptXmssCtx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    XmssPubKeyParam pub;
    int32_t ret = XPubKeyParamCheck((BSL_Param *)(uintptr_t)para, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (pub.pubXdr != NULL) {
        uint32_t xdrId = GET_UINT32_BE((uint8_t *)pub.pubXdr->value, 0);
        const XmssParams *params = XmssParams_FindByXdrId(xdrId);
        if (params == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_XDR_ID);
            return CRYPT_XMSS_ERR_INVALID_XDR_ID;
        }
        if (params->algId != ctx->params->algId) {
            BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_XDR_ID_UNMATCH);
            return CRYPT_XMSS_ERR_XDR_ID_UNMATCH;
        }
    }
    if (pub.pubSeed->valueLen != ctx->params->n || pub.pubRoot->valueLen != ctx->params->n) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_KEYLEN);
        return CRYPT_XMSS_ERR_INVALID_KEYLEN;
    }
    memcpy(ctx->key.pubSeed, pub.pubSeed->value, pub.pubSeed->valueLen);
    memcpy(ctx->key.root, pub.pubRoot->value, pub.pubRoot->valueLen);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_XMSS_SetPrvKey(CryptXmssCtx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    XmssPrvKeyParam prv;
    uint32_t tmplen = sizeof(ctx->key.idx);
    int32_t ret = XPrvKeyParamCheck(ctx, (BSL_Param *)(uintptr_t)para, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    memcpy(ctx->key.seed, prv.prvSeed->value, ctx->params->n);
    memcpy(ctx->key.prf, prv.prvPrf->value, ctx->params->n);
    memcpy(ctx->key.pubSeed, prv.pubSeed->value, ctx->params->n);
    memcpy(ctx->key.root, prv.pubRoot->value, ctx->params->n);
    return BSL_PARAM_GetValue(prv.prvIndex, CRYPT_PARAM_XMSS_PRV_INDEX, BSL_PARAM_TYPE_UINT64, &ctx->key.idx, &tmplen);
}

#ifdef HITLS_CRYPTO_XMSS_CHECK

static int32_t XMSSKeyPairCheck(const CryptXmssCtx *pubKey, const CryptXmssCtx *prvKey)
{
    if (pubKey == NULL || prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prvKey->params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    if (pubKey->params->algId != prvKey->params->algId) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_XMSS_PAIRWISE_CHECK_FAIL;
    }
    uint32_t n = prvKey->params->n;
    uint32_t d = prvKey->params->d;
    uint32_t hp = prvKey->params->hp;
    XmssAdrs adrs;
    memset(&adrs, 0, sizeof(XmssAdrs));
    prvKey->adrsOps.setLayerAddr(&adrs, d - 1);
    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitFromXmss(&treeCtx, prvKey);
    uint8_t node[XMSS_MAX_MDSIZE] = {0};
    int32_t ret = HbsTree_ComputeNode(node, 0, hp, &adrs, &treeCtx, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t diff = 0;
    for (uint32_t i = 0; i < n; i++) {
        diff |= node[i] ^ pubKey->key.root[i];
    }
    if (diff != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_XMSS_PAIRWISE_CHECK_FAIL;
    }
    diff = 0;
    for (uint32_t i = 0; i < n; i++) {
        diff |= prvKey->key.pubSeed[i] ^ pubKey->key.pubSeed[i];
    }
    if (diff != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_XMSS_PAIRWISE_CHECK_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t XMSSPrvKeyCheck(const CryptXmssCtx *prvKey)
{
    if (prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prvKey->params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    if (prvKey->params->algId == 0 || prvKey->params->n == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_INVALID_PRVKEY);
        return CRYPT_XMSS_INVALID_PRVKEY;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_XMSS_Check(uint32_t checkType, const CryptXmssCtx *pkey1, const CryptXmssCtx *pkey2)
{
    switch (checkType) {
        case CRYPT_PKEY_CHECK_KEYPAIR:
            return XMSSKeyPairCheck(pkey1, pkey2);
        case CRYPT_PKEY_CHECK_PRVKEY:
            return XMSSPrvKeyCheck(pkey1);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
}

#endif /* HITLS_CRYPTO_XMSS_CHECK */

#endif /* HITLS_CRYPTO_XMSS */

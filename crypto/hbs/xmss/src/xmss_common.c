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
#include "bsl_bytes.h"
#include "bsl_err_internal.h"
#include "bsl_params.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_local_types.h"
#include "crypt_params_key.h"
#include "crypt_util_rand.h"
#include "crypt_utils.h"
#include "xmss_bds.h"
#include "xmss_hash.h"
#include "xmss_local.h"

XmssCtxCommon *XmssCommonNew(void)
{
    return (XmssCtxCommon *)BSL_SAL_Calloc(1, sizeof(XmssCtxCommon));
}

void XmssCommonFree(XmssCtxCommon *ctx)
{
    BSL_SAL_ClearFree(ctx, sizeof(XmssCtxCommon));
}

int32_t XmssInitInternal(XmssCtxCommon *ctx, uint32_t n, CRYPT_MD_AlgId mdId, uint32_t paddingLen)
{
    ctx->n = n;
    ctx->mdId = mdId;
    ctx->paddingLen = paddingLen;

    int32_t ret = XmssInitHashFuncs(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = XmssAdrsOps_Init(&ctx->adrsOps);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    memset(&ctx->key, 0, sizeof(ctx->key));
    ctx->hasPrivateKey = false;

    return CRYPT_SUCCESS;
}

int32_t XmssGenerateKeyMaterial(XmssCtxCommon *ctx, uint32_t n)
{
    int32_t ret;
    ctx->hasPrivateKey = false;

    ret = CRYPT_RandEx(ctx->libCtx, ctx->key.seed, n);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = CRYPT_RandEx(ctx->libCtx, ctx->key.prf, n);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = CRYPT_RandEx(ctx->libCtx, ctx->key.pubSeed, n);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ctx->key.idx = 0;
    return CRYPT_SUCCESS;
}

int32_t XmssCheckSignReady(const XmssCtxCommon *ctx, const uint8_t *data, const uint8_t *sign,
                           const uint32_t *signLen, bool hasParams)
{
    if (ctx == NULL || data == NULL || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (!hasParams) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    if (!ctx->hasPrivateKey) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    return CRYPT_SUCCESS;
}

int32_t XmssPrepareSignData(const XmssSignPrepareInput *input, XmssSignPrepareResult *result)
{
    int32_t ret;
    if (input == NULL || result == NULL || input->ctx == NULL || input->msg == NULL || input->sig == NULL ||
        input->sigLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    XmssCtxCommon *ctx = input->ctx;
    uint32_t n = ctx->n;
    result->idxConsumed = false;
    if (*input->sigLen < input->sigBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_SIG_LEN);
        return CRYPT_XMSS_ERR_INVALID_SIG_LEN;
    }
    if (input->h > XMSS_MAX_H) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (input->idxBytes > sizeof(uint64_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx->key.idx > (1ULL << input->h) - 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_KEY_EXPIRED);
        return CRYPT_XMSS_ERR_KEY_EXPIRED;
    }

    result->index = ctx->key.idx;
    ctx->key.idx = result->index + 1;
    result->idxConsumed = true;
    result->offset = 0;

    uint8_t indexBytes[sizeof(uint64_t)] = {0};
    Uint64ToBeBytes(result->index, indexBytes);
    memcpy(input->sig, indexBytes + sizeof(indexBytes) - input->idxBytes, input->idxBytes);
    result->offset += input->idxBytes;

    uint8_t idx[XMSS_MAX_MDSIZE] = {0};
    PUT_UINT64_BE(result->index, idx, sizeof(idx) - 8);

    ret = ctx->hashFuncs->sigRandGen(ctx, idx + sizeof(idx) - 32, NULL, 0, input->sig + result->offset);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = ctx->hashFuncs->msgHash(ctx, input->sig + result->offset, input->msg, input->msgLen,
                                  idx + sizeof(idx) - n, result->digest);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    result->offset += n;
    if (result->offset > *input->sigLen) {
        return CRYPT_XMSS_ERR_INVALID_SIG_LEN;
    }
    return CRYPT_SUCCESS;
}

int32_t XmssCheckVerifyReady(const XmssCtxCommon *ctx, const uint8_t *data, const uint8_t *sign, bool hasParams)
{
    if (ctx == NULL || data == NULL || sign == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (!hasParams) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    return CRYPT_SUCCESS;
}

int32_t XmssBuildVerifyDigest(const XmssCtxCommon *ctx, const uint8_t *msg, uint32_t msgLen, const uint8_t *sig,
                              uint32_t sigLen, uint32_t idxBytes, uint64_t *index, uint32_t *offset, uint8_t *digest,
                              uint32_t sigBytes)
{
    if (sigLen != sigBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_SIG_LEN);
        return CRYPT_XMSS_ERR_INVALID_SIG_LEN;
    }
    int32_t ret;
    uint32_t n = ctx->n;
    *offset = 0;
    uint8_t indexBytes[sizeof(uint64_t)] = {0};
    memcpy(indexBytes + sizeof(indexBytes) - idxBytes, sig, idxBytes);
    *index = Uint64FromBeBytes(indexBytes);
    *offset += idxBytes;
    uint8_t idx[XMSS_MAX_MDSIZE] = {0};
    PUT_UINT64_BE(*index, idx, sizeof(idx) - 8);
    ret = ctx->hashFuncs->msgHash(ctx, sig + *offset, msg, msgLen, idx + sizeof(idx) - n, digest);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *offset += n;
    return CRYPT_SUCCESS;
}

int32_t XmssCheckRoot(const uint8_t *actual, const uint8_t *expected, uint32_t n)
{
    uint8_t diff = 0;
    for (uint32_t i = 0; i < n; i++) {
        diff |= actual[i] ^ expected[i];
    }
    if (diff != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_MERKLETREE_ROOT_MISMATCH);
        return CRYPT_XMSS_ERR_MERKLETREE_ROOT_MISMATCH;
    }
    return CRYPT_SUCCESS;
}

int32_t XmssGetPubkeyLen(const XmssCtxCommon *ctx, void *val, uint32_t len, bool hasParams)
{
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx == NULL || !hasParams) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    *(uint32_t *)val = ctx->n * 2 + HASH_SIGN_XDR_ALG_TYPE_LEN;
    return CRYPT_SUCCESS;
}

int32_t XmssGetSignatureLen(void *val, uint32_t len, uint32_t sigBytes, bool hasParams)
{
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (!hasParams) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    *(uint32_t *)val = sigBytes;
    return CRYPT_SUCCESS;
}

int32_t XmssGetParaId(void *val, uint32_t len, CRYPT_PKEY_ParaId algId, bool hasParams)
{
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (!hasParams) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    *(int32_t *)val = (int32_t)algId;
    return CRYPT_SUCCESS;
}

int32_t XmssGetXdrAlgBuff(void *val, uint32_t len, const uint8_t *xdrAlgId, bool hasParams)
{
    if (len < HASH_SIGN_XDR_ALG_TYPE_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (!hasParams || xdrAlgId == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    memcpy(val, xdrAlgId, HASH_SIGN_XDR_ALG_TYPE_LEN);
    return CRYPT_SUCCESS;
}

int32_t XmssCheckGenReady(const XmssCtxCommon *ctx, bool hasParams)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (!hasParams || ctx->n == 0 || ctx->hashFuncs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_ALGID);
        return CRYPT_XMSS_ERR_INVALID_ALGID;
    }
    return CRYPT_SUCCESS;
}

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
    BSL_Param *bdsState;
} XmssPrvKeyParam;

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

int32_t XmssGetPubKeyCommon(const XmssCtxCommon *ctx, BSL_Param *para, const uint8_t *xdrAlgId)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->n == 0 || xdrAlgId == NULL) {
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
        memcpy(pub.pubXdr->value, xdrAlgId, HASH_SIGN_XDR_ALG_TYPE_LEN);
        pub.pubXdr->useLen = HASH_SIGN_XDR_ALG_TYPE_LEN;
    }
    if (ctx->n > pub.pubSeed->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_LEN_NOT_ENOUGH);
        return CRYPT_XMSS_LEN_NOT_ENOUGH;
    }
    memcpy(pub.pubSeed->value, ctx->key.pubSeed, ctx->n);
    pub.pubSeed->useLen = ctx->n;
    if (ctx->n > pub.pubRoot->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_LEN_NOT_ENOUGH);
        return CRYPT_XMSS_LEN_NOT_ENOUGH;
    }
    memcpy(pub.pubRoot->value, ctx->key.root, ctx->n);
    pub.pubRoot->useLen = ctx->n;
    return CRYPT_SUCCESS;
}

static int32_t XPrvKeyParamCheck(const XmssCtxCommon *ctx, BSL_Param *para, XmssPrvKeyParam *prv, uint32_t n)
{
    prv->prvIndex = BSL_PARAM_FindParam(para, CRYPT_PARAM_XMSS_PRV_INDEX);
    prv->prvSeed = BSL_PARAM_FindParam(para, CRYPT_PARAM_XMSS_PRV_SEED);
    prv->prvPrf = BSL_PARAM_FindParam(para, CRYPT_PARAM_XMSS_PRV_PRF);
    prv->pubSeed = BSL_PARAM_FindParam(para, CRYPT_PARAM_XMSS_PUB_SEED);
    prv->pubRoot = BSL_PARAM_FindParam(para, CRYPT_PARAM_XMSS_PUB_ROOT);
    prv->bdsState = BSL_PARAM_FindParam(para, CRYPT_PARAM_XMSS_BDS_STATE);
    if (prv->prvIndex == NULL || prv->prvIndex->value == NULL || prv->prvSeed == NULL || prv->prvSeed->value == NULL ||
        prv->prvPrf == NULL || prv->prvPrf->value == NULL || prv->pubSeed == NULL || prv->pubSeed->value == NULL ||
        prv->pubRoot == NULL || prv->pubRoot->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prv->prvIndex->valueLen != sizeof(ctx->key.idx) || prv->prvSeed->valueLen != n ||
        prv->prvPrf->valueLen != n || prv->pubSeed->valueLen != n || prv->pubRoot->valueLen != n) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_KEYLEN);
        return CRYPT_XMSS_ERR_INVALID_KEYLEN;
    }
    if (prv->bdsState != NULL && prv->bdsState->valueType != BSL_PARAM_TYPE_OCTETS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_SUCCESS;
}

int32_t XmssGetPrvKeyCommon(const XmssCtxCommon *ctx, BSL_Param *para, const void *bdsCtx,
                            const void *bdsParams, XmssBdsExportStateCb exportState)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->n == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    XmssPrvKeyParam prv;
    uint64_t index = ctx->key.idx;
    uint32_t n = ctx->n;
    int32_t ret = XPrvKeyParamCheck(ctx, para, &prv, n);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    prv.prvSeed->useLen = n;
    prv.prvPrf->useLen = n;
    prv.pubSeed->useLen = n;
    prv.pubRoot->useLen = n;
    memcpy(prv.prvSeed->value, ctx->key.seed, n);
    memcpy(prv.prvPrf->value, ctx->key.prf, n);
    memcpy(prv.pubSeed->value, ctx->key.pubSeed, n);
    memcpy(prv.pubRoot->value, ctx->key.root, n);
    ret = BSL_PARAM_SetValue(prv.prvIndex, CRYPT_PARAM_XMSS_PRV_INDEX, BSL_PARAM_TYPE_UINT64, &index, sizeof(index));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (prv.bdsState != NULL) {
        if (bdsParams == NULL || exportState == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
            return CRYPT_XMSS_KEYINFO_NOT_SET;
        }
        uint32_t bdsLen = prv.bdsState->valueLen;
        ret = exportState(ctx, bdsCtx, bdsParams, (uint8_t *)prv.bdsState->value, &bdsLen);
        prv.bdsState->useLen = bdsLen;
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

int32_t XmssSetPubKeyCommon(XmssCtxCommon *ctx, const BSL_Param *para, const uint8_t *xdrAlgId)
{
    if (ctx == NULL || para == NULL || xdrAlgId == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->n == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    XmssPubKeyParam pub;
    int32_t ret = XPubKeyParamCheck((BSL_Param *)(uintptr_t)para, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (pub.pubXdr != NULL) {
        if (memcmp(pub.pubXdr->value, xdrAlgId, HASH_SIGN_XDR_ALG_TYPE_LEN) != 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_XDR_ID_UNMATCH);
            return CRYPT_XMSS_ERR_XDR_ID_UNMATCH;
        }
    }
    if (pub.pubSeed->valueLen != ctx->n || pub.pubRoot->valueLen != ctx->n) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_KEYLEN);
        return CRYPT_XMSS_ERR_INVALID_KEYLEN;
    }
    memcpy(ctx->key.pubSeed, pub.pubSeed->value, pub.pubSeed->valueLen);
    memcpy(ctx->key.root, pub.pubRoot->value, pub.pubRoot->valueLen);
    return CRYPT_SUCCESS;
}

int32_t XmssSetPrvKeyCommon(XmssCtxCommon *ctx, const BSL_Param *para, void *bdsCtx, void *tmpBdsCtx,
                            uint32_t bdsCtxLen, const void *bdsParams, XmssBdsImportStateCb importState,
                            XmssBdsFreeStateCb freeState)
{
    if (ctx == NULL || para == NULL || bdsCtx == NULL || tmpBdsCtx == NULL || freeState == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->n == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    XmssPrvKeyParam prv;
    XmssCtxCommon tmpCtx = {0};
    tmpCtx.n = ctx->n;
    tmpCtx.mdId = ctx->mdId;
    tmpCtx.paddingLen = ctx->paddingLen;
    tmpCtx.hashFuncs = ctx->hashFuncs;
    tmpCtx.adrsOps = ctx->adrsOps;
    tmpCtx.libCtx = ctx->libCtx;
    uint32_t tmplen = sizeof(tmpCtx.key.idx);
    uint32_t n = ctx->n;
    int32_t ret = XPrvKeyParamCheck(ctx, (BSL_Param *)(uintptr_t)para, &prv, n);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    memcpy(tmpCtx.key.seed, prv.prvSeed->value, n);
    memcpy(tmpCtx.key.prf, prv.prvPrf->value, n);
    memcpy(tmpCtx.key.pubSeed, prv.pubSeed->value, n);
    memcpy(tmpCtx.key.root, prv.pubRoot->value, n);
    ret = BSL_PARAM_GetValue(prv.prvIndex, CRYPT_PARAM_XMSS_PRV_INDEX, BSL_PARAM_TYPE_UINT64, &tmpCtx.key.idx, &tmplen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(&tmpCtx.key, sizeof(tmpCtx.key));
        return ret;
    }
    if (prv.bdsState != NULL && prv.bdsState->valueLen != 0) {
        if (bdsParams == NULL || importState == NULL) {
            BSL_SAL_CleanseData(&tmpCtx.key, sizeof(tmpCtx.key));
            BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
            return CRYPT_XMSS_KEYINFO_NOT_SET;
        }
        if (prv.bdsState->value == NULL) {
            BSL_SAL_CleanseData(&tmpCtx.key, sizeof(tmpCtx.key));
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
            return CRYPT_NULL_INPUT;
        }
        ret = importState(&tmpCtx, tmpBdsCtx, bdsParams, (const uint8_t *)prv.bdsState->value,
                          prv.bdsState->valueLen);
        if (ret != CRYPT_SUCCESS) {
            freeState(tmpBdsCtx);
            BSL_SAL_CleanseData(&tmpCtx.key, sizeof(tmpCtx.key));
            return ret;
        }
    }
    freeState(bdsCtx);
    ctx->key = tmpCtx.key;
    memcpy(bdsCtx, tmpBdsCtx, bdsCtxLen);
    BSL_SAL_CleanseData(&tmpCtx.key, sizeof(tmpCtx.key));
    memset(tmpBdsCtx, 0, bdsCtxLen);
    ctx->hasPrivateKey = true;
    return CRYPT_SUCCESS;
}

#if defined(HITLS_CRYPTO_XMSS_CHECK) || defined(HITLS_CRYPTO_XMSSMT_CHECK)

int32_t XmssCheckKeyPairRoot(const XmssCtxCommon *pubKey, const XmssCtxCommon *prvKey, const HbsTreeCtx *treeCtx,
                             const XmssAdrs *adrs)
{
    if (pubKey == NULL || prvKey == NULL || treeCtx == NULL || adrs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prvKey->n == 0 || pubKey->n == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    if (pubKey->n != prvKey->n) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_XMSS_PAIRWISE_CHECK_FAIL;
    }
    uint32_t n = prvKey->n;
    XmssAdrs treeAdrs = *adrs;
    uint8_t node[XMSS_MAX_MDSIZE] = {0};
    int32_t ret = HbsTree_ComputeNode(node, 0, treeCtx->hp, &treeAdrs, treeCtx, NULL, 0);
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

int32_t XmssCheckPrvKeyBasic(const XmssCtxCommon *prvKey, bool hasParams, CRYPT_PKEY_ParaId algId)
{
    if (prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (!hasParams) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    if (algId == 0 || prvKey->n == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_INVALID_PRVKEY);
        return CRYPT_XMSS_INVALID_PRVKEY;
    }
    return CRYPT_SUCCESS;
}

#endif /* defined(HITLS_CRYPTO_XMSS_CHECK) || defined(HITLS_CRYPTO_XMSSMT_CHECK) */

#endif /* defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT) */

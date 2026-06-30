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
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_local_types.h"
#include "crypt_utils.h"
#include "crypt_xmss.h"
#include "xmss_bds.h"
#include "xmss_local.h"
#include "xmss_params.h"

CryptXmssCtx *CRYPT_XMSS_NewCtx(void)
{
    CryptXmssCtx *ctx = (CryptXmssCtx *)BSL_SAL_Calloc(sizeof(CryptXmssCtx), 1);
    if (ctx != NULL) {
        ctx->common = XmssCommonNew();
    }
    if (ctx == NULL || ctx->common == NULL) {
        CRYPT_XMSS_FreeCtx(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ctx = NULL;
    }
    return ctx;
}

CryptXmssCtx *CRYPT_XMSS_NewCtxEx(void *libCtx)
{
    CryptXmssCtx *ctx = CRYPT_XMSS_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->common->libCtx = libCtx;
    return ctx;
}

void CRYPT_XMSS_FreeCtx(CryptXmssCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    XmssBds_Free(&ctx->bds);
    XmssCommonFree(ctx->common);
    BSL_SAL_ClearFree(ctx, sizeof(CryptXmssCtx));
}

CryptXmssCtx *CRYPT_XMSS_DupCtx(CryptXmssCtx *ctx)
{
    if (ctx == NULL || ctx->common == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CryptXmssCtx *newCtx = CRYPT_XMSS_NewCtx();
    if (newCtx == NULL) {
        return NULL;
    }
    newCtx->params = ctx->params;
    newCtx->common->libCtx = ctx->common->libCtx;
    newCtx->common->n = ctx->common->n;
    newCtx->common->mdId = ctx->common->mdId;
    newCtx->common->paddingLen = ctx->common->paddingLen;
    newCtx->common->hashFuncs = ctx->common->hashFuncs;
    newCtx->common->adrsOps = ctx->common->adrsOps;
    memcpy(newCtx->common->key.pubSeed, ctx->common->key.pubSeed, XMSS_MAX_SEED_SIZE);
    memcpy(newCtx->common->key.root, ctx->common->key.root, XMSS_MAX_MDSIZE);
    return newCtx;
}

static int32_t XmssInitWithParams(CryptXmssCtx *ctx, const XmssParams *params)
{
    XmssBds_Free(&ctx->bds);
    int32_t ret = XmssInitInternal(ctx->common, params->n, params->mdId, params->paddingLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ctx->params = params;
    return CRYPT_SUCCESS;
}

void HbsTreeCtx_InitForXmss(HbsTreeCtx *treeCtx, const CryptXmssCtx *ctx)
{
    const XmssCtxCommon *common = ctx->common;

    treeCtx->n = common->n;
    treeCtx->hp = ctx->params->h;
    treeCtx->d = 1U;
    treeCtx->otsLen = ctx->params->wotsLen;

    treeCtx->pubSeed = common->key.pubSeed;
    treeCtx->skSeed = common->key.seed;
    treeCtx->root = common->key.root;

    treeCtx->hashFuncs.xmss = common->hashFuncs;
    treeCtx->adrsOps = &common->adrsOps;
    treeCtx->originalCtx = (const void *)common;
    treeCtx->algoType = HBS_ALGO_XMSS;
}

static int32_t XmssExportBdsState(const XmssCtxCommon *ctx, const void *bdsCtx, const void *params,
                                  uint8_t *out, uint32_t *outLen)
{
    return XmssBds_ExportTreeState(ctx, (const XmssBdsCtx *)bdsCtx, (const XmssParams *)params, out, outLen);
}

static int32_t XmssImportBdsState(const XmssCtxCommon *ctx, void *bdsCtx, const void *params, const uint8_t *in,
                                  uint32_t inLen)
{
    return XmssBds_ImportTreeState(ctx, (XmssBdsCtx *)bdsCtx, (const XmssParams *)params, in, inLen);
}

static void XmssFreeBdsState(void *bdsCtx)
{
    XmssBds_Free((XmssBdsCtx *)bdsCtx);
}

#ifdef HITLS_CRYPTO_XMSS_CHECK
static int32_t XmssKeyPairCheck(const CryptXmssCtx *pubKey, const CryptXmssCtx *prvKey)
{
    if (pubKey == NULL || prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->common == NULL || prvKey->common == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->params == NULL || prvKey->params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_KEYINFO_NOT_SET);
        return CRYPT_XMSS_KEYINFO_NOT_SET;
    }
    if (pubKey->params->algId != prvKey->params->algId) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_XMSS_PAIRWISE_CHECK_FAIL;
    }

    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitForXmss(&treeCtx, prvKey);

    XmssAdrs adrs;
    memset(&adrs, 0, sizeof(adrs));
    prvKey->common->adrsOps.setLayerAddr(&adrs, 0);
    prvKey->common->adrsOps.setTreeAddr(&adrs, 0);
    return XmssCheckKeyPairRoot(pubKey->common, prvKey->common, &treeCtx, &adrs);
}
#endif

static int32_t XmssSetParaId(CryptXmssCtx *ctx, void *val, uint32_t len)
{
    if (ctx->params != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_CTRL_INIT_REPEATED);
        return CRYPT_XMSS_CTRL_INIT_REPEATED;
    }
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    const XmssParams *params = XmssParams_FindByAlgId((CRYPT_PKEY_ParaId)(*(int32_t *)val));
    if (params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_ALGID);
        return CRYPT_XMSS_ERR_INVALID_ALGID;
    }
    return XmssInitWithParams(ctx, params);
}

static int32_t XmssSetXdrAlgId(CryptXmssCtx *ctx, void *val, uint32_t len)
{
    if (ctx->params != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_CTRL_INIT_REPEATED);
        return CRYPT_XMSS_CTRL_INIT_REPEATED;
    }
    if (len < HASH_SIGN_XDR_ALG_TYPE_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint32_t xdrId = GET_UINT32_BE((const uint8_t *)val, 0);
    const XmssParams *params = XmssParams_FindByXdrId(xdrId);
    if (params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_XDR_ID);
        return CRYPT_XMSS_ERR_INVALID_XDR_ID;
    }
    return XmssInitWithParams(ctx, params);
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
            return XmssGetParaId(val, len, ctx->params == NULL ? 0 : ctx->params->algId, ctx->params != NULL);
        case CRYPT_CTRL_GET_XMSS_XDR_ALG_TYPE:
            return XmssGetXdrAlgBuff(val, len, ctx->params == NULL ? NULL : ctx->params->xdrAlgId,
                                     ctx->params != NULL);
        case CRYPT_CTRL_SET_XMSS_XDR_ALG_TYPE:
            return XmssSetXdrAlgId(ctx, val, len);
        case CRYPT_CTRL_GET_SIGNLEN:
            return XmssGetSignatureLen(val, len, ctx->params == NULL ? 0 : ctx->params->sigBytes,
                                       ctx->params != NULL);
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            return XmssGetPubkeyLen(ctx->common, val, len, ctx->params != NULL);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

/* Return a low-bits mask while avoiding undefined 64-bit shifts. */
static uint64_t XmssMaskForBits(uint32_t bits)
{
    return bits >= 64U ? UINT64_MAX : ((1ULL << bits) - 1ULL);
}

/*
 * XMSS owns exactly one BDS tree state. Initialization builds that single tree
 * immediately and publishes its root as the XMSS public root.
 */
static int32_t XmssInitBds(CryptXmssCtx *ctx)
{
    XmssCtxCommon *common = ctx == NULL ? NULL : ctx->common;
    if (common == NULL || ctx->params == NULL || common->n == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = XmssBds_Alloc(&ctx->bds);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitForXmss(&treeCtx, ctx);
    ret = XmssBds_InitTreeState(ctx->bds.state, 0, 0, &treeCtx);
    if (ret != CRYPT_SUCCESS) {
        XmssBds_Free(&ctx->bds);
        return ret;
    }

    memcpy(common->key.root, ctx->bds.state->root, common->n);
    ctx->bds.enabled = true;
    return CRYPT_SUCCESS;
}

/*
 * BDS accelerated XMSS signing is a single-tree operation: emit the WOTS+ sig
 * and auth path for the current leaf, then advance only that one BDS state.
 */
static int32_t XmssSignWithBds(CryptXmssCtx *ctx, const uint8_t *digest, uint32_t digestLen, uint64_t index,
                               uint8_t *sign, uint32_t *signLen)
{
    XmssCtxCommon *common = ctx == NULL ? NULL : ctx->common;
    if (common == NULL || ctx->params == NULL || digest == NULL || sign == NULL || signLen == NULL ||
        common->n == 0 || ctx->bds.state == NULL || !ctx->bds.enabled) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint32_t hp = ctx->params->h;
    uint32_t treeSigLen = (ctx->params->wotsLen + hp) * common->n;
    uint64_t maxLeaf = XmssMaskForBits(hp);
    if (index > maxLeaf) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (*signLen < treeSigLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_SIG_LEN);
        return CRYPT_XMSS_ERR_INVALID_SIG_LEN;
    }

    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitForXmss(&treeCtx, ctx);

    uint32_t leafIdx = (uint32_t)index;
    int32_t ret = XmssBds_WriteLayerSignature(ctx->bds.state, digest, digestLen, leafIdx, 0, 0, &treeCtx, sign,
                                              &treeSigLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (index < maxLeaf) {
        ret = XmssBds_TreeRound(ctx->bds.state, leafIdx, 0, 0, &treeCtx);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        ret = XmssBds_TreehashUpdates(ctx->bds.state, XmssBds_GetTreehashUpdateBudget(hp), 0, 0, &treeCtx, NULL);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    *signLen = treeSigLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_XMSS_Gen(CryptXmssCtx *ctx)
{
    XmssCtxCommon *common = ctx == NULL ? NULL : ctx->common;
    int32_t ret = XmssCheckGenReady(common, ctx != NULL && ctx->params != NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = XmssGenerateKeyMaterial(common, ctx->params->n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = XmssInitBds(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    common->hasPrivateKey = true;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_XMSS_Sign(CryptXmssCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                        uint32_t *signLen)
{
    (void)algId;
    XmssCtxCommon *common = ctx == NULL ? NULL : ctx->common;
    int32_t ret = XmssCheckSignReady(common, data, sign, signLen, ctx != NULL && ctx->params != NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint32_t signBufLen = *signLen;
    XmssSignPrepareInput prepareInput = {
        common,
        data,
        dataLen,
        sizeof(uint32_t),
        ctx->params->h,
        ctx->params->sigBytes,
        sign,
        signLen
    };
    XmssSignPrepareResult prepareResult = {0};
    ret = XmssPrepareSignData(&prepareInput, &prepareResult);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }

    uint32_t treeSigLen = *signLen - prepareResult.offset;
    if (ctx->bds.enabled) {
        ret = XmssSignWithBds(ctx, prepareResult.digest, ctx->params->n, prepareResult.index,
                              sign + prepareResult.offset, &treeSigLen);
    } else {
        HbsTreeCtx treeCtx;
        HbsTreeCtx_InitForXmss(&treeCtx, ctx);

        XmssAdrs adrs;
        memset(&adrs, 0, sizeof(adrs));
        common->adrsOps.setTreeAddr(&adrs, 0);

        uint8_t root[XMSS_MAX_MDSIZE] = {0};
        ret = HbsTree_Sign(prepareResult.digest, ctx->params->n, (uint32_t)prepareResult.index, &adrs, &treeCtx,
                           sign + prepareResult.offset, &treeSigLen, root);
    }
    BSL_SAL_CleanseData(prepareResult.digest, sizeof(prepareResult.digest));
    if (ret != CRYPT_SUCCESS) {
        goto ERR_CLEAN_SIG;
    }

    *signLen = prepareResult.offset + treeSigLen;
    return CRYPT_SUCCESS;

ERR:
    BSL_SAL_CleanseData(prepareResult.digest, sizeof(prepareResult.digest));
ERR_CLEAN_SIG:
    if (prepareResult.idxConsumed) {
        XmssBds_Free(&ctx->bds);
        BSL_SAL_CleanseData(sign, signBufLen);
        *signLen = 0;
    }
    BSL_ERR_PUSH_ERROR(ret);
    return ret;
}

int32_t CRYPT_XMSS_Verify(const CryptXmssCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                          const uint8_t *sign, uint32_t signLen)
{
    (void)algId;
    const XmssCtxCommon *common = ctx == NULL ? NULL : ctx->common;
    int32_t ret = XmssCheckVerifyReady(common, data, sign, ctx != NULL && ctx->params != NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint64_t index = 0;
    uint32_t offset = 0;
    uint8_t digest[XMSS_MAX_MDSIZE] = {0};
    ret = XmssBuildVerifyDigest(common, data, dataLen, sign, signLen, sizeof(uint32_t), &index, &offset, digest,
                                ctx->params->sigBytes);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(digest, sizeof(digest));
        return ret;
    }

    HbsTreeCtx treeCtx;
    HbsTreeCtx_InitForXmss(&treeCtx, ctx);

    XmssAdrs adrs;
    memset(&adrs, 0, sizeof(adrs));
    common->adrsOps.setTreeAddr(&adrs, 0);

    uint8_t root[XMSS_MAX_MDSIZE] = {0};
    ret = HbsTree_Verify(digest, ctx->params->n, sign + offset, signLen - offset, (uint32_t)index, &adrs, &treeCtx,
                         root);
    BSL_SAL_CleanseData(digest, sizeof(digest));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return XmssCheckRoot(root, common->key.root, ctx->params->n);
}

int32_t CRYPT_XMSS_GetPubKey(const CryptXmssCtx *ctx, BSL_Param *para)
{
    return XmssGetPubKeyCommon(ctx == NULL ? NULL : ctx->common, para, ctx == NULL || ctx->params == NULL ?
        NULL : ctx->params->xdrAlgId);
}

int32_t CRYPT_XMSS_GetPrvKey(const CryptXmssCtx *ctx, BSL_Param *para)
{
    return XmssGetPrvKeyCommon(ctx == NULL ? NULL : ctx->common, para, ctx == NULL ? NULL : &ctx->bds,
                               ctx == NULL ? NULL : ctx->params, XmssExportBdsState);
}

int32_t CRYPT_XMSS_SetPubKey(CryptXmssCtx *ctx, const BSL_Param *para)
{
    int32_t ret = XmssSetPubKeyCommon(ctx == NULL ? NULL : ctx->common, para, ctx == NULL || ctx->params == NULL ?
        NULL : ctx->params->xdrAlgId);
    if (ret == CRYPT_SUCCESS) {
        XmssBds_Free(&ctx->bds);
    }
    return ret;
}

int32_t CRYPT_XMSS_SetPrvKey(CryptXmssCtx *ctx, const BSL_Param *para)
{
    XmssBdsCtx tmpBds = {0};
    return XmssSetPrvKeyCommon(ctx == NULL ? NULL : ctx->common, para, ctx == NULL ? NULL : &ctx->bds, &tmpBds,
                               sizeof(tmpBds), ctx == NULL ? NULL : ctx->params, XmssImportBdsState,
                               XmssFreeBdsState);
}

#ifdef HITLS_CRYPTO_XMSS_CHECK
int32_t CRYPT_XMSS_Check(uint32_t checkType, const CryptXmssCtx *pkey1, const CryptXmssCtx *pkey2)
{
    switch (checkType) {
        case CRYPT_PKEY_CHECK_KEYPAIR:
            return XmssKeyPairCheck(pkey1, pkey2);
        case CRYPT_PKEY_CHECK_PRVKEY:
            return XmssCheckPrvKeyBasic(pkey1 == NULL ? NULL : pkey1->common, pkey1 != NULL && pkey1->params != NULL,
                                        pkey1 == NULL || pkey1->params == NULL ? 0 : pkey1->params->algId);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
}
#endif /* HITLS_CRYPTO_XMSS_CHECK */

#endif /* HITLS_CRYPTO_XMSS */

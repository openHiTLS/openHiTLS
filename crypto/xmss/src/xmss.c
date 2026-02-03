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
#include "bsl_err_internal.h"
#include "bsl_params.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_params_key.h"
#include "crypt_xmss.h"
#include "crypt_utils.h"
#include "xmss_local.h"
#include "xmss_params.h"
#include "xmss_tree.h"
#include "xmss_address.h"

typedef struct {
    BSL_Param *pubXdr;    // XDR type identifier (4 bytes, optional)
    BSL_Param *pubSeed;   // Public seed (n bytes)
    BSL_Param *pubRoot;   // Tree root (n bytes)
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
    ctx->params = NULL;
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
    BSL_SAL_CleanseData(ctx->key.seed, sizeof(ctx->key.seed));
    BSL_SAL_CleanseData(ctx->key.prf, sizeof(ctx->key.prf));
    BSL_SAL_Free(ctx);
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
    CRYPT_PKEY_ParaId algId = *(CRYPT_PKEY_ParaId *)val;
    if (CheckNotXmssAlgId(algId)) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_ALGID);
        return CRYPT_XMSS_ERR_INVALID_ALGID;
    }
    return XmssSetAlgId(ctx, algId);
}

/*
 * Get XMSS public key length (RFC 9802)
 * Returns: XDR type (4 bytes) + pubSeed (n bytes) + root (n bytes)
 */
static int32_t XmssGetPubkeyLen(CryptXmssCtx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *(uint32_t *)val = ctx->params->n * 2 + HASH_SIGN_XDR_ALG_TYPE_LEN;
    return CRYPT_SUCCESS;
}

/*
 * Get XMSS signature length
 * Returns the signature size in bytes for the current parameter set
 */
static int32_t XmssGetSignatureLen(CryptXmssCtx *ctx, void *val, uint32_t len)
{
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *(uint32_t *)val = ctx->params->sigBytes;
    return CRYPT_SUCCESS;
}

/*
 * Get XMSS algorithm parameter ID
 * Returns the CRYPT_PKEY_ParaId for the current parameter set
 */
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

/*
 * Get XDR algorithm type buffer (RFC 9802)
 * Copies the 4-byte XDR OID to the output buffer
 */
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
    (void)memcpy_s(val, len, ctx->params->xdrAlgId, HASH_SIGN_XDR_ALG_TYPE_LEN);
    return CRYPT_SUCCESS;
}

/*
 * Set XMSS parameters by XDR algorithm ID (RFC 9802)
 *
 * Allows setting algorithm parameters using the 4-byte XDR OID.
 * This is used when loading XMSS public keys from X.509 certificates.
 *
 * @param ctx  XMSS context
 * @param val  Pointer to 4-byte XDR OID buffer
 * @param len  Buffer length (must be >= 4)
 *
 * @return CRYPT_SUCCESS on success
 *         CRYPT_XMSS_ERR_INVALID_XDR_ID if XDR ID is invalid
 */
static int32_t XmssSetXdrAlgId(CryptXmssCtx *ctx, void *val, uint32_t len)
{
    if (val == NULL || len < HASH_SIGN_XDR_ALG_TYPE_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    /* Convert 4-byte buffer to uint32 */
    uint32_t xdrId = GET_UINT32_BE((const uint8_t *)val, 0);

    /* Look up parameters by XDR ID (return pointer to global table) */
    const XmssParams *params = XmssParams_FindByXdrId(xdrId);
    if (params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_XDR_ID);
        return CRYPT_XMSS_ERR_INVALID_XDR_ID;
    }

    /* Initialize core context with found parameters */
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

    /* Generate key pair using core API */
    int32_t ret = CRYPT_XMSS_KeyGenInternal(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_XMSS_Sign(CryptXmssCtx *ctx, int32_t algId,
                        const uint8_t *data, uint32_t dataLen,
                        uint8_t *sign, uint32_t *signLen)
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

int32_t CRYPT_XMSS_Verify(const CryptXmssCtx *ctx, int32_t algId,
                          const uint8_t *data, uint32_t dataLen,
                          const uint8_t *sign, uint32_t signLen)
{
    (void)algId;
    if (ctx == NULL || data == NULL || sign == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    /* Verify signature using internal API */
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
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /* Copy XDR type if requested (RFC 9802 X.509 support) */
    if (pub.pubXdr != NULL) {
        if (memcpy_s(pub.pubXdr->value, pub.pubXdr->valueLen,
                     ctx->params->xdrAlgId, HASH_SIGN_XDR_ALG_TYPE_LEN) != 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_XMSS_LEN_NOT_ENOUGH);
            return CRYPT_XMSS_LEN_NOT_ENOUGH;
        }
        pub.pubXdr->useLen = HASH_SIGN_XDR_ALG_TYPE_LEN;
    }
    if (memcpy_s(pub.pubSeed->value, pub.pubSeed->valueLen, ctx->key.pubSeed, ctx->params->n) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_LEN_NOT_ENOUGH);
        return CRYPT_XMSS_LEN_NOT_ENOUGH;
    }
    pub.pubSeed->useLen = ctx->params->n;
    if (memcpy_s(pub.pubRoot->value, pub.pubRoot->valueLen, ctx->key.root, ctx->params->n) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_LEN_NOT_ENOUGH);
        return CRYPT_XMSS_LEN_NOT_ENOUGH;
    }
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
    if (prv->prvIndex == NULL || prv->prvIndex->value == NULL ||
        prv->prvSeed == NULL || prv->prvSeed->value == NULL ||
        prv->prvPrf == NULL || prv->prvPrf->value == NULL ||
        prv->pubSeed == NULL || prv->pubSeed->value == NULL ||
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
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    prv.prvSeed->useLen = ctx->params->n;
    prv.prvPrf->useLen = ctx->params->n;
    prv.pubSeed->useLen = ctx->params->n;
    prv.pubRoot->useLen = ctx->params->n;
    (void)memcpy_s(prv.prvSeed->value, prv.prvSeed->valueLen, ctx->key.seed, ctx->params->n);
    (void)memcpy_s(prv.prvPrf->value, prv.prvPrf->valueLen, ctx->key.prf, ctx->params->n);
    (void)memcpy_s(prv.pubSeed->value, prv.pubSeed->valueLen, ctx->key.pubSeed, ctx->params->n);
    (void)memcpy_s(prv.pubRoot->value, prv.pubRoot->valueLen, ctx->key.root, ctx->params->n);
    return BSL_PARAM_SetValue(prv.prvIndex, CRYPT_PARAM_XMSS_PRV_INDEX, BSL_PARAM_TYPE_UINT64,
            &index, sizeof(index));
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
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* Validate XDR type if provided (RFC 9802 X.509 support) */
    if (pub.pubXdr != NULL) {
        uint32_t xdrId = GET_UINT32_BE((uint8_t *)pub.pubXdr->value, 0);
        const XmssParams *params = XmssParams_FindByXdrId(xdrId);
        if (params == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_XDR_ID);
            return CRYPT_XMSS_ERR_INVALID_XDR_ID;
        }
        /* Verify XDR matches currently set algorithm ID */
        if (params->algId != ctx->params->algId) {
            BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_XDR_ID_UNMATCH);
            return CRYPT_XMSS_ERR_XDR_ID_UNMATCH;
        }
    }
    if (pub.pubSeed->valueLen != ctx->params->n || pub.pubRoot->valueLen != ctx->params->n) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_KEYLEN);
        return CRYPT_XMSS_ERR_INVALID_KEYLEN;
    }
    (void)memcpy_s(ctx->key.pubSeed, XMSS_MAX_MDSIZE, pub.pubSeed->value, pub.pubSeed->valueLen);
    (void)memcpy_s(ctx->key.root, XMSS_MAX_MDSIZE, pub.pubRoot->value, pub.pubRoot->valueLen);
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
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memcpy_s(ctx->key.seed, sizeof(ctx->key.seed), prv.prvSeed->value, ctx->params->n);
    (void)memcpy_s(ctx->key.prf, sizeof(ctx->key.prf), prv.prvPrf->value, ctx->params->n);
    (void)memcpy_s(ctx->key.pubSeed, sizeof(ctx->key.pubSeed), prv.pubSeed->value, ctx->params->n);
    (void)memcpy_s(ctx->key.root, sizeof(ctx->key.root), prv.pubRoot->value, ctx->params->n);
    return BSL_PARAM_GetValue(prv.prvIndex, CRYPT_PARAM_XMSS_PRV_INDEX, BSL_PARAM_TYPE_UINT64, &ctx->key.idx, &tmplen);
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
    memcpy_s(newCtx, sizeof(CryptXmssCtx), ctx, sizeof(CryptXmssCtx));
    return newCtx;
}

void InitTreeCtxFromXmssCtx(TreeCtx *treeCtx, const CryptXmssCtx *ctx)
{
    /* Initialize algorithm parameters */
    treeCtx->n = ctx->params->n;
    treeCtx->hp = ctx->params->hp;
    treeCtx->d = ctx->params->d;
    treeCtx->wotsLen = ctx->params->wotsLen;

    /* Initialize key material */
    treeCtx->pubSeed = ctx->key.pubSeed;
    treeCtx->skSeed = ctx->key.seed;
    treeCtx->root = ctx->key.root;

    /* Initialize hash function table */
    treeCtx->hashFuncs = ctx->hashFuncs;
    /* Initialize address operations */
    treeCtx->adrsOps = &ctx->adrsOps;
    treeCtx->originalCtx = (void *)(uintptr_t)ctx;
    treeCtx->isXmss = true;
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

    // Recalculate root from private key
    XmssAdrs adrs;
    (void)memset_s(&adrs, sizeof(XmssAdrs), 0, sizeof(XmssAdrs));
    prvKey->adrsOps.setLayerAddr(&adrs, d - 1);

    TreeCtx treeCtx;
    InitTreeCtxFromXmssCtx(&treeCtx, prvKey);

    uint8_t node[XMSS_MAX_MDSIZE] = {0};
    int32_t ret = XmssTree_ComputeNode(node, 0, hp, &adrs, &treeCtx, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Compare recalculated root with public key root
    if (memcmp(node, pubKey->key.root, n) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_XMSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_XMSS_PAIRWISE_CHECK_FAIL;
    }
    // Compare public seeds
    if (memcmp(prvKey->key.pubSeed, pubKey->key.pubSeed, n) != 0) {
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

#endif // HITLS_CRYPTO_XMSS_CHECK

#endif // HITLS_CRYPTO_XMSS

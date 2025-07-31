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
#ifdef HITLS_CRYPTO_HYBRIDKEM

#include "securec.h"
#include "bsl_sal.h"
#include "sal_atomic.h"
#include "eal_pkey_local.h"
#include "crypt_eal_pkey.h"
#include "crypt_utils.h"
#include "crypt_hybridkem_local.h"
#include "crypt_hybridkem.h"
#include "crypt_ecdh.h"
#include "crypt_curve25519.h"
#include "crypt_mlkem.h"

typedef struct {
    int32_t hybrId;
    int32_t pkeyParam;
    int32_t kemParam;
    int32_t pkeyAlg;
    int32_t kemAlg;
} HybridKemIdList;

static const HybridKemIdList HYBRID_KEY_LIST[] = {
    {CRYPT_HYBRID_X25519_MLKEM512, 0, CRYPT_KEM_TYPE_MLKEM_512, CRYPT_PKEY_X25519, CRYPT_PKEY_ML_KEM},
    {CRYPT_HYBRID_X25519_MLKEM768, 0, CRYPT_KEM_TYPE_MLKEM_768, CRYPT_PKEY_X25519, CRYPT_PKEY_ML_KEM},
    {CRYPT_HYBRID_X25519_MLKEM1024, 0, CRYPT_KEM_TYPE_MLKEM_1024, CRYPT_PKEY_X25519, CRYPT_PKEY_ML_KEM},

    {CRYPT_HYBRID_ECDH_NISTP256_MLKEM512, CRYPT_ECC_NISTP256, CRYPT_KEM_TYPE_MLKEM_512,
     CRYPT_PKEY_ECDH, CRYPT_PKEY_ML_KEM},
    {CRYPT_HYBRID_ECDH_NISTP256_MLKEM768, CRYPT_ECC_NISTP256, CRYPT_KEM_TYPE_MLKEM_768,
     CRYPT_PKEY_ECDH, CRYPT_PKEY_ML_KEM},
    {CRYPT_HYBRID_ECDH_NISTP256_MLKEM1024, CRYPT_ECC_NISTP256, CRYPT_KEM_TYPE_MLKEM_1024,
     CRYPT_PKEY_ECDH, CRYPT_PKEY_ML_KEM},
    {CRYPT_HYBRID_ECDH_NISTP384_MLKEM512, CRYPT_ECC_NISTP384, CRYPT_KEM_TYPE_MLKEM_512,
     CRYPT_PKEY_ECDH, CRYPT_PKEY_ML_KEM},
    {CRYPT_HYBRID_ECDH_NISTP384_MLKEM768, CRYPT_ECC_NISTP384, CRYPT_KEM_TYPE_MLKEM_768,
     CRYPT_PKEY_ECDH, CRYPT_PKEY_ML_KEM},
    {CRYPT_HYBRID_ECDH_NISTP384_MLKEM1024, CRYPT_ECC_NISTP384, CRYPT_KEM_TYPE_MLKEM_1024,
     CRYPT_PKEY_ECDH, CRYPT_PKEY_ML_KEM},
    {CRYPT_HYBRID_ECDH_NISTP521_MLKEM512, CRYPT_ECC_NISTP521, CRYPT_KEM_TYPE_MLKEM_512,
     CRYPT_PKEY_ECDH, CRYPT_PKEY_ML_KEM},
    {CRYPT_HYBRID_ECDH_NISTP521_MLKEM768, CRYPT_ECC_NISTP521, CRYPT_KEM_TYPE_MLKEM_768,
     CRYPT_PKEY_ECDH, CRYPT_PKEY_ML_KEM},
    {CRYPT_HYBRID_ECDH_NISTP521_MLKEM1024, CRYPT_ECC_NISTP521, CRYPT_KEM_TYPE_MLKEM_1024,
     CRYPT_PKEY_ECDH, CRYPT_PKEY_ML_KEM},
};

static int32_t HybridGetCurveIdAndKemId(int32_t hybrId, const HybridKemIdList **algInfo)
{
    for (uint32_t i = 0; i < (sizeof(HYBRID_KEY_LIST) / sizeof(HYBRID_KEY_LIST[0])); i++) {
        if (HYBRID_KEY_LIST[i].hybrId == hybrId) {
            *algInfo = &HYBRID_KEY_LIST[i];
            return CRYPT_SUCCESS;
        }
    }
    return CRYPT_ERR_ALGID;
}

CRYPT_HybridKemCtx *CRYPT_HYBRID_KEM_NewCtx(void)
{
    CRYPT_HybridKemCtx *hybridKey = BSL_SAL_Calloc(sizeof(CRYPT_HybridKemCtx), 1);
    if (hybridKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    BSL_SAL_ReferencesInit(&(hybridKey->references));
    return hybridKey;
}

CRYPT_HybridKemCtx *CRYPT_HYBRID_KEM_NewCtxEx(void *libCtx)
{
    CRYPT_HybridKemCtx *hybridKey = CRYPT_HYBRID_KEM_NewCtx();
    if (hybridKey == NULL) {
        return NULL;
   
    }
    hybridKey->libCtx = libCtx;
    return hybridKey;
}

void CRYPT_HYBRID_KEM_FreeCtx(CRYPT_HybridKemCtx *hybridKey)
{
    if (hybridKey == NULL) {
        return;
    }
    int ref = 0;
    BSL_SAL_AtomicDownReferences(&(hybridKey->references), &ref);
    if (ref > 0) {
        return;
    }
    BSL_SAL_ReferencesFree(&(hybridKey->references));
    if (hybridKey->pKeyMethod != NULL && hybridKey->pKeyMethod->freeCtx != NULL) {
        hybridKey->pKeyMethod->freeCtx(hybridKey->pkeyCtx);
    }
    if (hybridKey->kemMethod != NULL && hybridKey->kemMethod->freeCtx != NULL) {
        hybridKey->kemMethod->freeCtx(hybridKey->kemCtx);
    }
    BSL_SAL_FREE(hybridKey);
}

static void *CRYPT_HybridNewPkeyCtx(CRYPT_HybridKemCtx *ctx, int32_t algId)
{
    void *pkeyCtx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    if (algId == CRYPT_PKEY_X25519) {
        pkeyCtx = CRYPT_X25519_NewCtxEx(ctx->libCtx);
    } else {
        pkeyCtx = CRYPT_ECDH_NewCtxEx(ctx->libCtx);
    }
#else
    (void) ctx;
    if (algId == CRYPT_PKEY_X25519) {
        pkeyCtx = CRYPT_X25519_NewCtx();
    } else {
        pkeyCtx = CRYPT_ECDH_NewCtx();
    }
#endif
    return pkeyCtx;
}

static void *CRYPT_HybridNewKemCtx(CRYPT_HybridKemCtx *ctx, int32_t algId)
{
    (void) algId;
    void *kemCtx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    kemCtx = CRYPT_ML_KEM_NewCtxEx(ctx->libCtx);
#else
    (void) ctx;
    kemCtx = CRYPT_ML_KEM_NewCtx();
#endif
    return kemCtx;
}

static int32_t CRYPT_HybridSetKeyType(CRYPT_HybridKemCtx *ctx, int32_t val)
{
    int32_t ret;
    const HybridKemIdList *algInfo = NULL;
    RETURN_RET_IF((ctx->pkeyCtx != NULL || ctx->kemCtx != NULL), CRYPT_INVALID_ARG);
    RETURN_RET_IF_ERR(HybridGetCurveIdAndKemId(val, &algInfo), ret);

    const EAL_PkeyMethod *pKeyMethod = CRYPT_EAL_PkeyFindMethod(algInfo->pkeyAlg);
    const EAL_PkeyMethod *kemMethod = CRYPT_EAL_PkeyFindMethod(algInfo->kemAlg);
    RETURN_RET_IF((pKeyMethod == NULL || kemMethod == NULL), CRYPT_NOT_SUPPORT);

    ctx->pkeyCtx = CRYPT_HybridNewPkeyCtx(ctx, algInfo->pkeyAlg);
    RETURN_RET_IF(ctx->pkeyCtx == NULL, CRYPT_MEM_ALLOC_FAIL);
    ctx->kemCtx = CRYPT_HybridNewKemCtx(ctx, algInfo->kemAlg);
    if (ctx->kemCtx == NULL) {
        pKeyMethod->freeCtx(ctx->pkeyCtx);
        ctx->pkeyCtx = NULL;
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->pKeyMethod = pKeyMethod;
    ctx->kemMethod = kemMethod;

    int32_t kemType = algInfo->kemParam;
    int32_t curveId = algInfo->pkeyParam;
    GOTO_ERR_IF_EX(ctx->kemMethod->ctrl(ctx->kemCtx, CRYPT_CTRL_SET_PARA_BY_ID, &kemType, sizeof(kemType)), ret);
    if (curveId == 0) {  // For X25519, the curve ID does not need to be set.
        return CRYPT_SUCCESS;
    }
    GOTO_ERR_IF_EX(ctx->pKeyMethod->ctrl(ctx->pkeyCtx, CRYPT_CTRL_SET_PARA_BY_ID, &curveId, sizeof(curveId)), ret);
    return CRYPT_SUCCESS;
ERR:
    pKeyMethod->freeCtx(ctx->pkeyCtx);
    ctx->pkeyCtx = NULL;
    kemMethod->freeCtx(ctx->kemCtx);
    ctx->kemCtx = NULL;
    return ret;
}

static int32_t CRYPT_HybridGetEncapsKeyLen(const CRYPT_HybridKemCtx *ctx, uint32_t *pubLen, uint32_t *ekLen)
{
    int32_t ret;
    uint32_t val;
    RETURN_RET_IF((ctx->pKeyMethod == NULL || ctx->kemMethod == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF_ERR(ctx->pKeyMethod->ctrl(ctx->pkeyCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &val, sizeof(val)), ret);
    *pubLen = val;

    RETURN_RET_IF_ERR(ctx->kemMethod->ctrl(ctx->kemCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &val, sizeof(val)), ret);
    *ekLen = val;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_HybridGetDecapsKeyLen(const CRYPT_HybridKemCtx *ctx, uint32_t *prvLen, uint32_t *dkLen)
{
    int32_t ret;
    uint32_t val;
    RETURN_RET_IF((ctx->pKeyMethod == NULL || ctx->kemMethod == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF_ERR(ctx->pKeyMethod->ctrl(ctx->pkeyCtx, CRYPT_CTRL_GET_PRVKEY_LEN, &val, sizeof(val)), ret);
    *prvLen = val;

    RETURN_RET_IF_ERR(ctx->kemMethod->ctrl(ctx->kemCtx, CRYPT_CTRL_GET_PRVKEY_LEN, &val, sizeof(val)), ret);
    *dkLen = val;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_HybridGetCipherTextLen(const CRYPT_HybridKemCtx *ctx, uint32_t *pubLen, uint32_t *ctLen)
{
    int32_t ret;
    uint32_t val;
    RETURN_RET_IF((ctx->pKeyMethod == NULL || ctx->kemMethod == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF_ERR(ctx->pKeyMethod->ctrl(ctx->pkeyCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &val, sizeof(val)), ret);
    *pubLen = val;

    RETURN_RET_IF_ERR(ctx->kemMethod->ctrl(ctx->kemCtx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &val, sizeof(val)), ret);
    *ctLen = val;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_HybridGetShareKeyLen(const CRYPT_HybridKemCtx *ctx, uint32_t *pkeyLen, uint32_t *kemLen)
{
    int32_t ret;
    uint32_t val;
    RETURN_RET_IF((ctx->pKeyMethod == NULL || ctx->kemMethod == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF_ERR(ctx->pKeyMethod->ctrl(ctx->pkeyCtx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &val, sizeof(val)), ret);
    *pkeyLen = val;
    RETURN_RET_IF_ERR(ctx->kemMethod->ctrl(ctx->kemCtx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &val, sizeof(val)), ret);
    *kemLen = val;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_HybridSetEccPointFormit(const CRYPT_HybridKemCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF((ctx->pKeyMethod == NULL || ctx->pkeyCtx == NULL), CRYPT_INVALID_ARG);
    return ctx->pKeyMethod->ctrl(ctx->pkeyCtx, CRYPT_CTRL_SET_ECC_POINT_FORMAT, val, len);
}

int32_t CRYPT_HYBRID_KEM_KeyCtrl(CRYPT_HybridKemCtx *ctx, int32_t opt, void *val, uint32_t len)
{
    int32_t ret;
    RETURN_RET_IF(ctx == NULL || val == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(len != sizeof(uint32_t), CRYPT_INVALID_ARG);
    uint32_t pkeyLen = 0;
    uint32_t kemLen = 0;
    switch (opt) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            return CRYPT_HybridSetKeyType(ctx, *(int32_t *)val);
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            ret = CRYPT_HybridGetEncapsKeyLen(ctx, &pkeyLen, &kemLen);
            break;
        case CRYPT_CTRL_GET_PRVKEY_LEN:
            ret = CRYPT_HybridGetDecapsKeyLen(ctx, &pkeyLen, &kemLen);
            break;
        case CRYPT_CTRL_GET_CIPHERTEXT_LEN:
            ret = CRYPT_HybridGetCipherTextLen(ctx, &pkeyLen, &kemLen);
            break;
        case CRYPT_CTRL_GET_SHARED_KEY_LEN:
            ret = CRYPT_HybridGetShareKeyLen(ctx, &pkeyLen, &kemLen);
            break;
        case CRYPT_CTRL_SET_ECC_POINT_FORMAT:
            return CRYPT_HybridSetEccPointFormit(ctx, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    *(uint32_t *)val = pkeyLen + kemLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HYBRID_KEM_GenKey(CRYPT_HybridKemCtx *ctx)
{
    int32_t ret;
    RETURN_RET_IF(ctx == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF((ctx->pKeyMethod == NULL || ctx->kemMethod == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF_ERR(ctx->pKeyMethod->gen(ctx->pkeyCtx), ret);
    return ctx->kemMethod->gen(ctx->kemCtx);
}

/*
 * According of <Post-quantum hybrid ECDHE-MLKEM Key Agreement for TLSv1.3>, when MLKEM and X25519 are mixed,
 * the key of MLKEM is before the key of X25519.
 * Protocol link: www.ietf.org/archive/id/draft-kwiatkowski-tls-ecdhe-mlkem-03.html#name-negotiated-groups
*/
static int32_t CRYPT_HybridGetKeyPtr(const CRYPT_HybridKemCtx *ctx, void *pub, uint32_t pubLen, BSL_Param *pkeyData,
    BSL_Param *kemData)
{
    RETURN_RET_IF(pubLen < (pkeyData->valueLen + kemData->valueLen), CRYPT_INVALID_ARG);
    if (ctx->pKeyMethod->id == CRYPT_PKEY_X25519) {
        kemData->value = pub;
        pkeyData->value = pub + kemData->valueLen;
    } else {
        pkeyData->value = pub;
        kemData->value = pub + pkeyData->valueLen;
    }
    return CRYPT_SUCCESS;
}

// Get the local public Key and kem encapsulation key.
int32_t CRYPT_HYBRID_KEM_GetEncapsKey(const CRYPT_HybridKemCtx *ctx, CRYPT_KemEncapsKey *ek)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || ek == NULL || ek->data == NULL), CRYPT_NULL_INPUT);
    BSL_Param pubKey[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, NULL, 0, 0}, BSL_PARAM_END};
    BSL_Param kemEK[2] = {{CRYPT_PARAM_ML_KEM_PUBKEY, BSL_PARAM_TYPE_OCTETS, NULL, 0, 0}, BSL_PARAM_END};
    RETURN_RET_IF_ERR(CRYPT_HybridGetEncapsKeyLen(ctx, &(pubKey[0].valueLen), &(kemEK[0].valueLen)), ret);
    RETURN_RET_IF_ERR(CRYPT_HybridGetKeyPtr(ctx, ek->data, ek->len, pubKey, kemEK), ret);

    if (ctx->pKeyMethod->id == CRYPT_PKEY_X25519) {
        pubKey[0].key = CRYPT_PARAM_CURVE25519_PUBKEY;
    }
    RETURN_RET_IF_ERR(ctx->pKeyMethod->getPub(ctx->pkeyCtx, pubKey), ret);
    RETURN_RET_IF_ERR(ctx->kemMethod->getPub(ctx->kemCtx, kemEK), ret);
    ek->len = pubKey[0].useLen + kemEK[0].useLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HYBRID_KEM_GetDecapsKey(const CRYPT_HybridKemCtx *ctx, CRYPT_KemDecapsKey *dk)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || dk == NULL || dk->data == NULL), CRYPT_NULL_INPUT);
    BSL_Param prvKey[2] = {{CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, NULL, 0, 0}, BSL_PARAM_END};
    BSL_Param kemDK[2] = {{CRYPT_PARAM_ML_KEM_PRVKEY, BSL_PARAM_TYPE_OCTETS, NULL, 0, 0}, BSL_PARAM_END};
    RETURN_RET_IF_ERR(CRYPT_HybridGetDecapsKeyLen(ctx, &prvKey[0].valueLen, &kemDK[0].valueLen), ret);
    RETURN_RET_IF_ERR(CRYPT_HybridGetKeyPtr(ctx, dk->data, dk->len, prvKey, kemDK), ret);

    if (ctx->pKeyMethod->id == CRYPT_PKEY_X25519) {
        prvKey[0].key = CRYPT_PARAM_CURVE25519_PRVKEY;
    }
    RETURN_RET_IF_ERR(ctx->pKeyMethod->getPrv(ctx->pkeyCtx, prvKey), ret);
    RETURN_RET_IF_ERR(ctx->kemMethod->getPrv(ctx->kemCtx, kemDK), ret);
    dk->len = prvKey[0].useLen + kemDK[0].useLen;
    return CRYPT_SUCCESS;
}

// Set the public key and kem encapsulation key.
int32_t CRYPT_HYBRID_KEM_SetEncapsKey(CRYPT_HybridKemCtx *ctx, const CRYPT_KemEncapsKey *ek)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || ek == NULL || ek->data == NULL), CRYPT_NULL_INPUT);
    BSL_Param pubKey[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, NULL, 0, 0}, BSL_PARAM_END};
    BSL_Param kemEK[2] = {{CRYPT_PARAM_ML_KEM_PUBKEY, BSL_PARAM_TYPE_OCTETS, NULL, 0, 0}, BSL_PARAM_END};
    RETURN_RET_IF_ERR(CRYPT_HybridGetEncapsKeyLen(ctx, &pubKey[0].valueLen, &kemEK[0].valueLen), ret);
    RETURN_RET_IF(ek->len < kemEK[0].valueLen, CRYPT_INVALID_ARG);
    pubKey[0].valueLen = ek->len - kemEK[0].valueLen;
    RETURN_RET_IF_ERR(CRYPT_HybridGetKeyPtr(ctx, ek->data, ek->len, pubKey, kemEK), ret);

    if (ctx->pKeyMethod->id == CRYPT_PKEY_X25519) {
        pubKey[0].key = CRYPT_PARAM_CURVE25519_PUBKEY;
    }
    RETURN_RET_IF_ERR(ctx->kemMethod->setPub(ctx->kemCtx, kemEK), ret);
    return ctx->pKeyMethod->setPub(ctx->pkeyCtx, pubKey);
}

int32_t CRYPT_HYBRID_KEM_SetDecapsKey(CRYPT_HybridKemCtx *ctx, const CRYPT_KemDecapsKey *dk)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || dk == NULL || dk->data == NULL), CRYPT_NULL_INPUT);
    BSL_Param prvKey[2] = {{CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, NULL, 0, 0}, BSL_PARAM_END};
    BSL_Param kemDK[2] = {{CRYPT_PARAM_ML_KEM_PRVKEY, BSL_PARAM_TYPE_OCTETS, NULL, 0, 0}, BSL_PARAM_END};
    RETURN_RET_IF_ERR(CRYPT_HybridGetDecapsKeyLen(ctx, &(prvKey[0].valueLen), &(kemDK[0].valueLen)), ret);
    RETURN_RET_IF_ERR(CRYPT_HybridGetKeyPtr(ctx, dk->data, dk->len, prvKey, kemDK), ret);

    if (ctx->pKeyMethod->id == CRYPT_PKEY_X25519) {
        prvKey[0].key = CRYPT_PARAM_CURVE25519_PRVKEY;
    }
    RETURN_RET_IF_ERR(ctx->kemMethod->setPrv(ctx->kemCtx, kemDK), ret);
    return ctx->pKeyMethod->setPrv(ctx->pkeyCtx, prvKey);
}

int32_t CRYPT_HYBRID_KEM_GetEncapsKeyEx(const CRYPT_HybridKemCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_KemEncapsKey pub = {0};
    BSL_Param *paramPub = GetParamValue(para, CRYPT_PARAM_HYBRID_PUBKEY, &pub.data, &(pub.len));
    if (paramPub == NULL) {
        paramPub = GetParamValue(para, CRYPT_PARAM_PKEY_ENCODE_PUBKEY, &pub.data, &(pub.len));
    }
    int32_t ret = CRYPT_HYBRID_KEM_GetEncapsKey(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramPub->useLen = pub.len;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HYBRID_KEM_GetDecapsKeyEx(const CRYPT_HybridKemCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_KemDecapsKey prv = {0};
    BSL_Param *paramPrv = GetParamValue(para, CRYPT_PARAM_HYBRID_PRVKEY, &prv.data, &(prv.len));
    int32_t ret = CRYPT_HYBRID_KEM_GetDecapsKey(ctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramPrv->useLen = prv.len;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HYBRID_KEM_SetEncapsKeyEx(CRYPT_HybridKemCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_KemEncapsKey pub = {0};
    if (GetConstParamValue(para, CRYPT_PARAM_HYBRID_PUBKEY, &pub.data, &pub.len) == NULL) {
        (void)GetConstParamValue(para, CRYPT_PARAM_PKEY_ENCODE_PUBKEY, &pub.data, &pub.len);
    }
    return CRYPT_HYBRID_KEM_SetEncapsKey(ctx, &pub);
}

int32_t CRYPT_HYBRID_KEM_SetDecapsKeyEx(CRYPT_HybridKemCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_KemDecapsKey prv = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_HYBRID_PRVKEY, &prv.data, &prv.len);
    return CRYPT_HYBRID_KEM_SetDecapsKey(ctx, &prv);
}

int32_t CRYPT_HYBRID_KEM_Encaps(const CRYPT_HybridKemCtx *ctx, uint8_t *cipher, uint32_t *cipherLen,
    uint8_t *sharekey, uint32_t *shareLen)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || cipher == NULL || cipherLen == NULL || sharekey == NULL || shareLen == NULL),
        CRYPT_NULL_INPUT);

    BSL_Param kemCT = { 0 };
    BSL_Param pubKey[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, NULL, 0, 0}, BSL_PARAM_END};
    RETURN_RET_IF_ERR(CRYPT_HybridGetCipherTextLen(ctx, &(pubKey[0].valueLen), &(kemCT.valueLen)), ret);
    RETURN_RET_IF_ERR(CRYPT_HybridGetKeyPtr(ctx, cipher, *cipherLen, pubKey, &kemCT), ret);

    void *tmpKey = ctx->pKeyMethod->dupCtx(ctx->pkeyCtx);
    RETURN_RET_IF(tmpKey == NULL, CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF(ctx->pKeyMethod->gen(tmpKey), ret);
    if (ctx->pKeyMethod->id == CRYPT_PKEY_X25519) {
        pubKey[0].key = CRYPT_PARAM_CURVE25519_PUBKEY;
    }
    GOTO_ERR_IF(ctx->pKeyMethod->getPub(tmpKey, pubKey), ret);

    BSL_Param kemSK = { 0 };
    BSL_Param pkeyShared = { 0 };
    GOTO_ERR_IF(CRYPT_HybridGetShareKeyLen(ctx, &pkeyShared.valueLen, &kemSK.valueLen), ret);
    GOTO_ERR_IF(CRYPT_HybridGetKeyPtr(ctx, sharekey, *shareLen, &pkeyShared, &kemSK), ret);
    GOTO_ERR_IF(ctx->pKeyMethod->computeShareKey(tmpKey, ctx->pkeyCtx, pkeyShared.value, &pkeyShared.valueLen), ret);

    GOTO_ERR_IF(ctx->kemMethod->encaps(ctx->kemCtx, kemCT.value, &kemCT.valueLen, kemSK.value, &kemSK.valueLen), ret);
    *shareLen = pkeyShared.valueLen + kemSK.valueLen;
    *cipherLen = pubKey[0].valueLen + kemCT.valueLen;

ERR:
    ctx->pKeyMethod->freeCtx(tmpKey);
    return ret;
}

int32_t CRYPT_HYBRID_KEM_Decaps(const CRYPT_HybridKemCtx *ctx, uint8_t *cipher, uint32_t cipherLen,
    uint8_t *sharekey, uint32_t *shareLen)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || cipher == NULL || sharekey == NULL || shareLen == NULL), CRYPT_NULL_INPUT);

    BSL_Param kemCT = { 0 };
    BSL_Param pubKey[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, NULL, 0, 0}, BSL_PARAM_END};
    RETURN_RET_IF_ERR(CRYPT_HybridGetCipherTextLen(ctx, &pubKey[0].valueLen, &kemCT.valueLen), ret);
    RETURN_RET_IF_ERR(CRYPT_HybridGetKeyPtr(ctx, cipher, cipherLen, pubKey, &kemCT), ret);

    void *tmpKey = ctx->pKeyMethod->dupCtx(ctx->pkeyCtx);
    RETURN_RET_IF(tmpKey == NULL, CRYPT_MEM_ALLOC_FAIL);
    if (ctx->pKeyMethod->id == CRYPT_PKEY_X25519) {
        pubKey[0].key = CRYPT_PARAM_CURVE25519_PUBKEY;
    }
    GOTO_ERR_IF(ctx->pKeyMethod->setPub(tmpKey, pubKey), ret);

    BSL_Param pkeyShared = { 0 };
    BSL_Param kemSK = { 0 };
    GOTO_ERR_IF(CRYPT_HybridGetShareKeyLen(ctx, &pkeyShared.valueLen, &kemSK.valueLen), ret);
    GOTO_ERR_IF(CRYPT_HybridGetKeyPtr(ctx, sharekey, *shareLen, &pkeyShared, &kemSK), ret);
    GOTO_ERR_IF(ctx->pKeyMethod->computeShareKey(ctx->pkeyCtx, tmpKey, pkeyShared.value, &pkeyShared.valueLen), ret);

    GOTO_ERR_IF(ctx->kemMethod->decaps(ctx->kemCtx, kemCT.value, kemCT.valueLen, kemSK.value, &kemSK.valueLen), ret);
    *shareLen = pkeyShared.valueLen + kemSK.valueLen;
ERR:
    ctx->pKeyMethod->freeCtx(tmpKey);
    return ret;
}

#endif
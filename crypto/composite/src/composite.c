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
#ifdef HITLS_CRYPTO_COMPOSITE

#include <string.h>

#include "composite_local.h"
#include "bsl_asn1.h"
#include "eal_pkey_local.h"
#include "eal_md_local.h"
#include "crypt_utils.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_md.h"
#include "crypt_mldsa.h"
#include "crypt_eal_pkey.h"

static const uint8_t PREFIX[] = {0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x65, 0x41, 0x6C,
                                 0x67, 0x6F, 0x72, 0x69, 0x74, 0x68, 0x6D, 0x53, 0x69, 0x67, 0x6E,
                                 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x32, 0x30, 0x32, 0x35};
static const uint8_t COMPOSITE_RSA_F4[] = {0x01, 0x00, 0x01};

static const COMPOSITE_ALG_INFO g_composite_info[] = {
#ifdef HITLS_CRYPTO_RSA
    {CRYPT_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256, "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_44, CRYPT_PKEY_RSA, BSL_CID_RSASSAPSS,
     CRYPT_MD_SHA256, CRYPT_MD_SHA256, 2048, 1582, 1226, 1312, 32, 2420},
    {CRYPT_COMPOSITE_MLDSA44_RSA2048_PKCS15_SHA256, "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_44, CRYPT_PKEY_RSA, BSL_CID_RSA,
     CRYPT_MD_SHA256, CRYPT_MD_SHA256, 2048, 1582, 1226, 1312, 32, 2420},
#endif
#ifdef HITLS_CRYPTO_ED25519
    {CRYPT_COMPOSITE_MLDSA44_ED25519_SHA512, "COMPSIG-MLDSA44-Ed25519-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_44, CRYPT_PKEY_ED25519, CRYPT_PKEY_PARAID_MAX,
     CRYPT_MD_SHA512, CRYPT_MD_SHA512, 0, 1344, 64, 1312, 32, 2420},
#endif
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_COMPOSITE_MLDSA44_ECDSA_P256_SHA256, "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_44, CRYPT_PKEY_ECDSA, CRYPT_ECC_NISTP256,
     CRYPT_MD_SHA256, CRYPT_MD_SHA256, 0, 1377, 83, 1312, 32, 2420},
#endif
#ifdef HITLS_CRYPTO_RSA
    {CRYPT_COMPOSITE_MLDSA65_RSA3072_PSS_SHA512, "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_65, CRYPT_PKEY_RSA, BSL_CID_RSASSAPSS,
     CRYPT_MD_SHA512, CRYPT_MD_SHA256, 3072, 2350, 1802, 1952, 32, 3309},
    {CRYPT_COMPOSITE_MLDSA65_RSA3072_PKCS15_SHA512, "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_65, CRYPT_PKEY_RSA, BSL_CID_RSA,
     CRYPT_MD_SHA512, CRYPT_MD_SHA256, 3072, 2350, 1802, 1952, 32, 3309},
    {CRYPT_COMPOSITE_MLDSA65_RSA4096_PSS_SHA512, "COMPSIG-MLDSA65-RSA4096-PSS-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_65, CRYPT_PKEY_RSA, BSL_CID_RSASSAPSS,
     CRYPT_MD_SHA512, CRYPT_MD_SHA384, 4096, 2478, 2383, 1952, 32, 3309},
    {CRYPT_COMPOSITE_MLDSA65_RSA4096_PKCS15_SHA512, "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_65, CRYPT_PKEY_RSA, BSL_CID_RSA,
     CRYPT_MD_SHA512, CRYPT_MD_SHA384, 4096, 2478, 2383, 1952, 32, 3309},
#endif
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_COMPOSITE_MLDSA65_ECDSA_P256_SHA512, "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_65, CRYPT_PKEY_ECDSA, CRYPT_ECC_NISTP256,
     CRYPT_MD_SHA512, CRYPT_MD_SHA256, 0, 2017, 83, 1952, 32, 3309},
    {CRYPT_COMPOSITE_MLDSA65_ECDSA_P384_SHA512, "COMPSIG-MLDSA65-ECDSA-P384-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_65, CRYPT_PKEY_ECDSA, CRYPT_ECC_NISTP384,
     CRYPT_MD_SHA512, CRYPT_MD_SHA384, 0, 2049, 96, 1952, 32, 3309},
    {CRYPT_COMPOSITE_MLDSA65_ECDSA_BRAINPOOLP256R1_SHA512, "COMPSIG-MLDSA65-ECDSA-BP256-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_65, CRYPT_PKEY_ECDSA, CRYPT_ECC_BRAINPOOLP256R1,
     CRYPT_MD_SHA512, CRYPT_MD_SHA256, 0, 2017, 84, 1952, 32, 3309},
#endif
#ifdef HITLS_CRYPTO_ED25519
    {CRYPT_COMPOSITE_MLDSA65_ED25519_SHA512, "COMPSIG-MLDSA65-Ed25519-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_65, CRYPT_PKEY_ED25519, CRYPT_PKEY_PARAID_MAX,
     CRYPT_MD_SHA512, CRYPT_MD_SHA512, 0, 1984, 64, 1952, 32, 3309},
#endif
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_COMPOSITE_MLDSA87_ECDSA_P384_SHA512, "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_87, CRYPT_PKEY_ECDSA, CRYPT_ECC_NISTP384,
     CRYPT_MD_SHA512, CRYPT_MD_SHA384, 0, 2689, 96, 2592, 32, 4627},
    {CRYPT_COMPOSITE_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512, "COMPSIG-MLDSA87-ECDSA-BP384-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_87, CRYPT_PKEY_ECDSA, CRYPT_ECC_BRAINPOOLP384R1,
     CRYPT_MD_SHA512, CRYPT_MD_SHA384, 0, 2689,	100, 2592, 32, 4627},
#endif
#ifdef HITLS_CRYPTO_RSA
    {CRYPT_COMPOSITE_MLDSA87_RSA3072_PSS_SHA512, "COMPSIG-MLDSA87-RSA3072-PSS-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_87, CRYPT_PKEY_RSA, BSL_CID_RSASSAPSS,
     CRYPT_MD_SHA512, CRYPT_MD_SHA256, 3072, 2990, 1802, 2592, 32, 4627},
    {CRYPT_COMPOSITE_MLDSA87_RSA4096_PSS_SHA512, "COMPSIG-MLDSA87-RSA4096-PSS-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_87, CRYPT_PKEY_RSA, BSL_CID_RSASSAPSS,
     CRYPT_MD_SHA512, CRYPT_MD_SHA384, 4096, 3118,	2383, 2592, 32, 4627},
#endif
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_COMPOSITE_MLDSA87_ECDSA_P521_SHA512, "COMPSIG-MLDSA87-ECDSA-P521-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_87, CRYPT_PKEY_ECDSA, CRYPT_ECC_NISTP521,
     CRYPT_MD_SHA512, CRYPT_MD_SHA512, 0, 2725,	114, 2592, 32, 4627},
#endif
};

const COMPOSITE_ALG_INFO *CRYPT_COMPOSITE_GetInfo(int32_t paramId)
{
    const COMPOSITE_ALG_INFO *info = NULL;
    for (size_t i = 0; i < sizeof(g_composite_info) / sizeof(g_composite_info[0]); i++) {
        if (g_composite_info[i].paramId == paramId) {
            info = &g_composite_info[i];
            return info;
        }
    }
    return NULL;
}

CRYPT_CompositeCtx *CRYPT_COMPOSITE_NewCtx(void)
{
    CRYPT_CompositeCtx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_CompositeCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

CRYPT_CompositeCtx *CRYPT_COMPOSITE_NewCtxEx(void *libCtx)
{
    CRYPT_CompositeCtx *ctx = CRYPT_COMPOSITE_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

static void CompositeFreeInnerCtx(CRYPT_CompositeCtx *ctx)
{
    CRYPT_EAL_PkeyFreeCtx(ctx->pqcCtx);
    ctx->pqcCtx = NULL;
    CRYPT_EAL_PkeyFreeCtx(ctx->tradCtx);
    ctx->tradCtx = NULL;
    ctx->info = NULL;
}

void CRYPT_COMPOSITE_FreeCtx(CRYPT_CompositeCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    int ref = 0;
    BSL_SAL_AtomicDownReferences(&(ctx->references), &ref);
    if (ref > 0) {
        return;
    }
    CompositeFreeInnerCtx(ctx);
    BSL_SAL_FREE(ctx->ctxInfo);
    BSL_SAL_ReferencesFree(&(ctx->references));
    BSL_SAL_FREE(ctx);
}

CRYPT_CompositeCtx *CRYPT_COMPOSITE_DupCtx(CRYPT_CompositeCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_CompositeCtx *newCtx = CRYPT_COMPOSITE_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    newCtx->info = ctx->info;
    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->ctxInfo, ctx->ctxInfo, BSL_SAL_Dump(ctx->ctxInfo, ctx->ctxLen),
        CRYPT_MEM_ALLOC_FAIL);
    newCtx->pubLen = ctx->pubLen;
    newCtx->prvLen = ctx->prvLen;
    newCtx->ctxLen = ctx->ctxLen;
    if (ctx->pqcCtx != NULL) {
        newCtx->pqcCtx = CRYPT_EAL_PkeyDupCtx(ctx->pqcCtx);
        GOTO_ERR_IF_TRUE(newCtx->pqcCtx == NULL, CRYPT_MEM_ALLOC_FAIL);
    }
    if (ctx->tradCtx != NULL) {
        newCtx->tradCtx = CRYPT_EAL_PkeyDupCtx(ctx->tradCtx);
        GOTO_ERR_IF_TRUE(newCtx->tradCtx == NULL, CRYPT_MEM_ALLOC_FAIL);
    }
    newCtx->libCtx = ctx->libCtx;
    return newCtx;
ERR:
    CRYPT_COMPOSITE_FreeCtx(newCtx);
    return NULL;
}

static int32_t CompositeGetRequiredSignLen(CRYPT_CompositeCtx *ctx, uint32_t *signLen)
{
    uint32_t tradSigLen = 0;
    int32_t ret;

    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF_ERR(CRYPT_EAL_PkeyCtrl(ctx->tradCtx, CRYPT_CTRL_GET_SIGNLEN, &tradSigLen, sizeof(tradSigLen)), ret);
    *signLen = ctx->info->pqcSigLen + tradSigLen;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeGetSignLen(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    uint32_t signLen = 0;
    int32_t ret;

    RETURN_RET_IF(val == NULL || len != sizeof(int32_t), CRYPT_INVALID_ARG);
    RETURN_RET_IF_ERR_EX(CompositeGetRequiredSignLen(ctx, &signLen), ret);
    *(int32_t *)val = (int32_t)signLen;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeSetRsaPara(CRYPT_CompositeCtx *ctx)
{
    uint32_t bits = ctx->info->bits;
    BSL_Param param[] = {{CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS,
                           (void *)(uintptr_t)COMPOSITE_RSA_F4, sizeof(COMPOSITE_RSA_F4), 0},
                         {CRYPT_PARAM_RSA_BITS, BSL_PARAM_TYPE_UINT32, &bits, sizeof(bits), 0},
                         BSL_PARAM_END};
    return CRYPT_EAL_PkeySetParaEx(ctx->tradCtx, param);
}

static int32_t CRYPT_CompositeSetAlgInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    int32_t ret;
    RETURN_RET_IF(len != sizeof(int32_t) || val == NULL, CRYPT_INVALID_ARG);
    RETURN_RET_IF(ctx->info != NULL, CRYPT_COMPOSITE_CTRL_INIT_REPEATED);
    ctx->info = CRYPT_COMPOSITE_GetInfo(*(int32_t *)val);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_INVALID_ARG);
    ctx->pqcCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx->libCtx, ctx->info->pqcAlg, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, NULL);
    if (ctx->pqcCtx == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    ctx->tradCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx->libCtx, ctx->info->tradAlg, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, NULL);
    if (ctx->tradCtx == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    int32_t pqcParam = ctx->info->pqcParam;
    GOTO_ERR_IF_EX(CRYPT_EAL_PkeyCtrl(ctx->pqcCtx, CRYPT_CTRL_SET_PARA_BY_ID, &(pqcParam), sizeof(pqcParam)), ret);
    if (ctx->info->tradAlg == CRYPT_PKEY_RSA) {
        GOTO_ERR_IF_EX(CRYPT_CompositeSetRsaPara(ctx), ret);
    }
    if (ctx->info->tradAlg == CRYPT_PKEY_ECDSA) {
        int32_t curve = ctx->info->tradParam;
        GOTO_ERR_IF_EX(CRYPT_EAL_PkeyCtrl(ctx->tradCtx, CRYPT_CTRL_SET_PARA_BY_ID, &curve, sizeof(curve)), ret);
    }
    return CRYPT_SUCCESS;
ERR:
    CompositeFreeInnerCtx(ctx);
    BSL_ERR_PUSH_ERROR(ret);
    return ret;
}

static int32_t CRYPT_CompositeSetctxInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    uint8_t *ctxInfo = NULL;

    RETURN_RET_IF(len > COMPOSITE_MAX_CTX_BYTES, CRYPT_COMPOSITE_KEYLEN_ERROR);
    if (len == 0) {
        BSL_SAL_FREE(ctx->ctxInfo);
        ctx->ctxLen = 0;
        return CRYPT_SUCCESS;
    }
    RETURN_RET_IF(val == NULL, CRYPT_INVALID_ARG);
    ctxInfo = BSL_SAL_Dump((uint8_t *)val, len);
    RETURN_RET_IF(ctxInfo == NULL, CRYPT_MEM_ALLOC_FAIL);
    BSL_SAL_FREE(ctx->ctxInfo);
    ctx->ctxInfo = ctxInfo;
    ctx->ctxLen = len;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeGetParaId(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL || len != sizeof(int32_t), CRYPT_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    *(int32_t *)val = ctx->info->paramId;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeGetSecBits(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    int32_t ret;
    int32_t pqcSecBits = 0;
    int32_t tradSecBits = 0;

    RETURN_RET_IF(val == NULL || len != sizeof(int32_t), CRYPT_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);

    RETURN_RET_IF_ERR(CRYPT_EAL_PkeyCtrl(ctx->pqcCtx, CRYPT_CTRL_GET_SECBITS, &pqcSecBits, sizeof(pqcSecBits)), ret);
    RETURN_RET_IF_ERR(CRYPT_EAL_PkeyCtrl(ctx->tradCtx, CRYPT_CTRL_GET_SECBITS, &tradSecBits, sizeof(tradSecBits)),
        ret);

    *(int32_t *)val = (pqcSecBits < tradSecBits) ? pqcSecBits : tradSecBits;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeGetPubKeyLen(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL || len != sizeof(uint32_t), CRYPT_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(ctx->pubLen == 0, CRYPT_COMPOSITE_KEY_NOT_SET);
    *(uint32_t *)val = ctx->pubLen;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeGetPrvKeyLen(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL || len != sizeof(uint32_t), CRYPT_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(ctx->prvLen == 0, CRYPT_COMPOSITE_KEY_NOT_SET);
    *(uint32_t *)val = ctx->prvLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_COMPOSITE_Ctrl(CRYPT_CompositeCtx *ctx, int32_t opt, void *val, uint32_t len)
{
    RETURN_RET_IF(ctx == NULL, CRYPT_NULL_INPUT);
    switch (opt) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            return CRYPT_CompositeSetAlgInfo(ctx, val, len);
        case CRYPT_CTRL_GET_PARAID:
            return CRYPT_CompositeGetParaId(ctx, val, len);
        case CRYPT_CTRL_GET_SIGNLEN:
            return CRYPT_CompositeGetSignLen(ctx, val, len);
        case CRYPT_CTRL_GET_SECBITS:
            return CRYPT_CompositeGetSecBits(ctx, val, len);
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            return CRYPT_CompositeGetPubKeyLen(ctx, val, len);
        case CRYPT_CTRL_GET_PRVKEY_LEN:
            return CRYPT_CompositeGetPrvKeyLen(ctx, val, len);
        case CRYPT_CTRL_SET_CTX_INFO:
            return CRYPT_CompositeSetctxInfo(ctx, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

static int32_t CompositeConcatKey(const BSL_Buffer *pqcKey, const BSL_Buffer *tradKey, uint8_t **key, uint32_t *keyLen)
{
    uint32_t totalLen = pqcKey->dataLen + tradKey->dataLen;
    uint8_t *tmp = (uint8_t *)BSL_SAL_Malloc(totalLen);
    RETURN_RET_IF(tmp == NULL, CRYPT_MEM_ALLOC_FAIL);
    memcpy(tmp, pqcKey->data, pqcKey->dataLen);
    memcpy(tmp + pqcKey->dataLen, tradKey->data, tradKey->dataLen);
    *key = tmp;
    *keyLen = totalLen;
    return CRYPT_SUCCESS;
}

static int32_t CompositeRefreshCachedPrvKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *prvKey)
{
    int32_t ret;
    BSL_Buffer pqcPrv = {0};
    BSL_Buffer tradPrv = {0};

    GOTO_ERR_IF(CRYPT_CompositeGetPqcPrvKey(ctx, &pqcPrv), ret);
    GOTO_ERR_IF(CRYPT_CompositeGetTradPrvKey(ctx, &tradPrv), ret);
    GOTO_ERR_IF(CompositeConcatKey(&pqcPrv, &tradPrv, &prvKey->data, &prvKey->dataLen), ret);
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_ClearFree(pqcPrv.data, pqcPrv.dataLen);
    BSL_SAL_ClearFree(tradPrv.data, tradPrv.dataLen);
    return ret;
}

static int32_t CompositeRefreshCachedPubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *pubKey)
{
    int32_t ret;
    BSL_Buffer pqcPub = {0};
    BSL_Buffer tradPub = {0};

    GOTO_ERR_IF(CRYPT_CompositeGetPqcPubKey(ctx, &pqcPub), ret);
    GOTO_ERR_IF(CRYPT_CompositeGetTradPubKey(ctx, &tradPub), ret);
    GOTO_ERR_IF(CompositeConcatKey(&pqcPub, &tradPub, &pubKey->data, &pubKey->dataLen), ret);
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_Free(pqcPub.data);
    BSL_SAL_Free(tradPub.data);
    return ret;
}

static int32_t CompositeUpdatePrvKeyLen(CRYPT_CompositeCtx *ctx)
{
    int32_t ret;
    uint32_t pqcPrvLen = 0;
    uint32_t tradPrvLen = 0;
    BSL_Buffer tradPrv = {0};

    pqcPrvLen = ctx->info->pqcPrvkeyLen;
    if (ctx->info->tradAlg == CRYPT_PKEY_RSA || ctx->info->tradAlg == CRYPT_PKEY_ECDSA) {
        GOTO_ERR_IF(CRYPT_CompositeGetTradPrvKey(ctx, &tradPrv), ret);
        tradPrvLen = tradPrv.dataLen;
    } else {
        GOTO_ERR_IF(CRYPT_EAL_PkeyCtrl(ctx->tradCtx, CRYPT_CTRL_GET_PRVKEY_LEN, &tradPrvLen, sizeof(tradPrvLen)), ret);
    }
    ctx->prvLen = pqcPrvLen + tradPrvLen;
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_ClearFree(tradPrv.data, tradPrv.dataLen);
    return ret;
}

static int32_t CompositeUpdatePubKeyLen(CRYPT_CompositeCtx *ctx)
{
    int32_t ret;
    uint32_t pqcPubLen = 0;
    uint32_t tradPubLen = 0;
    BSL_Buffer tradPub = {0};

    pqcPubLen = ctx->info->pqcPubkeyLen;
    if (ctx->info->tradAlg == CRYPT_PKEY_RSA) {
        GOTO_ERR_IF(CRYPT_CompositeGetTradPubKey(ctx, &tradPub), ret);
        tradPubLen = tradPub.dataLen;
    } else {
        GOTO_ERR_IF(CRYPT_EAL_PkeyCtrl(ctx->tradCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &tradPubLen, sizeof(tradPubLen)), ret);
        GOTO_ERR_IF_TRUE(tradPubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
    }
    ctx->pubLen = pqcPubLen + tradPubLen;
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_FREE(tradPub.data);
    return ret;
}

int32_t CRYPT_COMPOSITE_GenKey(CRYPT_CompositeCtx *ctx)
{
    int32_t ret;
    RETURN_RET_IF(ctx == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    GOTO_ERR_IF(CRYPT_EAL_PkeyGen(ctx->pqcCtx), ret);
    GOTO_ERR_IF(CRYPT_EAL_PkeyGen(ctx->tradCtx), ret);
    if (ctx->info->tradAlg == CRYPT_PKEY_RSA) {
        GOTO_ERR_IF(CRYPT_CompositeSetRsaPadding(ctx), ret);
    }
    GOTO_ERR_IF(CompositeUpdatePrvKeyLen(ctx), ret);
    GOTO_ERR_IF(CompositeUpdatePubKeyLen(ctx), ret);
    return CRYPT_SUCCESS;
ERR:
    return ret;
}

int32_t CRYPT_COMPOSITE_GetPrvKey(const CRYPT_CompositeCtx *ctx, CRYPT_CompositePrv *prv)
{
    int32_t ret;
    BSL_Buffer key = {0};

    RETURN_RET_IF((ctx == NULL || prv == NULL || prv->data == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->prvLen == 0, CRYPT_COMPOSITE_KEY_NOT_SET);
    GOTO_ERR_IF(CompositeRefreshCachedPrvKey(ctx, &key), ret);
    ret = CRYPT_COMPOSITE_LEN_NOT_ENOUGH;
    GOTO_ERR_IF_TRUE(prv->len < key.dataLen, ret);
    memcpy(prv->data, key.data, key.dataLen);
    prv->len = key.dataLen;
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_ClearFree(key.data, key.dataLen);
    return ret;
}

int32_t CRYPT_COMPOSITE_GetPubKey(const CRYPT_CompositeCtx *ctx, CRYPT_CompositePub *pub)
{
    int32_t ret;
    BSL_Buffer key = {0};

    RETURN_RET_IF((ctx == NULL || pub == NULL || pub->data == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->pubLen == 0, CRYPT_COMPOSITE_KEY_NOT_SET);
    GOTO_ERR_IF(CompositeRefreshCachedPubKey(ctx, &key), ret);
    ret = CRYPT_COMPOSITE_LEN_NOT_ENOUGH;
    GOTO_ERR_IF_TRUE(pub->len < key.dataLen, ret);
    memcpy(pub->data, key.data, key.dataLen);
    pub->len = key.dataLen;
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_FREE(key.data);
    return ret;
}

static uint32_t CompositeGetImportMaxKeyLen(const CRYPT_CompositeCtx *ctx, uint32_t keyLen)
{
    if (ctx->info->tradAlg != CRYPT_PKEY_RSA) {
        return keyLen;
    }
    /* RSA import may use a larger e than F4, so allow one extra n/8-byte INTEGER in the encoded key. */
    return keyLen + (ctx->info->bits / 8);
}

int32_t CRYPT_COMPOSITE_SetPrvKey(CRYPT_CompositeCtx *ctx, const CRYPT_CompositePrv *prv)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || prv == NULL || prv->data == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(ctx->prvLen != 0, CRYPT_COMPOSITE_KEY_REPEATED_SET);
    RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    RETURN_RET_IF(prv->len > CompositeGetImportMaxKeyLen(ctx, ctx->info->prvKeyLen), CRYPT_COMPOSITE_KEYLEN_ERROR);
    BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
    GOTO_ERR_IF(CRYPT_CompositeSetPqcPrvKey(ctx, &pqcPrv), ret);
    GOTO_ERR_IF(CRYPT_CompositeSetTradPrvKey(ctx, &tradPrv), ret);
    GOTO_ERR_IF(CompositeUpdatePrvKeyLen(ctx), ret);
    return CRYPT_SUCCESS;
ERR:
    return ret;
}

int32_t CRYPT_COMPOSITE_SetPubKey(CRYPT_CompositeCtx *ctx, const CRYPT_CompositePub *pub)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || pub == NULL || pub->data == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(ctx->pubLen != 0, CRYPT_COMPOSITE_KEY_REPEATED_SET);
    RETURN_RET_IF(pub->len <= ctx->info->pqcPubkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    RETURN_RET_IF(pub->len > CompositeGetImportMaxKeyLen(ctx, ctx->info->pubKeyLen), CRYPT_COMPOSITE_KEYLEN_ERROR);
    BSL_Buffer pqcPub = {pub->data, ctx->info->pqcPubkeyLen};
    BSL_Buffer tradPub = {pub->data + ctx->info->pqcPubkeyLen, pub->len - ctx->info->pqcPubkeyLen};
    GOTO_ERR_IF(CRYPT_CompositeSetPqcPubKey(ctx, &pqcPub), ret);
    GOTO_ERR_IF(CRYPT_CompositeSetTradPubKey(ctx, &tradPub), ret);
    GOTO_ERR_IF(CompositeUpdatePubKeyLen(ctx), ret);
    return CRYPT_SUCCESS;
ERR:
    return ret;
}

int32_t CRYPT_COMPOSITE_GetPrvKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    RETURN_RET_IF(para == NULL, CRYPT_NULL_INPUT);
    int32_t ret;
    CRYPT_CompositePrv prv = {0};
    BSL_Param *paramPrv = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
    RETURN_RET_IF_ERR_EX(CRYPT_COMPOSITE_GetPrvKey(ctx, &prv), ret);
    paramPrv->useLen = prv.len;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_COMPOSITE_GetPubKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    RETURN_RET_IF(para == NULL, CRYPT_NULL_INPUT);
    int32_t ret;
    CRYPT_CompositePub pub = {0};
    BSL_Param *paramPub = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PUBKEY, &pub.data, &(pub.len));
    RETURN_RET_IF_ERR_EX(CRYPT_COMPOSITE_GetPubKey(ctx, &pub), ret);
    paramPub->useLen = pub.len;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_COMPOSITE_SetPrvKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para)
{
    RETURN_RET_IF(para == NULL, CRYPT_NULL_INPUT);
    CRYPT_CompositePrv prv = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &prv.len);
    return CRYPT_COMPOSITE_SetPrvKey(ctx, &prv);
}

int32_t CRYPT_COMPOSITE_SetPubKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para)
{
    RETURN_RET_IF(para == NULL, CRYPT_NULL_INPUT);
    CRYPT_CompositePub pub = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_COMPOSITE_PUBKEY, &pub.data, &pub.len);
    return CRYPT_COMPOSITE_SetPubKey(ctx, &pub);
}

static int32_t CompositeGetPreHashLen(CRYPT_MD_AlgId hashId, uint32_t *digestLen)
{
    uint32_t len = CRYPT_EAL_MdGetDigestSize(hashId);
    RETURN_RET_IF(len == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
    *digestLen = len;
    return CRYPT_SUCCESS;
}

static int32_t CompositeMsgEncodeDigest(CRYPT_CompositeCtx *ctx, const uint8_t *digest, uint32_t digestLen,
                                        CRYPT_Data *msg)
{
    const char *label = ctx->info->label;
    uint32_t prefixLen = COMPOSITE_SIGNATURE_PREFIX_LEN;
    uint32_t labelLen = (uint32_t)strlen(label);
    msg->len = prefixLen + labelLen + 1 + ctx->ctxLen + digestLen;
    msg->data = (uint8_t *)BSL_SAL_Malloc(msg->len);
    RETURN_RET_IF(msg->data == NULL, CRYPT_MEM_ALLOC_FAIL);
    uint8_t *ptr = msg->data;
    memcpy(ptr, PREFIX, prefixLen);
    ptr += prefixLen;
    memcpy(ptr, label, labelLen);
    ptr += labelLen;
    *ptr = ctx->ctxLen;
    ptr++;
    if (ctx->ctxInfo != NULL && ctx->ctxLen > 0) {
        memcpy(ptr, ctx->ctxInfo, ctx->ctxLen);
        ptr += ctx->ctxLen;
    }
    memcpy(ptr, digest, digestLen);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_COMPOSITE_SignData(CRYPT_CompositeCtx *ctx, const uint8_t *data, uint32_t dataLen,
                                 uint8_t *sign, uint32_t *signLen)
{
    uint32_t expectedDigestLen = 0;
    uint32_t requiredSignLen = 0;
    int32_t ret;

    RETURN_RET_IF(ctx == NULL || sign == NULL || signLen == NULL || (data == NULL && dataLen != 0), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF_ERR(CompositeGetPreHashLen(ctx->info->hashId, &expectedDigestLen), ret);
    RETURN_RET_IF(dataLen != expectedDigestLen, CRYPT_INVALID_ARG);
    RETURN_RET_IF_ERR_EX(CompositeGetRequiredSignLen(ctx, &requiredSignLen), ret);
    RETURN_RET_IF(*signLen < requiredSignLen, CRYPT_COMPOSITE_INVALID_SIG_LEN);

    CRYPT_Data msg = {0};
    uint8_t *tmpSign = NULL;
    uint32_t pqcSigLen = ctx->info->pqcSigLen;
    uint32_t tradSigLen = requiredSignLen - pqcSigLen;
    RETURN_RET_IF_ERR(CompositeMsgEncodeDigest(ctx, data, dataLen, &msg), ret);
    tmpSign = (uint8_t *)BSL_SAL_Malloc(requiredSignLen);
    ret = CRYPT_MEM_ALLOC_FAIL;
    GOTO_ERR_IF_TRUE(tmpSign == NULL, ret);
    GOTO_ERR_IF(CRYPT_EAL_PkeyCtrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctx->info->label,
        (uint32_t)strlen(ctx->info->label)), ret);
    GOTO_ERR_IF(CRYPT_EAL_PkeySign(ctx->pqcCtx, CRYPT_MD_MAX, msg.data, msg.len, tmpSign, &pqcSigLen), ret);
    GOTO_ERR_IF(CRYPT_EAL_PkeySign(ctx->tradCtx, ctx->info->tradHashId, msg.data, msg.len, tmpSign + pqcSigLen,
        &tradSigLen), ret);
    memcpy(sign, tmpSign, pqcSigLen + tradSigLen);
    *signLen = pqcSigLen + tradSigLen;
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_ClearFree(tmpSign, requiredSignLen);
    BSL_SAL_ClearFree(msg.data, msg.len);
    return ret;
}

int32_t CRYPT_COMPOSITE_Sign(CRYPT_CompositeCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                             uint8_t *sign, uint32_t *signLen)
{
    int32_t ret;
    uint8_t digest[64];
    uint32_t digestLen = sizeof(digest);

    RETURN_RET_IF(ctx == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF((CRYPT_MD_AlgId)algId != ctx->info->hashId, CRYPT_INVALID_ARG);
    RETURN_RET_IF_ERR(CRYPT_EAL_ProviderMd(ctx->libCtx, ctx->info->hashId, NULL, data, dataLen, digest, &digestLen),
        ret);
    return CRYPT_COMPOSITE_SignData(ctx, digest, digestLen, sign, signLen);
}

int32_t CRYPT_COMPOSITE_VerifyData(CRYPT_CompositeCtx *ctx, const uint8_t *data, uint32_t dataLen,
                                   const uint8_t *sign, uint32_t signLen)
{
    int32_t ret;
    uint32_t expectedDigestLen = 0;

    RETURN_RET_IF(ctx == NULL || sign == NULL || (data == NULL && dataLen != 0), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(signLen < ctx->info->pqcSigLen, CRYPT_COMPOSITE_INVALID_SIG_LEN);
    RETURN_RET_IF_ERR(CompositeGetPreHashLen(ctx->info->hashId, &expectedDigestLen), ret);
    RETURN_RET_IF(dataLen != expectedDigestLen, CRYPT_INVALID_ARG);

    CRYPT_Data msg = {0};
    uint32_t pqcSigLen = ctx->info->pqcSigLen;
    uint32_t tradSigLen = signLen - pqcSigLen;
    RETURN_RET_IF_ERR(CompositeMsgEncodeDigest(ctx, data, dataLen, &msg), ret);
    GOTO_ERR_IF(CRYPT_EAL_PkeyCtrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctx->info->label,
        (uint32_t)strlen(ctx->info->label)), ret);
    GOTO_ERR_IF(CRYPT_EAL_PkeyVerify(ctx->pqcCtx, CRYPT_MD_MAX, msg.data, msg.len, sign, pqcSigLen), ret);
    GOTO_ERR_IF(CRYPT_EAL_PkeyVerify(ctx->tradCtx, ctx->info->tradHashId, msg.data, msg.len, sign + pqcSigLen,
        tradSigLen), ret);
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_ClearFree(msg.data, msg.len);
    return ret;
}

int32_t CRYPT_COMPOSITE_Verify(CRYPT_CompositeCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                               const uint8_t *sign, uint32_t signLen)
{
    int32_t ret;
    uint8_t digest[64];
    uint32_t digestLen = sizeof(digest);

    RETURN_RET_IF(ctx == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF((CRYPT_MD_AlgId)algId != ctx->info->hashId, CRYPT_INVALID_ARG);
    RETURN_RET_IF_ERR(CRYPT_EAL_ProviderMd(ctx->libCtx, ctx->info->hashId, NULL, data, dataLen, digest, &digestLen),
        ret);
    return CRYPT_COMPOSITE_VerifyData(ctx, digest, digestLen, sign, signLen);
}

#ifdef HITLS_CRYPTO_COMPOSITE_CHECK
int32_t CRYPT_COMPOSITE_Check(uint32_t checkType, const CRYPT_CompositeCtx *pkey1, const CRYPT_CompositeCtx *pkey2)
{
    int32_t ret;
    int32_t pqcRet;
    int32_t tradRet;

    RETURN_RET_IF(pkey1 == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(pkey1->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(checkType == CRYPT_PKEY_CHECK_KEYPAIR && pkey2 == NULL, CRYPT_NULL_INPUT);
    if (pkey2 != NULL) {
        RETURN_RET_IF(pkey2->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
        RETURN_RET_IF(pkey1->info->paramId != pkey2->info->paramId, CRYPT_INVALID_ARG);
    }
    switch (checkType) {
        case CRYPT_PKEY_CHECK_KEYPAIR:
            pqcRet = CRYPT_EAL_PkeyPairCheck((CRYPT_EAL_PkeyCtx *)pkey1->pqcCtx, (CRYPT_EAL_PkeyCtx *)pkey2->pqcCtx);
            tradRet = CRYPT_EAL_PkeyPairCheck((CRYPT_EAL_PkeyCtx *)pkey1->tradCtx,
                (CRYPT_EAL_PkeyCtx *)pkey2->tradCtx);
            break;
        case CRYPT_PKEY_CHECK_PRVKEY:
            pqcRet = CRYPT_EAL_PkeyPrvCheck((CRYPT_EAL_PkeyCtx *)pkey1->pqcCtx);
            tradRet = CRYPT_EAL_PkeyPrvCheck((CRYPT_EAL_PkeyCtx *)pkey1->tradCtx);
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
    ret = (pqcRet != CRYPT_SUCCESS) ? pqcRet : tradRet;
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_COMPOSITE_CHECK
#endif

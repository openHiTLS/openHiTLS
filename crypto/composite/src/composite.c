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
#include "crypt_mldsa.h"
#include "crypt_eal_pkey.h"

static const uint8_t PREFIX[] = {0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x65, 0x41, 0x6C,
                                 0x67, 0x6F, 0x72, 0x69, 0x74, 0x68, 0x6D, 0x53, 0x69, 0x67, 0x6E,
                                 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x32, 0x30, 0x32, 0x35};

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
    if (ctx->pqcMethod != NULL && ctx->pqcMethod->freeCtx != NULL) {
        ctx->pqcMethod->freeCtx(ctx->pqcCtx);
    }
    if (ctx->tradMethod != NULL && ctx->tradMethod->freeCtx != NULL) {
        ctx->tradMethod->freeCtx(ctx->tradCtx);
    }
    BSL_SAL_ClearFree(ctx->prvKey, ctx->prvLen);
    BSL_SAL_FREE(ctx->pubKey);
    BSL_SAL_FREE(ctx->ctxInfo);
    BSL_SAL_FREE(ctx->e);
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
    newCtx->pqcMethod = ctx->pqcMethod;
    newCtx->tradMethod = ctx->tradMethod;
    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->pubKey, ctx->pubKey, BSL_SAL_Dump(ctx->pubKey, ctx->pubLen),
        CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->prvKey, ctx->prvKey, BSL_SAL_Dump(ctx->prvKey, ctx->prvLen),
        CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->ctxInfo, ctx->ctxInfo, BSL_SAL_Dump(ctx->ctxInfo, ctx->ctxLen),
        CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newCtx->e, ctx->e, BSL_SAL_Dump(ctx->e, ctx->eLen), CRYPT_MEM_ALLOC_FAIL);
    newCtx->pubLen = ctx->pubLen;
    newCtx->prvLen = ctx->prvLen;
    newCtx->ctxLen = ctx->ctxLen;
    newCtx->eLen = ctx->eLen;
    if (ctx->pqcMethod != NULL && ctx->tradMethod != NULL) {
        newCtx->pqcCtx = ctx->pqcMethod->dupCtx(ctx->pqcCtx);
        newCtx->tradCtx = ctx->tradMethod->dupCtx(ctx->tradCtx);
        if (newCtx->pqcCtx == NULL || newCtx->tradCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            goto ERR;
        }
    }
    newCtx->libCtx = ctx->libCtx;
    return newCtx;
ERR:
    CRYPT_COMPOSITE_FreeCtx(newCtx);
    return NULL;
}

static int32_t CRYPT_CompositeGetSignLen(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx->info == NULL ||ctx->pqcCtx == NULL || ctx->tradCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYINFO_NOT_SET);
        return CRYPT_COMPOSITE_KEYINFO_NOT_SET;
    }
    uint32_t pqcSigLen = ctx->info->pqcSigLen;
    uint32_t tradSigLen = 0;
    int32_t ret = ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_SIGNLEN, &tradSigLen, sizeof(tradSigLen));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *(int32_t *)val = pqcSigLen + tradSigLen;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeSetRsaE(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (val == NULL && len == 0) {
        BSL_SAL_FREE(ctx->e);
        ctx->eLen = 0;
        return CRYPT_SUCCESS;
    }
    RETURN_RET_IF((val == NULL || len == 0), CRYPT_INVALID_ARG);
    uint8_t *e = BSL_SAL_Dump((uint8_t *)val, len);
    RETURN_RET_IF(e == NULL, CRYPT_MEM_ALLOC_FAIL);
    BSL_SAL_FREE(ctx->e);
    ctx->e = e;
    ctx->eLen = len;
    return CRYPT_SUCCESS;
}


static int32_t CRYPT_CompositeSetRsaPara(CRYPT_CompositeCtx *ctx)
{
    static uint8_t defaultE[] = {0x01, 0x00, 0x01};
    void *useE = NULL;
    uint32_t useELen = 0;
    if (ctx->e != NULL && ctx->eLen != 0) {
        useE = ctx->e;
        useELen = ctx->eLen;
    } else {
        useE = defaultE;
        useELen = sizeof(defaultE);
    }
    uint32_t bits = ctx->info->bits;
    BSL_Param param[] = {{CRYPT_PARAM_RSA_E, BSL_PARAM_TYPE_OCTETS, useE, useELen, 0},
                         {CRYPT_PARAM_RSA_BITS, BSL_PARAM_TYPE_UINT32, &bits, sizeof(bits), 0},
                         BSL_PARAM_END};
    return ctx->tradMethod->setPara(ctx->tradCtx, param);
}

static int32_t CRYPT_CompositeSetAlgInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    int32_t ret;
    if (len != sizeof(int32_t) || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (ctx->info != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_CTRL_INIT_REPEATED);
        return CRYPT_COMPOSITE_CTRL_INIT_REPEATED;
    }
    ctx->info = CRYPT_COMPOSITE_GetInfo(*(int32_t *)val);
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    const EAL_PkeyMethod *pqcMethod = CRYPT_EAL_PkeyFindMethod(ctx->info->pqcAlg);
    const EAL_PkeyMethod *tradMethod = CRYPT_EAL_PkeyFindMethod(ctx->info->tradAlg);
    if (pqcMethod == NULL || tradMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    ctx->pqcMethod = pqcMethod;
    ctx->tradMethod = tradMethod;
    ctx->pqcCtx = pqcMethod->newCtx();
    RETURN_RET_IF((ctx->pqcCtx == NULL), CRYPT_MEM_ALLOC_FAIL);
    ctx->tradCtx = tradMethod->newCtx();
    if (ctx->tradCtx == NULL) {
        pqcMethod->freeCtx(ctx->pqcCtx);
        ctx->pqcCtx = NULL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t pqcParam = ctx->info->pqcParam;
    GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_SET_PARA_BY_ID, &(pqcParam), sizeof(pqcParam)), ret);
    if (ctx->info->tradAlg == CRYPT_PKEY_RSA) {
        GOTO_ERR_IF(CRYPT_CompositeSetRsaPara(ctx), ret);
    }
    if (ctx->info->tradAlg == CRYPT_PKEY_ECDSA) {
        int32_t curve = ctx->info->tradParam;
        GOTO_ERR_IF(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_SET_PARA_BY_ID, &curve, sizeof(curve)), ret);
    }
    return CRYPT_SUCCESS;
ERR:
    pqcMethod->freeCtx(ctx->pqcCtx);
    ctx->pqcCtx = NULL;
    tradMethod->freeCtx(ctx->tradCtx);
    ctx->tradCtx = NULL;
    ctx->info = NULL;
    BSL_ERR_PUSH_ERROR(ret);
    return ret;
}

static int32_t CRYPT_CompositeSetctxInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (len > COMPOSITE_MAX_CTX_BYTES) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYLEN_ERROR);
        return CRYPT_COMPOSITE_KEYLEN_ERROR;
    }
    if (ctx->ctxInfo != NULL) {
        BSL_SAL_FREE(ctx->ctxInfo);
        ctx->ctxLen = 0;
    }
    if (len == 0) {
        return CRYPT_SUCCESS;
    }
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    ctx->ctxInfo = BSL_SAL_Dump((uint8_t *)val, len);
    if (ctx->ctxInfo == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->ctxLen = len;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeGetParaId(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL || len != sizeof(uint32_t), CRYPT_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    *(int32_t *)val = ctx->info->paramId;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeGetPubKeyLen(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL || len != sizeof(uint32_t), CRYPT_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(ctx->pubKey == NULL, CRYPT_COMPOSITE_KEY_NOT_SET);
    *(uint32_t *)val = ctx->pubLen;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CompositeGetPrvKeyLen(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL || len != sizeof(uint32_t), CRYPT_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(ctx->prvKey == NULL, CRYPT_COMPOSITE_KEY_NOT_SET);
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
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            return CRYPT_CompositeGetPubKeyLen(ctx, val, len);
        case CRYPT_CTRL_GET_PRVKEY_LEN:
            return CRYPT_CompositeGetPrvKeyLen(ctx, val, len);
        case CRYPT_CTRL_SET_CTX_INFO:
            return CRYPT_CompositeSetctxInfo(ctx, val, len);
        case CRYPT_CTRL_SET_RSA_E:
            return CRYPT_CompositeSetRsaE(ctx, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

static int32_t CRYPT_CompositeCreateKeyBuf(CRYPT_CompositeCtx *ctx)
{
    if (ctx->pubKey == NULL) {
        ctx->pubKey = BSL_SAL_Malloc(ctx->pubLen);
        if (ctx->pubKey == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    if (ctx->prvKey == NULL) {
        ctx->prvKey = BSL_SAL_Malloc(ctx->prvLen);
        if (ctx->prvKey == NULL) {
            BSL_SAL_FREE(ctx->pubKey);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_COMPOSITE_GenKey(CRYPT_CompositeCtx *ctx)
{
    int32_t ret;
    RETURN_RET_IF(ctx == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF((ctx->pqcCtx == NULL || ctx->tradCtx == NULL), CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    if (ctx->pqcMethod->gen == NULL || ctx->tradMethod->gen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    RETURN_RET_IF_ERR(ctx->pqcMethod->gen(ctx->pqcCtx), ret);
    RETURN_RET_IF_ERR(ctx->tradMethod->gen(ctx->tradCtx), ret);
    if (ctx->info->tradAlg == CRYPT_PKEY_RSA) {
        RETURN_RET_IF_ERR(CRYPT_CompositeSetRsaPadding(ctx), ret);
    }
    BSL_Buffer pqcPrv = {0};
    BSL_Buffer tradPrv = {0};
    BSL_Buffer pqcPub = {0};
    BSL_Buffer tradPub = {0};
    GOTO_ERR_IF(CRYPT_CompositeGetPqcPrvKey(ctx, &pqcPrv), ret);
    GOTO_ERR_IF(CRYPT_CompositeGetTradPrvKey(ctx, &tradPrv), ret);
    GOTO_ERR_IF(CRYPT_CompositeGetPqcPubKey(ctx, &pqcPub), ret);
    GOTO_ERR_IF(CRYPT_CompositeGetTradPubKey(ctx, &tradPub), ret);

    ctx->prvLen = pqcPrv.dataLen + tradPrv.dataLen;
    ctx->pubLen = pqcPub.dataLen + tradPub.dataLen;
    GOTO_ERR_IF(CRYPT_CompositeCreateKeyBuf(ctx), ret);

    memcpy(ctx->prvKey, pqcPrv.data, pqcPrv.dataLen);
    memcpy(ctx->prvKey + pqcPrv.dataLen, tradPrv.data, tradPrv.dataLen);
    memcpy(ctx->pubKey, pqcPub.data, pqcPub.dataLen);
    memcpy(ctx->pubKey + pqcPub.dataLen, tradPub.data, tradPub.dataLen);
    BSL_SAL_ClearFree(pqcPrv.data, pqcPrv.dataLen);
    BSL_SAL_ClearFree(tradPrv.data, tradPrv.dataLen);
    BSL_SAL_Free(pqcPub.data);
    BSL_SAL_Free(tradPub.data);

    return CRYPT_SUCCESS;
ERR:
    BSL_SAL_ClearFree(pqcPrv.data, pqcPrv.dataLen);
    BSL_SAL_ClearFree(tradPrv.data, tradPrv.dataLen);
    BSL_SAL_Free(pqcPub.data);
    BSL_SAL_Free(tradPub.data);
    return ret;
}

int32_t CRYPT_COMPOSITE_GetPrvKey(const CRYPT_CompositeCtx *ctx, CRYPT_CompositePrv *prv)
{
    RETURN_RET_IF((ctx == NULL || prv == NULL || prv->data == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->prvKey == NULL, CRYPT_COMPOSITE_KEY_NOT_SET);
    if (prv->len < ctx->prvLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_LEN_NOT_ENOUGH);
        return CRYPT_COMPOSITE_LEN_NOT_ENOUGH;
    }
    memcpy(prv->data, ctx->prvKey, ctx->prvLen);
    prv->len = ctx->prvLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_COMPOSITE_GetPubKey(const CRYPT_CompositeCtx *ctx, CRYPT_CompositePub *pub)
{
    RETURN_RET_IF((ctx == NULL || pub == NULL || pub->data == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->pubKey == NULL, CRYPT_COMPOSITE_KEY_NOT_SET);
    if (pub->len < ctx->pubLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_LEN_NOT_ENOUGH);
        return CRYPT_COMPOSITE_LEN_NOT_ENOUGH;
    }
    memcpy(pub->data, ctx->pubKey, ctx->pubLen);
    pub->len = ctx->pubLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_COMPOSITE_SetPrvKey(CRYPT_CompositeCtx *ctx, const CRYPT_CompositePrv *prv)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || prv == NULL || prv->data == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(ctx->prvKey != NULL, CRYPT_COMPOSITE_KEY_REPEATED_SET);
    RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    RETURN_RET_IF(prv->len > ctx->info->prvKeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
    RETURN_RET_IF_ERR(CRYPT_CompositeSetPqcPrvKey(ctx, &pqcPrv), ret);
    RETURN_RET_IF_ERR(CRYPT_CompositeSetTradPrvKey(ctx, &tradPrv), ret);
    ctx->prvKey = BSL_SAL_Dump(prv->data, prv->len);
    RETURN_RET_IF(ctx->prvKey == NULL, CRYPT_MEM_ALLOC_FAIL);
    ctx->prvLen = prv->len;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_COMPOSITE_SetPubKey(CRYPT_CompositeCtx *ctx, const CRYPT_CompositePub *pub)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || pub == NULL || pub->data == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(ctx->pubKey != NULL, CRYPT_COMPOSITE_KEY_REPEATED_SET);
    RETURN_RET_IF(pub->len <= ctx->info->pqcPubkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    RETURN_RET_IF(pub->len > ctx->info->pubKeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    BSL_Buffer pqcPub = {pub->data, ctx->info->pqcPubkeyLen};
    BSL_Buffer tradPub = {pub->data + ctx->info->pqcPubkeyLen, pub->len - ctx->info->pqcPubkeyLen};
    RETURN_RET_IF_ERR(CRYPT_CompositeSetPqcPubKey(ctx, &pqcPub), ret);
    RETURN_RET_IF_ERR(CRYPT_CompositeSetTradPubKey(ctx, &tradPub), ret);
    ctx->pubKey = BSL_SAL_Dump(pub->data, pub->len);
    RETURN_RET_IF(ctx->pubKey == NULL, CRYPT_MEM_ALLOC_FAIL);
    ctx->pubLen = pub->len;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_COMPOSITE_GetPrvKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    BSL_Param *paramPrv = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
    int32_t ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramPrv->useLen = prv.len;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_COMPOSITE_GetPubKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePub pub = {0};
    BSL_Param *paramPub = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PUBKEY, &pub.data, &(pub.len));
    int32_t ret = CRYPT_COMPOSITE_GetPubKey(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramPub->useLen = pub.len;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_COMPOSITE_SetPrvKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &prv.len);
    return CRYPT_COMPOSITE_SetPrvKey(ctx, &prv);
}

int32_t CRYPT_COMPOSITE_SetPubKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePub pub = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_COMPOSITE_PUBKEY, &pub.data, &pub.len);
    return CRYPT_COMPOSITE_SetPubKey(ctx, &pub);
}

static int32_t CompositePreHash(int32_t hashId, const uint8_t *data, uint32_t dataLen,
                                uint8_t *digest, uint32_t *digestLen)
{
    int32_t ret;
    const EAL_MdMethod *hashMethod = EAL_MdFindDefaultMethod(hashId);
    RETURN_RET_IF(hashMethod == NULL, CRYPT_EAL_ALG_NOT_SUPPORT);
    void *mdCtx = hashMethod->newCtx(NULL, hashMethod->id);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(hashMethod->init(mdCtx, NULL), ret);
    GOTO_ERR_IF(hashMethod->update(mdCtx, data, dataLen), ret);
    GOTO_ERR_IF(hashMethod->final(mdCtx, digest, digestLen), ret);
ERR:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

static int32_t CompositeMsgEncode(CRYPT_CompositeCtx *ctx, int32_t hashId, const uint8_t *data, uint32_t dataLen,
                                  CRYPT_Data *msg)
{
    int32_t ret;
    uint8_t digest[64];
    uint32_t digestLen = sizeof(digest);
    RETURN_RET_IF_ERR(CompositePreHash(hashId, data, dataLen, digest, &digestLen), ret);
    const char *label = ctx->info->label;
    uint32_t prefixLen = COMPOSITE_SIGNATURE_PREFIX_LEN;
    uint32_t labelLen = (uint32_t)strlen(label);
    msg->len = prefixLen + labelLen + 1 +ctx->ctxLen + digestLen;
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

int32_t CRYPT_COMPOSITE_Sign(CRYPT_CompositeCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                             uint8_t *sign, uint32_t *signLen)
{
    (void)algId;
    if (ctx == NULL || data == NULL || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pqcCtx == NULL || ctx->tradCtx == NULL || ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYINFO_NOT_SET);
        return CRYPT_COMPOSITE_KEYINFO_NOT_SET;
    }
    if (*signLen < ctx->info->pqcSigLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_INVALID_SIG_LEN);
        return CRYPT_COMPOSITE_INVALID_SIG_LEN;
    }
    int32_t ret;
    uint32_t pqcSigLen = ctx->info->pqcSigLen;
    uint32_t tradSigLen = *signLen - pqcSigLen;
    CRYPT_Data msg = {0};
    RETURN_RET_IF_ERR(CompositeMsgEncode(ctx, ctx->info->hashId, data, dataLen, &msg), ret);
    if (ctx->pqcMethod->ctrl == NULL || ctx->pqcMethod->sign == NULL || ctx->tradMethod->sign == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctx->info->label,
        (uint32_t)strlen(ctx->info->label)), ret);
    int32_t pqcRet = ctx->pqcMethod->sign(ctx->pqcCtx, CRYPT_MD_MAX, msg.data, msg.len, sign, &pqcSigLen);
    int32_t tradRet = ctx->tradMethod->sign(ctx->tradCtx, ctx->info->tradHashId, msg.data, msg.len, sign + pqcSigLen,
                                           &tradSigLen);
    if (pqcRet != CRYPT_SUCCESS || tradRet != CRYPT_SUCCESS) {
        ret = (pqcRet != CRYPT_SUCCESS) ? pqcRet : tradRet;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    *signLen = pqcSigLen + tradSigLen;
ERR:
    BSL_SAL_FREE(msg.data);
    return ret;
}

int32_t CRYPT_COMPOSITE_Verify(CRYPT_CompositeCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                               uint8_t *sign, uint32_t signLen)
{
    (void)algId;
    if (ctx == NULL || data == NULL || sign == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pqcCtx == NULL || ctx->tradCtx == NULL || ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYINFO_NOT_SET);
        return CRYPT_COMPOSITE_KEYINFO_NOT_SET;
    }
    if (signLen < ctx->info->pqcSigLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_INVALID_SIG_LEN);
        return CRYPT_COMPOSITE_INVALID_SIG_LEN;
    }
    int32_t ret;
    uint32_t pqcSigLen = ctx->info->pqcSigLen;
    uint32_t tradSigLen = signLen - pqcSigLen;
    CRYPT_Data msg = {0};
    RETURN_RET_IF_ERR(CompositeMsgEncode(ctx, ctx->info->hashId, data, dataLen, &msg), ret);
    if (ctx->pqcMethod->ctrl == NULL || ctx->pqcMethod->verify == NULL || ctx->tradMethod->verify == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctx->info->label,
        (uint32_t)strlen(ctx->info->label)), ret);
    GOTO_ERR_IF(ctx->pqcMethod->verify(ctx->pqcCtx, CRYPT_MD_MAX, msg.data, msg.len, sign, pqcSigLen), ret);
    GOTO_ERR_IF(ctx->tradMethod->verify(ctx->tradCtx, ctx->info->tradHashId, msg.data, msg.len, sign + pqcSigLen,
        tradSigLen), ret);
    ret = CRYPT_SUCCESS;
ERR:
    BSL_ERR_PUSH_ERROR(ret);
    BSL_SAL_FREE(msg.data);
    return ret;
}

#ifdef HITLS_CRYPTO_COMPOSITE_CHECK
int32_t CRYPT_COMPOSITE_Check(uint32_t checkType, const CRYPT_CompositeCtx *pkey1, const CRYPT_CompositeCtx *pkey2)
{
    if (pkey1 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey1->info == NULL || pkey1->pqcMethod == NULL || pkey1->tradMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYINFO_NOT_SET);
        return CRYPT_COMPOSITE_KEYINFO_NOT_SET;
    }
    void *pqcCtx2 = NULL;
    void *tradCtx2 = NULL;
    if (pkey2 != NULL) {
        if (pkey2->info == NULL || pkey2->pqcMethod == NULL || pkey2->tradMethod == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYINFO_NOT_SET);
            return CRYPT_COMPOSITE_KEYINFO_NOT_SET;
        }
        if (pkey1->info->paramId != pkey2->info->paramId) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        pqcCtx2 = pkey2->pqcCtx;
        tradCtx2 = pkey2->tradCtx;
    }
    if (checkType == CRYPT_PKEY_CHECK_KEYPAIR && pkey2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pkey1->pqcMethod->check == NULL || pkey1->tradMethod->check == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    int32_t pqcRet = pkey1->pqcMethod->check(checkType, pkey1->pqcCtx, pqcCtx2);
    int32_t tradRet = pkey1->tradMethod->check(checkType, pkey1->tradCtx, tradCtx2);
    if (pqcRet != CRYPT_SUCCESS || tradRet != CRYPT_SUCCESS) {
        int32_t ret = (pqcRet != CRYPT_SUCCESS) ? pqcRet : tradRet;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_COMPOSITE_CHECK

#endif

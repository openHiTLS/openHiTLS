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
#ifdef HITLS_CRYPTO_CKKS

#include "crypt_utils.h"
#include "ckks_local.h"
#include "crypt_ckks.h"
#include "ckks_utils.h"
#include "ckks_encdec.h"
#include "crypt_errno.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"

typedef struct {
    BSL_Param *s; /**< CKKS private key parameter marked as s */
} CRYPT_CKKSPrvParam;

typedef struct {
    BSL_Param *a; /**< CKKS public key parameter marked as a */
    BSL_Param *b; /**< CKKS public key parameter marked as b */
} CRYPT_CKKSPubParam;

#define PARAMISNULL(a) (a == NULL || a->value == NULL)

static int32_t SetPrvPara(const CRYPT_CKKS_PrvKey *prvKey, const CRYPT_CKKSPrvParam *prv)
{
    int32_t ret = CKKS_Bin2DoubleCRT(prvKey->s, prv->s->value, prv->s->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

static int32_t GetAndCheckPrvKey(const CRYPT_CKKS_Ctx *ctx, BSL_Param *para, CRYPT_CKKSPrvParam *prv)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    prv->s = BSL_PARAM_FindParam(para, CRYPT_PARAM_CKKS_S);
    if (PARAMISNULL(prv->s) || prv->s->valueLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CKKS_SetPrvKey(CRYPT_CKKS_Ctx *ctx, const BSL_Param *para)
{
    CRYPT_CKKSPrvParam prv = {0};
    int32_t ret = GetAndCheckPrvKey(ctx, (BSL_Param *)(uintptr_t)para, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_CKKS_Ctx *newCtx = CRYPT_CKKS_NewCtx();
    if (newCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    newCtx->prvKey = CKKS_NewPrvKey();
    if (newCtx->prvKey == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = SetPrvPara(newCtx->prvKey, &prv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    CKKS_FREE_PRV_KEY(ctx->prvKey);
    ctx->prvKey = newCtx->prvKey;

    BSL_SAL_FREE(newCtx);
    return ret;
ERR:
    CRYPT_CKKS_FreeCtx(newCtx);
    return ret;
}

static int32_t SetPubPara(const CRYPT_CKKS_PubKey *pubKey, const CRYPT_CKKSPubParam *pub)
{
    int32_t ret = CKKS_Bin2DoubleCRT(pubKey->a, pub->a->value, pub->a->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CKKS_Bin2DoubleCRT(pubKey->b, pub->b->value, pub->b->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

static int32_t GetAndCheckPubKey(const CRYPT_CKKS_Ctx *ctx, BSL_Param *para, CRYPT_CKKSPubParam *pub)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    pub->a = BSL_PARAM_FindParam(para, CRYPT_PARAM_CKKS_A);
    pub->b = BSL_PARAM_FindParam(para, CRYPT_PARAM_CKKS_B);
    if (PARAMISNULL(pub->a) || PARAMISNULL(pub->b) || pub->a->valueLen == 0 || pub->b->valueLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CKKS_SetPubKey(CRYPT_CKKS_Ctx *ctx, const BSL_Param *para)
{
    CRYPT_CKKSPubParam pub = {0};
    int32_t ret = GetAndCheckPubKey(ctx, (BSL_Param *)(uintptr_t)para, &pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_CKKS_Ctx *newCtx = CRYPT_CKKS_NewCtx();
    if (newCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    newCtx->pubKey = CKKS_NewPubKey();
    if (newCtx->pubKey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = SetPubPara(newCtx->pubKey, &pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    CKKS_FREE_PUB_KEY(ctx->pubKey);
    ctx->pubKey = newCtx->pubKey;

    BSL_SAL_FREE(newCtx);
    return ret;
ERR:
    CRYPT_CKKS_FreeCtx(newCtx);
    return ret;
}

static int32_t GetPrvBasicCheck(const CRYPT_CKKS_Ctx *ctx, BSL_Param *para, CRYPT_CKKSPrvParam *prv)
{
    if (ctx == NULL || ctx->prvKey == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    prv->s = BSL_PARAM_FindParam(para, CRYPT_PARAM_CKKS_S);
    if (PARAMISNULL(prv->s)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CKKS_GetPrvKey(const CRYPT_CKKS_Ctx *ctx, BSL_Param *para)
{
    CRYPT_CKKSPrvParam prv = {0};
    int32_t ret = GetPrvBasicCheck(ctx, para, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    prv.s->useLen = prv.s->valueLen;
    ret = CKKS_DoubleCRT2Bin(ctx->prvKey->s, prv.s->value, &(prv.s->useLen));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_CleanseData(prv.s->value, prv.s->useLen);
        prv.s->useLen = 0;
        return ret;
    }
    return ret;
}

static int32_t GetPubBasicCheck(const CRYPT_CKKS_Ctx *ctx, BSL_Param *para, CRYPT_CKKSPubParam *pub)
{
    if (ctx == NULL || ctx->pubKey == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    pub->a = BSL_PARAM_FindParam(para, CRYPT_PARAM_CKKS_A);
    pub->b = BSL_PARAM_FindParam(para, CRYPT_PARAM_CKKS_B);
    if (PARAMISNULL(pub->a) || PARAMISNULL(pub->b)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CKKS_GetPubKey(const CRYPT_CKKS_Ctx *ctx, BSL_Param *para)
{
    CRYPT_CKKSPubParam pub = {0};
    int32_t ret = GetPubBasicCheck(ctx, para, &pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    pub.a->useLen = pub.a->valueLen;
    ret = CKKS_DoubleCRT2Bin(ctx->pubKey->a, pub.a->value, &(pub.a->useLen));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_CleanseData(pub.a->value, pub.a->useLen);
        pub.a->useLen = 0;
        return ret;
    }
    pub.b->useLen = pub.b->valueLen;
    ret = CKKS_DoubleCRT2Bin(ctx->pubKey->b, pub.b->value, &(pub.b->useLen));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_CleanseData(pub.b->value, pub.b->useLen);
        pub.b->useLen = 0;
        return ret;
    }
    return ret;
}

static int32_t GetCKKSParam(const BSL_Param *params, uint32_t *m, uint32_t *bits, int32_t *precision)
{
    uint32_t mLen = sizeof(m);
    uint32_t bitsLen = sizeof(bits);
    uint32_t precLen = sizeof(precision);

    const BSL_Param *temp = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_CKKS_M);
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    int32_t ret = BSL_PARAM_GetValue(temp, CRYPT_PARAM_CKKS_M, BSL_PARAM_TYPE_UINT32, m, &mLen);
    if (ret != BSL_SUCCESS || *m < 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    temp = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_CKKS_BITS);
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    ret = BSL_PARAM_GetValue(temp, CRYPT_PARAM_CKKS_BITS, BSL_PARAM_TYPE_UINT32, bits, &bitsLen);
    if (ret != BSL_SUCCESS || *bits == 0 || *bits > CKKS_MAX_MODULUS_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    temp = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_CKKS_PREC);
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    ret = BSL_PARAM_GetValue(temp, CRYPT_PARAM_CKKS_PREC, BSL_PARAM_TYPE_INT32, precision, &precLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    return CRYPT_SUCCESS;
}

CRYPT_CKKS_Ctx *CRYPT_CKKS_NewCtx(void)
{
    CRYPT_CKKS_Ctx *ctx = (CRYPT_CKKS_Ctx *)BSL_SAL_Malloc(sizeof(CRYPT_CKKS_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ctx, sizeof(CRYPT_CKKS_Ctx), 0, sizeof(CRYPT_CKKS_Ctx));
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

static CRYPT_CKKS_PubKey *CKKSPubKeyDupCtx(CRYPT_CKKS_PubKey *pubKey)
{
    CRYPT_CKKS_PubKey *newPubKey = (CRYPT_CKKS_PubKey *)BSL_SAL_Malloc(sizeof(CRYPT_CKKS_PubKey));
    if (newPubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(newPubKey, sizeof(CRYPT_CKKS_PubKey), 0, sizeof(CRYPT_CKKS_PubKey));
    GOTO_ERR_IF_SRC_NOT_NULL(newPubKey->a, pubKey->a, CKKS_DoubleCRT_Dup(pubKey->a), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newPubKey->b, pubKey->b, CKKS_DoubleCRT_Dup(pubKey->b), CRYPT_MEM_ALLOC_FAIL);
    newPubKey->pubkey_noiseB = pubKey->pubkey_noiseB;
    newPubKey->prvkey_noiseB = pubKey->prvkey_noiseB;
    return newPubKey;
ERR:
    CKKS_FREE_PUB_KEY(newPubKey);
    return NULL;
}

static CRYPT_CKKS_PrvKey *CKKSPrvKeyDupCtx(CRYPT_CKKS_PrvKey *prvKey)
{
    CRYPT_CKKS_PrvKey *newPrvKey = (CRYPT_CKKS_PrvKey *)BSL_SAL_Malloc(sizeof(CRYPT_CKKS_PrvKey));
    if (newPrvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(newPrvKey, sizeof(CRYPT_CKKS_PrvKey), 0, sizeof(CRYPT_CKKS_PrvKey));
    GOTO_ERR_IF_SRC_NOT_NULL(newPrvKey->s, prvKey->s, CKKS_DoubleCRT_Dup(prvKey->s), CRYPT_MEM_ALLOC_FAIL);
    newPrvKey->prvkey_noiseB = prvKey->prvkey_noiseB;
    return newPrvKey;
ERR:
    CKKS_FREE_PRV_KEY(newPrvKey);
    return NULL;
}

static CRYPT_CKKS_Para *CKKSParaDupCtx(CRYPT_CKKS_Para *para)
{
    CRYPT_CKKS_Para *newPara = (CRYPT_CKKS_Para *)BSL_SAL_Malloc(sizeof(CRYPT_CKKS_Para));
    if (newPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(newPara, sizeof(CRYPT_CKKS_Para), 0, sizeof(CRYPT_CKKS_Para));

    newPara->precision = para->precision;
    newPara->mag = para->mag;
    newPara->err = para->err;
    newPara->m = para->m;
    newPara->phiM = para->phiM;
    newPara->bits = para->bits;
    newPara->qsz = para->qsz;
    newPara->scale = para->scale;
    newPara->slots_size = para->slots_size;
    newPara->stdev = para->stdev;
    newPara->noise_bound = para->noise_bound;
    newPara->ratfactor = para->ratfactor;
    GOTO_ERR_IF_SRC_NOT_NULL(newPara->moduli, para->moduli, CKKS_Moduli_Dup(para->moduli), CRYPT_MEM_ALLOC_FAIL);
    return newPara;

ERR:
    CKKS_FREE_PARA(newPara);
    return NULL;
}

CRYPT_CKKS_Ctx *CRYPT_CKKS_DupCtx(CRYPT_CKKS_Ctx *keyCtx)
{
    if (keyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_CKKS_Ctx *newKeyCtx = (CRYPT_CKKS_Ctx *)BSL_SAL_Malloc(sizeof(CRYPT_CKKS_Ctx));
    if (newKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(newKeyCtx, sizeof(CRYPT_CKKS_Ctx), 0, sizeof(CRYPT_CKKS_Ctx));

    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->prvKey, keyCtx->prvKey, CKKSPrvKeyDupCtx(keyCtx->prvKey), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->pubKey, keyCtx->pubKey, CKKSPubKeyDupCtx(keyCtx->pubKey), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->para, keyCtx->para, CKKSParaDupCtx(keyCtx->para), CRYPT_MEM_ALLOC_FAIL);
    BSL_SAL_ReferencesInit(&(newKeyCtx->references));
    return newKeyCtx;

ERR:
    CRYPT_CKKS_FreeCtx(newKeyCtx);
    return NULL;
}

CRYPT_CKKS_Para *CRYPT_CKKS_NewPara(const BSL_Param *params)
{
    if (params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }

    int32_t precision = 0;
    uint32_t m = 0;
    uint32_t bits = 0;
    int32_t ret = GetCKKSParam(params, &m, &bits, &precision);
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }

    CRYPT_CKKS_Para *retPara = BSL_SAL_Malloc(sizeof(CRYPT_CKKS_Para));
    if (retPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    BN_Optimizer *optimizer = BN_OptimizerCreate();
    if (optimizer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    if (precision < 0) { // When precision is negative, the default precision(20) is used
        precision = DEFAULT_PREC;
    }
    retPara->precision = precision;
    retPara->err = Default_Err(0.5, m / 2);
    retPara->scale = Default_Scale(retPara->err, precision);
    retPara->mag = 0.0;
    retPara->m = m;
    retPara->phiM = m / 2;
    retPara->bits = bits;
    retPara->qsz = 0;
    retPara->slots_size = m / 4;
    retPara->stdev = DEFAULT_STDEV;
    retPara->noise_bound = 0.0;
    retPara->ratfactor = retPara->scale;
    retPara->moduli = (CKKS_Moduli *)BSL_SAL_Malloc(sizeof(CKKS_Moduli));
    if (Build_Ctx_Primes(retPara->moduli, retPara, optimizer) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
        return NULL;
    }

    BN_OptimizerDestroy(optimizer);
    return retPara;
}

void CRYPT_CKKS_FreeCtx(CRYPT_CKKS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    int i = 0;
    BSL_SAL_AtomicDownReferences(&(ctx->references), &i);
    if (i > 0) {
        return;
    }
    BSL_SAL_ReferencesFree(&(ctx->references));
    CKKS_FREE_PRV_KEY(ctx->prvKey);
    CKKS_FREE_PUB_KEY(ctx->pubKey);
    CKKS_FREE_PARA(ctx->para);
    BSL_SAL_Free(ctx);
}

void CRYPT_CKKS_FreePara(CRYPT_CKKS_Para *para)
{
    if (para == NULL) {
        return;
    }
    CKKS_Moduli_Destroy(para->moduli);
    BSL_SAL_Free(para);
}

void CKKS_FreePrvKey(CRYPT_CKKS_PrvKey *prvKey)
{
    if (prvKey == NULL) {
        return;
    }
    CKKS_DoubleCRT_Destroy(prvKey->s);
    BSL_SAL_Free(prvKey);
}

void CKKS_FreePubKey(CRYPT_CKKS_PubKey *pubKey)
{
    if (pubKey == NULL) {
        return;
    }
    CKKS_DoubleCRT_Destroy(pubKey->a);
    CKKS_DoubleCRT_Destroy(pubKey->b);
    BSL_SAL_Free(pubKey);
}

static int32_t IsCKKSSetParaVaild(const CRYPT_CKKS_Ctx *ctx, const CRYPT_CKKS_Para *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->bits > CKKS_MAX_MODULUS_BITS || para->bits <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_KEY_BITS);
        return CRYPT_CKKS_ERR_KEY_BITS;
    }
    return CRYPT_SUCCESS;
}

CRYPT_CKKS_Para *CRYPT_CKKS_DupPara(const CRYPT_CKKS_Para *para)
{
    CRYPT_CKKS_Para *paraCopy = BSL_SAL_Malloc(sizeof(CRYPT_CKKS_Para));
    if (paraCopy == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    paraCopy->precision = para->precision;
    paraCopy->mag = para->mag;
    paraCopy->err = para->err;
    paraCopy->m = para->m;
    paraCopy->bits = para->bits;
    paraCopy->qsz = para->qsz;
    paraCopy->scale = para->scale;
    paraCopy->slots_size = para->slots_size;
    paraCopy->stdev = para->stdev;
    paraCopy->noise_bound = para->noise_bound;
    paraCopy->ratfactor = para->ratfactor;
    paraCopy->moduli = CKKS_Moduli_Dup(para->moduli);

    if (paraCopy->moduli == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        CKKS_FREE_PARA(paraCopy);
        return NULL;
    }
    return paraCopy;
}

int32_t CRYPT_CKKS_SetPara(CRYPT_CKKS_Ctx *ctx, const BSL_Param *param)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    CRYPT_CKKS_Para *CKKSPara = CRYPT_CKKS_NewPara(param);
    if (CKKSPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_NEW_PARA_FAIL);
        return CRYPT_EAL_ERR_NEW_PARA_FAIL;
    }
    int32_t ret = IsCKKSSetParaVaild(ctx, CKKSPara);
    if (ret != CRYPT_SUCCESS) {
        CKKS_FREE_PARA(CKKSPara);
        return ret;
    }

    CKKS_FREE_PARA(ctx->para);
    CKKS_FREE_PRV_KEY(ctx->prvKey);
    CKKS_FREE_PUB_KEY(ctx->pubKey);

    ctx->para = CKKSPara;
    return CRYPT_SUCCESS;
}

CRYPT_CKKS_PrvKey *CKKS_NewPrvKey(void)
{
    CRYPT_CKKS_PrvKey *prvKey = BSL_SAL_Malloc(sizeof(CRYPT_CKKS_PrvKey));
    if (prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    prvKey->prvkey_noiseB = 0.0;
    return prvKey;
}

CRYPT_CKKS_PubKey *CKKS_NewPubKey(void)
{
    CRYPT_CKKS_PubKey *pubKey = BSL_SAL_Malloc(sizeof(CRYPT_CKKS_PubKey));
    if (pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    pubKey->a = (CKKS_DoubleCRT *)BSL_SAL_Malloc(sizeof(CKKS_DoubleCRT));
    pubKey->b = (CKKS_DoubleCRT *)BSL_SAL_Malloc(sizeof(CKKS_DoubleCRT));
    if (pubKey->a == NULL || pubKey->b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    pubKey->pubkey_noiseB = 0.0;
    pubKey->prvkey_noiseB = 0.0;
    return pubKey;
}

int32_t CKKS_CalcPrvKey(CRYPT_CKKS_Ctx *ctx)
{
    int32_t ret = Sample_Gaussian_Bound(&ctx->prvKey->prvkey_noiseB, ctx->prvKey->s->poly, ctx->para->stdev);
    if (ret != CRYPT_SUCCESS || ctx->prvKey->prvkey_noiseB <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
        return CRYPT_CKKS_ERR_CAL_VALUE;
    }
    return CRYPT_SUCCESS;
}

int32_t CKKS_CalcPubKey(CRYPT_CKKS_Ctx *ctx, BN_Optimizer *optimizer)
{
    ctx->pubKey->pubkey_noiseB = RLWE(ctx, ctx->pubKey->b, ctx->pubKey->a, ctx->prvKey->s, optimizer);
    ctx->pubKey->prvkey_noiseB = ctx->prvKey->prvkey_noiseB;
    if (ctx->pubKey->pubkey_noiseB <= 0 || ctx->pubKey->prvkey_noiseB <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
        return CRYPT_CKKS_ERR_CAL_VALUE;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CKKS_Gen(CRYPT_CKKS_Ctx *ctx)
{
    if (ctx == NULL || ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    BN_Optimizer *optimizer = BN_OptimizerCreate();
    CRYPT_CKKS_Ctx *newCtx = CRYPT_CKKS_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    newCtx->para = CRYPT_CKKS_DupPara(ctx->para);
    newCtx->prvKey = CKKS_NewPrvKey();
    newCtx->pubKey = CKKS_NewPubKey();
    if (optimizer == NULL || newCtx->para == NULL || newCtx->prvKey == NULL || newCtx->pubKey == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = CKKS_CalcPrvKey(newCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = CKKS_CalcPubKey(newCtx, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    CKKS_FREE_PARA(ctx->para);
    CKKS_FREE_PRV_KEY(ctx->prvKey);
    CKKS_FREE_PUB_KEY(ctx->pubKey);
    BSL_SAL_ReferencesFree(&(newCtx->references));

    ctx->prvKey = newCtx->prvKey;
    ctx->pubKey = newCtx->pubKey;
    ctx->para = newCtx->para;
    BSL_SAL_FREE(newCtx);
    BN_OptimizerDestroy(optimizer);

    return ret;

ERR:
    CRYPT_CKKS_FreeCtx(newCtx);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

#endif //HITLS_CRYPTO_CKKS
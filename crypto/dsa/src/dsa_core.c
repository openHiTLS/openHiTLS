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
#ifdef HITLS_CRYPTO_DSA

#include "crypt_errno.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_encode_internal.h"
#include "dsa_local.h"
#include "crypt_dsa.h"
#include "eal_md_local.h"
#include "crypt_params_key.h"

CRYPT_DSA_Ctx *CRYPT_DSA_NewCtx(void)
{
    CRYPT_DSA_Ctx *ctx = BSL_SAL_Malloc(sizeof(CRYPT_DSA_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ctx, sizeof(CRYPT_DSA_Ctx), 0, sizeof(CRYPT_DSA_Ctx));
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

CRYPT_DSA_Ctx *CRYPT_DSA_NewCtxEx(void *libCtx)
{
    CRYPT_DSA_Ctx *ctx = CRYPT_DSA_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

static bool InputBufferCheck(const uint8_t *buffer, uint32_t bufferLen)
{
    if (buffer == NULL || bufferLen == 0) {
        return true;
    }
    return false;
}

static CRYPT_DSA_Para *ParaMemGet(uint32_t bits)
{
    CRYPT_DSA_Para *para = BSL_SAL_Malloc(sizeof(CRYPT_DSA_Para));
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    para->p = BN_Create(bits);
    para->q = BN_Create(bits);
    para->g = BN_Create(bits);
    if (para->p == NULL || para->q == NULL || para->g == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        CRYPT_DSA_FreePara(para);
        return NULL;
    }
    return para;
}

static int32_t GetDsaParamValue(const BSL_Param *params, int32_t paramId, uint32_t maxLen,
    const uint8_t **value, uint32_t *valueLen)
{
    const BSL_Param *param = BSL_PARAM_FindConstParam(params, paramId);
    if (param == NULL || param->value == NULL || param->valueLen > maxLen || param->valueLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_PARA);
        return CRYPT_DSA_ERR_KEY_PARA;
    }
    *value = param->value;
    *valueLen = param->valueLen;
    return CRYPT_SUCCESS;
}

static int32_t GetAllDsaParams(const BSL_Param *params,
    const uint8_t **p, uint32_t *pLen,
    const uint8_t **q, uint32_t *qLen,
    const uint8_t **g, uint32_t *gLen)
{
    int32_t ret = GetDsaParamValue(params, CRYPT_PARAM_DSA_P, BN_BITS_TO_BYTES(DSA_MAX_PBITS), p, pLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = GetDsaParamValue(params, CRYPT_PARAM_DSA_Q, *pLen, q, qLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return GetDsaParamValue(params, CRYPT_PARAM_DSA_G, *pLen, g, gLen);
}

static int32_t InitDsaParaValues(CRYPT_DSA_Para *para,
    const uint8_t *p, uint32_t pLen,
    const uint8_t *q, uint32_t qLen,
    const uint8_t *g, uint32_t gLen)
{
    int32_t ret = BN_Bin2Bn(para->p, p, pLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Bin2Bn(para->q, q, qLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Bin2Bn(para->g, g, gLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

CRYPT_DSA_Para *CRYPT_DSA_NewPara(const BSL_Param *params)
{
    if (params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    const uint8_t *p = NULL, *q = NULL, *g = NULL;
    uint32_t pLen = 0, qLen = 0, gLen = 0;
    int32_t ret = GetAllDsaParams(params, &p, &pLen, &q, &qLen, &g, &gLen);
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }
    CRYPT_DSA_Para *para = ParaMemGet(pLen * 8);
    if (para == NULL) {
        return NULL;
    }
    ret = InitDsaParaValues(para, p, pLen, q, qLen, g, gLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_DSA_FreePara(para);
        return NULL;
    }
    return para;
}

void CRYPT_DSA_FreePara(CRYPT_DSA_Para *para)
{
    if (para == NULL) {
        return;
    }
    BN_Destroy(para->p);
    BN_Destroy(para->q);
    BN_Destroy(para->g);
    BSL_SAL_FREE(para);
}

void CRYPT_DSA_FreeCtx(CRYPT_DSA_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    int ref = 0;
    BSL_SAL_AtomicDownReferences(&(ctx->references), &ref);
    if (ref > 0) {
        return;
    }
    BSL_SAL_ReferencesFree(&(ctx->references));
    CRYPT_DSA_FreePara(ctx->para);
    BN_Destroy(ctx->x);
    BN_Destroy(ctx->y);
    BSL_SAL_FREE(ctx);
}

static int32_t ParaPQGCheck(const BN_BigNum *p, const BN_BigNum *q, const BN_BigNum *g)
{
    uint32_t pBits = BN_Bits(p);
    BN_BigNum *r = BN_Create(pBits + 1);
    BN_Optimizer *opt = BN_OptimizerCreate();
    int32_t ret;
    if (r == NULL || opt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    // judgment of numeric values
    // r = p - 1
    ret = BN_SubLimb(r, p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    // q < p - 1
    if (BN_Cmp(q, r) >= 0) {
        ret = CRYPT_DSA_ERR_KEY_PARA;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    // g < p - 1
    if (BN_Cmp(g, r) >= 0) {
        ret = CRYPT_DSA_ERR_KEY_PARA;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    // judgment of multiple relationship about p & q
    ret = BN_Div(NULL, r, r, q, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    // (p - 1) % q == 0
    if (!BN_IsZero(r)) {
        ret = CRYPT_DSA_ERR_KEY_PARA;
        BSL_ERR_PUSH_ERROR(ret);
    }
EXIT:
    BN_Destroy(r);
    BN_OptimizerDestroy(opt);
    return ret;
}

static int32_t ParaDataCheck(const CRYPT_DSA_Para *para)
{
    const BN_BigNum *p = para->p;
    const BN_BigNum *q = para->q;
    const BN_BigNum *g = para->g;
    // 1. judge validity of length
    uint32_t pBits = BN_Bits(p);
    if (pBits < DSA_MIN_PBITS || pBits > DSA_MAX_PBITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_PARA);
        return CRYPT_DSA_ERR_KEY_PARA;
    }
    if (BN_Bits(q) < DSA_MIN_QBITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_PARA);
        return CRYPT_DSA_ERR_KEY_PARA;
    }
    // 2. parity judgment of p & q and value judgment of g
    // p is an odd number && q is an odd number
    if (BN_GetBit(p, 0) == 0 || BN_GetBit(q, 0) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_PARA);
        return CRYPT_DSA_ERR_KEY_PARA;
    }
    // g != 1 && g != 0
    if (BN_IsOne(g) || BN_IsZero(g)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_PARA);
        return CRYPT_DSA_ERR_KEY_PARA;
    }
    // This interface is invoked only here, and pushErr is performed internally.
    // If this interface fails, pushErr does not need to be invoked.
    return ParaPQGCheck(p, q, g);
}

static CRYPT_DSA_Para *ParaDup(const CRYPT_DSA_Para *para)
{
    CRYPT_DSA_Para *ret = BSL_SAL_Malloc(sizeof(CRYPT_DSA_Para));
    if (ret == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ret->p = BN_Dup(para->p);
    ret->q = BN_Dup(para->q);
    ret->g = BN_Dup(para->g);
    if (ret->p == NULL || ret->q == NULL || ret->g == NULL) {
        CRYPT_DSA_FreePara(ret);
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_PARA);
        return NULL;
    }
    return ret;
}

int32_t CRYPT_DSA_SetPara(CRYPT_DSA_Ctx *ctx, const BSL_Param *para)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_DSA_Para *dsaPara = CRYPT_DSA_NewPara(para);
    if (dsaPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_NEW_PARA_FAIL);
        return CRYPT_EAL_ERR_NEW_PARA_FAIL;
    }
    int32_t ret = ParaDataCheck(dsaPara);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_DSA_FreePara(dsaPara);
        return ret;
    }

    BN_Destroy(ctx->x);
    BN_Destroy(ctx->y);
    CRYPT_DSA_FreePara(ctx->para);
    ctx->x = NULL;
    ctx->y = NULL;
    ctx->para = dsaPara;
    return CRYPT_SUCCESS;
}

static int32_t GetDsaParam(const BN_BigNum *x, BSL_Param *param, int32_t key)
{
    BSL_Param *temp = BSL_PARAM_FindParam(param, key);
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_PARA_ERROR);
        return CRYPT_DSA_PARA_ERROR;
    }

    temp->useLen = temp->valueLen;
    int32_t ret = BN_Bn2Bin(x, temp->value, &temp->useLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_DSA_GetPara(const CRYPT_DSA_Ctx *ctx, BSL_Param *param)
{
    int32_t ret;
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_PARA_ERROR);
        return CRYPT_DSA_PARA_ERROR;
    }

    ret = GetDsaParam(ctx->para->p, param, CRYPT_PARAM_DSA_P);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = GetDsaParam(ctx->para->q, param, CRYPT_PARAM_DSA_Q);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = GetDsaParam(ctx->para->g, param, CRYPT_PARAM_DSA_G);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

CRYPT_DSA_Ctx *CRYPT_DSA_DupCtx(CRYPT_DSA_Ctx *dsaCtx)
{
    if (dsaCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    CRYPT_DSA_Ctx *dsaNewCtx = BSL_SAL_Malloc(sizeof(CRYPT_DSA_Ctx));
    if (dsaNewCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memset_s(dsaNewCtx, sizeof(CRYPT_DSA_Ctx), 0, sizeof(CRYPT_DSA_Ctx));

    GOTO_ERR_IF_SRC_NOT_NULL(dsaNewCtx->x, dsaCtx->x, BN_Dup(dsaCtx->x), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(dsaNewCtx->y, dsaCtx->y, BN_Dup(dsaCtx->y), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(dsaNewCtx->para, dsaCtx->para, ParaDup(dsaCtx->para), CRYPT_MEM_ALLOC_FAIL);
    BSL_SAL_ReferencesInit(&(dsaNewCtx->references));
    return dsaNewCtx;

ERR:
    CRYPT_DSA_FreeCtx(dsaNewCtx);
    return NULL;
}

uint32_t CRYPT_DSA_GetBits(const CRYPT_DSA_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_PARA);
        return 0;
    }
    return BN_Bits(ctx->para->p);
}

uint32_t CRYPT_DSA_GetSignLen(const CRYPT_DSA_Ctx *ctx)
{
    if (ctx == NULL || ctx->para == NULL) {
        return 0;
    }
    uint32_t qLen = BN_Bytes(ctx->para->q);
    uint32_t maxSignLen = 0;
    int32_t ret = CRYPT_EAL_GetSignEncodeLen(qLen, qLen, &maxSignLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return 0;
    }
    return maxSignLen;
}

/* x != 0 && x < q */
int32_t CRYPT_DSA_SetPrvKey(CRYPT_DSA_Ctx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *prv = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_DSA_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (InputBufferCheck(prv->value, prv->valueLen)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_PARA);
        return CRYPT_DSA_ERR_KEY_PARA;
    }
    if (BN_Bytes(ctx->para->q) < prv->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_INFO);
        return CRYPT_DSA_ERR_KEY_INFO;
    }
    BN_BigNum *bnX = BN_Create(prv->valueLen * 8);
    if (bnX == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BN_Bin2Bn(bnX, prv->value, prv->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // x < q
    if (BN_Cmp(bnX, ctx->para->q) >= 0) {
        ret = CRYPT_DSA_ERR_KEY_INFO;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // x != 0
    if (BN_IsZero(bnX)) {
        ret = CRYPT_DSA_ERR_KEY_INFO;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    BN_Destroy(ctx->x);
    ctx->x = bnX;
    return ret;
ERR:
    BN_Destroy(bnX);
    return ret;
}

/* y != 0 && y != 1 && y < p */
int32_t CRYPT_DSA_SetPubKey(CRYPT_DSA_Ctx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *pub = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_DSA_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (InputBufferCheck(pub->value, pub->valueLen)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_PARA);
        return CRYPT_DSA_ERR_KEY_PARA;
    }
    if (BN_Bytes(ctx->para->p) < pub->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_INFO);
        return CRYPT_DSA_ERR_KEY_INFO;
    }
    BN_BigNum *bnY = BN_Create(pub->valueLen * 8);
    if (bnY == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BN_Bin2Bn(bnY, pub->value, pub->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // y < p
    if (BN_Cmp(bnY, ctx->para->p) >= 0)  {
        ret = CRYPT_DSA_ERR_KEY_INFO;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // y != 0 && y != 1
    if (BN_IsZero(bnY) || BN_IsOne(bnY)) {
        ret = CRYPT_DSA_ERR_KEY_INFO;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    BN_Destroy(ctx->y);
    ctx->y = bnY;
    return CRYPT_SUCCESS;
ERR:
    BN_Destroy(bnY);
    return ret;
}

int32_t CRYPT_DSA_GetPrvKey(const CRYPT_DSA_Ctx *ctx, BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_Param *prv = BSL_PARAM_FindParam(para, CRYPT_PARAM_DSA_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_PARA);
        return CRYPT_DSA_ERR_KEY_PARA;
    }
    if (ctx->x == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_INFO);
        return CRYPT_DSA_ERR_KEY_INFO;
    }
    if (BN_Bytes(ctx->para->q) > prv->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_DSA_BUFF_LEN_NOT_ENOUGH;
    }
    uint32_t useLen = prv->valueLen;
    int32_t ret = BN_Bn2Bin(ctx->x, prv->value, &useLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    prv->useLen = useLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_DSA_GetPubKey(const CRYPT_DSA_Ctx *ctx, BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_Param *pub = BSL_PARAM_FindParam(para, CRYPT_PARAM_DSA_PUBKEY);
    if (pub == NULL || pub->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->y == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_INFO);
        return CRYPT_DSA_ERR_KEY_INFO;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_PARA);
        return CRYPT_DSA_ERR_KEY_PARA;
    }
    if (BN_Bytes(ctx->para->p) > pub->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_DSA_BUFF_LEN_NOT_ENOUGH;
    }
    uint32_t useLen = pub->valueLen;
    int32_t ret = BN_Bn2Bin(ctx->y, pub->value, &useLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pub->useLen = useLen;
    return CRYPT_SUCCESS;
}

static int32_t RandRangeQ(void *libCtx, BN_BigNum *r, const BN_BigNum *q)
{
    int32_t cnt = 0;
    for (cnt = 0; cnt < CRYPT_DSA_TRY_MAX_CNT; cnt++) {
        int32_t ret = BN_RandRangeEx(libCtx, r, q);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (BN_IsZero(r)) {
            continue;
        }
        return CRYPT_SUCCESS; // if succeed then exit
    }
    /* If the key fails to be generated after try CRYPT_DSA_TRI_MAX_CNT times, then failed and exit. */
    BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_TRY_CNT);
    return CRYPT_DSA_ERR_TRY_CNT;
}

static void RefreshCtx(CRYPT_DSA_Ctx *ctx, BN_BigNum *x, BN_BigNum *y, int32_t ret)
{
    if (ret == CRYPT_SUCCESS) {
        BN_Destroy(ctx->x);
        BN_Destroy(ctx->y);
        ctx->x = x;
        ctx->y = y;
    } else {
        BN_Destroy(x);
        BN_Destroy(y);
    }
}

int32_t CRYPT_DSA_Gen(CRYPT_DSA_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_PARA);
        return CRYPT_DSA_ERR_KEY_PARA;
    }
    int32_t ret = CRYPT_SUCCESS;
    int32_t cnt;
    BN_BigNum *x = BN_Create(BN_Bits(ctx->para->q));
    BN_BigNum *y = BN_Create(BN_Bits(ctx->para->p));
    BN_Mont *mont = BN_MontCreate(ctx->para->p);
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (x == NULL || y == NULL || opt == NULL || mont == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    for (cnt = 0; cnt < CRYPT_DSA_TRY_MAX_CNT; cnt++) {
        /* Generate the private key x of [1, q-1], see RFC6979-2.2. */
        ret = RandRangeQ(ctx->libCtx, x, ctx->para->q);
        if (ret != CRYPT_SUCCESS) {
            // Internal API, the BSL_ERR_PUSH_ERROR info is already exists when failed.
            goto ERR;
        }
        /* Calculate the public key y. */
        ret = BN_MontExpConsttime(y, ctx->para->g, x, mont, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        /* y != 0 && y != 1 */
        if (BN_IsZero(y) || BN_IsOne(y)) {
            continue;
        }
        goto ERR; // If succeed then exit.
    }
    /* If the key fails to be generated after try CRYPT_DSA_TRY_MAX_CNT times, then failed and exit. */
    ret = CRYPT_DSA_ERR_TRY_CNT;
    BSL_ERR_PUSH_ERROR(ret);
ERR:
    RefreshCtx(ctx, x, y, ret);
    BN_MontDestroy(mont);
    BN_OptimizerDestroy(opt);
    return ret;
}

// Get the input hash data, see RFC6979-2.4.1 and RFC6979-2.3.2
static BN_BigNum *DSA_Bits2Int(BN_BigNum *q, const uint8_t *data, uint32_t dataLen)
{
    BN_BigNum *d = BN_Create(BN_Bits(q)); // 1 byte = 8 bits
    if (d == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    if (data != NULL) {
        uint32_t qLen = BN_Bytes(q);
        uint32_t dLen = (dataLen < qLen) ? dataLen : qLen;
        // The input parameters of the function have been verified, and no failure exists.
        (void)BN_Bin2Bn(d, data, dLen);
    }
    return d;
}

// s = (h+x*sign->r)/k mod q
static int32_t CalcSValue(const CRYPT_DSA_Ctx *ctx, BN_BigNum *r, BN_BigNum *s, BN_BigNum *k,
    BN_BigNum *d, BN_Optimizer *opt)
{
    int32_t ret = BN_ModMul(s, ctx->x, r, ctx->para->q, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_ModAdd(s, d, s, ctx->para->q, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_ModInv(k, k, ctx->para->q, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return BN_ModMul(s, s, k, ctx->para->q, opt);
}

static int32_t SignCore(const CRYPT_DSA_Ctx *ctx, BN_BigNum *d, BN_BigNum *r,
    BN_BigNum *s)
{
    int32_t cnt = 0;
    int32_t ret = CRYPT_SUCCESS;
    BN_BigNum *k = BN_Create(BN_Bits(ctx->para->q));
    BN_Mont *montP = BN_MontCreate(ctx->para->p);
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (k == NULL || montP == NULL || opt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    for (cnt = 0; cnt < CRYPT_DSA_TRY_MAX_CNT; cnt++) {
        // Generate random number k of [1, q-1], see RFC6979-2.4.2 */
        ret = RandRangeQ(ctx->libCtx, k, ctx->para->q);
        if (ret != CRYPT_SUCCESS) {
            // Internal function. The BSL_ERR_PUSH_ERROR information exists when the failure occurs.
            goto EXIT;
        }
        // Compute r = g^k mod p mod q, see RFC6979-2.4.3 */
        ret = BN_MontExpConsttime(r, ctx->para->g, k, montP, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        ret = BN_Mod(r, r, ctx->para->q, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        if (BN_IsZero(r)) {
            continue;
        }
        // Compute s = (h+x*sign->r)/k mod q, see RFC6979-2.4.4 */
        ret = CalcSValue(ctx, r, s, k, d, opt);
        if (ret != CRYPT_SUCCESS) {
            goto EXIT;
        }
        if (BN_IsZero(s)) {
            continue;
        }
        goto EXIT; // The signature generation meets the requirements and exits successfully.
    }
    ret = CRYPT_DSA_ERR_TRY_CNT;
    BSL_ERR_PUSH_ERROR(ret);
EXIT:
    BN_Destroy(k);
    BN_MontDestroy(montP);
    BN_OptimizerDestroy(opt);
    return ret;
}

static int32_t CryptDsaSign(const CRYPT_DSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen, BN_BigNum **r,
    BN_BigNum **s)
{
    int32_t ret;
    BN_BigNum *signR = NULL;
    BN_BigNum *signS = NULL;
    BN_BigNum *d = DSA_Bits2Int(ctx->para->q, data, dataLen);
    if (d == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    signR = BN_Create(BN_Bits(ctx->para->p));
    signS = BN_Create(BN_Bits(ctx->para->q));
    if ((signR == NULL) || (signS == NULL)) {
        BN_Destroy(d);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    ret = SignCore(ctx, d, signR, signS);
    BN_Destroy(d);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    *r = signR;
    *s = signS;
    return ret;
ERR:
    BN_Destroy(signR);
    BN_Destroy(signS);
    return ret;
}

// Data with a value of 0 can also be signed.
int32_t CRYPT_DSA_SignData(const CRYPT_DSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    if (ctx == NULL || sign == NULL || signLen == NULL || (data == NULL && dataLen != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_PARA);
        return CRYPT_DSA_ERR_KEY_PARA;
    }
    if (ctx->x == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_INFO);
        return CRYPT_DSA_ERR_KEY_INFO;
    }
    if (*signLen < CRYPT_DSA_GetSignLen(ctx)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_DSA_BUFF_LEN_NOT_ENOUGH;
    }
    int32_t ret;
    BN_BigNum *r = NULL;
    BN_BigNum *s = NULL;
    ret = CryptDsaSign(ctx, data, dataLen, &r, &s);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_EncodeSign(r, s, sign, signLen);
    BN_Destroy(r);
    BN_Destroy(s);
    return ret;
}

int32_t CRYPT_DSA_Sign(const CRYPT_DSA_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    uint8_t hash[64]; // 64 is max hash len
    uint32_t hashLen = sizeof(hash) / sizeof(hash[0]);
    int32_t ret = EAL_Md(algId, data, dataLen, hash, &hashLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_DSA_SignData(ctx, hash, hashLen, sign, signLen);
}

static int32_t VerifyCore(const CRYPT_DSA_Ctx *ctx, BN_BigNum *d, BN_BigNum *r, BN_BigNum *s)
{
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    BN_BigNum *u1 = BN_Create(BN_Bits(ctx->para->p));
    BN_BigNum *u2 = BN_Create(BN_Bits(ctx->para->p));
    BN_BigNum *w = BN_Create(BN_Bits(ctx->para->q));
    BN_Mont *montP = BN_MontCreate(ctx->para->p);
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (u1 == NULL || u2 == NULL || w == NULL || montP == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    /* Calculate w = 1/s mod q
     * u1 = (d * w) mod q
     * u2 = (r * w) mod q
     * u1 = (g ^ u1) mod p
     * u2 = (y ^ u2) mod p
     * v = (u1 * u2) mod p
     * v = v mod q
     * If v == r, sign verification is succeeded.
     */
    ret = BN_ModInv(w, s, ctx->para->q, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_ModMul(u1, d, w, ctx->para->q, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_ModMul(u2, r, w, ctx->para->q, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_MontExpMul(u1, ctx->para->g, u1, ctx->y, u2, montP, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_Mod(u1, u1, ctx->para->q, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_Cmp(u1, r);
    if (ret != 0) {
        BSL_ERR_PUSH_ERROR(ret);
        ret = CRYPT_DSA_VERIFY_FAIL;
    }
EXIT:
    BN_Destroy(u1);
    BN_Destroy(u2);
    BN_Destroy(w);
    BN_MontDestroy(montP);
    BN_OptimizerDestroy(opt);
    return ret;
}

int32_t CRYPT_DSA_VerifyData(const CRYPT_DSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen)
{
    if (ctx == NULL || sign == NULL || signLen == 0 || (data == NULL && dataLen != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL || ctx->y == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DSA_ERR_KEY_INFO);
        return CRYPT_DSA_ERR_KEY_INFO;
    }

    int32_t ret;
    BN_BigNum *r = BN_Create(BN_Bits(ctx->para->p));
    BN_BigNum *s = BN_Create(BN_Bits(ctx->para->q));
    BN_BigNum *d = DSA_Bits2Int(ctx->para->q, data, dataLen);
    if (r == NULL || s == NULL || d == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }

    ret = CRYPT_EAL_DecodeSign(sign, signLen, r, s);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ret = VerifyCore(ctx, d, r, s);
EXIT:
    BN_Destroy(r);
    BN_Destroy(s);
    BN_Destroy(d);
    return ret;
}

int32_t CRYPT_DSA_Verify(const CRYPT_DSA_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen)
{
    uint8_t hash[64]; // 64 is max hash len
    uint32_t hashLen = sizeof(hash) / sizeof(hash[0]);
    int32_t ret = EAL_Md(algId, data, dataLen, hash, &hashLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_DSA_VerifyData(ctx, hash, hashLen, sign, signLen);
}

int32_t CRYPT_DSA_Cmp(const CRYPT_DSA_Ctx *a, const CRYPT_DSA_Ctx *b)
{
    RETURN_RET_IF(a == NULL || b == NULL, CRYPT_NULL_INPUT);

    RETURN_RET_IF(a->y == NULL || b->y == NULL, CRYPT_DSA_ERR_KEY_INFO);
    RETURN_RET_IF(BN_Cmp(a->y, b->y) != 0, CRYPT_DSA_PUBKEY_NOT_EQUAL);

    // para must be both NULL and non-NULL.
    RETURN_RET_IF((a->para == NULL) != (b->para == NULL), CRYPT_DSA_PARA_ERROR);
    if (a->para != NULL) {
        RETURN_RET_IF(BN_Cmp(a->para->p, b->para->p) != 0 ||
                      BN_Cmp(a->para->q, b->para->q) != 0 ||
                      BN_Cmp(a->para->g, b->para->g) != 0,
                      CRYPT_DSA_PARA_NOT_EQUAL);
    }
    return CRYPT_SUCCESS;
}

static uint32_t CRYPT_DSA_GetPrvKeyLen(const CRYPT_DSA_Ctx *ctx)
{
    return BN_Bytes(ctx->x);
}

static uint32_t CRYPT_DSA_GetPubKeyLen(const CRYPT_DSA_Ctx *ctx)
{
    if (ctx->para != NULL) {
        return BN_Bytes(ctx->para->p);
    }
    if (ctx->y != NULL) {
        return BN_Bytes(ctx->y);
    }
    BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
    return 0;
}

int32_t CRYPT_DSA_Ctrl(CRYPT_DSA_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_GET_BITS:
            return GetUintCtrl(ctx, val, len, (GetUintCallBack)CRYPT_DSA_GetBits);
        case CRYPT_CTRL_GET_SIGNLEN:
            return GetUintCtrl(ctx, val, len, (GetUintCallBack)CRYPT_DSA_GetSignLen);
        case CRYPT_CTRL_GET_SECBITS:
            return GetUintCtrl(ctx, val, len, (GetUintCallBack)CRYPT_DSA_GetSecBits);
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            return GetUintCtrl(ctx, val, len, (GetUintCallBack)CRYPT_DSA_GetPubKeyLen);
        case CRYPT_CTRL_GET_PRVKEY_LEN:
            return GetUintCtrl(ctx, val, len, (GetUintCallBack)CRYPT_DSA_GetPrvKeyLen);
        case CRYPT_CTRL_UP_REFERENCES:
            if (val == NULL || len != (uint32_t)sizeof(int)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            return BSL_SAL_AtomicUpReferences(&(ctx->references), (int *)val);
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(CRYPT_DSA_UNSUPPORTED_CTRL_OPTION);
    return CRYPT_DSA_UNSUPPORTED_CTRL_OPTION;
}

int32_t CRYPT_DSA_GetSecBits(const CRYPT_DSA_Ctx *ctx)
{
    if (ctx == NULL || ctx->para == NULL || ctx->para->p == NULL || ctx->para->q == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    return BN_SecBits(BN_Bits(ctx->para->p), BN_Bits(ctx->para->q));
}
#endif /* HITLS_CRYPTO_DSA */

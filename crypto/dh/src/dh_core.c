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
#ifdef HITLS_CRYPTO_DH

#include "crypt_errno.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_bn.h"
#include "crypt_utils.h"
#include "crypt_dh.h"
#include "dh_local.h"
#include "sal_atomic.h"

CRYPT_DH_Ctx *CRYPT_DH_NewCtx(void)
{
    CRYPT_DH_Ctx *ctx = BSL_SAL_Malloc(sizeof(CRYPT_DH_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ctx, sizeof(CRYPT_DH_Ctx), 0, sizeof(CRYPT_DH_Ctx));
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

static CRYPT_DH_Para *ParaMemGet(uint32_t bits)
{
    CRYPT_DH_Para *para = BSL_SAL_Calloc(1u, sizeof(CRYPT_DH_Para));
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    para->p = BN_Create(bits);
    para->g = BN_Create(bits);
    para->id = CRYPT_PKEY_PARAID_MAX;
    if (para->p == NULL || para->g == NULL) {
        CRYPT_DH_FreePara(para);
        BSL_ERR_PUSH_ERROR(CRYPT_DH_CREATE_PARA_FAIL);
        return NULL;
    }
    return para;
}

static int32_t NewParaCheck(const CRYPT_DhPara *para)
{
    if (para == NULL || para->p == NULL || para->g == NULL ||
        para->pLen == 0 || para->gLen == 0 || (para->q == NULL &&
        para->qLen != 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->pLen > BN_BITS_TO_BYTES(DH_MAX_PBITS)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    if (para->gLen > para->pLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    if (para->q == NULL) {
        return CRYPT_SUCCESS;
    }
    if (para->qLen > para->pLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    return CRYPT_SUCCESS;
}

CRYPT_DH_Para *CRYPT_DH_NewPara(const CRYPT_DhPara *para)
{
    if (NewParaCheck(para) != CRYPT_SUCCESS) {
        return NULL;
    }
    uint32_t modBits = BN_BYTES_TO_BITS(para->pLen);
    CRYPT_DH_Para *retPara = ParaMemGet(modBits);
    if (retPara == NULL) {
        return NULL;
    }

    int32_t ret = BN_Bin2Bn(retPara->p, para->p, para->pLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Bin2Bn(retPara->g, para->g, para->gLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (para->q == NULL) {
        return retPara; // The parameter q does not exist, this function is ended early.
    }
    retPara->q = BN_Create(modBits);
    if (retPara->q == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_CREATE_PARA_FAIL);
        goto ERR;
    }
    ret = BN_Bin2Bn(retPara->q, para->q, para->qLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    retPara->id = CRYPT_PKEY_PARAID_MAX; // No ID is passed in this function. Assign a invalid ID temporarily.
    return retPara;
ERR:
    CRYPT_DH_FreePara(retPara);
    return NULL;
}

void CRYPT_DH_FreePara(CRYPT_DH_Para *dhPara)
{
    if (dhPara == NULL) {
        return;
    }
    BN_Destroy(dhPara->p);
    BN_Destroy(dhPara->q);
    BN_Destroy(dhPara->g);
    BSL_SAL_FREE(dhPara);
}

void CRYPT_DH_FreeCtx(CRYPT_DH_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    int val = 0;
    BSL_SAL_AtomicDownReferences(&(ctx->references), &val);
    if (val > 0) {
        return;
    }
    CRYPT_DH_FreePara(ctx->para);
    BN_Destroy(ctx->x);
    BN_Destroy(ctx->y);
    BSL_SAL_ReferencesFree(&(ctx->references));
    BSL_SAL_FREE(ctx);
}

static int32_t ParaQCheck(BN_BigNum *q, BN_BigNum *r)
{
    // 1. Determine the length.
    if (BN_Bits(q) < DH_MIN_QBITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    // 2. Parity and even judgment
    if (BN_GetBit(q, 0) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    // 3. Compare q and r.
    if (BN_Cmp(q, r) >= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }

    // 4. Check the pq multiple relationship.
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BN_Div(NULL, r, r, q, opt);
    BN_OptimizerDestroy(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // (p - 1) % q == 0
    if (!BN_IsZero(r)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    return CRYPT_SUCCESS;
}

static int32_t ParaDataCheck(const CRYPT_DH_Para *para)
{
    int32_t ret;
    const BN_BigNum *p = para->p;
    const BN_BigNum *g = para->g;
    // 1. Determine the length.
    uint32_t pBits = BN_Bits(p);
    if (pBits < DH_MIN_PBITS || pBits > DH_MAX_PBITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    // 2. P parity and g value judgment
    // p is an odd number
    if (BN_GetBit(p, 0) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    // g != 0 && g != 1
    if (BN_IsZero(g) || BN_IsOne(g)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }

    BN_BigNum *r = BN_Create(pBits + 1);
    if (r == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // r = p - 1
    ret = BN_SubLimb(r, p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // g < p - 1
    if (BN_Cmp(g, r) >= 0) {
        ret = CRYPT_DH_PARA_ERROR;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (para->q != NULL) {
        ret = ParaQCheck(para->q, r);
    }
ERR:
    BN_Destroy(r);
    return ret;
}

static CRYPT_DH_Para *ParaDup(const CRYPT_DH_Para *para)
{
    CRYPT_DH_Para *ret = BSL_SAL_Malloc(sizeof(CRYPT_DH_Para));
    if (ret == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ret->p = BN_Dup(para->p);
    ret->q = BN_Dup(para->q);
    ret->g = BN_Dup(para->g);
    ret->id = para->id;
    if (ret->p == NULL || ret->g == NULL) {
        CRYPT_DH_FreePara(ret);
        BSL_ERR_PUSH_ERROR(CRYPT_DH_CREATE_PARA_FAIL);
        return NULL;
    }
    if (para->q != NULL && ret->q == NULL) {
        CRYPT_DH_FreePara(ret);
        BSL_ERR_PUSH_ERROR(CRYPT_DH_CREATE_PARA_FAIL);
        return NULL;
    }
    return ret;
}

CRYPT_DH_Ctx *CRYPT_DH_DupCtx(CRYPT_DH_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_DH_Ctx *newKeyCtx = BSL_SAL_Calloc(1, sizeof(CRYPT_DH_Ctx));
    if (newKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    // If x, y and para is not empty, copy the value.
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->x, ctx->x, BN_Dup(ctx->x), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->y, ctx->y, BN_Dup(ctx->y), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->para, ctx->para, ParaDup(ctx->para), CRYPT_MEM_ALLOC_FAIL);
    BSL_SAL_ReferencesInit(&(newKeyCtx->references));
    return newKeyCtx;

ERR :
    CRYPT_DH_FreeCtx(newKeyCtx);
    return NULL;
}

int32_t CRYPT_DH_SetPara(CRYPT_DH_Ctx *ctx, const CRYPT_DH_Para *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = ParaDataCheck(para);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_Destroy(ctx->x);
    BN_Destroy(ctx->y);
    CRYPT_DH_FreePara(ctx->para);
    ctx->x = NULL;
    ctx->y = NULL;
    ctx->para = ParaDup(para);
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_DH_GetPara(const CRYPT_DH_Ctx *ctx, CRYPT_DhPara *para)
{
    int32_t ret;

    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    ret = BN_Bn2Bin(ctx->para->p, para->p, &(para->pLen));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (ctx->para->q == NULL) {
        para->q = NULL;
        para->qLen = 0;
    } else {
        ret = BN_Bn2Bin(ctx->para->q, para->q, &(para->qLen));
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    ret = BN_Bn2Bin(ctx->para->g, para->g, &(para->gLen));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ret;
}

/**
    y != 0
    y != 1
    y < p - 1
    (y ^ q) mod p == 1
*/
static int32_t PubCheck(const BN_BigNum *y, const BN_BigNum *minP,
    const BN_BigNum *q, BN_Mont *montP, BN_Optimizer *opt)
{
    // y != 0, y != 1
    if (BN_IsZero(y) || BN_IsOne(y)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    // y < p - 1
    if (BN_Cmp(y, minP) >= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    if (q == NULL) {
        return CRYPT_SUCCESS; // The parameter q does not exist, this function is ended early.
    }
    // Verify q.
    BN_BigNum *r = BN_Create(BN_Bits(minP));
    if (r == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BN_MontExp(r, y, q, montP, opt);
    if (ret != CRYPT_SUCCESS) {
        BN_Destroy(r);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (!BN_IsOne(r)) {
        BN_Destroy(r);
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    BN_Destroy(r);
    return CRYPT_SUCCESS;
}

// Get p-2 or q-1
static int32_t GetXLimb(BN_BigNum *xLimb, const BN_BigNum *p, const BN_BigNum *q)
{
    if (q != NULL) {
        // xLimb = q - 1
        return BN_SubLimb(xLimb, q, 1);
    }
    // xLimb = p - 2
    return BN_SubLimb(xLimb, p, 2);
}

static void RefreshCtx(CRYPT_DH_Ctx *dhCtx, BN_BigNum *x, BN_BigNum *y, int32_t ret)
{
    if (ret == CRYPT_SUCCESS) {
        BN_Destroy(dhCtx->x);
        BN_Destroy(dhCtx->y);
        dhCtx->x = x;
        dhCtx->y = y;
    } else {
        BN_Destroy(x);
        BN_Destroy(y);
    }
}

int32_t CRYPT_DH_Gen(CRYPT_DH_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    int32_t ret;
    int32_t cnt;
    BN_BigNum *x = BN_Create(BN_Bits(ctx->para->p) + 1);
    BN_BigNum *y = BN_Create(BN_Bits(ctx->para->p));
    BN_BigNum *minP = BN_Create(BN_Bits(ctx->para->p) + 1);
    BN_BigNum *xLimb = BN_Create(BN_Bits(ctx->para->p) + 1);
    BN_Mont *mont = BN_MontCreate(ctx->para->p);
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (x == NULL || y == NULL || minP == NULL || xLimb == NULL || mont == NULL || opt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_SubLimb(minP, ctx->para->p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = GetXLimb(xLimb, ctx->para->p, ctx->para->q);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    for (cnt = 0; cnt < CRYPT_DH_TRY_CNT_MAX; cnt++) {
        /*  Generate private key x for [1, q-1] or [1, p-2] */
        ret = BN_RandRange(x, xLimb);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        ret = BN_AddLimb(x, x, 1);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        /* Calculate the public key y. */
        ret = BN_MontExpConsttime(y, ctx->para->g, x, mont, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        /* Check whether the public key meets the requirements. If not, try to generate the key again. */
        // y != 0, y != 1, y < p - 1
        if (BN_IsZero(y) || BN_IsOne(y) || BN_Cmp(y, minP) >= 0) {
            continue;
        }
        goto ERR; // The function exits successfully.
    }
    ret = CRYPT_DH_RAND_GENERATE_ERROR;
    BSL_ERR_PUSH_ERROR(ret);
ERR:
    RefreshCtx(ctx, x, y, ret);
    BN_Destroy(minP);
    BN_Destroy(xLimb);
    BN_MontDestroy(mont);
    BN_OptimizerDestroy(opt);
    return ret;
}

static int32_t ComputeShareKeyInputCheck(const CRYPT_DH_Ctx *ctx, const CRYPT_DH_Ctx *pubKey,
    const uint8_t *shareKey, const uint32_t *shareKeyLen)
{
    if (ctx == NULL || pubKey == NULL || shareKey == NULL || shareKeyLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    if (ctx->x == NULL || pubKey->y == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    if (BN_Bytes(ctx->para->p) > *shareKeyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_DH_BUFF_LEN_NOT_ENOUGH;
    }
    return CRYPT_SUCCESS;
}

static void CheckAndFillZero(uint8_t *shareKey, uint32_t *shareKeyLen, uint32_t bytes)
{
    int32_t i;
    if (*shareKeyLen == bytes) { // (*shareKeyLen > bytes) is not possible
        return;
    }
    uint32_t fill = bytes - *shareKeyLen;
    for (i = (int32_t)*shareKeyLen - 1; i >= 0; i--) {
        shareKey[i + (int32_t)fill] = shareKey[i];
    }
    for (i = 0; i < (int32_t)fill; i++) {
        shareKey[i] = 0;
    }
    *shareKeyLen = bytes;
}

int32_t CRYPT_DH_ComputeShareKey(const CRYPT_DH_Ctx *ctx, const CRYPT_DH_Ctx *pubKey,
    uint8_t *shareKey, uint32_t *shareKeyLen)
{
    uint32_t bytes = 0;
    int32_t ret = ComputeShareKeyInputCheck(ctx, pubKey, shareKey, shareKeyLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BN_BigNum *minP = BN_Create(BN_Bits(ctx->para->p) + 1);
    BN_BigNum *r = BN_Create(BN_Bits(ctx->para->p));
    BN_Mont *mont = BN_MontCreate(ctx->para->p);
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (minP == NULL || r == NULL || mont == NULL || opt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_SubLimb(minP, ctx->para->p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    /* Check whether the public key meets the requirements. */
    ret = PubCheck(pubKey->y, minP, ctx->para->q, mont, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_MontExpConsttime(r, pubKey->y, ctx->x, mont, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Bn2Bin(r, shareKey, shareKeyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    bytes = BN_Bytes(ctx->para->p);
    CheckAndFillZero(shareKey, shareKeyLen, bytes);

ERR:
    BN_Destroy(minP);
    BN_Destroy(r);
    BN_MontDestroy(mont);
    BN_OptimizerDestroy(opt);
    return ret;
}

static int32_t PrvLenCheck(const CRYPT_DH_Ctx *ctx, const CRYPT_DhPrv *prv)
{
    if (ctx->para->q != NULL) {
        if (BN_Bytes(ctx->para->q) < prv->len) {
            BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
            return CRYPT_DH_KEYINFO_ERROR;
        }
    } else {
        if (BN_Bytes(ctx->para->p) < prv->len) {
            BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
            return CRYPT_DH_KEYINFO_ERROR;
        }
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_DH_SetPrvKey(CRYPT_DH_Ctx *ctx, const CRYPT_DhPrv *prv)
{
    if (ctx == NULL || prv == NULL || prv->data == NULL || prv->len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    int32_t ret = PrvLenCheck(ctx, prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BN_BigNum *bnX = BN_Create(BN_BYTES_TO_BITS(prv->len));
    BN_BigNum *xLimb = BN_Create(BN_Bits(ctx->para->p) + 1);
    if (bnX == NULL || xLimb == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = GetXLimb(xLimb, ctx->para->p, ctx->para->q);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Bin2Bn(bnX, prv->data, prv->len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // Satisfy x <= q - 1 or x <= p - 2
    if (BN_Cmp(bnX, xLimb) > 0) {
        ret = CRYPT_DH_KEYINFO_ERROR;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    // x != 0
    if (BN_IsZero(bnX)) {
        ret = CRYPT_DH_KEYINFO_ERROR;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    BN_Destroy(xLimb);
    BN_Destroy(ctx->x);
    ctx->x = bnX;
    return ret;
ERR:
    BN_Destroy(bnX);
    BN_Destroy(xLimb);
    return ret;
}

// No parameter information is required for setting the public key.
// Therefore, the validity of the public key is not checked during the setting.
// The validity of the public key is checked during the calculation of the shared key.
int32_t CRYPT_DH_SetPubKey(CRYPT_DH_Ctx *ctx, const CRYPT_DhPub *pub)
{
    if (ctx == NULL || pub == NULL || pub->data == NULL || pub->len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pub->len > BN_BITS_TO_BYTES(DH_MAX_PBITS)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    BN_BigNum *bnY = BN_Create(BN_BYTES_TO_BITS(pub->len));
    if (bnY == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BN_Bin2Bn(bnY, pub->data, pub->len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    BN_Destroy(ctx->y);
    ctx->y = bnY;
    return ret;
ERR:
    BN_Destroy(bnY);
    return ret;
}

int32_t CRYPT_DH_GetPrvKey(const CRYPT_DH_Ctx *ctx, CRYPT_DhPrv *prv)
{
    if (ctx == NULL || prv == NULL || prv->data == NULL || prv->len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->x == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    if (ctx->para->q != NULL) {
        if (BN_Bytes(ctx->para->q) > prv->len) {
            BSL_ERR_PUSH_ERROR(CRYPT_DH_BUFF_LEN_NOT_ENOUGH);
            return CRYPT_DH_BUFF_LEN_NOT_ENOUGH;
        }
    } else {
        if (BN_Bytes(ctx->para->p) > prv->len) {
            BSL_ERR_PUSH_ERROR(CRYPT_DH_BUFF_LEN_NOT_ENOUGH);
            return CRYPT_DH_BUFF_LEN_NOT_ENOUGH;
        }
    }
    int32_t ret = BN_Bn2Bin(ctx->x, prv->data, &(prv->len));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_DH_GetPubKey(const CRYPT_DH_Ctx *ctx, CRYPT_DhPub *pub)
{
    if (ctx == NULL || pub == NULL || pub->data == NULL || pub->len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->y == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    if (BN_Bytes(ctx->y) > pub->len) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_DH_BUFF_LEN_NOT_ENOUGH;
    }
    int32_t ret = BN_Bn2Bin(ctx->y, pub->data, &(pub->len));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

uint32_t CRYPT_DH_GetBits(const CRYPT_DH_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    return BN_Bits(ctx->para->p);
}

int32_t CRYPT_DH_Check(const CRYPT_DH_Ctx *ctx)
{
    int32_t ret;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->x == NULL || ctx->y == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    BN_Mont *mont = BN_MontCreate(ctx->para->p);
    BN_Optimizer *opt = BN_OptimizerCreate();
    BN_BigNum *y = BN_Create(BN_Bits(ctx->para->p));
    if (y == NULL || mont == NULL || opt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // SP800-56A R3 Section 5.6.2.1.4 Owner Assurance of Pair-wise Consistency
    ret = BN_MontExpConsttime(y, ctx->para->g, ctx->x, mont, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (BN_Cmp(y, ctx->y) != 0) {
        ret = CRYPT_DH_PAIRWISE_CHECK_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    BN_Destroy(y);
    BN_MontDestroy(mont);
    BN_OptimizerDestroy(opt);
    return ret;
}

int32_t CRYPT_DH_Cmp(const CRYPT_DH_Ctx *a, const CRYPT_DH_Ctx *b)
{
    RETURN_RET_IF(a == NULL || b == NULL, CRYPT_NULL_INPUT);

    RETURN_RET_IF(a->y == NULL || b->y == NULL, CRYPT_DH_KEYINFO_ERROR);
    RETURN_RET_IF(BN_Cmp(a->y, b->y) != 0, CRYPT_DH_PUBKEY_NOT_EQUAL);

    // para must be both null and non-null.
    RETURN_RET_IF((a->para == NULL) != (b->para == NULL), CRYPT_DH_PARA_ERROR);
    if (a->para != NULL) {
        RETURN_RET_IF(BN_Cmp(a->para->p, b->para->p) != 0 ||
                      BN_Cmp(a->para->q, b->para->q) != 0 ||
                      BN_Cmp(a->para->g, b->para->g) != 0,
                      CRYPT_DH_PARA_NOT_EQUAL);
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_DH_Ctrl(CRYPT_DH_Ctx *ctx, CRYPT_PkeyCtrl opt, void *val, uint32_t len)
{
    if (ctx == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len == (uint32_t)sizeof(int) && opt == CRYPT_CTRL_UP_REFERENCES) {
        return BSL_SAL_AtomicUpReferences(&(ctx->references), (int *)val);
    }
    BSL_ERR_PUSH_ERROR(CRYPT_DH_UNSUPPORTED_CTRL_OPTION);
    return CRYPT_DH_UNSUPPORTED_CTRL_OPTION;
}

/**
 * @ingroup dh
 * @brief dh get security bits
 *
 * @param ctx [IN] dh Context structure
 *
 * @retval security bits
 */
int32_t CRYPT_DH_GetSecBits(const CRYPT_DH_Ctx *ctx)
{
    if (ctx == NULL || ctx->para == NULL || ctx->para->p == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    if (ctx->para->q == NULL) {
        return BN_SecBit(BN_Bits(ctx->para->p), -1);
    }
    return BN_SecBit(BN_Bits(ctx->para->p), BN_Bits(ctx->para->q));
}

#endif /* HITLS_CRYPTO_DH */

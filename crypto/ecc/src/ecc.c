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
#ifdef HITLS_CRYPTO_ECC

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "ecc_local.h"

ECC_Point *ECC_NewPoint(const ECC_Para *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    int32_t ret;
    uint32_t words = BITS_TO_BN_UNIT(BN_Bits(para->p));
    ECC_Point *pt = BSL_SAL_Calloc(sizeof(ECC_Point), 1u);
    if (pt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    pt->id = para->id;
    if ((ret = BN_Extend(&pt->x, words)) != CRYPT_SUCCESS ||
        (ret = BN_Extend(&pt->y, words)) != CRYPT_SUCCESS ||
        (ret = BN_Extend(&pt->z, words)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        ECC_FreePoint(pt);
        return NULL;
    }
    return pt;
}

void ECC_FreePoint(ECC_Point *pt)
{
    if (pt == NULL) {
        return;
    }
    BSL_SAL_CleanseData((void *)(pt->x.data), pt->x.size * sizeof(BN_UINT));
    BSL_SAL_FREE(pt->x.data);
    BSL_SAL_CleanseData((void *)(pt->y.data), pt->y.size * sizeof(BN_UINT));
    BSL_SAL_FREE(pt->y.data);
    BSL_SAL_CleanseData((void *)(pt->z.data), pt->z.size * sizeof(BN_UINT));
    BSL_SAL_FREE(pt->z.data);
    BSL_SAL_Free(pt);
}

void ECC_SetLibCtx(void *libCtx, ECC_Para *para)
{
    para->libCtx = libCtx;
}

int32_t ECC_CopyPoint(ECC_Point *dst, const ECC_Point *src)
{
    if (dst == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (dst->id != src->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    int32_t ret;
    if ((ret = BN_Copy(&dst->x, &src->x)) != CRYPT_SUCCESS ||
        (ret = BN_Copy(&dst->y, &src->y)) != CRYPT_SUCCESS ||
        (ret = BN_Copy(&dst->z, &src->z)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

ECC_Point *ECC_DupPoint(const ECC_Point *pt)
{
    if (pt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    int32_t ret;
    ECC_Point *newPt = BSL_SAL_Calloc(sizeof(ECC_Point), 1u);
    if (newPt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    newPt->id = pt->id;
    if ((ret = BN_Extend(&newPt->x, pt->x.room)) != CRYPT_SUCCESS ||
        (ret = BN_Extend(&newPt->y, pt->y.room)) != CRYPT_SUCCESS ||
        (ret = BN_Extend(&newPt->z, pt->z.room)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        ECC_FreePoint(newPt);
        return NULL;
    }
    (void)BN_Copy(&newPt->x, &pt->x);
    (void)BN_Copy(&newPt->y, &pt->y);
    (void)BN_Copy(&newPt->z, &pt->z);
    return newPt;
}

// Convert to Cartesian coordinates
int32_t ECC_GetPoint(const ECC_Para *para, ECC_Point *pt, CRYPT_Data *x, CRYPT_Data *y)
{
    int32_t ret;
    bool nullInput = para == NULL || pt == NULL || x == NULL || x->data == NULL || ((y != NULL) && (y->data == NULL));
    if (nullInput == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != pt->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    uint32_t pBytes = BN_Bytes(para->p);
    if ((x->len < pBytes) || ((y != NULL) && (y->len < pBytes))) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_ECC_BUFF_LEN_NOT_ENOUGH;
    }
    if (BN_IsZero(&pt->z)) { // infinity point
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    if (para->method->point2Affine == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
        return CRYPT_ECC_NOT_SUPPORT;
    }
    GOTO_ERR_IF(para->method->point2Affine(para, pt, pt), ret);
    GOTO_ERR_IF(BN_Bn2BinFixZero(&pt->x, x->data, pBytes), ret);
    x->len = pBytes;
    if (y != NULL) {
        GOTO_ERR_IF(BN_Bn2BinFixZero(&pt->y, y->data, pBytes), ret);
        y->len = pBytes;
    }
ERR:
    return ret;
}

int32_t ECC_Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a)
{
    if (para == NULL || r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != a->id || para->id != r->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (BN_IsZero(&a->z)) { // infinity point
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    if (para->method->point2Affine == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
        return CRYPT_ECC_NOT_SUPPORT;
    }
    int32_t ret = para->method->point2Affine(para, r, a);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t ECC_GetPoint2Bn(const ECC_Para *para, ECC_Point *pt, BN_BigNum *x, BN_BigNum *y)
{
    int32_t ret;
    GOTO_ERR_IF(ECC_GetPointDataX(para, pt, x), ret);
    if (y != NULL) {
        GOTO_ERR_IF(BN_Copy(y, &pt->y), ret);
    }
ERR:
    return ret;
}

int32_t ECC_GetPointDataX(const ECC_Para *para, ECC_Point *pt, BN_BigNum *x)
{
    int32_t ret;
    if (x == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    GOTO_ERR_IF(ECP_PointAtInfinity(para, pt), ret);
    if (para->method->point2Affine == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
        return CRYPT_ECC_NOT_SUPPORT;
    }
    GOTO_ERR_IF(para->method->point2Affine(para, pt, pt), ret);
    GOTO_ERR_IF(BN_Copy(x, &pt->x), ret);
ERR:
    return ret;
}

ECC_Point *ECC_GetGFromPara(const ECC_Para *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    ECC_Point *pt = ECC_NewPoint(para);
    if (pt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)BN_Copy(&pt->x, para->x);
    (void)BN_Copy(&pt->y, para->y);
    (void)BN_SetLimb(&pt->z, 1);
    return pt;
}

int32_t ECC_PointMulAdd(ECC_Para *para, ECC_Point *r,
    const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->method->pointMulAdd == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
        return CRYPT_ECC_NOT_SUPPORT;
    }
    return para->method->pointMulAdd(para, r, k1, k2, pt);
}

int32_t ECC_PointMul(ECC_Para *para,  ECC_Point *r,
    const BN_BigNum *k, const ECC_Point *pt)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->method->pointMul == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
        return CRYPT_ECC_NOT_SUPPORT;
    }
    return para->method->pointMul(para, r, k, pt);
}

ECC_Para *ECC_DupPara(const ECC_Para *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    ECC_Para *newPara = ECC_NewPara(para->id);
    if (newPara != NULL) {
        newPara->libCtx = para->libCtx;
    }
    return newPara;
}

uint32_t ECC_ParaBits(const ECC_Para *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    return BN_Bits(para->p);
}

BN_BigNum *ECC_GetParaH(const ECC_Para *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    return BN_Dup(para->h);
}

BN_BigNum *ECC_GetParaN(const ECC_Para *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    return BN_Dup(para->n);
}

BN_BigNum *ECC_GetParaA(const ECC_Para *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    BN_BigNum *dupA = BN_Dup(para->a);
    if (dupA == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    if (para->method->bnMontDec != NULL) {
        para->method->bnMontDec(dupA, para->montP);
    }
    return dupA;
ERR:
    BN_Destroy(dupA);
    return NULL;
}

BN_BigNum *ECC_GetParaB(const ECC_Para *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    BN_BigNum *dupB = BN_Dup(para->b);
    if (dupB == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    if (para->method->bnMontDec != NULL) {
        para->method->bnMontDec(dupB, para->montP);
    }
    return dupB;
ERR:
    BN_Destroy(dupB);
    return NULL;
}

BN_BigNum *ECC_GetParaX(const ECC_Para *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    return BN_Dup(para->x);
}

BN_BigNum *ECC_GetParaY(const ECC_Para *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    return BN_Dup(para->y);
}

int32_t ECC_GetEncodeDataLen(const ECC_Para *para, ECC_Point *pt, CRYPT_PKEY_PointFormat format, uint32_t *dataLen)
{
    return ECP_GetEncodeDataLen(para, pt, format, dataLen);
}

int32_t ECC_PointCheck(const ECC_Point *pt)
{
    if (pt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    return CRYPT_SUCCESS;
}

int32_t ECC_ModOrderInv(const ECC_Para *para, BN_BigNum *r, const BN_BigNum *a)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->method->modOrdInv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
        return CRYPT_ECC_NOT_SUPPORT;
    }
    return para->method->modOrdInv(para, r, a);
}

int32_t ECC_PointToMont(const ECC_Para *para, ECC_Point *pt, BN_Optimizer *opt)
{
    if (para == NULL || pt == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->method->bnMontEnc == NULL) {
        return CRYPT_SUCCESS;
    }
    int32_t ret;
    if ((ret = para->method->bnMontEnc(&pt->x, para->montP, opt, false)) != CRYPT_SUCCESS ||
        (ret = para->method->bnMontEnc(&pt->y, para->montP, opt, false)) != CRYPT_SUCCESS ||
        (ret = para->method->bnMontEnc(&pt->z, para->montP, opt, false)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

void ECC_PointFromMont(const ECC_Para *para, ECC_Point *r)
{
    if (para == NULL || r == NULL || para->method->bnMontDec == NULL) {
        return;
    }
    para->method->bnMontDec(&r->x, para->montP);
    para->method->bnMontDec(&r->y, para->montP);
    para->method->bnMontDec(&r->z, para->montP);
}

/*
 Prime curve, point addition r = a + b
 Calculation formula:
    X3 = (Y2*Z1^3-Y1)^2 - (X2*Z1^2-X1)^2 * (X1+X2*Z1^2)
    Y3 = (Y2*Z1^3-Y1) * (X1*(X2*Z1^2-X1)^2-X3) - Y1 * (X2*Z1^2-X1)^3
    Z3 = (X2*Z1^2-X1) * Z1
*/
int32_t ECC_PointAddAffine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b)
{
    int32_t ret;
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->method->pointAddAffine == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
        return CRYPT_ECC_NOT_SUPPORT;
    }
    BN_Optimizer *opt = BN_OptimizerCreate();
    ECC_Point *affineb = ECC_NewPoint(para);
    ECC_Point *dupA = ECC_DupPoint(a);
    if (affineb == NULL || opt == NULL || dupA == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    GOTO_ERR_IF(ECC_Point2Affine(para, affineb, b), ret);
    GOTO_ERR_IF(ECC_PointToMont(para, dupA, opt), ret);
    GOTO_ERR_IF(ECC_PointToMont(para, affineb, opt), ret);
    GOTO_ERR_IF(para->method->pointAddAffine(para, r, dupA, affineb), ret);
    ECC_PointFromMont(para, r);
ERR:
    BN_OptimizerDestroy(opt);
    ECC_FreePoint(dupA);
    ECC_FreePoint(affineb);
    return ret;
}

typedef struct {
    uint32_t ecKeyLen;
    uint32_t secBits;
} ComparableStrengths;

/* See the standard document
   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
   Table 2: Comparable strengths */
const ComparableStrengths STRENGTHS_TABLE[] = {
    {512, 256},
    {384, 192},
    {256, 128},
    {224, 112},
    {160, 80}
};

int32_t ECC_GetSecBits(const ECC_Para *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    uint32_t bits = BN_Bits(para->n);
    for (uint32_t i = 0; i < sizeof(STRENGTHS_TABLE) / sizeof(STRENGTHS_TABLE[0]); i++) {
        if (bits >= STRENGTHS_TABLE[i].ecKeyLen) {
            return (int32_t)STRENGTHS_TABLE[i].secBits;
        }
    }
    return (int32_t)(bits / 2); // If the key length is less than 160, the key strength is equal to the key length / 2.
}

#endif /* HITLS_CRYPTO_ECC */

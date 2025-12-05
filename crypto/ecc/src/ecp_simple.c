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

int32_t ECP_PointAtInfinity(const ECC_Para *para, const ECC_Point *pt)
{
    if (para == NULL || pt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != pt->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    // If z is 0, the point is the infinite point (0 point).
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    return CRYPT_SUCCESS;
}

// Check whether the point is on the curve.
int32_t ECP_PointOnCurve(const ECC_Para *para, const ECC_Point *pt)
{
    uint32_t nistList[] = {CRYPT_ECC_NISTP224, CRYPT_ECC_NISTP256, CRYPT_ECC_NISTP384, CRYPT_ECC_NISTP521};
    int32_t ret = ECP_PointAtInfinity(para, pt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    // Do not check the point on the Jacobian coordinate system.
    RETURN_RET_IF(!BN_IsOne(&pt->z), CRYPT_ECC_POINT_NOT_AFFINE);

    uint32_t bits = BN_Bits(para->p);
    BN_Optimizer *opt = BN_OptimizerCreate();
    BN_BigNum *y = BN_Create(bits);
    BN_BigNum *x = BN_Create(bits);
    BN_BigNum *dupA = BN_Dup(para->a);
    BN_BigNum *dupB = BN_Dup(para->b);
    if (opt == NULL || x == NULL || y == NULL || dupA == NULL || dupB == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    if (para->method->bnMontDec != NULL) {
        para->method->bnMontDec(dupA, para->montP);
        para->method->bnMontDec(dupB, para->montP);
    }
    GOTO_ERR_IF(BN_ModSqr(x, &pt->x, para->p, opt), ret); // x^2
    GOTO_ERR_IF(BN_ModMul(x, x, &pt->x, para->p, opt), ret); // x^3
    if (ParamIdIsValid(para->id, nistList, sizeof(nistList) / sizeof(nistList[0]))) {
        // Currently, only the NIST curve is supported(calculating x^3 - 3x).
        // Other curves need to be expanded in the future.
        if ((ret = BN_ModSub(x, x, &pt->x, para->p, opt)) != CRYPT_SUCCESS ||
            (ret = BN_ModSub(x, x, &pt->x, para->p, opt)) != CRYPT_SUCCESS ||
            (ret = BN_ModSub(x, x, &pt->x, para->p, opt)) != CRYPT_SUCCESS) { //  x^3 - 3x
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
    } else {
        // General implementation
        GOTO_ERR_IF(BN_ModMul(y, dupA, &pt->x, para->p, opt), ret);
        GOTO_ERR_IF(BN_ModAdd(x, x, y, para->p, opt), ret); //  x^3 + ax
    }

    GOTO_ERR_IF(BN_ModAdd(x, x, dupB, para->p, opt), ret); //  x^3 - 3x + b
    GOTO_ERR_IF(BN_ModSqr(y, &pt->y, para->p, opt), ret); // y^2
    if (BN_Cmp(x, y) != 0) {
        ret = CRYPT_ECC_POINT_NOT_ON_CURVE;
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    BN_Destroy(x);
    BN_Destroy(y);
    BN_Destroy(dupA);
    BN_Destroy(dupB);
    BN_OptimizerDestroy(opt);
    return ret;
}

static int32_t CheckECCParameters(const ECC_Para *para, ECC_Point *r, const ECC_Point *pt)
{
    if (para == NULL || r == NULL || pt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != pt->id || para->id != r->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    return CRYPT_SUCCESS;
}

int32_t ECP_Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *pt)
{
    int32_t ret = CheckECCParameters(para, r, pt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (BN_IsOne(&pt->z)) {
        return ECC_CopyPoint(r, pt);
    }
    uint32_t bits = BN_Bits(para->p);
    BN_Optimizer *opt = BN_OptimizerCreate();
    BN_BigNum *zz = BN_Create(bits);
    BN_BigNum *inv = BN_Create(bits);
    if (opt == NULL || zz == NULL || inv == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if ((ret = BN_ModInv(inv, &pt->z, para->p, opt)) != CRYPT_SUCCESS ||
        (ret = BN_ModSqr(zz, inv, para->p, opt)) != CRYPT_SUCCESS ||
        (ret = BN_ModMul(&r->x, &pt->x, zz, para->p, opt)) != CRYPT_SUCCESS ||
        (ret = BN_ModMul(zz, zz, inv, para->p, opt)) != CRYPT_SUCCESS ||
        (ret = BN_ModMul(&r->y, &pt->y, zz, para->p, opt)) != CRYPT_SUCCESS ||
        (ret = BN_SetLimb(&r->z, 1)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

ERR:
    BN_Destroy(zz);
    BN_Destroy(inv);
    BN_OptimizerDestroy(opt);
    return ret;
}

// consttime
static int32_t ECP_PointCopyWithMask(ECC_Point *r, const ECC_Point *a, const ECC_Point *b, BN_UINT mask)
{
    int32_t ret;
    GOTO_ERR_IF(BN_CopyWithMask(&r->x, &a->x, &b->x, mask), ret);
    GOTO_ERR_IF(BN_CopyWithMask(&r->y, &a->y, &b->y, mask), ret);
    GOTO_ERR_IF(BN_CopyWithMask(&r->z, &a->z, &b->z, mask), ret);
ERR:
    return ret;
}

int32_t ECP_PointMul(ECC_Para *para,  ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt)
{
    if (para == NULL || r == NULL || k == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((para->id != r->id) || ((pt != NULL) && (para->id != pt->id))) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (pt != NULL && BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    if (BN_IsZero(k)) {
        (void)BN_Zeroize(&r->z);
        return CRYPT_SUCCESS;
    }
    if (BN_Cmp(k, para->n) == 0 && pt != NULL) {
        // In this case, the consttime calculation is not required
        // for checking whether the public key information is valid.
        return ECP_PointMulFast(para, r, para->n, pt);
    }
    uint32_t i;
    int32_t ret;
    BN_UINT mask;
    uint32_t bits;
    ECC_Point *base = (pt != NULL) ? ECC_DupPoint(pt) : ECC_GetGFromPara(para);
    ECC_Point *t = ECC_NewPoint(para);
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (base == NULL || t == NULL || opt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // Convert base to affine.
    GOTO_ERR_IF(ECP_Point2Affine(para, base, base), ret);
    // Add salt to prevent side channels.
    GOTO_ERR_IF(ECC_PointToMont(para, base, opt), ret);
    GOTO_ERR_IF(ECC_CopyPoint(r, base), ret);
    GOTO_ERR_IF(ECC_PointBlind(para, r), ret);
    bits = BN_Bits(k);
    for (i = bits - 1; i > 0; i--) {
        GOTO_ERR_IF(para->method->pointDouble(para, r, r), ret);
        GOTO_ERR_IF(para->method->pointAddAffine(para, t, r, base), ret);
        mask = BN_GetBit(k, i - 1) ? 0 : BN_MASK;
        // The last bit must be 1, and r must be updated to the latest data.
        GOTO_ERR_IF(ECP_PointCopyWithMask(r, t, r, mask), ret);
    }
    ECC_PointFromMont(para, r);
ERR:
    ECC_FreePoint(t);
    ECC_FreePoint(base);
    BN_OptimizerDestroy(opt);
    return ret;
}

// Generate a BigNum equal to (p + 1) / 2
BN_BigNum *ECP_HalfPGet(const BN_BigNum *p)
{
    int32_t ret;
    uint32_t bits = BN_Bits(p);
    BN_BigNum *halfP = BN_Create(bits + 1);
    if (halfP == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    GOTO_ERR_IF_EX(BN_AddLimb(halfP, p, 1), ret);
    GOTO_ERR_IF_EX(BN_Rshift(halfP, halfP, 1), ret);
    return halfP;
ERR:
    BN_Destroy(halfP);
    return NULL;
}

// The z coordinate of point pt multiplied by z.
int32_t ECP_Point2AffineWithInv(const ECC_Para *para, ECC_Point *r, const ECC_Point *pt, const BN_BigNum *inv)
{
    if (inv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CheckECCParameters(para, r, pt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(BN_ModSqr(&r->z, inv, para->p, opt), ret);            // z = inv^2
    GOTO_ERR_IF(BN_ModMul(&r->x, &pt->x, &r->z, para->p, opt), ret);    // x = x * (inv^2)
    GOTO_ERR_IF(BN_ModMul(&r->y, &pt->y, inv, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModMul(&r->y, &r->y, &r->z, para->p, opt), ret);     // y = y * (inv^3)
    GOTO_ERR_IF(BN_SetLimb(&r->z, 1), ret);                           // z = 1
ERR:
    BN_OptimizerDestroy(opt);
    return ret;
}

// Convert (x, y, z) to (x/z0^2, y/z0^3, z*z0)
static int32_t ECP_PointJacMulZ(const ECC_Para *para, ECC_Point *pt, const BN_BigNum *z, BN_Optimizer *opt)
{
    if (BN_IsZero(&pt->z)) {
        // Infinite point multiplied by z is meaningless.
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    uint32_t bits = BN_Bits(para->p);
    BN_BigNum *t = BN_Create(bits);
    if (t == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret;
    if ((ret = BN_ModMul(&pt->z, &pt->z, z, para->p, opt)) != CRYPT_SUCCESS || // z = z * z0
        (ret = BN_ModMul(&pt->y, &pt->y, z, para->p, opt)) != CRYPT_SUCCESS || // y = y * z0
        (ret = BN_ModSqr(t, z, para->p, opt)) != CRYPT_SUCCESS || // t = z0^2
        (ret = BN_ModMul(&pt->x, &pt->x, t, para->p, opt)) != CRYPT_SUCCESS || // x = x * (z0^2)
        (ret = BN_ModMul(&pt->y, &pt->y, t, para->p, opt)) != CRYPT_SUCCESS) { // y = y * (z0^3)
        BSL_ERR_PUSH_ERROR(ret);
    }
    BN_Destroy(t);
    return ret;
}

/*
 * relate to the paper "Resistance against Differential Power Analysis for Elliptic Curve Cryptosystems"
 * chapter 5.3 Third Countermeasure: Randomized Projective Coordinates
 * reference: http://www.crypto-uni.lu/jscoron/publications/dpaecc.pdf
 */
int32_t ECC_PointBlind(const ECC_Para *para, ECC_Point *pt)
{
    if (para == NULL || pt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != pt->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    int32_t ret;
    uint32_t bits = BN_Bits(para->p);
    BN_BigNum *blind = BN_Create(bits);
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (blind == NULL || opt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // Generate random numbers to randomize z.
    GOTO_ERR_IF(BN_RandRangeEx(para->libCtx, blind, para->p), ret);
    if (BN_IsZero(blind)) {
        ret = CRYPT_ECC_POINT_BLIND_WITH_ZERO;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF_EX(ECP_PointJacMulZ(para, pt, blind, opt), ret);
ERR:
    BN_Destroy(blind);
    BN_OptimizerDestroy(opt);
    return ret;
}

// Currently, only prime number curves are supported. Other curves need to be expanded.
int32_t ECC_PointCmp(const ECC_Para *para, const ECC_Point *a, const ECC_Point *b)
{
    RETURN_RET_IF(para == NULL || a == NULL || b == NULL, CRYPT_NULL_INPUT);
    if (para->id != a->id || para->id != b->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    // If both points are infinite points, equality is returned.
    if (BN_IsZero(&a->z) && BN_IsZero(&b->z)) {
        return CRYPT_SUCCESS;
    }
    if (BN_IsZero(&a->z) || BN_IsZero(&b->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_NOT_EQUAL);
        return CRYPT_ECC_POINT_NOT_EQUAL;
    }

    int32_t ret;
    BN_Optimizer *opt = BN_OptimizerCreate();
    ECC_Point *az = ECC_DupPoint(a);
    ECC_Point *bz = ECC_DupPoint(b);
    if (opt == NULL || az == NULL || bz == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // Transfer a and b to the same z.
    GOTO_ERR_IF(ECP_PointJacMulZ(para, az, &b->z, opt), ret);
    GOTO_ERR_IF(ECP_PointJacMulZ(para, bz, &a->z, opt), ret);
    if ((BN_Cmp(&az->x, &bz->x) != 0) || (BN_Cmp(&az->y, &bz->y) != 0)) {
        ret = CRYPT_ECC_POINT_NOT_EQUAL;
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    ECC_FreePoint(az);
    ECC_FreePoint(bz);
    BN_OptimizerDestroy(opt);
    return ret;
}

int32_t ECP_PointCopy(const ECC_Para *para, ECC_Point *a, const ECC_Point *b)
{
    (void)para;
    int32_t ret;

    a->id = b->id;
    if ((ret = BN_Copy(&a->x, &b->x)) != CRYPT_SUCCESS ||
        (ret = BN_Copy(&a->y, &b->y)) != CRYPT_SUCCESS ||
        (ret = BN_Copy(&a->z, &b->z)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

// Cartesian coordinate point inversion.
int32_t ECP_PointInvertAtAffine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a)
{
    if (para == NULL || r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != r->id || para->id != a->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (BN_IsZero(&a->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    int32_t ret;
    GOTO_ERR_IF(ECC_CopyPoint(r, a), ret);
    GOTO_ERR_IF(BN_Sub(&r->y, para->p, &r->y), ret);
ERR:
    return ret;
}

static int32_t ECP_PointPreCompute(const ECC_Para *para, ECC_Point *windows[], const ECC_Point *pt)
{
    int32_t ret;
    ECC_Point *doubleP = ECC_NewPoint(para);
    windows[0] = ECC_DupPoint(pt);
    BN_Optimizer *opt = NULL;
    uint32_t i;
    for (i = 1; i < WINDOW_TABLE_SIZE; i++) {
        windows[i] = ECC_NewPoint(para);
    }
    if (doubleP == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    for (i = 0; i < WINDOW_TABLE_SIZE; i++) {
        if (windows[i] == NULL) {
            ret = CRYPT_MEM_ALLOC_FAIL;
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
    }
    opt = BN_OptimizerCreate();
    if (opt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(ECC_PointToMont(para, windows[0], opt), ret);
    GOTO_ERR_IF(para->method->pointDouble(para, doubleP, windows[0]), ret);
    for (i = 1; i < (WINDOW_TABLE_SIZE >> 1); i++) {
        GOTO_ERR_IF(para->method->pointAdd(para, windows[i], windows[i - 1], doubleP), ret);
    }
    for (i = WINDOW_TABLE_SIZE >> 1; i < WINDOW_TABLE_SIZE; i++) {
        GOTO_ERR_IF(ECP_PointInvertAtAffine(para, windows[i], windows[i - (WINDOW_TABLE_SIZE >> 1)]), ret);
    }
    BN_OptimizerDestroy(opt);
    ECC_FreePoint(doubleP);
    return ret;
ERR:
    for (i = 0; i < WINDOW_TABLE_SIZE; i++) {
        ECC_FreePoint(windows[i]);
        windows[i] = NULL;
    }
    BN_OptimizerDestroy(opt);
    ECC_FreePoint(doubleP);
    return ret;
}

static int32_t ECP_ParaPrecompute(ECC_Para *para)
{
    if (para->tableG[0] != NULL) {
        // The pre-computation table already exists.
        return CRYPT_SUCCESS;
    }
    int32_t ret;
    ECC_Point *pt = ECC_GetGFromPara(para);
    if (pt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(ECP_PointPreCompute(para, para->tableG, pt), ret);
ERR:
    ECC_FreePoint(pt);
    return ret;
}

void ECC_ReCodeFree(ReCodeData *code)
{
    if (code == NULL) {
        return;
    }
    BSL_SAL_FREE(code->num); // The encoded data is insensitive and does not need to be set to 0.
    BSL_SAL_FREE(code->wide);
    BSL_SAL_FREE(code);
}

static ReCodeData *WinCodeNew(uint32_t len)
{
    ReCodeData *code = BSL_SAL_Malloc(sizeof(ReCodeData));
    if (code == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    code->num = BSL_SAL_Malloc(len * sizeof(int8_t));
    code->wide = BSL_SAL_Malloc(len * sizeof(uint32_t));
    if (code->num == NULL || code->wide == NULL) {
        ECC_ReCodeFree(code);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    return code;
}

// Shift the recoded data. If the shift fails, release the code data.
static int32_t RecodeKMove(ReCodeData *code, uint32_t len, uint32_t offset)
{
    // Data shift. The value assignment starts from the tail and moves the data to the left to start position.
    if (memmove_s(code->num, len * sizeof(int8_t), &(code->num[offset]), code->size * sizeof(int8_t)) != EOK ||
        memmove_s(code->wide, len * sizeof(uint32_t), &(code->wide[offset]), code->size * sizeof(uint32_t)) != EOK) {
        ECC_ReCodeFree(code);
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}

// Recode scalar data, remove the most significant bit 1 of the data in the window.
ReCodeData *ECC_ReCodeK(const BN_BigNum *k, uint32_t window)
{
    if (k == NULL || window == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }
    int8_t max = (1 << window);
    uint32_t bits = BN_Bits(k);
    uint32_t len = (bits / window) + 1;
    ReCodeData *code = WinCodeNew(len);
    if (code == NULL) {
        // The internal function WinCodeNew has executed push_err.
        return NULL;
    }
    uint32_t offset = len;
    uint32_t base = 0;
    bool carry = false;
    uint32_t lastWide = 0;
    while (base != bits) {
        offset--;
        // Find the start bit of the new item.
        while (BN_GetBit(k, base) == carry) {
            base++;
            lastWide++;
        }
        int8_t num = 0;
        uint32_t shift = 0;
        // Obtain the item of the window length.
        while ((shift < window) && (base != bits)) {
            int8_t add = (BN_GetBit(k, base) ? 1 : 0) << shift;
            num += add;
            base++;
            shift++;
        }
        // If there is a carry, perform carry processing.
        num += (carry ? 1 : 0);
        // Refresh carry.
        carry = num >= (max / 2); // Check whether the value >= (max/2). If yes, convert the value.
        // If the value of a new carry item exists, convert it to -(2^win - num)
        num = carry ? (-(max - num)) : num;
        code->num[offset] = num;
        code->wide[offset] = lastWide;
        lastWide = shift;
    }
    // If carry information exists, store data 1 in the most significant bit.
    if (carry) {
        offset--;
        code->num[offset] = 1;
        code->wide[offset] = lastWide;
    }
    code->baseBits = carry ? bits : (bits - lastWide);
    code->size = len - offset;
    // Data shift. The value assignment starts from the tail and moves the data to the left to start position.
    if (RecodeKMove(code, len, offset) != CRYPT_SUCCESS) {
        // If the operation fails, the RecodeKMove releases the code data.
        return NULL;
    }
    return code;
}

typedef struct {
    uint32_t baseBits;
    uint32_t bit;
    uint32_t bit1;
    uint32_t bit2;
    uint32_t offsetK1;
    uint32_t offsetK2;
    ReCodeData *codeK1;
    ReCodeData *codeK2;
} MulAddOffData;

static int32_t GetFirstData(const ECC_Para *para, ECC_Point *t, MulAddOffData *offData,
    ECC_Point **windowsP)
{
    int32_t ret;
    ECC_Point *const *windowsG = para->tableG;
    // Obtain the maximum start offset of the first item.
    offData->baseBits = (offData->codeK1->baseBits > offData->codeK2->baseBits) ?
        offData->codeK1->baseBits : offData->codeK2->baseBits;
    // If they are equal, the initial value is the sum of the two first items.
    // Otherwise, the initial value is the item with a larger offset among the two items.
    if (offData->codeK1->baseBits == offData->codeK2->baseBits) {
        int8_t offset1 = NUMTOOFFSET(offData->codeK1->num[offData->offsetK1]);
        int8_t offset2 = NUMTOOFFSET(offData->codeK2->num[offData->offsetK2]);
        GOTO_ERR_IF(para->method->pointAdd(para, t, windowsG[offset1], windowsP[offset2]), ret);
        offData->offsetK1++;
        offData->offsetK2++;
        offData->bit1 = offData->codeK1->wide[offData->offsetK1 - 1];
        offData->bit2 = offData->codeK2->wide[offData->offsetK2 - 1];
    } else if (offData->codeK1->baseBits > offData->codeK2->baseBits) {
        int8_t offset = NUMTOOFFSET(offData->codeK1->num[offData->offsetK1]);
        GOTO_ERR_IF(ECC_CopyPoint(t, windowsG[offset]), ret);
        offData->offsetK1++;
        offData->bit1 = offData->codeK1->wide[offData->offsetK1 - 1];
        offData->bit2 = offData->baseBits - offData->codeK2->baseBits;
    } else {
        int8_t offset = NUMTOOFFSET(offData->codeK2->num[offData->offsetK2]);
        GOTO_ERR_IF(ECC_CopyPoint(t, windowsP[offset]), ret);
        offData->offsetK2++;
        offData->bit1 = offData->baseBits - offData->codeK1->baseBits;
        offData->bit2 = offData->codeK2->wide[offData->offsetK2 - 1];
    }
ERR:
    return ret;
}

int32_t ECP_PointMulAddParaCheck(const ECC_Para *para, const ECC_Point *r, const BN_BigNum *k1,
    const BN_BigNum *k2, const ECC_Point *pt)
{
    if (para == NULL || r == NULL || k1 == NULL || k2 == NULL || pt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((para->id != r->id) || (para->id != pt->id)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    return CRYPT_SUCCESS;
}

// NotConstTime r = order*pt
int32_t ECP_PointMulFast(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt)
{
    if (para == NULL || r == NULL || k == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((para->id != r->id) || ((pt != NULL) && (para->id != pt->id))) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (BN_IsZero(k)) {
        (void)BN_Zeroize(&r->z);
        return CRYPT_SUCCESS;
    }
    int32_t ret;
    ReCodeData *codeK = NULL;
    int8_t offset;

    ECC_Point *windowsP[WINDOW_TABLE_SIZE] = { 0 };
    ECC_Point **windows = NULL;
    if (pt == NULL) {
        GOTO_ERR_IF(ECP_ParaPrecompute(para), ret);
        windows = para->tableG;
    } else {
        GOTO_ERR_IF(ECP_PointPreCompute(para, windowsP, pt), ret);
        windows = windowsP;
    }

    codeK = ECC_ReCodeK(k, PRE_COMPUTE_WINDOW);
    if (codeK == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    offset = NUMTOOFFSET(codeK->num[0]);
    GOTO_ERR_IF(ECC_CopyPoint(r, windows[offset]), ret);
    GOTO_ERR_IF(para->method->pointMultDouble(para, r, r, codeK->wide[0]), ret);
    for (uint32_t i = 1; i < codeK->size; i++) {
        offset = NUMTOOFFSET(codeK->num[i]);
        GOTO_ERR_IF(para->method->pointAdd(para, r, r, windows[offset]), ret);
        GOTO_ERR_IF(para->method->pointMultDouble(para, r, r, codeK->wide[i]), ret);
    }
    ECC_PointFromMont(para, r);
ERR:
    for (uint32_t i = 0; i < WINDOW_TABLE_SIZE; i++) {
        // Clear the pre-computation table.
        ECC_FreePoint(windowsP[i]);
    }
    ECC_ReCodeFree(codeK);
    return ret;
}

static int32_t KZeroHandle(ECC_Para *para, ECC_Point *r, const BN_BigNum *k1,
    const BN_BigNum *k2, const ECC_Point *pt)
{
    if (BN_IsZero(k1) && BN_IsZero(k2)) {
        // When k1 and k2 are both 0, the result is infinity.
        (void)BN_Zeroize(&r->z);
        return CRYPT_SUCCESS;
    }
    if (BN_IsZero(k1)) {
        return ECP_PointMulFast(para, r, k2, pt);
    }
    // k2 is 0
    return ECP_PointMulFast(para, r, k1, NULL);
}

// wNaf NotConstTime
int32_t ECP_PointMulAdd(ECC_Para *para, ECC_Point *r, const BN_BigNum *k1,
    const BN_BigNum *k2, const ECC_Point *pt)
{
    int32_t ret = ECP_PointMulAddParaCheck(para, r, k1, k2, pt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (BN_IsZero(k1) || BN_IsZero(k2)) {
        return KZeroHandle(para, r, k1, k2, pt);
    }
    MulAddOffData offData = { 0 };
    ECC_Point *windowsP[WINDOW_TABLE_SIZE] = { 0 };
    ECC_Point **windowsG = NULL;
    GOTO_ERR_IF(ECP_ParaPrecompute(para), ret);
    GOTO_ERR_IF(ECP_PointPreCompute(para, windowsP, pt), ret);
    windowsG = para->tableG;
    offData.codeK1 = ECC_ReCodeK(k1, PRE_COMPUTE_WINDOW);
    offData.codeK2 = ECC_ReCodeK(k2, PRE_COMPUTE_WINDOW);
    if (offData.codeK1 == NULL || offData.codeK2 == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // Obtain the initial point data.
    GOTO_ERR_IF(GetFirstData(para, r, &offData, windowsP), ret);

    while (offData.baseBits != 0) {
        // Slide window
        offData.bit1 = (offData.bit1 == 0) ? (offData.codeK1->wide[offData.offsetK1 - 1]) : (offData.bit1);
        offData.bit2 = (offData.bit2 == 0) ? (offData.codeK2->wide[offData.offsetK2 - 1]) : (offData.bit2);
        offData.bit = (offData.bit1 < offData.bit2) ? (offData.bit1) : (offData.bit2);
        GOTO_ERR_IF(para->method->pointMultDouble(para, r, r, offData.bit), ret);
        if (offData.bit == offData.bit1 && offData.offsetK1 < offData.codeK1->size) {
            int8_t offset = NUMTOOFFSET(offData.codeK1->num[offData.offsetK1]);
            GOTO_ERR_IF(para->method->pointAdd(para, r, r, windowsG[offset]), ret);
            offData.offsetK1++;
        }
        if (offData.bit == offData.bit2 && offData.offsetK2 < offData.codeK2->size) {
            int8_t offset = NUMTOOFFSET(offData.codeK2->num[offData.offsetK2]);
            GOTO_ERR_IF(para->method->pointAdd(para, r, r, windowsP[offset]), ret);
            offData.offsetK2++;
        }
        offData.bit1 -= offData.bit;
        offData.bit2 -= offData.bit;
        offData.baseBits -= offData.bit;
    }
    ECC_PointFromMont(para, r);
ERR:
    for (uint32_t i = 0; i < WINDOW_TABLE_SIZE; i++) {
        // Clear the pre-computation table.
        ECC_FreePoint(windowsP[i]);
    }
    ECC_ReCodeFree(offData.codeK1);
    ECC_ReCodeFree(offData.codeK2);
    return ret;
}

static int32_t PointParaCheck(const ECC_Para *para, const ECC_Point *pt, int32_t format)
{
    int32_t ret = ECP_PointAtInfinity(para, pt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (format < CRYPT_POINT_COMPRESSED || format > CRYPT_POINT_HYBRID) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_ERR_POINT_FORMAT);
        return CRYPT_ECC_ERR_POINT_FORMAT;
    }
    return CRYPT_SUCCESS;
}

int32_t ECP_GetEncodeDataLen(const ECC_Para *para, ECC_Point *pt, CRYPT_PKEY_PointFormat format, uint32_t *dataLen)
{
    int32_t ret = PointParaCheck(para, pt, format);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (dataLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint32_t curveBytes = BN_Bytes(para->p);
    uint32_t needBytes = (format == CRYPT_POINT_COMPRESSED) ? (curveBytes + 1) : ((curveBytes << 1) + 1);
    *dataLen = needBytes;
    return CRYPT_SUCCESS;
}

static int32_t EncodePointParaCheck(const ECC_Para *para, const ECC_Point *pt, const uint8_t *data,
    const uint32_t *dataLen, CRYPT_PKEY_PointFormat format)
{
    int32_t ret = PointParaCheck(para, pt, format);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (data == NULL || dataLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint32_t curveBytes = BN_Bytes(para->p);
    // Obtain the required buff length based on the compression format.
    uint32_t needBytes = (format == CRYPT_POINT_COMPRESSED) ? (curveBytes + 1) : ((curveBytes << 1) + 1);
    if (needBytes > *dataLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_ECC_BUFF_LEN_NOT_ENOUGH;
    }
    return CRYPT_SUCCESS;
}

// Currently, only prime number curves are supported. Other curves need to be expanded.
int32_t ECC_EncodePoint(const ECC_Para *para, ECC_Point *pt, uint8_t *data, uint32_t *dataLen,
    CRYPT_PKEY_PointFormat format)
{
    int32_t ret;
    bool z = false;
    uint32_t bytes, off, lastLen, i, curveBytes;
    GOTO_ERR_IF(EncodePointParaCheck(para, pt, data, dataLen, format), ret);
    // Convert the point to affine.
    GOTO_ERR_IF(para->method->point2Affine(para, pt, pt), ret);
    z = BN_GetBit(&pt->y, 0);
    bytes = BN_Bytes(&pt->x);
    curveBytes = BN_Bytes(para->p);
    off = curveBytes - bytes;
    for (i = 0; i < off; i++) {
        // Padded 0s to the most significant bits.
        data[i + 1] = 0;
    }
    lastLen = *dataLen - off - 1;
    GOTO_ERR_IF(BN_Bn2Bin(&pt->x, &data[off + 1], &lastLen), ret);
    /**
     * ANS X9.62–2005 A.5.5
     * If the compressed form is used PC is either 02 or 03.
     * If the uncompressed form is used Verify that PC is 04.
     * If the hybrid form is used Verify that PC is either 06 or 07
    */
    if (format == CRYPT_POINT_COMPRESSED) {
        // Set the bit zP to be equal to 0 if PC = 02, or 1 if PC = 03.
        data[0] = z ? 0x03 : 0x02;
        *dataLen = curveBytes + 1;
        return CRYPT_SUCCESS;
    } else if (format == CRYPT_POINT_UNCOMPRESSED) {
        data[0] = 0x04;
    } else if (format == CRYPT_POINT_HYBRID) {
        // Set the bit zP to be equal to 0 if PC = 06, or 1 if PC = 07.
        data[0] = z ? 0x07 : 0x06;
    }
    bytes = BN_Bytes(&pt->y);
    off = curveBytes - bytes;
    for (i = 0; i < off; i++) {
        // Padded 0s to the most significant bits.
        data[i + curveBytes + 1] = 0;
    }
    lastLen = *dataLen - off - curveBytes - 1;
    GOTO_ERR_IF(BN_Bn2Bin(&pt->y, &data[off + curveBytes + 1], &lastLen), ret);
    *dataLen = (curveBytes << 1) + 1;
ERR:
    return ret;
}

// Calculate the y coordinate based on the x coordinate.
// Currently, only the y^2 = x^3 + a*x + b curve equation can be solved.
static int32_t GetYData(const ECC_Para *para, ECC_Point *pt, bool pcBit)
{
    uint32_t bits = BN_Bits(para->p);
    BN_BigNum *t1 = BN_Create(bits);
    BN_BigNum *t2 = BN_Create(bits);
    BN_BigNum *dupA = BN_Dup(para->a);
    BN_BigNum *dupB = BN_Dup(para->b);
    BN_Optimizer *opt = BN_OptimizerCreate();
    int32_t ret;
    if (t1 == NULL || t2 == NULL || opt == NULL || dupA == NULL || dupB == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (para->method->bnMontDec != NULL) {
        para->method->bnMontDec(dupA, para->montP);
        para->method->bnMontDec(dupB, para->montP);
    }
    BN_OptimizerSetLibCtx(para->libCtx, opt);
    GOTO_ERR_IF(BN_ModSqr(t1, &pt->x, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModMul(t1, t1, &pt->x, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModMul(t2, dupA, &pt->x, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModAdd(t1, t1, t2, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModAdd(t1, t1, dupB, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModSqrt(&pt->y, t1, para->p, opt), ret);

    if (BN_GetBit(&pt->y, 0) != pcBit) { // if parity is inconsistent, y = -y
        GOTO_ERR_IF(BN_ModSub(&pt->y, para->p, &pt->y, para->p, opt), ret);
    }
ERR:
    BN_Destroy(t1);
    BN_Destroy(t2);
    BN_Destroy(dupA);
    BN_Destroy(dupB);
    BN_OptimizerDestroy(opt);
    return ret;
}

// Check whether the parsed data is valid during point decoding and provide compression information.
static int32_t GetFormatAndCheckLen(const uint8_t *data, uint32_t dataLen, CRYPT_PKEY_PointFormat *format,
    uint32_t curveBytes)
{
    if (dataLen < curveBytes + 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_ERR_POINT_CODE);
        return CRYPT_ECC_ERR_POINT_CODE;
    }
    uint8_t pc = data[0];
    /**
     * ANS X9.62–2005 A.5.5
     * If the compressed form is used PC is either 02 or 03.
     * If the uncompressed form is used Verify that PC is 04.
     * If the hybrid form is used Verify that PC is either 06 or 07
    */
    if (pc == 0x04) {
        // uncompressed
        if (dataLen != (curveBytes << 1) + 1) {
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_ERR_POINT_CODE);
            return CRYPT_ECC_ERR_POINT_CODE;
        }
        *format = CRYPT_POINT_UNCOMPRESSED;
        return CRYPT_SUCCESS;
    } else if (pc == 0x02 || pc == 0x03) {
        // compressed
        if (dataLen != curveBytes + 1) {
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_ERR_POINT_CODE);
            return CRYPT_ECC_ERR_POINT_CODE;
        }
        *format = CRYPT_POINT_COMPRESSED;
        return CRYPT_SUCCESS;
    } else if (pc == 0x06 || pc == 0x07) {
        // hybriid
        if (dataLen != (curveBytes << 1) + 1) {
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_ERR_POINT_CODE);
            return CRYPT_ECC_ERR_POINT_CODE;
        }
        *format = CRYPT_POINT_HYBRID;
        return CRYPT_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(CRYPT_ECC_ERR_POINT_CODE);
    return CRYPT_ECC_ERR_POINT_CODE;
}

// Currently, only prime number curves are supported. Other curves need to be expanded.
int32_t ECC_DecodePoint(const ECC_Para *para, ECC_Point *pt, const uint8_t *data, uint32_t dataLen)
{
    if (para == NULL || pt == NULL || data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != pt->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    int32_t ret;
    uint32_t curveBytes = BN_Bytes(para->p);
    CRYPT_PKEY_PointFormat format = CRYPT_POINT_UNCOMPRESSED;
    bool pcBit = ((data[0] & 0x01) == 1); // Parity check. If it's odd, return true. If it's even, return false.
    GOTO_ERR_IF(GetFormatAndCheckLen(data, dataLen, &format, curveBytes), ret);

    GOTO_ERR_IF(BN_SetLimb(&pt->z, 1), ret);
    if (format == CRYPT_POINT_COMPRESSED) {
        GOTO_ERR_IF(BN_Bin2Bn(&pt->x, &data[1], curveBytes), ret);
        // The y-coordinate information is obtained through calculation.
        GOTO_ERR_IF(GetYData(para, pt, pcBit), ret);
    } else if (format == CRYPT_POINT_UNCOMPRESSED) {
        GOTO_ERR_IF(BN_Bin2Bn(&pt->x, &data[1], curveBytes), ret);
        GOTO_ERR_IF(BN_Bin2Bn(&pt->y, &data[1 + curveBytes], curveBytes), ret);
    } else if (format == CRYPT_POINT_HYBRID) {
        GOTO_ERR_IF(BN_Bin2Bn(&pt->x, &data[1], curveBytes), ret);
        GOTO_ERR_IF(BN_Bin2Bn(&pt->y, &data[1 + curveBytes], curveBytes), ret);
        // The parity information on the coded information is inconsistent.
        if (BN_GetBit(&pt->y, 0) != pcBit) {
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_ERR_POINT_CODE);
            ret = CRYPT_ECC_ERR_POINT_CODE;
            goto ERR;
        }
    }
    // Check whether the value on the point exceeds the modulus field.
    if ((BN_Cmp(para->p, &pt->y) <= 0) || (BN_Cmp(para->p, &pt->x) <= 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_NOT_ON_CURVE);
        ret = CRYPT_ECC_POINT_NOT_ON_CURVE;
        goto ERR;
    }
    if (format != CRYPT_POINT_COMPRESSED) {
        // Check whether the point is on the curve.
        GOTO_ERR_IF(ECP_PointOnCurve(para, pt), ret);
    }
    return ret;
ERR:
    // Ensure that pt is not NULL. Therefore, pt->z is not NULL. This invoking does not fail.
    (void)BN_Zeroize(&pt->z);
    return ret;
}
#endif /* HITLS_CRYPTO_ECC */

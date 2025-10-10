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

#ifndef ECC_LOCAL_H
#define ECC_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ECC

#include "crypt_ecc.h"
#include "crypt_bn.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ECC_MAX_BIT_LEN 521

#define PRE_COMPUTE_WINDOW 5 // Default Window Size
#define PRE_COMPUTE_MAX_TABLELEN (1 << 5) // Maximum specifications of the pre-calculation table

/**
 * Elliptic Curve Implementation Method
 */
typedef struct {
    // Calculate  r = k1 * G + k2 * pt
    int32_t (*pointMulAdd)(ECC_Para *para, ECC_Point *r, const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt);
    // Calculate r = k * pt. If pt is null, calculate r = k * G. This is the ConstTime processing function.
    int32_t (*pointMul)(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt);
    // Calculate r = k * pt. If pt is null, calculate r = k * G
    int32_t (*pointMulFast)(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt);
    // point addition r = a + b, a all can be the jacobi coordinate, b must be an affine point
    int32_t (*pointAddAffine)(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b);
    // point addition r = a + b, a, b all can be the jacobi coordinate.
    int32_t (*pointAdd)(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b);
    // point double r = a + a, a can be the jacobi coordinate.
    int32_t (*pointDouble)(const ECC_Para *para, ECC_Point *r, const ECC_Point *a);
    // point Multi-double Calculate r = (2^m)*a, a can be the jacobi coordinate.
    int32_t (*pointMultDouble)(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, uint32_t m);
    // Module inverse
    int32_t (*modInv)(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *p, BN_Optimizer *opt);
    // Convert points to affine coordinates based on the given module inverse information.
    int32_t (*point2AffineWithInv)(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const BN_BigNum *inv);
    // Convert the point information to affine coordinates.
    int32_t (*point2Affine)(const ECC_Para *para, ECC_Point *r, const ECC_Point *a);
    // Calculate r = (a*b) % mod
    int32_t (*bnModNistEccMul)(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
        void *mod, BN_Optimizer *opt);
    // Calculate r = (a^2) % mod
    int32_t (*bnModNistEccSqr)(BN_BigNum *r, const BN_BigNum *a, void *mod, BN_Optimizer *opt);
    // Inverse mode order.
    int32_t (*modOrdInv)(const ECC_Para *para, BN_BigNum *r, const BN_BigNum *a);
    // convert date to Montgomery form
    int32_t (*bnMontEnc)(BN_BigNum *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime);
    // convert Montgomery form to common form
    void (*bnMontDec)(BN_BigNum *r, BN_Mont *mont);
} ECC_Method;

/**
 * Elliptic Curve Point Information
 */
struct EccPointInfo {
    BN_BigNum x;
    BN_BigNum y;
    BN_BigNum z;
    CRYPT_PKEY_ParaId id;
};

/**
 * Elliptic curve parameter information
 */
struct EccPara {
    BN_BigNum *p;
    BN_BigNum *a;
    BN_BigNum *b;
    BN_BigNum *n;
    BN_BigNum *h;
    BN_BigNum *x;
    BN_BigNum *y;
    // Currently, the 5-bit window is used. Only odd multiple points are calculated.
    // The total number of pre-calculated data is (2 ^ 5)/2, that is 16 points.
    ECC_Point *tableG[16];
    const ECC_Method *method;
    CRYPT_PKEY_ParaId id;
	BN_Mont *montP;
    void *libCtx;
};

/**
 * @ingroup ecc
 * @brief   Check whether the checkpoint is at infinity.
 *
 * @param   para [IN] Curve parameters
 * @param   pt [IN] Point information
 *
 * @retval CRYPT_SUCCESS    succeeded, indicating that the point is not at infinity.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_PointAtInfinity(const ECC_Para *para, const ECC_Point *pt);

/**
 * @ingroup ecc
 * @brief   Check whether the point is on the curve.
 * The determined point must be on the Cartesian coordinate, which is used to check the validity of the point input.
 *
 * @param   para [IN] Curve parameters
 * @param   pt [IN] Point information
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_PointOnCurve(const ECC_Para *para, const ECC_Point *pt);

/**
 * @ingroup ecc
 * @brief   Add salt to the pt point and add random z information.
 *
 * @param   para [IN] Curve parameters
 * @param   pt [IN/OUT] Point information
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_PointBlind(const ECC_Para *para, ECC_Point *pt);

/**
 * @ingroup ecc
 * @brief   Convert the point information pt to the affine coordinate system and synchronize the data to r.
 *
 * @param   para [IN] Curve parameters
 * @param   r [OUT] Output point information
 * @param   pt [IN] Input point information
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *pt);

/**
 * @ingroup ecc
 * @brief   Converts all point information on pt to affine coordinate system,
 *          which is used for the coordinate system conversion of the pre-computation table.
 *
 * @attention pt[0] cannot be an infinite point.
 *
 * @param   para [IN] Curve parameters
 * @param   pt [IN/OUT] Point information
 * @param   ptNums [IN] Number of pts
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_Points2Affine(const ECC_Para *para, ECC_Point *pt[], uint32_t ptNums);

/**
 * @ingroup ecc
 * @brief   Calculated r = -a
 *
 * @attention point a must be a point in the Cartesian coordinate system
 *
 * @param   para [IN] Curve parameters
 * @param   r [OUT] Output point information
 * @param   pt [IN] Input point information
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_PointInvertAtAffine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a);

/**
 * @ingroup ecc
 * @brief   Convert the point information pt to the affine coordinate system and refresh the data to r.
 *          The inverse information of z is provided by the user.
 *
 * @attention The validity of inv is guaranteed by the user.
 *
 * @param   para [IN] Curve parameters
 * @param   r [OUT] Output point information
 * @param   pt [IN] Input point information
 * @param   inv [IN] inverse information of z
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_Point2AffineWithInv(
    const ECC_Para *para, ECC_Point *r, const ECC_Point *pt, const BN_BigNum *inv);

/**
 * @ingroup ecc
 * @brief   Calculate r = k1 * G + k2 * pt
 *
 * @param   para [IN] Curve parameters
 * @param   r [OUT] Output point information
 * @param   k1 [IN] Scalar 1
 * @param   k2 [IN] Scalar 2
 * @param   pt [IN] Point data
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_PointMulAdd(
    ECC_Para *para, ECC_Point *r, const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt);

/**
 * @ingroup ecc
 * @brief   Calculate r = k * pt. When pt is NULL, calculate r = k * G
 *          The pre-computation table under para will be updated.
 *
 * @param   para [IN] Curve parameter information
 * @param   r [OUT] Output point information
 * @param   k [IN] Scalar
 * @param   pt [IN] Point data, which can be set to NULL
 *
 * @retval CRYPT_SUCCESS    set successfully
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_PointMul(ECC_Para *para,  ECC_Point *r,
    const BN_BigNum *k, const ECC_Point *pt);

/**
 * @ingroup ecc
 * @brief   Calculate r = k * pt. When pt is NULL, calculate r = k * G
 *          The pre-computation table under para will be updated.
 *          Non-consttime calculation
 *
 * @param   para [IN] Curve parameter information
 * @param   r [OUT] Output point information
 * @param   k [IN] Scalar
 * @param   pt [IN] Point data, which can be set to NULL
 *
 * @retval CRYPT_SUCCESS    set successfully
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_PointMulFast(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt);

/**
 * @ingroup ecc
 * @brief   Obtaining a prime number curve (p + 1)/2
 *
 * @param   p [IN] Input module
 *
 * @retval non-NULL   succeeded.
 * @retval NULL       failed
 */
BN_BigNum *ECP_HalfPGet(const BN_BigNum *p);

/**
 * @ingroup ecc
 * @brief   Search implementation method by curve ID
 *
 * @param   id [IN] Curve enumeration
 *
 * @retval non-NULL   succeeded.
 * @retval NULL       failed
 */
const ECC_Method *ECC_FindMethod(CRYPT_PKEY_ParaId id);

/**
 * @ingroup ecc
 * @brief   nist Calculation of multiplication(double) of points of prime curve: r = a + a
 *
 * @param   para [IN] Curve parameters
 * @param   r [OUT] Output point information
 * @param   a [IN] Input point information
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_NistPointDouble(const ECC_Para *para, ECC_Point *r, const ECC_Point *a);

/**
 * @ingroup ecc
 * @brief   nist Calculation of multi-double of points of prime curve: r = (2^m)*a
 *
 * @param   para [IN] Curve parameters
 * @param   r [OUT] Output point information
 * @param   a [IN] Input point information
 * @param   m [IN] Exponential information of point multiplication scalar
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_NistPointMultDouble(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, uint32_t m);

/**
 * @ingroup ecc
 * @brief   nist Calculation of multiplication(double) of points of prime curve: r = a + b
 *
 * @param   para [IN] Curve parameters
 * @param   r [OUT] Output point information
 * @param   a [IN] Input point information, a can be the jacobi coordinate.
 * @param   b [IN] Input point information, b must be the affine coordinate.
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_NistPointAddAffine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b);

/**
 * @ingroup ecc
 * @brief   nist Calculation of multiplication(double) of points of prime curve: r = a + b
 *
 * @param   para [IN] Curve parameters
 * @param   r [OUT] Output point information
 * @param   a [IN] Input point information, a can be the jacobi coordinate.
 * @param   b [IN] Input point information, b can be the jacobi coordinate.
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_NistPointAdd(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b);

/**
 * @brief   Calculate r = 1/a mod para->n
 *
 * @param   para [IN] Curve parameter information
 * @param   r [OUT] Output modulus inverse value
 * @param   a [IN] BigNum that needs to be inverted.
 *
 * @retval CRYPT_SUCCESS    set successfully
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_ModOrderInv(const ECC_Para *para, BN_BigNum *r, const BN_BigNum *a);

#ifdef HITLS_CRYPTO_CURVE_MONT

/**
 * The nist curve is based on Montgomery's calculation of double points.
 * r = a + a
 */
int32_t ECP_NistPointDoubleMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a);

/**
 * The nist curve is based on Montgomery's calculation of multi-double points.
 * r = m * (a + a)
 */
int32_t ECP_NistPointMultDoubleMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, uint32_t m);

/**
 * The nist curve is based on Montgomery's calculation of add points.
 * r = a + b, b must be an affine point.
 */
int32_t ECP_NistPointAddAffineMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b);

/**
 * The nist curve is based on Montgomery's calculation of add points.
 * r = a + b
 */
int32_t ECP_NistPointAddMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b);

/**
 * The nist curve is based on Montgomery's calculation of turn an point to an affine point.
 * r = a -> affine a
 */
int32_t ECP_Point2AffineMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *pt);

/**
 * The nist curve is based on Montgomery's calculation of turn an point to an affine point.
 * r = a -> affine a
 */
int32_t ECP_PrimePointDoubleMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a);

/**
 * The prime curve is based on Montgomery's calculation of multi-double points.
 * r = m * (a + a)
 */
int32_t ECP_PrimePointMultDoubleMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, uint32_t m);

/**
 * The prime curve is based on Montgomery's calculation of add points.
 * r = a + b, b must be an affine point.
 */
int32_t ECP_PrimePointAddAffineMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b);

/**
 * The prime curve is based on Montgomery's calculation of add points.
 * r = a + b
 */
int32_t ECP_PrimePointAddMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b);

/**
 * The prime curve is based on Montgomery's calculation of  k * pt.
 * The implementation is based on the Montgomery ladder.
 */
int32_t ECP_PointMulMont(ECC_Para *para,  ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt);

#endif // HITLS_CRYPTO_CURVE_MONT

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_ECC

#endif // ECC_LOCAL_H

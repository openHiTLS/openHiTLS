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

#ifndef ECP_SM2_H
#define ECP_SM2_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CURVE_SM2

#include "crypt_ecc.h"
#include "crypt_bn.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup sm2
 * @brief   Calculate r = k * pt. When pt is NULL, calculate r = k * G
 *
 * @param   para [IN] Curve parameter information
 * @param   r [OUT] Output point information
 * @param   k [IN] Scalar
 * @param   pt [IN] Point data, which can be set to NULL.
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_Sm2PointMul(ECC_Para *para, ECC_Point *r, const BN_BigNum *scalar, const ECC_Point *pt);

/**
 * @ingroup sm2
 * @brief   Calculate r = a + b, where a is the Jacobian coordinate system and b is the affine coordinate system.
 *
 * @param   para [IN] Curve parameter information
 * @param   r [OUT] Output point information
 * @param   a,b [IN] Point data
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_Sm2PointAddAffine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b);

/**
 * @ingroup sm2
 * @brief   Calculate r = 2*a, where a is the Jacobian coordinate system.
 *
 * @param   para [IN] Curve parameter information
 * @param   r [OUT] Output point information
 * @param   a [IN] Point data
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_Sm2PointDouble(const ECC_Para *para, ECC_Point *r, const ECC_Point *a);

/**
 * @ingroup sm2
 * @brief   Convert the point information pt to the affine coordinate system and refresh the data to r.
 *
 * @param   para [IN] Curve parameters
 * @param   r [OUT] Output point information
 * @param   a [IN] Input point information
 *
 * @retval CRYPT_SUCCESS    succeeded
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_Sm2Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a);

/**
 * @ingroup sm2
 * @brief   Calculate r = k * pt,
 *          Non-consttime calculation
 *
 * @param   para [IN] Curve parameter information
 * @param   r [OUT] Output point information
 * @param   k [IN] Scalar
 * @param   pt [IN] Point data, which can be set to NULL.
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECP_Sm2PointMulFast(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt);

int32_t ECP_Sm2OrderInv(const ECC_Para *para, BN_BigNum *r, const BN_BigNum *a);

int32_t ECP_Sm2PointMulAdd(ECC_Para *para, ECC_Point *r, const BN_BigNum *k1, const BN_BigNum *k2,
    const ECC_Point *pt);

#ifdef __cplusplus
}
#endif

#endif
#endif
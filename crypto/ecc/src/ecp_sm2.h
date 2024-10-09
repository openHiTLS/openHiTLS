/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef ECP_SM2_H
#define ECP_SM2_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_ECC) && defined(HITLS_CRYPTO_SM2)

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
int32_t ECP_Sm2PointAdd(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b);

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

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM2

#endif // ECP_SM2_H

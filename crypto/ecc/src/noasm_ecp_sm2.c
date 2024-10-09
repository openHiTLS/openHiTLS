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
#if defined(HITLS_CRYPTO_ECC) && defined(HITLS_CRYPTO_SM2)

#include "ecp_sm2.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "ecc_local.h"

int32_t ECP_Sm2PointDouble(const ECC_Para *para, ECC_Point *r, const ECC_Point *a)
{
    return ECP_NistPointDouble(para, r, a);
}

int32_t ECP_Sm2PointAdd(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b)
{
    return ECP_NistPointAdd(para, r, a, b);
}

int32_t ECP_Sm2PointMul(ECC_Para *para, ECC_Point *r, const BN_BigNum *scalar, const ECC_Point *pt)
{
    return ECP_PointMul(para, r, scalar, pt);
}

int32_t ECP_Sm2Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a)
{
    if (para == NULL || r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != CRYPT_ECC_SM2 || r->id != CRYPT_ECC_SM2 || a->id != CRYPT_ECC_SM2) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    return ECP_Point2Affine(para, r, a);
}
#endif

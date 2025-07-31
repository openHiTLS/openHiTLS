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

#ifndef CRYPT_ECC_H
#define CRYPT_ECC_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ECC

#include "crypt_bn.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Elliptic Curve Point Information
 */
typedef struct EccPointInfo ECC_Point;

/**
 * Elliptic Curve Parameter Information
 */
typedef struct EccPara ECC_Para;

/**
 * Point information of elliptic curve scalar after recoding
 */
typedef struct {
    int8_t *num;
    uint32_t *wide;
    uint32_t size;
    uint32_t baseBits; // Indicates the offset start address of the first block.
    uint32_t offset;
} ReCodeData;

/**
 * @ingroup ecc
 * @brief Creating curve parameters
 *
 * @param id [IN] Curve enumeration
 *
 * @retval Not NULL Success
 * @retval NULL     failure
 */
ECC_Para *ECC_NewPara(CRYPT_PKEY_ParaId id);

/**
 * @ingroup ecc
 * @brief Curve parameter release
 *
 * @param para [IN] Curve parameter information. The para is set NULL by the invoker.
 *
 * @retval None
 */
void ECC_FreePara(ECC_Para *para);

/**
 * @ingroup ecc
 * @brief Read the curve parameter ID.
 *
 * @param para [IN] Curve parameter information
 *
 * @retval Curve ID
 */
CRYPT_PKEY_ParaId ECC_GetParaId(const ECC_Para *para);

/**
 * @ingroup ecc
 * @brief Obtain the curve parameter ID based on the curve parameter information.
 *
 * @param eccpara [IN] Curve parameter information
 *
 * @retval Curve ID
 */
CRYPT_PKEY_ParaId GetCurveId(const CRYPT_EccPara *eccPara);

/**
 * @ingroup ecc
 * @brief Point creation
 *
 * @param para [IN] Curve parameter information
 *
 * @retval Not NULL Success
 * @retval NULL     failure
 */
ECC_Point *ECC_NewPoint(const ECC_Para *para);

/**
 * @ingroup ecc
 * @brief Point Release
 *
 * @param pt [IN] Point data, pt is set to null by the invoker.
 *
 * @retval none
 */
void ECC_FreePoint(ECC_Point *pt);

/**
 * @ingroup ecc
 * @brief Point copy
 *
 * @param dst [OUT] The copied point information
 * @param src [IN] Input
 *
 * @retval Not NULL Success
 * @retval NULL     failure
 */
int32_t ECC_CopyPoint(ECC_Point *dst, const ECC_Point *src);

/**
 * @ingroup ecc
 * @brief Generate a point data with the same content.
 *
 * @param pt [IN] Input point information
 *
 * @retval Not NULL Success
 * @retval NULL     failure
 */
ECC_Point *ECC_DupPoint(const ECC_Point *pt);

/**
 * @ingroup ecc
 * @brief Check if a and b are the same point
 *
 * @param para [IN] Curve parameter information
 * @param a [IN] Point a in Jacobian coordinate
 * @param b [IN] Point b in Jacobian coordinate
 *
 * @retval CRYPT_SUCCESS             The two points are the same.
 * @retval CRYPT_ECC_POINT_NOT_EQUAL The two points are different.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_PointCmp(const ECC_Para *para, const ECC_Point *a, const ECC_Point *b);

/**
 * @ingroup ecc
 * @brief Convert the Jacobian coordinate point (x, y, z) to affine coordinate (x/z^2, y/z^3, 1) and get coordinates.
 *
 * @param para [IN] Curve parameter information
 * @param pt [IN/OUT] Point (x, y, z) -> (x/z^2, y/z^3, 1)
 * @param x [OUT] x/z^2
 * @param y [OUT] y/z^3
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_GetPoint(const ECC_Para *para, ECC_Point *pt, CRYPT_Data *x, CRYPT_Data *y);

/**
 * @ingroup ecc
 * @brief Convert the Jacobian coordinate point (x, y, z) to affine coordinate (x/z^2, y/z^3, 1) and get coordinats.
 *
 * @param para [IN] Curve parameter information
 * @param pt [IN/OUT] Point (x, y, z) -> (x/z^2, y/z^3, 1)
 * @param x [OUT] x/z^2
 * @param y [OUT] y/z^3
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_GetPoint2Bn(const ECC_Para *para, ECC_Point *pt, BN_BigNum *x, BN_BigNum *y);

/**
 * @ingroup ecc
 * @brief Convert the Jacobian coordinate point (x, y, z) to affine coordinate (x/z^2, y/z^3, 1) and get x/z^2
 *
 * @param para [IN] Curve parameter information
 * @param pt [IN/OUT] Point (x, y, z) -> (x/z^2, y/z^3, 1)
 * @param x [OUT] x/z^2
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_GetPointDataX(const ECC_Para *para, ECC_Point *pt, BN_BigNum *x);

/**
 * @ingroup ecc
 * @brief Calculate r = k * pt. When pt is NULL, calculate r = k * G, where G is the generator
 * The pre-computation table under the para parameter will be updated.
 *
 * @param para [IN] Curve parameter information
 * @param r [OUT] Scalar multiplication
 * @param k [IN] Scalar
 * @param pt [IN] Point data, which can be NULL.
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_PointMul(ECC_Para *para,  ECC_Point *r,
    const BN_BigNum *k, const ECC_Point *pt);

/**
 * @ingroup ecc
 * @brief Calculate r = k1 * G + k2 * pt, where G is the generator.
 *
 * @param para [IN] Curve parameter information
 * @param r [OUT] Point k1 * G + k2 * pt
 * @param k1 [IN] Scalar k1
 * @param k2 [IN] Scalar k2
 * @param pt [IN] Point pt
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_PointMulAdd(ECC_Para *para,  ECC_Point *r,
    const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt);

/**
 * @ingroup ecc
 * @brief Convert the Jacobian coordinate point (x, y, z) to affine coordinate (x/z^2, y/z^3, 1) and encode point.
 *
 * @param para [IN] Curve parameter information
 * @param pt [IN/OUT] Point (x, y, z) -> (x/z^2, y/z^3, 1)
 * @param data [OUT] Data stream
 * @param dataLen [IN/OUT] The input is the buff length of data and the output is the valid length of data.
 * @param format [IN] Encoding format
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_EncodePoint(const ECC_Para *para, ECC_Point *pt, uint8_t *data, uint32_t *dataLen,
    CRYPT_PKEY_PointFormat format);

/**
 * @ingroup ecc
 * @brief Encode the data stream into point information.
 *
 * @param para [IN] Curve parameter information
 * @param pt [OUT] Point in affine coordinate(z=1)
 * @param data [IN] Data stream
 * @param dataLen [IN] Data stream length
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_DecodePoint(const ECC_Para *para, ECC_Point *pt, const uint8_t *data, uint32_t dataLen);

/**
 * @ingroup ecc
 * @brief Obtain the parameter value h based on the curve parameter.
 *
 * @param para [IN] Curve parameter information
 *
 * @retval Not NULL Success
 * @retval NULL     failure
 */
BN_BigNum *ECC_GetParaH(const ECC_Para *para);

/**
 * @ingroup ecc
 * @brief Obtain the parameter value n based on the curve parameter.
 *
 * @param para [IN] Curve parameter information
 *
 * @retval Not NULL Success
 * @retval NULL     failure
 */
BN_BigNum *ECC_GetParaN(const ECC_Para *para);

/**
 * @ingroup ecc
 * @brief Obtain the coefficient a based on curve parameters.
 *
 * @param para [IN] Curve parameter information
 *
 * @retval Not NULL Success
 * @retval NULL     failure
 */
BN_BigNum *ECC_GetParaA(const ECC_Para *para);

/**
 * @ingroup ecc
 * @brief Obtain the coefficient b based on curve parameters.
 *
 * @param para [IN] Curve parameter information
 *
 * @retval Not NULL Success
 * @retval NULL     failure
 */
BN_BigNum *ECC_GetParaB(const ECC_Para *para);

/**
 * @ingroup ecc
 * @brief Obtain the coordinate x of the base point G based on curve parameters.
 *
 * @param para [IN] Curve parameter information
 *
 * @retval Not NULL Success
 * @retval NULL     failure
 */
BN_BigNum *ECC_GetParaX(const ECC_Para *para);

/**
 * @ingroup ecc
 * @brief Obtain the coordinate y of the base point G based on curve parameters.
 *
 * @param para [IN] Curve parameter information
 *
 * @retval Not NULL Success
 * @retval NULL     failure
 */
BN_BigNum *ECC_GetParaY(const ECC_Para *para);

/**
 * @ingroup ecc
 * @brief Obtain bit length of parameter p based on the curve parameter.
 *
 * @param para [IN] Curve parameter information
 *
 * @retval Return the specification unit of the curve parameter is bits. 0 is returned when an error occurs.
 */
uint32_t ECC_ParaBits(const ECC_Para *para);

/**
 * @ingroup ecc
 * @brief Generate a curve parameter with the same content.
 *
 * @param para [IN] Curve parameter information
 *
 * @retval Not NULL Success
 * @retval NULL     failure
 */
ECC_Para *ECC_DupPara(const ECC_Para *para);

/**
 * @ingroup ecc
 * @brief Check whether the point is valid.
 *
 * @param pt [IN] Point information
 *
 * @retval CRYPT_SUCCESS                This point is valid.
 * @retval CRYPT_ECC_POINT_AT_INFINITY  The point is an infinite point (0 point).
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_PointCheck(const ECC_Point *pt);


/**
 * @ingroup ecc
 * @brief Obtain the generator(with z=1) based on curve parameters.
 *
 * @param para [IN] Curve parameters
 *
 * @retval Not NULL Success
 * @retval NULL     failure
 */
ECC_Point *ECC_GetGFromPara(const ECC_Para *para);

/**
 * @ingroup ecc
 * @brief Scalar re-encoding to obtain the encoded data whose window is the 'window'.
 *
 * @param k [IN] Curve parameters
 * @param window [IN] Window size
 *
 * @retval Not NULL Success
 * @retval NULL     failure
 */
ReCodeData *ECC_ReCodeK(const BN_BigNum *k, uint32_t window);

/**
 * @ingroup ecc
 * @brief Release the encoded data.
 *
 * @param code [IN/OUT] Data to be released. The code is set NULL by the invoker.
 *
 * @retval None
 */
void ECC_ReCodeFree(ReCodeData *code);

/**
 * @brief Calculate r = 1/a mod para->n
 *
 * @param para [IN] Curve parameter information
 * @param r [OUT] Output modulus inverse value
 * @param a [IN] Input BigNum that needs to be inverted.
 *
 * @retval CRYPT_SUCCESS    set successfully.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_ModOrderInv(const ECC_Para *para, BN_BigNum *r, const BN_BigNum *a);

/**
 * @ingroup ecc
 * @brief Calculate addition r = a + b
 *
 * @param para [IN] Curve parameter
 * @param r [OUT] Point r = a + b
 * @param a [IN] Point a
 * @param b [IN] Point b
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For other errors, see crypt_errno.h.
 */
int32_t ECC_PointAddAffine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b);

/**
 * @ingroup ecc
 * @brief ecc get security bits
 *
 * @param para [IN] ecc Context structure
 *
 * @retval security bits
 */
int32_t ECC_GetSecBits(const ECC_Para *para);

/**
 * @ingroup ecc
 * @brief   Randomize z for preventing attack.
 * Converting a point (x, y, z) -> (x/z0^2, y/z0^3, z*z0)
 * @param   para [IN] Curve parameters
 * @param   pt [IN/OUT] Point information
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECC_PointBlind(const ECC_Para *para, ECC_Point *pt);

/**
 * @ingroup ecc
 * @brief   convert ecc point to mont form
 * @param   para [IN] Curve parameters
 * @param   pt [IN/OUT] Point information
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
int32_t ECC_PointToMont(const ECC_Para *para, ECC_Point *pt, BN_Optimizer *opt);

/**
 * @ingroup ecc
 * @brief   recover ecc point from mont form
 * @param   para [IN] Curve parameters
 * @param   pt [IN/OUT] Point information
 *
 * @retval CRYPT_SUCCESS    succeeded.
 * @retval For details about other errors, see crypt_errno.h
 */
void ECC_PointFromMont(const ECC_Para *para, ECC_Point *r);

/**
 * @ingroup ecc
 * @brief   convert ecc point to mont form
 * @param   para [IN] Curve parameters
 * @param   pt [IN/OUT] Point information
 *
 * @param libCtx [IN] Pointer to the library context
 * @param para [OUT] Pointer to the elliptic curve parameters
 */
void ECC_SetLibCtx(void *libCtx, ECC_Para *para);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_ECC

#endif // CRYPT_ECC_H

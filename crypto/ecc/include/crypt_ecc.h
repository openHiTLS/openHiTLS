/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_ECC_H
#define CRYPT_ECC_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ECC

#include "crypt_bn.h"
#include "crypt_algid.h"
#include "crypt_types.h"

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
CRYPT_PKEY_ParaId ECC_GetCurveId(const CRYPT_EccPara *eccPara);

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
 * @brief Check whether a is consistent with b.
 *
 * @param para [IN] Curve parameter information
 * @param a [IN] Input point information
 * @param b [IN] Input point information
 *
 * @retval CRYPT_SUCCESS             The two points are the same.
 * @retval CRYPT_ECC_POINT_NOT_EQUAL The two points are different.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_PointCmp(const ECC_Para *para, const ECC_Point *a, const ECC_Point *b);

/**
 * @ingroup ecc
 * @brief Convert the point to the affine coordinate and obtain the x and y coordinates based on the point data.
 *
 * @param para [IN] Curve parameter information
 * @param pt [IN/OUT] Point information
 * @param x [OUT] Value of the coordinate x
 * @param y [OUT] Value of the coordinate y
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_GetPoint(const ECC_Para *para, ECC_Point *pt, CRYPT_Data *x, CRYPT_Data *y);

/**
 * @ingroup ecc
 * @brief Convert the point to the affine coordinate and obtain the BigNum x from the point data.
 *
 * @param para [IN] Curve parameter information
 * @param pt [IN/OUT] Point information
 * @param x [OUT] Value of the coordinate x
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_GetPointDataX(const ECC_Para *para, ECC_Point *pt, BN_BigNum *x);

/**
 * @ingroup ecc
 * @brief Calculate r = k * pt. When pt is NULL, calculate r = k * G.
 * The pre-computation table under the para parameter will be updated.
 *
 * @param para [IN] Curve parameter information
 * @param r [OUT] Output point information
 * @param k [IN] Scalar
 * @param pt [IN] Point data, which can be set to NULL.
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_PointMul(ECC_Para *para,  ECC_Point *r,
    const BN_BigNum *k, const ECC_Point *pt);

/**
 * @ingroup ecc
 * @brief Calculate r = k1 * G + k2 * pt
 *
 * @param para [IN] Curve parameter information
 * @param r [OUT] Output point information
 * @param k1 [IN] Scalar 1
 * @param k2 [IN] Scalar 2
 * @param pt [IN] Point data
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For details about other errors, see crypt_errno.h.
 */
int32_t ECC_PointMulAdd(ECC_Para *para,  ECC_Point *r,
    const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt);

/**
 * @ingroup ecc
 * @brief Convert the point to the affine coordinate and encode the point information as a data stream.
 *
 * @param para [IN] Curve parameter information
 * @param pt [IN/OUT] Point data
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
 * @param pt [OUT] Point data
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
 * @brief Obtain the specification based on the curve parameter, that is, the bit length of the parameter p.
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
 * @brief Obtain the generator based on curve parameters.
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
 * @brief Calculation of multiple points of prime curve r = a + b
 *
 * @param para [IN] Curve parameter
 * @param r [OUT] Output point information
 * @param a [IN] Input point information
 * @param b [IN] Input point information
 *
 * @retval CRYPT_SUCCESS succeeded.
 * @retval For other errors, see crypt_errno.h.
 */
int32_t ECC_PointAdd(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b);

/**
 * @ingroup ecc
 * @brief ecc get security bits
 *
 * @param para [IN] ecc Context structure
 *
 * @retval security bits
 */
int32_t ECC_GetSecBits(const ECC_Para *para);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_ECC

#endif // CRYPT_ECC_H

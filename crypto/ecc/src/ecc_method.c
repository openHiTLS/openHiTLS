/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ECC

#include "ecc_local.h"
#include "bsl_err_internal.h"
#include "ecp_sm2.h"

typedef struct {
    uint32_t id;
    const ECC_Method *ecMeth;
} ECC_MethodMap;

// general method implementation of NIST prime curve
static const ECC_Method EC_METHOD_NIST = {
    .pointMulAdd = ECP_PointMulAdd,
    .pointMul = ECP_PointMul,
    .pointMulFast = ECP_PointMulFast,
    .pointAdd = ECP_NistPointAdd,
    .pointDouble = ECP_NistPointDouble,
    .pointMultDouble = ECP_NistPointMultDouble,
    .modInv = BN_ModInv,
    .point2AffineWithInv = ECP_Point2AffineWithInv,
    .point2Affine = ECP_Point2Affine,
    .bnModNistEccMul = BN_ModNistEccMul,
    .bnModNistEccSqr = BN_ModNistEccSqr,
    .modOrdInv = ECP_ModOrderInv,
};

#ifdef HITLS_CRYPTO_SM2
// method implementation of SM2
static const ECC_Method EC_METHOD_SM2 = {
    .pointMulAdd = ECP_PointMulAdd,
    .pointMul = ECP_Sm2PointMul,
    .pointAdd = ECP_Sm2PointAdd,
    .pointDouble = ECP_Sm2PointDouble,
    .pointMultDouble = ECP_NistPointMultDouble,
    .modInv = BN_ModInv,
    .point2AffineWithInv = ECP_Point2AffineWithInv,
    .point2Affine = ECP_Sm2Point2Affine,
    .bnModNistEccMul = BN_ModSm2EccMul,
    .bnModNistEccSqr = BN_ModSm2EccSqr,
    .modOrdInv = ECP_ModOrderInv,
};
#endif

// general method implementation of prime curve
static const ECC_Method EC_METHOD_PRIME = {
    .pointMulAdd = ECP_PointMulAdd,
    .pointMul = ECP_PointMul,
    .pointAdd = ECP_PointAdd,
    .pointDouble = ECP_PointDouble,
    .pointMultDouble = ECP_PointMultDouble,
    .modInv = BN_ModInv,
    .point2AffineWithInv = ECP_Point2AffineWithInv,
    .point2Affine = ECP_Point2Affine,
    .bnModNistEccMul = BN_ModNistEccMul,
    .bnModNistEccSqr = BN_ModNistEccSqr,
    .modOrdInv = ECP_ModOrderInv,
};

static const ECC_MethodMap EC_METHODS[] = {
    { CRYPT_ECC_NISTP224, &EC_METHOD_NIST },
    { CRYPT_ECC_NISTP256, &EC_METHOD_NIST },
    { CRYPT_ECC_NISTP384, &EC_METHOD_NIST },
    { CRYPT_ECC_NISTP521, &EC_METHOD_NIST },
    { CRYPT_ECC_BRAINPOOLP256R1, &EC_METHOD_PRIME },
    { CRYPT_ECC_BRAINPOOLP384R1, &EC_METHOD_PRIME },
    { CRYPT_ECC_BRAINPOOLP512R1, &EC_METHOD_PRIME },
#ifdef HITLS_CRYPTO_SM2
    { CRYPT_ECC_SM2, &EC_METHOD_SM2 },
#endif
};


const ECC_Method *ECC_FindMethod(CRYPT_PKEY_ParaId id)
{
    for (uint32_t i = 0; i < sizeof(EC_METHODS) / sizeof(EC_METHODS[0]); i++) {
        if (EC_METHODS[i].id == id) {
            return EC_METHODS[i].ecMeth;
        }
    }
    return NULL;
}
#endif /* HITLS_CRYPTO_ECC */

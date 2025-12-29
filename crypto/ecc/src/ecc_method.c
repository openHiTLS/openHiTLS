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

#include "ecc_local.h"
#include "bsl_err_internal.h"
#include "ecp_nistp224.h"
#include "ecp_nistp256.h"
#include "ecp_nistp521.h"
#include "ecp_sm2.h"


typedef struct {
    uint32_t id;
    const ECC_Method *ecMeth;
} ECC_MethodMap;

#if defined(HITLS_SIXTY_FOUR_BITS)
#if defined(HITLS_CRYPTO_CURVE_NISTP192) || \
    ((defined(HITLS_CRYPTO_CURVE_NISTP224) || defined(HITLS_CRYPTO_CURVE_NISTP521)) && \
        !defined(HITLS_CRYPTO_NIST_USE_ACCEL)) || \
    defined(HITLS_CRYPTO_CURVE_NISTP384) || \
    (defined(HITLS_CRYPTO_CURVE_NISTP256) && (!defined(HITLS_CRYPTO_CURVE_NISTP256_ASM) || \
        (!defined(HITLS_CRYPTO_NIST_ECC_ACCELERATE))) && (!defined(HITLS_CRYPTO_NIST_USE_ACCEL)))
static const ECC_Method EC_METHOD_NIST = {
    .pointMulAdd = ECP_PointMulAdd,
    .pointMul = ECP_PointMul,
    .pointMulFast = ECP_PointMulFast,
    .pointAddAffine = ECP_NistPointAddAffine,
    .pointDouble = ECP_NistPointDouble,
    .pointMultDouble = ECP_NistPointMultDouble,
    .modInv = BN_ModInv,
    .point2AffineWithInv = ECP_Point2AffineWithInv,
    .point2Affine = ECP_Point2Affine,
    .bnModNistEccMul = BN_ModNistEccMul,
    .bnModNistEccSqr = BN_ModNistEccSqr,
    .modOrdInv = ECP_ModOrderInv,
    .pointAdd = ECP_NistPointAdd,
};
#endif
#endif // HITLS_SIXTY_FOUR_BITS

#ifdef HITLS_CRYPTO_CURVE_MONT_NIST
static const ECC_Method EC_METHOD_NIST_MONT = {
    .pointMulAdd = ECP_PointMulAdd,
    .pointMul = ECP_PointMulMont,
    .pointMulFast = ECP_PointMulFast,
    .pointDouble = ECP_NistPointDoubleMont,
    .pointMultDouble = ECP_NistPointMultDoubleMont,
    .modInv = BN_ModInv,
    .point2Affine = ECP_Point2AffineMont,
    .bnModNistEccMul = BN_EcPrimeMontMul,
    .bnModNistEccSqr = BN_EcPrimeMontSqr,
    .modOrdInv = ECP_ModOrderInv,
    .pointAdd = ECP_NistPointAddMont,
    .pointAddAffine = ECP_NistPointAddAffineMont,
    .bnMontEnc = BnMontEnc,
    .bnMontDec = BnMontDec,
};
#endif // HITLS_CRYPTO_CURVE_MONT_NIST

#ifdef HITLS_CRYPTO_CURVE_SM2_ASM
// method implementation of SM2
static const ECC_Method EC_METHOD_SM2_ASM = {
    .pointMulAdd = ECP_Sm2PointMulAdd,
    .pointMul = ECP_Sm2PointMul,
    .pointMulFast = ECP_Sm2PointMulFast,
    .pointAddAffine = ECP_Sm2PointAddAffine,
    .pointDouble = ECP_Sm2PointDouble,
    .pointMultDouble = ECP_NistPointMultDouble,
    .modInv = BN_ModInv,
    .point2AffineWithInv = ECP_Point2AffineWithInv,
    .point2Affine = ECP_Sm2Point2Affine,
    .bnModNistEccMul = BN_ModSm2EccMul,
    .bnModNistEccSqr = BN_ModSm2EccSqr,
    .modOrdInv = ECP_Sm2OrderInv,
    .pointAdd = ECP_NistPointAdd,
};
#endif

#if defined(HITLS_CRYPTO_CURVE_SM2) && !defined(HITLS_CRYPTO_CURVE_SM2_ASM) && defined(HITLS_SIXTY_FOUR_BITS)
static const ECC_Method EC_METHOD_SM2_NIST = {
    .pointMulAdd = ECP_PointMulAdd,
    .pointMul = ECP_PointMul,
    .pointMulFast = ECP_PointMulFast,
    .pointAddAffine = ECP_NistPointAddAffine,
    .pointDouble = ECP_NistPointDouble,
    .pointMultDouble = ECP_NistPointMultDouble,
    .modInv = BN_ModInv,
    .point2AffineWithInv = ECP_Point2AffineWithInv,
    .point2Affine = ECP_Point2Affine,
    .bnModNistEccMul = BN_ModSm2EccMul,
    .bnModNistEccSqr = BN_ModSm2EccSqr,
    .modOrdInv = ECP_ModOrderInv,
    .pointAdd = ECP_NistPointAdd,
};
#endif

#if defined(HITLS_CRYPTO_CURVE_BP256R1) || defined(HITLS_CRYPTO_CURVE_BP384R1) || \
    defined(HITLS_CRYPTO_CURVE_BP512R1)
// Montgomery Ladder Optimization for General Curves in Prime Domain
static const ECC_Method EC_METHOD_PRIME_MONT = {
    .pointMulAdd = ECP_PointMulAdd,
    .pointMul = ECP_PointMulMont,
    .pointDouble = ECP_PrimePointDoubleMont,
    .pointMulFast = ECP_PointMulFast,
    .pointMultDouble = ECP_PrimePointMultDoubleMont,
    .modInv = BN_ModInv,
    .point2Affine = ECP_Point2AffineMont,
    .bnModNistEccMul = BN_EcPrimeMontMul,
    .bnModNistEccSqr = BN_EcPrimeMontSqr,
    .modOrdInv = ECP_ModOrderInv,
    .pointAdd = ECP_PrimePointAddMont,
    .pointAddAffine = ECP_PrimePointAddAffineMont,
    .bnMontEnc = BnMontEnc,
    .bnMontDec = BnMontDec,
};
#endif

#ifdef HITLS_CRYPTO_NIST_USE_ACCEL
#ifdef HITLS_CRYPTO_CURVE_NISTP224
static const ECC_Method EC_METHOD_NIST_P224 = {
    .pointMulAdd = ECP224_PointMulAdd,
    .pointMul = ECP224_PointMul,
    .pointMulFast = ECP224_PointMul,
    .pointAddAffine = ECP_NistPointAddAffine,
    .pointDouble = ECP_NistPointDouble,
    .pointMultDouble = ECP_NistPointMultDouble,
    .modInv = BN_ModInv,
    .point2AffineWithInv = ECP_Point2AffineWithInv,
    .point2Affine = ECP224_Point2Affine,
    .bnModNistEccMul = BN_ModNistEccMul,
    .bnModNistEccSqr = BN_ModNistEccSqr,
    .modOrdInv = ECP_ModOrderInv,
};
#endif

#ifdef HITLS_CRYPTO_CURVE_NISTP521
static const ECC_Method EC_METHOD_NIST_P521 = {
    .pointMulAdd = ECP521_PointMulAdd,
    .pointMul = ECP521_PointMul,
    .pointMulFast = ECP521_PointMul,
    .pointAddAffine = ECP_NistPointAddAffine,
    .pointDouble = ECP_NistPointDouble,
    .pointMultDouble = ECP_NistPointMultDouble,
    .modInv = BN_ModInv,
    .point2AffineWithInv = ECP_Point2AffineWithInv,
    .point2Affine = ECP521_Point2Affine,
    .bnModNistEccMul = BN_ModNistEccMul,
    .bnModNistEccSqr = BN_ModNistEccSqr,
    .modOrdInv = ECP_ModOrderInv,
};
#endif
#endif // HITLS_CRYPTO_NIST_USE_ACCEL

#ifdef HITLS_CRYPTO_CURVE_NISTP256
#if ((defined(HITLS_CRYPTO_CURVE_NISTP256_ASM) && defined(HITLS_CRYPTO_NIST_ECC_ACCELERATE)) || \
    (!defined(HITLS_CRYPTO_CURVE_NISTP256_ASM) && defined(HITLS_CRYPTO_NIST_USE_ACCEL)))
static const ECC_Method EC_METHOD_NIST_P256 = {
    .pointMulAdd = ECP256_PointMulAdd,
    .pointMul = ECP256_PointMul,
    .pointMulFast = ECP256_PointMul,
    .pointAddAffine = ECP_NistPointAddAffine,
    .pointDouble = ECP_NistPointDouble,
    .pointMultDouble = ECP_NistPointMultDouble,
    .modInv = BN_ModInv,
    .point2AffineWithInv = ECP_Point2AffineWithInv,
    .point2Affine = ECP256_Point2Affine,
    .bnModNistEccMul = BN_ModNistEccMul,
    .bnModNistEccSqr = BN_ModNistEccSqr,
    .modOrdInv = ECP256_ModOrderInv,
};
#endif
#endif

static const ECC_MethodMap EC_METHODS[] = {
// p192
#ifdef HITLS_CRYPTO_CURVE_NISTP192
    #ifdef HITLS_SIXTY_FOUR_BITS
        { CRYPT_ECC_NISTP192, &EC_METHOD_NIST }, // Common nist cal + fast modulus reduction of Bn
    #else
        { CRYPT_ECC_NISTP192, &EC_METHOD_NIST_MONT },
    #endif
#endif

// p224
#ifdef HITLS_CRYPTO_CURVE_NISTP224
    #ifdef HITLS_CRYPTO_NIST_USE_ACCEL
        { CRYPT_ECC_NISTP224, &EC_METHOD_NIST_P224 }, // Depends on uint128.
    #elif defined(HITLS_SIXTY_FOUR_BITS)
        { CRYPT_ECC_NISTP224, &EC_METHOD_NIST }, // Common nist cal + fast modulus reduction of Bn
    #else
        { CRYPT_ECC_NISTP224, &EC_METHOD_NIST_MONT },
    #endif
#endif

// p256
#ifdef HITLS_CRYPTO_CURVE_NISTP256
    #if defined(HITLS_CRYPTO_CURVE_NISTP256_ASM) && defined(HITLS_CRYPTO_NIST_ECC_ACCELERATE)
        { CRYPT_ECC_NISTP256, &EC_METHOD_NIST_P256 }, // The ECC assembly optimization does not depend on uint128.
    #elif (!defined(HITLS_CRYPTO_CURVE_NISTP256_ASM) && defined(HITLS_CRYPTO_NIST_USE_ACCEL))
        { CRYPT_ECC_NISTP256, &EC_METHOD_NIST_P256 }, // Non-assembled ECC optimization based on uint128
    #elif defined(HITLS_SIXTY_FOUR_BITS)
        { CRYPT_ECC_NISTP256, &EC_METHOD_NIST }, // Common nist calculation + fast modulus reduction of Bn
    #else
        { CRYPT_ECC_NISTP256, &EC_METHOD_NIST_MONT },
    #endif
#endif

// p384
#ifdef HITLS_CRYPTO_CURVE_NISTP384
    #if defined(HITLS_SIXTY_FOUR_BITS)
        { CRYPT_ECC_NISTP384, &EC_METHOD_NIST }, // Common nist calculation + fast modulus reduction of Bn
    #else
        { CRYPT_ECC_NISTP384, &EC_METHOD_NIST_MONT },
    #endif
#endif

// p521
#ifdef HITLS_CRYPTO_CURVE_NISTP521
    #ifdef HITLS_CRYPTO_NIST_USE_ACCEL
        { CRYPT_ECC_NISTP521, &EC_METHOD_NIST_P521 }, // Non-assembly optimization, depending on uint128
    #elif defined(HITLS_SIXTY_FOUR_BITS)
        { CRYPT_ECC_NISTP521, &EC_METHOD_NIST },  // nist calculation + fast modulus reduction of Bn
    #else
        { CRYPT_ECC_NISTP521, &EC_METHOD_NIST_MONT },
    #endif
#endif

// bp256
#ifdef HITLS_CRYPTO_CURVE_BP256R1
    { CRYPT_ECC_BRAINPOOLP256R1, &EC_METHOD_PRIME_MONT },
#endif

// bp384
#ifdef HITLS_CRYPTO_CURVE_BP384R1
    { CRYPT_ECC_BRAINPOOLP384R1, &EC_METHOD_PRIME_MONT },
#endif

// bp512
#ifdef HITLS_CRYPTO_CURVE_BP512R1
    { CRYPT_ECC_BRAINPOOLP512R1, &EC_METHOD_PRIME_MONT },
#endif

#ifdef HITLS_CRYPTO_CURVE_SM2
    #ifdef HITLS_CRYPTO_CURVE_SM2_ASM
        { CRYPT_ECC_SM2, &EC_METHOD_SM2_ASM },
    #elif defined(HITLS_SIXTY_FOUR_BITS)
        { CRYPT_ECC_SM2, &EC_METHOD_SM2_NIST },
    #else
        { CRYPT_ECC_SM2, &EC_METHOD_NIST_MONT },
    #endif
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

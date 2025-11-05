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

#ifndef ASM_ECP_SM2_ARMV7_H
#define ASM_ECP_SM2_ARMV7_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CURVE_SM2_ARMV7

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM2_BITS  256
#define SM2_BYTES 64
#define SM2_LIMBS 8    /// (SM2_BYTES / sizeof(uint32_t))

/**
 * @brief The type representing a 256-bit number in finite prime field.
 * @note The number is stored in little-endian order and used for underlying (mathematical) operations.
 */
typedef uint32_t Sm2Fp[SM2_LIMBS];

/**
 * @brief The structure representing a jacobian point on the elliptic curve.
 * @note This structure is used for underlying (mathematical) operations.
 */
typedef struct SM2Point{
    Sm2Fp x;   ///< x-coordinate of the jacobian point
    Sm2Fp y;   ///< y-coordinate of the jacobian point
    Sm2Fp z;   ///< z-coordinate of the jacobian point
} Sm2Point;

/**
 * @brief Compares two numbers.
 * @param [in] a The first number.
 * @param [in] b The second number.
 * @return 1 if a >= b, 0 otherwise.
 */
int32_t ECP_Sm2FpCmp(const Sm2Fp a, const Sm2Fp b);

/**
 * @brief Computes addition modulo sm2_p, i.e., r ≡ a + b mod sm2_p.
 * @param [out] r The result number.
 * @param [in] a The first number.
 * @param [in] b The second number.
 */
void ECP_Sm2FpAdd(Sm2Fp r, const Sm2Fp a, const Sm2Fp b);

/**
 * @brief Computes subtraction modulo sm2_p, i.e., r ≡ a - b mod sm2_p.
 * @param [out] r The result number.
 * @param [in] a The minuend.
 * @param [in] b The subtrahend.
 */
void ECP_Sm2FpSub(Sm2Fp r, const Sm2Fp a, const Sm2Fp b);

/**
 * @brief Computes additive inverse modulo sm2_p, i.e., r ≡ -a mod sm2_p.
 * @param [out] r The result number.
 * @param [in] a The number to negate.
 */
void ECP_Sm2FpNeg(Sm2Fp r, const Sm2Fp a);

/**
 * @brief Computes halving modulo sm2_p, i.e., r ≡ a/2 mod sm2_p.
 * @param [out] r The result number.
 * @param [in] a The number to halve.
 */
void ECP_Sm2FpHaf(Sm2Fp r, const Sm2Fp a);

/**
 * @brief Computes doubling modulo sm2_p, i.e., r ≡ 2a mod sm2_p.
 * @param [out] r The result number.
 * @param [in] a The number to double.
 */

void ECP_Sm2FpDou(Sm2Fp r, const Sm2Fp a);

/**
 * @brief Computes multiplication modulo sm2_p, i.e., r ≡ a * b mod sm2_p.
 * @param [out] r The result number.
 * @param [in] a The first number.
 * @param [in] b The second number.
 */
void ECP_Sm2FpMul(Sm2Fp r, const Sm2Fp a, const Sm2Fp b);

/**
 * @brief Computes squaring modulo sm2_p, i.e., r ≡ a^2 mod sm2_p.
 * @param [out] r The result number.
 * @param [in] a The number to square.
 */
void ECP_Sm2FpSqr(Sm2Fp r, const Sm2Fp a);

/**
 * @brief Computes addition modulo sm2_n, i.e., r ≡ a + b mod sm2_n.
 * @param [out] r The result number.
 * @param [in] a The first number.
 * @param [in] b The second number.
 */
void ECP_Sm2FnAdd(Sm2Fp r, const Sm2Fp a, const Sm2Fp b);

/**
 * @brief Computes subtraction modulo sm2_n, i.e., r ≡ a - b mod sm2_n.
 * @param [out] r The result number.
 * @param [in] a The minuend.
 * @param [in] b The subtrahend.
 */
void ECP_Sm2FnSub(Sm2Fp r, const Sm2Fp a, const Sm2Fp b);

/**
 * @brief Computes halving modulo sm2_n, i.e., r ≡ a/2 mod sm2_n.
 * @param [out] r The result number.
 * @param [in] a The number to halve.
 */
void ECP_Sm2FnHaf(Sm2Fp r, const Sm2Fp a);

/**
 * @brief Computes multiplication modulo sm2_n, i.e., r ≡ a * b mod sm2_n.
 * @param [out] r The result number.
 * @param [in] a The first number.
 * @param [in] b The second number.
 */
void ECP_Sm2FnMul(Sm2Fp r, const Sm2Fp a, const Sm2Fp b);

#ifdef __cplusplus
}
#endif

#endif
#endif //ASM_ECP_SM2_ARMV7_H

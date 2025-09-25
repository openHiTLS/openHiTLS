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

#ifndef ASM_ECP_SM2_H
#define ASM_ECP_SM2_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_CURVE_SM2) && defined(HITLS_SIXTY_FOUR_BITS)

#include <stdint.h>
#include "crypt_bn.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SM2_BITS 256
#define SM2_BITSOFBYTES 8
#define SM2_BYTES_NUM 32
#define SM2_LIMBS      (SM2_BYTES_NUM / sizeof(BN_UINT)) /* = 4 or 8 */

typedef struct SM2_point {
    BN_UINT x[SM2_LIMBS];
    BN_UINT y[SM2_LIMBS];
    BN_UINT z[SM2_LIMBS];
} SM2_point;

typedef struct SM2_pointaffine {
    BN_UINT x[SM2_LIMBS];
    BN_UINT y[SM2_LIMBS];
} SM2_AffinePoint;

/* Right shift: a >> 1 */
void ECP_Sm2BnRshift1(BN_UINT *a);
/* Finite field operations */
/* Modular div by 2: r = a/2 mod p */
void ECP_Sm2DivBy2(BN_UINT *r, const BN_UINT *a);
/* Modular add: r = a+b mod p */
void ECP_Sm2AddModP(BN_UINT *r, const BN_UINT *a, const BN_UINT *b);
/* Modular add: r = a+b mod n, where n = ord(p) */
void ECP_Sm2AddModOrd(BN_UINT *r, const BN_UINT *a, const BN_UINT *b);
/* Modular sub: r = a-b mod p */
void ECP_Sm2SubModP(BN_UINT *r, const BN_UINT *a, const BN_UINT *b);
/* Modular sub: r = a-b mod n, where n = ord(p) */
void ECP_Sm2SubModOrd(BN_UINT *r, const BN_UINT *a, const BN_UINT *b);
/* Modular mul by 3: r = 3*a mod p */
void ECP_Sm2MulBy3(BN_UINT *r, const BN_UINT *a);
/* Modular mul: r = a*b mod p */
void ECP_Sm2Mul(BN_UINT *r, const BN_UINT *a, const BN_UINT *b);
/* Modular sqr: r = a^2 mod p */
void ECP_Sm2Sqr(BN_UINT *r, const BN_UINT *a);
/* sub: r = p - b */
void ECP_Sm2Neg(BN_UINT *r, const BN_UINT *b);

const BN_UINT *ECP_Sm2Precomputed(void);

/* Right shift 1: r = a >> 1 */
void ECP_Sm2Div2(BN_UINT *r, BN_UINT *a);
/* Right shift 2: r = a >> 2 */
void ECP_Sm2Div4(BN_UINT *r, BN_UINT *a);
/* Sub: r = a - b */
void ECP_Sm2BnSub(BN_UINT *r, const BN_UINT *a, const BN_UINT *b);
/* Add: r = a + b */
void ECP_Sm2BnAdd(BN_UINT *r, const BN_UINT *a, const BN_UINT *b);

/* Finite field operations */

/* Modular div by 2: r = a/2 mod p */
void ECP_Sm2Div2ModP(BN_UINT *r, const BN_UINT *a);
/* Modular div by 2: r = a/2 mod n, where n = ord(p) */
void ECP_Sm2Div2ModOrd(BN_UINT *r, const BN_UINT *a);
/* Modular div by 4: r = a/4 mod p */
void ECP_Sm2Div4ModP(BN_UINT *r, BN_UINT *a);
/* Modular div by 4: r = a/4 mod n, where n = ord(p) */
void ECP_Sm2Div4ModOrd(BN_UINT *r, const BN_UINT *a);

/* Convert to Montgomery domain */
void ECP_Sm2ToMont(BN_UINT *r, const BN_UINT *a);
/* Convert from Montgomery domain */
void ECP_Sm2FromMont(BN_UINT *r, const BN_UINT *a);

/* Point double in Montgomery domain: r <- a + a */
void ECP_Sm2PointDoubleMont(SM2_point *r, const SM2_point *a);
/* Point add affine in Montgomery domain: R <- a + b */
void ECP_Sm2PointAddAffineMont(SM2_point *r, const SM2_point *a, const SM2_AffinePoint *b);
/* Point add in Montgomery domain: r <- a + b */
void ECP_Sm2PointAddMont(SM2_point *r, const SM2_point *a, const SM2_point *b);

#ifdef __cplusplus
}
#endif

#endif
#endif
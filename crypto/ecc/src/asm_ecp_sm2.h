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
#if defined(HITLS_CRYPTO_ECC) && defined(HITLS_CRYPTO_SM2)

#include <stdint.h>
#include "crypt_bn.h"

#ifdef __cplusplus
extern "C" {
#endif
#define P256_BITS      256
#define P256_BYTES     32
#define P256_SIZE       (P256_BYTES / sizeof(BN_UINT))

typedef struct {
    BN_UINT value[P256_SIZE];
} Coord;    // Point Coordinates

typedef struct p256_point {
    Coord x;
    Coord y;
    Coord z;
} P256_Point;

typedef struct p256_pointaffine {
    Coord x;
    Coord y;
} P256_AffinePoint;

typedef P256_AffinePoint ECP256_TableRow[64];

/* Right shift: a >> 1 */
void ECP_Sm2BnRshift1(BN_UINT *a);
/* Finite field operations */
/* Modular div by 2: r = a/2 mod p */
void ECP_Sm2DivBy2(BN_UINT *r, const BN_UINT *a);
/* Modular add: r = a+b mod p */
void ECP_Sm2Add(BN_UINT *r, const BN_UINT *a, const BN_UINT *b);
/* Modular add: r = a+b mod n, where n = ord(p) */
void ECP_Sm2AddModOrd(BN_UINT *r, const BN_UINT *a, const BN_UINT *b);
/* Modular sub: r = a-b mod p */
void ECP_Sm2Sub(BN_UINT *r, const BN_UINT *a, const BN_UINT *b);
/* Modular sub: r = a-b mod n, where n = ord(p) */
void ECP_Sm2SubModOrd(BN_UINT *r, const BN_UINT *a, const BN_UINT *b);
/* Modular mul by 3: r = 3*a mod p */
void ECP_Sm2MulBy3(BN_UINT *r, const BN_UINT *a);
/* Modular mul: r = a*b mod p */
void ECP_Sm2Mul(BN_UINT *r, const BN_UINT *a, const BN_UINT *b);
/* Modular sqr: r = a^2 mod p */
void ECP_Sm2Sqr(BN_UINT *r, const BN_UINT *a);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM2

#endif // ASM_ECP_SM2_H

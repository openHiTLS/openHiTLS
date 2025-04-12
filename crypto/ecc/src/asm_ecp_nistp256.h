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

#ifndef ASM_ECP_NISTP256_H
#define ASM_ECP_NISTP256_H

#include "hitls_build.h"

#ifdef __cplusplus
extern "C" {
#endif

#define P256_BYTES      32
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

#if defined(HITLS_CRYPTO_CURVE_NISTP256_ASM) && defined(HITLS_CRYPTO_NIST_ECC_ACCELERATE)

typedef P256_AffinePoint ECP256_TableRow[64];

const ECP256_TableRow *ECP256_GetPreCompTable(void);

void ECP256_FromMont(Coord *r, const Coord *a);

void ECP256_Mul(Coord *r, const Coord *a, const Coord *b);

void ECP256_Sqr(Coord *r, const Coord *a);

void ECP256_Neg(Coord *r, const Coord *a);

void ECP256_OrdMul(Coord *r, const Coord *a, const Coord *b);

void ECP256_OrdSqr(Coord *r, const Coord *a, int32_t repeat);

void ECP256_PointDouble(P256_Point *r, const P256_Point *a);

void ECP256_PointAdd(P256_Point *r, const P256_Point *a, const P256_Point *b);

void ECP256_AddAffine(P256_Point *r, const P256_Point *a, const P256_AffinePoint *b);

void ECP256_Scatterw5(P256_Point *table, const P256_Point *point, uint32_t index);

void ECP256_Gatherw5(P256_Point *point, const P256_Point *table, uint32_t index);

void ECP256_Gatherw7(P256_AffinePoint *point, const P256_AffinePoint *table, uint32_t index);

#endif /* HITLS_CRYPTO_CURVE_NISTP256_ASM && HITLS_CRYPTO_NIST_ECC_ACCELERATE */

#ifdef __cplusplus
}
#endif


#endif
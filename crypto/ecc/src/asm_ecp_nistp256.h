/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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

#if defined(HITLS_CRYPTO_CURVE_NISTP256) && defined(HITLS_CRYPTO_NIST_USE_ACCEL)

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

#endif /* defined(HITLS_CRYPTO_CURVE_NISTP256) && defined(HITLS_CRYPTO_NIST_USE_ACCEL) */

#ifdef __cplusplus
}
#endif


#endif
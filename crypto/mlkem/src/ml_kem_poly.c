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
#ifdef HITLS_CRYPTO_MLKEM
#include "ml_kem_local.h"

// basecase multiplication: add to polyH but not override it
static void BaseMulAdd(int16_t polyH[2], const int16_t f0, const int16_t f1, const int16_t g0, const int16_t g1,
                       const int16_t factor)
{
    polyH[0] += (int16_t)((f0 * g0 + f1 * g1 % MLKEM_Q * factor) % MLKEM_Q);
    polyH[1] += (int16_t)((f0 * g1 + f1 * g0) % MLKEM_Q);
}

static void CircMulAdd(int16_t dest[MLKEM_N], const int16_t src1[MLKEM_N], const int16_t src2[MLKEM_N],
                       const int16_t *factor)
{
    for (uint32_t i = 0; i < MLKEM_N / 4; i++) {
        // 4-byte data is calculated in each round.
        BaseMulAdd(&dest[4 * i], src1[4 * i], src1[4 * i + 1], src2[4 * i], src2[4 * i + 1], factor[i]);
        BaseMulAdd(&dest[4 * i + 2], src1[4 * i + 2], src1[4 * i + 3], src2[4 * i + 2], src2[4 * i + 3],
                   -1 * factor[i]);
    }
}

static void PolyReduce(int16_t *poly)
{
    for (int i = 0; i < MLKEM_N; ++i) {
        poly[i] = BarrettReduction(poly[i]);
    }
}
// polyVecOut += (matrix * polyVec): add to polyVecOut but not override it
void MLKEM_MatrixMulAdd(uint8_t k, int16_t **matrix, int16_t **polyVec, int16_t **polyVecOut, const int16_t *factor)
{
    int16_t **currOutPoly = polyVecOut;
    for (int i = 0; i < k; ++i) {
        int16_t **currMatrixPoly = matrix + i * MLKEM_K_MAX;
        int16_t **currVecPoly = polyVec;
        for (int j = 0; j < k; ++j) {
            CircMulAdd(*currOutPoly, *currMatrixPoly, *currVecPoly, factor + MLKEM_N_HALF / 2);
            ++currMatrixPoly;
            ++currVecPoly;
        }
        PolyReduce(*currOutPoly);
        ++currOutPoly;
    }
}

// polyVecOut += (matrix^T * polyVec): add to polyVecOut but not override it
void MLKEM_TransposeMatrixMulAdd(uint8_t k, int16_t **matrix, int16_t **polyVec, int16_t **polyVecOut,
                                 const int16_t *factor)
{
    int16_t **currOutPoly = polyVecOut;
    for (int i = 0; i < k; ++i) {
        int16_t **currMatrixPoly = matrix + i;
        int16_t **currVecPoly = polyVec;
        for (int j = 0; j < k; ++j) {
            CircMulAdd(*currOutPoly, *currMatrixPoly, *currVecPoly, factor + MLKEM_N_HALF / 2);
            currMatrixPoly += MLKEM_K_MAX;
            ++currVecPoly;
        }
        ++currOutPoly;
    }
}

void MLKEM_VectorInnerProductAdd(uint8_t k, int16_t **polyVec1, int16_t **polyVec2, int16_t *polyOut,
                                 const int16_t *factor)
{
    for (int i = 0; i < k; ++i) {
        CircMulAdd(polyOut, polyVec1[i], polyVec2[i], factor + MLKEM_N_HALF / 2);
    }
}

void MLKEM_SamplePolyCBD(int16_t *polyF, uint8_t *buf, uint8_t eta)
{
    uint32_t i;
    uint32_t j;
    uint8_t a;
    uint8_t b;
    uint32_t t1;
    if (eta == 3) {  // The value of eta can only be 2 or 3.
        for (i = 0; i < MLKEM_N / 4; i++) {
            uint32_t temp = (uint32_t)buf[eta * i];
            temp |= (uint32_t)buf[eta * i + 1] << 8;
            temp |= (uint32_t)buf[eta * i + 2] << 16;
            t1 = temp & 0x00249249;  // temp & 0x00249249 is used to obtain a specific bit in temp.
            t1 += (temp >> 1) & 0x00249249;
            t1 += (temp >> 2) & 0x00249249;

            for (j = 0; j < 4; j++) {
                a = (t1 >> (6 * j)) & 0x3;
                b = (t1 >> (6 * j + eta)) & 0x3;
                polyF[4 * i + j] = a - b;
            }
        }
    } else if (eta == 2) {
        for (i = 0; i < MLKEM_N / 4; i++) {
            uint16_t temp = (uint16_t)buf[eta * i];
            temp |= (uint16_t)buf[eta * i + 1] << 0x8;
            t1 = temp & 0x5555;  // temp & 0x5555 is used to obtain a specific bit in temp.
            t1 += (temp >> 1) & 0x5555;

            for (j = 0; j < 4; j++) {
                a = (t1 >> (4 * j)) & 0x3;
                b = (t1 >> (4 * j + eta)) & 0x3;
                polyF[4 * i + j] = a - b;
            }
        }
    }
}
#endif
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
#ifdef HITLS_CRYPTO_FRODOKEM
#include "frodo_local.h"

void FrodoCommonSampleNFromR(uint16_t *samples, const uint32_t n, const uint16_t *cdfTable, const uint32_t cdfLen,
                             const uint8_t *rBytes)
{
    for (uint32_t i = 0; i < n; i++) {
        uint16_t r = (uint16_t)rBytes[2 * i] | ((uint16_t)rBytes[2 * i + 1] << 8);

        uint16_t prnd = r >> 1;
        uint16_t sign = r & 1;

        uint16_t t = 0;
        for (uint32_t j = 0; j < cdfLen - 1; j++) {
            t += (uint16_t)(cdfTable[j] - prnd) >> 15;
        }
        samples[i] = ((uint16_t)(-sign) ^ t) + sign;
    }
}

void FrodoMulAddAsPlusE(uint16_t *out, const uint16_t *matrixS, int32_t n, int32_t nBar, uint16_t *rows,
                        int32_t rowNumber)
{
    const uint16_t *row0 = &rows[0 * n];
    const uint16_t *row1 = &rows[1 * n];
    const uint16_t *row2 = &rows[2 * n];
    const uint16_t *row3 = &rows[3 * n];

    for (int32_t j = 0; j < nBar; j++) {
        const uint16_t *rowS = &matrixS[j * n];
        uint16_t sum0 = 0;
        uint16_t sum1 = 0;
        uint16_t sum2 = 0;
        uint16_t sum3 = 0;
        for (int32_t k = 0; k < n; k++) {
            uint16_t sv = rowS[k];
            sum0 += (uint16_t)((uint32_t)row0[k] * sv);
            sum1 += (uint16_t)((uint32_t)row1[k] * sv);
            sum2 += (uint16_t)((uint32_t)row2[k] * sv);
            sum3 += (uint16_t)((uint32_t)row3[k] * sv);
        }
        out[(rowNumber + 0) * nBar + j] = (uint16_t)(out[(rowNumber + 0) * nBar + j] + sum0);
        out[(rowNumber + 1) * nBar + j] = (uint16_t)(out[(rowNumber + 1) * nBar + j] + sum1);
        out[(rowNumber + 2) * nBar + j] = (uint16_t)(out[(rowNumber + 2) * nBar + j] + sum2);
        out[(rowNumber + 3) * nBar + j] = (uint16_t)(out[(rowNumber + 3) * nBar + j] + sum3);
    }
}

void FrodoMulAddSaPlusE(uint16_t *out, const uint16_t *matrixS, int32_t n, int32_t nBar, uint16_t *rows,
                        int32_t rowNumber)
{
    const uint16_t *row0 = &rows[0 * n];
    const uint16_t *row1 = &rows[1 * n];
    const uint16_t *row2 = &rows[2 * n];
    const uint16_t *row3 = &rows[3 * n];

    for (int32_t k = 0; k < nBar; k++) {
        const uint16_t s0 = matrixS[k * n + (rowNumber + 0)];
        const uint16_t s1 = matrixS[k * n + (rowNumber + 1)];
        const uint16_t s2 = matrixS[k * n + (rowNumber + 2)];
        const uint16_t s3 = matrixS[k * n + (rowNumber + 3)];

        uint16_t *outRow = &out[k * n];
        for (int32_t j = 0; j < n; j++) {
            uint16_t acc = outRow[j];
            acc = (uint16_t)(acc + (uint16_t)((uint32_t)row0[j] * s0));
            acc = (uint16_t)(acc + (uint16_t)((uint32_t)row1[j] * s1));
            acc = (uint16_t)(acc + (uint16_t)((uint32_t)row2[j] * s2));
            acc = (uint16_t)(acc + (uint16_t)((uint32_t)row3[j] * s3));
            outRow[j] = acc;
        }
    }
}

void FrodoCommonMulAddSbPlusEPortable(uint16_t *V0, const uint16_t *STp, const uint16_t *B, const uint16_t *Epp,
                                      const FrodoKemParams *params)
{
    const uint32_t n = params->n;
    const uint32_t nBar = params->nBar;
    const uint16_t qMask = (uint16_t)((1u << params->logq) - 1u);

    for (uint32_t i = 0; i < nBar * nBar; i++) {
        V0[i] = (uint16_t)(Epp[i] & qMask);
    }

    for (uint32_t i = 0; i < nBar; i++) {
        const uint32_t si = i * n;
        const uint32_t vi = i * nBar;
        for (uint32_t k = 0; k < n; k++) {
            const uint32_t s = (uint32_t)(STp[si + k] & qMask);
            const uint32_t bk = k * nBar;
            for (uint32_t j = 0; j < nBar; j++) {
                const uint32_t b = (uint32_t)(B[bk + j] & qMask);
                uint32_t acc = (uint32_t)V0[vi + j] + s * b;
                V0[vi + j] = (uint16_t)(acc & qMask);
            }
        }
    }
}

#endif

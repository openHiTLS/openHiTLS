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

void MLKEM_ComputNTT(int16_t *a, const int32_t *psi)
{
    uint32_t start = 0;
    uint32_t j = 0;
    uint32_t k = 1;
    int32_t zeta;
    for (uint32_t len = MLKEM_N_HALF; len >= 2; len >>= 1) {
        for (start = 0; start < MLKEM_N; start = j + len) {
            zeta = psi[k++];
            for (j = start; j < start + len; ++j) {
                int16_t t = PlantardReduction(a[j + len] * zeta);
                a[j + len] = a[j] - t;
                a[j] += t;
            }
        }
    }
}

#define MLKEM_INTT_LOOP(len) \
    for (uint32_t start = 0; start < 256; start = j + (len)) {        \
        zeta = psi[k--];                                              \
        for (j = start; j < start + (len); j++) {                     \
            t = a[j];                                                 \
            a[j] = t + a[j + (len)];                                  \
            a[j + (len)] = a[j + (len)] - t;                          \
            a[j + (len)] = PlantardReduction(zeta * a[j + (len)]);    \
        }                                                             \
    }

void MLKEM_ComputINTT(int16_t *a, const int32_t *psi)
{
    int16_t t;
    int32_t zeta;
    uint32_t j = 0;
    // Mont / 128
    uint32_t k = MLKEM_N_HALF - 1;
    MLKEM_INTT_LOOP(2);
    MLKEM_INTT_LOOP(4);
    MLKEM_INTT_LOOP(8);
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        a[i] = BarrettReduction(a[i]);
    }
    MLKEM_INTT_LOOP(16);
    MLKEM_INTT_LOOP(32);
    MLKEM_INTT_LOOP(64);

    for (int32_t i = 0; i < MLKEM_N; ++i) {
        a[i] = BarrettReduction(a[i]);
    }

    int32_t len = 128;
    for (uint32_t start = 0; start < MLKEM_N; start = j + len) {
        for (j = start; j < start + len; j++) {
            t = a[j];
            a[j] = (int16_t)(t + a[j + len]);
            a[j + len] = a[j + len] - t;
            a[j + len] = PlantardReduction(MLKEM_LAST_ROUND_ZETA * a[j + len]);
        }
    }

    for (j = 0; j < MLKEM_N / 2; j++) {
        a[j] = PlantardReduction(a[j] * MLKEM_HALF_DEGREE_INVERSE_MOD_Q);
    }
}
#endif
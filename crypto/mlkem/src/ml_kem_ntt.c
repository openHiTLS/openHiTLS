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
                int16_t t = PlantardReduction((uint32_t)a[j + len] * (uint32_t)zeta);
                a[j + len] = a[j] - t;
                a[j] += t;
            }
        }
    }
}

#define MLKEM_INTT_LOOP(len, k, a, psi) \
    for (uint32_t start = 0; start < 256; start += 2 * (len)) {       \
        int32_t zeta = (psi)[(k)--];                                  \
        for (uint32_t j = start; j < start + (len); j++) {            \
            int16_t t = (a)[j];                                       \
            (a)[j] = t + (a)[j + (len)];                              \
            (a)[j + (len)] = (a)[j + (len)] - t;                      \
            (a)[j + (len)] = PlantardReduction((uint32_t)zeta * (uint32_t)(a)[j + (len)]);    \
        }                                                             \
    }

void MLKEM_ComputINTT(int16_t *a, const int32_t *psi)
{
    uint32_t k = MLKEM_N_HALF - 1;
    MLKEM_INTT_LOOP(2, k, a, psi);
    MLKEM_INTT_LOOP(4, k, a, psi);
    MLKEM_INTT_LOOP(8, k, a, psi);
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        a[i] = BarrettReduction(a[i]);
    }
    MLKEM_INTT_LOOP(16, k, a, psi);
    MLKEM_INTT_LOOP(32, k, a, psi);
    MLKEM_INTT_LOOP(64, k, a, psi);

    for (int32_t i = 0; i < MLKEM_N; ++i) {
        a[i] = BarrettReduction(a[i]);
    }

    int32_t len = 128;
    for (uint32_t start = 0; start < MLKEM_N; start += 2 * len) {
        for (uint32_t j = start; j < start + len; j++) {
            int16_t t = a[j];
            a[j] = (int16_t)(t + a[j + len]);
            a[j + len] = a[j + len] - t;
            a[j + len] = PlantardReduction((uint32_t)MLKEM_LAST_ROUND_ZETA * (uint32_t)a[j + len]);
        }
    }

    for (uint32_t j = 0; j < MLKEM_N / 2; j++) {
        a[j] = PlantardReduction((uint32_t)a[j] * (uint32_t)MLKEM_HALF_DEGREE_INVERSE_MOD_Q);
    }
}
#endif
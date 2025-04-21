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

void MLKEM_ComputNTT(int16_t *a, const int16_t *psi, uint32_t pruLength)
{
    uint32_t t = MLKEM_N;
    for (uint32_t m = 1; m < pruLength; m <<= 1) {
        t >>= 1;
        for (uint32_t i = 0; i < m; i++) {
            uint32_t j1 = (i << 1) * t;
            int16_t s = psi[m + i];
            int16_t *x = a + j1;
            int16_t *y = x + (int16_t)t;
            for (uint32_t j = j1; j < j1 + t; j++) {
                int32_t ys = (*y) * s;
                *y = (*x - ys) % MLKEM_Q;
                *x = (*x + ys) % MLKEM_Q;
                MlKemAddModQ(y);
                MlKemAddModQ(x);
                y++;
                x++;
            }
        }
    }
}

void MLKEM_ComputINTT(int16_t *a, const int16_t *psiInv, uint32_t pruLength)
{
    uint32_t t = MLKEM_N / pruLength;
    for (uint32_t m = pruLength; m > 1; m >>= 1) {
        uint32_t j1 = 0;
        uint32_t h = m >> 1;
        for (uint32_t i = 0; i < h; i++) {
            int16_t s = psiInv[h + i];
            for (uint32_t j = j1; j < j1 + t; j++) {
                int16_t u = a[j];
                int16_t v = a[j + t];
                a[j] = (u + v) % MLKEM_Q;
                // Both u and v are smaller than MLKEM_Q, temp not overflow.
                int16_t temp = u - v;
                MlKemAddModQ(&a[j]);
                MlKemAddModQ(&temp);
                a[j + t] = ((int32_t)temp * s) % MLKEM_Q;
            }
            j1 += (t << 1);
        }
        t <<= 1;
    }
    for (uint32_t n = 0; n < MLKEM_N; n++) {
        a[n] = (a[n] * MLKEM_INVN) % MLKEM_Q;
        MlKemAddModQ(&a[n]);
    }
}

#endif
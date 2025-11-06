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

void MLKEM_ComputNTT(int16_t *a, const int16_t *psi)
{
    uint32_t start = 0;
    uint32_t j = 0;
    uint32_t k = 1;
    int16_t zeta;
    for (uint32_t len = MLKEM_N_HALF; len >= 2; len >>= 1) {
        for (start = 0; start < MLKEM_N; start = j + len) {
            zeta = psi[k++];
            for (j = start; j < start + len; ++j) {
                int16_t t = MontgomeryReduction(a[j + len] * zeta);
                a[j + len] = a[j] - t;
                a[j] += t;
            }
        }
    }
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        a[i] = BarrettReduction(a[i]);
    }
}

void MLKEM_ComputINTT(int16_t *a, const int16_t *psi)
{
    int16_t t;
    int16_t zeta;
    uint32_t j = 0;
    // Mont / 128
    const int16_t f = 512;
    uint32_t k = MLKEM_N_HALF - 1;
    for (uint32_t len = 2; len <= 128; len <<= 1) {
        for (uint32_t start = 0; start < 256; start = j + len) {
            zeta = psi[k--];
            for (j = start; j < start + len; j++) {
                t = a[j];
                a[j] = BarrettReduction(t + a[j + len]);
                a[j + len] = a[j + len] - t;
                a[j + len] = MontgomeryReduction(zeta * a[j + len]);
            }
        }
    }
    for (j = 0; j < MLKEM_N; j++) {
        a[j] = MontgomeryReduction(a[j] * f);
    }
}
#endif
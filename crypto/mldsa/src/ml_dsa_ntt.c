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
#ifdef HITLS_CRYPTO_MLDSA
#include "ml_dsa_local.h"

// mont = 2^32 mod q = -4186625
// ZETAS is NIST.FIPS.204 Zetas * mont
static const int32_t ZETAS[MLDSA_N] = {
    0, 25847, -2608894, -518909, 237124, -777960, -876248,
    466468, 1826347, 2353451, -359251, -2091905, 3119733, -2884855,
    3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488,
    -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672,
    1757237, -19422, 4010497, 280005, 2706023, 95776, 3077325,
    3530437, -1661693, -3592148, -2537516, 3915439, -3861115, -3043716,
    3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267,
    -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596,
    811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892,
    -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455, -1585221, -1257611, 1939314, -4083598, -1000202, -3190144,
    -3157330, -3632928, 126922, 3412210, -983419, 2147896, 2715295,
    -2967645, -3693493, -411027, -2477047, -671102, -1228525, -22981,
    -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944,
    508951, 3097992, 44288, -1100098, 904516, 3958618, -3724342,
    -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
    189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589,
    1341330, 1285669, -1584928, -812732, -1439742, -3019102, -3881060,
    -3628969, 3839961, 2091667, 3407706, 2316500, 3817976, -3342478,
    2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181,
    -3520352, -3759364, -1197226, -3193378, 900702, 1859098, 909542,
    819034, 495491, -1613174, -43260, -522500, -655327, -3122442,
    2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
    286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044,
    2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353,
    1595974, -3767016, 1250494, 2635921, -3548272, -2994039, 1869119,
    1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100,
    1312455, 3306115, -1962642, -1279661, 1917081, -2546312, -1374803,
    1500165, 777191, 2235880, 3406031, -542412, -2831860, -1671176,
    -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395,
    2454455, -164721, 1957272, 3369112, 185531, -1207385, -3183426,
    162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
    -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735,
    472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333,
    -260646, -3833893, -2939036, -2235985, -420899, -2286327, 183443,
    -976891, 1612842, -3545687, -554416, 3919660, -48306, -1362209,
    3937738, 1400424, -846154, 1976782
};

// Referenced from NIST.FIPS.204 Algorithm 49 MontgomeryReduce(a)
int32_t MLDSA_MontgomeryReduce(int64_t a)
{
    int32_t t = (int32_t)(a * MLDSA_QINV);
    t = (int32_t)((a - (int64_t)t * MLDSA_Q) >> 32);  // (a - t * q)/2^32
    return t;
}

// Algorithm 41 NTT(w)
void MLDSA_ComputesNTT(int32_t w[MLDSA_N])
{
    uint32_t m = 0;
    for (uint32_t len = MLDSA_N / 2; len > 0; len >>= 1) {
        for (uint32_t start = 0; start < MLDSA_N;) {
            m++;
            int32_t z = ZETAS[m];
            for (uint32_t j = start; j < start + len; ++j) {
                int32_t t = MLDSA_MontgomeryReduce((int64_t)z * w[j + len]);
                w[j + len] = w[j] - t;
                w[j] = w[j] + t;
            }
            start = start + 2 * len;
        }
    }
}

// Algorithm 42 NTT^−1(w)
void MLDSA_ComputesINVNTT(int32_t w[MLDSA_N])
{
    const int64_t f = 41978;  // 41978 is mont^2/256
    uint32_t m = MLDSA_N;
    for (uint32_t len = 1; len < MLDSA_N; len <<= 1) {
        for (uint32_t start = 0; start < MLDSA_N;) {
            m--;
            int32_t zeta = -ZETAS[m];
            for (uint32_t j = start; j < start + len; j++) {
                int32_t t = w[j];
                w[j] = t + w[j + len];
                w[j + len] = t - w[j + len];
                w[j + len] = MLDSA_MontgomeryReduce((int64_t)zeta * w[j + len]);
            }
            start = start + 2 * len;
        }
    }

    for (uint32_t j = 0; j < MLDSA_N; j++) {
        w[j] = MLDSA_MontgomeryReduce((int64_t)f * w[j]);
    }
}

#endif
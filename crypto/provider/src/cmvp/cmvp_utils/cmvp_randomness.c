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
#if defined(HITLS_CRYPTO_CMVP_SM) || defined(HITLS_CRYPTO_CMVP_FIPS)

#include <math.h>
#include <float.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_log_internal.h"
#include "bsl_binlog_id.h"
#include "crypt_errno.h"
#include "crypt_cmvp.h"

#define ALPHA (0.01)
#define MAXITERTIMES 1e5
#define BITSPERBYTE 8

static uint8_t *Byte2Bits(const uint8_t *data, uint32_t len)
{
    if (data == NULL || len == 0) {
        return NULL;
    }
    uint8_t *bits = BSL_SAL_Malloc(sizeof(uint8_t) * (len * BITSPERBYTE));
    if (bits == NULL) {
        return NULL;
    }
    for (uint32_t i = 0; i < len; i++) {
        uint32_t j = i * 8;
        bits[j + 7] = data[i] & 0x01;         // bit0 offset 7
        bits[j + 6] = (data[i] >> 1) & 0x01;  // bit1 offset 6
        bits[j + 5] = (data[i] >> 2) & 0x01;  // bit2 offset 5
        bits[j + 4] = (data[i] >> 3) & 0x01;  // bit3 offset 4
        bits[j + 3] = (data[i] >> 4) & 0x01;  // bit4 offset 3
        bits[j + 2] = (data[i] >> 5) & 0x01;  // bit5 offset 2
        bits[j + 1] = (data[i] >> 6) & 0x01;  // bit6 offset 1
        bits[j] = (data[i] >> 7) & 0x01;      // bit7 offset 0
    }
    return bits;
}

static double IgammaFraction(double a, double x);
static double IgammaSeries(double a, double x);

// Upper Incomplete Gamma Function
static double Igamc(double a, double x)
{
    if (a <= 0 || x <= 0) {
        return 1.0;
    }

    if (x < a + 1.0) {
        return  1.0 - IgammaSeries(a, x);
    } else {
        return IgammaFraction(a, x);
    }
}

// Evaluate upper igamma by continued fraction
// use Lentz's algorithm to calculate the continued fraction
// where ak = k(a - k), bk = (x - a + 2k + 1)
// define
// C_n = b_n + a_n / C_(n-1)
// D_n = 1 / (b_n + a_n * D_(n - 1))
// then f_n = C_n * D_n * f_n-1 converges to Igamc
// see https://en.wikipedia.org/wiki/Lentz%27s_algorithm for detailed information.
static double IgammaFraction(double a, double x)
{
    double an, bn = x + 1.0 - a;
    double factor = a * log(x) - x - lgamma(a);
    if (factor >= DBL_MAX_EXP) {
        return 1.0; // float underflow
    }
    factor = exp(factor);
    double c = 1 / DBL_MIN;
    double d = 1.0 / bn;
    double prod = d;
    for (uint32_t k = 1; k < MAXITERTIMES; k++) {
        an = ((double)k) * (a - (double)k); // ak = k(a - k)
        bn += 2.0; // bk = (x - a + 2.0 * k + 1)
        c = bn + an / c;
        d = bn + an * d;
        if (fabs(c) < DBL_MIN) {
            break; // float underflow
        }
        if (fabs(d) < DBL_MIN) {
            break; // float underflow
        }
        d = 1 / d;
        prod *= (d * c);
    }
    return factor * prod;
}

// Evaluate lower incomplete gamma function by series representation
static double IgammaSeries(double a, double x)
{
    double sum = 0, bn = 1, factor, ak = a;
    factor = a * log(x) - x - lgamma(a);
    if (factor >= DBL_MAX_EXP) {
        return 0.0; // float underflow
    }
    factor = exp(factor);
    for (uint32_t k = 1; k < MAXITERTIMES; k++) {
        sum += bn;
        ak += 1;
        bn *= x / ak;
    }
    return (sum / a) * factor;
}

static uint8_t DataToIndex(const uint8_t* data, const int32_t blocklen)
{
    uint8_t s = 0;
    for (int32_t i = 0; i < blocklen; i++) {
        s += (data[i] << (blocklen - i - 1));
    }
    return s;
}

static int32_t PokerTest(const uint8_t *data, uint32_t len, int32_t blocklen)
{
    uint32_t N = len / blocklen;
    uint32_t maxComb = (uint32_t)pow(2.0, (double)blocklen);
    uint32_t *dict = BSL_SAL_Malloc(maxComb * sizeof(uint32_t));
    if (dict == NULL) {
        return CRYPT_CMVP_RANDOMNESS_ERR;
    }
    memset_s(dict, maxComb * sizeof(uint32_t), 0, maxComb * sizeof(uint32_t));
    for (uint32_t i = 0; (uint32_t)(i + blocklen) <= len; i += (uint32_t)blocklen) {
        dict[DataToIndex(data + i, blocklen)]++;
    }
    double s = 0.0;
    for (uint32_t i = 0; i < maxComb; i++) {
        s += pow(dict[i], 2); // 2: square each dict value
    }
    double v = (pow(2.0, (double)blocklen) / (double) N) * s - N;
    double pValue = Igamc(((double)maxComb - 1.0) / 2.0, v / 2.0); // p_value = igamc((2^m - 1) / 2, v / 2)
    BSL_SAL_FREE(dict);
    return pValue >= ALPHA ? CRYPT_SUCCESS : CRYPT_CMVP_RANDOMNESS_ERR;
}

static int32_t CMVP_PokerTest(const uint8_t *data, uint32_t len)
{
    if (data == NULL || len == 0) {
        return CRYPT_CMVP_RANDOMNESS_ERR;
    }
    // blocklen can be 2, 4 or 8 in GM/T 0005-2016, blocklen can't be greater than 8.
    for (int blocklen = 8; blocklen >= 2; blocklen -= 2) {
        // [n/m] >= 5 * 2^m in GM/T 0005-2016 chart B.1
        if ((uint32_t)(len / blocklen) >= 5 * pow(2, blocklen)) {
            return PokerTest(data, len, blocklen);
        }
    }
    return  CRYPT_CMVP_RANDOMNESS_ERR;
}

typedef struct {
    int32_t (*testFunc)(const uint8_t *data, uint32_t len);
    char *name;
} DRBG_TEST;

int32_t CRYPT_CMVP_RandomnessTest(const uint8_t *data, const uint32_t len)
{
    int32_t ret = CRYPT_SUCCESS;
    if (len > UINT32_MAX / BITSPERBYTE) {
        return  CRYPT_CMVP_RANDOMNESS_ERR;
    }
    uint8_t *bits = Byte2Bits(data, len);
    if (bits == NULL) {
        return  CRYPT_CMVP_RANDOMNESS_ERR;
    }
    const DRBG_TEST testList[] = {
        {CMVP_PokerTest, "POKER TEST"},
    };

    for (uint32_t i = 0; i < sizeof(testList) / sizeof(testList[0]); i++) {
        if (testList[i].testFunc != NULL && testList[i].testFunc(bits, len * BITSPERBYTE) != CRYPT_SUCCESS) {
            ret = CRYPT_CMVP_RANDOMNESS_ERR;
            break;
        }
    }
    BSL_SAL_FREE(bits);
    return ret;
}

#endif /* HITLS_CRYPTO_CMVP_SM || HITLS_CRYPTO_CMVP_FIPS */

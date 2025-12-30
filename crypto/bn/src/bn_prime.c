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
#ifdef HITLS_CRYPTO_BN_PRIME

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bn_bincal.h"
#include "bn_optimizer.h"

/*
 * Differential table of adjacent prime numbers, size = 1024
 * The times of trial division will affect whether the number enters the Miller-rabin test.
 * We consider common prime lengths: 1024, 2048, 4096, 8192 bits.
 * 1024 bits: we choose 128 try times, ref the paper of 'A Performant, Misuse-Resistant API for Primality Testing'.
 * 2048 bits: 128 try times: 1 (performance baseline)
 *            384 try times: +0.15
 *            512 try times: +0.03
 *            1024 try times: +0.16
 * 4096 bits: 1024 try times: 0.04 tps
 *            2048 try times: 0.02 tps
 * 8192 bits: 1024 try times: 0.02 tps
 *            2048 try times: 0.02 tps
 */
static const uint8_t PRIME_DIFF_TABLE[1024] = {
    0,  1,  2,  2,  4,  2,  4,  2,  4,  6,  2,  6,  4,  2,  4,  6,
    6,  2,  6,  4,  2,  6,  4,  6,  8,  4,  2,  4,  2,  4,  14, 4,
    6,  2,  10, 2,  6,  6,  4,  6,  6,  2,  10, 2,  4,  2,  12, 12,
    4,  2,  4,  6,  2,  10, 6,  6,  6,  2,  6,  4,  2,  10, 14, 4,
    2,  4,  14, 6,  10, 2,  4,  6,  8,  6,  6,  4,  6,  8,  4,  8,
    10, 2,  10, 2,  6,  4,  6,  8,  4,  2,  4,  12, 8,  4,  8,  4,
    6,  12, 2,  18, 6,  10, 6,  6,  2,  6,  10, 6,  6,  2,  6,  6,
    4,  2,  12, 10, 2,  4,  6,  6,  2,  12, 4,  6,  8,  10, 8,  10,
    8,  6,  6,  4,  8,  6,  4,  8,  4,  14, 10, 12, 2,  10, 2,  4,
    2,  10, 14, 4,  2,  4,  14, 4,  2,  4,  20, 4,  8,  10, 8,  4,
    6,  6,  14, 4,  6,  6,  8,  6,  12, 4,  6,  2,  10, 2,  6,  10,
    2,  10, 2,  6,  18, 4,  2,  4,  6,  6,  8,  6,  6,  22, 2,  10,
    8,  10, 6,  6,  8,  12, 4,  6,  6,  2,  6,  12, 10, 18, 2,  4,
    6,  2,  6,  4,  2,  4,  12, 2,  6,  34, 6,  6,  8,  18, 10, 14,
    4,  2,  4,  6,  8,  4,  2,  6,  12, 10, 2,  4,  2,  4,  6,  12,
    12, 8,  12, 6,  4,  6,  8,  4,  8,  4,  14, 4,  6,  2,  4,  6,
    2,  6,  10, 20, 6,  4,  2,  24, 4,  2,  10, 12, 2,  10, 8,  6,
    6,  6,  18, 6,  4,  2,  12, 10, 12, 8,  16, 14, 6,  4,  2,  4,
    2,  10, 12, 6,  6,  18, 2,  16, 2,  22, 6,  8,  6,  4,  2,  4,
    8,  6,  10, 2,  10, 14, 10, 6,  12, 2,  4,  2,  10, 12, 2,  16,
    2,  6,  4,  2,  10, 8,  18, 24, 4,  6,  8,  16, 2,  4,  8,  16,
    2,  4,  8,  6,  6,  4,  12, 2,  22, 6,  2,  6,  4,  6,  14, 6,
    4,  2,  6,  4,  6,  12, 6,  6,  14, 4,  6,  12, 8,  6,  4,  26,
    18, 10, 8,  4,  6,  2,  6,  22, 12, 2,  16, 8,  4,  12, 14, 10,
    2,  4,  8,  6,  6,  4,  2,  4,  6,  8,  4,  2,  6,  10, 2,  10,
    8,  4,  14, 10, 12, 2,  6,  4,  2,  16, 14, 4,  6,  8,  6,  4,
    18, 8,  10, 6,  6,  8,  10, 12, 14, 4,  6,  6,  2,  28, 2,  10,
    8,  4,  14, 4,  8,  12, 6,  12, 4,  6,  20, 10, 2,  16, 26, 4,
    2,  12, 6,  4,  12, 6,  8,  4,  8,  22, 2,  4,  2,  12, 28, 2,
    6,  6,  6,  4,  6,  2,  12, 4,  12, 2,  10, 2,  16, 2,  16, 6,
    20, 16, 8,  4,  2,  4,  2,  22, 8,  12, 6,  10, 2,  4,  6,  2,
    6,  10, 2,  12, 10, 2,  10, 14, 6,  4,  6,  8,  6,  6,  16, 12,
    2,  4,  14, 6,  4,  8,  10, 8,  6,  6,  22, 6,  2,  10, 14, 4,
    6,  18, 2,  10, 14, 4,  2,  10, 14, 4,  8,  18, 4,  6,  2,  4,
    6,  2,  12, 4,  20, 22, 12, 2,  4,  6,  6,  2,  6,  22, 2,  6,
    16, 6,  12, 2,  6,  12, 16, 2,  4,  6,  14, 4,  2,  18, 24, 10,
    6,  2,  10, 2,  10, 2,  10, 6,  2,  10, 2,  10, 6,  8,  30, 10,
    2,  10, 8,  6,  10, 18, 6,  12, 12, 2,  18, 6,  4,  6,  6,  18,
    2,  10, 14, 6,  4,  2,  4,  24, 2,  12, 6,  16, 8,  6,  6,  18,
    16, 2,  4,  6,  2,  6,  6,  10, 6,  12, 12, 18, 2,  6,  4,  18,
    8,  24, 4,  2,  4,  6,  2,  12, 4,  14, 30, 10, 6,  12, 14, 6,
    10, 12, 2,  4,  6,  8,  6,  10, 2,  4,  14, 6,  6,  4,  6,  2,
    10, 2,  16, 12, 8,  18, 4,  6,  12, 2,  6,  6,  6,  28, 6,  14,
    4,  8,  10, 8,  12, 18, 4,  2,  4,  24, 12, 6,  2,  16, 6,  6,
    14, 10, 14, 4,  30, 6,  6,  6,  8,  6,  4,  2,  12, 6,  4,  2,
    6,  22, 6,  2,  4,  18, 2,  4,  12, 2,  6,  4,  26, 6,  6,  4,
    8,  10, 32, 16, 2,  6,  4,  2,  4,  2,  10, 14, 6,  4,  8,  10,
    6,  20, 4,  2,  6,  30, 4,  8,  10, 6,  6,  8,  6,  12, 4,  6,
    2,  6,  4,  6,  2,  10, 2,  16, 6,  20, 4,  12, 14, 28, 6,  20,
    4,  18, 8,  6,  4,  6,  14, 6,  6,  10, 2,  10, 12, 8,  10, 2,
    10, 8,  12, 10, 24, 2,  4,  8,  6,  4,  8,  18, 10, 6,  6,  2,
    6,  10, 12, 2,  10, 6,  6,  6,  8,  6,  10, 6,  2,  6,  6,  6,
    10, 8,  24, 6,  22, 2,  18, 4,  8,  10, 30, 8,  18, 4,  2,  10,
    6,  2,  6,  4,  18, 8,  12, 18, 16, 6,  2,  12, 6,  10, 2,  10,
    2,  6,  10, 14, 4,  24, 2,  16, 2,  10, 2,  10, 20, 4,  2,  4,
    8,  16, 6,  6,  2,  12, 16, 8,  4,  6,  30, 2,  10, 2,  6,  4,
    6,  6,  8,  6,  4,  12, 6,  8,  12, 4,  14, 12, 10, 24, 6,  12,
    6,  2,  22, 8,  18, 10, 6,  14, 4,  2,  6,  10, 8,  6,  4,  6,
    30, 14, 10, 2,  12, 10, 2,  16, 2,  18, 24, 18, 6,  16, 18, 6,
    2,  18, 4,  6,  2,  10, 8,  10, 6,  6,  8,  4,  6,  2,  10, 2,
    12, 4,  6,  6,  2,  12, 4,  14, 18, 4,  6,  20, 4,  8,  6,  4,
    8,  4,  14, 6,  4,  14, 12, 4,  2,  30, 4,  24, 6,  6,  12, 12,
    14, 6,  4,  2,  4,  18, 6,  12, 8,  6,  4,  12, 2,  12, 30, 16,
    2,  6,  22, 14, 6,  10, 12, 6,  2,  4,  8,  10, 6,  6,  24, 14
};

/* Times of trial division. */
static uint32_t DivisorsCnt(uint32_t bits)
{
    if (bits <= 1024) { /* 1024bit */
        return 512; /* 512 times check */
    }
    return 1024; /* 1024 times check */
}

// Minimum times of checking for Miller-Rabin.
// The probability of errors in a check is one quarter. After 64 rounds of check, the error rate is 2 ^ - 128.
static uint32_t MinChecks(uint32_t bits)
{
    if (bits >= 2048) { /* 2048bit */
        return 128; /* 128 rounds of verification */
    }
    return 64; /* 64 rounds of verification */
}

/* A BigNum mod a limb, limb < (1 << (BN_UINT_BITS >> 1)) */
static BN_UINT ModLimbHalf(const BN_BigNum *a, BN_UINT w)
{
    BN_UINT rem = 0;
    uint32_t  i;
    for (i = a->size; i > 0; i--) {
        MOD_HALF(rem, rem, a->data[i - 1], w);
    }
    return rem;
}
static int32_t LimbCheck(const BN_BigNum *bn)
{
    uint32_t bits = BN_Bits(bn);
    uint32_t cnt = DivisorsCnt(bits);
    int32_t ret = CRYPT_SUCCESS;
    BN_UINT littlePrime = 2;
    for (uint32_t i = 0; i < cnt; i++) {
        // Try division. Large prime numbers do not divide small prime numbers.
        littlePrime += PRIME_DIFF_TABLE[i];
        BN_UINT mod = ModLimbHalf(bn, littlePrime);
        if (mod == 0) {
            if (BN_IsLimb(bn, littlePrime) == false) { // small prime judgement
                ret = CRYPT_BN_NOR_CHECK_PRIME;
            }
            break;
        }
    }
    return ret;
}
/* The random number increases by 2 each time, and added for n times,
   so that it is mutually primed to all data in the prime table. */
static int32_t FillUp(BN_BigNum *rnd, const BN_UINT *mods, uint32_t modsLen)
{
    uint32_t i;
    uint32_t complete = 0;
    uint32_t bits = BN_Bits(rnd);
    uint32_t cnt = modsLen;
    BN_UINT inc = 0;
    while (complete == 0) {
        BN_UINT littlePrime = 2; // the minimum prime = 2
        for (i = 1; i < cnt; i++) {
            /* check */
            littlePrime += PRIME_DIFF_TABLE[i];
            if ((mods[i] + inc) % littlePrime == 0) {
                inc += 2; // inc increases by 2 each time
                break;
            }
            if (i == cnt - 1) { // end and exit
                complete = 1;
            }
        }
        if (inc + 2 == 0) { // inc increases by 2 each time. Check whether the inc may overflow.
            BSL_ERR_PUSH_ERROR(CRYPT_BN_NOR_CHECK_PRIME);
            return CRYPT_BN_NOR_CHECK_PRIME;
        }
    }
    int32_t ret = BN_AddLimb(rnd, rnd, inc);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // If the random number length of a prime number is incorrect, generate a new random number.
    if (BN_Bits(rnd) != bits) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_NOR_CHECK_PRIME);
        return CRYPT_BN_NOR_CHECK_PRIME;
    }
    return CRYPT_SUCCESS;
}

/* Generate random numbers that can be mutually primed with the data in the small prime number table. */
static int32_t ProbablePrime(BN_BigNum *rnd, BN_BigNum *e, uint32_t bits, bool half, BN_Optimizer *opt)
{
    const int32_t maxCnt = 100; /* try 100 times */
    int32_t tryCnt = 0;
    uint32_t i;
    uint32_t cnt = DivisorsCnt(bits);
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BN_BigNum *mods = OptimizerGetBn(opt, cnt);
    if (mods == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }

    uint32_t top = ((half == true) ? BN_RAND_TOP_TWOBIT : BN_RAND_TOP_ONEBIT);
    do {
        tryCnt++;
        if (tryCnt > maxCnt) {
            /* If it cannot be generated after loop 100 times, a failure message is returned. */
            OptimizerEnd(opt);
            /* In this case, the random number may be incorrect. Keep the error information. */
            BSL_ERR_PUSH_ERROR(CRYPT_BN_NOR_GEN_PRIME);
            return CRYPT_BN_NOR_GEN_PRIME;
        }
        // 'top' can control whether to set the most two significant bits to 1.
        // RSA key generation usually focuses on this parameter to ensure the length of p*q.
        ret = BN_RandEx(opt->libCtx, rnd, bits, top, BN_RAND_BOTTOM_ONEBIT);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            OptimizerEnd(opt);
            return ret;
        }
        BN_UINT littlePrime = 2; // the minimum prime = 2
        // Random number rnd divided by the prime number in the table of small prime numbers, modulo mods.
        for (i = 1; i < cnt; i++) {
            littlePrime += PRIME_DIFF_TABLE[i];
            mods->data[i] = ModLimbHalf(rnd, littlePrime);
        }
        // Check the mods and supplement the rnd.
        ret = FillUp(rnd, mods->data, cnt);
        if (ret != CRYPT_BN_NOR_CHECK_PRIME && ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            OptimizerEnd(opt);
            return ret;
        }
        if (ret != CRYPT_BN_NOR_CHECK_PRIME && e != NULL) {
            // check if rnd-1 and e are coprime
            // reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf A.1.3
            BN_BigNum *rnd1 = OptimizerGetBn(opt, BITS_TO_BN_UNIT(bits));
            BN_BigNum *inv = OptimizerGetBn(opt, e->size);
            if (rnd1 == NULL || inv == NULL) {
                OptimizerEnd(opt);
                BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
                return CRYPT_BN_OPTIMIZER_GET_FAIL;
            }
            ret = BN_SubLimb(rnd1, rnd, 1);
            if (ret != CRYPT_SUCCESS) {
                OptimizerEnd(opt);
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            ret = BN_ModInv(inv, rnd1, e, opt);
        }
    } while (ret == CRYPT_BN_NOR_CHECK_PRIME);
    OptimizerEnd(opt);
    return ret;
}

static int32_t BnCheck(const BN_BigNum *bnSubOne, const BN_BigNum *bnSubThree,
    const BN_BigNum *divisor, const BN_BigNum *rnd, const BN_Mont *mont)
{
    if (bnSubOne == NULL || bnSubThree == NULL || divisor == NULL || rnd == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    if (mont == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t GenRnd(void *libCtx, BN_BigNum *rnd, const BN_BigNum *bnSubThree)
{
    int32_t ret = BN_RandRangeEx(libCtx, rnd, bnSubThree);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return BN_AddLimb(rnd, rnd, 2); /* bn - 3 + 2 = bn - 1 */
}
static bool SumCorrect(BN_BigNum *sum, const BN_BigNum *bnSubOne)
{
    if (BN_IsOne(sum) || BN_Cmp(sum, bnSubOne) == 0) {
        (void)BN_SetLimb(sum, 1);
        return true;
    }
    return false;
}
int32_t MillerRabinCheckCore(const BN_BigNum *bn, BN_Mont *mont, BN_BigNum *rnd,
    const BN_BigNum *divisor, const BN_BigNum *bnSubOne, const BN_BigNum *bnSubThree,
    uint32_t p, uint32_t checkTimes, BN_Optimizer *opt, BN_CbCtx *cb)
{
    uint32_t i, j;
    int32_t ret = CRYPT_SUCCESS;
    uint32_t checks = (checkTimes == 0) ? MinChecks(BN_Bits(bn)) : checkTimes;
    BN_BigNum *sum = rnd;
    for (i = 0; i < checks; i++) {
        // 3.1  Generate a random number rnd, 2 < rnd < n-1
        ret = GenRnd(opt->libCtx, rnd, bnSubThree);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        // 3.2 Calculate base = rnd^divisor mod bn
        ret = BN_MontExp(sum, rnd, divisor, mont, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        for (j = 0; j < p; j++) {
            // If sum is equal to 1 or bn-1, the modulus square result must be 1. Exit directly.
            if (SumCorrect(sum, bnSubOne)) {
                break;
            }
            // sum < bn
            ret = MontSqrCore(sum, sum, mont, opt);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            // Inverse negation of Miller Rabin's theorem, if equal to 1, bn is not a prime number.
            if (BN_IsOne(sum)) {
                ret = CRYPT_BN_NOR_CHECK_PRIME;
                return ret;
            }
        }
        // 3.4 Fermat's little theorem inverse negation if sum = rnd^(bn -1) != 1 mod bn, bn is not a prime number.
        if (!BN_IsOne(sum)) {
            ret = CRYPT_BN_NOR_CHECK_PRIME;
            return ret;
        }
#ifdef HITLS_CRYPTO_BN_CB
        ret = BN_CbCtxCall(cb, 0, 0);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
#else
        (void)cb;
#endif
    }
    return ret;
}
static int32_t BnSubGet(BN_BigNum *bnSubOne, BN_BigNum *bnSubThree, const BN_BigNum *bn)
{
    int32_t ret = BN_SubLimb(bnSubOne, bn, 1); /* bn - 1 */
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return BN_SubLimb(bnSubThree, bn, 3); /* bn - 3 */
}
static int32_t PrimeLimbCheck(const BN_BigNum *bn)
{
    if (BN_IsLimb(bn, 2) || BN_IsLimb(bn, 3)) { /* 2 and 3 directly determine that the number is a prime number. */
        return CRYPT_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(CRYPT_BN_NOR_CHECK_PRIME);
    return CRYPT_BN_NOR_CHECK_PRIME;
}
static uint32_t GetP(const BN_BigNum *bn)
{
    uint32_t p = 0;
    while (!BN_GetBit(bn, p)) {
        p++;
    }
    return p;
}
// CRYPT_SUCCESS is returned for a prime number,
// and CRYPT_BN_NOR_CHECK_PRIME is returned for a non-prime number. Other error codes are returned.
static int32_t MillerRabinPrimeVerify(const BN_BigNum *bn, uint32_t checkTimes, BN_Optimizer *opt, BN_CbCtx *cb)
{
    int32_t ret = CRYPT_SUCCESS;
    uint32_t p;
    if (PrimeLimbCheck(bn) == CRYPT_SUCCESS) { /* 2 and 3 directly determine that the number is a prime number. */
        return CRYPT_SUCCESS;
    }
    if (!BN_GetBit(bn, 0)) { // even
        BSL_ERR_PUSH_ERROR(CRYPT_BN_NOR_CHECK_PRIME);
        return CRYPT_BN_NOR_CHECK_PRIME;
    }
    ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BN_BigNum *bnSubOne = OptimizerGetBn(opt, bn->size);   // bnSubOne = bn - 1
    BN_BigNum *bnSubThree = OptimizerGetBn(opt, bn->size); // bnSubThree = bn - 3
    BN_BigNum *divisor = OptimizerGetBn(opt, bn->size); // divisor = bnSubOne / 2^p
    BN_BigNum *rnd = OptimizerGetBn(opt, bn->size); // rnd to verify bn
    BN_Mont *mont = BN_MontCreate(bn);

    ret = BnCheck(bnSubOne, bnSubThree, divisor, rnd, mont);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto err;
    }
    ret = BnSubGet(bnSubOne, bnSubThree, bn);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto err;
    }
    // 1. Extract the power p of factor 2 in bnSubOne.
    p = GetP(bnSubOne);
    // 2. Number after factor 2 is extracted by bnSubOne. divisor = (bn - 1) / 2^p
    ret = BN_Rshift(divisor, bnSubOne, p);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto err;
    }
    ret = MillerRabinCheckCore(bn, mont, rnd, divisor, bnSubOne, bnSubThree, p, checkTimes, opt, cb);
err:
    BN_MontDestroy(mont);
    OptimizerEnd(opt);
    return ret;
}

// CRYPT_SUCCESS is returned for a prime number,
// and CRYPT_BN_NOR_CHECK_PRIME is returned for a non-prime number. Other error codes are returned.
int32_t BN_PrimeCheck(const BN_BigNum *bn, uint32_t checkTimes, BN_Optimizer *opt, BN_CbCtx *cb)
{
    if (bn == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    // Check whether the value is 0 or 1.
    if (BN_IsZero(bn) || BN_IsOne(bn)) {
        return CRYPT_BN_NOR_CHECK_PRIME;
    }
    // Check whether the number is negative.
    if (bn->sign == 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_NOR_CHECK_PRIME);
        return CRYPT_BN_NOR_CHECK_PRIME;
    }
    ret = LimbCheck(bn);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
#ifdef HITLS_CRYPTO_BN_CB
    ret = BN_CbCtxCall(cb, 0, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
#endif
    return MillerRabinPrimeVerify(bn, checkTimes, opt, cb);
}
static int32_t GenPrimeLimb(BN_BigNum *bn, uint32_t bits, bool half, BN_Optimizer *opt)
{
    const BN_UINT baseAll[11]  = {0, 2, 4, 6, 11, 18, 31, 54, 97,  172, 309};
    const BN_UINT cntAll[11]   = {2, 2, 2, 5, 7,  13, 23, 43, 75,  137, 255};
    const BN_UINT baseHalf[11] = {1, 3, 5, 9, 15, 24, 43, 76, 135, 242, 439};
    const BN_UINT cntHalf[11]  = {1, 1, 1, 2, 3,  7,  11, 21, 37,  67,  125};
    const BN_UINT *base = baseAll;
    const BN_UINT *cnt = cntAll;
    if (half == true) {
        base = baseHalf;
        cnt = cntHalf;
    }
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_BigNum *bnCnt = OptimizerGetBn(opt, BITS_TO_BN_UNIT(bits));
    BN_BigNum *bnRnd = OptimizerGetBn(opt, BITS_TO_BN_UNIT(bits));
    if (bnCnt == NULL || bnRnd == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    (void)BN_SetLimb(bnCnt, cnt[bits - 2]); /* offset, the minimum bit of the interface is 2. */
    ret = BN_RandRangeEx(opt->libCtx, bnRnd, bnCnt);
    if (ret != CRYPT_SUCCESS) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_UINT rnd = bnRnd->data[0] + base[bits - 2]; /* offset, the minimum bit of the interface is 2. */
    OptimizerEnd(opt);
    BN_UINT littlePrime = 2;
    for (BN_UINT i = 1; i <= rnd; i++) {
        littlePrime += PRIME_DIFF_TABLE[i];
    }
    return BN_SetLimb(bn, littlePrime);
}
static int32_t GenCheck(BN_BigNum *bn, uint32_t bits, const BN_Optimizer *opt)
{
    if (bn == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (bits < 2) { // The number of bits less than 2 can only be 0 or 1. The prime number cannot be generated.
        BSL_ERR_PUSH_ERROR(CRYPT_BN_NOR_CHECK_PRIME);
        return CRYPT_BN_NOR_CHECK_PRIME;
    }
    return BnExtend(bn, BITS_TO_BN_UNIT(bits));
}

// If the prime number r is generated successfully, CRYPT_SUCCESS is returned.
// If the prime number r fails to be generated, CRYPT_BN_NOR_GEN_PRIME is returned. Other error codes are returned.
// If half is 1, the prime number whose two most significant bits are 1 is generated.
int32_t BN_GenPrime(BN_BigNum *r, BN_BigNum *e, uint32_t bits, bool half, BN_Optimizer *opt, BN_CbCtx *cb)
{
    int32_t time = 0;
#ifndef HITLS_CRYPTO_BN_CB
    (void)cb;
#endif
    int32_t ret = GenCheck(r, bits, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (bits < 13) { // < 13 is limited by the small prime table of 1024 size.
        return GenPrimeLimb(r, bits, half, opt);
    }
    ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /* To preventing insufficient space in addition operations when the rnd is constructed. */
    BN_BigNum *rnd = OptimizerGetBn(opt, BITS_TO_BN_UNIT(bits) + 1);
    if (rnd == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    do {
#ifdef HITLS_CRYPTO_BN_CB
        if (BN_CbCtxCall(cb, time, 0) != CRYPT_SUCCESS) {
            OptimizerEnd(opt);
            BSL_ERR_PUSH_ERROR(CRYPT_BN_NOR_GEN_PRIME);
            return CRYPT_BN_NOR_GEN_PRIME;
        }
#endif
        // Generate a random number bn that may be a prime.
        ret = ProbablePrime(rnd, e, bits, half, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            OptimizerEnd(opt);
            return ret;
        }
        ret = MillerRabinPrimeVerify(rnd, 0, opt, cb);
        time++;
    } while (ret != CRYPT_SUCCESS);

    OptimizerEnd(opt);
    return BN_Copy(r, rnd);
}
#endif /* HITLS_CRYPTO_BN_PRIME */

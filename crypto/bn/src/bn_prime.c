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
#ifdef HITLS_CRYPTO_BN

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "bn_bincal.h"
#include "bn_optimizer.h"


// small prime number table
static BN_UINT g_primesTable[2048];
static BN_UINT PrimeLimbGen(BN_UINT base, int32_t len)
{
    BN_UINT n = base;
    int32_t i;
    do {
        n += 2; /* Ensure that n is an odd number by adding 2 each time. */
        for (i = 1; i < len; i++) {
            if ((n % g_primesTable[i]) == 0) {
                break;
            }
            if (i == len - 1) { // end and exit
                return n;
            }
        }
    } while (true);
    return n;
}

static void PrimeTableGen(void)
{
    static bool gen = false;
    if (gen) {
        return;
    }
    g_primesTable[0] = 2;
    g_primesTable[1] = 3;
    int32_t i;
    for (i = 2; i < 2048; i++) {
        g_primesTable[i] = PrimeLimbGen(g_primesTable[i - 1], i);
    }
    gen = true;
}

// Minimum times of checking for Miller-Rabin.
// The probability of errors in a check is one quarter. After 64 rounds of check, the error rate is 2 ^ - 128.
static uint32_t MinChecks(uint32_t bits)
{
    if (bits >= 2048) {
        return 128;
    }
    return 64;
}

// Try division, divided by the number of prime numbers.
static uint32_t DivisorsCnt(uint32_t bits)
{
    if (bits <= 512) {
        return 256;
    }
    if (bits <= 1024) {
        return 512;
    }
    if (bits <= 2048) {
        return 1024;
    }
    return 2048;
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
    uint32_t i;
    uint32_t bits = BN_Bits(bn);
    uint32_t cnt = DivisorsCnt(bits);
    int32_t ret = CRYPT_SUCCESS;

    for (i = 0; i < cnt; i++) {
        // Try division. Large prime numbers do not divide small prime numbers.
        BN_UINT mod = ModLimbHalf(bn, g_primesTable[i]);
        if (mod == 0) {
            if (BN_IsLimb(bn, g_primesTable[i]) == false) { // small prime judgement
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
        for (i = 1; i < cnt; i++) {
            if ((mods[i] + inc) % g_primesTable[i] == 0) {
                inc += 2;
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
static int32_t ProbablePrime(BN_BigNum *rnd, uint32_t bits, bool half, BN_Optimizer *opt)
{
    const int32_t maxCnt = 100;
    int32_t tryCnt = 0;
    uint32_t i;
    int32_t ret;
    uint32_t cnt = DivisorsCnt(bits);
    ret = OptimizerStart(opt);
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
        ret = BN_Rand(rnd, bits, top, BN_RAND_BOTTOM_ONEBIT);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            OptimizerEnd(opt);
            return ret;
        }
        // Random number rnd divided by the prime number in the table of small prime numbers, modulo mods.
        for (i = 1; i < cnt; i++) {
            mods->data[i] = ModLimbHalf(rnd, g_primesTable[i]);
        }
        // Check the mods and supplement the rnd.
        ret = FillUp(rnd, mods->data, cnt);
        if (ret != CRYPT_BN_NOR_CHECK_PRIME && ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            OptimizerEnd(opt);
            return ret;
        }
    } while (ret == CRYPT_BN_NOR_CHECK_PRIME);
    OptimizerEnd(opt);
    return ret;
}

static int32_t BnCheck(const BN_BigNum *bnSubOne, const BN_BigNum *bnSubThree,
    const BN_BigNum *divisor, const BN_BigNum *rnd, const BN_Mont *mont)
{
    bool isNull = (bnSubOne == NULL || bnSubThree == NULL || divisor == NULL || rnd == NULL);
    if (isNull) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    if (mont == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t GenRnd(BN_BigNum *rnd, const BN_BigNum *bnSubThree)
{
    int32_t ret = BN_RandRange(rnd, bnSubThree);
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
    uint32_t p, BN_Optimizer *opt)
{
    uint32_t i, j;
    int32_t ret = CRYPT_SUCCESS;
    uint32_t checks = MinChecks(BN_Bits(bn));
    BN_BigNum *sum = rnd;
    for (i = 0; i < checks; i++) {
        // 3.1  Generate a random number rnd, 2 < rnd < n-1
        ret = GenRnd(rnd, bnSubThree);
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
            ret = BN_ModSqr(sum, sum, bn, opt);
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
    ret = BN_SubLimb(bnSubThree, bn, 3); /* bn - 3 */
    return ret;
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
static int32_t MillerRabinPrimeVerify(const BN_BigNum *bn, BN_Optimizer *opt)
{
    uint32_t p;
    if (PrimeLimbCheck(bn) == CRYPT_SUCCESS) { /* 2 and 3 directly determine that the number is a prime number. */
        return CRYPT_SUCCESS;
    }
    if (!BN_GetBit(bn, 0)) { // even
        BSL_ERR_PUSH_ERROR(CRYPT_BN_NOR_CHECK_PRIME);
        return CRYPT_BN_NOR_CHECK_PRIME;
    }
    int32_t ret = OptimizerStart(opt);
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
        goto EXIT;
    }
    ret = BnSubGet(bnSubOne, bnSubThree, bn);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    // 1. Extract the power p of factor 2 in bnSubOne.
    p = GetP(bnSubOne);
    // 2. Number after factor 2 is extracted by bnSubOne. divisor = (bn - 1) / 2^p
    ret = BN_Rshift(divisor, bnSubOne, p);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = MillerRabinCheckCore(bn, mont, rnd, divisor, bnSubOne, bnSubThree, p, opt);
EXIT:
    BN_MontDestroy(mont);
    OptimizerEnd(opt);
    return ret;
}

// CRYPT_SUCCESS is returned for a prime number,
// and CRYPT_BN_NOR_CHECK_PRIME is returned for a non-prime number. Other error codes are returned.
int32_t BN_PrimeCheck(const BN_BigNum *bn, BN_Optimizer *opt)
{
    if (bn == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    // Check whether the value is 0 or 1.
    if (BN_IsZero(bn) || BN_IsOne(bn)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_NOR_CHECK_PRIME);
        return CRYPT_BN_NOR_CHECK_PRIME;
    }
    // Check whether the number is negative.
    if (BN_ISNEG(bn->flag)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_NOR_CHECK_PRIME);
        return CRYPT_BN_NOR_CHECK_PRIME;
    }
    PrimeTableGen(); // Generate a small prime number table.
    ret = LimbCheck(bn);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return MillerRabinPrimeVerify(bn, opt);
}

static int32_t GenPrimeLimb(BN_BigNum *bn, uint32_t bits, bool half, BN_Optimizer *opt)
{
    const BN_UINT baseAll[13]  = {0, 2, 4, 6, 11, 18, 31, 54, 97,  172, 309, 564, 1028};
    const BN_UINT cntAll[13]   = {2, 2, 2, 5, 7,  13, 23, 43, 75,  137, 255, 464, 872};
    const BN_UINT baseHalf[13] = {1, 3, 5, 9, 15, 24, 43, 76, 135, 242, 439, 801, 1469};
    const BN_UINT cntHalf[13]  = {1, 1, 1, 2, 3,  7,  11, 21, 37,  67,  125, 227, 431};
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
    ret = BN_RandRange(bnRnd, bnCnt);
    if (ret != CRYPT_SUCCESS) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_UINT rnd = bnRnd->data[0] + base[bits - 2]; /* offset, the minimum bit of the interface is 2. */
    OptimizerEnd(opt);
    return BN_SetLimb(bn, g_primesTable[rnd]);
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
    if (BnExtend(bn, BITS_TO_BN_UNIT(bits)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

// Create a new optimizer to prevent optimizer from using too much memory.
static int32_t PrimeVerifyGenPrime(const BN_BigNum *bn)
{
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = MillerRabinPrimeVerify(bn, opt);
    BN_OptimizerDestroy(opt);
    return ret;
}

// If the prime number r is generated successfully, CRYPT_SUCCESS is returned.
// If the prime number r fails to be generated, CRYPT_BN_NOR_GEN_PRIME is returned. Other error codes are returned.
// If half is 1, the prime number whose two most significant bits are 1 is generated.
int32_t BN_GenPrime(BN_BigNum *r, uint32_t bits, bool half, BN_Optimizer *opt, BN_CbCtx *cb)
{
    int32_t time = 0;
    int32_t maxTime = 256; // if cb == NULL, The maximum number of cycles is 256.
    int32_t ret = GenCheck(r, bits, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    PrimeTableGen(); // Generate a small prime number table.
    if (bits <= 14) { // The number within 14 bits is less than 17863 and can be obtained from the small prime table.
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
        if (cb == NULL && maxTime == time) {
            BSL_ERR_PUSH_ERROR(CRYPT_BN_NOR_GEN_PRIME);
            OptimizerEnd(opt);
            return CRYPT_BN_NOR_GEN_PRIME;
        }
        if (BN_CbCtxCall(cb, time, 0) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_BN_NOR_GEN_PRIME);
            OptimizerEnd(opt);
            return CRYPT_BN_NOR_GEN_PRIME;
        }
        // Generate a random number bn that may be a prime.
        ret = ProbablePrime(rnd, bits, half, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            OptimizerEnd(opt);
            return ret;
        }
        ret = PrimeVerifyGenPrime(rnd);
        time++;
    } while (ret != CRYPT_SUCCESS);

    OptimizerEnd(opt);
    return BN_Copy(r, rnd);
}
#endif /* HITLS_CRYPTO_BN */

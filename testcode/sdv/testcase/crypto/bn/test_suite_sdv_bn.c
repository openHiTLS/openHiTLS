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

/* BEGIN_HEADER */

#include <stdlib.h>
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_bn.h"
#include "bn_basic.h"
#include "crypt_eal_rand.h"
#include "crypt_util_rand.h"
#include "crypto_test_util.h"

#if defined(HITLS_SIXTY_FOUR_BITS)
#define BN_UINT_MAX UINT64_MAX
#define BN_DIGITS_MAX 65
#define DH_BN_DIGITS_MAX 129
#elif defined(HITLS_THIRTY_TWO_BITS)
#define BN_UINT_MAX UINT32_MAX
#define BN_DIGITS_MAX 65 * 2
#define DH_BN_DIGITS_MAX 129 * 2
#else
#error
#endif

#define BITS_OF_BYTE 8
#define BIGNUM_REDUNDANCY_BITS 64
#define LONG_BN_BYTES_32 32
#define SHORT_BN_BITS_128 128
#define LONG_BN_BITS_256 256
#define UINT8_MAX_NUM 255
#define BN_SIZE 1024

extern int32_t ModExpInputCheck(
    const BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e, const BN_BigNum *m, const BN_Optimizer *opt);
extern int32_t ModExpCore(BN_BigNum *x, BN_BigNum *y, const BN_BigNum *e, const BN_BigNum *m, BN_Optimizer *opt);
extern int32_t BnGcdCheckInput(const BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, const BN_Optimizer *opt);
extern int32_t InverseInputCheck(const BN_BigNum *r, const BN_BigNum *x, const BN_BigNum *m, const BN_Optimizer *opt);

static int32_t TEST_Random(uint8_t *r, uint32_t randLen)
{
    for (uint32_t i = 0; i < randLen; i++) {
        r[i] = rand() % UINT8_MAX_NUM;
    }
    return 0;
}

static int32_t TEST_RandomEx(void *libCtx, uint8_t *r, uint32_t randLen)
{
    (void) libCtx;
    for (uint32_t i = 0; i < randLen; i++) {
        r[i] = rand() % UINT8_MAX_NUM;
    }
    return 0;
}


uint32_t TEST_GetMax(uint32_t num1, uint32_t num2, uint32_t num3)
{
    uint32_t res = num1;
    res = (res > num2) ? res : num2;
    res = (res > num3) ? res : num3;
    return res;
}

BN_BigNum *TEST_VectorToBN(int sign, uint8_t *buff, uint32_t length)
{
    if (length == 0) {
        return NULL;
    }
    BN_BigNum *bn = BN_Create(length * 8);  // 8 bits per byte
    if (bn != NULL) {
        if (BN_Bin2Bn(bn, buff, length) != CRYPT_SUCCESS) {
            BN_Destroy(bn);
            bn = NULL;
        } else {
            BN_SetSign(bn, sign != 0);
        }
    }
    return bn;
}
void TEST_RegSimpleRand(void)
{
    CRYPT_RandRegist(TestSimpleRand);
}

int32_t TEST_BnTestCaseInit(void)
{
    TEST_RegSimpleRand();
    TestMemInit();
    return CRYPT_SUCCESS;
}
/* END_HEADER */

/**
 * @test   SDV_CRYPTO_BN_CREATE_API_TC001
 * @title  BN_Create: Invalid parameter.
 * @precon nan
 * @brief
 *    1. Call the BN_Create method, input parameter is BN_MAX_BITS + 1, expected result 1
 *    2. Call the BN_Create method, input parameter is 0, expected result 2
 * @expect
 *    1. Return NULL.
 *    2. Return non-NULL.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_CREATE_API_TC001(void)
{
    BN_BigNum *bn = NULL;
    TestMemInit();

    bn = BN_Create((1u << 29) + 1);  // BN_MAX_BITS + 1
    ASSERT_TRUE(bn == NULL);

    bn = BN_Create(0);
    ASSERT_TRUE(bn != NULL);
EXIT:
    BN_Destroy(bn);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_SETSIGN_API_TC001
 * @title  BN_SetSign: Test invalid parameters and normal functions.
 * @precon nan
 * @brief
 *    1. Create BN_BigNum bn, the initial value is 0.
 *    2. Call the BN_SetSign method, a is null, expected result 1
 *    3. Call the BN_SetSign method, a is bn, sign is true, expected result 2
 *    4. Set bn to 1, expected result 3
 *    5. Call the BN_SetSign method, a is bn, sign is true/false, expected result 4
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_BN_NO_NEGATIVE_ZERO
 *    3-4. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_SETSIGN_API_TC001(void)
{
    BN_BigNum *bn = NULL;
    TestMemInit();
    ASSERT_TRUE(BN_SetSign(NULL, 0) == CRYPT_NULL_INPUT);

    bn = BN_Create(BN_MAX_BITS);
    ASSERT_TRUE(bn != NULL);
    ASSERT_TRUE(BN_SetSign(bn, true) == CRYPT_BN_NO_NEGATIVE_ZERO);

    ASSERT_TRUE(BN_SetLimb(bn, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetSign(bn, false) == CRYPT_SUCCESS);
EXIT:
    BN_Destroy(bn);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_COPY_API_TC001
 * @title  BN_Copy: The dest parameter space is smaller than src parameter.
 * @precon nan
 * @brief
 *    1. Call the BN_Copy method, parameters are all, expected result 1
 *    2. Create BN_BigNum bn a and r, the size of r is half of a, expected result 2
 *    3. Call the BN_Copy method, copy a to r, expected result 3
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS(Big number can be automatically expanded.)
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_COPY_API_TC001(void)
{
    BN_BigNum *r = NULL;
    BN_BigNum *a = NULL;
    uint8_t buff[LONG_BN_BYTES_32] = {'F'};

    TestMemInit();
    ASSERT_TRUE(BN_Copy(NULL, NULL) == CRYPT_NULL_INPUT);

    // r.room < a.bits
    r = BN_Create(SHORT_BN_BITS_128);
    ASSERT_TRUE(r != NULL);
    // SHORT_BN_BYTES 16 = 32 / 2
    ASSERT_TRUE(BN_Bin2Bn(r, buff, sizeof(buff) / 2) == CRYPT_SUCCESS);

    a = BN_Create(LONG_BN_BITS_256);
    ASSERT_TRUE(a != NULL);
    ASSERT_TRUE(BN_Bin2Bn(a, buff, sizeof(buff)) == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_Copy(r, a) == CRYPT_SUCCESS);

EXIT:
    BN_Destroy(r);
    BN_Destroy(a);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_ZEROIZE_API_TC001
 * @title  BN_Zeroize: Invalid parameter.
 * @precon nan
 * @brief
 *    1. Call the BN_Zeroize, parameter is null, expected result 1
 * @expect
 *    1. CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_ZEROIZE_API_TC001(void)
{
    ASSERT_TRUE(BN_Zeroize(NULL) == CRYPT_NULL_INPUT);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_SETLIMB_API_TC001
 * @title  BN_SetLimb: Test invalid parameters and normal functions.
 * @precon nan
 * @brief
 *    1. Create BN_BigNum bn.
 *    2. Call the BN_SetLimb method, r is null, w is 0, expected result 1
 *    3. Call the BN_SetLimb method, r is bn, w is 0, expected result 2
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_SETLIMB_API_TC001(void)
{
    TestMemInit();
    BN_BigNum *bn = BN_Create(1);

    ASSERT_TRUE(BN_SetLimb(NULL, 0) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(BN_SetLimb(bn, 0) == CRYPT_SUCCESS);
EXIT:
    BN_Destroy(bn);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_SETBIT_API_TC001
 * @title  BN_SetBit: Test invalid parameters and normal functions.
 * @precon nan
 * @brief
 *    1. Create BN_BigNum bn.
 *    2. Call the BN_SetBit method, a is null, n is 0, expected result 1
 *    3. Call the BN_SetBit method, a is bn, n is invalid, expected result 2
 *    4. Call the BN_SetBit method, a is bn, n is valid, expected result 3
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_BN_SPACE_NOT_ENOUGH
 *    2. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_SETBIT_API_TC001(void)
{
    TestMemInit();
    BN_BigNum *bn = BN_Create(1);

    ASSERT_TRUE(BN_SetBit(NULL, 0) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(BN_SetBit(bn, (uint32_t)sizeof(BN_UINT) << 3) == CRYPT_BN_SPACE_NOT_ENOUGH);
    ASSERT_TRUE(BN_SetBit(bn, ((uint32_t)sizeof(BN_UINT) << 3) - 1) == CRYPT_SUCCESS);
EXIT:
    BN_Destroy(bn);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_GETBIT_API_TC001
 * @title  BN_GetBit: Test invalid parameters and normal functions.
 * @precon nan
 * @brief
 *    1. Call the BN_GetBit method, a is null, n is 0, expected result 1
 *    2. Create BN_BigNum bn, bn = 0, expected result 2
 *    3. Call the BN_GetBit method, get the first bit of bn, expected result 3
 *    4. Set limb of bn to BN_UINT_MAX, expected result 4
 *    5. Call the BN_GetBit method, Check whether the number of the specified bit is 1:
 *       (1) bit = limbBits - 1, expected result 5
 *       (1) bit = limbBits, expected result 6
 *       (1) bit = limbBits + 1, expected result 7
 * @expect
 *    1. Return 0.
 *    2. CRYPT_SUCCESS
 *    3. The first bit of bn is 0.
 *    4. CRYPT_SUCCESS. The number of bits in the limb is limbBits.
 *    5. true
 *    6. false
 *    7. false
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_GETBIT_API_TC001(void)
{
    BN_BigNum *bn = NULL;
    const int limbBits = sizeof(BN_UINT) * BITS_OF_BYTE;

    ASSERT_TRUE(BN_GetBit(NULL, 0) == 0);

    TestMemInit();
    bn = BN_Create(SHORT_BN_BITS_128);
    ASSERT_TRUE(bn != NULL);

    // a = 0 , n = 0
    ASSERT_TRUE(BN_SetLimb(bn, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_GetBit(bn, 0) == 0);

    ASSERT_TRUE(BN_SetLimb(bn, BN_UINT_MAX) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_GetBit(bn, limbBits - 1) == true);
    ASSERT_TRUE(BN_GetBit(bn, limbBits) == false);
    ASSERT_TRUE(BN_GetBit(bn, limbBits + 1) == false);
EXIT:
    BN_Destroy(bn);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_CLRBIT_API_TC001
 * @title  BN_ClrBit: Test invalid parameters and normal functions.
 * @precon nan
 * @brief
 *    1. Call the BN_ClrBit method, a is null, n is 0, expected result 1
 *    2. Create BN_BigNum bn, and set bn to -1, expected result 2
 *    3. Call the BN_ClrBit method, set the lowest bit to 0, expected result 3
 *    4. Set bn to 1, expected result 4
 *    5. Call the BN_ClrBit method, a is bn, n is BN_UINT_BITS, expected result 5
 *    6. Call the BN_ClrBit method, a is bn, n is valid, expected result 6
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS, bn changed from - 1 to 0.
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_BN_SPACE_NOT_ENOUGH
 *    6. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_CLRBIT_API_TC001(void)
{
    BN_BigNum *bn = NULL;
    ASSERT_TRUE(BN_ClrBit(NULL, 0) == CRYPT_NULL_INPUT);

    TestMemInit();
    bn = BN_Create(BN_MAX_BITS);

    /* bn = -1 */
    ASSERT_TRUE(BN_SetLimb(bn, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetSign(bn, 1) == CRYPT_SUCCESS);

    /* Set the lowest bit to 0. */
    ASSERT_TRUE(BN_ClrBit(bn, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_IsZero(bn));
    ASSERT_TRUE(BN_IsNegative(bn) == false);

    /* bn = 1 */
    ASSERT_TRUE(BN_SetLimb(bn, 1) == CRYPT_SUCCESS);

    ASSERT_EQ(BN_ClrBit(bn, ((uint32_t)sizeof(BN_UINT) << 3)), CRYPT_BN_SPACE_NOT_ENOUGH);  // BN_UINT_BITS
    ASSERT_TRUE(BN_ClrBit(bn, ((uint32_t)sizeof(BN_UINT) << 3) - 1) == CRYPT_SUCCESS);      // BN_UINT_BITS - 1
EXIT:
    BN_Destroy(bn);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_RSHIFT_FUNC_TC001
 * @title  BN_Rshift test.
 * @precon Vectors: hex and its result after right-shifting n bits.
 * @brief
 *    1. Convert vectors to bn.
 *    2. Call BN_Rshift, and compared the result with vector, expected result 1:
 *       (1) Pointer addresses for parameters are different from each other.
 *       (2) The address of the output parameter pointer r is the same as that of the input parameter pointer a.
 *    3. Test the scenario where the output parameter space is insufficient, expected result 1.
 * @expect
 *    1. The calculation result is consistent with the vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_RSHIFT_FUNC_TC001(int sign, Hex *hex, int n, int signRes, Hex *result)
{
    TestMemInit();
    BN_BigNum *r = NULL;
    BN_BigNum *q = NULL;
    BN_BigNum *p = NULL;
    BN_BigNum *a = TEST_VectorToBN(sign, hex->x, hex->len);
    BN_BigNum *res = TEST_VectorToBN(signRes, result->x, result->len);
    ASSERT_TRUE(a != NULL && res != NULL);

    r = BN_Create(BN_Bits(a) + BIGNUM_REDUNDANCY_BITS);
    ASSERT_TRUE(r != NULL);
    ASSERT_EQ(BN_Rshift(r, a, n), CRYPT_SUCCESS);  // r != a
    ASSERT_TRUE(BN_Cmp(r, res) == 0);

    ASSERT_EQ(BN_Copy(r, a), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Rshift(r, r, n), CRYPT_SUCCESS);  // r == a
    ASSERT_TRUE(BN_Cmp(r, res) == 0);

    /* Test the scenario where the output parameter space of q is insufficient */
    q = BN_Create(0);
    ASSERT_TRUE(q != NULL);
    ASSERT_EQ(BN_Rshift(q, a, n), CRYPT_SUCCESS);  // r != a
    ASSERT_TRUE(BN_Cmp(r, res) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BN_Destroy(a);
    BN_Destroy(r);
    BN_Destroy(q);
    BN_Destroy(p);
    BN_Destroy(res);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_MODINV_API_TC001
 * @title  BN_ModInv test.
 * @precon nan
 * @brief
 *    1. Call BN_ModInv method:
 *       (1) all parameters are valid, expected result 1.
 *       (2) r is null, expected result 2.
 *       (3) a is null, expected result 3.
 *       (4) m is null, expected result 4.
 *       (5) opt is null, expected result 5.
 *       (6) a is zero or m is zero, expected result 6.
 *       (7) r.room.bits < m.bits, expected result 7.
 *       (8) r.room.bits = m.bits, expected result 8.
 *       (9) r.room.bits > m.bits, expected result 9.
 * @expect
 *    1. CRYPT_SUCCESS
 *    2-5. CRYPT_NULL_INPUT
 *    6. CRYPT_BN_ERR_DIVISOR_ZERO
 *    7-9. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_MODINV_API_TC001(void)
{
    TestMemInit();
    uint8_t buff[LONG_BN_BYTES_32];
    BN_BigNum *a = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *m = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *zero = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *r128 = BN_Create(SHORT_BN_BITS_128);
    BN_BigNum *r256 = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *r257 = BN_Create(LONG_BN_BITS_256 + 1);
    BN_Optimizer *opt = BN_OptimizerCreate();
    ASSERT_TRUE(a != NULL && m != NULL && r128 != NULL && r256 != NULL && zero != NULL && opt != NULL);
    ASSERT_TRUE(BN_IsZero(zero) == true);

    // a = FF...FF (32 bytes)
    ASSERT_TRUE(memset_s(buff, sizeof(buff), 0xFF, LONG_BN_BYTES_32) == EOK);
    ASSERT_TRUE(BN_Bin2Bn(a, buff, LONG_BN_BYTES_32) == CRYPT_SUCCESS);
    // m == FF...FD (32 bytes)
    buff[LONG_BN_BYTES_32 - 1] = (uint8_t)0xFD;
    ASSERT_TRUE(BN_Bin2Bn(m, buff, LONG_BN_BYTES_32) == CRYPT_SUCCESS);

    // NULL
    ASSERT_TRUE(BN_ModInv(r256, a, m, opt) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_ModInv(NULL, a, m, opt) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(BN_ModInv(r256, NULL, m, opt) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(BN_ModInv(r256, a, NULL, opt) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(BN_ModInv(r256, a, m, NULL) == CRYPT_NULL_INPUT);

    // zero
    ASSERT_TRUE(BN_ModInv(r256, a, zero, opt) == CRYPT_BN_ERR_DIVISOR_ZERO);
    ASSERT_TRUE(BN_ModInv(r256, zero, m, opt) == CRYPT_BN_ERR_DIVISOR_ZERO);

    // r.room.bits < m.bits
    ASSERT_TRUE(BN_ModInv(r128, a, m, opt) == CRYPT_SUCCESS);

    // r.room.bits == m.bits
    ASSERT_TRUE(BN_ModInv(r256, a, m, opt) == CRYPT_SUCCESS);

    // r.room.bits > m.bits
    ASSERT_TRUE(BN_ModInv(r257, a, m, opt) == CRYPT_SUCCESS);

EXIT:
    BN_Destroy(a);
    BN_Destroy(m);
    BN_Destroy(zero);
    BN_Destroy(r128);
    BN_Destroy(r256);
    BN_Destroy(r257);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_MODINV_FUNC_TC002
 * @title  BN_ModInv test.
 * @precon Vectors: hex1^(-1) mod modulo = result
 * @brief
 *    1. Convert vectors to bn.
 *    2. Call BN_ModInv, and compared the result with vector, expected result 1.
 *    3. If success is returned in the previous step, continue to test BN_ModInv when the output parameter address
 *       is the same as the input parameter address. expected result 2:
 *       (1) The address of the output parameter pointer r is the same as that of the input parameter pointer a.
 *       (2) The address of the output parameter pointer r is the same as that of the input parameter pointer m.
 *    4. Test the scenario where the output parameter space is insufficient, expected result 2.
 * @expect
 *    1. Reutrn CRYPT_BN_ERR_NO_INVERSE on result is null. Otherwise, CRYPT_SUCCESS and result is same with vector.
 *    2. The calculation result is consistent with the vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_MODINV_FUNC_TC002(int sign, Hex *hex, Hex *modulo, Hex *result)
{
    TestMemInit();
    int32_t ret;
    BN_BigNum *res = NULL;
    BN_BigNum *r = NULL;
    BN_Optimizer *opt = BN_OptimizerCreate();
    BN_BigNum *a = TEST_VectorToBN(sign, hex->x, hex->len);
    BN_BigNum *m = TEST_VectorToBN(0, modulo->x, modulo->len);
    ASSERT_TRUE(a != NULL && m != NULL && opt != NULL);

    r = BN_Create(BN_Bits(a) + BN_Bits(m) + BIGNUM_REDUNDANCY_BITS);
    ASSERT_TRUE(r != NULL);

    ASSERT_TRUE(BN_Copy(r, a) == CRYPT_SUCCESS);

    ret = BN_ModInv(r, a, m, opt);  // r != a
    if (result->len == 0) {
        ASSERT_TRUE(ret == CRYPT_BN_ERR_NO_INVERSE);  // No results exist
    } else {
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
        res = BN_Create(result->len * BITS_OF_BYTE);
        ASSERT_TRUE(res != NULL);

        ASSERT_TRUE(BN_Bin2Bn(res, result->x, result->len) == CRYPT_SUCCESS);

        ASSERT_TRUE(BN_Cmp(r, res) == 0);

        ASSERT_TRUE(BN_Copy(r, a) == CRYPT_SUCCESS);
        ASSERT_TRUE(BN_ModInv(r, r, m, opt) == CRYPT_SUCCESS);
        ASSERT_TRUE_AND_LOG("r == a", BN_Cmp(r, res) == 0);

        ASSERT_TRUE(BN_Copy(r, m) == CRYPT_SUCCESS);
        ASSERT_TRUE(BN_ModInv(r, a, r, opt) == CRYPT_SUCCESS);
        ASSERT_TRUE_AND_LOG("r == m", BN_Cmp(r, res) == 0);
        BN_Destroy(r);

        /* Test the scenario where the output parameter space is insufficient. */
        r = BN_Create(0);
        ASSERT_TRUE(r != NULL);
        ASSERT_TRUE(BN_ModInv(r, a, m, opt) == CRYPT_SUCCESS);
        ASSERT_TRUE(BN_Cmp(r, res) == 0);
        BN_Destroy(r);

        r = BN_Create(0);
        ASSERT_TRUE(r != NULL);
        ASSERT_TRUE(BN_Copy(r, a) == CRYPT_SUCCESS);
        ASSERT_TRUE(BN_ModInv(r, r, m, opt) == CRYPT_SUCCESS);
        ASSERT_TRUE_AND_LOG("r == a", BN_Cmp(r, res) == 0);
        BN_Destroy(r);

        r = BN_Create(0);
        ASSERT_TRUE(r != NULL);
        ASSERT_TRUE(BN_Copy(r, m) == CRYPT_SUCCESS);
        ASSERT_TRUE(BN_ModInv(r, a, r, opt) == CRYPT_SUCCESS);
        ASSERT_TRUE_AND_LOG("r == m", BN_Cmp(r, res) == 0);
        ASSERT_TRUE(TestIsErrStackEmpty());
    }

EXIT:
    BN_Destroy(a);
    BN_Destroy(m);
    BN_Destroy(r);
    BN_Destroy(res);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_MOD_EXP_INPUT_CHECK_API_TC001
 * @title  ModExpInputCheck: Test invalid parameters and normal functions.
 * @precon nan
 * @brief
 *    1. Call the ModExpInputCheck method, parameters are null,expected result 1
 *    2. Call the ModExpInputCheck method, the size of r is smaller then m, expected result 2
 *    3. Call the ModExpInputCheck method, m is 0, expected result 3
 *    4. Call the ModExpInputCheck method, e is a negative number, expected result 4
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_BN_ERR_DIVISOR_ZERO
 *    4. CRYPT_BN_ERR_EXP_NO_NEGATIVE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_MOD_EXP_INPUT_CHECK_API_TC001(void)
{
    BN_BigNum *bn = NULL;
    BN_BigNum *r = NULL;
    BN_BigNum *a = NULL;
    BN_BigNum *e = NULL;
    BN_BigNum *m = NULL;
    BN_Optimizer *opt = NULL;
    TestMemInit();

    ASSERT_TRUE(ModExpInputCheck(NULL, NULL, NULL, NULL, NULL) == CRYPT_NULL_INPUT);

    bn = BN_Create(1);
    a = BN_Create(BN_MAX_BITS);
    e = BN_Create(BN_MAX_BITS);
    opt = BN_OptimizerCreate();
    r = BN_Create(1);
    m = BN_Create(BN_MAX_BITS);
    ASSERT_TRUE(BN_SetBit(m, BN_SIZE) == CRYPT_SUCCESS);
    ASSERT_TRUE(ModExpInputCheck(r, a, e, m, opt) == CRYPT_SUCCESS);

    BN_Destroy(r);
    r = BN_Create(BN_MAX_BITS);
    ASSERT_TRUE(ModExpInputCheck(r, a, e, bn, opt) == CRYPT_BN_ERR_DIVISOR_ZERO);

    ASSERT_TRUE(BN_SetBit(e, BN_SIZE) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetSign(e, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(ModExpInputCheck(r, a, e, m, opt) == CRYPT_BN_ERR_EXP_NO_NEGATIVE);

EXIT:
    BN_Destroy(bn);
    BN_Destroy(r);
    BN_Destroy(a);
    BN_Destroy(e);
    BN_Destroy(m);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_MODEXP_API_TC001
 * @title  BN_ModExp: Test invalid parameters.
 * @precon nan
 * @brief
 *    1. Call the BN_ModExp method, parameters are null, expected result 1
 *    2. Call the BN_ModExp method, the size of r is smaller then m, expected result 2
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_MODEXP_API_TC001(void)
{
    uint8_t buff[LONG_BN_BYTES_32];
    TestMemInit();

    BN_BigNum *a = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *e = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *r = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *m = BN_Create(LONG_BN_BITS_256);
    BN_Optimizer *opt = BN_OptimizerCreate();
    ASSERT_TRUE(a != NULL);
    ASSERT_TRUE(e != NULL);
    ASSERT_TRUE(r != NULL);
    ASSERT_TRUE(m != NULL);
    ASSERT_TRUE(opt != NULL);
    ASSERT_TRUE(memset_s(buff, sizeof(buff), 0xFF, LONG_BN_BYTES_32) == EOK);

    ASSERT_TRUE(BN_Bin2Bn(a, buff, LONG_BN_BYTES_32) == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_Bin2Bn(e, buff, LONG_BN_BYTES_32) == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_Bin2Bn(m, buff, LONG_BN_BYTES_32) == CRYPT_SUCCESS);

    // NULL
    ASSERT_TRUE(BN_ModExp(NULL, NULL, NULL, NULL, NULL) == CRYPT_NULL_INPUT);

    BN_Destroy(r);
    r = BN_Create(LONG_BN_BITS_256 - BIGNUM_REDUNDANCY_BITS);
    ASSERT_TRUE(BN_ModExp(r, a, e, m, opt) == CRYPT_SUCCESS);

EXIT:
    BN_Destroy(a);
    BN_Destroy(e);
    BN_Destroy(r);
    BN_Destroy(m);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_MODEXP_API_TC002
 * @title  BN_ModExp: Invalid parameter and function test.
 * @precon nan
 * @brief
 *    1. Call the BN_ModExp method, the divisor is 0, expected result 1
 *    2. Call the BN_ModExp method, the value of the exponent is negative, expected result 2
 *    3. Call the BN_ModExp method, all parameters are valid, expected result 3
 * @expect
 *    1. CRYPT_BN_ERR_DIVISOR_ZERO
 *    2. CRYPT_BN_ERR_EXP_NO_NEGATIVE
 *    3. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_MODEXP_API_TC002(void)
{
    uint8_t buff[LONG_BN_BYTES_32];
    BN_BigNum *a = BN_Create(LONG_BN_BYTES_32 * 8);
    BN_BigNum *e = BN_Create(LONG_BN_BYTES_32 * 8);
    BN_BigNum *m = BN_Create(LONG_BN_BYTES_32 * 8);
    BN_BigNum *r = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *zero = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *one = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *negOne = BN_Create(LONG_BN_BITS_256);
    BN_Optimizer *opt = BN_OptimizerCreate();
    TestMemInit();

    ASSERT_TRUE(r != NULL);
    ASSERT_TRUE(zero != NULL);
    ASSERT_TRUE(one != NULL);
    ASSERT_TRUE(negOne != NULL);
    ASSERT_TRUE(opt != NULL);

    ASSERT_TRUE(memset_s(buff, sizeof(buff), 0xFF, LONG_BN_BYTES_32) == EOK);

    ASSERT_TRUE(a != NULL);
    ASSERT_TRUE(BN_Bin2Bn(a, buff, LONG_BN_BYTES_32) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetSign(a, false) == CRYPT_SUCCESS);

    ASSERT_TRUE(e != NULL);
    ASSERT_TRUE(BN_Bin2Bn(e, buff, LONG_BN_BYTES_32) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetSign(e, false) == CRYPT_SUCCESS);

    ASSERT_TRUE(m != NULL);
    ASSERT_TRUE(BN_Bin2Bn(m, buff, LONG_BN_BYTES_32) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetSign(m, false) == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_Zeroize(zero) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetLimb(one, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetLimb(negOne, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetSign(negOne, true) == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_ModExp(r, a, e, zero, opt) == CRYPT_BN_ERR_DIVISOR_ZERO);
    ASSERT_TRUE(BN_ModExp(r, a, negOne, m, opt) == CRYPT_BN_ERR_EXP_NO_NEGATIVE);
    ASSERT_TRUE(BN_ModExp(r, zero, zero, m, opt) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Cmp(r, one) == 0);
    ASSERT_TRUE(BN_ModExp(r, zero, zero, one, opt) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Cmp(r, zero) == 0);
    ASSERT_TRUE(BN_ModExp(r, a, e, negOne, opt) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Cmp(r, zero) == 0);

EXIT:
    BN_Destroy(a);
    BN_Destroy(e);
    BN_Destroy(r);
    BN_Destroy(m);
    BN_Destroy(zero);
    BN_Destroy(one);
    BN_Destroy(negOne);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_MODEXP_FUNC_TC001
 * @title  BN_ModExp test.
 * @precon Vectors: two big numbers, mod, result.
 * @brief
 *    1. Convert vectors to big numbers.
 *    2. Call BN_ModExp to calculate the modular exponentiation, and compared to the vector value, expected result 1:
 *       (1) Pointer addresses for parameters are different from each other.
 *       (2) The address of the output parameter pointer r is the same as that of the input parameter pointer a.
 *       (3) The address of the output parameter pointer r is the same as that of the input parameter pointer e.
 *       (4) The address of the output parameter pointer r is the same as that of the input parameter pointer m.
 *    3. Test the scenario where the output parameter space is insufficient, expected result 1.
 * @expect
 *    1. The calculation result is consistent with the vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_MODEXP_FUNC_TC001(int sign1, Hex *hex1, Hex *hex2, Hex *modulo, Hex *result)
{
    TestMemInit();
    BN_BigNum *r = NULL;
    BN_Optimizer *opt = NULL;
    uint32_t maxBits;
    BN_BigNum *res = TEST_VectorToBN(0, result->x, result->len);
    BN_BigNum *a = TEST_VectorToBN(sign1, hex1->x, hex1->len);
    BN_BigNum *e = TEST_VectorToBN(0, hex2->x, hex2->len);
    BN_BigNum *m = TEST_VectorToBN(0, modulo->x, modulo->len);
    ASSERT_TRUE(res != NULL && a != NULL && e != NULL && m != NULL);

    maxBits = TEST_GetMax(BN_Bits(a), BN_Bits(e), BN_Bits(m));
    r = BN_Create(maxBits + BIGNUM_REDUNDANCY_BITS);
    ASSERT_TRUE(r != NULL);

    opt = BN_OptimizerCreate();
    ASSERT_TRUE(opt != NULL);

    ASSERT_TRUE(BN_Copy(r, a) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_ModExp(r, a, e, m, opt) == CRYPT_SUCCESS);  // r != a
    ASSERT_TRUE_AND_LOG("r != a", BN_Cmp(r, res) == 0);

    ASSERT_TRUE(BN_Copy(r, a) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_ModExp(r, r, e, m, opt) == CRYPT_SUCCESS);  // r == a
    ASSERT_TRUE_AND_LOG("r == a", BN_Cmp(r, res) == 0);

    ASSERT_TRUE(BN_Copy(r, e) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_ModExp(r, a, r, m, opt) == CRYPT_SUCCESS);  // r == e
    ASSERT_TRUE_AND_LOG("r == e", BN_Cmp(r, res) == 0);

    ASSERT_TRUE(BN_Copy(r, m) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_ModExp(r, a, e, r, opt) == CRYPT_SUCCESS);  // r == m
    ASSERT_TRUE_AND_LOG("r == m", BN_Cmp(r, res) == 0);

    // Test the scenario where the output parameter space is insufficient.
    BN_Destroy(r);
    r = BN_Create(0);
    ASSERT_TRUE(r != NULL);

    ASSERT_TRUE(BN_ModExp(r, a, e, m, opt) == CRYPT_SUCCESS);  // r != a
    ASSERT_TRUE_AND_LOG("r != a", BN_Cmp(r, res) == 0);

    BN_Destroy(r);
    r = BN_Create(0);
    ASSERT_TRUE(r != NULL);
    ASSERT_TRUE(BN_Copy(r, a) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_ModExp(r, r, e, m, opt) == CRYPT_SUCCESS);  // r == a
    ASSERT_TRUE_AND_LOG("r == a", BN_Cmp(r, res) == 0);

    BN_Destroy(r);
    r = BN_Create(0);
    ASSERT_TRUE(r != NULL);
    ASSERT_TRUE(BN_Copy(r, e) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_ModExp(r, a, r, m, opt) == CRYPT_SUCCESS);  // r == e
    ASSERT_TRUE_AND_LOG("r == e", BN_Cmp(r, res) == 0);

    BN_Destroy(r);
    r = BN_Create(0);
    ASSERT_TRUE(r != NULL);
    ASSERT_TRUE(BN_Copy(r, m) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_ModExp(r, a, e, r, opt) == CRYPT_SUCCESS);  // r == m
    ASSERT_TRUE_AND_LOG("r == m", BN_Cmp(r, res) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BN_Destroy(a);
    BN_Destroy(e);
    BN_Destroy(m);
    BN_Destroy(r);
    BN_Destroy(res);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_MODEXPCORE_API_TC001
 * @title  ModExpCore: Invalid parameter.
 * @precon nan
 * @brief
 *    1. Call the ModExpCore method, the divisor is 0, expected result 1
 * @expect
 *    1. CRYPT_BN_ERR_DIVISOR_ZERO
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_MODEXPCORE_API_TC001(void)
{
    TestMemInit();
    BN_BigNum *a = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *e = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *r = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *m = BN_Create(LONG_BN_BITS_256);
    BN_Optimizer *opt = BN_OptimizerCreate();
    ASSERT_TRUE(BN_SetLimb(e, 10) == CRYPT_SUCCESS);
    ASSERT_TRUE(ModExpCore(r, a, e, m, opt) == CRYPT_BN_ERR_DIVISOR_ZERO);

EXIT:
    BN_Destroy(a);
    BN_Destroy(e);
    BN_Destroy(r);
    BN_Destroy(m);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_MOD_API_TC001
 * @title  BN_Mod: Invalid parameter.
 * @precon nan
 * @brief
 *    1. Call the BN_Mod method, all parameters are null, expected result 1
 *    2. Call the BN_Mod method, mod is UINT8_MAX_NUM, expected result 2
 *    3. Call the BN_Mod method, mod is 0, expected result 3
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_BN_ERR_DIVISOR_ZERO
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_MOD_API_TC001(void)
{
    TestMemInit();
    BN_BigNum *a = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *r = BN_Create(SHORT_BN_BITS_128);
    BN_BigNum *m = BN_Create(LONG_BN_BITS_256);
    BN_Optimizer *opt = BN_OptimizerCreate();

    ASSERT_TRUE(BN_Mod(NULL, NULL, NULL, NULL) == CRYPT_NULL_INPUT);

    ASSERT_TRUE(BN_SetBit(m, UINT8_MAX_NUM) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Mod(r, a, m, opt) == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_SetLimb(m, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Mod(r, a, m, opt) == CRYPT_BN_ERR_DIVISOR_ZERO);

EXIT:
    BN_Destroy(a);
    BN_Destroy(r);
    BN_Destroy(m);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_MOD_FUNC_TC001
 * @title  BN_Mod test.
 * @precon Vectors: hex1 mod module = result
 * @brief
 *    1. Convert vectors to bn.
 *    2. Call BN_Mod, and compared the result with vector, expected result 1:
 *       (1) Pointer addresses for parameters are different from each other.
 *       (2) The address of the output parameter pointer r is the same as that of the input parameter pointer a.
 *       (3) The address of the output parameter pointer r is the same as that of the input parameter pointer m.
 *    3. Test the scenario where the output parameter space is insufficient, expected result 1.
 * @expect
 *    1. The calculation result is consistent with the vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_MOD_FUNC_TC001(int sign1, Hex *hex1, int sign2, Hex *modulo, Hex *result)
{
    TestMemInit();
    BN_BigNum *r = NULL;
    BN_Optimizer *opt = NULL;

    BN_BigNum *res = TEST_VectorToBN(0, result->x, result->len);
    BN_BigNum *a = TEST_VectorToBN(sign1, hex1->x, hex1->len);
    BN_BigNum *m = TEST_VectorToBN(sign2, modulo->x, modulo->len);
    ASSERT_TRUE(a != NULL && m != NULL && res != NULL);

    r = BN_Create(BN_Bits(a) + BN_Bits(m) + BIGNUM_REDUNDANCY_BITS);
    ASSERT_TRUE(r != NULL);

    opt = BN_OptimizerCreate();
    ASSERT_TRUE(opt != NULL);

    ASSERT_EQ(BN_Copy(r, a), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Mod(r, a, m, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r != a", BN_Cmp(r, res) == 0);

    ASSERT_EQ(BN_Copy(r, a), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Mod(r, r, m, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r == a", BN_Cmp(r, res) == 0);

    ASSERT_EQ(BN_Copy(r, m), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Mod(r, a, r, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r == m", BN_Cmp(r, res) == 0);

    /* Test the scenario where the output parameter space is insufficient. */
    BN_Destroy(r);
    r = BN_Create(0);
    ASSERT_TRUE(r != NULL);

    ASSERT_EQ(BN_Mod(r, a, m, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r != a", BN_Cmp(r, res) == 0);

    ASSERT_EQ(BN_Copy(r, m), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Mod(r, a, r, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r == m", BN_Cmp(r, res) == 0);

    BN_Destroy(r);
    r = BN_Create(0);
    ASSERT_TRUE(r != NULL);

    ASSERT_EQ(BN_Copy(r, a), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Mod(r, r, m, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r == a", BN_Cmp(r, res) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BN_Destroy(a);
    BN_Destroy(m);
    BN_Destroy(r);
    BN_Destroy(res);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_PRIMECHECK_API_TC001
 * @title  BN_PrimeCheck: Invalid parameter.
 * @precon nan
 * @brief
 *    1. Create BN_BigNum bn, set the value of bn to 10, expected result 1
 *    2. Call the BN_PrimeCheck to check bn, expected result 2
 * @expect
 *    1. CRYPT_SUCCESS
 *    1. CRYPT_BN_NOR_CHECK_PRIME
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_PRIMECHECK_API_TC001(void)
{
    TestMemInit();
    BN_BigNum *bn = BN_Create(LONG_BN_BITS_256);
    BN_Optimizer *opt = BN_OptimizerCreate();

    ASSERT_TRUE(BN_SetLimb(bn, 10) == CRYPT_SUCCESS);  // bn == 10
    ASSERT_TRUE(BN_PrimeCheck(bn, 0, opt, NULL) == CRYPT_BN_NOR_CHECK_PRIME);

EXIT:
    BN_Destroy(bn);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_PRIME_CHECK_FUNC_TC001
 * @title  BN_PrimeCheck method test.
 * @precon A big number and information about whether the big number is prime.
 * @brief
 *    1. Convert hex to bn.
 *    2. Init the drbg.
 *    3. Call the BN_PrimeCheck method to check whether the big number is prime, expected result 1
 * @expect
 *    1. Return CRYPT_SUCCESS on isPrime != 0, CRYPT_BN_NOR_CHECK_PRIME otherwise.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_PRIME_CHECK_FUNC_TC001(Hex *hex, int isPrime)
{
#ifndef HITLS_CRYPTO_DRBG
    (void)hex;
    (void)isPrime;
    SKIP_TEST();
#else
    TestMemInit();
    int32_t ret;
    BN_BigNum *bn = BN_Create(hex->len * BITS_OF_BYTE);
    BN_Optimizer *opt = BN_OptimizerCreate();
    ASSERT_TRUE(bn != NULL && opt != NULL);

    ASSERT_EQ(BN_Bin2Bn(bn, hex->x, hex->len), CRYPT_SUCCESS);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ret = BN_PrimeCheck(bn, 0, opt, NULL);
    if (isPrime != 0) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ASSERT_TRUE(TestIsErrStackEmpty());
    } else {
        ASSERT_EQ(ret, CRYPT_BN_NOR_CHECK_PRIME);
    }

EXIT:
    TestRandDeInit();
    BN_Destroy(bn);
    BN_OptimizerDestroy(opt);
#endif
}
/* END_CASE */

static int32_t PrimeGenCb(BN_CbCtx *callBack, int32_t process, int32_t target)
{
    if (callBack == NULL)
        return CRYPT_SUCCESS;

    int32_t *limit = BN_CbCtxGetArg(callBack);
    if (process < *limit) {
        return CRYPT_SUCCESS;
    }
    (void)target;
    printf("now try tims is %d, gen failed\n", process);
    return -1;
}

/**
 * @test   SDV_CRYPTO_BN_GENPRIMELIMB_API_TC001
 * @title  BN_GenPrime method test.
 * @precon nan
 * @brief
 *    1. Create BN_CbCtx and call the BN_CbCtxSet method to register BN_CallBack method.
 *    2. Init the drbg.
 *    3. Call the BN_GenPrime method to generate prime, bits is LONG_BN_BITS_256, half is false, expected result 1
 *    4. Call the BN_GenPrime method to generate prime, bits < 14, half is true, expected result 2
 *    5. Call the BN_GenPrime method to generate prime, bits is 10, expected result 3
 * @expect
 *    1-3. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_GENPRIMELIMB_API_TC001(void)
{
    TestMemInit();
    BN_Optimizer *opt = BN_OptimizerCreate();
    ASSERT_TRUE(opt != NULL);
    BN_CbCtx *cb = BN_CbCtxCreate();
    ASSERT_TRUE(cb != NULL);
    int32_t limit = 256;
    BN_CbCtxSet(cb, PrimeGenCb, &limit);
    const uint32_t bits = LONG_BN_BITS_256;
    bool half = false;
    BN_BigNum *r = BN_Create(LONG_BN_BITS_256);
    ASSERT_TRUE(r != NULL);

    CRYPT_RandRegist(TEST_Random);
    CRYPT_RandRegistEx(TEST_RandomEx);

    ASSERT_TRUE(BN_GenPrime(r, NULL, bits, half, opt, cb) == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_GenPrime(r, NULL, 13, true, opt, cb) == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_GenPrime(r, NULL, 10, half, opt, cb) == CRYPT_SUCCESS);

EXIT:
    BN_CbCtxDestroy(cb);
    BN_Destroy(r);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_ADDLIMB_FUNC_TC001
 * @title  BN_AddLimb method test.
 * @precon nan
 * @brief
 *    1. Convert vectors to big numbers.
 *    2. Call the BN_AddLimb method to calculate the sum of two numbers, expected result 1.
 *    3. If expectRet=CRYPT_SUCCESS, call the BN_Cmp to compare r and resHex, expected result 3.
 * @expect
 *    1. The return value is the same as 'expectRet'.
 *    2. The calculated sum is 0.
 *    3. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_ADDLIMB_FUNC_TC001(int sign, Hex *rHex, int limb, int resSign, Hex *resHex, int expectRet)
{
    TestMemInit();
    BN_BigNum *resBn = NULL;
    BN_BigNum *a = TEST_VectorToBN(sign, rHex->x, rHex->len);
    BN_BigNum *r = TEST_VectorToBN(resSign, resHex->x, resHex->len);
    /* a and r can be null. */

    resBn = BN_Create(SHORT_BN_BITS_128);
    ASSERT_TRUE(resBn != NULL);

    ASSERT_EQ(BN_AddLimb(resBn, a, limb), expectRet);
    if (expectRet == CRYPT_SUCCESS) {
        ASSERT_EQ(BN_Cmp(resBn, r), 0);
    }

EXIT:
    BN_Destroy(a);
    BN_Destroy(r);
    BN_Destroy(resBn);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_SUB_FUNC_TC001
 * @title  BN_Sub test.
 * @precon Vectors: hex1 - hex2 = result
 * @brief
 *    1. Convert vectors to big numbers.
 *    2. Call BN_Sub to calculate hex1 minus hex2, and compared the result with vector, expected result 1:
 *       (1) Pointer addresses for parameters are different from each other.
 *       (2) The address of the output parameter pointer r is the same as that of the input parameter pointer a.
 *       (3) The address of the output parameter pointer r is the same as that of the input parameter pointer b.
 *    3. Test the scenario where the output parameter space is insufficient, expected result 1.
 * @expect
 *    1. The calculation result is consistent with the vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_SUB_FUNC_TC001(int sign1, Hex *hex1, int sign2, Hex *hex2, int signRes, Hex *result)
{
    TestMemInit();
    BN_BigNum *r = NULL;
    BN_BigNum *n = NULL;
    uint32_t maxBits;

    BN_BigNum *res = TEST_VectorToBN(signRes, result->x, result->len);
    BN_BigNum *a = TEST_VectorToBN(sign1, hex1->x, hex1->len);
    BN_BigNum *b = TEST_VectorToBN(sign2, hex2->x, hex2->len);
    ASSERT_TRUE(res != NULL && a != NULL && b != NULL);

    maxBits = TEST_GetMax(BN_Bits(a), BN_Bits(b), 0);
    r = BN_Create(maxBits + BIGNUM_REDUNDANCY_BITS);
    ASSERT_TRUE(r != NULL);

    ASSERT_EQ(BN_Copy(r, a), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Sub(r, a, b), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r != a", BN_Cmp(r, res) == 0);

    ASSERT_EQ(BN_Copy(r, a), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Sub(r, r, b), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r == a", BN_Cmp(r, res) == 0);

    ASSERT_EQ(BN_Copy(r, b), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Sub(r, a, r), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r == b", BN_Cmp(r, res) == 0);

    /* Test the scenario where the output parameter space is insufficient. */
    n = BN_Create(0);
    ASSERT_TRUE(n != NULL);

    ASSERT_EQ(BN_Sub(n, a, b), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("n != a", BN_Cmp(n, res) == 0);

    ASSERT_EQ(BN_Sub(a, a, b), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("a == a", BN_Cmp(a, res) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BN_Destroy(a);
    BN_Destroy(b);
    BN_Destroy(r);
    BN_Destroy(n);
    BN_Destroy(res);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_SUBLIMB_API_TC001
 * @title  BN_SubLimb method test.
 * @precon nan
 * @brief
 *    1. Create BN_BigNum r and a.
 *    2. Call the BN_SubLimb method, parameters are null, expected result 1
 *    3. Call the BN_AddLimb method to subtract a from 2, expected result 2
 *    4. Call the BN_AddLimb method to subtract a from 1, expected result 3
 *    5. Call the BN_AddLimb method to subtract a from 0, expected result 4
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_SUBLIMB_API_TC001(void)
{
    BN_BigNum *r = NULL;
    BN_BigNum *a = NULL;

    TestMemInit();

    r = BN_Create(LONG_BN_BITS_256);
    a = BN_Create(LONG_BN_BITS_256);
    ASSERT_TRUE(r != NULL && a != NULL);

    ASSERT_TRUE(BN_SubLimb(NULL, NULL, 0) == CRYPT_NULL_INPUT);

    ASSERT_TRUE(BN_SubLimb(r, a, 2) == CRYPT_SUCCESS);  // r == LONG_BN_BITS_256 - 2

    ASSERT_TRUE(BN_SetBit(a, 1) == CRYPT_SUCCESS);  // a->size == 1
    ASSERT_TRUE(BN_SetSign(a, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SubLimb(r, a, 1) == CRYPT_SUCCESS);  // r == LONG_BN_BITS_256 - 1

    ASSERT_TRUE(BN_SetBit(a, SHORT_BN_BITS_128 - 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SubLimb(r, a, 0) == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_SetBit(a, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SubLimb(r, a, 0) == CRYPT_SUCCESS);

    BN_Destroy(a);
    a = NULL;
    a = BN_Create(0);
    ASSERT_TRUE(a != NULL);
    ASSERT_TRUE(BN_SubLimb(r, a, 10) == CRYPT_SUCCESS);

EXIT:
    BN_Destroy(r);
    BN_Destroy(a);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_SUB_LIMB_FUNC_TC001
 * @title  BN_SubLimb test.
 * @precon Vectors: hex1 - hex2 = result
 * @brief
 *    1. Convert vectors to big numbers.
 *    2. Call BN_SubLimb to calculate hex1 minus hex2, and compared the result with vector, expected result 1.
 *    3. Test the scenario where the output parameter space is insufficient, expected result 1.
 * @expect
 *    1. The calculation result is consistent with the vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_SUB_LIMB_FUNC_TC001(int sign1, Hex *hex1, Hex *hex2, int signRes, Hex *result)
{
    TestMemInit();
    BN_BigNum *r = NULL;
    BN_BigNum *n = NULL;
    BN_UINT w = 0;

    BN_BigNum *res = TEST_VectorToBN(signRes, result->x, result->len);
    BN_BigNum *a = TEST_VectorToBN(sign1, hex1->x, hex1->len);
    ASSERT_TRUE(res != NULL && a != NULL);

    // w
    ASSERT_TRUE(sizeof(BN_UINT) >= hex2->len);
    for (uint32_t i = 0; i < hex2->len; i++) {
        w <<= BITS_OF_BYTE;
        w += hex2->x[i];
    }

    // r
    r = BN_Create(BN_Bits(a) + BIGNUM_REDUNDANCY_BITS);
    ASSERT_TRUE(r != NULL);

    ASSERT_EQ(BN_Copy(r, a), CRYPT_SUCCESS);

    ASSERT_EQ(BN_SubLimb(r, a, w), CRYPT_SUCCESS);

    ASSERT_TRUE(BN_Cmp(r, res) == 0);

    /* Test the scenario where the output parameter space is insufficient. */
    n = BN_Create(0);
    ASSERT_TRUE(n != NULL);

    ASSERT_EQ(BN_Zeroize(a), CRYPT_SUCCESS);

    ASSERT_TRUE(BN_SubLimb(n, a, w) == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_SetLimb(res, w) == CRYPT_SUCCESS);
    if (w != 0) {
        res->sign = true;
    }
    ASSERT_TRUE(BN_Cmp(n, res) == 0);

EXIT:
    BN_Destroy(a);
    BN_Destroy(r);
    BN_Destroy(n);
    BN_Destroy(res);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_DIV_FUNC_TC001
 * @title  BN_Div test.
 * @precon Vectors: hex1 / hex2 = resultQ, hex1 % hex2 = resultR
 * @brief
 *    1. Convert vectors to big numbers.
 *    2. Call BN_Div method, and compared the result with vector, expected result 1:
 *       (1) Pointer addresses for parameters are different from each other.
 *       (2) q == x, r == y.
 *    3. Test the scenario where the output parameter space is insufficient, expected result 1.
 * @expect
 *    1. The calculation result is consistent with the vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_DIV_FUNC_TC001(
    int sign1, Hex *hex1, int sign2, Hex *hex2, int signQ, Hex *resultQ, int signR, Hex *resultR)
{
    TestMemInit();
    BN_BigNum *q = NULL;
    BN_BigNum *r = NULL;
    BN_BigNum *q1 = NULL;
    BN_BigNum *n = NULL;
    BN_Optimizer *opt = NULL;
    uint32_t maxBits;

    BN_BigNum *resQ = TEST_VectorToBN(signQ, resultQ->x, resultQ->len);
    BN_BigNum *resR = TEST_VectorToBN(signR, resultR->x, resultR->len);
    BN_BigNum *x = TEST_VectorToBN(sign1, hex1->x, hex1->len);
    BN_BigNum *y = TEST_VectorToBN(sign2, hex2->x, hex2->len);
    ASSERT_TRUE(resQ != NULL && resR != NULL && x != NULL && y != NULL);

    maxBits = TEST_GetMax(BN_Bits(x), BN_Bits(y), 0);
    // q
    q = BN_Create(maxBits + BIGNUM_REDUNDANCY_BITS);
    r = BN_Create(maxBits + BIGNUM_REDUNDANCY_BITS);
    ASSERT_TRUE(q != NULL && r != NULL);

    opt = BN_OptimizerCreate();
    ASSERT_TRUE(opt != NULL);

    ASSERT_EQ(BN_Copy(q, x), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Copy(r, y), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Div(q, r, x, y, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("q != x, r != y", BN_Cmp(q, resQ) == 0);
    ASSERT_TRUE_AND_LOG("q != x, r != y", BN_Cmp(r, resR) == 0);

    ASSERT_EQ(BN_Copy(q, x), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Copy(r, y), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Div(q, r, q, r, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("q == x, r == y", BN_Cmp(q, resQ) == 0);
    ASSERT_TRUE_AND_LOG("q == x, r == y", BN_Cmp(r, resR) == 0);

    /* Test the scenario where the output parameter space is insufficient. */
    n = BN_Create(0);
    q1 = BN_Create(0);
    ASSERT_TRUE(n != NULL);
    ASSERT_TRUE(q1 != NULL);

    ASSERT_EQ(BN_Div(q1, n, x, y, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("q1 != x, n != y", BN_Cmp(q1, resQ) == 0);
    ASSERT_TRUE_AND_LOG("q1 != x, n != y", BN_Cmp(n, resR) == 0);
EXIT:
    BN_Destroy(x);
    BN_Destroy(y);
    BN_Destroy(q);
    BN_Destroy(r);
    BN_Destroy(n);
    BN_Destroy(q1);
    BN_Destroy(resQ);
    BN_Destroy(resR);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_SQR_API_TC001
 * @title  BN_Sqr method test.
 * @precon nan
 * @brief
 *    1. Call the BN_Sqr method, parameters are null, expected result 1
 *    2. Call the BN_Sqr method, parameters are valid, expected result 2
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_SQR_API_TC001(void)
{
    uint8_t buff[LONG_BN_BYTES_32];
    BN_BigNum *a = NULL;
    BN_BigNum *r = NULL;
    BN_BigNum *zero = NULL;
    BN_Optimizer *opt = NULL;
    TestMemInit();

    a = BN_Create(SHORT_BN_BITS_128);
    r = BN_Create(SHORT_BN_BITS_128);
    ASSERT_TRUE(a != NULL && r != NULL);
    opt = BN_OptimizerCreate();
    ASSERT_TRUE(opt != NULL);

    ASSERT_TRUE(BN_Sqr(NULL, NULL, NULL) == CRYPT_NULL_INPUT);

    ASSERT_TRUE(BN_Sqr(r, a, opt) == CRYPT_SUCCESS);

    memset_s(buff, sizeof(buff), 0xFF, LONG_BN_BYTES_32);
    ASSERT_TRUE(BN_Bin2Bn(a, buff, sizeof(buff)) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Sqr(r, a, opt) == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_Bin2Bn(a, buff, sizeof(buff) / 2) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Sqr(r, a, opt) == CRYPT_SUCCESS);

EXIT:
    BN_Destroy(a);
    BN_Destroy(r);
    BN_Destroy(zero);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_SQR_FUNC_TC001
 * @title  BN_Sqr method test.
 * @precon nan
 * @brief
 *    1. Call the BN_Copy method, Compute (-1)*(-1) or 1*1, expected result 1
 *    2. Compare r and result, expected result 2
 * @expect
 *    1. CRYPT_SUCCESS
 *    2. r = result
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_SQR_FUNC_TC001(int sign1, Hex *hex1, Hex *result)
{
    TestMemInit();
    BN_BigNum *a;
    BN_BigNum *res = NULL;
    BN_BigNum *r = NULL;
    BN_Optimizer *opt = NULL;

    a = BN_Create(hex1->len * BITS_OF_BYTE);
    res = BN_Create(result->len * BITS_OF_BYTE);
    ASSERT_TRUE(a != NULL && res != NULL);

    ASSERT_TRUE(BN_Bin2Bn(res, result->x, result->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Bin2Bn(a, hex1->x, hex1->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetSign(a, sign1 != 0) == CRYPT_SUCCESS);

    // r.bits > a.bits * 2
    r = BN_Create(BN_Bits(a) * 2 + BIGNUM_REDUNDANCY_BITS);
    ASSERT_TRUE(r != NULL);

    opt = BN_OptimizerCreate();
    ASSERT_TRUE(opt != NULL);

    ASSERT_TRUE(BN_Copy(r, a) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Sqr(r, a, opt) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Cmp(r, res) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BN_Destroy(a);
    BN_Destroy(r);
    BN_Destroy(res);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_RAND_API_TC001
 * @title  BN_Rand: Invalid parameter.
 * @precon nan
 * @brief
 *    1. Call the BN_Rand, parameters are null and 0, expected result 1
 *    2. Call the BN_Rand, top is out of maximum value(BN_RAND_TOP_TWOBIT + 1), expected result 2
 *    3. Call the BN_Rand, bottom is out of maximum value(BN_RAND_BOTTOM_TWOBIT + 1), expected result 3
 *    4. Call the BN_Rand, bit is 0, top and bottom are not 0, expected result 4
 *    5. Call the BN_Rand, bit > BN_MAX_BITS, expected result 5
 *    6. Call the BN_Rand, bit, top and bottom is 0, expected result 6
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2-3. CRYPT_BN_ERR_RAND_TOP_BOTTOM
 *    4. CRYPT_BN_ERR_RAND_BITS_NOT_ENOUGH
 *    5. CRYPT_BN_BITS_TOO_MAX
 *    6. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_RAND_API_TC001(void)
{
#ifndef HITLS_CRYPTO_DRBG
    SKIP_TEST();
#else
    BN_BigNum *bn = NULL;
    TestMemInit();
    bn = BN_Create(BITS_OF_BYTE);

    ASSERT_TRUE(BN_Rand(NULL, 0, 0, 0) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(
        BN_Rand(bn, BITS_OF_BYTE, BN_RAND_TOP_TWOBIT + 1, BN_RAND_BOTTOM_TWOBIT) == CRYPT_BN_ERR_RAND_TOP_BOTTOM);
    ASSERT_TRUE(
        BN_Rand(bn, BITS_OF_BYTE, BN_RAND_TOP_TWOBIT, BN_RAND_BOTTOM_TWOBIT + 1) == CRYPT_BN_ERR_RAND_TOP_BOTTOM);
    ASSERT_TRUE(BN_Rand(bn, 0, BN_RAND_TOP_TWOBIT, BN_RAND_BOTTOM_TWOBIT) == CRYPT_BN_ERR_RAND_BITS_NOT_ENOUGH);

    ASSERT_TRUE(BN_Rand(bn, BN_MAX_BITS + 1, BN_RAND_TOP_TWOBIT, BN_RAND_BOTTOM_TWOBIT) == CRYPT_BN_BITS_TOO_MAX);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Rand(bn, 0, 0, 0) == CRYPT_SUCCESS);
EXIT:
    BN_Destroy(bn);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_RANDRANGE_API_TC001
 * @title  BN_RandRange: Invalid parameter.
 * @precon nan
 * @brief
 *    1. Call the BN_RandRange method, parameters are null, expected result 1
 *    2. Call the BN_RandRange method, parameters are 0, expected result 2
 *    3. Call the BN_RandRange method, parameters are -1, expected result 3
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_BN_ERR_RAND_ZERO
 *    3. CRYPT_BN_ERR_RAND_NEGATIVE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_RANDRANGE_API_TC001(void)
{
    BN_BigNum *bn = NULL;
    TestMemInit();
    bn = BN_Create(BITS_OF_BYTE);

    ASSERT_TRUE(BN_RandRange(NULL, NULL) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(BN_RandRange(bn, bn) == CRYPT_BN_ERR_RAND_ZERO);
    ASSERT_TRUE(BN_SetLimb(bn, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetSign(bn, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_RandRange(bn, bn) == CRYPT_BN_ERR_RAND_NEGATIVE);
EXIT:
    BN_Destroy(bn);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_BNGCDCHECKINPUT_API_TC001
 * @title  BnGcdCheckInput: Invalid parameter.
 * @precon nan
 * @brief
 *    1. Call the BnGcdCheckInput method, parameters are null, expected result 1
 *    2. Call the BnGcdCheckInput method, a and b are BN_MAX_BITS, expected result 2
 *    3. Call the BnGcdCheckInput method, a and b are 0, expected result 3
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_BN_ERR_GCD_NO_ZERO
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_BNGCDCHECKINPUT_API_TC001(void)
{
    BN_BigNum *r;
    BN_BigNum *a;
    BN_BigNum *b;
    BN_Optimizer *opt = NULL;

    TestMemInit();
    r = BN_Create(BITS_OF_BYTE);
    a = BN_Create(LONG_BN_BITS_256);
    b = BN_Create(LONG_BN_BITS_256);
    opt = BN_OptimizerCreate();

    ASSERT_TRUE(BnGcdCheckInput(NULL, NULL, NULL, NULL) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(BN_SetLimb(a, BN_MAX_BITS) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetLimb(b, BN_MAX_BITS) == CRYPT_SUCCESS);
    ASSERT_TRUE(BnGcdCheckInput(r, a, b, opt) == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_Zeroize(a) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Zeroize(b) == CRYPT_SUCCESS);
    ASSERT_TRUE(BnGcdCheckInput(r, a, b, opt) == CRYPT_BN_ERR_GCD_NO_ZERO);
EXIT:
    BN_Destroy(r);
    BN_Destroy(a);
    BN_Destroy(b);
    BN_OptimizerDestroy(opt);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_MODINVINPUTCHECK_API_TC001
 * @title  InverseInputCheck: Invalid parameter.
 * @precon nan
 * @brief
 *    1. Call the InverseInputCheck method, parameters are null, expected result 1
 *    2. Call the InverseInputCheck method, x and m are BN_MAX_BITS, expected result 2
 *    3. Call the InverseInputCheck method, x and m are 0, expected result 3
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_BN_ERR_DIVISOR_ZERO
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_MODINVINPUTCHECK_API_TC001(void)
{
    BN_BigNum *r;
    BN_BigNum *x;
    BN_BigNum *m;
    BN_Optimizer *opt = NULL;

    TestMemInit();
    r = BN_Create(BITS_OF_BYTE);
    x = BN_Create(LONG_BN_BITS_256);
    m = BN_Create(LONG_BN_BITS_256);
    opt = BN_OptimizerCreate();
    ASSERT_TRUE(r != NULL && x != NULL && m != NULL && opt != NULL);

    ASSERT_TRUE(InverseInputCheck(NULL, NULL, NULL, NULL) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(BN_SetLimb(x, BN_MAX_BITS) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetLimb(m, BN_MAX_BITS) == CRYPT_SUCCESS);
    ASSERT_TRUE(InverseInputCheck(r, x, m, opt) == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_Zeroize(x) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Zeroize(m) == CRYPT_SUCCESS);
    ASSERT_TRUE(InverseInputCheck(r, x, m, opt) == CRYPT_BN_ERR_DIVISOR_ZERO);
EXIT:
    BN_Destroy(r);
    BN_Destroy(x);
    BN_Destroy(m);
    BN_OptimizerDestroy(opt);
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_U64_FUNC_TC001
 * @title  BN_U64Array2Bn/BN_Bn2U64Array test.
 * @precon nan
 * @brief
 *    1. Randomly generate a 64-bit unsigned array.
 *    2. Convert the array to a big number, and then convert the big number to array, expected result 1.
 *    3. compare whether the arrays are the same, expected result 2
 * @expect
 *    1. CRYPT_SUCCESS
 *    2. The two arrays are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_U64_FUNC_TC001(int len)
{
    TestMemInit();
    BN_BigNum *a = BN_Create(0);
    uint64_t *input = calloc(1, len * sizeof(uint64_t));
    uint64_t *output = calloc(1, len * sizeof(uint64_t));
    uint32_t outlen = len;
    for (int i = 0; i < len; i++) {
        input[i] = rand();
    }
    input[len - 1] = 1;

    ASSERT_TRUE(BN_U64Array2Bn(a, input, (uint32_t)len) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Bn2U64Array(a, output, &outlen) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(input, output, outlen * sizeof(uint64_t)) == 0);
    input[len - 1] = 0;

    ASSERT_TRUE(BN_U64Array2Bn(a, input, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Bn2U64Array(a, output, &outlen) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(input, output, outlen * sizeof(uint64_t)) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BN_Destroy(a);
    free(input);
    free(output);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_UINT_FUNC_TC001
 * @title  BN_Array2BN/BN_BN2Array test.
 * @precon nan
 * @brief
 *    1. Randomly generate a BN_UINT unsigned array.
 *    2. Convert the array to a big number, and then convert the big number to array, expected result 1.
 *    3. compare whether the arrays are the same, expected result 2
 * @expect
 *    1. CRYPT_SUCCESS
 *    2. The two arrays are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_UINT_FUNC_TC001(int len)
{
#if defined(HITLS_CRYPTO_CURVE_SM2_ASM) || (defined(HITLS_CRYPTO_CURVE_NISTP256_ASM) && \
    defined(HITLS_CRYPTO_NIST_USE_ACCEL))
    TestMemInit();
    BN_BigNum *a = BN_Create(0);
    BN_UINT *input = calloc(1, len * sizeof(BN_UINT));
    BN_UINT *output = calloc(1, len * sizeof(BN_UINT));
    for (int i = 0; i < len; i++) {
        input[i] = rand();
    }

    ASSERT_TRUE(BN_Array2BN(a, input, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_BN2Array(a, output, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(input, output, len * sizeof(BN_UINT)) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BN_Destroy(a);
    free(input);
    free(output);
#else
    (void)len;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_GCD_FUNC_TC001
 * @title  BN_Gcd test.
 * @precon Vectors: two big numbers, result.
 * @brief
 *    1. Convert vectors to big numbers.
 *    2. Call BN_Gcd to calculate the modular exponentiation, and compared to the vector value, expected result 1:
 *       (1) Pointer addresses for parameters are different from each other.
 *       (2) The address of the output parameter pointer r is the same as that of the input parameter pointer a.
 *       (3) The address of the output parameter pointer r is the same as that of the input parameter pointer b.
 *    3. Test the scenario where the output parameter space is insufficient, expected result 1.
 * @expect
 *    1. The calculation result is consistent with the vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_GCD_FUNC_TC001(int sign1, Hex *hex1, int sign2, Hex *hex2, Hex *result)
{
    TestMemInit();
    BN_BigNum *out = NULL;
    BN_Optimizer *opt = NULL;
    uint32_t maxBits;

    BN_BigNum *bn = TEST_VectorToBN(sign1, hex1->x, hex1->len);
    BN_BigNum *bn2 = TEST_VectorToBN(sign2, hex2->x, hex2->len);
    BN_BigNum *res = TEST_VectorToBN(0, result->x, result->len);
    ASSERT_TRUE(bn != NULL && bn2 != NULL && res != NULL);

    maxBits = TEST_GetMax(BN_Bits(bn), BN_Bits(bn2), 0);
    out = BN_Create(maxBits + BIGNUM_REDUNDANCY_BITS);
    ASSERT_TRUE(out != NULL);

    opt = BN_OptimizerCreate();
    ASSERT_TRUE(opt != NULL);

    ASSERT_EQ(BN_Copy(out, bn), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Gcd(out, bn, bn2, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r != a", BN_Cmp(out, res) == 0);

    ASSERT_EQ(BN_Copy(out, bn), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Gcd(out, out, bn2, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r == a", BN_Cmp(out, res) == 0);

    ASSERT_EQ(BN_Copy(out, bn2), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Gcd(out, bn, out, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r == b", BN_Cmp(out, res) == 0);
    BN_Destroy(out);

    /* Test the scenario where the output parameter space is insufficient. */
    out = BN_Create(0);
    ASSERT_TRUE(out != NULL);

    ASSERT_EQ(BN_Gcd(out, bn, bn2, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r != a", BN_Cmp(out, res) == 0);
    BN_Destroy(out);

    out = BN_Create(0);
    ASSERT_TRUE(out != NULL);
    ASSERT_EQ(BN_Copy(out, bn), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Gcd(out, out, bn2, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r == a", BN_Cmp(out, res) == 0);
    BN_Destroy(out);

    out = BN_Create(0);
    ASSERT_TRUE(out != NULL);
    ASSERT_EQ(BN_Copy(out, bn2), CRYPT_SUCCESS);
    ASSERT_EQ(BN_Gcd(out, bn, out, opt), CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("r == b", BN_Cmp(out, res) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BN_Destroy(bn);
    BN_Destroy(bn2);
    BN_Destroy(res);
    BN_Destroy(out);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_CMP_FUNC_TC001
 * @title  BN_Cmp test.
 * @precon Vectors: two big numbers, result.
 * @brief
 *    1. Convert vectors to big numbers.
 *    2. Call the BN_Cmp method to compare two large numbers, expected result 1.
 * @expect
 *    1. The comparison results are the same as 'result'.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_CMP_FUNC_TC001(int sign1, Hex *hex1, int sign2, Hex *hex2, int result)
{
    TestMemInit();

    BN_BigNum *bn1 = TEST_VectorToBN(sign1, hex1->x, hex1->len);
    BN_BigNum *bn2 = TEST_VectorToBN(sign2, hex2->x, hex2->len);
    /* bn1 and bn2 can be null. */

    ASSERT_EQ(BN_Cmp(bn1, bn2), result);

EXIT:
    BN_Destroy(bn1);
    BN_Destroy(bn2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_ADD_FUNC_TC001
 * @title  BN_Add test.
 * @precon a + b = r
 * @brief
 *    1. Convert vectors to big numbers.
 *    2. Call the BN_Add method to calculate the sum of two large numbers, expected result 1.
 *    3. If expectRet=CRYPT_SUCCESS and r=null(i.e.a=-b), call BN_IsZero to check whether sum is 0, expected result 2.
 *    4. If expectRet=CRYPT_SUCCESS, call the BN_Cmp to compare r and resBn, expected result 3.
 * @expect
 *    1. The return value is the same as 'expectRet'.
 *    2. The calculated sum is 0.
 *    3. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_ADD_FUNC_TC001(int sign1, int sign2, int sign3, Hex *a, Hex *b, Hex *r, int expectRet)
{
    TestMemInit();
    BN_BigNum *resBn = NULL;

    BN_BigNum *bn1 = TEST_VectorToBN(sign1, a->x, a->len);
    BN_BigNum *bn2 = TEST_VectorToBN(sign2, b->x, b->len);
    BN_BigNum *sum = TEST_VectorToBN(sign3, r->x, r->len);
    /* bn1, bn2 and sum can be null. */

    resBn = BN_Create(SHORT_BN_BITS_128);
    ASSERT_TRUE(resBn != NULL);

    ASSERT_EQ(BN_Add(resBn, bn1, bn2), expectRet);
    if (expectRet == CRYPT_SUCCESS) {
        if (r->len == 0) {
            ASSERT_EQ(BN_IsZero(resBn), 1);
        } else {
            ASSERT_EQ(BN_Cmp(resBn, sum), 0);
        }
    }

EXIT:
    BN_Destroy(bn1);
    BN_Destroy(bn2);
    BN_Destroy(sum);
    BN_Destroy(resBn);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_BN_TO_BIN_FIX_ZERO_API_TC001
 * @title  BN_Bn2BinFixZero test.
 * @precon nan
 * @brief
 *    1. Call the BN_Create method to create bn, parameter is 0, expected result 1.
 *    2. Call the BN_Bn2BinFixZero method, expected result 2:
 *       (1) bn is null
 *       (2) bin is null
 *       (3) binLen is 0
 *    3. Call the BN_Bn2BinFixZero method, all parameters are valid, expected result 3
 *    4. Destroy bn and recreate bn, bits is 128, expected result 4.
 *    5. Set the highest bit of bn to 1, expected result 5.
 *    6. Call the BN_Bn2BinFixZero method, binLen is 1, expected result 6.
 * @expect
 *    1. Success.
 *    2. CRYPT_NULL_INPUT.
 *    3. CRYPT_SUCCESS.
 *    4. Success.
 *    5. CRYPT_SUCCESS.
 *    6. CRYPT_BN_BUFF_LEN_NOT_ENOUGH.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_BN_TO_BIN_FIX_ZERO_API_TC001(void)
{
    TestMemInit();
    uint8_t bin[1] = {0};
    BN_BigNum *bn = BN_Create(0);
    ASSERT_TRUE(bn != NULL);

    ASSERT_EQ(BN_Bn2BinFixZero(NULL, bin, 1), CRYPT_NULL_INPUT);
    ASSERT_EQ(BN_Bn2BinFixZero(bn, NULL, 1), CRYPT_NULL_INPUT);
    ASSERT_EQ(BN_Bn2BinFixZero(bn, bin, 0), CRYPT_SUCCESS);

    // bn bytes is 0
    ASSERT_EQ(BN_Bn2BinFixZero(bn, bin, 1), CRYPT_SUCCESS);
    BN_Destroy(bn);

    bn = BN_Create(SHORT_BN_BITS_128);
    ASSERT_TRUE(bn != NULL);
    ASSERT_EQ(BN_SetBit(bn, SHORT_BN_BITS_128 - 1), CRYPT_SUCCESS);

    ASSERT_EQ(BN_Bn2BinFixZero(bn, bin, 1), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);

EXIT:
    BN_Destroy(bn);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_BN_Rand_API_TC001(void)
{
    TEST_BnTestCaseInit();
    BN_BigNum bn[2] = {{0}};
    BN_UINT bn_data[DH_BN_DIGITS_MAX * 2] = { 0 };
    BN_Init(bn, bn_data, DH_BN_DIGITS_MAX, 2);
    ASSERT_TRUE(BN_Rand(&bn[0], 8192, 1, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_RandRange(&bn[1], &bn[0]) == CRYPT_SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_BN_Add_API_TC001(void)
{
    TEST_BnTestCaseInit();
    BN_BigNum bn[3] = {{0}};
    BN_UINT bn_data[BN_DIGITS_MAX * 3] = { 0 };
    BN_Init(bn, bn_data, BN_DIGITS_MAX, 3);
    ASSERT_TRUE(BN_Rand(&bn[0], 4096, 1, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Rand(&bn[1], 4096, 1, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Add(&bn[2], &bn[0], &bn[1]) == CRYPT_SUCCESS);
EXIT:
    return;
}
/* END_CASE */


/* BEGIN_CASE */
void SDV_CRYPTO_BN_Mul_API_TC001(void)
{
    TEST_BnTestCaseInit();
    BN_Optimizer *opt = BN_OptimizerCreate();
    BN_BigNum bn[2] = {{0}};
    BN_BigNum rn = {0};
    BN_UINT bn_data[BN_DIGITS_MAX * 2] = { 0 };
    BN_UINT r_data[DH_BN_DIGITS_MAX * 2] = { 0 };
    BN_Init(bn, bn_data, BN_DIGITS_MAX, 2);
    ASSERT_TRUE(BN_Rand(&bn[0], 4096, 1, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Rand(&bn[1], 4096, 1, 1) == CRYPT_SUCCESS);
    BN_Init(&rn, r_data, DH_BN_DIGITS_MAX, 1);
    ASSERT_TRUE(BN_Mul(&rn, &bn[0], &bn[1], opt) == CRYPT_SUCCESS);
EXIT:
    BN_OptimizerDestroy(opt);
    return;
}
/* END_CASE */


/* BEGIN_CASE */
void SDV_CRYPTO_BN_Div_API_TC001(void)
{
    TEST_BnTestCaseInit();
    BN_Optimizer *opt = BN_OptimizerCreate();

    BN_BigNum bn[4] = {{0}};
    BN_UINT bn_data[BN_DIGITS_MAX * 4] = { 0 };
    BN_Init(bn, bn_data, BN_DIGITS_MAX, 4);
    ASSERT_TRUE(BN_Rand(&bn[2], 4096, 1, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Rand(&bn[3], 4096, 1, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Div(&bn[0], &bn[1], &bn[2], &bn[3], opt) == CRYPT_SUCCESS);
EXIT:
    BN_OptimizerDestroy(opt);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_BN_Mod_API_TC001(void)
{
    TEST_BnTestCaseInit();

    BN_Optimizer *opt = BN_OptimizerCreate();
    BN_UINT res = 0;
    BN_UINT input = 3;
    BN_BigNum bn[4] = {{0}};
    BN_UINT bn_data[BN_DIGITS_MAX * 4] = { 0 };
    BN_Init(bn, bn_data, BN_DIGITS_MAX, 4);
    ASSERT_TRUE(BN_Rand(&bn[1], 4096, 1, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Rand(&bn[2], 4096, 1, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Rand(&bn[3], 4096, 1, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_ModMul(&bn[0], &bn[1], &bn[2], &bn[3], opt) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_ModSqr(&bn[0], &bn[1], &bn[2], opt) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_ModAdd(&bn[0], &bn[1], &bn[2], &bn[3], opt) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_ModLimb(&res, &bn[1], input) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_AddLimb(&bn[0], &bn[1], input) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetLimb(&bn[0], input) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Cmp(&bn[1], &bn[2]) != CRYPT_SUCCESS);

EXIT:
    BN_OptimizerDestroy(opt);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_BN_ModLimb_API_TC001(void)
{
    TEST_BnTestCaseInit();
    BN_Optimizer *opt = BN_OptimizerCreate();
    ASSERT_TRUE(opt != NULL);
    BN_UINT res = 0;
    BN_UINT input = 3;
    BN_BigNum bn[2] = {{0}};
    BN_UINT bn_data[DH_BN_DIGITS_MAX * 2] = { 0 };
    BN_Init(bn, bn_data, DH_BN_DIGITS_MAX, 2);
    ASSERT_TRUE(BN_ModLimb(&res, &bn[1], input) == CRYPT_SUCCESS);
EXIT:
    BN_OptimizerDestroy(opt);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_BN_rshift_API_TC001(void)
{
    TEST_BnTestCaseInit();
    BN_UINT input = 3;
    BN_BigNum bn[2] = {{0}};
    BN_UINT bn_data[DH_BN_DIGITS_MAX * 2] = { 0 };
    BN_Init(bn, bn_data, DH_BN_DIGITS_MAX, 2);
    ASSERT_TRUE(BN_Rand(&bn[1], 4096, 1, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Rshift(&bn[0], &bn[1], input) == CRYPT_SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_BN_ModExp_API_TC001(void)
{
    TEST_BnTestCaseInit();
    BN_Optimizer *opt = BN_OptimizerCreate();
    ASSERT_TRUE(opt != NULL);
    BN_BigNum bn[4] = {{0}};
    BN_UINT bn_data[DH_BN_DIGITS_MAX * 4] = { 0 };
    BN_Init(bn, bn_data, DH_BN_DIGITS_MAX, 4);
    ASSERT_TRUE(BN_Rand(&bn[1], 8192, 1, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Rand(&bn[2], 8192, 1, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Rand(&bn[3], 8192, 1, 1) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_ModExp(&bn[0], &bn[1], &bn[2], &bn[3], opt) == CRYPT_SUCCESS);
EXIT:
    BN_OptimizerDestroy(opt);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_BN_SET_FLAG_TC001(void)
{
    TEST_BnTestCaseInit();
    BN_BigNum a = {0};
    ASSERT_TRUE(BN_SetFlag(&a, 0xFF) == CRYPT_BN_FLAG_INVALID);
    ASSERT_TRUE(BN_SetFlag(&a, CRYPT_BN_FLAG_STATIC) == CRYPT_SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_BN_GETLIMB_API_TC001(void)
{
    TEST_BnTestCaseInit();
    int32_t ret;

    BN_BigNum *a = BN_Create(LONG_BN_BITS_256);
    ASSERT_TRUE(a != NULL);
    
    ASSERT_TRUE(BN_GetLimb(NULL) == 0);

    ret = BN_SetLimb(a, 0);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_GetLimb(a) == 0);

    ret = BN_SetLimb(a, 1);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_GetLimb(a) == 1);

    ret = BN_SetLimb(a, 2);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_GetLimb(a) == 2);

    ret = BN_SetLimb(a, BN_UINT_MAX - 1);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_GetLimb(a) == BN_UINT_MAX - 1);

    ret = BN_SetLimb(a, BN_UINT_MAX);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_GetLimb(a) == BN_UINT_MAX);

    ret = BN_Lshift(a, a, BN_UINT_MAX + 1);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_GetLimb(a) == BN_UINT_MAX);

EXIT:
    BN_Destroy(a);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_BN_MASKBIT_API_TC001(void)
{
    TEST_BnTestCaseInit();
    ASSERT_TRUE(BN_MaskBit(NULL, 0) == CRYPT_NULL_INPUT);
    int32_t ret;
    BN_BigNum *bn = BN_Create(1);

    ret = BN_SetBit(bn, 1);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    BN_SetSign(bn, 1);
    ret = BN_MaskBit(bn, 0);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(bn->sign == 0);

    ret = BN_SetLimb(bn, BN_UINT_MAX * 2);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = BN_MaskBit(bn, BN_UINT_BITS * 3);
    ASSERT_TRUE(ret == CRYPT_BN_SPACE_NOT_ENOUGH);
EXIT:
    BN_Destroy(bn);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_BN_MULLIMB_API_TC001(void)
{
    TEST_BnTestCaseInit();
    int32_t ret;
    uint8_t buff[LONG_BN_BYTES_32];
    BN_BigNum *a = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *b = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *r1 = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *r2 = BN_Create(LONG_BN_BITS_256 * 2); // 512 == 2 * 256
    BN_BigNum *zero = BN_Create(LONG_BN_BITS_256);
    BN_Optimizer *opt = BN_OptimizerCreate();
    ASSERT_TRUE(a != NULL);
    ASSERT_TRUE(b != NULL);
    ASSERT_TRUE(r1 != NULL);
    ASSERT_TRUE(r2 != NULL);
    ASSERT_TRUE(zero != NULL);
    ASSERT_TRUE(opt != NULL);
    memset_s(buff, sizeof(buff), 0xFF, LONG_BN_BYTES_32);

    ret = BN_Bin2Bn(a, buff, LONG_BN_BYTES_32);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = BN_SetLimb(b, BN_UINT_MAX);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = BN_Zeroize(zero);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_IsZero(zero));

    // NULL
    ASSERT_TRUE(BN_MulLimb(NULL, a, BN_UINT_MAX) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(BN_MulLimb(r1, NULL, BN_UINT_MAX) == CRYPT_NULL_INPUT);

    // a == 0
    ret = BN_MulLimb(r1, zero, BN_UINT_MAX);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_IsZero(r1));

    // w == 0
    ret = BN_MulLimb(r1, a, 0);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_IsZero(r1));

    // a == 0
    ret = BN_MulLimb(r1, a, BN_UINT_MAX);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ret = BN_Mul(r2, a, b, opt);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_Cmp(r1, r2) == CRYPT_SUCCESS);

EXIT:
    BN_Destroy(a);
    BN_Destroy(b);
    BN_Destroy(r1);
    BN_Destroy(r2);
    BN_Destroy(zero);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_BN_DIVLIMB_API_TC001(void)
{
    TEST_BnTestCaseInit();
    int32_t ret;
    uint8_t buff[LONG_BN_BYTES_32];
    BN_BigNum *a = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *b = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *r1 = BN_Create(LONG_BN_BITS_256);
    BN_BigNum *r2 = BN_Create(LONG_BN_BITS_256 * 2); // 512 == 2 * 256
    BN_BigNum *res2 = BN_Create(LONG_BN_BITS_256 * 2); // 512 == 2 * 256
    BN_BigNum *zero = BN_Create(LONG_BN_BITS_256);
    BN_Optimizer *opt = BN_OptimizerCreate();
    ASSERT_TRUE(a != NULL);
    ASSERT_TRUE(b != NULL);
    ASSERT_TRUE(r1 != NULL);
    ASSERT_TRUE(r2 != NULL);
    ASSERT_TRUE(zero != NULL);
    ASSERT_TRUE(opt != NULL);
    BN_UINT res1;
    // BN_UINT res2;
    memset_s(buff, sizeof(buff), 0xFF, LONG_BN_BYTES_32);

    ret = BN_Bin2Bn(a, buff, LONG_BN_BYTES_32);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = BN_SetLimb(b, BN_UINT_MAX);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = BN_Zeroize(zero);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_IsZero(zero));

    // NULL
    ASSERT_TRUE(BN_DivLimb(NULL, &res1, a, BN_UINT_MAX) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_DivLimb(r1, NULL, a, BN_UINT_MAX) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_DivLimb(NULL, NULL, a, BN_UINT_MAX) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(BN_DivLimb(r1, &res1, NULL, BN_UINT_MAX) == CRYPT_NULL_INPUT);

    // a == 0
    ret = BN_DivLimb(r1, &res1, zero, BN_UINT_MAX);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_IsZero(r1));
    ASSERT_TRUE(res1 == 0);

    // w == 0
    ret = BN_DivLimb(r1, &res1, a, 0);
    ASSERT_TRUE(ret == CRYPT_BN_ERR_DIVISOR_ZERO);

    ret = BN_Copy(r1, a);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ret = BN_DivLimb(r1, &res1, r1, BN_UINT_MAX);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ret = BN_Div(r2, res2, a, b, opt);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ASSERT_TRUE(BN_Cmp(r1, r2) == CRYPT_SUCCESS);
    ASSERT_TRUE(res1 == res2->data[0]);
EXIT:
    BN_Destroy(a);
    BN_Destroy(b);
    BN_Destroy(r1);
    BN_Destroy(r2);
    BN_Destroy(res2);
    BN_Destroy(zero);
    BN_OptimizerDestroy(opt);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_BN_EXTEND_API_TC001(void)
{
    TEST_BnTestCaseInit();
    uint32_t word = BITS_TO_BN_UNIT(BN_MAX_BITS) + 1;
    BN_BigNum *a = BN_Create(LONG_BN_BITS_256);
    ASSERT_TRUE(a != NULL);
    ASSERT_TRUE(BN_Extend(a, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_SetFlag(a, CRYPT_BN_FLAG_STATIC) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Extend(a, word) == CRYPT_BN_NOT_SUPPORT_EXTENSION);
    ASSERT_TRUE(BN_SetFlag(a, CRYPT_BN_FLAG_CONSTTIME) == CRYPT_SUCCESS);
    ASSERT_TRUE(BN_Extend(a, word) == CRYPT_BN_BITS_TOO_MAX);
    ASSERT_TRUE(BN_Extend(a, word - 1) == CRYPT_SUCCESS);
EXIT:
    BN_Destroy(a);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_BN_FIXSIZE_API_TC001(void)
{
    TEST_BnTestCaseInit();
    BN_BigNum *a = BN_Create(LONG_BN_BITS_256);
    ASSERT_TRUE(a != NULL);
    a->size = 1;
    BN_FixSize(a);
    ASSERT_TRUE(a->size == 0);
EXIT:
    BN_Destroy(a);
}
/* END_CASE */

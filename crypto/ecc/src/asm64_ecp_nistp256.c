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
#if defined(HITLS_CRYPTO_CURVE_NISTP256_ASM) && defined(HITLS_CRYPTO_NIST_ECC_ACCELERATE)

#include <stdint.h>
#include "crypt_errno.h"
#include "crypt_bn.h"
#include "ecp_nistp256.h"
#include "crypt_ecc.h"
#include "ecc_local.h"
#include "bsl_err_internal.h"
#include "asm_ecp_nistp256.h"

static const Coord g_rrModOrder = {{
    0x83244c95be79eea2,
    0x4699799c49bd6fa6,
    0x2845b2392b6bec59,
    0x66e12d94f3d95620
}};

static int32_t ECP256_ModOrderInvCheck(const ECC_Para *para, const BN_BigNum *r, const BN_BigNum *a)
{
    if (para == NULL || r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (para->id != CRYPT_ECC_NISTP256) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }

    if (BN_IsZero(a)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_INVERSE_INPUT_ZERO);
        return CRYPT_ECC_INVERSE_INPUT_ZERO;
    }

    return CRYPT_SUCCESS;
}

static int32_t Bn2CoordArray(const ECC_Para *para, Coord *aArr, const BN_BigNum *a)
{
    int32_t ret = CRYPT_SUCCESS;
    uint32_t bits = BN_Bits(para->n);
    BN_Optimizer *opt = BN_OptimizerCreate();
    BN_BigNum *aTemp = BN_Create(bits);
    if (opt == NULL || aTemp == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    if (BN_Cmp(a, para->n) >= 0) {
        ret = BN_Mod(aTemp, a, para->n, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        if (BN_IsZero(aTemp)) {  // If x and m are coprime, the module inverse cannot be obtained.
            BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_NO_INVERSE);
            ret = CRYPT_BN_ERR_NO_INVERSE;
            goto EXIT;
        }
    } else {
        ret = BN_Copy(aTemp, a);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
    }
    (void)BN_BN2Array(aTemp, aArr->value, P256_SIZE);
EXIT:
    BN_OptimizerDestroy(opt);
    BN_Destroy(aTemp);
    return ret;
}

// r = a^(-1) mod n, a cannot be 0
// a^(-1) mod n = a^(n-2) mod n
// n   = 0xffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc632551
// n-2 = 0xffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc63254f
// Split the file into binary files as follows:
// 11111111111111111111111111111111---------0xffffffff
// 00000000000000000000000000000000---------0x00000000
// 11111111111111111111111111111111---------0xffffffff
// 11111111111111111111111111111111---------0xffffffff
// 101111 00 111 00 11 0 1111 10101 0 101 101
// 101 00 111 000 101111 00 1111 0 1 0000 1 00
// 1111 00 111 0 111 00 111 00 101 0 11 0000 10(1111): append four 1s
// (1111) 11 000 11 000 11 00 1 00 10101 00 1111
// To calculate the power of a, the exponent list is { 1, 10, 11, 101, 111, 1010, 1111, 10101, 101010, 101111, ffffffff}
// To calculate a^(0xffffffff), a^(0xffff) is required. The former requires a^(0xff), the latter requires a^(0x3f).
// The above is the optimal multiplication chain of a^(n-2)
// https://briansmith.org/ecc-inversion-addition-chains-01#p256_scalar_inversion
int32_t ECP256_ModOrderInv(const ECC_Para *para, BN_BigNum *r, const BN_BigNum *a)
{
    int32_t ret = ECP256_ModOrderInvCheck(para, r, a);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    const Coord one = {{1}};
    Coord aArr, res;
    Coord table[14];
    enum {
        bin1 = 0, bin10, bin11, bin101, bin111, bin1010, bin1111,
        bin10101, bin101010, bin101111, hex3f, hexff, hexffff, hexffffffff
    };
    static const uint8_t mulMap[26] = {        // The lower 128 bits of n-2 can be split into 26 binary numbers.
        bin101111, bin111, bin11, bin1111, bin10101, bin101,
        bin101, bin101, bin111, bin101111, bin1111, bin1,
        bin1, bin1111, bin111, bin111, bin111, bin101,
        bin11, bin101111, bin11, bin11, bin11, bin1,
        bin10101, bin1111
    };
    static const uint8_t sqrRep[26] = {        // The lower 128 bits of n-2 can be split into 26 binary numbers.
        6, 5, 4, 5, 5, 4,
        3, 3, 5, 9, 6, 2,
        5, 6, 5, 4, 5, 5,
        3, 10, 2, 5, 5, 3,
        7, 6
    };

    ret = Bn2CoordArray(para, &aArr, a);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ECP256_OrdMul(&table[bin1], &aArr, &g_rrModOrder);               // table[bin1] = a, to the field with Montgomery

    ECP256_OrdSqr(&table[bin10], &table[bin1], 1);                   // table[bin10] = a^(0b10)
    ECP256_OrdMul(&table[bin11], &table[bin1], &table[bin10]);       // table[bin11] = a^(0b11)
    ECP256_OrdMul(&table[bin101], &table[bin11], &table[bin10]);     // table[bin101] = a^(0b101)
    ECP256_OrdMul(&table[bin111], &table[bin101], &table[bin10]);    // table[bin111] = a^(0b111)

    ECP256_OrdSqr(&table[bin1010], &table[bin101], 1);               // table[bin1010] = a^(0b1010)

    ECP256_OrdMul(&table[bin1111], &table[bin1010], &table[bin101]); // table[bin1111] = a^(0b1111)

    ECP256_OrdSqr(&table[bin10101], &table[bin1010], 1);             // table[bin10101] = a^(0b10100)
    ECP256_OrdMul(&table[bin10101], &table[bin10101], &table[bin1]); // table[bin10101] = a^(0b10101)

    ECP256_OrdSqr(&table[bin101010], &table[bin10101], 1);           // table[bin101010] = a^(0b101010)

    ECP256_OrdMul(&table[bin101111], &table[bin101010], &table[bin101]); // table[bin101111] = a^(0b101111)

    ECP256_OrdMul(&table[hex3f], &table[bin101010], &table[bin10101]);   // table[hex3f] = a^(0b0011 1111) = a^(0x3f)

    ECP256_OrdSqr(&table[hexff], &table[hex3f], 2);   // left shift by 2 bits, table[hexff] = a^(0b1111 1100) = a^(0xfc)
    ECP256_OrdMul(&table[hexff], &table[hexff], &table[bin11]); // table[hexff] = a^(0b1111 1111) = a^(0xff)

    ECP256_OrdSqr(&table[hexffff], &table[hexff], 8);               // left shift by 8 bits, table[hexffff] = a^(0xff00)
    ECP256_OrdMul(&table[hexffff], &table[hexffff], &table[hexff]);  // table[hexffff] = a^(0xffff)

    // left shift by 16 bits, table[hexffffffff] = a^(0xffff0000)
    ECP256_OrdSqr(&table[hexffffffff], &table[hexffff], 16);
    ECP256_OrdMul(&table[hexffffffff], &table[hexffffffff], &table[hexffff]); // table[hexffffffff] = a^(0xffffffff)

    ECP256_OrdSqr(&res, &table[hexffffffff], 64);    // res = a^(0xffffffff 00000000 00000000), left shift by 64 bits
    ECP256_OrdMul(&res, &res, &table[hexffffffff]);  // res = a^(0xffffffff 00000000 ffffffff)

    ECP256_OrdSqr(&res, &res, 32);             // res = a^(0xffffffff 00000000 ffffffff 00000000), left shift by 32 bits
    ECP256_OrdMul(&res, &res, &table[hexffffffff]);  // res = a^(0xffffffff 00000000 ffffffff ffffffff)

    for (uint32_t i = 0; i < sizeof(mulMap); i++) {
        ECP256_OrdSqr(&res, &res, sqrRep[i]);
        ECP256_OrdMul(&res, &res, &table[mulMap[i]]);
    }

    // Multiplied by 1 can be converted back to the normal real number field, which is equivalent to a reduce.
    // For details, see Montgomery modular multiplication.
    ECP256_OrdMul(&res, &res, &one);

    (void)BN_Array2BN(r, res.value, P256_SIZE);
    return ret;
}
#endif
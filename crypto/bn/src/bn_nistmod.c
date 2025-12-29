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
#if defined(HITLS_CRYPTO_BN) && defined(HITLS_CRYPTO_ECC)

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "bn_bincal.h"

// Refresh the valid length of the BigNum r. The maximum length is modSize.
static void UpdateSize(BN_BigNum *r, uint32_t modSize)
{
    uint32_t size = modSize;
    while (size > 0) {
        if (r->data[size - 1] != 0) {
            break;
        }
        size--;
    }
    if (r->size > modSize) {
        // Clear the high bits.
        uint32_t i = 0;
        for (i = modSize; i < r->size; i++) {
            r->data[i] = 0;
        }
    }
    r->size = size;
    r->sign = false;
}

#define P521SIZE SIZE_OF_BNUINT(521)
#define SIZE_OF_BNUINT(bits) (((bits) + BN_UINT_BITS - 1) / BN_UINT_BITS) // 1byte = 8bit


#if defined(HITLS_SIXTY_FOUR_BITS)
#define P224SIZE SIZE_OF_BNUINT(224)
#define P256SIZE SIZE_OF_BNUINT(256)
#define P384SIZE SIZE_OF_BNUINT(384)

BN_UINT g_modDataP224[][P224SIZE] = {
    {   // 1p
        0x0000000000000001UL, 0xffffffff00000000UL,
        0xffffffffffffffffUL, 0x00000000ffffffffUL
    },
    {   // 2p
        0x0000000000000002UL, 0xfffffffe00000000UL,
        0xffffffffffffffffUL, 0x00000001ffffffffUL
    }
};

BN_UINT g_modDataP256[][P256SIZE] = {
    {   // p
        0xffffffffffffffffUL, 0x00000000ffffffffUL,
        0x0000000000000000UL, 0xffffffff00000001UL
    },
    {   // 2p
        0xfffffffffffffffeUL, 0x00000001ffffffffUL,
        0x0000000000000000UL, 0xfffffffe00000002UL
    },
    {   // 3p
        0xfffffffffffffffdUL, 0x00000002ffffffffUL,
        0x0000000000000000UL, 0xfffffffd00000003UL
    },
    {   // 4p
        0xfffffffffffffffcUL, 0x00000003ffffffffUL,
        0x0000000000000000UL, 0xfffffffc00000004UL
    },
    {   // 5p
        0xfffffffffffffffbUL, 0x00000004ffffffffUL,
        0x0000000000000000UL, 0xfffffffb00000005UL
    },
};
#ifdef HITLS_CRYPTO_CURVE_SM2
const BN_UINT MODDATASM2P256[][P256SIZE] = {
    {   // p
        0xffffffffffffffffUL, 0xffffffff00000000UL,
        0xffffffffffffffffUL, 0xfffffffeffffffffUL
    },
    {   // 2p
        0xfffffffffffffffeUL, 0xfffffffe00000001UL,
        0xffffffffffffffffUL, 0xfffffffdffffffffUL
    },
    {   // 3p
        0xfffffffffffffffdUL, 0xfffffffd00000002UL,
        0xffffffffffffffffUL, 0xfffffffcffffffffUL
    },
    {   // 4p
        0xfffffffffffffffcUL, 0xfffffffc00000003UL,
        0xffffffffffffffffUL, 0xfffffffbffffffffUL
    },
    {   // 5p
        0xfffffffffffffffbUL, 0xfffffffb00000004UL,
        0xffffffffffffffffUL, 0xfffffffaffffffffUL
    },
    {   // 6p
        0xfffffffffffffffaUL, 0xfffffffa00000005UL,
        0xffffffffffffffffUL, 0xfffffff9ffffffffUL
    },
    {   // 7p
        0xfffffffffffffff9UL, 0xfffffff900000006UL,
        0xffffffffffffffffUL, 0xfffffff8ffffffffUL
    },
    {   // 8p
        0xfffffffffffffff8UL, 0xfffffff800000007UL,
        0xffffffffffffffffUL, 0xfffffff7ffffffffUL
    },
    {   // 9p
        0xfffffffffffffff7UL, 0xfffffff700000008UL,
        0xffffffffffffffffUL, 0xfffffff6ffffffffUL
    },
    {   // 10p
        0xfffffffffffffff6UL, 0xfffffff600000009UL,
        0xffffffffffffffffUL, 0xfffffff5ffffffffUL
    },
    {   // 11p
        0xfffffffffffffff5UL, 0xfffffff50000000aUL,
        0xffffffffffffffffUL, 0xfffffff4ffffffffUL
    },
    {   // 12p
        0xfffffffffffffff4UL, 0xfffffff40000000bUL,
        0xffffffffffffffffUL, 0xfffffff3ffffffffUL
    },
    {   // 13p
        0xfffffffffffffff3UL, 0xfffffff30000000cUL,
        0xffffffffffffffffUL, 0xfffffff2ffffffffUL
    },
};
#endif

const BN_UINT MOD_DATA_P384[][P384SIZE] = {
    {
        0x00000000ffffffffUL, 0xffffffff00000000UL, 0xfffffffffffffffeUL,
        0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL
    },
    {
        0x00000001fffffffeUL, 0xfffffffe00000000UL, 0xfffffffffffffffdUL,
        0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL
    },
    {
        0x00000002fffffffdUL, 0xfffffffd00000000UL, 0xfffffffffffffffcUL,
        0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL
    },
    {
        0x00000003fffffffcUL, 0xfffffffc00000000UL, 0xfffffffffffffffbUL,
        0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL
    },
    {
        0x00000004fffffffbUL, 0xfffffffb00000000UL, 0xfffffffffffffffaUL,
        0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL
    },
};

const BN_UINT MOD_DATA_P521[P521SIZE] = {
    0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL, 0x00000000000001ffUL
};

static BN_UINT NistP384Add(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t n)
{
    (void)n;
    BN_UINT carry = 0;
    ADD_ABC(carry, r[0], a[0], b[0], carry); /* offset 0 */
    ADD_ABC(carry, r[1], a[1], b[1], carry); /* offset 1 */
    ADD_ABC(carry, r[2], a[2], b[2], carry); /* offset 2 */
    ADD_ABC(carry, r[3], a[3], b[3], carry); /* offset 3 */
    ADD_ABC(carry, r[4], a[4], b[4], carry); /* offset 4 */
    ADD_ABC(carry, r[5], a[5], b[5], carry); /* offset 5 */
    return carry;
}

static BN_UINT NistP384Sub(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t n)
{
    (void)n;
    BN_UINT borrow = 0;
    SUB_ABC(borrow, r[0], a[0], b[0], borrow); /* offset 0 */
    SUB_ABC(borrow, r[1], a[1], b[1], borrow); /* offset 1 */
    SUB_ABC(borrow, r[2], a[2], b[2], borrow); /* offset 2 */
    SUB_ABC(borrow, r[3], a[3], b[3], borrow); /* offset 3 */
    SUB_ABC(borrow, r[4], a[4], b[4], borrow); /* offset 4 */
    SUB_ABC(borrow, r[5], a[5], b[5], borrow); /* offset 5 */
    return borrow;
}

/**
 * Reduction item: 2^128 + 2^96  - 2^32+ 2^0
 *
 * Reduction list   11  10   9   8   7   6   5   4   3   2   1   0
 *        a12	    00, 00, 00, 00, 00, 00, 00, 01, 01, 00, -1, 01,
 *        a13	    00, 00, 00, 00, 00, 00, 01, 01, 00, -1, 01, 00,
 *        a14	    00, 00, 00, 00, 00, 01, 01, 00, -1, 01, 00, 00,
 *        a15	    00, 00, 00, 00, 01, 01, 00, -1, 01, 00, 00, 00,
 *        a16	    00, 00, 00, 01, 01, 00, -1, 01, 00, 00, 00, 00,
 *        a17	    00, 00, 01, 01, 00, -1, 01, 00, 00, 00, 00, 00,
 *        a18	    00, 01, 01, 00, -1, 01, 00, 00, 00, 00, 00, 00,
 *        a19	    01, 01, 00, -1, 01, 00, 00, 00, 00, 00, 00, 00,
 *        a20	    01, 00, -1, 01, 00, 00, 00, 01, 01, 00, -1, 01,
 *        a21	    00, -1, 01, 00, 00, 00, 01, 02, 01, -1, 00, 01,
 *        a22	    -1, 01, 00, 00, 00, 01, 02, 01, -1, 00, 01, 00,
 *        a23	    01, 00, 00, 00, 01, 02, 01, -2, -1, 01, 01, -1
 *
 * Reduction chain
 * Coefficient   11  10   9   8   7   6   5   4   3   2   1   0
 *           1	 a23 a22 a21 a20 a19 a18 a17 a16 a15 a14 a13 a12
 *           1	 a20 a19 a18 a17 a16 a15 a14 a13 a12 a23 a22 a21
 *           1	 a19 a18 a17 a16 a15 a14 a13 a12 a20	 a23 a20
 *           1				 a23 a22 a21 a20 a21
 *           1						 a23 a22
 *           2					 a23 a22 a21
 *          -1   a22 a21 a20 a19 a18 a17 a16 a15 a14 a13 a12 a23
 *          -1							 a23 a22 a21 a20
 *          -1							 a23 a23
 */
int8_t ReduceNistP384(BN_UINT *r, const BN_UINT *a)
{
    BN_UINT list[P384SIZE];
    BN_UINT t[P384SIZE];
    // 0
    list[5] = a[11];                                        // offset 5 a23|a22 == ah[11]|al[11]
    list[4] = a[10];                                        // offset 4 a21|a20 == ah[10]|al[10]
    list[3] = a[9];                                         // offset 3 a19|a18 == ah[9]|al[9]
    list[2] = a[8];                                         // offset 2 a17|a16 == ah[8]|al[8]
    list[1] = a[7];                                         // offset 1 a15|a14 == ah[7]|al[7]
    list[0] = a[6];                                         // offset 0 a13|a12 == ah[6]|al[6]
    // 1
    t[5] = BN_UINT_LO_TO_HI(a[10]) | BN_UINT_HI(a[9]);      // offset 5 a20|a19 == al[10]|ah[9]
    t[4] = BN_UINT_LO_TO_HI(a[9]) | BN_UINT_HI(a[8]);       // offset 4 a18|a17 == al[9]|ah[8]
    t[3] = BN_UINT_LO_TO_HI(a[8]) | BN_UINT_HI(a[7]);       // offset 3 a16|a15 == al[8]|ah[7]
    t[2] = BN_UINT_LO_TO_HI(a[7]) | BN_UINT_HI(a[6]);       // offset 2 a14|a13 == al[7]|ah[6]
    t[1] = BN_UINT_LO_TO_HI(a[6]) | BN_UINT_HI(a[11]);      // offset 1 a12|a23 == al[6]|ah[11]
    t[0] = BN_UINT_LO_TO_HI(a[11]) | BN_UINT_HI(a[10]);     // offset 0 a22|a21 == al[11]|ah[10]
    int8_t carry = (int8_t)NistP384Add(t, list, t, P384SIZE);
    // 2
    list[5] = a[9];                                         // offset 5 a19|a18 == ah[9]|al[9]
    list[4] = a[8];                                         // offset 4 a17|a16 == ah[8]|al[8]
    list[3] = a[7];                                         // offset 3 a15|a14 == ah[7]|al[7]
    list[2] = a[6];                                         // offset 2 a13|a12 == ah[6]|al[6]
    list[1] = BN_UINT_LO_TO_HI(a[10]);                      // offset 1 a20|0  == al[10]| 0
    list[0] = BN_UINT_HI_TO_HI(a[11]) | BN_UINT_LO(a[10]);  // offset 0 a23|a20 == ah[11]|al[10]
    carry += (int8_t)NistP384Add(t, list, t, P384SIZE);
    // 3
    list[5] = 0;                                            // offset 5 0
    list[4] = 0;                                            // offset 4 0
    list[3] = a[11];                                        // offset 3 a23|a22 == ah[11]|al[11]
    list[2] = a[10];                                        // offset 2 a21|a20 == ah[10]|al[10]
    list[1] = BN_UINT_HI_TO_HI(a[10]);                      // offset 1 a21|0 == ah[10]|0
    list[0] = 0;                                            // offset 0 0
    carry += (int8_t)NistP384Add(t, list, t, P384SIZE);
    // 4
    list[5] = 0;                                            // offset 5 0
    list[4] = 0;                                            // offset 4 0
    list[3] = 0;                                            // offset 3 0
    list[2] = a[11];                                        // offset 2 a23|a22 == ah[11]|al[11]
    list[1] = 0;                                            // offset 1 0
    list[0] = 0;                                            // offset 0 0
    carry += (int8_t)NistP384Add(t, list, t, P384SIZE);
    // 5
    list[5] = 0;                                            // offset 5 0
    list[4] = 0;                                            // offset 4 0
    list[3] = BN_UINT_HI(a[11]);                            // offset 3 0|a23 == 0|ah[11]
    list[2] = BN_UINT_LO_TO_HI(a[11]) | BN_UINT_HI(a[10]);  // offset 2 a22|a21 == al[11]|ah[10]
    list[1] = 0;                                            // offset 1 0
    list[0] = 0;                                            // offset 0 0
    // double 5
    // list[3] is left-shifted by 1 bit and the most significant bit of list[2] is added.
    list[3] = (list[2] >> (BN_UINT_BITS - 1)) | (list[3] << 1);
    list[2] = list[2] << 1;  // list[2] left-shifted by 1bit
    carry += (int8_t)NistP384Add(t, list, t, P384SIZE);
    // 6
    list[5] = BN_UINT_LO_TO_HI(a[11]) | BN_UINT_HI(a[10]);  // offset 5 a22|a21 == al[11]|ah[10]
    list[4] = BN_UINT_LO_TO_HI(a[10]) | BN_UINT_HI(a[9]);   // offset 4 a20|a19 == al[10]|ah[9]
    list[3] = BN_UINT_LO_TO_HI(a[9]) | BN_UINT_HI(a[8]);    // offset 3 a18|a17 == al[9]|ah[8]
    list[2] = BN_UINT_LO_TO_HI(a[8]) | BN_UINT_HI(a[7]);    // offset 2 a16|a15 == al[8]|ah[7]
    list[1] = BN_UINT_LO_TO_HI(a[7]) | BN_UINT_HI(a[6]);    // offset 1 a14|a13 == al[7]|ah[6]
    list[0] = BN_UINT_LO_TO_HI(a[6]) | BN_UINT_HI(a[11]);   // offset 0 a12|a23 == al[6]|ah[11]
    carry -= (int8_t)NistP384Sub(t, t, list, P384SIZE);
    // 7
    list[5] = 0;                                            // offset 5 0
    list[4] = 0;                                            // offset 4 0
    list[3] = 0;                                            // offset 3 0
    list[2] = BN_UINT_HI(a[11]);                            // offset 2 0|a23 == 0|ah[11]
    list[1] = BN_UINT_LO_TO_HI(a[11]) | BN_UINT_HI(a[10]);  // offset 1 a22|a21 == al[11]|ah[10]
    list[0] = BN_UINT_LO_TO_HI(a[10]);                      // offset 0 a20|0 == al[10]|0
    carry -= (int8_t)NistP384Sub(t, t, list, P384SIZE);
    // 8
    list[5] = 0;                                            // offset 5 0
    list[4] = 0;                                            // offset 4 0
    list[3] = 0;                                            // offset 3 0
    list[2] = BN_UINT_HI(a[11]);                            // offset 2 0|a23 == 0|ah[11]
    list[1] = BN_UINT_HI_TO_HI(a[11]);                      // offset 1 a23|0 == ah[11]|0
    list[0] = 0;                                            // offset 0
    carry -= (int8_t)NistP384Sub(t, t, list, P384SIZE);
    carry += (int8_t)NistP384Add(r, t, a, P384SIZE);

    return carry;
}

// The size of a is 2*P384SIZE, and the size of r is P384SIZE
int32_t ModNistP384(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *m, BN_Optimizer *opt)
{
    (void)opt;
    (void)m;
    const BN_UINT *mod = MOD_DATA_P384[0];
    int8_t carry = ReduceNistP384(r->data, a->data);
    if (carry > 0) {
        carry = (int8_t)1 - (int8_t)BinSub(r->data, r->data, MOD_DATA_P384[carry - 1], P384SIZE);
    } else if (carry < 0) {
        // For details could ref p256.
        carry = (int8_t)1 - (int8_t)BinAdd(r->data, r->data, MOD_DATA_P384[-carry - 1], P384SIZE);
        carry = -carry;
    }
    if (carry < 0) {
        BinAdd(r->data, r->data, mod, P384SIZE);
    } else if (carry > 0 || BinCmp(r->data, P384SIZE, mod, P384SIZE) >= 0) {
        BinSub(r->data, r->data, mod, P384SIZE);
    }
    UpdateSize(r, P384SIZE);
    return 0;
}

// Reduction item: 2^0
int8_t ReduceNistP521(BN_UINT *r, const BN_UINT *a)
{
    #define P521LEFTBITS  (521 % (sizeof(BN_UINT) * 8))
    #define P521RIGHTBITS ((sizeof(BN_UINT) * 8) - P521LEFTBITS)
    BN_UINT t[P521SIZE];
    uint32_t base = P521SIZE - 1;
    uint32_t i;
    for (i = 0; i < P521SIZE - 1; i++) {
        t[i] = (a[i + base] >> P521LEFTBITS) | (a[i + base + 1] << P521RIGHTBITS);
        r[i] = a[i];
    }
    r[i] = a[i] & (((BN_UINT)1 << (P521LEFTBITS)) - 1);
    t[i] = (a[i + base] >> P521LEFTBITS);
    BinAdd(r, t, r, P521SIZE);
    return 0;
}

// The size of a is 2*P521SIZE-1, and the size of r is P521SIZE
int32_t ModNistP521(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *m, BN_Optimizer *opt)
{
    (void)opt;
    (void)m;
    const BN_UINT *mod = MOD_DATA_P521;
    ReduceNistP521(r->data, a->data);

    if (BinCmp(r->data, P521SIZE, mod, P521SIZE) >= 0) {
        BinSub(r->data, r->data, mod, P521SIZE);
    }
    UpdateSize(r, P521SIZE);

    return 0;
}

static inline int8_t P256SUB(BN_UINT *rr, const BN_UINT *aa, const BN_UINT *bb)
{
    BN_UINT borrow;
    SUB_AB(borrow, rr[0], aa[0], bb[0]);
    SUB_ABC(borrow, rr[1], aa[1], bb[1], borrow); /* offset 1 */
    SUB_ABC(borrow, rr[2], aa[2], bb[2], borrow); /* offset 2 */
    SUB_ABC(borrow, rr[3], aa[3], bb[3], borrow); /* offset 3 */
    return (int8_t)borrow;
}

static inline int8_t P256ADD(BN_UINT *rr, const BN_UINT *aa, const BN_UINT *bb)
{
    BN_UINT carry;
    ADD_AB(carry, rr[0], aa[0], bb[0]); /* offset 0 */
    ADD_ABC(carry, rr[1], aa[1], bb[1], carry); /* offset 1 */
    ADD_ABC(carry, rr[2], aa[2], bb[2], carry); /* offset 2 */
    ADD_ABC(carry, rr[3], aa[3], bb[3], carry); /* offset 3 */
    return (int8_t)carry;
}

/**
 *  NIST_P256 curve reduction calculation for parameter P
 *  Reduction item: 2^224 - 2^192 - 2^96 + 2^0
 *  ref. https://csrc.nist.gov/csrc/media/events/workshop-on-elliptic-curve-cryptography-standards/documents/papers/session6-adalier-mehmet.pdf
 *
 *  Reduction list:
 *   	 7   6   5   4   3   2   1   0
 *  a8	01, -1, 00, 00, -1, 00, 00, 01,
 *  a9	00, -1, 00, -1, -1, 00, 01, 01,
 *  a10	-1, 00, -1, -1, 00, 01, 01, 00,
 *  a11	-1, 00, -1, 00, 02, 01, 00, -1,
 *  a12	-1, 00, 00, 02, 02, 00, -1, -1,
 *  a13	-1, 01, 02, 02, 01, -1, -1, -1,
 *  a14	00, 03, 02, 01, 00, -1, -1, -1,
 *  a15	03, 02, 01, 00, -1, -1, -1, 00
 *
 *  Reduction chain
 *  Compared with the reduce flow of the paper, we have made proper transformation,
 *  which can reduce the splicing of upper 32 bits and lower 32 bits.
 *  Coefficient  7   6   5   4   3   2  1   0
 *           2	a15	a14	a13	a12	a12	 0	0	0
 *           2		a15	a14	a13	a11
 *           1	a15	a14	a15	a14	a13	a11	a9	a8
 *           1	a8	a13				a10	a10	a9
 *          -1	a13	a9	a11	a10	a15	a14	a15	a14
 *          -1	a12	a8	a10	a9	a8	a13	a14	a13
 *          -1	a11				a9	a15	a13	a12
 *          -1	a10						a12	a11
 */
static int8_t ReduceNistP256(BN_UINT *r, const BN_UINT *a)
{
    BN_UINT list[P256SIZE];
    BN_UINT t[P256SIZE];
    // Reduction chain 0
    list[3] = a[7];                                         // offset 3 a15|a14 == ah[7]|al[7]
    list[2] = a[6];                                         // offset 2 a13|a12 == ah[6]|al[6]
    list[1] = BN_UINT_LO_TO_HI(a[6]);                       // offset 1 a12|0 == al[6]|0
    list[0] = 0;                                            // offset 0 0
    // Reduction chain 1
    t[3] = BN_UINT_HI(a[7]);                                // offset 3 0|a15 == 0|ah[7]
    t[2] = BN_UINT_LO_TO_HI(a[7]) | BN_UINT_HI(a[6]);       // offset 2 a14|a13 == al[7]|ah[6]
    t[1] = BN_UINT_HI_TO_HI(a[5]);                          // offset 1 a11|0 == ah[5]|0
    t[0] = 0;                                               // offset 0 0
    int8_t carry = P256ADD(t, t, list);
    // carry multiplied by 2 and padded with the most significant bit of t[3]
    carry = (carry * 2) + (int8_t)(t[3] >> (BN_UINT_BITS - 1));
    t[3] = (t[3] << 1) | (t[2] >> (BN_UINT_BITS - 1)); // t[3] is shifted left by 1 bit and the MSB of t[2] is added.
    t[2] = (t[2] << 1) | (t[1] >> (BN_UINT_BITS - 1)); // t[2] is shifted left by 1 bit and the MSB of t[1] is added.
    t[1] = (t[1] << 1) | (t[0] >> (BN_UINT_BITS - 1)); // t[1] is shifted left by 1 bit and the MSB of t[0] is added.
    t[0] <<= 1;
    // 2
    list[3] = a[7];                                         // offset 3 a15|a14 == ah[7]|al[7]
    list[2] = a[7];                                         // offset 2 a15|a14 == ah[7]|al[7]
    list[1] = BN_UINT_HI_TO_HI(a[6]) | BN_UINT_HI(a[5]);    // offset 1 a13|a11 == ah[6]|ah[5]
    list[0] = a[4];                                         // offset 0 a9|a8 == ah[4]|al[4]
    carry += (int8_t)P256ADD(t, t, list);
    // 3
    list[3] = BN_UINT_LO_TO_HI(a[4]) | BN_UINT_HI(a[6]);    // offset 3 a8|a13 == al[4]|ah[6]
    list[2] = 0;                                            // offset 2 0
    list[1] = BN_UINT_LO(a[5]);                             // offset 1 0|a10 == 0|al[5]
    list[0] = BN_UINT_LO_TO_HI(a[5]) | BN_UINT_HI(a[4]);    // offset 0 a10|a9 == al[5]|ah[4]
    carry += (int8_t)P256ADD(t, t, list);
    // 4
    list[3] = BN_UINT_HI_TO_HI(a[6]) | BN_UINT_HI(a[4]);    // offset 3 a13|a9 == ah[6]|ah[4]
    list[2] = a[5];                                         // offset 2 a11|a10 == ah[5]|al[5]
    list[1] = a[7];                                         // offset 1 a15|a14 == ah[7]|al[7]
    list[0] = a[7];                                         // offset 0 a15|a14 == ah[7]|al[7]
    carry -= (int8_t)P256SUB(t, t, list);
    // 5
    list[3] = BN_UINT_LO_TO_HI(a[6]) | BN_UINT_LO(a[4]);    // offset 3 a12|a8 == al[6]|al[4]
    list[2] = BN_UINT_LO_TO_HI(a[5]) | BN_UINT_HI(a[4]);    // offset 2 a10|a9 == al[5]|ah[4]
    list[1] = BN_UINT_LO_TO_HI(a[4]) | BN_UINT_HI(a[6]);    // offset 1 a8|a13 == al[4]|ah[6]
    list[0] = BN_UINT_LO_TO_HI(a[7]) | BN_UINT_HI(a[6]);    // offset 0 a14|a13 == al[7]|ah[6]
    carry -= (int8_t)P256SUB(t, t, list);
    // 6
    list[3] = BN_UINT_HI_TO_HI(a[5]);                       // offset 3 a11|0 == ah[5]|0
    list[2] = 0;                                            // offset 2 0
    list[1] = BN_UINT_HI_TO_HI(a[4]) | BN_UINT_HI(a[7]);    // offset 1 a9|a15 == ah[4]|ah[7]
    list[0] = a[6];                                         // offset 0 a13|a12 == ah[6]|al[6]
    carry -= (int8_t)P256SUB(t, t, list);
    // 7
    list[3] = BN_UINT_LO_TO_HI(a[5]);                       // offset 3 a10|0 == al[5]|0
    list[2] = 0;                                            // offset 2 0
    list[1] = 0;                                            // offset 1 0
    list[0] = BN_UINT_LO_TO_HI(a[6]) | BN_UINT_HI(a[5]);    // offset 0 a12|a11 == al[6]|ah[5]
    carry -= (int8_t)P256SUB(t, t, list);
    carry += (int8_t)P256ADD(r, t, a);
    return carry;
}

// For the NIST_P256 curve, perform modulo operation on parameter P.
// The size of a is 2*P256SIZE, and the size of r is P256SIZE
int32_t ModNistP256(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *m, BN_Optimizer *opt)
{
    (void)opt;
    (void)m;
    const BN_UINT *mod = g_modDataP256[0];
    int8_t carry = ReduceNistP256(r->data, a->data);
    if (carry > 0) {
        carry = (int8_t)1 - (int8_t)P256SUB(r->data, r->data, g_modDataP256[carry - 1]);
    } else if (carry < 0) {
        /*
         * Here, we take carry < 0 as an example.
         * If carry = -3, it indicates that ReduceNistP256 needs to be borrowed three times. In this case,
         * we need to add 3 * p. It is worth noting that we have estimated 3 * p in g_modDataP256,
         * but the carry of 3 * p is not save, which is expressed by the following formula:
         *           g_modDataP256[2] = 3 * p mod 2^256, we denoted as 2 + (3 * p)_remain.
         * Actually, we need to calculate the following formula:
         *           -3 + r_data + 2 + (3 * p)_remain = -1 + r_data + (3 * p)_remain
         * Obviously, -1 is a mathematical borrowing, only r_data + (3 * p)_remain is calculated in actual P256ADD.
         * Therefore, we still need to consider the carry case of P256ADD.
         *   1. r_data + (3 * p)_remain has a carry. -1 has been eliminated. We only need to consider
         *       whether r_data + (3 * p)_remain belongs to [0, p).
         *   2. r_data + (3*p)_remain does not carry. It indicates that –1 is not eliminated. We need to add another P
         *       to eliminate –1. Considering the value of 3 * p in g_modDataP256, r_data + (3 * p)_remain + P must
         *       generate a carry, and the final result value < P.
        */
        carry = (int8_t)1 - (int8_t)P256ADD(r->data, r->data, g_modDataP256[-carry - 1]);
        carry = -carry;
    }
    if (carry < 0) {
        P256ADD(r->data, r->data, mod);
    } else if (carry > 0 || BinCmp(r->data, P256SIZE, mod, P256SIZE) >= 0) {
        P256SUB(r->data, r->data, mod);
    }
    UpdateSize(r, P256SIZE);
    return 0;
}

/**
 *  NIST_P224 curve reduction calculation for parameter P
 *  Reduction item: 2^96 - 2^0
 *
 *  Reduction list:
 *      6   5   4   3   2  1   0
 *  a7	00, 00, 00, 01, 00, 00, -1
 *  a8	00, 00, 01, 00, 00, -1, 00
 *  a9	00, 01, 00, 00, -1, 00, 00
 *  a10	01, 00, 00, -1, 00, 00, 00
 *  a11	00, 00, -1, 01, 00, 00, -1
 *  a12	00, -1, 01, 00, 00, -1, 00
 *  a13	-1, 01, 00, 00, -1, 00, 00
 *
 *  Reduction chain
 *  Coefficient  6  5	 4	 3	 2	1	0
 *          1	a10	a9	a8	a7
 *          1		a13	a12	a11
 *         -1	a13	a12	a11	a10	a9	a8	a7
 *         -1					a13	a12	a11
 */
static int8_t ReduceNistP224(BN_UINT *r, const BN_UINT *a)
{
    BN_UINT list[P224SIZE];
    BN_UINT t[P224SIZE];
    // 1
    list[3] = BN_UINT_LO(a[5]);                             // offset 3 0|a10 == 0|al[5]
    list[2] = a[4];                                         // offset 2 a9|a8 == ah[4]|al[4]
    list[1] = BN_UINT_HI_TO_HI(a[3]);                       // offset 1 a7|0 == ah[3]|0
    list[0] = 0;                                            // offset 0 0
    // 2
    t[3] = 0;                                               // offset 3 0
    t[2] = a[6];                                            // offset 2 a13|a12 == ah[6]|al[6]
    t[1] = BN_UINT_HI_TO_HI(a[5]);                          // offset 1 a11|0 == ah[5]|0
    t[0] = 0;                                               // offset 0 0
    P256ADD(t, t, list);
    // 3
    list[3] = BN_UINT_HI(a[6]);                             // offset 3 0|a13 == 0|ah[6]
    list[2] = BN_UINT_LO_TO_HI(a[6]) | BN_UINT_HI(a[5]);    // offset 2 a12|a11 == al[6]|ah[5]
    list[1] = BN_UINT_LO_TO_HI(a[5]) | BN_UINT_HI(a[4]);    // offset 1 a10|a9 == al[5]|ah[4]
    list[0] = BN_UINT_LO_TO_HI(a[4]) | BN_UINT_HI(a[3]);    // offset 0 a8|a7 == al[4]|ah[3]
    P256SUB(t, t, list);
    // 4
    list[3] = 0;                                            // offset 3 0
    list[2] = 0;                                            // offset 2 0
    list[1] = BN_UINT_HI(a[6]);                             // offset 1 0|a13 == 0|ah[6]
    list[0] = BN_UINT_LO_TO_HI(a[6]) | BN_UINT_HI(a[5]);    // offset 0 a12|a11 == al[6]|ah[5]
    P256SUB(t, t, list);

    r[3] = BN_UINT_LO(a[3]);                                // Take lower 32 bits of a[3]
    r[2] = a[2];                                            // Take a[2]
    r[1] = a[1];
    r[0] = a[0];
    P256ADD(r, r, t);

    return 0;
}

// NIST_P224 curve reduction calculation for parameter P. The size of a is 2*P224SIZE-1, and the size of r is P224SIZE
int32_t ModNistP224(
    BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *m, BN_Optimizer *opt)
{
    (void)opt;
    (void)m;
    const BN_UINT *mod = g_modDataP224[0];
    ReduceNistP224(r->data, a->data);
    // Obtain the high-order data of r[3] as carry information
    int8_t carry = (int8_t)((uint8_t)(BN_UINT_HI(r->data[3]) & 0xFF));
    if (carry > 0) {
        (void)P256SUB(r->data, r->data, g_modDataP224[carry - 1]);
    } else if (carry < 0) {
        (void)P256ADD(r->data, r->data, g_modDataP224[-carry - 1]);
    }
    // Obtain the high-order data of r[3] as carry information
    carry = (int8_t)((uint8_t)(BN_UINT_HI(r->data[3]) & 0xFF));
    if (carry < 0) {
        P256ADD(r->data, r->data, mod);
    } else if (carry > 0 || BinCmp(r->data, P256SIZE, mod, P256SIZE) >= 0) {
        P256SUB(r->data, r->data, mod);
    }
    UpdateSize(r, P224SIZE);
    return 0;
}

/**
 * Reduction item: 2^224 + 2^96 - 2^64  + 2^0
 *   	  7    6    5    4    3    2    1    0
 *  a8   01,  00,  00,  00,  01,  -1,  00,  01,
 *  a9	 01,  00,  00,  01,  00,  -1,  01,  01,
 *  a10	 01,  00,  01,  00,  00,  00,  01,  01,
 *  a11	 01,  01,  00,  00,  01,  00,  01,  01,
 *  a12	 02,  00,  00,  01,  01,  00,  01,  01,
 *  a13	 02,  00,  01,  01,  02,  -1,  01,  02,
 *  a14	 02,  01,  01,  02,  01,  -1,  02,  02,
 *  a15	 03,  01,  02,  01,  01,  00,  02,  02,


 *  Reduction chain
 *  The last two reduction chain can be combined into the third to last chain for calculation.
 *  Coefficient  7    6    5    4     3    2    1    0
 *         2    a15  a14  a15  a14   a13   0   a15   a14
 *         2    a14   0    0    0    0     0   a14   a13
 *         2    a13   0   a13  a12   a11   0   a12   a11
 *         2    a12  a11  a10   a9    0    0   a9    a8
 *         1    a15   0    0    a15  a14   0   a13   a12
 *         1    a11   0    0    0     a8   0    0    a15
 *         1    a10   0    0    0    a15   0   a11   a10
 *         1    a9                             a10   a9
 *         1    a8   a15  a14  a13   a12             a15
 *        -1         a14  a13  a12   a11  a13  a12   a11
 *        -1         a11  a10   a9    0   a14  a9    a8
 *        -1                              a8
 *        -1                              a9
 */
#ifdef HITLS_CRYPTO_CURVE_SM2
static int8_t ReduceSm2P256(BN_UINT *r, const BN_UINT *a)
{
    BN_UINT list[P256SIZE];
    BN_UINT t[P256SIZE];

    // Reduction chain 0, Coefficient 2
    list[3] = a[7];                                         // offset 3 a15|a14 == ah[7]|al[7]
    list[2] = a[7];                                         // offset 2 a15|a14 == ah[7]|al[7]
    list[1] = BN_UINT_HI_TO_HI(a[6]);                       // offset 1 a13|0 == ah[6]|0
    list[0] = a[7];                                         // offset 0 a15|a14 == ah[7]|al[7]

    // Reduction chain 1, Coefficient 2
    t[3] = BN_UINT_LO_TO_HI(a[7]);                          // offset 3 a14|0 == al[7]|0
    t[2] = 0;                                               // offset 2 0
    t[1] = 0;                                               // offset 1 0
    t[0] = BN_UINT_LO_TO_HI(a[7]) | BN_UINT_HI(a[6]);       // offset 0 a14|a13 = al[7]|ah[6]
    int8_t carry = P256ADD(t, t, list);

    // Reduction chain 2, Coefficient 2
    list[3] = BN_UINT_HI_TO_HI(a[6]);                       // offset 3 a13|0 == ah[6]|0
    list[2] = a[6];                                         // offset 2 a13|a12 == ah[6]|al[6]
    list[1] = BN_UINT_HI_TO_HI(a[5]);                       // offset 1 a11|0 == ah[5]|0
    list[0] = BN_UINT_LO_TO_HI(a[6]) | BN_UINT_HI(a[5]);    // offset 0 a12|a11 == al[6]|ah[5]
    carry += (int8_t)P256ADD(t, t, list);

    // Reduction chain 3, Coefficient 2
    list[3] = BN_UINT_LO_TO_HI(a[6]) | BN_UINT_HI(a[5]);    // offset 3 a12|a11 == al[6]|ah[5]
    list[2] = BN_UINT_LO_TO_HI(a[5]) | BN_UINT_HI(a[4]);    // offset 2 a10|a9 == al[5]|ah[4]
    list[1] = 0;                                            // offset 1 0
    list[0] = a[4];                                         // offset 0 a9|a8 == ah[4]|al[4]
    carry += (int8_t)P256ADD(t, t, list);

    // carry multiplied by 2 and padded with the most significant bit of t[3]
    carry = (carry * 2) + (int8_t)(t[3] >> (BN_UINT_BITS - 1));
    t[3] = (t[3] << 1) | (t[2] >> (BN_UINT_BITS - 1)); // t[3] is shifted left by 1 bit and the MSB of t[2] is added.
    t[2] = (t[2] << 1) | (t[1] >> (BN_UINT_BITS - 1)); // t[2] is shifted left by 1 bit and the MSB of t[1] is added.
    t[1] = (t[1] << 1) | (t[0] >> (BN_UINT_BITS - 1)); // t[1] is shifted left by 1 bit and the MSB of t[0] is added.
    t[0] <<= 1;

    // Reduction chain 4, Coefficient 1
    list[3] = BN_UINT_HI_TO_HI(a[7]);                      // offset 3 a15|0 == ah[7]|0
    list[2] = BN_UINT_HI(a[7]);                            // offset 2  0|a15 == 0|ah[7]
    list[1] = BN_UINT_LO_TO_HI(a[7]);                      // offset 1 a14|0 == al[7]|0
    list[0] = a[6];                                        // offset 0 a13|a12 == ah[6]|al[6]
    carry += (int8_t)P256ADD(t, t, list);

    // Reduction chain 5, Coefficient 1
    list[3] = BN_UINT_HI_TO_HI(a[5]);                      // offset 3 a11|0 == ah[5]|0
    list[2] = 0;                                           // offset 2 0
    list[1] = BN_UINT_LO_TO_HI(a[4]);                      // offset 1 a8|0 == al[4]|0
    list[0] = BN_UINT_HI(a[7]);                            // offset 0 0|a15 == 0|ah[7]
    carry += (int8_t)P256ADD(t, t, list);

    // Reduction chain 6, Coefficient 1
    list[3] = BN_UINT_LO_TO_HI(a[5]);                      // offset 3 a10|0 == al[5]|0
    list[2] = 0;                                           // offset 2 0
    list[1] = BN_UINT_HI_TO_HI(a[7]);                      // offset 1 a15|0 == ah[7]|0
    list[0] = a[5];                                        // offset 0 a11|a10 == ah[5]|al[5]
    carry += (int8_t)P256ADD(t, t, list);

    // Reduction chain 7, Coefficient 1
    list[3] = BN_UINT_HI_TO_HI(a[4]);                     // offset 3 a9|0 == ah[4]|0
    list[2] = 0;                                          // offset 2 0
    list[1] = 0;                                          // offset 1 0
    list[0] = BN_UINT_LO_TO_HI(a[5]) | BN_UINT_HI(a[4]);  // offset 0 a10|a9 == al[5]|ah[4]
    carry += (int8_t)P256ADD(t, t, list);

    // Reduction chain 8, Coefficient 1
    list[3] = BN_UINT_LO_TO_HI(a[4]) | BN_UINT_HI(a[7]);  // offset 3 a8|a15 == al[4]|ah[7]
    list[2] = BN_UINT_LO_TO_HI(a[7]) | BN_UINT_HI(a[6]);  // offset 2 a14|a13 = al[7]|ah[6]
    list[1] = BN_UINT_LO_TO_HI(a[6]);                     // offset 1 a12|0 == al[6]|0
    list[0] = BN_UINT_HI(a[7]);                           // offset 0  0|a15 == 0|ah[7]
    carry += (int8_t)P256ADD(t, t, list);

    // Reduction chain 9, Coefficient -1
    list[3] = BN_UINT_LO(a[7]);                             // offset 3 0|a14 == 0|al[7]
    list[2] = a[6];                                         // offset 2 a13|a12 == ah[6]|al[6]
    list[1] = BN_UINT_HI_TO_HI(a[5]) | BN_UINT_HI(a[6]);    // offset 1 a11|a13 == ah[5]|ah[6]
    list[0] = BN_UINT_LO_TO_HI(a[6]) | BN_UINT_HI(a[5]);    // offset 0 a12|a11 == al[6]|ah[5]
    carry -= (int8_t)P256SUB(t, t, list);

    // Reduction chain 10, Coefficient -1
    list[3] = BN_UINT_HI(a[5]);                                       // offset 3 0|a11 == 0|ah[5]
    list[2] = BN_UINT_LO_TO_HI(a[5]) | BN_UINT_HI(a[4]);              // offset 2 a10|a9 == al[5]|ah[4]
    // offset 1 0|a14 == 0|al[7]. Add the values of the last two chains.
    list[1] = BN_UINT_LO(a[7]) + BN_UINT_HI(a[4]) + BN_UINT_LO(a[4]);
    list[0] = a[4];                                                   // offset 0 a9|a8 == ah[4]|al[4]
    carry -= (int8_t)P256SUB(t, t, list);

    carry += (int8_t)P256ADD(r, t, a);
    return carry;
}

// SM2_P256 curve modulo parameter P. The size of a is 2*P256SIZE, and the size of r is P256SIZE
int32_t ModSm2P256(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *m, BN_Optimizer *opt)
{
    (void)opt;
    (void)m;
    const BN_UINT *mod = MODDATASM2P256[0];
    int8_t carry = ReduceSm2P256(r->data, a->data);
    if (carry < 0) {
        carry = (int8_t)1 - (int8_t)P256ADD(r->data, r->data, MODDATASM2P256[-carry - 1]);
        carry = -carry;
    } else if (carry > 0) {
        // For details could ref p256.
        carry = (int8_t)1 - (int8_t)P256SUB(r->data, r->data, MODDATASM2P256[carry - 1]);
    }
    if (carry < 0) {
        P256ADD(r->data, r->data, mod);
    } else if (carry > 0 || BinCmp(r->data, P256SIZE, mod, P256SIZE) >= 0) {
        P256SUB(r->data, r->data, mod);
    }
    UpdateSize(r, P256SIZE);
    return 0;
}
#endif

#elif defined(HITLS_THIRTY_TWO_BITS)

#define ModNistP192(r, a, m, opt) BN_Mod(r, a, m, opt)
#define ModNistP224(r, a, m, opt) BN_Mod(r, a, m, opt)
#define ModNistP256(r, a, m, opt) BN_Mod(r, a, m, opt)
#define ModNistP384(r, a, m, opt) BN_Mod(r, a, m, opt)
#define ModNistP521(r, a, m, opt) BN_Mod(r, a, m, opt)

#ifdef HITLS_CRYPTO_CURVE_SM2
#define ModSm2P256(r, a, m, opt) BN_Mod(r, a, m, opt)
#endif

#endif

#if defined(HITLS_CRYPTO_BN_COMBA) && defined(HITLS_SIXTY_FOUR_BITS)
static uint32_t MulNistP256P224(BN_UINT *r, uint32_t rSize, const BN_UINT *a, uint32_t aSize,
    const BN_UINT *b, uint32_t bSize)
{
    (void)rSize;
    (void)aSize;
    (void)bSize;

    MulComba4(r, a, b);
    uint32_t size = P224SIZE << 1; // in 64-bit environment, P224SIZE = P256SIZE
    while (size > 0) {
        if (r[size - 1] != 0) {
            break;
        }
        --size;
    }
    return size;
}

static uint32_t SqrNistP256P224(BN_UINT *r, uint32_t rSize, const BN_UINT *a, uint32_t aSize)
{
    (void)rSize;
    (void)aSize;

    SqrComba4(r, a);
    uint32_t size = P224SIZE << 1; // in 64-bit environment, P224SIZE = P256SIZE
    while (size > 0) {
        if (r[size - 1] != 0) {
            break;
        }
        --size;
    }
    return size;
}

static uint32_t MulNistP384(BN_UINT *r, uint32_t rSize, const BN_UINT *a, uint32_t aSize,
    const BN_UINT *b, uint32_t bSize)
{
    (void)rSize;
    (void)aSize;
    (void)bSize;

    MulComba6(r, a, b);
    uint32_t size = P384SIZE << 1;
    while (size > 0) {
        if (r[size - 1] != 0) {
            break;
        }
        size--;
    }
    return size;
}

static uint32_t SqrNistP384(BN_UINT *r, uint32_t rSize, const BN_UINT *a, uint32_t aSize)
{
    (void)rSize;
    (void)aSize;

    SqrComba6(r, a);
    uint32_t size = P384SIZE << 1;
    while (size > 0) {
        if (r[size - 1] != 0) {
            break;
        }
        size--;
    }
    return size;
}
#else

#define MulNistP256P224(r, rSize, a, aSize, b, bSize) BinMul(r, rSize, a, aSize, b, bSize)
#define SqrNistP256P224(r, rSize, a, aSize)           BinSqr(r, rSize, a, aSize)
#define MulNistP384(r, rSize, a, aSize, b, bSize)     BinMul(r, rSize, a, aSize, b, bSize)
#define SqrNistP384(r, rSize, a, aSize)               BinSqr(r, rSize, a, aSize)

#endif

static inline int32_t ModCalParaCheck(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, const BN_BigNum *mod)
{
    if (r == NULL || a == NULL || b == NULL || mod == NULL) {
        return CRYPT_NULL_INPUT;
    }
    // 保证不越界访问
    if ((mod->size > a->room) || (mod->size > b->room)) {
        return CRYPT_BN_SPACE_NOT_ENOUGH;
    }
    return BnExtend(r, mod->size);
}

// The user must ensure that a < m, and a->room & b->room are not less than mod->size.
// All the data must be not negative number, otherwise the API may be not functional.
int32_t BN_ModAddQuick(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
    const BN_BigNum *mod, const BN_Optimizer *opt)
{
    int32_t ret = ModCalParaCheck(r, a, b, mod);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)opt;
    BN_UINT carry = BinAdd(r->data, a->data, b->data, mod->size);
    if (carry > 0 || BinCmp(r->data, mod->size, mod->data, mod->size) >= 0) {
        BinSub(r->data, r->data, mod->data, mod->size);
    }
    UpdateSize(r, mod->size);
    return CRYPT_SUCCESS;
}

// The user must ensure that a < m, and a->room & b->room are not less than mod->size.
// All the data must be not negative number, otherwise the API may be not functional.
int32_t BN_ModSubQuick(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
    const BN_BigNum *mod, const BN_Optimizer *opt)
{
    int32_t ret = ModCalParaCheck(r, a, b, mod);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)opt;
    int32_t res = BinCmp(a->data, a->size, b->data, b->size);
    if (res < 0) {
        /* Apply for the temporary space of the BN object. */
        BinSub(r->data, a->data, b->data, mod->size);
        BinAdd(r->data, r->data, mod->data, mod->size);
    } else {
        BinSub(r->data, a->data, b->data, mod->size);
    }
    UpdateSize(r, mod->size);
    return CRYPT_SUCCESS;
}

static inline int32_t ModEccMulParaCheck(BN_BigNum *r, const BN_BigNum *a,
    const BN_BigNum *b, const BN_BigNum *mod, BN_Optimizer *opt)
{
    if (r == NULL || a == NULL || b == NULL || mod == NULL || opt == NULL) {
        return CRYPT_NULL_INPUT;
    }
    // Ensure that no out-of-bounds access occurs.
    if ((mod->size > b->room) || (mod->size > a->room)) {
        return CRYPT_BN_SPACE_NOT_ENOUGH;
    }
    return BnExtend(r, mod->size);
}
// The user must ensure that a < m, and a->room & b->room are not less than mod->size.
// All the data must be not negative number, otherwise the API may be not functional.
int32_t BN_ModNistEccMul(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, void *data, BN_Optimizer *opt)
{
    BN_BigNum *mod = (BN_BigNum *)data;
    int32_t ret = ModEccMulParaCheck(r, a, b, mod, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (b->size == 0 || a->size == 0) {
        return BN_Zeroize(r);
    }
    BN_UINT tData[P521SIZE << 1] = { 0 };
    BN_BigNum rMul = {
        .data = tData,
        .size = 0,
        .sign = false,
        .room = P521SIZE << 1
    };
    uint32_t size = mod->size << 1;
    uint32_t bits = BN_Bits(mod);
    if (bits == 224) { // 224bit
        rMul.size = MulNistP256P224(rMul.data, size, a->data, mod->size, b->data, mod->size);
        ModNistP224(r, &rMul, mod, opt);
    } else if (bits == 256) { // 256bit
        rMul.size = MulNistP256P224(rMul.data, size, a->data, mod->size, b->data, mod->size);
        ModNistP256(r, &rMul, mod, opt);
    } else if (bits == 384) { // 384bit
        rMul.size = MulNistP384(rMul.data, size, a->data, mod->size, b->data, mod->size);
        ModNistP384(r, &rMul, mod, opt);
    } else if (bits == 521) { // 521bit
        rMul.size = BinMul(rMul.data, size, a->data, mod->size, b->data, mod->size);
        ModNistP521(r, &rMul, mod, opt);
    } else if (bits == 192) { // 192bit
        return BN_ModMul(r, a, b, mod, opt);
    } else {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_QUICK_MODDATA);
        return CRYPT_BN_ERR_QUICK_MODDATA;
    }
    return CRYPT_SUCCESS;
}

static int32_t ModEccSqrParaCheck(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *mod, BN_Optimizer *opt)
{
    if (r == NULL || a == NULL || mod == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // Ensure that no out-of-bounds access occurs.
    if (mod->size > a->room) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_SPACE_NOT_ENOUGH);
        return CRYPT_BN_SPACE_NOT_ENOUGH;
    }
    return BnExtend(r, mod->size);
}

// The user must ensure that a < m, and a->room & b->room are not less than mod->size.
// All the data must be not negative number, otherwise the API may be not functional.
int32_t BN_ModNistEccSqr(BN_BigNum *r, const BN_BigNum *a, void *data, BN_Optimizer *opt)
{
    BN_BigNum *mod = (BN_BigNum *)data;
    int32_t ret = ModEccSqrParaCheck(r, a, mod, opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (a->size == 0) {
        return BN_Zeroize(r);
    }
    BN_UINT tData[P521SIZE << 1] = { 0 };
    BN_BigNum rSqr = {
        .data = tData,
        .size = 0,
        .sign = false,
        .room = P521SIZE << 1
    };
    uint32_t size = mod->size << 1;
    uint32_t bits = BN_Bits(mod);
    if (bits == 224) { // 224bit
        rSqr.size = SqrNistP256P224(rSqr.data, size, a->data, mod->size);
        ModNistP224(r, &rSqr, mod, opt);
    } else if (bits == 256) { // 256bit
        rSqr.size = SqrNistP256P224(rSqr.data, size, a->data, mod->size);
        ModNistP256(r, &rSqr, mod, opt);
    } else if (bits == 384) { // 384bit
        rSqr.size = SqrNistP384(rSqr.data, size, a->data, mod->size);
        ModNistP384(r, &rSqr, mod, opt);
    } else if (bits == 521) { // 521bit
        rSqr.size = BinSqr(rSqr.data, size, a->data, mod->size);
        ModNistP521(r, &rSqr, mod, opt);
    } else if (bits == 192) { // 192bit
        return BN_ModSqr(r, a, mod, opt);
    } else {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_QUICK_MODDATA);
        return CRYPT_BN_ERR_QUICK_MODDATA;
    }
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_CURVE_SM2

#define SM2SIZE SIZE_OF_BNUINT(256)

// The user must ensure that a < m, and a->room & b->room are not less than mod->size.
// All the data must be not negative number, otherwise the API may be not functional.
int32_t BN_ModSm2EccMul(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, void *data, BN_Optimizer *opt)
{
    BN_BigNum *mod = (BN_BigNum *)data;
    int32_t ret = ModEccMulParaCheck(r, a, b, mod, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (a->size == 0 || b->size == 0) {
        return BN_Zeroize(r);
    }
    BN_UINT tData[SM2SIZE << 1] = { 0 };
    BN_BigNum rMul = {
        .data = tData,
        .size = 0,
        .sign = false,
        .room = SM2SIZE << 1
    };
    uint32_t size = mod->size << 1;
    rMul.size = MulNistP256P224(rMul.data, size, a->data, mod->size, b->data, mod->size);
    ModSm2P256(r, &rMul, mod, opt);

    return CRYPT_SUCCESS;
}

// The user must ensure that a < m, and a->room & b->room are not less than mod->size.
// All the data must be not negative number, otherwise the API may be not functional.
int32_t BN_ModSm2EccSqr(BN_BigNum *r, const BN_BigNum *a, void *data, BN_Optimizer *opt)
{
    BN_BigNum *mod = (BN_BigNum *)data;
    int32_t ret = ModEccSqrParaCheck(r, a, mod, opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (a->size == 0) {
        return BN_Zeroize(r);
    }
    BN_UINT tData[SM2SIZE << 1] = { 0 };
    BN_BigNum rSqr = {
        .data = tData,
        .size = 0,
        .sign = false,
        .room = SM2SIZE << 1
    };
    uint32_t size = mod->size << 1;
    rSqr.size = SqrNistP256P224(rSqr.data, size, a->data, mod->size);
    ModSm2P256(r, &rSqr, mod, opt);

    return CRYPT_SUCCESS;
}
#endif
#endif
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
#ifdef HITLS_CRYPTO_X25519

#include "securec.h"
#include "curve25519_local.h"

// X25519 alternative implementation, faster but require int128
#ifdef HITLS_INT128
#define CURVE25519_51BITS_MASK 0x7ffffffffffff
#define CURVE25519_51BITS 51

static void Fp51DataToPoly(Fp51 *out, const uint8_t in[32])
{
    uint64_t h[5];

    CURVE25519_BYTES7_LOAD(h, in);

    CURVE25519_BYTES6_LOAD(h + 1, in + 7);
    h[1] <<= 5;

    CURVE25519_BYTES7_LOAD(h + 2, in + 13);
    h[2] <<= 2;

    CURVE25519_BYTES6_LOAD(h + 3, in + 20);
    h[3] <<= 7;

    CURVE25519_BYTES6_LOAD(h + 4, in + 26);
    h[4] &= 0x7fffffffffff; // 41 bits mask = 0x7fffffffffff
    h[4] <<= 4;

    h[1] |= h[0] >> CURVE25519_51BITS;
    h[0] &= CURVE25519_51BITS_MASK;

    h[2] |= h[1] >> CURVE25519_51BITS;
    h[1] &= CURVE25519_51BITS_MASK;

    h[3] |= h[2] >> CURVE25519_51BITS;
    h[2] &= CURVE25519_51BITS_MASK;

    h[4] |= h[3] >> CURVE25519_51BITS;
    h[3] &= CURVE25519_51BITS_MASK;

    out->data[0] = h[0];
    out->data[1] = h[1];
    out->data[2] = h[2];
    out->data[3] = h[3];
    out->data[4] = h[4];
}

static void Fp51UnloadTo8Bits(uint8_t out[32], uint64_t h[5])
{
    // load from uint64 to uint8, load 8 bits at a time
    out[0] = (uint8_t)h[0];
    out[1] = (uint8_t)(h[0] >> 8);
    out[2] = (uint8_t)(h[0] >> 16);
    out[3] = (uint8_t)(h[0] >> 24);
    out[4] = (uint8_t)(h[0] >> 32);
    out[5] = (uint8_t)(h[0] >> 40);
    // load from position 48 from h[1] and (8-5)=3 bits from h[1] to out[6]
    out[6] = (uint8_t)((h[0] >> 48) | (uint8_t)(h[1] << 3));
    out[7] = (uint8_t)(h[1] >> 5);
    out[8] = (uint8_t)(h[1] >> 13);
    out[9] = (uint8_t)(h[1] >> 21);
    out[10] = (uint8_t)(h[1] >> 29);
    out[11] = (uint8_t)(h[1] >> 37);
    // load from position 45 from h[1] and (8-2)=6 bits from h[2] to out[12]
    out[12] = (uint8_t)((h[1] >> 45) | (uint8_t)(h[2] << 6));
    out[13] = (uint8_t)(h[2] >> 2);
    out[14] = (uint8_t)(h[2] >> 10);
    out[15] = (uint8_t)(h[2] >> 18);
    out[16] = (uint8_t)(h[2] >> 26);
    out[17] = (uint8_t)(h[2] >> 34);
    out[18] = (uint8_t)(h[2] >> 42);
    // load from position 50 from h[2] and (8-1)=7 bits from h[3] to out[19]
    out[19] = (uint8_t)((h[2] >> 50) | (uint8_t)(h[3] << 1));
    out[20] = (uint8_t)(h[3] >> 7);
    out[21] = (uint8_t)(h[3] >> 15);
    out[22] = (uint8_t)(h[3] >> 23);
    out[23] = (uint8_t)(h[3] >> 31);
    out[24] = (uint8_t)(h[3] >> 39);
    // load from position 47 from h[3] and (4-4)=4 bits from h[4] to out[25]
    out[25] = (uint8_t)((h[3] >> 47) | (uint8_t)(h[4] << 4));
    out[26] = (uint8_t)(h[4] >> 4);
    out[27] = (uint8_t)(h[4] >> 12);
    out[28] = (uint8_t)(h[4] >> 20);
    out[29] = (uint8_t)(h[4] >> 28);
    out[30] = (uint8_t)(h[4] >> 36);
    out[31] = (uint8_t)(h[4] >> 44);
}

static void Fp51PolyToData(const Fp51 *in, uint8_t out[32])
{
    uint64_t h[5];
    h[0] = in->data[0];
    h[1] = in->data[1];
    h[2] = in->data[2];
    h[3] = in->data[3];
    h[4] = in->data[4];
    uint64_t carry;

    carry = (h[0] + 19) >> CURVE25519_51BITS; // plus 19 then calculate carry
    carry = (h[1] + carry) >> CURVE25519_51BITS;
    carry = (h[2] + carry) >> CURVE25519_51BITS;
    carry = (h[3] + carry) >> CURVE25519_51BITS;
    carry = (h[4] + carry) >> CURVE25519_51BITS;

    h[0] += 19 * carry; // process carry h[4] -> h[0], h[0] += 19 * carry
    h[1] += h[0] >> CURVE25519_51BITS;
    h[0] &= CURVE25519_51BITS_MASK;
    h[2] += h[1] >> CURVE25519_51BITS;
    h[1] &= CURVE25519_51BITS_MASK;
    h[3] += h[2] >> CURVE25519_51BITS;
    h[2] &= CURVE25519_51BITS_MASK;
    h[4] += h[3] >> CURVE25519_51BITS;
    h[3] &= CURVE25519_51BITS_MASK;
    h[4] &= CURVE25519_51BITS_MASK;

    Fp51UnloadTo8Bits(out, h);
}

void Fp51ProcessCarry(__uint128_t in[5])
{
    in[1] += (uint64_t)(in[0] >> CURVE25519_51BITS);
    in[0] = (uint64_t)in[0] & CURVE25519_51BITS_MASK;

    in[2] += (uint64_t)(in[1] >> CURVE25519_51BITS);
    in[1] = (uint64_t)in[1] & CURVE25519_51BITS_MASK;

    in[3] += (uint64_t)(in[2] >> CURVE25519_51BITS);
    in[2] = (uint64_t)in[2] & CURVE25519_51BITS_MASK;

    in[4] += (uint64_t)(in[3] >> CURVE25519_51BITS);
    in[3] = (uint64_t)in[3] & CURVE25519_51BITS_MASK;

    in[0] += (uint64_t)(in[4] >> CURVE25519_51BITS) * 19;
    in[4] = (uint64_t)in[4] & CURVE25519_51BITS_MASK;

    in[1] += in[0] >> CURVE25519_51BITS;
    in[0] &= CURVE25519_51BITS_MASK;
}

void Fp51Mul(Fp51 *out, const Fp51 *f, const Fp51 *g)
{
    __uint128_t h[5];
    // h[0] = f0g0 + 19*f1g4 + 19*f2g3 + 19*f3g2 + 19*f4g1
    h[0] = (__uint128_t)f->data[0] * g->data[0] + (__uint128_t)f->data[1] * g->data[4] * 19 +
        (__uint128_t)f->data[2] * g->data[3] * 19 + (__uint128_t)f->data[3] * g->data[2] * 19 + // 19*f2g3 + 19*f3g2
        (__uint128_t)f->data[4] * g->data[1] * 19; // 19*f4g1
    // h[1] = f0g1 + f1g0 + 19*f2g4 + 19*f3g3 + 19*f4g2
    h[1] = (__uint128_t)f->data[0] * g->data[1] + (__uint128_t)f->data[1] * g->data[0] +
        (__uint128_t)f->data[2] * g->data[4] * 19 + (__uint128_t)f->data[3] * g->data[3] * 19 + // 19*f2g4 + 19*f3g3
        (__uint128_t)f->data[4] * g->data[2] * 19; // 19*f4g2
    // h[2] = f0g2 + f1g1 + f2g0 + 19*f3g4 + 19*f4g3
    h[2] = (__uint128_t)f->data[0] * g->data[2] + (__uint128_t)f->data[1] * g->data[1] +
        (__uint128_t)f->data[2] * g->data[0] + (__uint128_t)f->data[3] * g->data[4] * 19 + // f2g0 + 19*f3g4
        (__uint128_t)f->data[4] * g->data[3] * 19; // 19*f4g3
    // h[3] = f0g3 + f1g2 + f2g1 + f3g0 + 19*f4g4
    h[3] = (__uint128_t)f->data[0] * g->data[3] + (__uint128_t)f->data[1] * g->data[2] +
        (__uint128_t)f->data[2] * g->data[1] + (__uint128_t)f->data[3] * g->data[0] + // f2g1 + f3g0
        (__uint128_t)f->data[4] * g->data[4] * 19; // 19*f4g4
    // h[4] = f0g4 + f1g3 + f2g2 + f3g1 + f4g0
    h[4] = (__uint128_t)f->data[0] * g->data[4] + (__uint128_t)f->data[1] * g->data[3] +
        (__uint128_t)f->data[2] * g->data[2] + (__uint128_t)f->data[3] * g->data[1] + // f2g2 + f3g1
        (__uint128_t)f->data[4] * g->data[0]; // f4g0

    Fp51ProcessCarry(h);

    out->data[0] = (uint64_t)h[0];
    out->data[1] = (uint64_t)h[1];
    out->data[2] = (uint64_t)h[2];
    out->data[3] = (uint64_t)h[3];
    out->data[4] = (uint64_t)h[4];
}

void Fp51Square(Fp51 *out, const Fp51 *in)
{
    __uint128_t h[5];
    uint64_t in0mul2 = in->data[0] * 2;
    uint64_t in1mul2 = in->data[1] * 2;
    uint64_t in2mul2 = in->data[2] * 2;
    uint64_t in3mul19 = in->data[3] * 19;
    uint64_t in4mul19 = in->data[4] * 19;

    // h0 = in0^2 + 38 * in1 * in4 + 38 * in2 * in3
    h[0] = (__uint128_t)in->data[0] * in->data[0] + (__uint128_t)in1mul2 * in4mul19 +
        (__uint128_t)in2mul2 * in3mul19;
    // h1 = 2 * in0 * in1 + 19 * in3^2 + 38 * in2 * in4
    h[1] = (__uint128_t)in0mul2 * in->data[1] + (__uint128_t)in->data[3] * in3mul19 +
        (__uint128_t)in2mul2 * in4mul19;
    // h2 = 2 * in0 * in2 + in1^2 + 38 * in3 * in4
    h[2] = (__uint128_t)in0mul2 * in->data[2] + (__uint128_t)in->data[1] * in->data[1] +
        (__uint128_t)(in->data[3] * 2) * in4mul19; // 2 * 19 * in3 * in4
    // h3 = 2 * in0 * in3 + 19 * in4^2 + 2 * in1 * in2
    h[3] = (__uint128_t)in0mul2 * in->data[3] + (__uint128_t)in->data[4] * in4mul19 +
        (__uint128_t)in1mul2 * in->data[2]; // 2 * in1 * in2
    // h4 = 2 * in0 * in4 + 2 * in1 * in3 + in2^2
    h[4] = (__uint128_t)in0mul2 * in->data[4] + (__uint128_t)in1mul2 * in->data[3] +
        (__uint128_t)in->data[2] * in->data[2]; // in2^2

    Fp51ProcessCarry(h);

    out->data[0] = (uint64_t)h[0];
    out->data[1] = (uint64_t)h[1];
    out->data[2] = (uint64_t)h[2];
    out->data[3] = (uint64_t)h[3];
    out->data[4] = (uint64_t)h[4];
}

void Fp51MulScalar(Fp51 *out, const Fp51 *in, const uint32_t scalar)
{
    __uint128_t h[5];
    h[0] = in->data[0] * (__uint128_t)scalar;
    h[1] = in->data[1] * (__uint128_t)scalar;
    h[2] = in->data[2] * (__uint128_t)scalar;
    h[3] = in->data[3] * (__uint128_t)scalar;
    h[4] = in->data[4] * (__uint128_t)scalar;

    Fp51ProcessCarry(h);

    out->data[0] = (uint64_t)h[0];
    out->data[1] = (uint64_t)h[1];
    out->data[2] = (uint64_t)h[2];
    out->data[3] = (uint64_t)h[3];
    out->data[4] = (uint64_t)h[4];
}

/* out = in1 ^ (4 * 2 ^ (2 * times)) * in2 */
static inline void Fp51MultiSquare(Fp51 *in1, Fp51 *in2, Fp51 *out, int32_t times)
{
    int32_t i;
    Fp51 temp1, temp2;
    Fp51Square(&temp1, in1);
    Fp51Square(&temp2, &temp1);
    for (i = 0; i < times; i++) {
        Fp51Square(&temp1, &temp2);
        Fp51Square(&temp2, &temp1);
    }
    Fp51Mul(out, in2, &temp2);
}

/* out = a ^ -1 */
static void Fp51Invert(Fp51 *out, const Fp51 *a)
{
    Fp51 a0;    /* save a^1         */
    Fp51 a1;    /* save a^2         */
    Fp51 a2;    /* save a^11        */
    Fp51 a3;    /* save a^(2^5-1)   */
    Fp51 a4;    /* save a^(2^10-1)  */
    Fp51 a5;    /* save a^(2^20-1)  */
    Fp51 a6;    /* save a^(2^40-1)  */
    Fp51 a7;    /* save a^(2^50-1)  */
    Fp51 a8;    /* save a^(2^100-1) */
    Fp51 a9;    /* save a^(2^200-1) */
    Fp51 a10;   /* save a^(2^250-1) */
    Fp51 temp1, temp2;

    /* We know a×b=1(mod p), then a and b are inverses of mod p, i.e. a=b^(-1), b=a^(-1);
     * According to Fermat's little theorem a^(p-1)=1(mod p), so a*a^(p-2)=1(mod p);
     * So the inverse element of a is a^(-1) = a^(p-2)(mod p)
     * Here it is, p=2^255-19, thus we need to compute a^(2^255-21)(mod(2^255-19))
     */

    /* a^1 */
    CURVE25519_FP51_COPY(a0.data, a->data);

    /* a^2 */
    Fp51Square(&a1, &a0);

    /* a^4 */
    Fp51Square(&temp1, &a1);

    /* a^8 */
    Fp51Square(&temp2, &temp1);

    /* a^9 */
    Fp51Mul(&temp1, &a0, &temp2);

    /* a^11 */
    Fp51Mul(&a2, &a1, &temp1);

    /* a^22 */
    Fp51Square(&temp2, &a2);

    /* a^(2^5-1) = a^(9+22) */
    Fp51Mul(&a3, &temp1, &temp2);

    /* a^(2^10-1) = a^(2^10-2^5) * a^(2^5-1) */
    Fp51Square(&temp1, &a3);
    Fp51Square(&temp2, &temp1);
    Fp51Square(&temp1, &temp2);
    Fp51Square(&temp2, &temp1);
    Fp51Square(&temp1, &temp2);
    Fp51Mul(&a4, &a3, &temp1);

    /* a^(2^20-1) = a^(2^20-2^10) * a^(2^10-1) */
    Fp51MultiSquare(&a4, &a4, &a5, 4); // (2 * 2) ^ 4

    /* a^(2^40-1) = a^(2^40-2^20) * a^(2^20-1) */
    Fp51MultiSquare(&a5, &a5, &a6, 9); // (2 * 2) ^ 9

    /* a^(2^50-1) = a^(2^50-2^10) * a^(2^10-1) */
    Fp51MultiSquare(&a6, &a4, &a7, 4); // (2 * 2) ^ 4

    /* a^(2^100-1) = a^(2^100-2^50) * a^(2^50-1) */
    Fp51MultiSquare(&a7, &a7, &a8, 24); // (2 * 2) ^ 24

    /* a^(2^200-1) = a^(2^200-2^100) * a^(2^100-1) */
    Fp51MultiSquare(&a8, &a8, &a9, 49); // (2 * 2) ^ 49

    /* a^(2^250-1) = a^(2^250-2^50) * a^(2^50-1) */
    Fp51MultiSquare(&a9, &a7, &a10, 24); // (2 * 2) ^ 24

    /* a^(2^5*(2^250-1)) = (a^(2^250-1))^5 */
    Fp51Square(&temp1, &a10);
    Fp51Square(&temp2, &temp1);
    Fp51Square(&temp1, &temp2);
    Fp51Square(&temp2, &temp1);
    Fp51Square(&temp1, &temp2);

    /* The output: a^(2^255-21) = a(2^5*(2^250-1)+11) = a^(2^5*(2^250-1)) * a^11 */
    Fp51Mul(out, &a2, &temp1);
}

void ScalarMultiPoint(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
    uint8_t k[32];
    const uint8_t *u = point;
    int32_t t;
    uint32_t swap;
    uint32_t kTemp;
    Fp51 x1, x2, x3;
    Fp51 z2, z3;
    Fp51 t1, t2;

    /* Decord the scalar into k */
    CURVE25519_DECODE_LITTLE_ENDIAN(k, scalar);

    /* Reference RFC 7748 section 5: The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519 */
    Fp51DataToPoly(&x1, u);
    CURVE25519_FP51_SET(x2.data, 1);
    CURVE25519_FP51_SET(z2.data, 0);
    CURVE25519_FP51_COPY(x3.data, x1.data);
    CURVE25519_FP51_SET(z3.data, 1);
    swap = 0;

    /* "bits" parameter set to 255 for x25519  */ /* For t = bits-1(254) down to 0: */
    for (t = 254; t >= 0; t--) {
        /* t >> 3: calculation the index of bit; t & 7: Obtains the corresponding bit in the byte */
        kTemp = (k[(uint32_t)t >> 3] >> ((uint32_t)t & 7)) & 1;           /* kTemp = (k >> t) & 1 */
        swap ^= kTemp;                                /* swap ^= kTemp */
        CURVE25519_FP51_CSWAP(swap, x2.data, x3.data);  /* (x_2, x_3) = cswap(swap, x_2, x_3) */
        CURVE25519_FP51_CSWAP(swap, z2.data, z3.data);  /* (z_2, z_3) = cswap(swap, z_2, z_3) */
        swap = kTemp;                                 /* swap = kTemp */
        CURVE25519_FP51_SUB(t1.data, x3.data, z3.data);                /* x3 = D */
        CURVE25519_FP51_SUB(t2.data, x2.data, z2.data);                /* t2 = B */
        CURVE25519_FP51_ADD(x2.data, x2.data, z2.data);                /* t1 = A */
        CURVE25519_FP51_ADD(z2.data, x3.data, z3.data);                /* x2 = C */

        Fp51Mul(&z3, &t1, &x2);
        Fp51Mul(&z2, &z2, &t2);
        Fp51Square(&t1, &t2);
        Fp51Square(&t2, &x2);

        CURVE25519_FP51_ADD(x3.data, z3.data, z2.data);
        CURVE25519_FP51_SUB(z2.data, z3.data, z2.data);
        Fp51Mul(&x2, &t2, &t1);
        CURVE25519_FP51_SUB(t2.data, t2.data, t1.data);
        Fp51Square(&z2, &z2);
        Fp51MulScalar(&z3, &t2, 121666); // z2 *= 121665 + 1 = 121666
        Fp51Square(&x3, &x3);
        CURVE25519_FP51_ADD(t1.data, t1.data, z3.data);
        Fp51Mul(&z3, &x1, &z2);
        Fp51Mul(&z2, &t2, &t1);
    }

    CURVE25519_FP51_CSWAP(swap, x2.data, x3.data);
    CURVE25519_FP51_CSWAP(swap, z2.data, z3.data);
    /* Return x2 * (z2 ^ (p - 2)) */
    Fp51Invert(&t1, &z2);
    Fp51Mul(&t2, &x2, &t1);
    Fp51PolyToData(&t2, out);
    BSL_SAL_CleanseData(k, sizeof(k));
}

#else

void FpMulScalar(Fp25 out, const Fp25 p, const int32_t scalar)
{
    int64_t s = (int64_t)scalar;
    uint64_t over;
    uint64_t result[10];
    uint64_t mul19;
    uint64_t t1;
    uint64_t signMask1;
    uint64_t signMask2;

    /* Could be more than 32 bits but not be more than 64 bits */
    CURVE25519_FP_MUL_SCALAR(result, p, s);

    /* Process Carry */
    /* the radix 2^25.5 representation:
     * f0+2^26*f1+2^51*f2+2^77*f3+2^102*f4+2^128*f5+2^153*f6+2^179*f7+2^204*f8+2^230*f9 */
    over = result[9] + (1 << 24); /* carry chain: index 9->0; 2^25 progressiv, left shift by 24 bits */
    signMask1 = MASK_HIGH64(25) & (-((over) >> 63)); /* 2^25 progressiv, shift 63 for sign */
    t1 = (over >> 25) | signMask1;
    mul19 = (t1 + (t1 << 1) + (t1 << 4));            /* 19 = 1 + 2^1 + 2^4 */
    result[0] += mul19;                              /* carry chain: index 9->0 */
    result[9] -= CURVE25519_MASK_HIGH_39 & over;

    /* carry chain: index 1->2; 2^25 progressiv(26->51) */
    /* carry chain: index 1->2; 2^25 progressiv, left shift by 24 bits */
    PROCESS_CARRY(result[1], result[2], signMask1, over, 24);

    /* carry chain: index 3->4; 2^25 progressiv(77->102) */
    /* carry chain: index 3->4; 2^25 progressiv, left shift by 24 bits */
    PROCESS_CARRY(result[3], result[4], signMask1, over, 24);

    /* carry chain: index 5->6; 2^25 progressiv(128->153) */
    /* carry chain: index 5->6; 2^25 progressiv, left shift by 24 bits */
    PROCESS_CARRY(result[5], result[6], signMask1, over, 24);

    /* carry chain: index 7->8; 2^25 progressiv(179->204) */
    /* carry chain: index 7->8; 2^25 progressiv, left shift by 24 bits */
    PROCESS_CARRY(result[7], result[8], signMask1, over, 24);

    /* carry chain: index 0->1; 2^26 progressiv(0->26) */
    /* carry chain: index 0->1; 2^26 progressiv, left shift by 25 bits */
    PROCESS_CARRY(result[0], result[1], signMask2, over, 25);

    /* carry chain: index 2->3; 2^26 progressiv(51->77) */
    /* carry chain: index 2->3; 2^26 progressiv, left shift by 25 bits */
    PROCESS_CARRY(result[2], result[3], signMask2, over, 25);

    /* carry chain: index 4->5; 2^26 progressiv(102->128) */
    /* carry chain: index 4->5; 2^26 progressiv, left shift by 25 bits */
    PROCESS_CARRY(result[4], result[5], signMask2, over, 25);

    /* carry chain: index 6->7; 2^26 progressiv(153->179) */
    /* carry chain: index 6->7; 2^26 progressiv, left shift by 25 bits */
    PROCESS_CARRY(result[6], result[7], signMask2, over, 25);

    /* carry chain: index 8->9; 2^26 progressiv(204->230) */
    /* carry chain: index 8->9; 2^26 progressiv, left shift by 25 bits */
    PROCESS_CARRY(result[8], result[9], signMask2, over, 25);

    /* The result would not be more than 32 bits */
    out[0] = (int32_t)result[0]; // 0
    out[1] = (int32_t)result[1]; // 1
    out[2] = (int32_t)result[2]; // 2
    out[3] = (int32_t)result[3]; // 3
    out[4] = (int32_t)result[4]; // 4
    out[5] = (int32_t)result[5]; // 5
    out[6] = (int32_t)result[6]; // 6
    out[7] = (int32_t)result[7]; // 7
    out[8] = (int32_t)result[8]; // 8
    out[9] = (int32_t)result[9]; // 9

    (void)memset_s(result, sizeof(result), 0, sizeof(result));
}

void ScalarMultiPoint(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
    uint8_t k[32];
    const uint8_t *u = point;
    int32_t t;
    uint32_t swap;
    uint32_t kTemp;
    Fp25 x1, x2, x3, z2, z3, t1, t2, t3;

    /* Decord the scalar into k */
    CURVE25519_DECODE_LITTLE_ENDIAN(k, scalar);

    /* Reference RFC 7748 section 5：The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519 */
    DataToPolynomial(x1, u);
    CURVE25519_FP_SET(x2, 1);
    CURVE25519_FP_SET(z2, 0);
    CURVE25519_FP_COPY(x3, x1);
    CURVE25519_FP_SET(z3, 1);
    swap = 0;

    /* "bits" parameter set to 255 for x25519  */ /* For t = bits-1(254) down to 0: */
    for (t = 254; t >= 0; t--) {
        /* t >> 3: calculation the index of bit; t & 7: Obtains the corresponding bit in the byte */
        kTemp = (k[(uint32_t)t >> 3] >> ((uint32_t)t & 7)) & 1;           /* kTemp = (k >> t) & 1 */
        swap ^= kTemp;                                /* swap ^= kTemp */
        CURVE25519_FP_CSWAP(swap, x2, x3);  /* (x_2, x_3) = cswap(swap, x_2, x_3) */
        CURVE25519_FP_CSWAP(swap, z2, z3);  /* (z_2, z_3) = cswap(swap, z_2, z_3) */
        swap = kTemp;                                 /* swap = kTemp */
        CURVE25519_FP_ADD(t1, x2, z2);                /* t1 = A */
        CURVE25519_FP_SUB(t2, x2, z2);                /* t2 = B */
        CURVE25519_FP_ADD(x2, x3, z3);                /* x2 = C */
        CURVE25519_FP_SUB(x3, x3, z3);                /* x3 = D */
        FpMul(z2, x3, t1);             /* z2 = DA */
        FpMul(z3, x2, t2);             /* z3 = CB */
        FpSquareDoubleCore(t1, t1, false);               /* t1 = AA */
        FpSquareDoubleCore(t2, t2, false);               /* t2 = BB */
        CURVE25519_FP_SUB(t3, t1, t2);                /* t3 = E = AA - BB */
        CURVE25519_FP_ADD(x3, z2, z3);                /* x3 = DA + CB */
        FpSquareDoubleCore(x3, x3, false);             /* x3 = (DA + CB)^2 */
        CURVE25519_FP_SUB(z3, z2, z3);                /* z3 = DA - CB */
        FpSquareDoubleCore(z3, z3, false);             /* z3 = (DA - CB)^2 */
        FpMul(z3, x1, z3);            /* z3 = x1 * (DA - CB)^2 */
        FpMul(x2, t1, t2);            /* x2 = AA * BB */
        FpMul(t1, t3, t1);            /* t1 = E * AA */
        FpSquareDoubleCore(z2, t3, false);             /* z2 = E^2 */
        /* Reference RFC 7748 section 5：The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519 */
        FpMulScalar(z2, z2, 121665);  /* z2 = a24 * E^2 */
        CURVE25519_FP_ADD(z2, t1, z2);                /* z2 = E * (AA + a24 * E) */
    }

    CURVE25519_FP_CSWAP(swap, x2, x3);
    CURVE25519_FP_CSWAP(swap, z2, z3);
    /* Return x2 * (z2 ^ (p - 2)) */
    FpInvert(t1, z2);
    FpMul(t2, x2, t1);
    PolynomialToData(out, t2);
}
#endif // uint128
#endif /* HITLS_CRYPTO_X25519 */

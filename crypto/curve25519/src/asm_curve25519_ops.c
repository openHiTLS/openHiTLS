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

#include "x25519_asm.h"
#include "securec.h"
#include "curve25519_local.h"
#ifdef HITLS_CRYPTO_X25519_X8664
#include "crypt_utils.h"
#endif
// X25519 alternative implementation, faster but require asm
#define CURVE25519_51BITS_MASK 0x7ffffffffffff
#define CURVE25519_51BITS 51

static void Fp51DataToPoly(Fp51 *out, const uint8_t in[32])
{
    uint64_t h[5];

    CURVE25519_BYTES7_LOAD(h, in); // load 7 bytes

    CURVE25519_BYTES6_LOAD(h + 1, in + 7); // load 6 bytes from in7 to h1
    h[1] <<= 5; // shift 5 to fit 51 bits

    CURVE25519_BYTES7_LOAD(h + 2, in + 13); // load 7 bytes from in13 to h2
    h[2] <<= 2; // shift 2 to fit 51 bits

    CURVE25519_BYTES6_LOAD(h + 3, in + 20); // load 6 bytes from in20 to h3
    h[3] <<= 7; // shift 7 to fit 51 bits

    CURVE25519_BYTES6_LOAD(h + 4, in + 26); // load 6 bytes from in26 to h4
    h[4] &= 0x7fffffffffff; // 41 bits mask = 0x7fffffffffff
    h[4] <<= 4; // shift 4 to fit 51 bits

    h[1] |= h[0] >> CURVE25519_51BITS; // carry h[0] -> h[1]
    h[0] &= CURVE25519_51BITS_MASK; // clear h[0]

    h[2] |= h[1] >> CURVE25519_51BITS; // carry h[1] -> h[2]
    h[1] &= CURVE25519_51BITS_MASK; // clear h[1]

    h[3] |= h[2] >> CURVE25519_51BITS; // carry h[2] -> h[3]
    h[2] &= CURVE25519_51BITS_MASK; // clear h[2]

    h[4] |= h[3] >> CURVE25519_51BITS; // carry h[3] -> h[4]
    h[3] &= CURVE25519_51BITS_MASK; // clear h[3]

    out->data[0] = h[0]; // 0
    out->data[1] = h[1]; // 1
    out->data[2] = h[2]; // 2
    out->data[3] = h[3]; // 3
    out->data[4] = h[4]; // 4
}

static void Fp51UnloadTo8Bits(uint8_t out[32], uint64_t h[5])
{
    // load from uint64 to uint8, load 8 bits at a time
    out[0] = (uint8_t)h[0];
    out[1] = (uint8_t)(h[0] >> 8); // load from position 8 to out[1]
    out[2] = (uint8_t)(h[0] >> 16); // load from position 16 to out[2]
    out[3] = (uint8_t)(h[0] >> 24); // load from position 24 to out[3]
    out[4] = (uint8_t)(h[0] >> 32); // load from position 32 to out[4]
    out[5] = (uint8_t)(h[0] >> 40); // load from position 40 to out[5]
    // load from position 48 from h[1] and (8-5)=3 bits from h[1] to out[6]
    out[6] = (uint8_t)((h[0] >> 48) | (uint8_t)(h[1] << 3));
    out[7] = (uint8_t)(h[1] >> 5); // load h[1] from position 5 to out[7]
    out[8] = (uint8_t)(h[1] >> 13); // load h[1] from position 13 to out[8]
    out[9] = (uint8_t)(h[1] >> 21); // load h[1] from position 21 to out[9]
    out[10] = (uint8_t)(h[1] >> 29); // load h[1] from position 29 to out[10]
    out[11] = (uint8_t)(h[1] >> 37); // load h[1] from position 37 to out[11]
    // load from position 45 from h[1] and (8-2)=6 bits from h[2] to out[12]
    out[12] = (uint8_t)((h[1] >> 45) | (uint8_t)(h[2] << 6));
    out[13] = (uint8_t)(h[2] >> 2); // load h[2] from position 2 to out[13]
    out[14] = (uint8_t)(h[2] >> 10); // load h[2] from position 10 to out[14]
    out[15] = (uint8_t)(h[2] >> 18); // load h[2] from position 18 to out[15]
    out[16] = (uint8_t)(h[2] >> 26); // load h[2] from position 26 to out[16]
    out[17] = (uint8_t)(h[2] >> 34); // load h[2] from position 34 to out[17]
    out[18] = (uint8_t)(h[2] >> 42); // load h[2] from position 42 to out[18]
    // load from position 50 from h[2] and (8-1)=7 bits from h[3] to out[19]
    out[19] = (uint8_t)((h[2] >> 50) | (uint8_t)(h[3] << 1));
    out[20] = (uint8_t)(h[3] >> 7); // load h[3] from position 7 to out[20]
    out[21] = (uint8_t)(h[3] >> 15); // load h[3] from position 15 to out[21]
    out[22] = (uint8_t)(h[3] >> 23); // load h[3] from position 23 to out[22]
    out[23] = (uint8_t)(h[3] >> 31); // load h[3] from position 31 to out[23]
    out[24] = (uint8_t)(h[3] >> 39); // load h[3] from position 39 to out[24]
    // load from position 47 from h[3] and (4-4)=4 bits from h[4] to out[25]
    out[25] = (uint8_t)((h[3] >> 47) | (uint8_t)(h[4] << 4));
    out[26] = (uint8_t)(h[4] >> 4); // load h[4] from position 4 to out[26]
    out[27] = (uint8_t)(h[4] >> 12); // load h[4] from position 12 to out[27]
    out[28] = (uint8_t)(h[4] >> 20); // load h[4] from position 20 to out[28]
    out[29] = (uint8_t)(h[4] >> 28); // load h[4] from position 28 to out[29]
    out[30] = (uint8_t)(h[4] >> 36); // load h[4] from position 36 to out[30]
    out[31] = (uint8_t)(h[4] >> 44); // load h[4] from position 44 to out[31]
}

static void Fp51PolyToData(const Fp51 *in, uint8_t out[32])
{
    uint64_t h[5];
    h[0] = in->data[0]; // 0
    h[1] = in->data[1]; // 1
    h[2] = in->data[2]; // 2
    h[3] = in->data[3]; // 3
    h[4] = in->data[4]; // 4
    uint64_t carry;

    carry = (h[0] + 19) >> CURVE25519_51BITS; // plus 19 then calculate carry
    carry = (h[1] + carry) >> CURVE25519_51BITS; // carry of h[1]
    carry = (h[2] + carry) >> CURVE25519_51BITS; // carry of h[2]
    carry = (h[3] + carry) >> CURVE25519_51BITS; // carry of h[3]
    carry = (h[4] + carry) >> CURVE25519_51BITS; // carry of h[4]

    h[0] += 19 * carry; // process carry h[4] -> h[0], h[0] += 19 * carry
    h[1] += h[0] >> CURVE25519_51BITS; // process carry h[0] -> h[1]
    h[0] &= CURVE25519_51BITS_MASK; // clear h[0]
    h[2] += h[1] >> CURVE25519_51BITS; // process carry h[1] -> h[2]
    h[1] &= CURVE25519_51BITS_MASK; // clear h[1]
    h[3] += h[2] >> CURVE25519_51BITS; // process carry h[2] -> h[3]
    h[2] &= CURVE25519_51BITS_MASK; // clear h[2]
    h[4] += h[3] >> CURVE25519_51BITS; // process carry h[3] -> h[4]
    h[3] &= CURVE25519_51BITS_MASK; // clear h[3]
    h[4] &= CURVE25519_51BITS_MASK; // clear h[4]

    Fp51UnloadTo8Bits(out, h);
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

    /* The output：a^(2^255-21) = a(2^5*(2^250-1)+11) = a^(2^5*(2^250-1)) * a^11 */
    Fp51Mul(out, &a2, &temp1);
}

void Fp51ScalarMultiPoint(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
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

    /* Reference RFC 7748 section 5：The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519 */
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
        Fp51MulScalar(&z3, &t2); // z2 *= 121665 + 1 = 121666
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
    (void)memset_s(k, sizeof(k), 0, sizeof(k));
}

#ifdef HITLS_CRYPTO_X25519_X8664

#define CURVE25519_63BITS_MASK 0x7fffffffffffffff
#define CURVE25519_FP64_SET(dst, value)     \
    do {                                    \
        (dst)[0] = (value);                 \
        (dst)[1] = 0;                       \
        (dst)[2] = 0;                       \
        (dst)[3] = 0;                       \
    } while (0)

#define CURVE25519_FP64_COPY(dst, src)     \
    do {                                   \
        (dst)[0] = (src)[0];               \
        (dst)[1] = (src)[1];               \
        (dst)[2] = (src)[2];               \
        (dst)[3] = (src)[3];               \
    } while (0)

#define CURVE25519_BYTES8_LOAD(dst, src)                 \
    do {                                                 \
            dst =  (uint64_t)(src)[0];                   \
            dst |= ((uint64_t)(src)[1]) << 8;            \
            dst |= ((uint64_t)(src)[2]) << 16;           \
            dst |= ((uint64_t)(src)[3]) << 24;           \
            dst |= ((uint64_t)(src)[4]) << 32;           \
            dst |= ((uint64_t)(src)[5]) << 40;           \
            dst |= ((uint64_t)(src)[6]) << 48;           \
            dst |= ((uint64_t)(src)[7]) << 56;           \
    } while (0)

#define CURVE25519_FP64_CSWAP(s, a, b)                                  \
    do {                                                                \
            uint64_t tt;                                                \
            const uint64_t tsMacro = 0 - (uint64_t)(s);                 \
            for (uint32_t ii = 0; ii < 4; ii++) {                       \
                tt = tsMacro & ((a)[ii] ^ (b)[ii]);                     \
                (a)[ii] = (a)[ii] ^ tt;                                 \
                (b)[ii] = (b)[ii] ^ tt;                                 \
            }                                                           \
    } while (0)

static void Fp64DataToPoly(Fp64 h, const uint8_t *point)
{
    uint8_t *tmp = (uint8_t *)(uintptr_t)point;
    CURVE25519_BYTES8_LOAD(h[0], tmp);
    tmp += 8; // the second 8 bytes
    CURVE25519_BYTES8_LOAD(h[1], tmp);
    tmp += 8; // the third 8 bytes
    CURVE25519_BYTES8_LOAD(h[2], tmp);
    tmp += 8; // the forth 8 bytes
    CURVE25519_BYTES8_LOAD(h[3], tmp);
    h[3] &= CURVE25519_63BITS_MASK;
    return;
}

/* out = in1 ^ (4 * 2 ^ (2 * times)) * in2 */
static inline void Fp64MultiSqr(Fp64 in1, Fp64 in2, Fp64 out, int32_t times)
{
    int32_t i;
    Fp64 temp1, temp2;
    Fp64Sqr(temp1, in1);
    Fp64Sqr(temp2, temp1);
    for (i = 0; i < times; i++) {
        Fp64Sqr(temp1, temp2);
        Fp64Sqr(temp2, temp1);
    }
    Fp64Mul(out, in2, temp2);
}

static void Fe64Invert(Fp64 out, const Fp64 z)
{
    Fp64 t0;
    Fp64 t1;
    Fp64 t2;
    Fp64 t3;
    Fp64 t4;

    Fp64Sqr(t0, z); /* t^2 */
    Fp64Sqr(t1, t0); /* t^4 */
    Fp64Sqr(t1, t1); /* t^8 */
    Fp64Mul(t1, z, t1); /* t^9 */
    Fp64Mul(t0, t0, t1); /* t^11 */
    Fp64Sqr(t2, t0); /* t^22 */
    Fp64Mul(t1, t1, t2); /* t^(2^5-1) = t^(9+22) */

    /* t^(2^10-1) = t^(2^10-2^5) * t^(2^5-1) */
    Fp64Sqr(t2, t1);
    Fp64Sqr(t4, t2);
    Fp64Sqr(t2, t4);
    Fp64Sqr(t4, t2);
    Fp64Sqr(t2, t4);
    Fp64Mul(t1, t2, t1);

    /* t^(2^20-1) = t^(2^20-2^10) * t^(2^10-1) */
    Fp64MultiSqr(t1, t1, t2, 4);

    /* t^(2^40-1) = t^(2^40-2^20) * t^(2^20-1) */
    Fp64MultiSqr(t2, t2, t4, 9); // (2 * 2) ^ 9

    /* t^(2^50-1) = t^(2^50-2^10) * t^(2^10-1) */
    Fp64MultiSqr(t4, t1, t2, 4); // (2 * 2) ^ 4

    /* t^(2^100-1) = t^(2^100-2^50) * t^(2^50-1) */
    Fp64MultiSqr(t2, t2, t1, 24); // (2 * 2) ^ 24

    /* t^(2^200-1) = t^(2^200-2^100) * t^(2^100-1) */
    Fp64MultiSqr(t1, t1, t4, 49); // (2 * 2) ^ 49

    /* t^(2^250-1) = t^(2^250-2^50) * t^(2^50-1) */
    Fp64MultiSqr(t4, t2, t3, 24); // (2 * 2) ^ 24

    /* t^(2^5*(2^250-1)) = (t^(2^250-1))^5 */
    Fp64Sqr(t1, t3);
    Fp64Sqr(t2, t1);
    Fp64Sqr(t1, t2);
    Fp64Sqr(t2, t1);
    Fp64Sqr(t1, t2);

    /* The output：t^(2^255-21) = t(2^5*(2^250-1)+11) = t^(2^5*(2^250-1)) * t^11 */
    Fp64Mul(out, t0, t1);
}


void Fp64ScalarMultiPoint(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
    uint8_t e[32];
    uint32_t swap = 0;
    int32_t t;
    Fp64 x1, x2, x3;
    Fp64 z2, z3;
    Fp64 t1, t2;

    CURVE25519_DECODE_LITTLE_ENDIAN(e, scalar);
    Fp64DataToPoly(x1, point);
    CURVE25519_FP64_SET(x2, 1);
    CURVE25519_FP64_SET(z2, 0);
    CURVE25519_FP64_COPY(x3, x1);
    CURVE25519_FP64_SET(z3, 1);

    for (t = 254; t >= 0; --t) { /* For t = bits-1(254) down to 0: */
        /* t >> 3: calculation the index of bit; t & 7: Obtains the corresponding bit in the byte */
        uint32_t kTemp = (e[(uint32_t)t >> 3] >> ((uint32_t)t & 7)) & 1;

        swap ^= kTemp;
        CURVE25519_FP64_CSWAP(swap, x2, x3);
        CURVE25519_FP64_CSWAP(swap, z2, z3);
        swap = kTemp;
        Fp64Sub(t1, x3, z3);
        Fp64Sub(t2, x2, z2);
        Fp64Add(x2, x2, z2);
        Fp64Add(z2, x3, z3);
        Fp64Mul(z3, x2, t1);
        Fp64Mul(z2, z2, t2);
        Fp64Sqr(t1, t2);
        Fp64Sqr(t2, x2);
        Fp64Add(x3, z3, z2);
        Fp64Sub(z2, z3, z2);
        Fp64Mul(x2, t2, t1);
        Fp64Sub(t2, t2, t1);
        Fp64Sqr(z2, z2);
        Fp64MulScalar(z3, t2);
        Fp64Sqr(x3, x3);
        Fp64Add(t1, t1, z3);
        Fp64Mul(z3, x1, z2);
        Fp64Mul(z2, t2, t1);
    }

    Fe64Invert(z2, z2);
    Fp64Mul(x2, x2, z2);
    Fp64PolyToData(out, x2);
    (void)memset_s(e, sizeof(e), 0, sizeof(e));
}
#endif

void ScalarMultiPoint(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
#if defined (__x86_64__) && defined (HITLS_CRYPTO_X25519_X8664)
    if (IsSupportBMI2() && IsSupportADX()) {
        Fp64ScalarMultiPoint(out, scalar, point);
        return;
    }
#endif
    Fp51ScalarMultiPoint(out, scalar, point);
    return;
}

#endif /* HITLS_CRYPTO_X25519 */

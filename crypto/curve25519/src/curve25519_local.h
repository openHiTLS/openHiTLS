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

#ifndef CURVE25519_LOCAL_H
#define CURVE25519_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CURVE25519

#include "crypt_curve25519.h"
#include "sal_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CURVE25519_NOKEY 0
#define CURVE25519_PRVKEY 0x1
#define CURVE25519_PUBKEY 0x10

#define UINT8_32_21BITS_BLOCKNUM 12
#define UINT8_64_21BITS_BLOCKNUM 24

struct CryptCurve25519Ctx {
    uint8_t keyType; /* specify the key type */
    const EAL_MdMethod *hashMethod;
    uint8_t pubKey[CRYPT_CURVE25519_KEYLEN];
    uint8_t prvKey[CRYPT_CURVE25519_KEYLEN];
    BSL_SAL_RefCount references;
    void *libCtx;
};

typedef int32_t Fp25[10];

typedef struct Fp51 {
    uint64_t data[5];
} Fp51;

typedef struct H19 {
    int64_t data[19];
} H19;

// group element in Projective Coordinate, x = X / Z, y = Y / Z
typedef struct GeP {
    Fp25 x;
    Fp25 y;
    Fp25 z;
} GeP;

// group element in Extended Coordinate, x = X / Z, y = Y / Z, T = XY / Z which leads to XY = ZT
typedef struct GeE {
    Fp25 x;
    Fp25 y;
    Fp25 t;
    Fp25 z;
} GeE;

// group element in Completed Coordinate, x = X / Z, y = Y / T
typedef struct GeC {
    Fp25 x;
    Fp25 y;
    Fp25 t;
    Fp25 z;
} GeC;

typedef struct GePre {
    Fp25 yplusx;
    Fp25 yminusx;
    Fp25 xy2d;
} GePre;

typedef struct GeEPre {
    Fp25 yplusx;
    Fp25 yminusx;
    Fp25 t2z;
    Fp25 z;
} GeEPre;

/* Get High x bits for 64bits block */
#define MASK_HIGH64(x) (0xFFFFFFFFFFFFFFFFLL << (64 - (x)))
/* Get low x bits for 32bits block */
#define MASK_LOW32(x) (0xFFFFFFFF >> (32 - (x)))
/* Get high x bits for 32bits block */
#define MASK_HIGH32(x) (0xFFFFFFFF << (32 - (x)))

/* low 21 bits for 64bits block */
#define MASK_64_LOW21 0x1fffffLL

#define CURVE25519_MASK_HIGH_38     0xfffffffffc000000LL
#define CURVE25519_MASK_HIGH_39     0xfffffffffe000000LL

/* process carry from h0_ to h1_, h0_ boundary restrictions is bits */
#define PROCESS_CARRY(h0_, h1_, signMask_, over_, bits)             \
    do {                                                            \
        (over_) = (h0_) + (1 << (bits));                            \
        (signMask_) = MASK_HIGH64((bits) + 1) & (-((over_) >> 63)); \
        (h1_) += ((over_) >> ((bits) + 1)) | (signMask_);           \
        (h0_) -= MASK_HIGH64(64 - ((bits) + 1)) & (over_);          \
    } while (0)

/* process carry from h0_ to h1_ ignoring sign, h0_ boundary restrictions is bits */
#define PROCESS_CARRY_UNSIGN(h0_, h1_, signMask_, over_, bits)      \
    do {                                                            \
        (signMask_) = MASK_HIGH64((bits)) & (-((h0_) >> 63));       \
        (over_) = ((h0_) >> (bits)) | (signMask_);                  \
        (h1_) += (over_);                                           \
        (h0_) -= (over_) * (1 << (bits));                           \
    } while (0)

/* l = 2^252 + 27742317777372353535851937790883648493, let l0 = 27742317777372353535851937790883648493 */
/* -l0 = 666643 * 2^0 + 470296 * 2^21 + 654183 * 2^(2*21) - 997805 * 2^(3*21) + 136657 * 2^(4*21) - 683901 * 2^(5*21) */
#define CURVE25519_MULTI_BY_L0(src, pos)    \
    do {              \
        (src)[0 + (pos)] += (src)[12 + (pos)] * 666643;  \
        (src)[1 + (pos)] += (src)[12 + (pos)] * 470296;  \
        (src)[2 + (pos)] += (src)[12 + (pos)] * 654183;  \
        (src)[3 + (pos)] -= (src)[12 + (pos)] * 997805;  \
        (src)[4 + (pos)] += (src)[12 + (pos)] * 136657;  \
        (src)[5 + (pos)] -= (src)[12 + (pos)] * 683901;  \
        (src)[12 + (pos)] = 0; \
    } while (0)

/* Compute multiplications by 19 */
#define CURVE25519_MULTI_BY_19(dst, src, t1_, t2_, t16_)        \
    do {                                                        \
        (t1_)  = (uint64_t)(src);                               \
        (t2_)  = (t1_) << 1;                                    \
        (t16_) = (t1_) << 4;                                    \
        (dst) += (int64_t)((t1_) + (t2_) + (t16_));             \
    } while (0)

/* Set this parameter to value, */
#define CURVE25519_FP_SET(dst, value)       \
    do {                                    \
        (dst)[0] = (value);                 \
        (dst)[1] = 0;                       \
        (dst)[2] = 0;                       \
        (dst)[3] = 0;                       \
        (dst)[4] = 0;                       \
        (dst)[5] = 0;                       \
        (dst)[6] = 0;                       \
        (dst)[7] = 0;                       \
        (dst)[8] = 0;                       \
        (dst)[9] = 0;                       \
    } while (0)

#define CURVE25519_FP51_SET(dst, value)     \
    do {                                    \
        (dst)[0] = (value);                 \
        (dst)[1] = 0;                       \
        (dst)[2] = 0;                       \
        (dst)[3] = 0;                       \
        (dst)[4] = 0;                       \
    } while (0)

/* Copy */
#define CURVE25519_FP_COPY(dst, src)       \
    do {                                   \
        (dst)[0] = (src)[0];               \
        (dst)[1] = (src)[1];               \
        (dst)[2] = (src)[2];               \
        (dst)[3] = (src)[3];               \
        (dst)[4] = (src)[4];               \
        (dst)[5] = (src)[5];               \
        (dst)[6] = (src)[6];               \
        (dst)[7] = (src)[7];               \
        (dst)[8] = (src)[8];               \
        (dst)[9] = (src)[9];               \
    } while (0)

#define CURVE25519_FP51_COPY(dst, src)     \
    do {                                   \
        (dst)[0] = (src)[0];               \
        (dst)[1] = (src)[1];               \
        (dst)[2] = (src)[2];               \
        (dst)[3] = (src)[3];               \
        (dst)[4] = (src)[4];               \
    } while (0)

/* Negate */
#define CURVE25519_FP_NEGATE(dst, src)      \
    do {                                    \
        (dst)[0] = -(src)[0];               \
        (dst)[1] = -(src)[1];               \
        (dst)[2] = -(src)[2];               \
        (dst)[3] = -(src)[3];               \
        (dst)[4] = -(src)[4];               \
        (dst)[5] = -(src)[5];               \
        (dst)[6] = -(src)[6];               \
        (dst)[7] = -(src)[7];               \
        (dst)[8] = -(src)[8];               \
        (dst)[9] = -(src)[9];               \
    } while (0)

/* Basic operation */
#define CURVE25519_FP_OP(dst, src1, src2, op)        \
    do {                                             \
        (dst)[0] = (src1)[0] op (src2)[0];           \
        (dst)[1] = (src1)[1] op (src2)[1];           \
        (dst)[2] = (src1)[2] op (src2)[2];           \
        (dst)[3] = (src1)[3] op (src2)[3];           \
        (dst)[4] = (src1)[4] op (src2)[4];           \
        (dst)[5] = (src1)[5] op (src2)[5];           \
        (dst)[6] = (src1)[6] op (src2)[6];           \
        (dst)[7] = (src1)[7] op (src2)[7];           \
        (dst)[8] = (src1)[8] op (src2)[8];           \
        (dst)[9] = (src1)[9] op (src2)[9];           \
    } while (0)

/* Basic operation */
#define CURVE25519_FP51_ADD(dst, src1, src2)        \
    do {                                            \
        (dst)[0] = (src1)[0] + (src2)[0];           \
        (dst)[1] = (src1)[1] + (src2)[1];           \
        (dst)[2] = (src1)[2] + (src2)[2];           \
        (dst)[3] = (src1)[3] + (src2)[3];           \
        (dst)[4] = (src1)[4] + (src2)[4];           \
    } while (0)

#define CURVE25519_FP51_SUB(dst, src1, src2)                  \
    do {                                                      \
        (dst)[0] = ((src1)[0] + 0xfffffffffffda) - (src2)[0]; \
        (dst)[1] = ((src1)[1] + 0xffffffffffffe) - (src2)[1]; \
        (dst)[2] = ((src1)[2] + 0xffffffffffffe) - (src2)[2]; \
        (dst)[3] = ((src1)[3] + 0xffffffffffffe) - (src2)[3]; \
        (dst)[4] = ((src1)[4] + 0xffffffffffffe) - (src2)[4]; \
    } while (0)

#define CURVE25519_GE_COPY(dst, src)                      \
    do {                                                  \
        CURVE25519_FP_COPY((dst).x, (src).x);   \
        CURVE25519_FP_COPY((dst).y, (src).y);   \
        CURVE25519_FP_COPY((dst).z, (src).z);   \
        CURVE25519_FP_COPY((dst).t, (src).t);   \
    } while (0)

/* Add */
#define CURVE25519_FP_ADD(dst, src1, src2) CURVE25519_FP_OP(dst, src1, src2, +)
/* Subtract */
#define CURVE25519_FP_SUB(dst, src1, src2) CURVE25519_FP_OP(dst, src1, src2, -)

/* dst = dst * bit, bit = 0 or 1 */
#define CURVE25519_FP_MUL_BIT(dst, bit)              \
    do {                                             \
        int ii;                                      \
        for (ii = 0; ii < 10; ii++) {                \
            (dst)[ii] = (dst)[ii] * (bit);           \
        }                                            \
    } while (0)

/* dst[i] = src[i] * scalar */
#define CURVE25519_FP_MUL_SCALAR(dst, src, scalar)         \
    do {                                                   \
        uint32_t ii;                                       \
        for (ii = 0; ii < 10; ii++) {                      \
            (dst)[ii] = (uint64_t)((src)[ii] * (scalar));  \
        }                                                  \
    } while (0)

#define CURVE25519_BYTES3_LOAD_PADDING(dst, bits, src)             \
    do {                                                           \
            uint64_t valMacro = ((uint64_t)*((src) + 0)) << 0;         \
            valMacro |= ((uint64_t)*((src) + 1)) << 8;                 \
            valMacro |= ((uint64_t)*((src) + 2)) << 16;                \
            *(dst) = (uint64_t)(valMacro<< (bits));                    \
    } while (0)

#define CURVE25519_BYTES3_LOAD(dst, src)                        \
    do {                                                        \
            *(dst) = ((uint64_t)*((src) + 0)) << 0;             \
            *(dst) |= ((uint64_t)*((src) + 1)) << 8;            \
            *(dst) |= ((uint64_t)*((src) + 2)) << 16;           \
    } while (0)

#define CURVE25519_BYTES4_LOAD(dst, src)                        \
    do {                                                        \
            *(dst) =  ((uint64_t)*((src) + 0)) << 0;            \
            *(dst) |= ((uint64_t)*((src) + 1)) << 8;            \
            *(dst) |= ((uint64_t)*((src) + 2)) << 16;           \
            *(dst) |= ((uint64_t)*((src) + 3)) << 24;           \
    } while (0)

#define CURVE25519_BYTES6_LOAD(dst, src)                        \
    do {                                                        \
            *(dst) =  (uint64_t)*(src);                         \
            *(dst) |= ((uint64_t)*((src) + 1)) << 8;            \
            *(dst) |= ((uint64_t)*((src) + 2)) << 16;           \
            *(dst) |= ((uint64_t)*((src) + 3)) << 24;           \
            *(dst) |= ((uint64_t)*((src) + 4)) << 32;           \
            *(dst) |= ((uint64_t)*((src) + 5)) << 40;           \
    } while (0)

#define CURVE25519_BYTES7_LOAD(dst, src)                        \
    do {                                                        \
            *(dst) =  (uint64_t)*(src);                         \
            *(dst) |= ((uint64_t)*((src) + 1)) << 8;            \
            *(dst) |= ((uint64_t)*((src) + 2)) << 16;           \
            *(dst) |= ((uint64_t)*((src) + 3)) << 24;           \
            *(dst) |= ((uint64_t)*((src) + 4)) << 32;           \
            *(dst) |= ((uint64_t)*((src) + 5)) << 40;           \
            *(dst) |= ((uint64_t)*((src) + 6)) << 48;           \
    } while (0)

#define CURVE25519_BYTES3_PADDING_UNLOAD(dst, bits1, bits2, src)                                      \
    do {                                                                                              \
            const uint32_t posMacro = 8 - (bits1);                                                    \
            uint32_t valMacro = (uint32_t)(*(src));                                                   \
            uint32_t signMaskMacro= -(valMacro >> 31);                                                \
            uint32_t expand =( (uint32_t)(*((src) + 1))) << (bits2);                                  \
            *((dst) + 0) = (uint8_t)(valMacro >> (0 + posMacro) | (signMaskMacro>> (0 + posMacro)));                 \
            *((dst) + 1) = (uint8_t)(valMacro >> (8 + posMacro) | (signMaskMacro>> (8 + posMacro)));                 \
            *((dst) + 2) = (uint8_t)(expand | ((valMacro >> (16 + posMacro)) | (signMaskMacro>> (16 + posMacro))));  \
    } while (0)

#define CURVE25519_BYTES3_UNLOAD(dst, bits, src)                                           \
    do {                                                                                   \
            const uint32_t posMacro = 8 - (bits);                                          \
            uint32_t valMacro = (uint32_t)(*(src));                                        \
            uint32_t signMaskMacro= -(valMacro >> 31);                                     \
            *((dst) + 0) = (uint8_t)((valMacro >> (0 + posMacro)) | (signMaskMacro>> (0 + posMacro)));    \
            *((dst) + 1) = (uint8_t)((valMacro >> (8 + posMacro)) | (signMaskMacro>> (8 + posMacro)));    \
            *((dst) + 2) = (uint8_t)((valMacro >> (16 + posMacro)) | (signMaskMacro>> (16 + posMacro)));  \
    } while (0)

#define CURVE25519_BYTES4_PADDING_UNLOAD(dst, bits, src)                           \
    do {                                                                           \
            uint32_t valMacro = (uint32_t)(*(src));                                \
            uint32_t signMaskMacro= -(valMacro >> 31);                             \
            uint32_t expand = ((uint32_t)(*((src) + 1))) << (bits);                \
            *((dst) + 0) = (uint8_t)((valMacro >> 0) | (signMaskMacro>> 0));              \
            *((dst) + 1) = (uint8_t)((valMacro >> 8) | (signMaskMacro>> 8));              \
            *((dst) + 2) = (uint8_t)((valMacro >> 16) | (signMaskMacro>> 16));            \
            *((dst) + 3) = (uint8_t)(expand | ((valMacro >> 24) | (signMaskMacro>> 24))); \
    } while (0)

/**
 * Reference RFC 7748 section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
 * set the three least significant bits of the first byte and the most significant bit of the last to zero,
 * set the second most significant bit of the last byte to 1 and, finally, decode as little-endian.
*/
#define CURVE25519_DECODE_LITTLE_ENDIAN(dst, src)        \
    do {                                                 \
            uint32_t ii;                                 \
            for (ii = 0; ii < 32; ii++) {                \
                (dst)[ii] = (src)[ii];                   \
            }                                            \
            (dst)[0]  &= 248;                            \
            (dst)[31] &= 127;                            \
            (dst)[31] |= 64;                             \
    } while (0)

#define CURVE25519_FP_CSWAP(s, a, b)                                    \
    do {                                                                \
            uint32_t tt;                                                \
            const uint32_t tsMacro = 0 - (s);                           \
            for (uint32_t ii = 0; ii < 10; ii++) {                      \
                tt = tsMacro & (((uint32_t)(a)[ii]) ^ ((uint32_t)(b)[ii])); \
                (a)[ii] = (int32_t)((uint32_t)(a)[ii] ^ tt);            \
                (b)[ii] = (int32_t)((uint32_t)(b)[ii] ^ tt);            \
            }                                                           \
    } while (0)

#define CURVE25519_FP51_CSWAP(s, a, b)                                  \
    do {                                                                \
            uint64_t tt;                                                \
            const uint64_t tsMacro = 0 - (uint64_t)(s);                 \
            for (uint32_t ii = 0; ii < 5; ii++) {                       \
                tt = tsMacro & ((a)[ii] ^ (b)[ii]);                     \
                (a)[ii] = (a)[ii] ^ tt;                                 \
                (b)[ii] = (b)[ii] ^ tt;                                 \
            }                                                           \
    } while (0)

void TableLookup(GePre *preCompute, int32_t pos, int8_t e);

void ConditionalMove(GePre *preCompute, const GePre *tableElement, uint32_t indicator);

void ScalarMultiBase(GeE *out, const uint8_t in[CRYPT_CURVE25519_KEYLEN]);

#ifdef HITLS_CRYPTO_ED25519
void PointEncoding(const GeE *point, uint8_t *output, uint32_t outputLen);

int32_t PointDecoding(GeE *point, const uint8_t in[CRYPT_CURVE25519_KEYLEN]);

void ScalarMulAdd(uint8_t s[CRYPT_CURVE25519_KEYLEN], const uint8_t a[CRYPT_CURVE25519_KEYLEN],
    const uint8_t b[CRYPT_CURVE25519_KEYLEN], const uint8_t c[CRYPT_CURVE25519_KEYLEN]);

void ModuloL(uint8_t s[CRYPT_CURVE25519_SIGNLEN]);

void KAMulPlusMulBase(GeE *out, const uint8_t hash[CRYPT_CURVE25519_KEYLEN],
    const GeE *p, const uint8_t s[CRYPT_CURVE25519_KEYLEN]);
#endif

#ifdef HITLS_CRYPTO_X25519
void ScalarMultiPoint(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
#endif

void FpInvert(Fp25 out, const Fp25 a);

void FpMul(Fp25 out, const Fp25 f, const Fp25 g);

void FpSquareDoubleCore(Fp25 out, const Fp25 in, bool doDouble);

void PolynomialToData(uint8_t out[32], const Fp25 polynomial);

void DataToPolynomial(Fp25 out, const uint8_t data[32]);

#ifdef HITLS_CRYPTO_X25519
void CRYPT_X25519_PublicFromPrivate(const uint8_t privateKey[CRYPT_CURVE25519_KEYLEN],
    uint8_t publicKey[CRYPT_CURVE25519_KEYLEN]);
#endif

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_CURVE25519

#endif // CURVE25519_LOCAL_H

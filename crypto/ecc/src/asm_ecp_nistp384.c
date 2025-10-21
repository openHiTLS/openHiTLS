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
#if defined(HITLS_CRYPTO_CURVE_NISTP384) && defined(HITLS_CRYPTO_NIST_USE_ACCEL)

#include <stdint.h>

#include "securec.h"
#include "crypt_bn.h"
#include "crypt_ecc.h"
#include "ecc_local.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "bsl_util_internal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "ecp_nistp384.h"

#ifndef HITLS_INT128
#error "This nistp384 implementation require the compiler support 128-bits integer."
#endif

/*
 * A 128-bit implemantation of NIST-p384, inspired by Rohan McLure's work for openssl.
 * reference: https://sthbrx.github.io/blog/2023/08/07/going-out-on-a-
 *                    limb-efficient-elliptic-curve-arithmetic-in-openssl/
 *
 * Field element representation:
 * The basic idea is to use 7 56-bits limbs to represent the field element(a 'felem') of p384:
 * x_0*2^0 + x_1*2^56 + x_2*2^112 + x_3*2^168 ... + x_6*2^336
 * the 'redundant limbs' means that the upper 8 bits of each limb which use a uint64 to hold,
 * and the 'redundant bits' is use to cache carrys or upper bits of a multiplication, so that
 * the number of carry propagation can be reduced to a few.
 */
typedef limb Felem64[7]; // Field-elemnt of 'redundant limbs'
typedef uint128_t longlimb;
typedef longlimb Felem128[13]; // 13 uint128 to store the mul/sqr result
typedef uint8_t FelemBytes[48]; // 48 bytes as binary format of Field-elemnt

// Jacobian projective coordinates
typedef struct {
    Felem64 x;
    Felem64 y;
    Felem64 z;
} FelemPoint;

// Affine point
typedef struct {
    Felem64 x;
    Felem64 y;
} FelemAffinePoint;


static Flimbs g_one = {1};
// n
__attribute__((aligned(32))) static Flimbs g_order = {0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf,
                                                      0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
// (n >> 1) + 1
__attribute__((aligned(32))) static Flimbs g_orderHalfCeil = {0x76760cb5666294ba, 0xac0d06d9245853bd,
                                                              0xe3b1a6c0fa1b96ef, 0xffffffffffffffff,
                                                              0xffffffffffffffff, 0x7fffffffffffffff};
// p
__attribute__((aligned(32))) static Flimbs g_poly = {0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe,
                                                     0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
// (p >> 1) + 1
__attribute__((aligned(32))) static Flimbs g_polyHalfCeil = {0x0000000080000000, 0x7fffffff80000000,
                                                             0xffffffffffffffff, 0xffffffffffffffff,
                                                             0xffffffffffffffff, 0x7fffffffffffffff};

// precomputed base point of p384: 1,3,...15,-1,-3..-15 * G
__attribute__((aligned(32))) static FelemPoint g_precomputedG[WINDOW_TABLE_SIZE] = {
  {{0x00545e3872760ab7, 0x00f25dbf55296c3a, 0x00e082542a385502, 0x008ba79b9859f741, 0x0020ad746e1d3b62,
    0x0005378eb1c71ef3, 0x0000aa87ca22be8b},
   {0x00431d7c90ea0e5f, 0x00b1ce1d7e819d7a, 0x0013b5f0b8c00a60, 0x00289a147ce9da31, 0x0092dc29f8f41dbd,
    0x002c6f5d9e98bf92, 0x00003617de4a9626},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x00d7e5c70500c831, 0x00bbae5026580d02, 0x0040d3566da6b408, 0x00202dcd06bea4f2, 0x00dc7d98cb9d3910,
    0x00fa1464793c7e5f, 0x0000077a41d4606f},
   {0x005f28600a2f1df1, 0x00bd6be4b5d298b6, 0x000edc111eacc24a, 0x0085115aa5f7684c, 0x00a9fc998520b41c,
    0x0042837d0bbe9602, 0x0000c995f7ca0b0c},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x00bcdbc3836d84bc, 0x002f4a1ca297e60a, 0x00cbe56583b03788, 0x00bff98fc54f6661, 0x0025e467f208e51d,
    0x00c777573cac5ea0, 0x000011de24a2c251},
   {0x004414abe6c1713a, 0x00686d0ae8fb3318, 0x0033b6901aeb3177, 0x0054d5dee88c9865, 0x0000e7c5284b4477,
    0x00f92d0f5837e90a, 0x00008fa696c77440},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x000f05b48fb6d0e1, 0x00526f55b9ebb204, 0x009dfa7b1c508b05, 0x00fbea5ffa2d58cc, 0x004edffead6fe997,
    0x004788f29f8ebf23, 0x0000283c1d7365ce},
   {0x00664cdac512ef8c, 0x004ede32a78f9e64, 0x00d01dbd225630d8, 0x00ed799729d9c92c, 0x001690471a61d867,
    0x001b88ba52efdb8c, 0x00009475c99061e4},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x0055e4461079118b, 0x00528bfee2b9535c, 0x00e285fb6e21c388, 0x001e6fd3bac6cb1e, 0x0025b78f2216f729,
    0x00cb3ef1bf29b8b0, 0x00008f0a39a4049b},
   {0x002da4f9ac664af8, 0x003efedfd51b6826, 0x0054aed9b3029e74, 0x00a3c400c6b76788, 0x00c3a9799a9b3d7c,
    0x0001d6452c4a5322, 0x000062c77e1438b6},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x00356f3b55b4ddd8, 0x00b66e3afb81d626, 0x0014892d3f8c4749, 0x005837c37456c9fd, 0x004816c57fe935ed,
    0x00b998da1eeec290, 0x0000099056e27da7},
   {0x005dba8138c5e0bb, 0x00d51263aaff357d, 0x00f41b52a3255466, 0x00dfc363fd43ff93, 0x00c5e0396fc4eed8,
    0x00ab96688505544a, 0x00002e4c0c234e30},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x00f1ca1e3b5cbce7, 0x00f441abd99f1baa, 0x00d1f0f11c139ee5, 0x00f01f873f6267bc, 0x00fcc6ab9632bff9,
    0x00ea5bafdaf5002f, 0x0000a567ba97b67a},
   {0x0023a12736f429cc, 0x00cb8272218a7d64, 0x00e057857d66776b, 0x0046932ec086329b, 0x00164ecc51855950,
    0x003318644e4147af, 0x0000de1b38b3989f},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x0088701a9606860b, 0x00557a10b6383b4b, 0x00f7da7c4e9ca849, 0x00fff01c205b21f9, 0x0013525522a94156,
    0x0001058cc15c11d8, 0x0000b3d13fc8b32b},
   {0x005d588d33f7bd62, 0x0024f8b284af5098, 0x004373dfbfd9838d, 0x001d749af484d111, 0x00164b1beebac4a1,
    0x0062a61b049b2536, 0x0000152919e7df91},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x00545e3872760ab7, 0x00f25dbf55296c3a, 0x00e082542a385502, 0x008ba79b9859f741, 0x0020ad746e1d3b62,
    0x0005378eb1c71ef3, 0x0000aa87ca22be8b},
   {0x00bce2846f15f1a0, 0x004e30e2817e6285, 0x00ec4a0f473ef59f, 0x00d765eb831625ce, 0x006d23d6070be242,
    0x00d390a26167406d, 0x0000c9e821b569d9},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x00d7e5c70500c831, 0x00bbae5026580d02, 0x0040d3566da6b408, 0x00202dcd06bea4f2, 0x00dc7d98cb9d3910,
    0x00fa1464793c7e5f, 0x0000077a41d4606f},
   {0x00a0d7a0f5d0e20e, 0x0042931b4a2d6749, 0x00f123eee1523db5, 0x007aeea55a0897b3, 0x005603667adf4be3,
    0x00bd7c82f44169fd, 0x0000366a0835f4f3},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x00bcdbc3836d84bc, 0x002f4a1ca297e60a, 0x00cbe56583b03788, 0x00bff98fc54f6661, 0x0025e467f208e51d,
    0x00c777573cac5ea0, 0x000011de24a2c251},
   {0x00bbeb55193e8ec5, 0x009791f51704cce7, 0x00cc496fe513ce88, 0x00ab2a211773679a, 0x00ff183ad7b4bb88,
    0x0006d2f0a7c816f5, 0x0000705969388bbf},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x000f05b48fb6d0e1, 0x00526f55b9ebb204, 0x009dfa7b1c508b05, 0x00fbea5ffa2d58cc, 0x004edffead6fe997,
    0x004788f29f8ebf23, 0x0000283c1d7365ce},
   {0x0099b3263aed1073, 0x00b120cd5870619b, 0x002fe242dda8cf27, 0x00128668d62636d3, 0x00e96fb8e59e2798,
    0x00e47745ad102473, 0x00006b8a366f9e1b},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x0055e4461079118b, 0x00528bfee2b9535c, 0x00e285fb6e21c388, 0x001e6fd3bac6cb1e, 0x0025b78f2216f729,
    0x00cb3ef1bf29b8b0, 0x00008f0a39a4049b},
   {0x00d25b075399b507, 0x00c100202ae497d9, 0x00ab51264cfc618b, 0x005c3bff39489877, 0x003c56866564c283,
    0x00fe29bad3b5acdd, 0x00009d3881ebc749},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x00356f3b55b4ddd8, 0x00b66e3afb81d626, 0x0014892d3f8c4749, 0x005837c37456c9fd, 0x004816c57fe935ed,
    0x00b998da1eeec290, 0x0000099056e27da7},
   {0x00a2457fc73a1f44, 0x002aec9c5500ca82, 0x000be4ad5cd9ab99, 0x00203c9c02bc006c, 0x003a1fc6903b1127,
    0x005469977afaabb5, 0x0000d1b3f3dcb1cf},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x00f1ca1e3b5cbce7, 0x00f441abd99f1baa, 0x00d1f0f11c139ee5, 0x00f01f873f6267bc, 0x00fcc6ab9632bff9,
    0x00ea5bafdaf5002f, 0x0000a567ba97b67a},
   {0x00dc5ed9c90bd633, 0x00347c8dde75829b, 0x001fa87a82988894, 0x00b96cd13f79cd64, 0x00e9b133ae7aa6af,
    0x00cce79bb1beb850, 0x000021e4c74c6760},
   {1, 0, 0, 0, 0, 0, 0}},
  {{0x0088701a9606860b, 0x00557a10b6383b4b, 0x00f7da7c4e9ca849, 0x00fff01c205b21f9, 0x0013525522a94156,
    0x0001058cc15c11d8, 0x0000b3d13fc8b32b},
   {0x00a2a773cc08429d, 0x00db064d7b50af67, 0x00bc8c2040257c72, 0x00e28b650b7b2eee, 0x00e9b4e411453b5e,
    0x009d59e4fb64dac9, 0x0000ead6e618206e},
   {1, 0, 0, 0, 0, 0, 0}}};

static inline limb Uint56FromBeBin(const uint8_t *bytes)
{
    return (((limb)bytes[0] << 48) |    // Byte 0 shift to 48 bits
            ((limb)bytes[1] << 40) |    // Byte 1 shift to 40 bits
            ((limb)bytes[2] << 32) |    // Byte 2 shift to 32 bits
            ((limb)bytes[3] << 24) |    // Byte 3 shift to 24 bits
            ((limb)bytes[4] << 16) |    // Byte 4 shift to 16 bits
            ((limb)bytes[5] << 8) |     // Byte 5 shift to 8 bits
            ((limb)bytes[6]));          // Byte 6 shift to 0 bits
}

static inline limb Uint48FromBeBin(const uint8_t *bytes)
{
    return (((limb)bytes[0] << 40) |    // Byte 1 shift to 40 bits
            ((limb)bytes[1] << 32) |    // Byte 2 shift to 32 bits
            ((limb)bytes[2] << 24) |    // Byte 3 shift to 24 bits
            ((limb)bytes[3] << 16) |    // Byte 4 shift to 16 bits
            ((limb)bytes[4] << 8) |     // Byte 5 shift to 8 bits
            ((limb)bytes[5]));          // Byte 6 shift to 0 bits
}

// the input 'bin' is big-endian
static void Bin2Felem64(Felem64 fx, const uint8_t *bin)
{
    fx[0] = Uint56FromBeBin(bin + 41); // 41~47 bytes to 0th limb
    fx[1] = Uint56FromBeBin(bin + 34); // 34~40 bytes to 1th limb
    fx[2] = Uint56FromBeBin(bin + 27); // 27~33 bytes to 2th limb
    fx[3] = Uint56FromBeBin(bin + 20); // 20~32 bytes to 3th limb
    fx[4] = Uint56FromBeBin(bin + 13); // 13~19 bytes to 4th limb
    fx[5] = Uint56FromBeBin(bin + 6);  // 6~13 bytes to 5th limb
    fx[6] = Uint48FromBeBin(bin);      // 0~5 bytes to 6th limb
}

static inline void Uint48ToBeBin(uint64_t v, uint8_t *b)
{
    b[0] = v >> 40;  // 0 th byte on (48 - 8)=40
    b[1] = v >> 32;  // 1 th byte on (40 - 8)=32
    b[2] = v >> 24;  // 2 th byte on (32 - 8)=24
    b[3] = v >> 16;  // 3 th byte on (24 - 8)=16
    b[4] = v >> 8;   // 4 th byte on (16 - 8)=8
    b[5] = v & 0xff; // 5 th byte on 0
}

static inline void Uint56ToBeBin(uint64_t v, uint8_t *b)
{
    b[0] = v >> 48;  // 0 th byte on (56 - 8)=48
    b[1] = v >> 40;  // 1 th byte on (48 - 8)=40
    b[2] = v >> 32;  // 2 th byte on (40 - 8)=32
    b[3] = v >> 24;  // 3 th byte on (32 - 8)=24
    b[4] = v >> 16;  // 4 th byte on (24 - 8)=16
    b[5] = v >> 8;   // 5 th byte on (16 - 8)=8
    b[6] = v & 0xff; // 6 th byte on 0
}

// the output 'bin' is big-endian
static void Felem64ToBin(uint8_t *bin, const Felem64 fx)
{
    Uint48ToBeBin(fx[6], bin);       // 6 th limb on start of the binary
    Uint56ToBeBin(fx[5], bin + 6);   // 5 th limb on 48/8=6 bytes
    Uint56ToBeBin(fx[4], bin + 13);  // 4 th limb on (6+7)=13 bytes
    Uint56ToBeBin(fx[3], bin + 20);  // 3 th limb on (13+7)=20 bytes
    Uint56ToBeBin(fx[2], bin + 27);  // 2 th limb on (20+7)=27 bytes
    Uint56ToBeBin(fx[1], bin + 34);  // 1 th limb on (27+7)=34 bytes
    Uint56ToBeBin(fx[0], bin + 41);  // 0 th limb on (34+7)=41 bytes
}

static bool FlimbsIsOne(const Flimbs a)
{
    return memcmp(a, g_one, sizeof(Flimbs)) == 0;
}

// if a > b return 1
// else if a < b return -1
// else a == b return 0
static int32_t FlimbsCmp(const Flimbs a, const Flimbs b)
{
    for (int i = 5; i >= 0; i--) {  // compare start from most significant side(the last one, that's the 5th limb).
        if (a[i] > b[i]) {
            return 1;
        } else if (a[i] < b[i]) {
            return -1;
        }
    }
    return 0;
}

static int32_t BN2Felem64(Felem64 fx, const BN_BigNum *x)
{
    int32_t ret;
    FelemBytes bin;
    uint32_t len = sizeof(bin);

    GOTO_ERR_IF(BN_Bn2BinFixZero(x, bin, len), ret);
    Bin2Felem64(fx, bin);
ERR:
    return ret;
}

static int32_t Felem64ToBn(BN_BigNum *b, const Felem64 f)
{
    int32_t ret;
    FelemBytes fb = {0};
    Felem64ToBin(fb, f);
    GOTO_ERR_IF(BN_Bin2Bn(b, fb, sizeof(fb)), ret);
ERR:
    return ret;
}

static void EccPoint2Felem(FelemPoint *r, const ECC_Point *a)
{
    (void)BN2Felem64(r->x, &a->x);
    (void)BN2Felem64(r->y, &a->y);
    (void)BN2Felem64(r->z, &a->z);
}

static void FlimbsBnFixSize(ECC_Point *p)
{
    FlimbsSub(p->x.data, p->x.data, g_poly);
    BN_FixSize(&p->x);
    FlimbsSub(p->y.data, p->y.data, g_poly);
    BN_FixSize(&p->y);
    FlimbsSub(p->z.data, p->z.data, g_poly);
    BN_FixSize(&p->z);
}

static void Felem2EccPoint(ECC_Para *para, ECC_Point *p, FelemPoint *f)
{
    (void)para;

    (void)Felem64ToBn(&p->x, f->x);
    (void)Felem64ToBn(&p->y, f->y);
    (void)Felem64ToBn(&p->z, f->z);
    FlimbsBnFixSize(p);
}

static void FelemMul(Felem128 t, const Felem64 a, const Felem64 b)
{
    // t[0~3]
    t[0] = ((longlimb)a[0]) * b[0];   // 0 = 0*0. The left '0' and right '0' of operator '*' is 0th element of a,b
    t[1] = ((longlimb)a[0]) * b[1];   // 1 = 0*1
    t[2] = ((longlimb)a[0]) * b[2];   // 2 = 0*2
    t[3] = ((longlimb)a[0]) * b[3];   // 3 = 0*3
    t[1] += ((longlimb)a[1]) * b[0];  // 1 += 1*0
    t[2] += ((longlimb)a[1]) * b[1];  // 2 += 1*1
    t[3] += ((longlimb)a[1]) * b[2];  // 3 += 1*2
    t[2] += ((longlimb)a[2]) * b[0];  // 2 += 2*0
    t[3] += ((longlimb)a[2]) * b[1];  // 3 += 2*1
    t[3] += ((longlimb)a[3]) * b[0];  // 3 += 3*0

    // t[4~7]
    t[4] = ((longlimb)a[0]) * b[4];   // 4 = 0*4
    t[5] = ((longlimb)a[0]) * b[5];   // 5 = 0*5
    t[6] = ((longlimb)a[0]) * b[6];   // 6 = 0*6
    t[7] = ((longlimb)a[1]) * b[6];   // 7 = 1*6
    t[4] += ((longlimb)a[1]) * b[3];  // 4 += 1*3
    t[5] += ((longlimb)a[1]) * b[4];  // 5 += 1*4
    t[6] += ((longlimb)a[1]) * b[5];  // 6 += 1*5
    t[4] += ((longlimb)a[2]) * b[2];  // 4 += 2*2
    t[5] += ((longlimb)a[2]) * b[3];  // 5 += 2*3
    t[6] += ((longlimb)a[2]) * b[4];  // 6 += 2*4
    t[7] += ((longlimb)a[2]) * b[5];  // 7 += 2*5
    t[4] += ((longlimb)a[3]) * b[1];  // 4 += 3*1
    t[5] += ((longlimb)a[3]) * b[2];  // 5 += 3*2
    t[6] += ((longlimb)a[3]) * b[3];  // 6 += 3*3
    t[7] += ((longlimb)a[3]) * b[4];  // 7 += 3*4
    t[4] += ((longlimb)a[4]) * b[0];  // 4 += 4*0
    t[5] += ((longlimb)a[4]) * b[1];  // 5 += 4*1
    t[6] += ((longlimb)a[4]) * b[2];  // 6 += 4*2
    t[7] += ((longlimb)a[4]) * b[3];  // 7 += 4*3
    t[5] += ((longlimb)a[5]) * b[0];  // 5 += 5*0
    t[6] += ((longlimb)a[5]) * b[1];  // 6 += 5*1
    t[7] += ((longlimb)a[5]) * b[2];  // 7 += 5*2
    t[6] += ((longlimb)a[6]) * b[0];  // 6 += 6*0
    t[7] += ((longlimb)a[6]) * b[1];  // 7 += 6*1

    // t[8~11]
    t[8] = ((longlimb)a[2]) * b[6];   // 8 = 2*6
    t[9] = ((longlimb)a[3]) * b[6];   // 9 = 3*6
    t[10] = ((longlimb)a[4]) * b[6];  // 10 = 4*6
    t[11] = ((longlimb)a[5]) * b[6];  // 11 = 5*6
    t[8] += ((longlimb)a[3]) * b[5];  // 8 += 3*5
    t[9] += ((longlimb)a[4]) * b[5];  // 9 += 4*5
    t[10] += ((longlimb)a[5]) * b[5]; // 10 += 5*5
    t[11] += ((longlimb)a[6]) * b[5]; // 11 += 6*5
    t[8] += ((longlimb)a[4]) * b[4];  // 8 += 4*4
    t[9] += ((longlimb)a[5]) * b[4];  // 9 += 5*4
    t[8] += ((longlimb)a[5]) * b[3];  // 8 += 5*3
    t[9] += ((longlimb)a[6]) * b[3];  // 9 += 6*3
    t[10] += ((longlimb)a[6]) * b[4]; // 10 += 6*4
    t[8] += ((longlimb)a[6]) * b[2];  // 8 += 6*2

    // t[12]
    t[12] = ((longlimb)a[6]) * b[6];  // 12 = 6*6
}

static void FelemSquare(Felem128 t, const Felem64 a)
{
    // t[0~3]
    t[0] = ((longlimb)a[0]) * a[0];        // 0 = 0*0
    t[1] = ((longlimb)a[0] << 1) * a[1];   // 1 = (0*1)*2
    t[2] = ((longlimb)a[0] << 1) * a[2];   // 2 = (0*2)*2
    t[3] = ((longlimb)a[0] << 1) * a[3];   // 3 = (0*3)*2
    t[2] += ((longlimb)a[1]) * a[1];       // 2 += 1*1
    t[3] += ((longlimb)a[1] << 1) * a[2];  // 3 = (1*2)*2

    // t[4~7]
    t[4] = ((longlimb)a[0] << 1) * a[4];   // 4 = (0*4)*2
    t[5] = ((longlimb)a[0] << 1) * a[5];   // 5 = (0*5)*2
    t[6] = ((longlimb)a[0] << 1) * a[6];   // 6 = (0*5)*2
    t[7] = ((longlimb)a[1] << 1) * a[6];   // 7 = (1*6)*2
    t[4] += ((longlimb)a[1] << 1) * a[3];  // 4 += (1*3)*2
    t[5] += ((longlimb)a[1] << 1) * a[4];  // 5 += (1*4)*2
    t[6] += ((longlimb)a[1] << 1) * a[5];  // 6 += (1*5)*2
    t[4] += ((longlimb)a[2]) * a[2];       // 4 += 2*2
    t[5] += ((longlimb)a[2] << 1) * a[3];  // 5 += (2*3)*2
    t[6] += ((longlimb)a[2] << 1) * a[4];  // 6 += (2*4)*2
    t[7] += ((longlimb)a[2] << 1) * a[5];  // 7 += (2*5)*2
    t[6] += ((longlimb)a[3]) * a[3];       // 6 += 3*3
    t[7] += ((longlimb)a[3] << 1) * a[4];  // 7 += (3*4)*2

    // t[8~11]
    t[8] = ((longlimb)a[2] << 1) * a[6];   // 8 = (2*6)*2
    t[9] = ((longlimb)a[3] << 1) * a[6];   // 9 = (3*6)*2
    t[10] = ((longlimb)a[4] << 1) * a[6];  // 10 = (4*6)*2
    t[11] = ((longlimb)a[5] << 1) * a[6];  // 11 = (5*6)*2
    t[8] += ((longlimb)a[3] << 1) * a[5];  // 8 += (3*5)*2
    t[9] += ((longlimb)a[4] << 1) * a[5];  // 9 += (4*5)*2
    t[10] += ((longlimb)a[5]) * a[5];      // 10 += 5*5
    t[8] += ((longlimb)a[4]) * a[4];       // 8 += 4*4

    // t[12]
    t[12] = ((longlimb)a[6]) * a[6];       // 12 = 6*6
}

/*
 * for nistp348, p_384 = 2^384 - 2^128 - 2^96 + 2^32 + 1,
 * let t = 2^56, then delta(t) = 2^16*t^2 + 2^40t - 2^32 + 1,
 * then, p_384 = 2^384 - delta(t)
 * then, 2^384 = delta(t) mod p_384.
 *
 * Before do the reduction of two field element's production,
 *              t^7 = 2^8*2^384 = 2^8*delta(t) mod p_384
 * so, for example, do the reduction of 13th 56-bits radix limb,
 *              a[12]t^12 = a[12]t^5*t^7
 *                        = a[12]t^5*2^8*delta(t) mod p_384
 *                        = a[12]t^5*2^8*(2^16*t^2 + 2^40t - 2^32 + 1) mod p_384
 *                        = a[12](2^24*t^7 + 2^48*t^6 + (2^8 - 2^40)*t^5) mod p_384
 *
 * let t = 2^56, then f(t) = 2^48t^6 - 2^16t^2 - 2^40t + (2^32 - 1) = p_384
 */
static void Felem128Reduce(Felem64 r, Felem128 a)
{
    /*
     * To prevent underflow when doing subtraction, add 2^76*p to the minuend
     *         2^76*p = 2^76*(2^384 - 2^128 - 2^96 + 2^32 - 1)
     *                = 2^460 - 2^204 - 2^172 + 2^108 - 2^76
     *                = (2^124 + 2^108 - 2^76) + 2^56*(2^124 - 2^116 - 2^68) + 2^112*(2^124 - 2^92 - 2^68) +
     *                  2^168*(2^124 - 2^68) + 2^224*(2^124 - 2^68) + 2^280*(2^124 - 2^68) + 2^336*(2^124 - 2^68)
     *
     */

    // 'upl' is short for 'Underflow Prevention Limb'
    longlimb upl0 = ((longlimb)1 << 124) + ((longlimb)1 << 108) - ((longlimb)1 << 76); // (1<<124)+(1<<108)-(1<<76)
    longlimb upl1 = ((longlimb)1 << 124) - ((longlimb)1 << 116) - ((longlimb)1 << 68); // (1<<124)-(1<<116)-(1<<68)
    longlimb upl2 = ((longlimb)1 << 124) - ((longlimb)1 << 92) - ((longlimb)1 << 68);  // (1<<124)-(1<<92)-(1<<68)
    longlimb upl3 = ((longlimb)1 << 124) - ((longlimb)1 << 68);                        // (1<<124)-(1<<68)

    __attribute__((aligned(32))) longlimb t[9];  // only keep the low 9 longlimbs
    t[0] = upl0 + a[0]; // copy 0 th longlimb
    t[1] = upl1 + a[1]; // copy 1 th longlimb
    t[2] = upl2 + a[2]; // copy 2 th longlimb
    t[3] = upl3 + a[3]; // copy 3 th longlimb
    t[4] = upl3 + a[4]; // copy 4 th longlimb
    t[5] = upl3 + a[5]; // copy 5 th longlimb
    t[6] = upl3 + a[6]; // copy 6 th longlimb
    t[7] = a[7];        // copy 7 th longlimb
    t[8] = a[8];        // copy 8 th longlimb

   /*
    * first substitution,
    * do the reduction of a[12], a[11], a[10], a[9]
    */

    // 2^24*t^7*a[12]
    t[8] += a[12] >> 32; // reduce the higher 56-32=24 bits of 12th limb to 8th limb
    t[7] += (a[12] & 0xffffffff) << 24; // reduce the lower 56-24=32 bits of 12th limb to 7th limb
    // 2^48*t^6*a[12]
    t[7] += a[12] >> 8; // reduce the higher 56-8=48 bits of 12th limb to 7th limb
    t[6] += (a[12] & 0xff) << 48; // reduce the lower 56-48=8 bits of 12th limb to 6th limb
    // 2^8*t^5
    t[6] += a[12] >> 48; // reduce the higher 56-48=8 bits of 12th limb to 6th limb
    t[5] += (a[12] & 0xffffffffffff) << 8; // reduce the lower 56-8=48 bits of 12th limb to 5th limb
    // -2^40*t^5
    t[6] -= a[12] >> 16; // reduce the higher 56-16=40 bits of 12th limb to 6th limb
    t[5] -= (a[12] & 0xffff) << 40; // reduce the lower 56-40=16 bits of 12th limb to 5th limb

    // a[11]t^11 = a[11](2^24*t^6 + 2^48*t^5 + 2^8*t^4 - 2^40*t^4) mod p_384
    t[7] += a[11] >> 32; // reduce the higher 56-32=24 bits of 11th limb to 7th limb
    t[6] += (a[11] & 0xffffffff) << 24; // reduce the lower 56-24=32 bits of 11th limb to 6th limb
    t[6] += a[11] >> 8; // reduce the higher 56-8=48 bits of 11th limb to 6th limb
    t[5] += (a[11] & 0xff) << 48; // reduce the lower 56-48=8 bits of 11th limb to 5th limb
    t[5] += a[11] >> 48; // reduce the higher 56-48=8 bits of 11th limb to 5th limb
    t[4] += (a[11] & 0xffffffffffff) << 8; // reduce the lower 56-8=38 bits of 11th limb to 4th limb
    t[5] -= a[11] >> 16; // reduce the higher 56-16=40 bits of 11th limb to 5th limb
    t[4] -= (a[11] & 0xffff) << 40; // reduce the lower 56-40=16 bits of 11th limb to 4th limb

    // a[10]t^10 = a[10](2^24*t^5 + 2^48*t^4 + 2^8*t^3 - 2^40*t^3) mod p_384
    t[6] += a[10] >> 32; // reduce the higher 56-32=24 bits of 10th limb to 6th limb
    t[5] += (a[10] & 0xffffffff) << 24; // reduce the lower 56-24=32 bits of 10th limb to 5th limb
    t[5] += a[10] >> 8; // reduce the higher 56-8=48 bits of 10th limb to 5th limb
    t[4] += (a[10] & 0xff) << 48; // reduce the lower 56-48=8 bits of 10th limb to 4th limb
    t[4] += a[10] >> 48; // reduce the higher 56-48=8 bits of 10th limb to 4th limb
    t[3] += (a[10] & 0xffffffffffff) << 8; // reduce the lower 56-8=48 bits of 10th limb to 3th limb
    t[4] -= a[10] >> 16; // reduce the higher 56-16=40 bits of 10th limb to 4th limb
    t[3] -= (a[10] & 0xffff) << 40; // reduce the lower 56-40=16 bits of 10th limb to 3th limb

    // a[9]t^9 = a[9](2^24*t^4 + 2^48*t^3 + 2^8*t^2 - 2^40*t^2) mod p_384
    t[5] += a[9] >> 32; // reduce the higher 56-32=24 bits of 9th limb to 5th limb
    t[4] += (a[9] & 0xffffffff) << 24; // reduce the lower 56-24=32 bits of 9th limb to 4th limb
    t[4] += a[9] >> 8; // reduce the higher 56-8=48 bits of 9th limb to 4th limb
    t[3] += (a[9] & 0xff) << 48; // reduce the lower 56-48=8 bits of 9th limb to 3th limb
    t[3] += a[9] >> 48; // reduce the higher 56-48=8 bits of 9th limb to 3th limb
    t[2] += (a[9] & 0xffffffffffff) << 8; // reduce the lower 56-8=48 bits of 9th limb to 2th limb
    t[3] -= a[9] >> 16; // reduce the higher 56-16=40 bits of 9th limb to 3th limb
    t[2] -= (a[9] & 0xffff) << 40; // reduce the lower 56-40=16 bits of 9th limb to 2th limb

    /*
     * second substitution
     * do the reduction of a[8], a[7]
     */

    // a[8]t^8 = a[8](2^24*t^3 + 2^48*t^2 + 2^8*t - 2^40*t) mod p_384
    t[4] += t[8] >> 32; // reduce the higher 56-32=24 bits of 8th limb to 4th limb
    t[3] += (t[8] & 0xffffffff) << 24; // reduce the lower 56-24=32 bits of 8th limb to 3th limb
    t[3] += t[8] >> 8; // reduce the higher 56-8=48 bits of 8th limb to 3th limb
    t[2] += (t[8] & 0xff) << 48; // reduce the lower 56-48=8 bits of 8th limb to 2th limb
    t[2] -= t[8] >> 16; // reduce the higher 56-16=40 bits of 8th limb to 2th limb
    t[2] += t[8] >> 48; // reduce the higher 56-48=8 bits of 8th limb to 2th limb
    t[1] -= (t[8] & 0xffff) << 40; // reduce the lower 56-40=16 bits of 8th limb to 1th limb
    t[1] += (t[8] & 0xffffffffffff) << 8; // reduce the lower 56-8=40 bits of 8th limb to 1th limb

    // a[7]t^7 = a[7](2^24*t^2 + 2^48*t^1 + 2^8 - 2^40) mod p_384
    t[3] += t[7] >> 32; // reduce the higher 56-32=24 bits of 7th limb to 3th limb
    t[2] += (t[7] & 0xffffffff) << 24; // reduce the lower 56-24=32 bits of 7th limb to 2th limb
    t[2] += t[7] >> 8; // reduce the higher 56-8=48 bits of 7th limb to 2th limb
    t[1] += (t[7] & 0xff) << 48; // reduce the lower 56-48=8 bits of 7th limb to 2th limb
    t[1] -= t[7] >> 16; // reduce the higher 56-16=40 bits of 7th limb to 1th limb
    t[1] += t[7] >> 48; // reduce the higher 56-48=8 bits of 7th limb to 1th limb
    t[0] -= (t[7] & 0xffff) << 40; // reduce the lower 56-40=16 bits of 7th limb to 0th limb
    t[0] += (t[7] & 0xffffffffffff) << 8; // reduce the lower 56-8=48 bits of 7th limb to 0th limb

   /*
    * third substitution
    * Update carries of every temporaries limb, only keep the lower 48 bits of a[6] (384-56*6=48),
    * and do the reduction of higher bits of a[6]
    */

    // first, forward carry of a[4]=>a[5]=>a[6]
    t[5] += t[4] >> 56; // keep 56-bits of 4th limb, forwoard carry to 5th limb
    t[4] &= 0xffffffffffffff; // keep 56-bits of 4th limb
    t[6] += t[5] >> 56; // keep 56-bits of 5th limb, forwoard carry to 6th limb
    t[5] &= 0xffffffffffffff; // keep 56-bits of 5th limb

    // tmp*2^384 = tmp(2^16*t^2 + 2^40t - 2^32 + 1) mod p_384
    longlimb tmp = t[6] >> 48; // keep 48-bits of 6th limb
    t[6] &= 0xffffffffffff; // keep 48-bits of 6th limb

    t[3] += tmp >> 40; // reduce higher 56-40=16 bits of tmp to 3th limb
    t[2] += (tmp & 0xffffffffff) << 16; // reduce lower 56-16=40 bits of tmp to 2th limb
    t[2] += tmp >> 16; // reduce higher 56-16=40 bits of tmp to 2th limb
    t[1] += (tmp & 0xffff) << 40; // reduce lower 56-40=16 bits of tmp to 1th limb
    t[1] -= tmp >> 24; // reduce higher 56-24=32 bits of tmp to 1th limb
    t[0] -= (tmp & 0xffffff) << 32; // reduce lower 56-32=24 bits of tmp to 0th limb
    t[0] += tmp; // reduce the tmp to 0th limb

    // forward carry, t[0]=>t[1]=>t[2]=>t[3]=》t[4]=>t[5]=>t[6]
    t[1] += t[0] >> 56; // keep 56-bits of 0th limb, forward carry to 1th limb
    r[0] = t[0] & 0xffffffffffffff; // t[0] &= 0xffffffffffffff
    t[2] += t[1] >> 56; // keep 56-bits of 1th limb, forward carry to 2th limb
    r[1] = t[1] & 0xffffffffffffff; // t[1] &= 0xffffffffffffff
    t[3] += t[2] >> 56; // keep 56-bits of 2th limb, forward carry to 3th limb
    r[2] = t[2] & 0xffffffffffffff; // t[2] &= 0xffffffffffffff
    t[4] += t[3] >> 56; // keep 56-bits of 3th limb, forward carry to 4th limb
    r[3] = t[3] & 0xffffffffffffff; // t[3] &= 0xffffffffffffff
    t[5] += t[4] >> 56; // keep 56-bits of 4th limb, forward carry to 5th limb
    r[4] = t[4] & 0xffffffffffffff; // t[4] &= 0xffffffffffffff
    t[6] += t[5] >> 56; // keep 56-bits of 5th limb, forward carry to 6th limb
    r[5] = t[5] & 0xffffffffffffff; // t[5] &= 0xffffffffffffff
    r[6] = (limb)t[6]; // keep 48-bits of 6th limb
}

static void FelemSqrRdc(Felem64 r, const Felem64 a)
{
    __attribute__((aligned(32))) Felem128 t;

    FelemSquare(t, a);
    Felem128Reduce(r, t);
}

static void FelemMulRdc(Felem64 r, const Felem64 a, const Felem64 b)
{
    __attribute__((aligned(32))) Felem128 t;
    FelemMul(t, a, b);
    Felem128Reduce(r, t);
}

static void FelemCopy(Felem64 a, const Felem64 b)
{
    (void)memcpy_s(a, sizeof(Felem64), b, sizeof(Felem64));
}

static void FelemSub(Felem64 r, const Felem64 a, const Felem64 b)
{
    /*
     * To prevent underflow when doing subtraction, add 2^12*p to the minuend
     *         2^12*p = 2^12*(2^384 - 2^128 - 2^96 + 2^32 - 1)
     *                = 2^396 - 2^140 - 2^108 + 2^44 - 2^12
     *                = 2^336*(2^60 - 2^4) + 2^280*(2^60 - 2^4) + 2^224*(2^60 - 2^4) + 2^168*(2^60 - 2^4) +
     *                  2^112*(2^60 - 2^28 - 2^4) + 2^56*(2^60 - 2^52 - 2^4) + 2^0*(2^60 + 2^44 - 2^12)
     *
     */

    // 'upl' is short for 'Underflow Prevention Limb'
    limb upl0 = ((limb)1 << 60) + ((limb)1 << 44) - ((limb)1 << 12); // (1<<60)+(1<<44)-(1<<12)
    limb upl1 = ((limb)1 << 60) - ((limb)1 << 52) - ((limb)1 << 4);  // (1<<60)-(1<<52)-(1<<4)
    limb upl2 = ((limb)1 << 60) - ((limb)1 << 28) - ((limb)1 << 4);  // (1<<60)-(1<<28)-(1<<4)
    limb upl3 = ((limb)1 << 60) - ((limb)1 << 4);                    // (1<<60)-(1<<4)

    r[0] = upl0 + a[0] - b[0]; // 0 = 0 - 0. The left '0' and right '0' of operator '-' is 0th elemnt of a,b
    r[1] = upl1 + a[1] - b[1]; // 1 = 1 - 1
    r[2] = upl2 + a[2] - b[2]; // 2 = 2 - 2
    r[3] = upl3 + a[3] - b[3]; // 3 = 3 - 3
    r[4] = upl3 + a[4] - b[4]; // 4 = 4 - 4
    r[5] = upl3 + a[5] - b[5]; // 5 = 5 - 5
    r[6] = upl3 + a[6] - b[6]; // 6 = 6 - 6
}

static void Felem128Invert(Felem128 r, const Felem64 a)
{
   /*
    * r = -a
    * to prevent underflow, r = 2^12*p - a like 'FelemSub'
    */

    longlimb upl0 = ((longlimb)1 << 60) + ((longlimb)1 << 44) - ((longlimb)1 << 12); // (1<<60)+(1<<44)-(1<<12)
    longlimb upl1 = ((longlimb)1 << 60) - ((longlimb)1 << 52) - ((longlimb)1 << 4);  // (1<<60)-(1<<52)-(1<<4)
    longlimb upl2 = ((longlimb)1 << 60) - ((longlimb)1 << 28) - ((longlimb)1 << 4);  // (1<<60)-(1<<28)-(1<<4)
    longlimb upl3 = ((longlimb)1 << 60) - ((longlimb)1 << 4);                        // (1<<60)-(1<<4)

    r[0] = upl0 - a[0]; // 0 = -0
    r[1] = upl1 - a[1]; // 1 = -1
    r[2] = upl2 - a[2]; // 2 = -2
    r[3] = upl3 - a[3]; // 3 = -3
    r[4] = upl3 - a[4]; // 4 = -4
    r[5] = upl3 - a[5]; // 5 = -5
    r[6] = upl3 - a[6]; // 6 = -6
}

static void Felem128Sub(Felem128 r, const Felem128 a, const Felem64 b)
{
    // sames like 'FelemSub', add 2^16*p to the minuend to prevent underflow
        // 'upl' is short for 'Underflow Prevention Limb'
    longlimb upl0 = ((longlimb)1 << 64) + ((longlimb)1 << 48) - ((longlimb)1 << 16); // (1<<64)+(1<<48)-(1<<16)
    longlimb upl1 = ((longlimb)1 << 64) - ((longlimb)1 << 56) - ((longlimb)1 << 8);  // (1<<64)-(1<<56)-(1<<8)
    longlimb upl2 = ((longlimb)1 << 64) - ((longlimb)1 << 32) - ((longlimb)1 << 8);  // (1<<64)-(1<<32)-(1<<8)
    longlimb upl3 = ((longlimb)1 << 64) - ((longlimb)1 << 8);                        // (1<<64)-(1<<8)

    r[0] = upl0 + a[0] - b[0]; // 0 = 0 - 0
    r[1] = upl1 + a[1] - b[1]; // 1 = 1 - 1
    r[2] = upl2 + a[2] - b[2]; // 2 = 2 - 2
    r[3] = upl3 + a[3] - b[3]; // 3 = 3 - 3
    r[4] = upl3 + a[4] - b[4]; // 4 = 4 - 4
    r[5] = upl3 + a[5] - b[5]; // 5 = 5 - 5
    r[6] = upl3 + a[6] - b[6]; // 6 = 6 - 6
}

static void FelemAdd(Felem64 r, const Felem64 a, const Felem64 b)
{
    r[0] = a[0] + b[0]; // 0 = 0 + 0
    r[1] = a[1] + b[1]; // 1 = 1 + 1
    r[2] = a[2] + b[2]; // 2 = 2 + 2
    r[3] = a[3] + b[3]; // 3 = 3 + 3
    r[4] = a[4] + b[4]; // 4 = 4 + 4
    r[5] = a[5] + b[5]; // 5 = 5 + 5
    r[6] = a[6] + b[6]; // 6 = 6 + 6
}

static void FelemScalarMul(Felem64 r, limb k)
{
    r[0] *= k; // 0th limb multiply k
    r[1] *= k; // 1th limb multiply k
    r[2] *= k; // 2th limb multiply k
    r[3] *= k; // 3th limb multiply k
    r[4] *= k; // 4th limb multiply k
    r[5] *= k; // 5th limb multiply k
    r[6] *= k; // 6th limb multiply k
}

static void FelemPointCopy(FelemPoint *r, const FelemPoint *a)
{
    FelemCopy(r->x, a->x);
    FelemCopy(r->y, a->y);
    FelemCopy(r->z, a->z);
}

static void Felem2Flimbs(Flimbs r, const Felem64 a)
{
    r[0] = a[0] | ((a[1] & 0xff) << 56); // 0th limb's 56-bits and 1th limb's 8-bits
    r[1] = (a[1] >> 8) | ((a[2] & 0xffff) << 48); // 1th limb's 56-8=48 bits and 2th limb's 64-48=16 bits
    r[2] = (a[2] >> 16) | ((a[3] & 0xffffff) << 40); // 2th limb's 56-16=40 bits and 3th limb's 64-40=24 bits
    r[3] = (a[3] >> 24) | ((a[4] & 0xffffffff) << 32); // 3th limb's 56-24=32 bits and 3th limb's 64-32=32 bits
    r[4] = (a[4] >> 32) | ((a[5] & 0xffffffffff) << 24); // 4th limb's 56-32=24 bits and 5th limb's 64-24=40 bits
    r[5] = (a[5] >> 40) | (a[6] << 16); // 5th limb's 56-40=16 bits and 6th limb's 64-16=56 bits
}

static void Flimbs2Felem(Felem64 r, Flimbs a)
{
    r[0] = a[0] & 0x00ffffffffffffff; // 0th limb's 56 bits
    r[1] = (a[0] >> 56) | ((a[1] & 0x0000ffffffffffff) << 8); // 0th limb's 64-56=8 bits and 1th limb's 56-8=48 bits
    r[2] = (a[1] >> 48) | ((a[2] & 0x000000ffffffffff) << 16); // 1th limb's 64-48=16 bits and 2th limb's 56-16=40 bits
    r[3] = (a[2] >> 40) | ((a[3] & 0x00000000ffffffff) << 24); // 2th limb's 64-40=24 bits and 3th limb's 56-24=32 bits
    r[4] = (a[3] >> 32) | ((a[4] & 0x0000000000ffffff) << 32); // 3th limb's 64-32=32 bits and 4th limb's 56-32=24 bits
    r[5] = (a[4] >> 24) | ((a[5] & 0x000000000000ffff) << 40); // 4th limb's 64-24=40 bits and 5th limb's 56-40=16 bits
    r[6] = a[5] >> 16; // 5th limb's 56-16=48 bits to 6th
}

/* Felem64 a here is 0<a<2p, 
 * so it's just need to check if a ==0 || a == p
 */
static bool FelemIsZero(const Felem64 a)
{
    Flimbs t;
    Felem2Flimbs(t, a);
    limb zero = 0;
    limb p = 0;
    for (int i = 0; i < 6; i++) { // 6 is Flimb length
        zero |= t[i];
        p |= t[i] ^ g_poly[i];
    }
    return (zero == 0UL || p == 0UL);
}

static void P384ModInv(Flimbs r, Flimbs u, Flimbs v, Flimbs halfCeil,
                       void (*add)(Flimbs, Flimbs, Flimbs),
                       void (*sub)(Flimbs, Flimbs, Flimbs))
{
    __attribute__((aligned(32))) Flimbs x1 = {1};
    __attribute__((aligned(32))) Flimbs x2 = {0};

    while (!FlimbsIsOne(u) && !FlimbsIsOne(v)) {
        while ((u[0] & 0x1) == 0) {
            FlimbsRshift1(u);
            if ((x1[0] & 0x1) == 0) {
                FlimbsRshift1(x1);
            } else {
                FlimbsRshift1(x1);
                add(x1, x1, halfCeil);
            }
        }
        while ((v[0] & 0x1) == 0) {
            FlimbsRshift1(v);
            if ((x2[0] & 0x1) == 0) {
                FlimbsRshift1(x2);
            } else {
                FlimbsRshift1(x2);
                add(x2, x2, halfCeil);
            }
        }
        if (FlimbsCmp(u, v) >= 0) {
            sub(u, u, v);
            sub(x1, x1, x2);
        } else {
            sub(v, v, u);
            sub(x2, x2, x1);
        }
    }
    if (FlimbsIsOne(u)) {
        (void)memcpy_s(r, sizeof(Flimbs), x1, sizeof(Flimbs));
    } else {
        (void)memcpy_s(r, sizeof(Flimbs), x2, sizeof(Flimbs));
    }
}

static void FelemInv(Felem64 r, const Felem64 a)
{
    Flimbs re;
    __attribute__((aligned(32))) Flimbs u;
    __attribute__((aligned(32))) Flimbs v;
    Felem2Flimbs(u, a);
    (void)memcpy_s(v, sizeof(Flimbs), g_poly, sizeof(Flimbs));
    P384ModInv(re, u, v, g_polyHalfCeil, FlimbsAdd, FlimbsSub);
    Flimbs2Felem(r, re);
}

/*
 * point double
 * Algorithm reference: http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
 * Number of field operations: 3M + 5S + 8add + 1*3 + 1*4 + 2*8.
 *      delta = Z^2
 *      gamma = Y^2
 *      beta = X * gamma
 *      alpha = 3 * (X - delta) * (X + delta)
 *      X' = alpha^2 - 8 * beta
 *      Z' = (Y + Z)^2 - gamma - delta
 *      Y' = alpha * (4 * beta - X') - 8 * gamma^2
 */
static void FelemPointDbl(FelemPoint *r, FelemPoint *a)
{
    FelemPoint t;
    FelemPointCopy(&t, a);
    Felem64 delta, gamma, beta, alpha;
    Felem64 t1, t2, t3;
    Felem128 lt;

    FelemSqrRdc(delta, t.z);
    FelemSqrRdc(gamma, t.y);
    FelemMulRdc(beta, t.x, gamma);

    // alpha = 3 * (X - delta) * (X + delta)
    FelemSub(t1, t.x, delta);
    FelemAdd(t2, t.x, delta);
    FelemScalarMul(t1, 3); // 3 * (X - delta)
    FelemMulRdc(alpha, t1, t2);

    // X' = alpha^2 - 8 * beta
    FelemSquare(lt, alpha);
    FelemCopy(t3, beta);
    FelemScalarMul(t3, 8); // 8*beta
    Felem128Sub(lt, lt, t3);
    Felem128Reduce(r->x, lt);

    // Z' = (Y + Z)^2 - gamma - delta
    FelemAdd(t3, t.y, t.z);
    FelemSquare(lt, t3);
    FelemAdd(t2, gamma, delta);
    Felem128Sub(lt, lt, t2);
    Felem128Reduce(r->z, lt);

    // Y' = alpha * (4 * beta - X') - 8 * gamma^2
    FelemScalarMul(beta, 4); // 4*beta
    FelemSub(beta, beta, r->x);
    FelemMul(lt, alpha, beta);
    FelemSqrRdc(t1, gamma);
    FelemScalarMul(t1, 8); // 8 * gamma^2
    Felem128Sub(lt, lt, t1);
    Felem128Reduce(r->y, lt);
}

/*
 * point add
 * Algorithm reference: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
 * Number of field operations: 11M + 5S + 9add + 4*2.
 *              Z1Z1 = Z1^2
 *              Z2Z2 = Z2^2
 *              U1 = X1*Z2Z2
 *              U2 = X2*Z1Z1
 *              S1 = Y1*Z2*Z2Z2
 *              S2 = Y2*Z1*Z1Z1
 *              H = U2-U1
 *              I = (2*H)^2
 *              J = H*I
 *              r = 2*(S2-S1)
 *              V = U1*I
 *              X3 = r^2-J-2*V
 *              Y3 = r*(V-X3)-2*S1*J
 *              Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
 */
static void FelemPointAdd(FelemPoint *r, FelemPoint *a, const FelemPoint *b)
{
    Felem64 z11, z22, u1, u2, s1, s2, i, j, rr, t;
    Felem128 lt;
    FelemPoint tmp;
    bool z10 = FelemIsZero(a->z);
    bool z20 = FelemIsZero(b->z);
    bool h0 = false;
    bool r0 = false;

    FelemSqrRdc(z11, a->z);
    FelemSqrRdc(z22, b->z);

    // t = (Z1+Z2)^2-Z1Z1-Z2Z2
    FelemAdd(t, a->z, b->z);
    FelemSquare(lt, t);
    Felem128Sub(lt, lt, z11);
    Felem128Sub(lt, lt, z22);
    Felem128Reduce(t, lt);
    // U2, U1
    FelemMulRdc(u1, a->x, z22);
    FelemMul(lt, b->x, z11);
    // H = U2-U1
    Felem128Sub(lt, lt, u1);
    Felem128Reduce(u2, lt);
    h0 = FelemIsZero(u2);
    // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
    FelemMulRdc(tmp.z, t, u2);

    // I = (2*H)^2
    // J = H*I
    FelemCopy(i, u2);
    FelemScalarMul(i, 2); // 2*H
    FelemSqrRdc(i, i);
    FelemMulRdc(j, u2, i);

    // r = 2*(S2-S1)
    FelemMulRdc(s1, b->z, z22);
    FelemMulRdc(s1, s1, a->y);
    FelemMulRdc(s2, a->z, z11);
    FelemMul(lt, s2, b->y);
    Felem128Sub(lt, lt, s1);
    Felem128Reduce(rr, lt);
    r0 = FelemIsZero(rr);
    FelemScalarMul(rr, 2); // 2*(S2-S1)
    if (h0 && r0 && !z10 && !z20) {
        FelemPointDbl(r, a);
        return;
    }
    // V = U1*I
    // X3 = r^2-J-2*V
    FelemMulRdc(z11, u1, i);
    FelemCopy(z22, z11);
    FelemScalarMul(z22, 2); // 2*V
    FelemSquare(lt, rr);
    Felem128Sub(lt, lt, j);
    Felem128Sub(lt, lt, z22);
    Felem128Reduce(tmp.x, lt);

    // Y3 = r*(V-X3)-2*S1*J
    FelemScalarMul(s1, 2); // 2*S1*J
    FelemMulRdc(s1, s1, j);
    FelemSub(z11, z11, tmp.x);
    FelemMul(lt, z11, rr);
    Felem128Sub(lt, lt, s1);
    Felem128Reduce(tmp.y, lt);

    FelemPointCopy(r, &tmp);
}

static int32_t PreFelemPointMul(ECC_Para *para, FelemPoint *r, const BN_BigNum *k, const FelemPoint *pt)
{
    (void)para;

    // use wNAF
    ReCodeData *recodeK = ECC_ReCodeK(k, PRE_COMPUTE_WINDOW);
    if (recodeK == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int8_t offset = NUMTOOFFSET(recodeK->num[0]);
    FelemPointCopy(r, &pt[offset]);
    uint32_t w = recodeK->wide[0];
    while (w > 0) {
        FelemPointDbl(r, r);
        w--;
    }
    for (uint32_t i = 1; i < recodeK->size; i++) {
        offset = NUMTOOFFSET(recodeK->num[i]);
        FelemPointAdd(r, r, &pt[offset]);
        w = recodeK->wide[i];
        // r *= 2^w
        while (w > 0) {
            FelemPointDbl(r, r);
            w--;
        }
    }

    ECC_ReCodeFree(recodeK);
    return CRYPT_SUCCESS;
}

static int32_t P384PrecomputePointMul(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const FelemPoint *pt)
{
    FelemPoint t = {{0}, {0}, {0}};
    int32_t ret = PreFelemPointMul(para, &t, k, pt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    Felem2EccPoint(para, r, &t);
    return CRYPT_SUCCESS;
}

static int32_t P384PrecomputeFelemPoint(FelemPoint *precompute, const ECC_Point *pt)
{
    int32_t ret;

    FelemPoint p2;
    // 1*pt
    GOTO_ERR_IF_EX(BN2Felem64(precompute[0].x, &pt->x), ret);
    GOTO_ERR_IF_EX(BN2Felem64(precompute[0].y, &pt->y), ret);
    if (BN_IsOne(&pt->z)) {
        (void)memset_s(precompute[0].z, sizeof(Felem64), 0, sizeof(Felem64));
        precompute[0].z[0] = 1;
    } else {
        GOTO_ERR_IF_EX(BN2Felem64(precompute[0].z, &pt->z), ret);
    }

    // 2*pt
    FelemPointDbl(&p2, &precompute[0]);
    // 3*pt ~ 15*pt
    for (uint32_t i = 1; i < (WINDOW_TABLE_SIZE >> 1); i++) {
        FelemPointAdd(&precompute[i], &precompute[i - 1], &p2);
    }

    // -1*pt ~ -15*pt
    for (uint32_t i = (WINDOW_TABLE_SIZE >> 1); i < WINDOW_TABLE_SIZE; i++) {
        Felem128 tmp = {0};
        FelemPointCopy(&precompute[i], &precompute[i - (WINDOW_TABLE_SIZE >> 1)]);
        Felem128Invert(tmp, precompute[i].y);
        Felem128Reduce(precompute[i].y, tmp); // make sure limbs of  FelemPoint <= 56bits
    }
ERR:
    return ret;
}

/*
 * r = k1*g + k2*pt
 */
int32_t ECP384_PointMulAdd(ECC_Para *para, ECC_Point *r,
                           const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt)
{
    int32_t ret = ECP_PointMulAddParaCheck(para, r, k1, k2, pt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    FelemPoint t1 = {{0}, {0}, {0}};
    FelemPoint t2 = {{0}, {0}, {0}};
    FelemPoint *t = NULL;
    bool k1Zero = BN_IsZero(k1);
    bool k2Zero = BN_IsZero(k2);

    if (!k1Zero) {
        ret = PreFelemPointMul(para, &t1, k1, g_precomputedG);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    if (!k2Zero) {
        // r = k *! pt
        // precompute 1~15,-1~-15*pt
        FelemPoint precompute[WINDOW_TABLE_SIZE];
        ret = P384PrecomputeFelemPoint(precompute, pt);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        ret = PreFelemPointMul(para, &t2, k2, precompute);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    if (k1Zero || k2Zero) {
        if (k1Zero && k2Zero) {
            return BN_Zeroize(&r->z);
        }
        if (k1Zero) {
            t = &t2;
        } else {
            t = &t1;
        }
    } else {
        t = &t2;
        FelemPointAdd(t, t, &t1);
    }
    Felem2EccPoint(para, r, t);
    return CRYPT_SUCCESS;
}

int32_t ECP384_PointMul(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt)
{
    if (para == NULL || r == NULL || k == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (((pt != NULL) && (para->id != pt->id)) || (para->id != r->id)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (BN_IsZero(k)) {
        return BN_Zeroize(&r->z);
    }

    if (pt == NULL) {
        if (k == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
            return CRYPT_NULL_INPUT;
        }

        // r = k * G
        return P384PrecomputePointMul(para, r, k, g_precomputedG);
    } else {
        // r = k * pt
        // precompute 1~15,-1~-15*pt
        FelemPoint precompute[WINDOW_TABLE_SIZE];
        int32_t ret = P384PrecomputeFelemPoint(precompute, pt);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }

        return P384PrecomputePointMul(para, r, k, precompute);
    }

    return CRYPT_SUCCESS;
}

// Convert Jacobian coordinates to affine coordinates
int32_t ECP384_Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *pt)
{
    int32_t ret;
    FelemPoint t;
    Felem64 zinv = {0};
    Felem64 zinv2 = {0};

    // check pt is at infinity.
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    // pt is already a affine point.
    if (BN_IsOne(&pt->z)) {
        return ECP_PointCopy(para, r, pt);
    }

    EccPoint2Felem(&t, pt);

    // X' = X/Z^2, Y' = Y/Z^3
    FelemInv(zinv, t.z);
    FelemSqrRdc(zinv2, zinv); // z^(-2)
    FelemMulRdc(t.x, t.x, zinv2);
    FelemMulRdc(zinv2, zinv2, zinv); // z^(-3)
    FelemMulRdc(t.y, t.y, zinv2);

    GOTO_ERR_IF(Felem64ToBn(&r->x, t.x), ret);
    FlimbsSub(r->x.data, r->x.data, g_poly);
    BN_FixSize(&r->x);
    GOTO_ERR_IF(Felem64ToBn(&r->y, t.y), ret);
    FlimbsSub(r->y.data, r->y.data, g_poly);
    BN_FixSize(&r->y);
    GOTO_ERR_IF(BN_SetLimb(&r->z, 1), ret);

ERR:
    return ret;
}

// r = a^(-1) mod para->n
int32_t ECP384_ModOrderInv(const ECC_Para *para, BN_BigNum *r, const BN_BigNum *a)
{
    (void)para;
    int32_t ret;
    if (BN_IsZero(a)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_INVERSE_INPUT_ZERO);
        return CRYPT_ECC_INVERSE_INPUT_ZERO;
    }
    if (BN_Cmp(para->n, a) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_NO_INVERSE);
        return CRYPT_BN_ERR_NO_INVERSE;
    }
    Flimbs re;
    __attribute__((aligned(32))) Flimbs u = {0};
    __attribute__((aligned(32))) Flimbs v = {0};

    uint32_t l = sizeof(Flimbs) / sizeof(limb);
    (void)BN_Bn2U64Array(a, u, &l);
    (void)memcpy_s(v, sizeof(v), g_order, sizeof(v));
    P384ModInv(re, u, v, g_orderHalfCeil, FlimbsAddModOrd, FlimbsSubModOrd);
    GOTO_ERR_IF(BN_U64Array2Bn(r, re, l), ret);

ERR:
    return ret;
}

#endif /* defined(HITLS_CRYPTO_CURVE_NISTP384) && defined(HITLS_CRYPTO_NIST_USE_ACCEL) */

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
#if defined(HITLS_CRYPTO_CURVE_NISTP256) && defined(HITLS_CRYPTO_NIST_USE_ACCEL)

#include <stdbool.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_util_internal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_bn.h"
#include "crypt_ecc.h"
#include "ecc_local.h"
#include "ecc_utils.h"

#ifndef HITLS_INT128
#error "This nistp256 implementation require the compiler support 128-bits integer."
#endif

/* field element definition */
#define FELEM_BITS      256
#define FELEM_BYTES     32
#define LIMB_BITS       (sizeof(uint128_t) << 3)
#define LIMB_NUM        4
#define BASE_BITS       64
/* The pre-calculation table of the G table has 16 points. */
#define TABLE_G_SIZE    16
/* The pre-calculation table of the P table has 17 points. */
#define TABLE_P_SIZE    17

/*
 * Field elements, stored as arrays, all represented in little endian.
 * Each element of the array is called a digit. Each digit represents an extended 2 ^ 64-bit.
 * That is, Felem can be expressed as:
 * f_0 + f_1 * 2^64 + f_2 * 2^128 + f_3 * 2^192
 * LongFelem is used to store the result of multiplication of field elements and is twice the width of Felem.
 * Point is a point represented as a Jacobian coordinate
 */
typedef struct {
    uint128_t data[LIMB_NUM];
} Felem;

typedef struct {
    uint128_t data[LIMB_NUM * 2];
} LongFelem;

typedef struct {
    Felem x;
    Felem y;
    Felem z;
} Point;

/* ------------------------------------------------------------ */
/* ECP256 field order p. The value is 2^256 - 2^224 + 2^192 + 2^96 - 1, little endian */
static const Felem FIELD_ORDER = {
    {0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001}
};

/*
 * Pre-computation table of the base point G, which contains the (X, Y, Z) coordinates of k*G
 *
 * PRE_MUL_G divides all bits into four equal parts.
 * index       corresponding bit                         value of k
 *   0              0 0 0 0                       0     + 0     + 0     + 0
 *   1              0 0 0 1                       0     + 0     + 0     + 1
 *   2              0 0 1 0                       0     + 0     + 2^64  + 0
 *   3              0 0 1 1                       0     + 0     + 2^64  + 1
 *   4              0 1 0 0                       0     + 2^128 + 0     + 0
 *   5              0 1 0 1                       0     + 2^128 + 0     + 1
 *   6              0 1 1 0                       0     + 2^128 + 2^64  + 0
 *   7              0 1 1 1                       0     + 2^128 + 2^64  + 1
 *   8              1 0 0 0                       2^192 + 0     + 0     + 0
 *   9              1 0 0 1                       2^192 + 0     + 0     + 1
 *  10              1 0 1 0                       2^192 + 0     + 2^64  + 0
 *  11              1 0 1 1                       2^192 + 0     + 2^64  + 1
 *  12              1 1 0 0                       2^192 + 2^128 + 0     + 0
 *  13              1 1 0 1                       2^192 + 2^128 + 0     + 1
 *  14              1 1 1 0                       2^192 + 2^128 + 2^64  + 0
 *  15              1 1 1 1                       2^192 + 2^128 + 2^64  + 1
 *
 */
static const Point PRE_MUL_G[TABLE_G_SIZE] = {
    {
        {{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}},
        {{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}},
        {{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247}},
        {{0xcbb6406837bf51f5, 0x2bce33576b315ece, 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x90e75cb48e14db63, 0x29493baaad651f7e, 0x8492592e326e25de, 0x0fa822bc2811aaa5}},
        {{0xe41124545f462ee7, 0x34b1a65050fe82f5, 0x6f4ad4bcb3df188b, 0xbff44ae8f5dba80d}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x93391ce2097992af, 0xe96c98fd0d35f1fa, 0xb257c0de95e02789, 0x300a4bbc89d6726f}},
        {{0xaa54a291c08127a0, 0x5bb1eeada9d806a5, 0x7f1ddb25ff1e3c6f, 0x72aac7e0d09b4644}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x57c84fc9d789bd85, 0xfc35ff7dc297eac3, 0xfb982fd588c6766e, 0x447d739beedb5e67}},
        {{0x0c7e33c972e25b32, 0x3d349b95a7fae500, 0xe12e9d953a4aaff7, 0x2d4825ab834131ee}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x13949c932a1d367f, 0xef7fbd2b1a0a11b7, 0xddc6068bb91dfc60, 0xef9519328a9c72ff}},
        {{0x196035a77376d8a8, 0x23183b0895ca1740, 0xc1ee9807022c219c, 0x611e9fc37dbb2c9b}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0xcae2b1920b57f4bc, 0x2936df5ec6c9bc36, 0x7dea6482e11238bf, 0x550663797b51f5d8}},
        {{0x44ffe216348a964c, 0x9fb3d576dbdefbe1, 0x0afa40018d9d50e5, 0x157164848aecb851}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0xe48ecafffc5cde01, 0x7ccd84e70d715f26, 0xa2e8f483f43e4391, 0xeb5d7745b21141ea}},
        {{0xcac917e2731a3479, 0x85f22cfe2844b645, 0x0990e6a158006cee, 0xeafd72ebdbecc17b}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x6cf20ffb313728be, 0x96439591a3c6b94a, 0x2736ff8344315fc5, 0xa6d39677a7849276}},
        {{0xf2bab833c357f5f4, 0x824a920c2284059b, 0x66b8babd2d27ecdf, 0x674f84749b0b8816}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x2df48c04677c8a3e, 0x74e02f080203a56b, 0x31855f7db8c7fedb, 0x4e769e7672c9ddad}},
        {{0xa4c36165b824bbb0, 0xfb9ae16f3b9122a5, 0x1ec0057206947281, 0x42b99082de830663}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x6ef95150dda868b9, 0xd1f89e799c0ce131, 0x7fdc1ca008a1c478, 0x78878ef61c6ce04d}},
        {{0x9c62b9121fe0d976, 0x6ace570ebde08d4f, 0xde53142c12309def, 0xb6cb3f5d7b72c321}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x7f991ed2c31a3573, 0x5b82dd5bd54fb496, 0x595c5220812ffcae, 0x0c88bc4d716b1287}},
        {{0x3a57bf635f48aca8, 0x7c8181f4df2564f3, 0x18d1b5b39c04e6aa, 0xdd5ddea3f3901dc6}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0xe96a79fb3e72ad0c, 0x43a0a28c42ba792f, 0xefe0a423083e49f3, 0x68f344af6b317466}},
        {{0xcdfe17db3fb24d4a, 0x668bfc2271f5c626, 0x604ed93c24d67ff3, 0x31b9c405f8540a20}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0xd36b4789a2582e7f, 0x0d1a10144ec39c28, 0x663c62c3edbad7a0, 0x4052bf4b6f461db9}},
        {{0x235a27c3188d25eb, 0xe724f33999bfcc5b, 0x862be6bd71d70cc8, 0xfecf4d5190b0fc61}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x74346c10a1d4cfac, 0xafdf5cc08526a7a4, 0x123202a8f62bff7a, 0x1eddbae2c802e41a}},
        {{0x8fa0af2dd603f844, 0x36e06b7e4c701917, 0x0c45f45273db33a0, 0x43104d86560ebcfc}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x9615b5110d1d78e5, 0x66b0de3225c4744b, 0x0a4a46fb6aaf363a, 0xb48e26b484f7a21c}},
        {{0x06ebb0f621a01b2d, 0xc004e4048b7b0f98, 0x64131bcdfed6f668, 0xfac015404d4d3dab}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }
};

/*
 * Pre-computation table of the base point G, which contains the (X, Y, Z) coordinates of k*G
 *
 * PRE_MUL_G2[] = PRE_MUL_G[] * 2^32
 * index       corresponding bit                       value of k
 *   0              0 0 0 0                    0     + 0     + 0     + 0
 *   1              0 0 0 1                    0     + 0     + 0     + 2^32
 *   2              0 0 1 0                    0     + 0     + 2^96  + 0
 *   3              0 0 1 1                    0     + 0     + 2^96  + 2^32
 *   4              0 1 0 0                    0     + 2^160 + 0     + 0
 *   5              0 1 0 1                    0     + 2^160 + 0     + 2^32
 *   6              0 1 1 0                    0     + 2^160 + 2^96  + 0
 *   7              0 1 1 1                    0     + 2^160 + 2^96  + 2^32
 *   8              1 0 0 0                    2^224 + 0     + 0     + 0
 *   9              1 0 0 1                    2^224 + 0     + 0     + 2^32
 *  10              1 0 1 0                    2^224 + 0     + 2^96  + 0
 *  11              1 0 1 1                    2^224 + 0     + 2^96  + 2^32
 *  12              1 1 0 0                    2^224 + 2^160 + 0     + 0
 *  13              1 1 0 1                    2^224 + 2^160 + 0     + 2^32
 *  14              1 1 1 0                    2^224 + 2^160 + 2^96  + 0
 *  15              1 1 1 1                    2^224 + 2^160 + 2^96  + 2^32
 */
static const Point PRE_MUL_G2[TABLE_G_SIZE] = {
    {
        {{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}},
        {{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}},
        {{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x3a5a9e22185a5943, 0x1ab919365c65dfb6, 0x21656b32262c71da, 0x7fe36b40af22af89}},
        {{0xd50d152c699ca101, 0x74b3d5867b8af212, 0x9f09f40407dca6f1, 0xe697d45825b63624}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0xa84aa9397512218e, 0xe9a521b074ca0141, 0x57880b3a18a2e902, 0x4a5b506612a677a6}},
        {{0x0beada7a4c4f3840, 0x626db15419e26d9d, 0xc42604fbe1627d40, 0xeb13461ceac089f1}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0xf9faed0927a43281, 0x5e52c4144103ecbc, 0xc342967aa815c857, 0x0781b8291c6a220a}},
        {{0x5a8343ceeac55f80, 0x88f80eeee54a05e3, 0x97b2a14f12916434, 0x690cde8df0151593}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0xaee9c75df7f82f2a, 0x9e4c35874afdf43a, 0xf5622df437371326, 0x8a535f566ec73617}},
        {{0xc5f9a0ac223094b7, 0xcde533864c8c7669, 0x37e02819085a92bf, 0x0455c08468b08bd7}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x0c0a6e2c9477b5d9, 0xf9a4bf62876dc444, 0x5050a949b6cdc279, 0x06bada7ab77f8276}},
        {{0xc8b4aed1ea48dac9, 0xdebd8a4b7ea1070f, 0x427d49101366eb70, 0x5b476dfd0e6cb18a}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x7c5c3e44278c340a, 0x4d54606812d66f3b, 0x29a751b1ae23c5d8, 0x3e29864e8a2ec908}},
        {{0x142d2a6626dbb850, 0xad1744c4765bd780, 0x1f150e68e322d1ed, 0x239b90ea3dc31e7e}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x78c416527a53322a, 0x305dde6709776f8e, 0xdbcab759f8862ed4, 0x820f4dd949f72ff7}},
        {{0x6cc544a62b5debd4, 0x75be5d937b4e8cc4, 0x1b481b1b215c14d3, 0x140406ec783a05ec}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x6a703f10e895df07, 0xfd75f3fa01876bd8, 0xeb5b06e70ce08ffe, 0x68f6b8542783dfee}},
        {{0x90c76f8a78712655, 0xcf5293d2f310bf7f, 0xfbc8044dfda45028, 0xcbe1feba92e40ce6}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0xe998ceea4396e4c1, 0xfc82ef0b6acea274, 0x230f729f2250e927, 0xd0b2f94d2f420109}},
        {{0x4305adddb38d4966, 0x10b838f8624c3b45, 0x7db2636658954e7a, 0x971459828b0719e5}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x4bd6b72623369fc9, 0x57f2929e53d0b876, 0xc2d5cba4f2340687, 0x961610004a866aba}},
        {{0x49997bcd2e407a5e, 0x69ab197d92ddcb24, 0x2cf1f2438fe5131c, 0x7acb9fadcee75e44}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x254e839423d2d4c0, 0xf57f0c917aea685b, 0xa60d880f6f75aaea, 0x24eb9acca333bf5b}},
        {{0xe3de4ccb1cda5dea, 0xfeef9341c51a6b4f, 0x743125f88bac4c4d, 0x69f891c5acd079cc}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0xeee44b35702476b5, 0x7ed031a0e45c2258, 0xb422d1e7bd6f8514, 0xe51f547c5972a107}},
        {{0xa25bcd6fc9cf343d, 0x8ca922ee097c184e, 0xa62f98b3a9fe9a06, 0x1c309a2b25bb1387}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x9295dbeb1967c459, 0xb00148833472c98e, 0xc504977708011828, 0x20b87b8aa2c4e503}},
        {{0x3063175de057c277, 0x1bd539338fe582dd, 0x0d11adef5f69a044, 0xf5c6fa49919776be}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x8c944e760fd59e11, 0x3876cba1102fad5f, 0xa454c3fad83faa56, 0x1ed7d1b9332010b9}},
        {{0xa1011a270024b889, 0x05e4d0dcac0cd344, 0x52b520f0eb6a2a24, 0x3a2b03f03217257a}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0xf20fc2afdf1d043d, 0xf330240db58d5a62, 0xfc7d229ca0058c3b, 0x15fee545c78dd9f6}},
        {{0x501e82885bc98cda, 0x41ef80e5d046ac04, 0x557d9f49461210fb, 0x4ab5b6b2b8753f81}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }
};

/* --------------------------helper function-------------------------- */
/*
 * Convert big-endian byte stream to Felem
 */
static inline void Bin2Felem(Felem *out, const uint8_t in[FELEM_BYTES])
{
    // Write the input data to 128-bit digits every 64 bits.
    out->data[3] = (uint128_t)Uint64FromBeBytes(in);        // Index 3 read 0~7   bytes
    out->data[2] = (uint128_t)Uint64FromBeBytes(in + 8);    // Index 2 read 8~15  bytes
    out->data[1] = (uint128_t)Uint64FromBeBytes(in + 16);   // Index 1 read 16~23 bytes
    out->data[0] = (uint128_t)Uint64FromBeBytes(in + 24);   // Index 0 read 24~31 bytes
}

/*
 * Convert Felem to big-endian byte stream
 * Input:
 *      in[] < 2^64
 * Output:
 *      out length is 32
 */
static inline void Felem2Bin(uint8_t out[FELEM_BYTES], const Felem *in)
{
    Uint64ToBeBytes((uint64_t)in->data[3], out);          // Index 3 write 0~7   bytes
    Uint64ToBeBytes((uint64_t)in->data[2], out + 8);      // Index 2 write 8~15  bytes
    Uint64ToBeBytes((uint64_t)in->data[1], out + 16);     // Index 1 write 16~23 bytes
    Uint64ToBeBytes((uint64_t)in->data[0], out + 24);     // Index 0 write 24~31 bytes
}

/*
 * Convert BN to Felem
 * Output:
 *      out[] < 2^64
 */
static int32_t BN2Felem(Felem *out, const BN_BigNum *in)
{
    int32_t ret;
    uint8_t bin[FELEM_BYTES];
    uint32_t len = FELEM_BYTES;

    GOTO_ERR_IF(BN_Bn2Bin(in, bin, &len), ret);

    for (uint32_t i = 0; i < FELEM_BYTES; ++i) {
        bin[FELEM_BYTES - 1 - i] = i < len ? bin[len - 1 - i] : 0;
    }

    Bin2Felem(out, bin);
ERR:
    return ret;
}

/*
 * Convert Felem to BN
 * Input:
 *      in[] < 2^64
 */
static int32_t Felem2BN(BN_BigNum *out, const Felem *in)
{
    int32_t ret;
    uint8_t bin[FELEM_BYTES];

    Felem2Bin(bin, in);

    GOTO_ERR_IF(BN_Bin2Bn(out, bin, FELEM_BYTES), ret);
ERR:
    return ret;
}

/* ---------------------------field operation--------------------------- */
/*
 * Assignment
 */
static inline void FelemAssign(Felem *out, const Felem *in)
{
    out->data[0] = in->data[0];     // out->data[0] get the value
    out->data[1] = in->data[1];     // out->data[1] get the value
    out->data[2] = in->data[2];     // out->data[2] get the value
    out->data[3] = in->data[3];     // out->data[3] get the value
}

/*
 * Copy each digit by mask. If the corresponding bit is 1, copy it. If the corresponding bit is 0, retain it.
 */
static inline void FelemAssignWithMask(Felem *out, const Felem *in, const uint128_t mask)
{
    uint128_t rmask = ~mask;
    // The value of out->data[0] is changed or remains unchanged.
    out->data[0] = (in->data[0] & mask) | (out->data[0] & rmask);
    // The value of out->data[1] is changed or remains unchanged.
    out->data[1] = (in->data[1] & mask) | (out->data[1] & rmask);
    // The value of out->data[2] is changed or remains unchanged.
    out->data[2] = (in->data[2] & mask) | (out->data[2] & rmask);
    // The value of out->data[3] is changed or remains unchanged.
    out->data[3] = (in->data[3] & mask) | (out->data[3] & rmask);
}

/*
 * Set the lowest digit
 */
static inline void FelemSetLimb(Felem *out, const uint128_t in)
{
    out->data[0] = in;  // out->data[0] get the value
    out->data[1] = 0;   // out->data[1] clear to 0
    out->data[2] = 0;   // out->data[2] clear to 0
    out->data[3] = 0;   // out->data[3] clear to 0
}

/*
 * Zero judgment: input less than 2 ^ 256, only 0 and p need to be judged.
 * Input:
 *      in[] < 2^64
 */
static inline uint128_t FelemIsZero(const Felem *in)
{
    uint128_t isZero, isP;

    // Check whether digits 0, 1, 2, and 3 are all 0.
    isZero = in->data[0] | in->data[1] | in->data[2] | in->data[3];
    isZero -= 1;  // If in == 0, the most significant bit is 1.

    // Determine that in is equal to the field order.
    isP = (in->data[0] ^ FIELD_ORDER.data[0]) |   // Determine whether the digits 0 is equal to the order
          (in->data[1] ^ FIELD_ORDER.data[1]) |   // Determine whether the digits 1 is equal to the order
          (in->data[2] ^ FIELD_ORDER.data[2]) |   // Determine whether the digits 2 is equal to the order
          (in->data[3] ^ FIELD_ORDER.data[3]);    // Determine whether the digits 3 is equal to the order
    isP -= 1;  // If in == p, the most significant bit is 1.

    return (isZero | isP) >> (LIMB_BITS - 1);
}

/*
 * Obtain the bit string whose length is len at idx in Felem.
 * Input:
 *      in[] < 2^64
 *      0 < len <= 64
 */
static uint64_t FelemGetBits(const Felem *in, int32_t idx, uint32_t len)
{
    uint128_t ret;
    uint32_t lower, upper;
    uint64_t mask;

    lower = (uint32_t)idx;
    // When 0 <= lower < 256, the most significant bit is 1, obtain the most significant bit by right shifted by 31 bits
    mask = (uint64_t)0 - ((~lower & (lower - 256)) >> 31);
    ret = (uint64_t)in->data[(lower / BASE_BITS) & mask] & mask;

    upper = (uint32_t)idx + BASE_BITS;  // next unary block
    // When 0 <= upper < 256, the most significant bit is 1, obtain the most significant bit by right shifted by 31 bits
    mask = (uint64_t)0 - ((~upper & (upper - 256)) >> 31);
    ret |= (uint128_t)((uint64_t)in->data[(upper / BASE_BITS) & mask] & mask) << BASE_BITS;

    // Take the lower six bits, that is, mod 64, regardless of the positive and negative values of "lower".
    ret >>= lower & (BASE_BITS - 1);
    ret &= ((uint64_t)1 << len) - 1;  // All 1-bit string with the len length

    return (uint64_t)ret;
}

/*
 * Field element reduction, retains the base bit (64 bits) of each digit in the 4-ary Felem, and reduce the high bit.
 * Should be called before modular multiplication, modulus square, or modulus
 * Input:
 *      in[] < 2^127
 * Output:
 *      out[] < 2^64
 */
static void FelemReduce(Felem *out, const Felem *in)
{
    uint128_t *po = out->data;
    const uint128_t *pi = in->data;
    const uint128_t borrow = (uint128_t)1 << 96;    // 2 ^ 96 borrowed from low to high
    const uint128_t lend = (uint128_t)1 << 32;      // 2 ^ 32 lent from high to low
    uint128_t carryLimb, carryLimbTotal;

    // Process the carry of each digit first: 0 -> 1 -> 2 -> 3
    po[1] = pi[1] + (pi[0] >> BASE_BITS);   // po[1] takes the input value and adds the carry of digit 0.
    po[2] = pi[2] + (po[1] >> BASE_BITS);   // po[2] takes the input value and adds the carry of digit 1.
    po[3] = pi[3] + (po[2] >> BASE_BITS);   // po[3] takes the input value and adds the carry of digit 2.

    po[0] = (uint64_t)pi[0];                // po[0] takes the basic digit.
    po[1] = (uint64_t)po[1];                // po[1] takes the basic digit.
    po[2] = (uint64_t)po[2];                // po[2] takes the basic digit.

    // Now reduce the highest digit. Only need to reduce the carry of the highest digit three times.
    // Note the carry bit of out[3] as carryLimb.
    // It can be known from the equation:
    // carryLimb * 2^256 = carryLimb * (2^224 - 2^192 - 2^96 + 1) (mod 2^256 - 2^224 + 2^192 + 2^96 - 1)
    // The part of carryLimb * (2^224 - 2^192)  needs to be placed in out[3]
    //
    // First reduction: po[3] < 2^128 ---> po[3] < 2^96
    // Assume that      po[3] = 0x ffffffffffffffff ffffffffffffffff
    //      0x 0000000000000000 ffffffffffffffff    -> po[3] basic digit(unit)
    // +    0x 00000000ffffffff ffffffff00000000    -> carryLimb * 2^32
    // -    0x 0000000000000000 ffffffffffffffff    -> carryLimb
    // -----------------------------------------
    // =    0x 00000000ffffffff ffffffff00000000    -> po[3] <= 2^96 - 2^32 < 2^96
    // Second reduction: po[3] < 2^96 ---> po[3] < 2^65 - 2^33
    // Assume that       po[3] = 0x 00000000ffffffff ffffffffffffffff
    //      0x 0000000000000000 ffffffffffffffff
    // +    0x 0000000000000000 ffffffff00000000
    // -    0x 0000000000000000 00000000ffffffff
    // -----------------------------------------
    // =    0x 0000000000000001 fffffffe00000000    -> po[3] <= 2^65 - 2^33 < 2^65 - 2^33
    // Third reduction: po[3] < 2^65 - 2^32 ---> po[3] < 2^64
    // Assume that      po[3] = 0x 0000000000000001 ffffffff00000000
    //      0x 0000000000000000 ffffffff00000000
    // +    0x 0000000000000000 0000000100000000
    // -    0x 0000000000000000 0000000000000001
    // -----------------------------------------
    // =    0x 0000000000000000 ffffffffffffffff    -> po[3] < 2^64
    //
    // In addition, use carryLimbTotal to store the sum of carry bits.
    // In this way, carryLimbTotal*(-2^96 + 1) can be calculated at a time.
    // The simple conclusion is that when out[3] is the maximum, carryLimbTotal is the maximum.
    // Consider the maximum value of out[3].
    //      0x 7fffffffffffffff ffffffffffffffff    -> Maximum value of pi[3] (pi[3] < 2^127)
    // +    0x 0000000000000000 8000000000000000    -> Maximum value of carry of pi[2]
    // -----------------------------------------
    // =    0x 8000000000000000 7fffffffffffffff    -> Maximum value of po[3]
    // Use the value to perform three reduction:
    // carryLimbTotal = 0x8000000000000000 + 0x7fffffff + 0x1 = 0x8000000080000000 < 2^64
    carryLimbTotal = carryLimb = po[3] >> BASE_BITS;            // Reduce carryLimb and take the carry of po[3].
    po[3] = (uint64_t)po[3] + (carryLimb << 32) - carryLimb;    // The reduction factor on po[3] is (2 ^ 32 - 1).
    carryLimbTotal += (carryLimb = po[3] >> BASE_BITS);         // Reduce carryLimb and take the carry of po[3].
    po[3] = (uint64_t)po[3] + (carryLimb << 32) - carryLimb;    // The reduction factor on po[3] is (2 ^ 32 - 1).
    carryLimbTotal += (carryLimb = po[3] >> BASE_BITS);         // Reduce carryLimb and take the carry of po[3].
    po[3] = (uint64_t)po[3] + (carryLimb << 32) - carryLimb;    // The reduction factor on po[3] is (2 ^ 32 - 1).

    // Calculate the remaining carryLimbTotal * (-2^96 + 1) <= 0
    // In this case, it is impossible to carry out[4]. Therefore, po[3] < 2^64.
    // If carryLimbTotal > 0, po[3] must be equal to at least 2 ^ 32 - 1. (i.e., po[3] = 2^64 in the last step)
    // In this case, it is obvious that (2^32 - 1) * 2^192 > |carryLimbTotal * (-2^96 + 1)|
    po[0] += carryLimbTotal;  // reduction of carryLimbTotal which the coefficient is 1
    // po[1] + po[0] carry + Borrowed Bits - Reduction Factor 2^32
    po[1] += ((po[0] >> BASE_BITS) ^ borrow) - (carryLimbTotal << 32);
    // po[2] + po[1] carry + Borrowing Bits - Lending Bits
    po[2] += ((po[1] >> BASE_BITS) ^ borrow) - lend;
    // po[3] + po[2] carry - Lending Bits
    po[3] += (po[2] >> BASE_BITS) - lend;

    po[0] = (uint64_t)po[0];  // po[0] takes the basic digit.
    po[1] = (uint64_t)po[1];  // po[1] takes the basic digit.
    po[2] = (uint64_t)po[2];  // po[2] takes the basic digit.
}

/*
 * Field element reduction, converting 8-ary LongFelem to 4-ary Felem
 * Input:
 *      in[] < 2^80
 * Output:
 *      out[] < 2^115
 *      - out[0] < (2^114 + 2^82 - 2^50) + 2^(80 + 32) + 2 * 2^80   < 2^115
 *      - out[1] < (2^114 + 2^82 - 2^50) + 2^(80 + 33) + 2 * 2^80   < 2^115
 *      - out[2] < (2^114 + 2^82 - 2^50) + 2^(80 + 33) + 4 * 2^80   < 2^115
 *      - out[3] < (2^114 + 2^82 - 2^50) + 2^(80 + 32) + 4 * 2^80   < 2^115
 *      out[] > 0
 *      - out[0] > (2^114 - 2^82) - 2 * 2^(80 + 32) - 2 * 2^80      > 0
 *      - out[1] > (2^114 - 2^82) - 2^(80 + 32) - 2^80              > 0
 *      - out[2] > (2^114 - 2^82) - 2^(80 + 32) - 2^80              > 0
 *      - out[3] > (2^114 - 2^82) - 2 * 2^(80 + 32) - 2^80          > 0
 */
static void LongFelemReduce(Felem *out, const LongFelem *in)
{
    // n ≡ n / a * (a - b) ≡ n / a * b (mod (a - b))
    // The following formula can be obtained:
    // 2^n ≡ 2^(n - 256) * (2^224 - 2^192 - 2^96 + 1) (mod (2^256 - 2^224 + 2^192 + 2^96 - 1))
    //
    //   2^256 mod p
    // = 2^224 - 2^192 - 2^96 + 1
    //
    //   2^288 mod p
    // = 2^256 - 2^224 - 2^128 + 2^32
    // = -2^192 - 2^128 - 2^96 + 2^32 + 1
    //
    //   2^320 mod p
    // = 2^288 - 2^256 - 2^160 + 2^64
    // = -2^224 - 2^160 - 2^128 + 2^64 + 2^32
    //
    //   2^352 mod p
    // = 2^320 - 2^288 - 2^192 + 2^96
    // = -2^224 - 2^160 + 2 * 2^96 + 2^64 - 1
    //
    //   2^384 mod p
    // = 2^352 - 2^320 - 2^224 + 2^128
    // = -2^224 + 2 * 2^128 + 2 * 2^96 - 2^32 - 1
    //
    //   2^416 mod p
    // = 2^384 - 2^352 - 2^256 + 2^160
    // = -2^224 + 2^192 + 2 * 2^160 + 2 * 2^128 + 2^96 - 2^64 - 2^32 - 1
    //
    //   2^448 mod p
    // = 2^416 - 2^384 - 2^288 + 2^192
    // = 3 * 2^192 + 2 * 2^160 + 2^128 - 2^64 - 2^32 - 1
    //
    //   2^480 mod p
    // = 2^448 - 2^416 - 2^320 + 2^224
    // = 3 * 2^224 + 2 * 2^192 + 2^160 - 2^96 - 2^64 - 2^32

    static const Felem zeroBase = {
        {
            (((uint128_t)1 << 64) - 1)                        << 50,
            (((uint128_t)1 << 64) + ((uint128_t)1 << 32) - 1) << 50,
            (((uint128_t)1 << 64) - 1)                        << 50,
            (((uint128_t)1 << 64) - ((uint128_t)1 << 32))     << 50,
        }
    };

    uint128_t *po = out->data;
    const uint128_t *pi = in->data;
    // Add the term reduced by pi[4]*2^256, pi[5]*2^320, pi[6]*2^384, pi[7]*2^448 to the corresponding digit.
    // Assign a value after zero adjustment.
    // Adjust to zero of digit 0. Take the input value pi[0].
    // The reduction item list is (pi[4], pi[5]*2^32, -pi[6] - pi[6]*2^32, -pi[7] - pi[7]*2^32)
    po[0] = zeroBase.data[0] + pi[0] + pi[4] + (pi[5] << 32) - pi[6] - (pi[6] << 32) - pi[7] - (pi[7] << 32);
    // Adjust to zero of digit 1. Take the input value pi[1].
    // The reduction item list is (-pi[4]*2^32, pi[5], pi[6]*2^33, -pi[7])
    po[1] = zeroBase.data[1] + pi[1] - (pi[4] << 32) + pi[5] + (pi[6] << 33) - pi[7];
    // Adjust to zero of digit 2. Take the input value pi[2].
    // The reduction item list is (0, -pi[5] - pi[5]*2^32, -pi[6]*2, pi[7] + pi[7]*2^33)
    po[2] = zeroBase.data[2] + pi[2] - pi[5] - (pi[5] << 32) + (pi[6] << 1) + pi[7] + (pi[7] << 33);
    // Adjust to zero of digit 3. Take the input value pi[3].
    // The reduction item list is (-pi[4] + pi[4]*2^32, -pi[5]*2^32, -pi[6]*2^32, pi[7]*3)
    po[3] = zeroBase.data[3] + pi[3] - pi[4] + (pi[4] << 32) - (pi[5] << 32) - (pi[6] << 32) + (pi[7] * 3);
}

/*
 * field element modulo: convert the field element to a unique value within [0, p)
 * Input:
 *      in[] < 2^64
 * Output:
 *      out < p, out[] < 2^64
 */
static void FelemContract(Felem *out, const Felem *in)
{
    uint128_t *po = out->data;
    const uint128_t *pi = in->data;
    const uint128_t borrow = (uint128_t)1 << BASE_BITS;
    const uint128_t lend = 1;

    bool isGreaterOrEqual = true;
    for (int32_t i = 3; i >= 0; i--) {
        if (pi[i] > FIELD_ORDER.data[i]) {
            break;
        } else if (pi[i] < FIELD_ORDER.data[i]) {
            isGreaterOrEqual = false;
            break;
        }
    }

    if (isGreaterOrEqual) {
        // p_3 = 0xffffffff00000001
        po[3] = (pi[3] - lend) - FIELD_ORDER.data[3];
        // p_2 = 0x0000000000000000
        po[2] = (borrow ^ pi[2]) - lend;
        // p_1 = 0x00000000ffffffff
        po[1] = ((borrow ^ pi[1]) - lend) - FIELD_ORDER.data[1];
        // p_0 = 0xffffffffffffffff
        po[0] = (borrow ^ pi[0]) - FIELD_ORDER.data[0];
    }

    // Process carry 0 -> 1 -> 2 -> 3
    po[1] += po[0] >> BASE_BITS;  // po[1] + po[0] carry
    po[2] += po[1] >> BASE_BITS;  // po[2] + po[1] carry
    po[3] += po[2] >> BASE_BITS;  // po[3] + po[2] carry

    po[0] = (uint64_t)po[0];        // po[0] takes the basic digit.
    po[1] = (uint64_t)po[1];        // po[1] takes the basic digit.
    po[2] = (uint64_t)po[2];        // po[2] takes the basic digit.
}

/*
 * Field Addition
 */
static inline void FelemAdd(Felem *out, const Felem *a, const Felem *b)
{
    out->data[0] = a->data[0] + b->data[0];  // out->data[0] get the value
    out->data[1] = a->data[1] + b->data[1];  // out->data[1] get the value
    out->data[2] = a->data[2] + b->data[2];  // out->data[2] get the value
    out->data[3] = a->data[3] + b->data[3];  // out->data[3] get the value
}

/*
 * Field element negation
 * Input:
 *      in[] <= 2^124 - 2^92
 * Output:
 *      out[] <= 2^124 + 2^92 - 2^60 + in[]
 */
static inline void FelemNeg(Felem *out, const Felem *in)
{
    static const Felem zeroBase = {{
        (((uint128_t)1 << 64) - 1)                        << 60,
        (((uint128_t)1 << 64) + ((uint128_t)1 << 32) - 1) << 60,
        (((uint128_t)1 << 64) - 1)                        << 60,
        (((uint128_t)1 << 64) - ((uint128_t)1 << 32))     << 60,
    }};

    out->data[0] = zeroBase.data[0] - in->data[0];  // out->data[0] get the value
    out->data[1] = zeroBase.data[1] - in->data[1];  // out->data[1] get the value
    out->data[2] = zeroBase.data[2] - in->data[2];  // out->data[2] get the value
    out->data[3] = zeroBase.data[3] - in->data[3];  // out->data[3] get the value
}

/*
 * Field subtraction
 * Input:
 *      a[] < 2^128 - 2^124 - 2^92 + 2^60，b[] <= 2^124 - 2^92
 * Output:
 *      out[] <= 2^124 + 2^92 - 2^60 + a[] < 2^128
 */
static inline void FelemSub(Felem *out, const Felem *a, const Felem *b)
{
    static const Felem zeroBase = {{
        (((uint128_t)1 << 64) - 1)                        << 60,
        (((uint128_t)1 << 64) + ((uint128_t)1 << 32) - 1) << 60,
        (((uint128_t)1 << 64) - 1)                        << 60,
        (((uint128_t)1 << 64) - ((uint128_t)1 << 32))     << 60,
    }};

    out->data[0] = zeroBase.data[0] + a->data[0] - b->data[0];  // out->data[0] get the value
    out->data[1] = zeroBase.data[1] + a->data[1] - b->data[1];  // out->data[1] get the value
    out->data[2] = zeroBase.data[2] + a->data[2] - b->data[2];  // out->data[2] get the value
    out->data[3] = zeroBase.data[3] + a->data[3] - b->data[3];  // out->data[3] get the value
}

/*
 * Field subtraction. Input LongFelem directly.
 * Input:
 *      a[] < 2^128 - 2^74 - 2^42 + 2^10，b[] <= 2^74 - 2^42
 * Output:
 *      out[] <= 2^74 + 2^42 - 2^10 + a[] < 2^128
 */
static void LongFelemSub(LongFelem *out, const LongFelem *a, const LongFelem *b)
{
    static const LongFelem zeroBase = {{
        ((uint128_t)1 << 64)                              << 10,
        (((uint128_t)1 << 64) - 1)                        << 10,
        (((uint128_t)1 << 64) - 1)                        << 10,
        (((uint128_t)1 << 64) - 1)                        << 10,
        (((uint128_t)1 << 64) - 2)                        << 10,
        (((uint128_t)1 << 64) + ((uint128_t)1 << 32) - 1) << 10,
        (((uint128_t)1 << 64) - 1)                        << 10,
        (((uint128_t)1 << 64) - ((uint128_t)1 << 32))     << 10,
    }};

    out->data[0] = zeroBase.data[0] + a->data[0] - b->data[0];  // out->data[0] get the value
    out->data[1] = zeroBase.data[1] + a->data[1] - b->data[1];  // out->data[1] get the value
    out->data[2] = zeroBase.data[2] + a->data[2] - b->data[2];  // out->data[2] get the value
    out->data[3] = zeroBase.data[3] + a->data[3] - b->data[3];  // out->data[3] get the value
    out->data[4] = zeroBase.data[4] + a->data[4] - b->data[4];  // out->data[4] get the value
    out->data[5] = zeroBase.data[5] + a->data[5] - b->data[5];  // out->data[5] get the value
    out->data[6] = zeroBase.data[6] + a->data[6] - b->data[6];  // out->data[6] get the value
    out->data[7] = zeroBase.data[7] + a->data[7] - b->data[7];  // out->data[7] get the value
}

/*
 * Scale the field element
 * Use only a small magnification(scale) factor to ensure that in[] * scalar does not overflow.
 */
static inline void FelemScale(Felem *out, const Felem *in, const uint32_t scalar)
{
    out->data[0] = in->data[0] * scalar;  // out->data[0] get the value
    out->data[1] = in->data[1] * scalar;  // out->data[1] get the value
    out->data[2] = in->data[2] * scalar;  // out->data[2] get the value
    out->data[3] = in->data[3] * scalar;  // out->data[3] get the value
}

/*
 * Scale the field element. Input LongFelem directly.
 * Use only a small magnification(scale) factor to ensure that in[] * scalar does not overflow.
 */
static inline void LongFelemScale(LongFelem *out, const LongFelem *in, const uint32_t scalar)
{
    out->data[0] = in->data[0] * scalar;  // out->data[0] get the value
    out->data[1] = in->data[1] * scalar;  // out->data[1] get the value
    out->data[2] = in->data[2] * scalar;  // out->data[2] get the value
    out->data[3] = in->data[3] * scalar;  // out->data[3] get the value
    out->data[4] = in->data[4] * scalar;  // out->data[4] get the value
    out->data[5] = in->data[5] * scalar;  // out->data[5] get the value
    out->data[6] = in->data[6] * scalar;  // out->data[6] get the value
    out->data[7] = in->data[7] * scalar;  // out->data[7] get the value
}

/*
 * Field Multiplication
 * Input:
 *      a[] < 2^64, b[] < 2^64
 * Output:
 *      out[] < 2^67
 *      - out[0] < 2^64
 *      - out[1] < 2^64 * 3
 *      - out[2] < 2^64 * 5
 *      - out[3] < 2^64 * 7
 *      - out[4] < 2^64 * 7
 *      - out[5] < 2^64 * 5
 *      - out[6] < 2^64 * 3
 *      - out[7] < 2^64
 */
static void FelemMul(LongFelem *out, const Felem *a, const Felem *b)
{
    // out[0] = a[0]*b[0]
    // out[1] = a[0]*b[1] + a[1]*b[0]
    // out[2] = a[0]*b[2] + a[1]*b[1] + a[2]*b[0]
    // out[3] = a[0]*b[3] + a[1]*b[2] + a[2]*b[1] + a[3]*b[0]
    // out[4] =             a[1]*b[3] + a[2]*b[2] + a[3]*b[1]
    // out[5] =                         a[2]*b[3] + a[3]*b[2]
    // out[6] =                                     a[3]*b[3]

    const uint64_t a64[4] = {(uint64_t)a->data[0], (uint64_t)a->data[1], (uint64_t)a->data[2], (uint64_t)a->data[3]};
    const uint64_t b64[4] = {(uint64_t)b->data[0], (uint64_t)b->data[1], (uint64_t)b->data[2], (uint64_t)b->data[3]};
    uint128_t limbMul;

    // out[0] = a[0]*b[0]
    limbMul = (uint128_t)a64[0] * b64[0];   // a[0] * b[0]
    out->data[0] = (uint64_t)limbMul;       // Digit 0 plus the basic digit
    out->data[1] = limbMul >> BASE_BITS;    // Digit 1 plus the carry

    // out[1] = a[0]*b[1] + a[1]*b[0]
    limbMul = (uint128_t)a64[0] * b64[1];   // a[0] * b[1]
    out->data[1] += (uint64_t)limbMul;      // Digit 1 plus the basic digit
    out->data[2] = limbMul >> BASE_BITS;    // Digit 2 plus the carry

    limbMul = (uint128_t)a64[1] * b64[0];   // a[1] * b[0]
    out->data[1] += (uint64_t)limbMul;      // Digit 1 plus the basic digit
    out->data[2] += limbMul >> BASE_BITS;   // Digit 2 plus the carry

    // out[2] = a[0]*b[2] + a[1]*b[1] + a[2]*b[0]
    limbMul = (uint128_t)a64[0] * b64[2];   // a[0] * b[2]
    out->data[2] += (uint64_t)limbMul;      // Digit 2 plus the basic digit
    out->data[3] = limbMul >> BASE_BITS;    // Digit 3 plus the carry

    limbMul = (uint128_t)a64[1] * b64[1];   // a[1] * a[1]
    out->data[2] += (uint64_t)limbMul;      // Digit 2 plus the basic digit
    out->data[3] += limbMul >> BASE_BITS;   // Digit 3 plus the carry

    limbMul = (uint128_t)a64[2] * b64[0];   // a[2] * b[0]
    out->data[2] += (uint64_t)limbMul;      // Digit 2 plus the basic digit
    out->data[3] += limbMul >> BASE_BITS;   // Digit 3 plus the carry

    // out[3] = a[0]*b[3] + a[1]*b[2] + a[2]*b[1] + a[3]*b[0]
    limbMul = (uint128_t)a64[0] * b64[3];   // a[0] * b[3]
    out->data[3] += (uint64_t)limbMul;      // Digit 3 plus the basic digit
    out->data[4] = limbMul >> BASE_BITS;    // Digit 4 plus the carry

    limbMul = (uint128_t)a64[1] * b64[2];   // a[1] * b[2]
    out->data[3] += (uint64_t)limbMul;      // Digit 3 plus the basic digit
    out->data[4] += limbMul >> BASE_BITS;   // Digit 4 plus the carry

    limbMul = (uint128_t)a64[2] * b64[1];   // a[2] * b[1]
    out->data[3] += (uint64_t)limbMul;      // Digit 3 plus the basic digit
    out->data[4] += limbMul >> BASE_BITS;   // Digit 4 plus the carry

    limbMul = (uint128_t)a64[3] * b64[0];   // a[3] * b[0]
    out->data[3] += (uint64_t)limbMul;      // Digit 3 plus the basic digit
    out->data[4] += limbMul >> BASE_BITS;   // Digit 4 plus the carry

    // out[4] = a[1]*b[3] + a[2]*b[2] + a[3]*b[1]
    limbMul = (uint128_t)a64[1] * b64[3];   // a[1] * b[3]
    out->data[4] += (uint64_t)limbMul;      // Digit 4 plus the basic digit
    out->data[5] = limbMul >> BASE_BITS;    // Digit 5 plus the carry

    limbMul = (uint128_t)a64[2] * b64[2];   // a[2] * b[2]
    out->data[4] += (uint64_t)limbMul;      // Digit 4 plus the basic digit
    out->data[5] += limbMul >> BASE_BITS;   // Digit 5 plus the carry

    limbMul = (uint128_t)a64[3] * b64[1];   // a[3] * b[1]
    out->data[4] += (uint64_t)limbMul;      // Digit 4 plus the basic digit
    out->data[5] += limbMul >> BASE_BITS;   // Digit 5 plus the carry

    // out[5] = a[2]*b[3] + a[3]*b[2]
    limbMul = (uint128_t)a64[2] * b64[3];   // a[2] * b[3]
    out->data[5] += (uint64_t)limbMul;      // Digit 5 plus the basic digit
    out->data[6] = limbMul >> BASE_BITS;    // Digit 6 plus the carry

    limbMul = (uint128_t)a64[3] * b64[2];   // a[3] * b[2]
    out->data[5] += (uint64_t)limbMul;      // Digit 5 plus the basic digit
    out->data[6] += limbMul >> BASE_BITS;   // Digit 6 plus the carry

    // out[6] = a[3]*b[3]
    limbMul = (uint128_t)a64[3] * b64[3];   // a[3] * b[3]
    out->data[6] += (uint64_t)limbMul;      // Digit 6 plus the basic digit
    out->data[7] = limbMul >> BASE_BITS;    // Digit 7 plus the carry
}

/*
 * Field square
 * Input:
 *      a[] < 2^64
 * Output:
 *      out[] < 2^67
 *      - out[0] < 2^64
 *      - out[1] < 2^64 * 2
 *      - out[2] < 2^64 * 4
 *      - out[3] < 2^64 * 5
 *      - out[4] < 2^64 * 6
 *      - out[5] < 2^64 * 4
 *      - out[6] < 2^64 * 3
 *      - out[7] < 2^64
 */
static void FelemSqr(LongFelem *out, const Felem *a)
{
    // out[0] = a[0]*a[0]
    // out[1] = a[0]*a[1]*2
    // out[2] = a[0]*a[2]*2 + a[1]*a[1]
    // out[3] = a[0]*a[3]*2 + a[1]*a[2]*2
    // out[4] = a[1]*a[3]*2 + a[2]*a[2]
    // out[5] = a[2]*a[3]*2
    // out[6] = a[3]*a[3]

    const uint64_t a64[4] = {(uint64_t)a->data[0], (uint64_t)a->data[1], (uint64_t)a->data[2], (uint64_t)a->data[3]};
    uint128_t limbMul;

    // out[0] = a[0]*a[0]
    limbMul = (uint128_t)a64[0] * a64[0];       // a[0] * a[0]
    out->data[0] = (uint64_t)limbMul;           // Digit 0 plus the basic digit
    out->data[1] = limbMul >> BASE_BITS;        // Digit 1 plus the carry

    // out[1] = a[0]*a[1]*2
    limbMul = (uint128_t)a64[0] * a64[1];       // a[0] * a[1]
    out->data[1] += (uint64_t)limbMul << 1;     // basic digit after the product is left shifted by 1bit, add to digit 1
    out->data[2] = limbMul >> (BASE_BITS - 1);  // carry after product shift, add to digit 2

    // out[2] = a[0]*a[2]*2 + a[1]*a[1]
    limbMul = (uint128_t)a64[0] * a64[2];       // a[0] * a[2]
    out->data[2] += (uint64_t)limbMul << 1;     // basic digit after the product is left shifted by 1bit, add to digit 2
    out->data[3] = limbMul >> (BASE_BITS - 1);  // carry after product shift, add to digit 3

    limbMul = (uint128_t)a64[1] * a64[1];       // a[1] * a[1]
    out->data[2] += (uint64_t)limbMul;          // Digit 2 plus the basic digit
    out->data[3] += limbMul >> BASE_BITS;       // Digit 3 plus the carry

    // out[3] = a[0]*a[3]*2 + a[1]*a[2]*2
    limbMul = (uint128_t)a64[0] * a64[3];       // a[0] * a[3]
    out->data[3] += (uint64_t)limbMul << 1;     // basic digit after the product is left shifted by 1bit, add to digit 3
    out->data[4] = limbMul >> (BASE_BITS - 1);  // carry after product shift, add to digit 4

    limbMul = (uint128_t)a64[1] * a64[2];       // a[1] * a[2]
    out->data[3] += (uint64_t)limbMul << 1;     // basic digit after the product is left shifted by 1bit, add to digit 3
    out->data[4] += limbMul >> (BASE_BITS - 1); // carry after product shift, add to digit 4

    // out[4] = a[1]*a[3]*2 + a[2]*a[2]
    limbMul = (uint128_t)a64[1] * a64[3];       // a[1] * a[3]
    out->data[4] += (uint64_t)limbMul << 1;     // basic digit after the product is left shifted by 1bit, add to digit 4
    out->data[5] = limbMul >> (BASE_BITS - 1);  // carry after product shift, add to digit 5

    limbMul = (uint128_t)a64[2] * a64[2];       // a[2] * a[2]
    out->data[4] += (uint64_t)limbMul;          // Digit 4 plus the basic digit
    out->data[5] += limbMul >> BASE_BITS;       // Digit 5 plus the carry

    // out[5] = a[2]*a[3]*2
    limbMul = (uint128_t)a64[2] * a64[3];       // a[2] * a[3]
    out->data[5] += (uint64_t)limbMul << 1;     // basic digit after the product is left shifted by 1bit, add to digit 5
    out->data[6] = limbMul >> (BASE_BITS - 1);  // carry after product shift, add to digit 6

    // out[6] = a[3]*a[3]
    limbMul = (uint128_t)a64[3] * a64[3];       // a[3] * a[3]
    out->data[6] += (uint64_t)limbMul;          // Digit 6 plus the basic digit
    out->data[7] = limbMul >> BASE_BITS;        // Digit 7 plus the carry
}

static inline void FelemMulReduce(Felem *out, const Felem *a, const Felem *b)
{
    LongFelem ltmp;
    FelemMul(&ltmp, a, b);
    LongFelemReduce(out, &ltmp);
}

static inline void FelemSqrReduce(Felem *out, const Felem *in)
{
    LongFelem ltmp;
    FelemSqr(&ltmp, in);
    LongFelemReduce(out, &ltmp);
}

static inline void FelemMulReduceToBase(Felem *out, const Felem *a, const Felem *b)
{
    LongFelem ltmp;
    FelemMul(&ltmp, a, b);
    LongFelemReduce(out, &ltmp);
    FelemReduce(out, out);
}

static inline void FelemSqrReduceToBase(Felem *out, const Felem *in)
{
    LongFelem ltmp;
    FelemSqr(&ltmp, in);
    LongFelemReduce(out, &ltmp);
    FelemReduce(out, out);
}

/*
 * Field element inversion
 * From Fermat's little theorem, in^(p - 2) = in^(-1) (mod p)
 * in^(-1) = in^(2^256 - 2^224 + 2^192 + 2^96 - 1 - 2) (mod p)
 * Input:
 *      in[] < 2^64
 * Output:
 *      out[] < 2^64
 */
static void FelemInv(Felem *out, const Felem *in)
{
    Felem inE3, inEf, inEff, inEffff, inEffffffff, inEfx16Lsh32, inEfffffffd;

    // Construct in^(p - 2) by moving left and adding.
    // The value of p - 2 is as follows:
    // ffffffff 00000001
    // 00000000 00000000
    // 00000000 ffffffff
    // ffffffff fffffffd

    // Construct the {1, 3, f, ff, ffff, ffffffff} power of in by left shift and addition.
    // Construct in^1
    FelemAssign(out, in);  // in^1
    // Construct in^3
    FelemSqrReduceToBase(out, out);  // in^2
    FelemMulReduceToBase(out, out, in);  // in^3
    FelemAssign(&inE3, out);
    // Construct in^f
    FelemSqrReduceToBase(out, out);  // in^6
    FelemSqrReduceToBase(out, out);  // in^c
    FelemMulReduceToBase(&inEfffffffd, out, in);  // inEfffffffd = in^d
    FelemMulReduceToBase(out, out, &inE3);  // in^f
    FelemAssign(&inEf, out);
    // Construct in^ff
    FelemSqrReduceToBase(out, out);  // in^1e
    FelemSqrReduceToBase(out, out);  // in^3c
    FelemSqrReduceToBase(out, out);  // in^78
    FelemSqrReduceToBase(out, out);  // in^f0
    FelemMulReduceToBase(&inEfffffffd, out, &inEfffffffd);  // inEfffffffd = in^fd
    FelemMulReduceToBase(out, out, &inEf);  // in^ff
    FelemAssign(&inEff, out);
    // Construct in^ffff and shift ff to the left by 8 bits to obtain ff00
    for (int32_t i = 0; i < 8; ++i) {
        FelemSqrReduceToBase(out, out);
    }  // in^ff00
    FelemMulReduceToBase(&inEfffffffd, out, &inEfffffffd);  // inEfffffffd = in^fffd
    FelemMulReduceToBase(out, out, &inEff);  // in^ffff
    FelemAssign(&inEffff, out);
    // Construct in^ffffffff and shift ffff to the left by 16 bits to obtain ffff0000
    for (int32_t i = 0; i < 16; ++i) {
        FelemSqrReduceToBase(out, out);
    }  // in^ffff0000
    FelemMulReduceToBase(&inEfffffffd, out, &inEfffffffd);  // inEfffffffd = in^fffffffd
    FelemMulReduceToBase(out, out, &inEffff);  // in^ffffffff
    FelemAssign(&inEffffffff, out);

    // Construct in^ffffffff ffffffff 00000000
    // Obtain in^ffffffff 00000000 and shift ffffffff to the left by 32 bits.
    for (int32_t i = 0; i < 32; ++i) {
        FelemSqrReduceToBase(out, out);
    }  // in^ffffffff 00000000
    FelemAssign(&inEfx16Lsh32, out);
    // Then obtain ffffffff 00000000 00000000 and shift it leftwards by 32 bits.
    for (int32_t i = 0; i < 32; ++i) {
        FelemSqrReduceToBase(out, out);
    }  // out = in^ffffffff 00000000 00000000
    FelemMulReduceToBase(&inEfx16Lsh32, out, &inEfx16Lsh32);  // inEfx16Lsh32 = in^ffffffff ffffffff 00000000

    // Construct in^ffffffff 00000001 00000000
    FelemMulReduceToBase(out, out, &inEffffffff);  // in^ffffffff 00000000 ffffffff
    FelemMulReduceToBase(out, out, in);  // in^ffffffff 00000001 00000000

    // Shift leftward by 160 bits to the top.
    for (int32_t i = 0; i < 160; ++i) {
        FelemSqrReduceToBase(out, out);
    }  // in^ffffffff 00000001 00000000 00000000 00000000 00000000 00000000 00000000

    // Construct in^ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff 00000000
    FelemMulReduceToBase(out, out, &inEfx16Lsh32);
    // Construct in^ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffd
    FelemMulReduceToBase(out, out, &inEfffffffd);
}

/* --------------------------Point group operation-------------------------- */
static inline void PtAssign(Point *out, const Point *in)
{
    FelemAssign(&out->x, &in->x);
    FelemAssign(&out->y, &in->y);
    FelemAssign(&out->z, &in->z);
}

static inline void PtAssignWithMask(Point *out, const Point *in, const uint128_t mask)
{
    FelemAssignWithMask(&out->x, &in->x, mask);
    FelemAssignWithMask(&out->y, &in->y, mask);
    FelemAssignWithMask(&out->z, &in->z, mask);
}

/*
 * point double
 * Algorithm reference: http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
 * Number of field operations: 3M + 5S
 *      delta = Z^2
 *      gamma = Y^2
 *      beta = X * gamma
 *      alpha = 3 * (X - delta) * (X + delta)
 *      X' = alpha^2 - 8 * beta
 *      Z' = (Y + Z)^2 - gamma - delta
 *      Y' = alpha * (4 * beta - X') - 8 * gamma^2
 * Input:
 *      in->x[], in->y[], in->z[] < 2^64
 * Output:
 *      out->x[], out->y[], out->z[] < 2^64
 */
static void PtDouble(Point *out, const Point *in)
{
    Felem delta, gamma, beta, alpha;
    Felem tmp, tmp2;
    LongFelem ltmp, ltmp2;

    // delta = Z^2
    FelemSqrReduce(&delta, &in->z);  // delta[] < 2^115

    // gamma = Y^2
    FelemSqrReduceToBase(&gamma, &in->y);

    // beta = X * gamma
    FelemMulReduce(&beta, &in->x, &gamma);  // beta[] < 2^115

    // alpha = 3 * (X - delta) * (X + delta)
    FelemAdd(&tmp, &in->x, &delta);     // tmp[] < 2^64 + 2^115
    FelemScale(&tmp, &tmp, 3);          // 3 * (X + delta), tmp[] < (2^64 + 2^115) * 3 < 2^117
    FelemSub(&tmp2, &in->x, &delta);    // tmp2[] < (2^124 + 2^92 - 2^60) + 2^64 < 2^125
    FelemReduce(&tmp, &tmp);
    FelemReduce(&tmp2, &tmp2);
    FelemMulReduceToBase(&alpha, &tmp, &tmp2);

    // X' = alpha^2 - 8 * beta
    FelemSqrReduce(&tmp, &alpha);       // alpha^2, tmp[] < 2^115
    FelemScale(&tmp2, &beta, 8);        // 8 * beta, tmp2[] < 2^115 * 8 = 2^119
    FelemSub(&out->x, &tmp, &tmp2);     // out->x[] < (2^124 + 2^92 - 2^60) + 2^115 < 2^125
    FelemReduce(&out->x, &out->x);      // out->x[] < 2^64

    // Z' = (Y + Z)^2 - gamma - delta
    FelemAdd(&tmp, &in->y, &in->z);
    FelemReduce(&tmp, &tmp);
    FelemSqrReduce(&tmp, &tmp);         // (Y + Z)^2, tmp[] < 2^115
    FelemAdd(&tmp2, &gamma, &delta);    // (gamma + delta), tmp2[] < 2^64 + 2^115 < 2^116
    FelemSub(&out->z, &tmp, &tmp2);     // out->z[] < (2^124 + 2^92 - 2^60) + 2^115 < 2^125
    FelemReduce(&out->z, &out->z);      // out->z[] < 2^64

    // Y' = alpha * (4 * beta - X') - 8 * gamma^2
    FelemScale(&beta, &beta, 4);        // beta[] < 2^115 * 4 = 2^117
    FelemSub(&tmp, &beta, &out->x);
    FelemReduce(&tmp, &tmp);
    FelemMul(&ltmp, &alpha, &tmp);      // alpha * (4 * beta - X'), ltmp[] < 2^67
    FelemSqr(&ltmp2, &gamma);
    LongFelemScale(&ltmp2, &ltmp2, 8);  // 8 * gamma^2, ltmp2[] < 2^67 * 8 < 2^70
    LongFelemSub(&ltmp, &ltmp, &ltmp2); // ltmp[] < (2^74 + 2^42 - 2^10) + 2^67 < 2^75
    LongFelemReduce(&out->y, &ltmp);    // out->y[] < 2^115
    FelemReduce(&out->y, &out->y);      // out->y[] < 2^64
}

/*
 * point addition
 * Algorithm reference: http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
 * Infinity point calculation is not supported.
 * Number of field operations: 11M + 5S
 *      Z1Z1 = Z1^2
 *      Z2Z2 = Z2^2
 *      U1 = X1 * Z2Z2
 *      U2 = X2 * Z1Z1
 *      S1 = Y1 * Z2 * Z2Z2
 *      S2 = Y2 * Z1 * Z1Z1
 *      H = U2 - U1
 *      I = (2 * H)^2
 *      J = H * I
 *      r = 2 * (S2 - S1)
 *      V = U1 * I
 *      X3 = r^2 - J - 2 * V
 *      Y3 = r * (V - X3) - 2 * S1 * J
 *      Z3 = ((Z1 + Z2)^2 - Z1Z1 - Z2Z2) * H
 * Input:
 *      a->x[], a->y[], a->z[] < 2^64
 *      b->x[], b->y[], b->z[] < 2^64
 * Output:
 *      out->x[], out->y[], out->z[] < 2^64
 */
static void PtAdd(Point *out, const Point *a, const Point *b)
{
    Point result;
    Felem z1sqr, z2sqr, u1, u2, s1, s2, h, i, j, r, v;
    Felem tmp;
    LongFelem ltmp, ltmp2;
    uint128_t isZ1Zero, isZ2Zero;

    // Z1Z1 = Z1^2
    FelemSqrReduceToBase(&z1sqr, &a->z);

    // Z2Z2 = Z2^2
    FelemSqrReduceToBase(&z2sqr, &b->z);

    isZ1Zero = 0 - FelemIsZero(&z1sqr);
    isZ2Zero = 0 - FelemIsZero(&z2sqr);

    // U1 = X1 * Z2Z2
    FelemMulReduceToBase(&u1, &a->x, &z2sqr);

    // U2 = X2 * Z1Z1
    FelemMulReduce(&u2, &b->x, &z1sqr);  // u2[] < 2^115

    // S1 = Y1 * Z2 * Z2Z2
    FelemMulReduceToBase(&s1, &b->z, &z2sqr);
    FelemMulReduceToBase(&s1, &a->y, &s1);

    // S2 = Y2 * Z1 * Z1Z1
    FelemMulReduceToBase(&s2, &a->z, &z1sqr);
    FelemMulReduce(&s2, &b->y, &s2);  // s2[] < 2^115

    // H = U2 - U1
    FelemSub(&h, &u2, &u1);  // h[] < (2^124 + 2^92 - 2^60) + 2^115 < 2^125
    FelemReduce(&h, &h);

    // r = 2 * (S2 - S1)
    FelemSub(&r, &s2, &s1);  // r[] < (2^124 + 2^92 - 2^60) + 2^115 < 2^125
    FelemScale(&r, &r, 2);   // r[] < 2^126
    FelemReduce(&r, &r);

    // H and r can determine whether x and y of the affine coordinates of two points are equal.
    // If the values are equal, use double().
    if (isZ1Zero == 0 && isZ2Zero == 0 && FelemIsZero(&h) != 0 && FelemIsZero(&r) != 0) {
        // Use a smaller b point
        PtDouble(out, b);
        return;
    }

    // I = (2 * H)^2
    FelemSqrReduce(&i, &h);  // H^2, i[] < 2^115
    FelemScale(&i, &i, 4);   // 4 * H^2, i[] < 2^117
    FelemReduce(&i, &i);

    // J = H * I
    FelemMulReduceToBase(&j, &h, &i);

    // V = U1 * I
    FelemMulReduce(&v, &u1, &i);  // v[] < 2^115

    // X3 = r^2 - (J + 2 * V)
    FelemSqrReduce(&result.x, &r);              // result.x[] < 2^115
    FelemScale(&tmp, &v, 2);                    // tmp[] < 2^115 * 2 = 2^116
    FelemAdd(&tmp, &j, &tmp);                   // tmp[] < 2^64 + 2^116 < 2^117
    FelemSub(&result.x, &result.x, &tmp);       // result.x[] < (2^124 + 2^90 - 2^60) + 2^115 < 2^125
    FelemReduce(&result.x, &result.x);          // result.x[] < 2^64

    // Y3 = r * (V - X3) - 2 * S1 * J
    FelemSub(&tmp, &v, &result.x);
    FelemReduce(&tmp, &tmp);
    FelemMul(&ltmp, &r, &tmp);                  // r * (V - X3), ltmp[] < 2^67
    FelemMul(&ltmp2, &s1, &j);                  // ltmp2[] < 2^67
    LongFelemScale(&ltmp2, &ltmp2, 2);          // 2 * S1 * J, ltmp2[] < 2^68
    LongFelemSub(&ltmp, &ltmp, &ltmp2);         // ltmp[] < (2^74 + 2^42 - 2^10) + 2^67 < 2^75
    LongFelemReduce(&result.y, &ltmp);          // result.y[] < 2^115
    FelemReduce(&result.y, &result.y);          // result.y[] < 2^64

    // Z3 = ((Z1 + Z2)^2 - Z1Z1 - Z2Z2) * H
    FelemAdd(&result.z, &a->z, &b->z);
    FelemReduce(&result.z, &result.z);
    FelemSqrReduce(&result.z, &result.z);       // (Z1 + Z2)^2
    FelemAdd(&tmp, &z1sqr, &z2sqr);             // Z1Z1 + Z2Z2
    FelemSub(&result.z, &result.z, &tmp);       // ((Z1 + Z2)^2 - Z1Z1 - Z2Z2)
    FelemReduce(&result.z, &result.z);
    FelemMulReduceToBase(&result.z, &result.z, &h);   // result.z[] < 2^64

    // Special case processing for infinity points
    PtAssignWithMask(&result, a, isZ2Zero);
    PtAssignWithMask(&result, b, isZ1Zero);
    PtAssign(out, &result);
}

/*
 * Mixed point addition
 * Algorithm reference: http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2007-bl
 * Infinity point calculation is not supported.
 * Number of field operations: 7M + 4S
 *      Z1Z1 = Z1^2
 *      U2 = X2 * Z1Z1
 *      S2 = Y2 * Z1 * Z1Z1
 *      H = U2 - X1
 *      HH = H^2
 *      I = 4 * HH
 *      J = H * I
 *      r = 2 * (S2 - Y1)
 *      V = X1 * I
 *      X3 = r^2 - J - 2 * V
 *      Y3 = r * (V - X3) - 2 * Y1 * J
 *      Z3 = (Z1 + H)^2 - Z1Z1 - HH
 * Input:
 *      a->x[] < 2^64, a->y[] < 2^64, a->z[] < 2^64
 *      b->x < p, b->y < p, b->z = 0 或 1
 * Output:
 *      out->x[] < 2^64
 *      out->y[] < 2^64
 *      out->z[] < 2^64
 */
static void PtAddMixed(Point *out, const Point *a, const Point *b)
{
    Point result;
    Felem z1sqr, u2, s2, h, hsqr, i, j, r, v;
    Felem tmp;
    LongFelem ltmp, ltmp2;
    uint128_t isZ1Zero, isZ2Zero;

    // Z1Z1 = Z1^2
    FelemSqrReduceToBase(&z1sqr, &a->z);

    isZ1Zero = 0 - FelemIsZero(&z1sqr);
    // The Z coordinate of point b can only be 0 or 1, that is, digit 0 can only be 0 or 1, and the other digits are 0.
    isZ2Zero = b->z.data[0] - 1;

    // U2 = X2 * Z1Z1
    FelemMulReduce(&u2, &b->x, &z1sqr);  // u2[] < 2^115

    // S2 = Y2 * Z1 * Z1Z1
    FelemMulReduceToBase(&s2, &a->z, &z1sqr);
    FelemMulReduce(&s2, &b->y, &s2);     // s2[] < 2^115

    // H = U2 - X1
    FelemSub(&h, &u2, &a->x);  // h[] < (2^124 + 2^92 - 2^60) + 2^115 < 2^125
    FelemReduce(&h, &h);

    // r = 2 * (S2 - Y1)
    FelemSub(&r, &s2, &a->y);  // r[] < (2^124 + 2^92 - 2^60) + 2^115 < 2^125
    FelemScale(&r, &r, 2);     // r[] < 2^126
    FelemReduce(&r, &r);

    // H and r can determine whether x and y of the affine coordinates of two points are equal.
    // If the values are equal, use double().
    if (isZ1Zero == 0 && isZ2Zero == 0 && FelemIsZero(&h) != 0 && FelemIsZero(&r) != 0) {
        // Use a smaller b point
        PtDouble(out, b);
        return;
    }

    // HH = H^2
    FelemSqrReduce(&hsqr, &h);  // hsqr[] < 2^115

    // I = 4 * HH
    FelemScale(&i, &hsqr, 4);   // i[] < 2^117
    FelemReduce(&i, &i);

    // J = H * I
    FelemMulReduceToBase(&j, &h, &i);

    // V = X1 * I
    FelemMulReduce(&v, &a->x, &i);  // v[] < 2^115

    // X3 = r^2 - J - 2 * V
    FelemSqrReduce(&result.x, &r);
    FelemScale(&tmp, &v, 2);                // tmp[] < 2^116
    FelemAdd(&tmp, &j, &tmp);               // tmp[] < 2^64 + 2^116 < 2^117
    FelemSub(&result.x, &result.x, &tmp);   // result.x[] < (2^124 + 2^92 - 2^60) + 2^115 < 2^125
    FelemReduce(&result.x, &result.x);      // result.x[] < 2^64

    // Y3 = r * (V - X3) - 2 * Y1 * J
    FelemSub(&tmp, &v, &result.x);          // tmp[] < (2^124 + 2^92 - 2^60) + 2^115 < 2^125
    FelemReduce(&tmp, &tmp);
    FelemMul(&ltmp, &r, &tmp);              // ltmp[] < 2^67
    FelemMul(&ltmp2, &a->y, &j);            // ltmp2[] < 2^67
    LongFelemScale(&ltmp2, &ltmp2, 2);      // ltmp2[] < 2^68
    LongFelemSub(&ltmp, &ltmp, &ltmp2);     // ltmp[] < (2^74 + 2^42 - 2^10) + 2^67 < 2^75
    LongFelemReduce(&result.y, &ltmp);      // result.y[] < 2^115
    FelemReduce(&result.y, &result.y);      // result.y[] < 2^64

    // Z3 = (Z1 + H)^2 - Z1Z1 - HH
    FelemAdd(&result.z, &a->z, &h);         // result.z[] < 2^64 + 2^64 = 2^65
    FelemReduce(&result.z, &result.z);
    FelemSqrReduce(&result.z, &result.z);   // result.z[] < 2^115
    FelemAdd(&tmp, &z1sqr, &hsqr);          // tmp[] < 2^64 + 2^115 < 2^116
    FelemSub(&result.z, &result.z, &tmp);   // result.z[] < (2^124 + 2^92 - 2^60) + 2^115 < 2^125
    FelemReduce(&result.z, &result.z);      // result.z[] < 2^64

    // Special case processing for infinity points
    PtAssignWithMask(&result, a, isZ2Zero);
    PtAssignWithMask(&result, b, isZ1Zero);
    PtAssign(out, &result);
}

/* Select the point with subscript index in the table and place it in the point. Anti-side channel process is exists. */
static inline void GetPointFromTable(Point *point, const Point table[], uint32_t pointNum, const uint32_t index)
{
    uint128_t mask;
    for (uint32_t i = 0; i < pointNum; i++) {
        /* If i is equal to index, the last mask is all Fs. Otherwise, the last mask is all 0s. */
        mask = (0 - (i ^ index)) >> 31;  // shifted rightwards by 31 bits and obtain the most significant bit.
        mask--;
        /* Conditional value assignment, valid only when i == index */
        PtAssignWithMask(point, &table[i], mask);
    }
}

/*
 * Input:
 *      k1 < n
 *      0 <= i < 32
 * Output:
 *      out->x < p, out->y < p, out->z = 0 或 1
 */
static inline void GetLowerPrecomputePtOfG(Point *out, const Felem *k1, int32_t curBit)
{
    uint32_t bits;
    uint32_t i = (uint32_t)curBit;

    bits = (uint32_t)(k1->data[0] >> i) & 1;          // i-bit of the lower half of the digit 0
    bits |= ((uint32_t)(k1->data[1] >> i) & 1) << 1;  // i-bit of the lower half of the digit 1
    bits |= ((uint32_t)(k1->data[2] >> i) & 1) << 2;  // i-bit of the lower half of the digit 2
    bits |= ((uint32_t)(k1->data[3] >> i) & 1) << 3;  // i-bit of the lower half of the digit 3

    GetPointFromTable(out, PRE_MUL_G, TABLE_G_SIZE, bits);
}

/*
 * Input:
 *      k1 < n
 *      0 <= i < 32
 * Output:
 *      out->x < p, out->y < p, out->z = 0 或 1
 */
static inline void GetUpperPrecomputePtOfG(Point *out, const Felem *k1, int32_t curBit)
{
    uint32_t bits;
    uint32_t i = (uint32_t)curBit;

    // i-bit of the upper half of the digit 0. (BASE_BITS/2) is the half width.
    bits = (uint32_t)(k1->data[0] >> (i + BASE_BITS / 2)) & 1;
    // i-bit of the upper half of the digit 1. (BASE_BITS/2) is the half width.
    bits |= ((uint32_t)(k1->data[1] >> (i + BASE_BITS / 2)) & 1) << 1;
    // i-bit of the upper half of the digit 2. (BASE_BITS/2) is the half width.
    bits |= ((uint32_t)(k1->data[2] >> (i + BASE_BITS / 2)) & 1) << 2;
    // i-bit of the upper half of the digit 3. (BASE_BITS/2) is the half width.
    bits |= ((uint32_t)(k1->data[3] >> (i + BASE_BITS / 2)) & 1) << 3;

    GetPointFromTable(out, PRE_MUL_G2, TABLE_G_SIZE, bits);
}

/*
 * Input:
 *      k2 < n
 *      0 <= i <= 255
 *      The coordinates of each point of preMulPt are reduced.
 * Output:
 *      out->x[] < 2^64, out->y[] < 2^64, out->z[] < 2^64
 */
static inline void GetPrecomputePtOfP(Point *out, const Felem *k2, int32_t curBit, const Point preMulPt[TABLE_P_SIZE])
{
    uint32_t bits;
    uint32_t sign, value;  // Indicates the grouping sign and actual value.
    Felem negY;
    // Obtain the 5-bit signed code. Read the sign bits of the next group of numbers
    // to determine whether there is a carry. The total length is 6.
    bits = (uint32_t)FelemGetBits(k2, curBit - 1, WINDOW_SIZE + 1);
    DecodeScalarCode(&sign, &value, bits);

    GetPointFromTable(out, preMulPt, TABLE_P_SIZE, value);

    FelemNeg(&negY, &out->y);
    FelemReduce(&negY, &negY);
    FelemAssignWithMask(&out->y, &negY, (uint128_t)0 - sign);
}

/*
 * Calculate k1 * G + k2 * P
 * Input:
 *      k1 < n
 *      k2 < n
 *      The coordinates of each point of preMulPt are reduced.
 * Output:
 *      out->x < p, out->y < p, out->z < p
 */
static void PtMul(Point *out, const Felem *k1, const Felem *k2, const Point preMulPt[TABLE_P_SIZE])
{
    Point ptQ = {};  // ptQ stores the result
    Point ptPre = {};  // ptPre stores the points obtained from the table.
    bool isGMul = k1 != NULL;
    bool isPtMul = k2 != NULL && preMulPt != NULL;
    int32_t curBit;

    // Initialize the Q point.
    if (isPtMul) {
        curBit = 255;  // Start from 255th bit.
        // Select the initial point from bit coding (_, _, _, _, 255, 254) of k2
        GetPrecomputePtOfP(&ptQ, k2, curBit, preMulPt);
    } else if (isGMul) {
        curBit = 31;  // Start from 31.
        // Select the initial point from bit coding (223, 159, 95, 31) of k1
        GetLowerPrecomputePtOfG(&ptQ, k1, curBit);
        // Select a precomputation point from the (223 + 32, 159 + 32, 95 + 32, 31 + 32) bit of k1
        // and add the precomputation point to the point Q
        GetUpperPrecomputePtOfG(&ptPre, k1, curBit);
        PtAddMixed(&ptQ, &ptQ, &ptPre);
    } else {
        // k1 and k2 are NULL, output the infinite point.
        (void)memset_s((void *)out, sizeof(Point), 0, sizeof(Point));
        return;
    }

    //     Operation chain:                                     Q point output range:
    //                                                        x[]         y[]         z[]
    //        Init value                                    < 2^64      < 2^64      < 2^64
    //            ↓
    //         double        ←↑                             < 2^64      < 2^64      < 2^64
    //            ↓           ↑
    //       mixed add        ↑                             < 2^64      < 2^64      < 2^64
    //            ↓           ↑
    //       mixed add       →↑                             < 2^64      < 2^64      < 2^64
    //            ↓           ↑
    // Y negation & reduction ↑                             < 2^64      < 2^64      < 2^64
    //            ↓           ↑
    //          add          →↑                             < 2^64      < 2^64      < 2^64

    while (--curBit >= 0) {
        // Start to shift right bit by bit. Because the most significant bit is initialized,
        // common point multiplication starts from 254th bit and base point multiplication starts from 30th bit.
        // Whether G-point multiplication is performed in the current cycle.
        // It is calculated once in each cycle starting from bit 31.
        bool isStepGMul = curBit <= 31;
        // Whether the current cycle is a common point multiplication, calculated once every 5 cycles
        bool isStepPtMul = curBit % WINDOW_SIZE == 0;

        PtDouble(&ptQ, &ptQ);

        // Generator G-point multiplication part.
        // Divide k1 into 8 segments, from high bits to low bits, select bits from each segment
        // and combine them together, then read the pre-computation table.
        // Specially, to shrink the precomputation table, the divided 8 segments are combined
        // according to the upper half and the lower half.
        if (isGMul && isStepGMul) {
            // Add the point multiplication result of the current bit of the eight-segment packet to the point Q
            GetLowerPrecomputePtOfG(&ptPre, k1, curBit);
            PtAddMixed(&ptQ, &ptQ, &ptPre);

            GetUpperPrecomputePtOfG(&ptPre, k1, curBit);
            PtAddMixed(&ptQ, &ptQ, &ptPre);
        }

        // Common point multiplication part.
        // Use the sliding window signed encoding method
        // to group the most significant bits to the least significant bits every five bits.
        // Each group of numbers is regarded as a signed number. 00000 to 01111 are decimal numbers 0 to 15,
        // and 10000 to 11111 are decimal numbers (32-16) to (32-1).
        // This is equivalent to the set of numbers in the complement form after carry 1.
        // for example:
        // 11011(complement) = 100000 - 00101
        if (isPtMul && isStepPtMul) {
            // Add the point multiplication result of the current group to point Q.
            GetPrecomputePtOfP(&ptPre, k2, curBit, preMulPt);
            PtAdd(&ptQ, &ptQ, &ptPre);
        }
    }

    // Output the modulo operation.
    FelemContract(&ptQ.x, &ptQ.x);
    FelemContract(&ptQ.y, &ptQ.y);
    FelemContract(&ptQ.z, &ptQ.z);

    PtAssign(out, &ptQ);
}

/*
 * Convert Jacobian coordinates to affine coordinates by a given module inverse
 * Input:
 *      in->x[] < 2^64, in->y[] < 2^64
 *      zInv < 2^64
 * Output:
 *      out->x < p, out->y < p, out->z = 1
 */
static void PtMakeAffineWithInv(Point *out, const Point *in, const Felem *zInv)
{
    Felem tmp;

    // 1/Z^2
    FelemSqrReduceToBase(&tmp, zInv);
    // X/Z^2
    FelemMulReduceToBase(&out->x, &in->x, &tmp);
    FelemContract(&out->x, &out->x);

    // 1/Z^3
    FelemMulReduceToBase(&tmp, &tmp, zInv);
    // Y/Z^3
    FelemMulReduceToBase(&out->y, &in->y, &tmp);
    FelemContract(&out->y, &out->y);

    FelemSetLimb(&out->z, 1);
}

/* --------------------------other functions-------------------------- */
/*
 * Obtain the pre-multiplication table of the input point pt, including 0pt-16pt. All points are reduced.
 */
static int32_t GetPreMulPt(Point preMulPt[TABLE_P_SIZE], const ECC_Point *pt)
{
    int32_t ret;

    // 0pt
    (void)memset_s((void *)&preMulPt[0], sizeof(Point), 0, sizeof(Point));
    // 1pt
    GOTO_ERR_IF_EX(BN2Felem(&preMulPt[1].x, &pt->x), ret);
    GOTO_ERR_IF_EX(BN2Felem(&preMulPt[1].y, &pt->y), ret);
    GOTO_ERR_IF_EX(BN2Felem(&preMulPt[1].z, &pt->z), ret);
    // 2pt ~ 15pt
    for (uint32_t i = 2; i < 15; i += 2) {
        PtDouble(&preMulPt[i], &preMulPt[i >> 1]);
        PtAdd(&preMulPt[i + 1], &preMulPt[i], &preMulPt[1]);
    }
    // 16pt
    PtDouble(&preMulPt[16], &preMulPt[16 >> 1]);
ERR:
    return ret;
}

int32_t ECP256_PointMulAdd(
    ECC_Para *para, ECC_Point *r, const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt)
{
    int32_t ret;
    Felem felemK1;
    Felem felemK2;
    Point preMulPt[TABLE_P_SIZE];
    Point out;

    // Check the input parameters.
    GOTO_ERR_IF(CheckParaValid(para, CRYPT_ECC_NISTP256), ret);
    GOTO_ERR_IF(CheckPointValid(r, CRYPT_ECC_NISTP256), ret);
    GOTO_ERR_IF(CheckBnValid(k1, FELEM_BITS), ret);
    GOTO_ERR_IF(CheckBnValid(k2, FELEM_BITS), ret);
    GOTO_ERR_IF(CheckPointValid(pt, CRYPT_ECC_NISTP256), ret);
    // Special treatment of infinity points
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }

    GOTO_ERR_IF_EX(BN2Felem(&felemK1, k1), ret);
    GOTO_ERR_IF_EX(BN2Felem(&felemK2, k2), ret);
    GOTO_ERR_IF_EX(GetPreMulPt(preMulPt, pt), ret);

    PtMul(&out, &felemK1, &felemK2, preMulPt);

    GOTO_ERR_IF_EX(Felem2BN(&r->x, &out.x), ret);
    GOTO_ERR_IF_EX(Felem2BN(&r->y, &out.y), ret);
    GOTO_ERR_IF_EX(Felem2BN(&r->z, &out.z), ret);
ERR:
    return ret;
}

int32_t ECP256_PointMul(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt)
{
    int32_t ret;
    Felem felemK;
    Point preMulPt[TABLE_P_SIZE];
    Point out;

    // Check the input parameters.
    GOTO_ERR_IF(CheckParaValid(para, CRYPT_ECC_NISTP256), ret);
    GOTO_ERR_IF(CheckPointValid(r, CRYPT_ECC_NISTP256), ret);
    GOTO_ERR_IF(CheckBnValid(k, FELEM_BITS), ret);
    if (pt != NULL) {
        GOTO_ERR_IF(CheckPointValid(pt, CRYPT_ECC_NISTP256), ret);
        // Special treatment of infinity points
        if (BN_IsZero(&pt->z)) {
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
            return CRYPT_ECC_POINT_AT_INFINITY;
        }
    }

    GOTO_ERR_IF_EX(BN2Felem(&felemK, k), ret);
    if (pt != NULL) {
        GOTO_ERR_IF_EX(GetPreMulPt(preMulPt, pt), ret);
        PtMul(&out, NULL, &felemK, preMulPt);
    } else {
        PtMul(&out, &felemK, NULL, NULL);
    }

    GOTO_ERR_IF_EX(Felem2BN(&r->x, &out.x), ret);
    GOTO_ERR_IF_EX(Felem2BN(&r->y, &out.y), ret);
    GOTO_ERR_IF_EX(Felem2BN(&r->z, &out.z), ret);
ERR:
    return ret;
}

int32_t ECP256_Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *pt)
{
    int32_t ret;
    Point out;
    Felem zInv;

    // Check the input parameters.
    GOTO_ERR_IF(CheckParaValid(para, CRYPT_ECC_NISTP256), ret);
    GOTO_ERR_IF(CheckPointValid(r, CRYPT_ECC_NISTP256), ret);
    GOTO_ERR_IF(CheckPointValid(pt, CRYPT_ECC_NISTP256), ret);
    // Special treatment of infinity points
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }

    GOTO_ERR_IF_EX(BN2Felem(&out.x, &pt->x), ret);
    GOTO_ERR_IF_EX(BN2Felem(&out.y, &pt->y), ret);
    GOTO_ERR_IF_EX(BN2Felem(&out.z, &pt->z), ret);

    FelemInv(&zInv, &out.z);
    PtMakeAffineWithInv(&out, &out, &zInv);

    GOTO_ERR_IF_EX(Felem2BN(&r->x, &out.x), ret);
    GOTO_ERR_IF_EX(Felem2BN(&r->y, &out.y), ret);
    GOTO_ERR_IF_EX(Felem2BN(&r->z, &out.z), ret);
ERR:
    return ret;
}

int32_t ECP256_ModOrderInv(const ECC_Para *para, BN_BigNum *r, const BN_BigNum *a)
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
    return ECP_ModOrderInv(para, r, a);
}

#endif /* defined(HITLS_CRYPTO_CURVE_NISTP256) && defined(HITLS_CRYPTO_NIST_USE_ACCEL) */

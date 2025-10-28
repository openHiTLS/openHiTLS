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
#if defined(HITLS_CRYPTO_CURVE_NISTP224) && defined(HITLS_CRYPTO_NIST_USE_ACCEL)

#include <stdbool.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_bn.h"
#include "crypt_ecc.h"
#include "ecc_local.h"
#include "ecc_utils.h"
#include "bsl_util_internal.h"

#ifndef __SIZEOF_INT128__
#error "This nistp224 implementation require the compiler support 128-bits integer."
#endif

/*  field element definition */
#define FELEM_BITS      224
#define FELEM_BYTES     28
#define LIMB_BITS       (sizeof(uint64_t) << 3)
#define LIMB_NUM        4
#define BASE_BITS       56
#define BASE_MASK       0x00ffffffffffffff
/* The pre-calculation table of the G table has 16 points. */
#define TABLE_G_SIZE    16
/* The pre-calculation table of the P table has 17 points. */
#define TABLE_P_SIZE    17

/*
 * field elements, stored as arrays, all represented in little endian.
 * Each element of the array is called a digit, and each digit represents an extended 2^56-number-system digit,
 * that is, Felem can be expressed as:
 * f_0 + f_1 * 2^56 + f_2 * 2^112 + f_3 * 2^168
 * LongFelem is the same, but twice the width of Felem.
 * It is used to store the result of multiplication of field elements.
 * Point is a point represented as a Jacobian coordinate
 */
typedef struct {
    uint64_t data[LIMB_NUM];
} Felem;

typedef struct {
    uint128_t data[LIMB_NUM * 2 - 1];
} LongFelem;

typedef struct {
    Felem x;
    Felem y;
    Felem z;
} Point;

/* ------------------------------------------------------------ */
/* ECP224 field order p, the value is 2^224 - 2^96 + 1, little endian. */
static const Felem FIELD_ORDER = {
    {0x0000000000000001, 0x00ffff0000000000, 0x00ffffffffffffff, 0x00ffffffffffffff}
};

/*
 * A pre-calculated table of the base point G, which contains the (X, Y, Z) coordinates of k*G
 *
 * PRE_MUL_G divides all bits into four equal parts.
 * index      Corresponding bit             value of k
 *   0             0 0 0 0         0     + 0     + 0     + 0
 *   1             0 0 0 1         0     + 0     + 0     + 1
 *   2             0 0 1 0         0     + 0     + 2^56  + 0
 *   3             0 0 1 1         0     + 0     + 2^56  + 1
 *   4             0 1 0 0         0     + 2^112 + 0     + 0
 *   5             0 1 0 1         0     + 2^112 + 0     + 1
 *   6             0 1 1 0         0     + 2^112 + 2^56  + 0
 *   7             0 1 1 1         0     + 2^112 + 2^56  + 1
 *   8             1 0 0 0         2^168 + 0     + 0     + 0
 *   9             1 0 0 1         2^168 + 0     + 0     + 1
 *  10             1 0 1 0         2^168 + 0     + 2^56  + 0
 *  11             1 0 1 1         2^168 + 0     + 2^56  + 1
 *  12             1 1 0 0         2^168 + 2^112 + 0     + 0
 *  13             1 1 0 1         2^168 + 2^112 + 0     + 1
 *  14             1 1 1 0         2^168 + 2^112 + 2^56  + 0
 *  15             1 1 1 1         2^168 + 2^112 + 2^56  + 1
 */
static const Point PRE_MUL_G[TABLE_G_SIZE] = {
    {
        {{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}},
        {{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}},
        {{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x003280d6115c1d21, 0x00c1d356c2112234, 0x007f321390b94a03, 0x00b70e0cbd6bb4bf}},
        {{0x00d5819985007e34, 0x0075a05a07476444, 0x00fb4c22dfe6cd43, 0x00bd376388b5f723}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x00fd9675666ebbe9, 0x00bca7664d40ce5e, 0x002242df8d8a2a43, 0x001f49bbb0f99bc5}},
        {{0x0029e0b892dc9c43, 0x00ece8608436e662, 0x00dc858f185310d0, 0x009812dd4eb8d321}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x006d3e678d5d8eb8, 0x00559eed1cb362f1, 0x0016e9a3bbce8a3f, 0x00eedcccd8c2a748}},
        {{0x00f19f90ed50266d, 0x00abf2b4bf65f9df, 0x00313865468fafec, 0x005cb379ba910a17}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x000641966cab26e3, 0x0091fb2991fab0a0, 0x00efec27a4e13a0b, 0x000499aa8a5f8ebe}},
        {{0x007510407766af5d, 0x0084d929610d5450, 0x0081d77aae82f706, 0x006916f6d4338c5b}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x00ea95ac3b1f15c6, 0x00086000905e82d4, 0x00dd323ae4d1c8b1, 0x00932b56be7685a3}},
        {{0x009ef93dea25dbbf, 0x0041665960f390f0, 0x00fdec76dbe2a8a7, 0x00523e80f019062a}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x00822fdd26732c73, 0x00a01c83531b5d0f, 0x00363f37347c1ba4, 0x00c391b45c84725c}},
        {{0x00bbd5e1b2d6ad24, 0x00ddfbcde19dfaec, 0x00c393da7e222a7f, 0x001efb7890ede244}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x004c9e90ca217da1, 0x00d11beca79159bb, 0x00ff8d33c2c98b7c, 0x002610b39409f849}},
        {{0x0044d1352ac64da0, 0x00cdbb7b2c46b4fb, 0x00966c079b753c89, 0x00fe67e4e820b112}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x00e28cae2df5312d, 0x00c71b61d16f5c6e, 0x0079b7619a3e7c4c, 0x0005c73240899b47}},
        {{0x009f7f6382c73e3a, 0x0018615165c56bda, 0x00641fab2116fd56, 0x0072855882b08394}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x000469182f161c09, 0x0074a98ca8d00fb5, 0x00b89da93489a3e0, 0x0041c98768fb0c1d}},
        {{0x00e5ea05fb32da81, 0x003dce9ffbca6855, 0x001cfe2d3fbf59e6, 0x000e5e03408738a7}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x00dab22b2333e87f, 0x004430137a5dd2f6, 0x00e03ab9f738beb8, 0x00cb0c5d0dc34f24}},
        {{0x00764a7df0c8fda5, 0x00185ba5c3fa2044, 0x009281d688bcbe50, 0x00c40331df893881}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x00b89530796f0f60, 0x00ade92bd26909a3, 0x001a0c83fb4884da, 0x001765bf22a5a984}},
        {{0x00772a9ee75db09e, 0x0023bc6c67cec16f, 0x004c1edba8b14e2f, 0x00e2a215d9611369}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x00571e509fb5efb3, 0x00ade88696410552, 0x00c8ae85fada74fe, 0x006c7e4be83bbde3}},
        {{0x00ff9f51160f4652, 0x00b47ce2495a6539, 0x00a2946c53b582f4, 0x00286d2db3ee9a60}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x0040bbd5081a44af, 0x000995183b13926c, 0x00bcefba6f47f6d0, 0x00215619e9cc0057}},
        {{0x008bc94d3b0df45e, 0x00f11c54a3694f6f, 0x008631b93cdfe8b5, 0x00e7e3f4b0982db9}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x00b17048ab3e1c7b, 0x00ac38f36ff8a1d8, 0x001c29819435d2c6, 0x00c813132f4c07e9}},
        {{0x002891425503b11f, 0x0008781030579fea, 0x00f5426ba5cc9674, 0x001e28ebf18562bc}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x009f31997cc864eb, 0x0006cd91d28b5e4c, 0x00ff17036691a973, 0x00f1aef351497c58}},
        {{0x00dd1f2d600564ff, 0x00dead073b1402db, 0x0074a684435bd693, 0x00eea7471f962558}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }
};

/*
 * A pre-calculated table of the base point G, which contains the (X, Y, Z) coordinates of k*G
 *
 * PRE_MUL_G2[] = PRE_MUL_G[] * 2^28
 * index      Corresponding bit                value of k
 *   0            0 0 0 0              0     + 0     + 0     + 0
 *   1            0 0 0 1              0     + 0     + 0     + 2^28
 *   2            0 0 1 0              0     + 0     + 2^84  + 0
 *   3            0 0 1 1              0     + 0     + 2^84  + 2^28
 *   4            0 1 0 0              0     + 2^140 + 0     + 0
 *   5            0 1 0 1              0     + 2^140 + 0     + 2^28
 *   6            0 1 1 0              0     + 2^140 + 2^84  + 0
 *   7            0 1 1 1              0     + 2^140 + 2^84  + 2^28
 *   8            1 0 0 0              2^196 + 0     + 0     + 0
 *   9            1 0 0 1              2^196 + 0     + 0     + 2^28
 *  10            1 0 1 0              2^196 + 0     + 2^84  + 0
 *  11            1 0 1 1              2^196 + 0     + 2^84  + 2^28
 *  12            1 1 0 0              2^196 + 2^140 + 0     + 0
 *  13            1 1 0 1              2^196 + 2^140 + 0     + 2^28
 *  14            1 1 1 0              2^196 + 2^140 + 2^84  + 0
 *  15            1 1 1 1              2^196 + 2^140 + 2^84  + 2^28
 */
static const Point PRE_MUL_G2[TABLE_G_SIZE] = {
    {
        {{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}},
        {{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}},
        {{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x009665266dddf554, 0x009613d78b60ef2d, 0x00ce27a34cdba417, 0x00d35ab74d6afc31}},
        {{0x0085ccdd22deb15e, 0x002137e5783a6aab, 0x00a141cffd8c93c6, 0x00355a1830e90f2d}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x001a494eadaade65, 0x00d6da4da77fe53c, 0x00e7992996abec86, 0x0065c3553c6090e3}},
        {{0x00fa610b1fb09346, 0x00f1c6540b8a4aaf, 0x00c51a13ccd3cbab, 0x0002995b1b18c28a}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x007874568e7295ef, 0x0086b419fbe38d04, 0x00dc0690a7550d9a, 0x00d3966a44beac33}},
        {{0x002b7280ec29132f, 0x00beaa3b6a032df3, 0x00dc7dd88ae41200, 0x00d25e2513e3a100}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x00924857eb2efafd, 0x00ac2bce41223190, 0x008edaa1445553fc, 0x00825800fd3562d5}},
        {{0x008d79148ea96621, 0x0023a01c3dd9ed8d, 0x00af8b219f9416b5, 0x00d8db0cc277daea}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x0076a9c3b1a700f0, 0x00e9acd29bc7e691, 0x0069212d1a6b0327, 0x006322e97fe154be}},
        {{0x00469fc5465d62aa, 0x008d41ed18883b05, 0x001f8eae66c52b88, 0x00e4fcbe9325be51}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x00825fdf583cac16, 0x00020b857c7b023a, 0x00683c17744b0165, 0x0014ffd0a2daf2f1}},
        {{0x00323b36184218f9, 0x004944ec4e3b47d4, 0x00c15b3080841acf, 0x000bced4b01a28bb}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x0092ac22230df5c4, 0x0052f33b4063eda8, 0x00cb3f19870c0c93, 0x0040064f2ba65233}},
        {{0x00fe16f0924f8992, 0x00012da25af5b517, 0x001a57bb24f723a6, 0x0006f8bc76760def}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x004a7084f7817cb9, 0x00bcab0738ee9a78, 0x003ec11e11d9c326, 0x00dc0fe90e0f1aae}},
        {{0x00cf639ea5f98390, 0x005c350aa22ffb74, 0x009afae98a4047b7, 0x00956ec2d617fc45}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x004306d648c1be6a, 0x009247cd8bc9a462, 0x00f5595e377d2f2e, 0x00bd1c3caff1a52e}},
        {{0x00045e14472409d0, 0x0029f3e17078f773, 0x00745a602b2d4f7d, 0x00191837685cdfbb}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x005b6ee254a8cb79, 0x004953433f5e7026, 0x00e21faeb1d1def4, 0x00c4c225785c09de}},
        {{0x00307ce7bba1e518, 0x0031b125b1036db8, 0x0047e91868839e8f, 0x00c765866e33b9f3}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x003bfece24f96906, 0x004794da641e5093, 0x00de5df64f95db26, 0x00297ecd89714b05}},
        {{0x00701bd3ebb2c3aa, 0x007073b4f53cb1d5, 0x0013c5665658af16, 0x009895089d66fe58}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x000fef05f78c4790, 0x002d773633b05d2e, 0x0094229c3a951c94, 0x00bbbd70df4911bb}},
        {{0x00b2c6963d2c1168, 0x00105f47a72b0d73, 0x009fdf6111614080, 0x007b7e94b39e67b0}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x00ad1a7d6efbe2b3, 0x00f012482c0da69d, 0x006b3bdf12438345, 0x0040d7558d7aa4d9}},
        {{0x008a09fffb5c6d3d, 0x009a356e5d9ffd38, 0x005973f15f4f9b1c, 0x00dcd5f59f63c3ea}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x00acf39f4c5ca7ab, 0x004c8071cc5fd737, 0x00c64e3602cd1184, 0x000acd4644c9abba}},
        {{0x006c011a36d8bf6e, 0x00fecd87ba24e32a, 0x0019f6f56574fad8, 0x00050b204ced9405}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }, {
        {{0x00ed4f1cae7d9a96, 0x005ceef7ad94c40a, 0x00778e4a3bf3ef9b, 0x007405783dc3b55e}},
        {{0x0032477c61b6e8c6, 0x00b46a97570f018b, 0x0091176d0a7e95d1, 0x003df90fbc4c7d0e}},
        {{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000}}
    }
};

/* --------------------------helper function-------------------------- */
/*
 * Convert big endian byte stream to Felem
 */
static void Bin2Felem(Felem *out, const uint8_t in[FELEM_BYTES])
{
    int32_t offset;
    for (int32_t i = LIMB_NUM - 1; i >= 0; --i) {
        offset = 7 * (LIMB_NUM - 1 - i);  // 56bits occupy 7 bytes.
        out->data[i] = ((uint64_t)in[offset + 0] << 48) |  // Byte 0 is shifted by 48 bits to the left.
                       ((uint64_t)in[offset + 1] << 40) |  // The 1st byte is shifted leftward by 40 bits.
                       ((uint64_t)in[offset + 2] << 32) |  // The 2nd byte is shifted leftward by 32 bits.
                       ((uint64_t)in[offset + 3] << 24) |  // The 3rd byte is shifted leftward by 24 bits.
                       ((uint64_t)in[offset + 4] << 16) |  // The 4th byte is shifted leftward by 16 bits.
                       ((uint64_t)in[offset + 5] << 8) |   // The 5th byte is shifted leftward by 8 bits.
                       ((uint64_t)in[offset + 6]);         // No shift is required for the 6th byte.
    }
}

/*
 * Convert Felem to big-endian byte stream
 * Input:
 *      in[] < 2^56
 * Output:
 *      the length of out is 28
 */
static void Felem2Bin(uint8_t out[FELEM_BYTES], const Felem *in)
{
    int32_t offset;
    for (int32_t i = LIMB_NUM - 1; i >= 0; --i) {
        offset = 7 * (LIMB_NUM - 1 - i);  // 56bits occupy 7 bytes.
        out[offset + 0] = (uint8_t)(in->data[i] >> 48);  // out[i + 0] get 48~55 bits
        out[offset + 1] = (uint8_t)(in->data[i] >> 40);  // out[i + 1] get 40~47 bits
        out[offset + 2] = (uint8_t)(in->data[i] >> 32);  // out[i + 2] get 32~39 bits
        out[offset + 3] = (uint8_t)(in->data[i] >> 24);  // out[i + 3] get 24~31 bits
        out[offset + 4] = (uint8_t)(in->data[i] >> 16);  // out[i + 4] get 16~23 bits
        out[offset + 5] = (uint8_t)(in->data[i] >> 8);   // out[i + 5] get 8~15 bits
        out[offset + 6] = (uint8_t)in->data[i];          // out[i + 6] get 0~7 bits
    }
}

/*
 * Convert BN to Felem
 * Output:
 *      out[] < 2^56
 */
static int32_t BN2Felem(Felem *out, const BN_BigNum *in)
{
    int32_t retVal;
    uint8_t bin[FELEM_BYTES];
    uint32_t len = FELEM_BYTES;

    GOTO_ERR_IF(BN_Bn2Bin(in, bin, &len), retVal);

    for (uint32_t i = 0; i < FELEM_BYTES; ++i) {
        bin[FELEM_BYTES - 1 - i] = i < len ? bin[len - 1 - i] : 0;
    }

    Bin2Felem(out, bin);
ERR:
    return retVal;
}

/*
 * Convert Felem to BN
 * Input:
 *      in[] < 2^56
 */
static int32_t Felem2BN(BN_BigNum *out, const Felem *in)
{
    int32_t retVal;
    uint8_t bin[FELEM_BYTES];

    Felem2Bin(bin, in);

    GOTO_ERR_IF(BN_Bin2Bn(out, bin, FELEM_BYTES), retVal);
ERR:
    return retVal;
}

/* ---------------------------field operation--------------------------- */
/*
 * Assignment
 */
static inline void FelemAssign(Felem *out, const Felem *in)
{
    out->data[0] = in->data[0];  // out->data[0] takes the value
    out->data[1] = in->data[1];  // out->data[1] takes the value
    out->data[2] = in->data[2];  // out->data[2] takes the value
    out->data[3] = in->data[3];  // out->data[3] takes the value
}

/*
 * Copy bits by mask. If the corresponding bit is 1, copy the bit. If the corresponding bit is 0, retain the bit.
 */
static inline void FelemAssignWithMask(Felem *out, const Felem *in, const uint64_t mask)
{
    uint64_t rmask = ~mask;
    out->data[0] = (in->data[0] & mask) | (out->data[0] & rmask);  // out->data[0] get a new value or remain unchanged.
    out->data[1] = (in->data[1] & mask) | (out->data[1] & rmask);  // out->data[1] get a new value or remain unchanged.
    out->data[2] = (in->data[2] & mask) | (out->data[2] & rmask);  // out->data[2] get a new value or remain unchanged.
    out->data[3] = (in->data[3] & mask) | (out->data[3] & rmask);  // out->data[3] get a new value or remain unchanged.
}

/*
 * Set the lowest digit
 */
static inline void FelemSetLimb(Felem *out, const uint64_t in)
{
    out->data[0] = in;  // out->data[0] takes the value
    out->data[1] = 0;   // out->data[1] clear to 0
    out->data[2] = 0;   // out->data[2] clear to 0
    out->data[3] = 0;   // out->data[3] clear to 0
}

/*
 * Zero judgment: is input less than(2^224 + 2^(16 + 192)). Only 0 and p need to be judged.
 * Input:
 *      in[] < 2^56 + 2^16
 *      - in[0] < 2^56
 *      - in[1] < 2^56
 *      - in[2] < 2^56
 *      - in[3] < 2^56 + 2^16
 */
static inline uint64_t FelemIsZero(const Felem *in)
{
    uint64_t isZero;
    uint64_t isP;

    // Check whether digits 0, 1, 2, and 3 of in are all 0.
    isZero = in->data[0] | in->data[1] | in->data[2] | in->data[3];
    isZero -= 1;  // If in == 0, the most significant bit is 1.

    // Determine that in is equal to the field order.
    isP = (in->data[0] ^ FIELD_ORDER.data[0]) |     // Determines whether the digits 0 are equal.
          (in->data[1] ^ FIELD_ORDER.data[1]) |     // Determines whether the digits 1 are equal.
          (in->data[2] ^ FIELD_ORDER.data[2]) |     // Determines whether the digits 2 are equal.
          (in->data[3] ^ FIELD_ORDER.data[3]);      // Determines whether the digits 3 are equal.
    isP -= 1;  // If in == p, the most significant bit is 1

    return (isZero | isP) >> (LIMB_BITS - 1);
}

/*
 * Obtain the bit string whose length is len at idx in Felem.
 * Input:
 *      in[i] < 2^56
 *      0 < len <= 64
 */
static uint64_t FelemGetBits(const Felem *in, int32_t idx, uint32_t len)
{
    uint64_t ret;
    uint32_t lower, upper;
    uint64_t mask;

    lower = (uint32_t)idx;
    // when 0 <= lower < 224, the most significant bit is 1. Obtain the most significant bit by right shifted by 31 bits
    mask = (uint64_t)0 - ((~lower & (lower - 224)) >> 31);
    ret = (in->data[(lower / BASE_BITS) & mask] & BASE_MASK & mask) >> (lower % BASE_BITS);

    upper = (uint32_t)idx + BASE_BITS;  // Next Unary Block
    // when 0 <= upper < 224, the most significant bit is 1. Obtain the most significant bit by right shifted by 31 bits
    mask = (uint64_t)0 - ((~upper & (upper - 224)) >> 31);
    ret |= (in->data[(upper / BASE_BITS) & mask] & BASE_MASK & mask) << (BASE_BITS - upper % BASE_BITS);

    ret &= ((uint64_t)1 << len) - 1;  // All 1s of the len length

    return ret;
}

/*
 * field element reduction, retain the lower 56 bits of each Limb in the 4-ary Felem,
 * perform reduction on the upper bits, and perform modulo operation to reduce all Limbs to [0, 2 ^ 56 + 2 ^ 7).
 * Input:
 *      in[] < 2^63
 * Output:
 *      out[] < 2^56 + 2^7
 *      - out[0] < 2^56
 *      - out[1] < 2^56
 *      - out[2] < 2^56
 *      - out[3] < 2^56 + 2^7
 */
static void FelemReduce(Felem *out, const Felem *in)
{
    uint64_t carryLimb = in->data[3] >> BASE_BITS;
    const uint64_t borrow = (uint64_t)1 << 56;
    const uint64_t lend = 1;

    // reduction carryLimb * (2^96 - 1), because it's the non-negative number, it must can be borrowed.
    // Calculate out->data[0]
    out->data[0] = in->data[0] + borrow - carryLimb;                                        // carryLimb * (-1)
    // Calculate out->data[1]
    out->data[1] = in->data[1] + (out->data[0] >> BASE_BITS) + (carryLimb << 40) - lend;    // carryLimb * 2^(56 + 40)
    // Calculate out->data[2]
    out->data[2] = in->data[2] + (out->data[1] >> BASE_BITS);
    // Calculate out->data[3]
    out->data[3] = (in->data[3] & BASE_MASK) + (out->data[2] >> BASE_BITS);                 // < 2^56 + 2^7

    out->data[0] &= BASE_MASK;  // out->data[0] Take the lower bits.
    out->data[1] &= BASE_MASK;  // out->data[1] Take the lower bits.
    out->data[2] &= BASE_MASK;  // out->data[2] Take the lower bits.
}

/*
 * field element reduction, convert 7-ary LongFelem to 4-ary Felem,
 * and modulo reduction to all Limbs to [0, 2 ^ 56 + 2 ^ 16)
 * Input:
 *      in[] < 2^126
 * Output:
 *      out[] < 2^56 + 2^16
 *      - out[0] < 2^56
 *      - out[1] < 2^56
 *      - out[2] < 2^56
 *      - out[3] < 2^56 + 2^16
 */
static void LongFelemReduce(Felem *out, const LongFelem *in)
{
    const uint128_t *pi = in->data;
    // p shifts left by 15
    static const LongFelem zeroBase = {
        {
            (((uint128_t)1 << 112) - ((uint128_t)1 << 96) + 1)    << 15,  // 2^127 - 2^111 + 2^15
            (((uint128_t)1 << 112) - ((uint128_t)1 << 56))        << 15,  // 2^127 - 2^71
            (((uint128_t)1 << 112) - ((uint128_t)1 << 56))        << 15,  // 2^127 - 2^71
            0,
            0,
            0,
            0,
        }
    };

    uint128_t lout[4] = {
        zeroBase.data[0] + pi[0],    // < 2^127 + 2^126 - 2^111 + 2^15
        zeroBase.data[1] + pi[1],    // < 2^127 + 2^126 - 2^71
        zeroBase.data[2] + pi[2],    // < 2^127 + 2^126 - 2^71
        pi[3]                        // < 2^126
    };
    uint128_t carryLimb = pi[4];      // < 2^126

    // n = n / a * (a - b) ≡ n / a * b (mod (a - b))
    // It can be obtained from the above formula:
    // 2^n = 2^(n - 128) - 2^(n - 224) (mod (2^224 - 2^96 + 1))
    //
    // The following equation can be listed:
    //   2^224 mod p
    // = 2^96 - 1
    //
    //   2^280 mod p
    // = 2^152 - 2^56
    //
    //   2^336 mod p
    // = 2^208 - 2^112

    // reduce pi[6] and obtain the part higher 16 bits.
    carryLimb += pi[6] >> 16;
    // lout[3], reduce pi[6], shift leftwards by 40 bits then truncate; reduce pi[5] and obtain the part higher 16 bits.
    lout[3] += ((pi[6] << 40) & BASE_MASK) + (pi[5] >> 16);
    // lout[2], reduce pi[5], leftshift by 40bit then truncate; reduce carryLimb, obtain the higher 16bits. reduce pi[6]
    lout[2] += ((pi[5] << 40) & BASE_MASK) + (carryLimb >> 16) - pi[6];
    // lout[1], reduce carryLimb, shift leftwards by 40 bits then truncate; reduce pi[5]
    lout[1] += ((carryLimb << 40) & BASE_MASK) - pi[5];
    // lout[0], reduce carryLimb
    lout[0] -= carryLimb;

    // Range after reduction:
    // carryLimb < 2^126 + 2^110
    // lout[3] < 2^126 + 2^56 + 2^110 < 2^127
    // lout[2] < (2^127 + 2^126 - 2^71) + 2^56 + (2^110 + 2^94) < 2^128
    // lout[1] < (2^127 + 2^126 - 2^71) + 2^56
    // lout[0] < 2^127 + 2^126 - 2^111 + 2^15 < 2^128

    // carry
    lout[3] += lout[2] >> BASE_BITS;   // lout[3] < 2^127 + 2^72 < 2^128
    carryLimb = lout[3] >> BASE_BITS;  // carryLimb < 2^72

    lout[2] &= BASE_MASK;   // lout[2] < 2^56
    lout[3] &= BASE_MASK;   // lout[3] < 2^56

    // reduce carryLimb
    // lout[2]，reduce carryLimb and obtain the part higher 16 bits.
    lout[2] += carryLimb >> 16;
    // lout[1]，reduce carryLimb, shift leftwards by 40 bits then truncate;
    lout[1] += (carryLimb << 40) & BASE_MASK;
    // lout[0]，reduce carryLimb
    lout[0] -= carryLimb;

    // Range after reduction:
    // lout[2] < 2^56 + 2^56
    // lout[1] < (2^127 + 2^126 - 2^71 + 2^56) + 2^56
    // lout[0] < 2^128

    // carry
    lout[1] += lout[0] >> BASE_BITS;            // lout[1] < (2^127 + 2^126 - 2^71 + 2^57 - 2^41) + 2^72
    lout[2] += lout[1] >> BASE_BITS;            // lout[2] < 2^57 + (2^71 + 2^70 + 2^16 - 2^15 + 1) < 2^72

    out->data[0] = (uint64_t)lout[0] & BASE_MASK;                         // out->data[0] < 2^56
    out->data[1] = (uint64_t)lout[1] & BASE_MASK;                         // out->data[1] < 2^56
    out->data[2] = (uint64_t)lout[2] & BASE_MASK;                         // out->data[2] < 2^56
    out->data[3] = (uint64_t)lout[3] + (uint64_t)(lout[2] >> BASE_BITS);  // out->data[3] < 2^56 + 2^16
}

/*
 * field element modulo in [0, p), call FelemReduce or LongFelemReduce in advance.
 * Input:
 *      in[] < 2^56 + 2^16
 *      - in[0] < 2^56
 *      - in[1] < 2^56
 *      - in[2] < 2^56
 *      - in[3] < 2^56 + 2^16
 * Output:
 *      out < p, out[i] < 2^56
 */
static void FelemContract(Felem *out, const Felem *in)
{
    Felem tmp = {{in->data[0], in->data[1], in->data[2], in->data[3] & BASE_MASK}};  // tmp[] < 2^56
    uint64_t carryLimb = in->data[3] >> BASE_BITS;                  // 0 or 1, because of in[3] < 2^56 + 2^16
    uint64_t mask;                                                  // Check the mask greater than or equal to p.

    const uint64_t lower40Mask = 0x000000ffffffffff;                // Lower 40-bit mask
    const uint64_t borrow = (uint64_t)1 << BASE_BITS;
    const uint64_t lend = 1;

    // Check whether tmp is greater than or equal to p. The upper 128 bits of p are all 1s and the lower 96 bits are 1.
    // If the upper 128 bits (digit 3, 2, and 1) are all 1s, the value is 1. Otherwise, the value is 0.
    mask = ((tmp.data[3] & tmp.data[2] & (tmp.data[1] | lower40Mask)) + 1) >> BASE_BITS;
    // If the lower 96 bits are not zero, the value is 1. Otherwise, the value is 0.
    mask &= (0 - ((tmp.data[1] & lower40Mask) | tmp.data[0])) >> (LIMB_BITS - 1);
    mask = 0 - mask;  // If tmp is greater than or equal to p, the value is 1. Otherwise, the value is 0.

    // reduce carryLimb or subtract p. Note that carryLimb and mask cannot be true at the same time.
    // p_0 = 0x0000000000000001
    tmp.data[0] = (tmp.data[0] ^ borrow) - carryLimb - (mask & FIELD_ORDER.data[0]);
    // p_1 = 0x00ffff0000000000
    tmp.data[1] += carryLimb << 40;      // reduction carryLimb * 2^(56 + 40)
    // If the value is less than p, remains unchanged. If it's greater than or equal to p, subtract 0x00ffff0000000000.
    // That is, the lower 40 bits remain unchanged, and other bits are set to 0.
    tmp.data[1] &= ~mask | lower40Mask;
    // Lend to the low bit: if reduce it, then 2^96 - 1 > 0, if minus p, then tmp[1] + tmp[0] > p_1 + p_2
    tmp.data[1] -= lend;

    // If the value is less than p, remains unchanged. If it's greater than or equal to p, subtract 0x00ffffffffffffff.
    // That is, set to 0.
    tmp.data[2] &= ~mask; // p_2 = 0x00ffffffffffffff

    // If the value is less than p, remains unchanged. If it's greater than or equal to p, subtract 0x00ffffffffffffff.
    // That is, set to 0.
    tmp.data[3] &= ~mask; // p_3 = 0x00ffffffffffffff

    // carry 0 -> 1 -> 2 -> 3
    out->data[0] = tmp.data[0] & BASE_MASK;                               // tmp.data[0] get the lower bits.
    out->data[1] = (tmp.data[1] += tmp.data[0] >> BASE_BITS) & BASE_MASK; // tmp.data[1] plus carry & get the lower bits
    out->data[2] = (tmp.data[2] += tmp.data[1] >> BASE_BITS) & BASE_MASK; // tmp.data[2] plus carry & get the lower bits
    out->data[3] = (tmp.data[3] += tmp.data[2] >> BASE_BITS) & BASE_MASK; // tmp.data[3] plus carry & get the lower bits
}

/*
 * field element negation(NOT)
 * Input:
 *      in[] <= 2^57 - 2^41 - 2^1
 * Output:
 *      out[] <= 2^57 + 2^1 + in[] < 2^64
 */
static inline void FelemNeg(Felem *out, const Felem *in)
{
    static const Felem zeroBase = {{
        (((uint64_t)1 << 56) + 1)                       << 1,
        (((uint64_t)1 << 56) - ((uint64_t)1 << 40) - 1) << 1,
        (((uint64_t)1 << 56) - 1)                       << 1,
        (((uint64_t)1 << 56) - 1)                       << 1,
    }};

    out->data[0] = zeroBase.data[0] - in->data[0];  // out->data[0] takes the value
    out->data[1] = zeroBase.data[1] - in->data[1];  // out->data[1] takes the value
    out->data[2] = zeroBase.data[2] - in->data[2];  // out->data[2] takes the value
    out->data[3] = zeroBase.data[3] - in->data[3];  // out->data[3] takes the value
}

/*
 * field Addition
 */
static inline void FelemAdd(Felem *out, const Felem *a, const Felem *b)
{
    out->data[0] = a->data[0] + b->data[0];  // out->data[0] takes the value
    out->data[1] = a->data[1] + b->data[1];  // out->data[1] takes the value
    out->data[2] = a->data[2] + b->data[2];  // out->data[2] takes the value
    out->data[3] = a->data[3] + b->data[3];  // out->data[3] takes the value
}

/*
 * field subtraction
 * Input:
 *      a[] < 2^64 - 2^60 - 2^4，b[] <= 2^60 - 2^44 - 2^4
 * Output:
 *      out[] <= 2^60 + 2^4 + a[] < 2^64
 */
static inline void FelemSub(Felem *out, const Felem *a, const Felem *b)
{
    static const Felem zeroBase = {{
        (((uint64_t)1 << 56) + 1)                       << 4,
        (((uint64_t)1 << 56) - ((uint64_t)1 << 40) - 1) << 4,
        (((uint64_t)1 << 56) - 1)                       << 4,
        (((uint64_t)1 << 56) - 1)                       << 4,
    }};

    out->data[0] = zeroBase.data[0] + a->data[0] - b->data[0];  // out->data[0] takes the value
    out->data[1] = zeroBase.data[1] + a->data[1] - b->data[1];  // out->data[1] takes the value
    out->data[2] = zeroBase.data[2] + a->data[2] - b->data[2];  // out->data[2] takes the value
    out->data[3] = zeroBase.data[3] + a->data[3] - b->data[3];  // out->data[3] takes the value
}

/*
 * field subtraction, input LongFelem directly.
 * Input:
 *      a[] < 2^128 - 2^124，b[] <= 2^124 - 2^68 - 2^52
 * Output:
 *      out[] <= 2^124 + a[] < 2^128
 */
static void LongFelemSub(LongFelem *out, const LongFelem *a, const LongFelem *b)
{
    // p shift left (8 + 56 * 3)
    static const LongFelem zeroBase = {{
        ((uint128_t)1 << 112)                                                   << 12,
        (((uint128_t)1 << 112) - ((uint128_t)1 << 56))                          << 12,
        (((uint128_t)1 << 112) - ((uint128_t)1 << 56))                          << 12,
        (((uint128_t)1 << 112) - ((uint128_t)1 << 56))                          << 12,
        (((uint128_t)1 << 112) - ((uint128_t)1 << 56) + 1)                      << 12,  // 1
        (((uint128_t)1 << 112) - ((uint128_t)1 << 56) - ((uint128_t)1 << 40))   << 12,  // -2^96
        (((uint128_t)1 << 112) - ((uint128_t)1 << 56))                          << 12,  // 2^224
    }};

    out->data[0] = zeroBase.data[0] + a->data[0] - b->data[0];  // out->data[0] takes the value
    out->data[1] = zeroBase.data[1] + a->data[1] - b->data[1];  // out->data[1] takes the value
    out->data[2] = zeroBase.data[2] + a->data[2] - b->data[2];  // out->data[2] takes the value
    out->data[3] = zeroBase.data[3] + a->data[3] - b->data[3];  // out->data[3] takes the value
    out->data[4] = zeroBase.data[4] + a->data[4] - b->data[4];  // out->data[4] takes the value
    out->data[5] = zeroBase.data[5] + a->data[5] - b->data[5];  // out->data[5] takes the value
    out->data[6] = zeroBase.data[6] + a->data[6] - b->data[6];  // out->data[6] takes the value
}

/*
 * field element magnification, input LongFelem directly.
 * Use only a small magnification factor to ensure that in[]*scalar does not overflow.
 */
static inline void LongFelemScale(LongFelem *out, const LongFelem *in, const uint32_t scalar)
{
    out->data[0] = in->data[0] * scalar;  // out->data[0] takes the value
    out->data[1] = in->data[1] * scalar;  // out->data[1] takes the value
    out->data[2] = in->data[2] * scalar;  // out->data[2] takes the value
    out->data[3] = in->data[3] * scalar;  // out->data[3] takes the value
    out->data[4] = in->data[4] * scalar;  // out->data[4] takes the value
    out->data[5] = in->data[5] * scalar;  // out->data[5] takes the value
    out->data[6] = in->data[6] * scalar;  // out->data[6] takes the value
}

/*
 * field element magnification
 * Use only a small magnification factor to ensure that in[]*scalar does not overflow.
 */
static inline void FelemScale(Felem *out, const Felem *in, const uint32_t scalar)
{
    out->data[0] = in->data[0] * scalar;  // out->data[0] takes the value
    out->data[1] = in->data[1] * scalar;  // out->data[1] takes the value
    out->data[2] = in->data[2] * scalar;  // out->data[2] takes the value
    out->data[3] = in->data[3] * scalar;  // out->data[3] takes the value
}

/*
 * field Multiplication
 * Input:
 *      a[] < 2^62, b[] < 2^62
 * output:
 *      out[] < a[] * b[] * 4 < 2^126
 *      - out[0] < 2^124
 *      - out[1] < 2^124 * 2
 *      - out[2] < 2^124 * 3
 *      - out[3] < 2^124 * 4
 *      - out[4] < 2^124 * 3
 *      - out[5] < 2^124 * 2
 *      - out[6] < 2^124
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

    uint128_t *po = out->data;
    const uint64_t *pa = a->data;
    const uint64_t *pb = b->data;

    po[0] = (uint128_t)pa[0] * pb[0];
    po[1] = (uint128_t)pa[0] * pb[1] + (uint128_t)pa[1] * pb[0];
    po[2] = (uint128_t)pa[0] * pb[2] + (uint128_t)pa[1] * pb[1] + (uint128_t)pa[2] * pb[0];
    po[3] = (uint128_t)pa[0] * pb[3] + (uint128_t)pa[1] * pb[2] + (uint128_t)pa[2] * pb[1] + (uint128_t)pa[3] * pb[0];
    po[4] =                            (uint128_t)pa[1] * pb[3] + (uint128_t)pa[2] * pb[2] + (uint128_t)pa[3] * pb[1];
    po[5] =                                                       (uint128_t)pa[2] * pb[3] + (uint128_t)pa[3] * pb[2];
    po[6] =                                                                                  (uint128_t)pa[3] * pb[3];
}

/*
 * field Square
 * Input:
 *      a[] < 2^62
 * output:
 *      out[] < a[] * a[] * 4 < 2^126
 *      - out[0] < 2^124
 *      - out[1] < 2^124 * 2
 *      - out[2] < 2^124 * 3
 *      - out[3] < 2^124 * 4
 *      - out[4] < 2^124 * 3
 *      - out[5] < 2^124 * 2
 *      - out[6] < 2^124
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

    const uint64_t *pa = a->data;

    uint64_t a1x2 = pa[1] << 1;
    uint64_t a2x2 = pa[2] << 1;

    out->data[0] = (uint128_t)pa[0] * pa[0];
    out->data[1] = (uint128_t)pa[0] * a1x2;
    out->data[2] = (uint128_t)pa[0] * a2x2 + (uint128_t)pa[1] * pa[1];
    out->data[3] = ((uint128_t)pa[0] * pa[3] + (uint128_t)pa[1] * pa[2]) << 1;
    out->data[4] = (uint128_t)pa[3] * a1x2 + (uint128_t)pa[2] * pa[2];
    out->data[5] = (uint128_t)pa[3] * a2x2;
    out->data[6] = (uint128_t)pa[3] * pa[3];
}

static inline void FelemMulReduce(Felem *out, const Felem *a, const Felem *b)
{
    LongFelem ltemp;
    FelemMul(&ltemp, a, b);
    LongFelemReduce(out, &ltemp);
}

static inline void FelemSqrReduce(Felem *out, const Felem *in)
{
    LongFelem ltemp;
    FelemSqr(&ltemp, in);
    LongFelemReduce(out, &ltemp);
}

/*
 * field element inversion
 * From Fermat's little theorem, in^(p - 2) = in^(-1) (mod p)
 * in^(-1) = in^(2^224 - 2^96 + 1 - 2) (mod p)
 * Input:
 *      in[i] < 2^63
 * Output:
 *      reduce(out[i])
 */
static void FelemInv(Felem *out, const Felem *in)
{
    Felem inE1, inE6, inE24, inE96;  //  inEx indicates in^(2^(0)+2^(1)+'''+2^(x-1))
    uint32_t i;

    //  Construct inE1
    FelemReduce(out, in);
    FelemAssign(&inE1, out);

    //  Construct inE2
    FelemSqrReduce(out, out);
    FelemMulReduce(out, out, &inE1);

    //  Construct inE4, and store it in inE6
    FelemAssign(&inE6, out);
    FelemSqrReduce(&inE6, &inE6);
    FelemSqrReduce(&inE6, &inE6);
    FelemMulReduce(&inE6, out, &inE6); //  inE6 is temporarily stored in inE4

    //  Construct in^6
    FelemSqrReduce(&inE6, &inE6);
    FelemSqrReduce(&inE6, &inE6);
    FelemMulReduce(&inE6, out, &inE6);

    //  Construct inE12
    FelemAssign(out, &inE6);
    for (i = 0; i < 6; ++i) {     //  Moves the out by 6 digits to the left.
        FelemSqrReduce(out, out);
    }
    FelemMulReduce(out, &inE6, out);

    //  Construct inE24
    FelemAssign(&inE96, out);
    for (i = 0; i < 12; ++i) {     //  Moves the out by 12 digits to the left.
        FelemSqrReduce(out, out);
    }
    FelemMulReduce(&inE24, &inE96, out);

    //  Construct inE48
    FelemAssign(out, &inE24);
    for (i = 0; i < 24; ++i) {     //  Moves the out by 24 digits to the left.
        FelemSqrReduce(out, out);
    }
    FelemMulReduce(out, &inE24, out);

    //  Construct inE96
    FelemAssign(&inE96, out);
    for (i = 0; i < 48; ++i) {    //  Moves the out by 48 digits to the left.
        FelemSqrReduce(out, out);
    }
    FelemMulReduce(&inE96, &inE96, out);

    //  Construct inE7, and store it in inE6
    FelemSqrReduce(&inE6, &inE6);
    FelemMulReduce(&inE6, &inE6, &inE1);

    //  Construct inE31, and store it in inE24
    for (i = 0; i < 7; ++i) {     //  Moves the inE24 by 7 digits to the left.
        FelemSqrReduce(&inE24, &inE24);
    }
    FelemMulReduce(&inE24, &inE6, &inE24);

    //  Construct inE127, and store it in inE24
    FelemAssign(out, &inE96);
    for (i = 0; i < 31; ++i) {    //  Moves the out by 31 digits to the left.
        FelemSqrReduce(out, out);
    }
    FelemMulReduce(&inE24, &inE24, out);

    // Move inE127 by 97 bits to the left and add inE97 to obtain inE(2^224 - 2^96 + 1 - 2)
    for (i = 0; i < 97; ++i) {    //  shifts inE24 to the left by 97 bits, and inE24 stores inE127.
        FelemSqrReduce(&inE24, &inE24);
    }
    FelemMulReduce(out, &inE96, &inE24);
}

/* --------------------------Point group operation-------------------------- */
static inline void PtAssignWithMask(Point *out, const Point *in, const uint64_t mask)
{
    FelemAssignWithMask(&out->x, &in->x, mask);
    FelemAssignWithMask(&out->y, &in->y, mask);
    FelemAssignWithMask(&out->z, &in->z, mask);
}

static inline void PtAssign(Point *out, const Point *in)
{
    FelemAssign(&out->x, &in->x);
    FelemAssign(&out->y, &in->y);
    FelemAssign(&out->z, &in->z);
}

/*
 * double the point
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
 *      in->x[] < 2^59, in->y[] < 2^61, in->z[] < 2^61
 * Output:
 *      reduce(out->x), reduce(out->y), out->z[] < 2^61
 */
static void PtDouble(Point *out, const Point *in)
{
    Felem delta, gamma, beta, alpha;
    Felem tmp, tmp2;
    LongFelem ltmp, ltmp2;

    // delta = Z^2
    FelemSqrReduce(&delta, &in->z);

    // gamma = Y^2
    FelemSqrReduce(&gamma, &in->y);

    // beta = X * gamma
    FelemMulReduce(&beta, &in->x, &gamma);

    // alpha = 3 * (X - delta) * (X + delta)
    FelemAdd(&tmp, &in->x, &delta);         // tmp[] < 2^59 + 2^57 < 2^60
    FelemScale(&tmp, &tmp, 3);              // tmp[] < 2^60 * 3 < 2^62
    FelemSub(&tmp2, &in->x, &delta);        // tmp2[] < 2^60 + 2^4 + 2^59 < 2^61
    FelemMulReduce(&alpha, &tmp, &tmp2);

    // X' = alpha^2 - 8 * beta
    FelemSqrReduce(&tmp, &alpha);           // alpha^2, tmp[] < 2^56 + 2^16
    FelemScale(&tmp2, &beta, 8);            // tmp2[] < (2^56 + 2^16) * 8 = 2^59 + 2^19
    FelemSub(&out->x, &tmp, &tmp2);         // xout[] < 2^60 + 2^4 + 2^56 + 2^16 < 2^61
    FelemReduce(&out->x, &out->x);          // xout[] < 2^56 + 2^7

    // Z' = (Y + Z)^2 - gamma - delta
    FelemAdd(&tmp, &in->y, &in->z);         // < 2^61 + 2^61 = 2^62
    FelemSqrReduce(&tmp, &tmp);             // (Y + Z)^2, tmp[] < 2^56 + 2^16
    FelemAdd(&tmp2, &gamma, &delta);        // (gamma + delta), tmp2[] < (2^56 + 2^16) * 2 = 2^57 + 2^17
    FelemSub(&out->z, &tmp, &tmp2);         // zout[] < 2^60 + 2^4 + 2^56 + 2^16 < 2^61

    // Y' = alpha * (4 * beta - X') - 8 * gamma^2
    FelemScale(&tmp, &beta, 4);             // tmp[] < (2^56 + 2^16) * 4 = 2^58 + 2^18
    FelemSub(&tmp, &tmp, &out->x);          // tmp[] < 2^60 + 2^4 + 2^58 + 2^18 < 2^61
    FelemMul(&ltmp, &alpha, &tmp);          // alpha * (4 * beta - X'), ltmp[] < 2^(61 * 2) * 4 = 2^124
    FelemSqr(&ltmp2, &gamma);               // gamma < 2^57, ltmp2[] < 2^(57 * 2) * 4 = 2^116
    LongFelemScale(&ltmp2, &ltmp2, 8);      // 8 * gamma^2, ltmp2[] < 2^116 * 8 = 2^119
    LongFelemSub(&ltmp, &ltmp, &ltmp2);     // ltmp[] < 2^124 + 2^124 < 2^125
    LongFelemReduce(&out->y, &ltmp);        // yout[] < 2^56 + 2^16
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
 *      a->x[] < 2^64, a->y[] < 2^64, a->z[] < 2^61
 *      reduce(b->x), b->y[] < 2^58, reduce(b->z)
 * Output:
 *      out->x[] < max(reduce(out->x), a->x[])
 *      out->y[] < max(reduce(out->y), a->y[], b->y[])
 *      out->z[] < max(reduce(out->z), a->z[])
 */
static void PtAdd(Point *out, const Point *a, const Point *b)
{
    Point result;
    Felem z1sqr, z2sqr, u1, u2, s1, s2, h, i, j, r, v;
    Felem tmp;
    LongFelem ltmp, ltmp2;
    uint64_t isZ1Zero, isZ2Zero;

    // Z1Z1 = Z1^2
    FelemSqrReduce(&z1sqr, &a->z);

    // Z2Z2 = Z2^2
    FelemSqrReduce(&z2sqr, &b->z);

    isZ1Zero = 0 - FelemIsZero(&z1sqr);
    isZ2Zero = 0 - FelemIsZero(&z2sqr);

    // U1 = X1 * Z2Z2
    FelemMulReduce(&u1, &a->x, &z2sqr);

    // U2 = X2 * Z1Z1
    FelemMulReduce(&u2, &b->x, &z1sqr);

    // S1 = Y1 * Z2 * Z2Z2
    FelemMulReduce(&s1, &b->z, &z2sqr);  // Z2 * Z2Z2
    FelemMulReduce(&s1, &a->y, &s1);

    // S2 = Y2 * Z1 * Z1Z1
    FelemMulReduce(&s2, &a->z, &z1sqr);  // Z1 * Z1Z1
    FelemMulReduce(&s2, &b->y, &s2);

    // H = U2 - U1
    FelemSub(&h, &u2, &u1);
    FelemReduce(&h, &h);

    // r = 2 * (S2 - S1)
    FelemSub(&r, &s2, &s1);
    FelemScale(&r, &r, 2);  // 2 * (S2 - S1)
    FelemReduce(&r, &r);

    // H and r can determine whether x and y of the affine coordinates of two points are equal.
    // If the values are equal, double the values.
    if (isZ1Zero == 0 && isZ2Zero == 0 && FelemIsZero(&h) != 0 && FelemIsZero(&r) != 0) {
        // Use the smaller b point
        PtDouble(out, b);
        return;
    }

    // I = (2 * H)^2
    FelemScale(&tmp, &h, 2);
    FelemSqrReduce(&i, &tmp);

    // J = H * I
    FelemMulReduce(&j, &h, &i);

    // V = U1 * I
    FelemMulReduce(&v, &u1, &i);

    // X3 = r^2 - (J + 2 * V)
    FelemSqrReduce(&result.x, &r);              // r^2
    FelemScale(&tmp, &v, 2);                    // tmp[] < (2^56 + 2^16) * 2 = 2^57 + 2^17
    FelemAdd(&tmp, &tmp, &j);                   // J + 2 * V, tmp[] < (2^57 + 2^17) + (2^56 + 2^16) < 2^58
    FelemSub(&result.x, &result.x, &tmp);       // result.x[] < (2^60 + 2^4) + (2^56 + 2^16) < 2^61
    FelemReduce(&result.x, &result.x);          // result.x[] < 2^56 + 2^7

    // Y3 = r * (V - X3) - 2 * S1 * J
    FelemSub(&tmp, &v, &result.x);              // tmp < (2^60 + 2^4) + (2^56 + 2^16) < 2^61
    FelemMul(&ltmp, &r, &tmp);                  // r * (V - X3), ltmp[] < 2^57 * 2^61 * 4 = 2^120
    FelemMul(&ltmp2, &s1, &j);                  // ltmp2[] < 2^57 * 2^57 * 4 = 2^116
    LongFelemScale(&ltmp2, &ltmp2, 2);          // 2 * S1 * J, ltmp2[] < 2^117
    LongFelemSub(&ltmp, &ltmp, &ltmp2);         // ltmp[] < 2^124 + 2^120 < 2^125
    LongFelemReduce(&result.y, &ltmp);          // result.y[] < 2^56 + 2^16

    // Z3 = ((Z1 + Z2)^2 - Z1Z1 - Z2Z2) * H
    FelemAdd(&result.z, &a->z, &b->z);          // Z1 + Z2, result.z[] < 2^61 + 2^57 < 2^62
    FelemSqrReduce(&result.z, &result.z);       // (Z1 + Z2)^2
    FelemAdd(&tmp, &z1sqr, &z2sqr);             // Z1Z1 + Z2Z2
    FelemSub(&result.z, &result.z, &tmp);       // ((Z1 + Z2)^2 - Z1Z1 - Z2Z2)
    FelemMulReduce(&result.z, &result.z, &h);   // result.z[] < 2^56 + 2^16

    // Special case processing for infinity points
    PtAssignWithMask(&result, a, isZ2Zero);
    PtAssignWithMask(&result, b, isZ1Zero);
    PtAssign(out, &result);
}

/*
 * mixed addition of point
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
 *      a->x[] <= 2^60 - 2^44 - 2^4, a->y[] <= 2^60 - 2^44 - 2^4, a->z[] < 2^61
 *      b->x < p, b->y < p, b->z = 0 or 1
 * Output:
 *      out->x[] < max(reduce(out->x), a->x[])
 *      out->y[] < max(reduce(out->y), a->y[])
 *      out->z[] < 2^61
 */
static void PtAddMixed(Point *out, const Point *a, const Point *b)
{
    Point result;
    Felem z1sqr, u2, s2, h, hsqr, i, j, r, v;
    Felem tmp;
    LongFelem ltmp, ltmp2;
    uint64_t isZ1Zero, isZ2Zero;

    // Z1Z1 = Z1^2
    FelemSqrReduce(&z1sqr, &a->z);

    isZ1Zero = 0 - FelemIsZero(&z1sqr);
    // The Z coordinate of point b can only be 0 or 1, that is, the bit 0 can only be 0 or 1, and the other bits are 0.
    isZ2Zero = b->z.data[0] - 1;

    // U2 = X2 * Z1Z1
    FelemMulReduce(&u2, &b->x, &z1sqr);

    // S2 = Y2 * Z1 * Z1Z1
    FelemMulReduce(&s2, &a->z, &z1sqr);  // Z1 * Z1Z1
    FelemMulReduce(&s2, &b->y, &s2);

    // H = U2 - X1
    FelemSub(&h, &u2, &a->x);
    FelemReduce(&h, &h);

    // r = 2 * (S2 - Y1)
    FelemSub(&r, &s2, &a->y);  // r[] < (2^60 + 2^4) + (2^56 + 2^16) < 2^61
    FelemScale(&r, &r, 2);     // r[] < 2^62
    FelemReduce(&r, &r);

    // H and r can determine whether x and y of the affine coordinates of two points are equal.
    // If they are equal, double the point.
    if (isZ1Zero == 0 && isZ2Zero == 0 && FelemIsZero(&h) != 0 && FelemIsZero(&r) != 0) {
        // Use the smaller b point
        PtDouble(out, b);
        return;
    }

    // HH = H^2
    FelemSqrReduce(&hsqr, &h);

    // I = 4 * HH
    FelemScale(&i, &hsqr, 4);  // i[] < (2^56 + 2^16) * 4 = 2^58 + 2^18

    // J = H * I
    FelemMulReduce(&j, &h, &i);

    // V = X1 * I
    FelemMulReduce(&v, &a->x, &i);

    // X3 = r^2 - J - 2 * V
    FelemSqrReduce(&result.x, &r);          // r^2
    FelemScale(&tmp, &v, 2);                // 2 * V, tmp[] < (2^56 + 2^16) * 2 = 2^57 + 2^17
    FelemAdd(&tmp, &j, &tmp);               // J + 2 * V, tmp[] < (2^56 + 2^16) + (2^57 + 2^17) < 2^58
    FelemSub(&result.x, &result.x, &tmp);   // result.x[] < (2^60 + 2^4) + (2^56 + 2^16) < 2^61
    FelemReduce(&result.x, &result.x);      // result.x[] < 2^56 + 2^7

    // Y3 = r * (V - X3) - 2 * Y1 * J
    FelemSub(&tmp, &v, &result.x);          // V - X3, tmp[] < (2^60 + 2^4) + (2^56 + 2^16) < 2^61
    FelemMul(&ltmp, &r, &tmp);              // r * (V - X3), ltmp[] < 2^57 * 2^61 * 4 = 2^120
    FelemMul(&ltmp2, &a->y, &j);            // Y1 * J, ltmp2[] < 2^61 * 2^57 * 4 = 2^120
    LongFelemScale(&ltmp2, &ltmp2, 2);      // 2 * Y1 * J, ltmp2[] < 2^120 * 2 = 2^121
    LongFelemSub(&ltmp, &ltmp, &ltmp2);     // ltmp[] < 2^124 + 2^120 < 2^125
    LongFelemReduce(&result.y, &ltmp);      // result.y[] < 2^56 + 2^16

    // Z3 = (Z1 + H)^2 - Z1Z1 - HH
    FelemAdd(&result.z, &a->z, &h);         // Z1 + H, result.z[] < 2^61 + (2^56 + 2^7) = 2^62
    FelemSqrReduce(&result.z, &result.z);
    FelemAdd(&tmp, &z1sqr, &hsqr);          // Z1Z1 + HH, tmp[] < (2^56 + 2^16) + (2^56 + 2^16) < 2^58
    FelemSub(&result.z, &result.z, &tmp);   // result.z[] < (2^60 + 2^4) + 2^58 < 2^61

    // Special case processing for infinity points
    PtAssignWithMask(&result, a, isZ2Zero);
    PtAssignWithMask(&result, b, isZ1Zero);
    PtAssign(out, &result);
}

/* Select the point that subscript is index in the table and place it in the Point *point.
   The anti-side channel processing exists. */
static inline void GetPointFromTable(Point *point, const Point table[], uint32_t pointNum, const uint32_t index)
{
    uint64_t mask;
    for (uint32_t i = 0; i < pointNum; i++) {
        /* If i is equal to index, the last mask is all Fs. Otherwise, the last mask is all 0s. */
        mask = (0 - (i ^ index)) >> 31;  // shifted rightwards by 31 bits to get the most significant bit
        mask--;
        /* Conditional value assignment, valid only when i == index */
        PtAssignWithMask(point, &table[i], mask);
    }
}

/*
 * Input:
 *      k1 < n
 *      0 <= i < 28
 * Output:
 *      out->x < p, out->y < p, out->z = 0 OR 1
 */
static inline void GetUpperPrecomputePtOfG(Point *out, const Felem *k1, int32_t curBit)
{
    uint32_t i = (uint32_t)curBit;
    uint32_t bits;

    // The i bit of the upper half of digit 0. (BASE_BITS/2) is half-wide.
    bits = (uint32_t)(k1->data[0] >> (i + BASE_BITS / 2)) & 1;
    // The i bit of the upper half of digit 1. (BASE_BITS/2) is half-wide.
    bits |= ((uint32_t)(k1->data[1] >> (i + BASE_BITS / 2)) & 1) << 1;
    // The i bit of the upper half of digit 2. (BASE_BITS/2) is half-wide.
    bits |= ((uint32_t)(k1->data[2] >> (i + BASE_BITS / 2)) & 1) << 2;
    // The i bit of the upper half of digit 3. (BASE_BITS/2) is half-wide.
    bits |= ((uint32_t)(k1->data[3] >> (i + BASE_BITS / 2)) & 1) << 3;

    GetPointFromTable(out, PRE_MUL_G2, TABLE_G_SIZE, bits);
}

/*
 * Input:
 *      k1 < n
 *      0 <= i < 28
 * Output:
 *      out->x < p, out->y < p, out->z = 0 or 1
 */
static inline void GetLowerPrecomputePtOfG(Point *out, const Felem *k1, int32_t curBit)
{
    uint32_t bits;
    uint32_t i = (uint32_t)curBit;

    bits = (uint32_t)(k1->data[0] >> i) & 1;          // The i bit of the lower half of digit 0.
    bits |= ((uint32_t)(k1->data[1] >> i) & 1) << 1;  // The i bit of the lower half of digit 1.
    bits |= ((uint32_t)(k1->data[2] >> i) & 1) << 2;  // The i bit of the lower half of digit 2.
    bits |= ((uint32_t)(k1->data[3] >> i) & 1) << 3;  // The i bit of the lower half of digit 3.

    GetPointFromTable(out, PRE_MUL_G, TABLE_G_SIZE, bits);
}

/*
 * Input:
 *      k2 < n
 *      0 <= i <= 220
 *      The coordinates of each point of preMulPt are reduced.
 * Output:
 *      reduce(out->x)
 *      out->y[] < max(reduce(out->y), negY)
 *      reduce(out->z)
 */
static inline void GetPrecomputePtOfP(Point *out, const Felem *k2, int32_t curBit, const Point preMulPt[TABLE_P_SIZE])
{
    uint32_t sign, value;  // the grouping sign and actual value.
    Felem negY;
    // Obtain the 5-bit signed code and read the sign bits of the next group of numbers
    // to determine whether there is a carry. The total length is 6.
    uint32_t bits = (uint32_t)FelemGetBits(k2, curBit - 1, WINDOW_SIZE + 1);
    DecodeScalarCode(&sign, &value, bits);

    GetPointFromTable(out, preMulPt, TABLE_P_SIZE, value);

    // out->y < 2^56 + 2^16
    FelemNeg(&negY, &out->y); // negY[] < (2^57 + 2^1) + (2^56 + 2^16) < 2^58
    FelemAssignWithMask(&out->y, &negY, (uint64_t)0 - sign);
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
    Point ptQ = {};  // ptQ stores result
    Point ptPre = {};  // ptPre stores the points obtained from the table.
    bool isGMul = k1 != NULL;
    bool isPtMul = k2 != NULL && preMulPt != NULL;
    int32_t curBit;

    // Initialize the Q point.
    if (isPtMul) {
        curBit = 220;  // Start from 220th bit.
        // From k2's (_, 223, 222, 221, 220, 219) bit coding to select the initial point
        GetPrecomputePtOfP(&ptQ, k2, curBit, preMulPt);
    } else if (isGMul) {
        curBit = 27;  // Start from 27th.
        // From k1's (195, 139, 83, 27) bit coding to select the initial point
        GetLowerPrecomputePtOfG(&ptQ, k1, curBit);
        // From k1's (195 + 28, 139 + 28, 83 + 28, 27 + 28) bit to select the pre-calculation point
        // and adds it to the point Q.
        GetUpperPrecomputePtOfG(&ptPre, k1, curBit);
        PtAddMixed(&ptQ, &ptQ, &ptPre);
    } else {
        // k1 and k2 are all NULL, and the infinite point is output.
        (void)memset_s((void *)out, sizeof(Point), 0, sizeof(Point));
        return;
    }

    // Operation chain：                     point Q output range:
    //                                        x[]         y[]         z[]
    // Initialization the value             reduced     reduced     < 2^61
    //     ↓
    //  Double           ←↑                 reduced     reduced     < 2^61
    //     ↓              ↑
    //  mixed add         ↑                 reduced     reduced     < 2^61
    //     ↓              ↑
    //  mixed add        →↑                 reduced     reduced     < 2^61
    //     ↓              ↑
    // negation of Y      ↑                 reduced     < 2^58      < 2^61
    //     ↓              ↑
    //    add            →↑                 reduced     < 2^58      < 2^61

    while (--curBit >= 0) {
        // Start to shift right bit by bit. Due to the initialization of the most significant bit,
        // common point multiplication starts from 219th bit and base point multiplication starts from 26th bit.
        // Whether G-point multiplication is performed in the current cycle,
        // calculated once in each cycle starting from bit 27.
        bool isStepGMul = curBit <= 27;
        // Whether the current cycle is a common point multiplication, calculated once every 5 cycles
        bool isStepPtMul = curBit % WINDOW_SIZE == 0;

        PtDouble(&ptQ, &ptQ);

        // Generator G multiplication part
        // Divide k1 into eight segments, from high bits to low bits,
        // select bits from each segment and combine them together, and read the pre-computation table.
        // To reduce the precomputation table,
        // the divided eight segments are combined according to the upper half and the lower half
        if (isGMul && isStepGMul) {
            // Add the point multiplication result of the current bit of the eight-segment to the point Q
            GetLowerPrecomputePtOfG(&ptPre, k1, curBit);
            PtAddMixed(&ptQ, &ptQ, &ptPre);

            GetUpperPrecomputePtOfG(&ptPre, k1, curBit);
            PtAddMixed(&ptQ, &ptQ, &ptPre);
        }

        // Common point multiplication part
        // Use the sliding window signed encoding method
        // to group the most significant bits to the least significant bits every five bits.
        // Each group of numbers is regarded as a signed number. 00000 to 01111 are decimal numbers 0 to 15,
        // and 10000 to 11111 are decimal numbers (32-16) to (32-1).
        // This is equivalent to the set the number in complement form after the number carries 1.
        // for example
        // 11011(Complement) = 100000 - 00101
        if (isPtMul && isStepPtMul) {
            // Add the point multiplication result of the current group to the point Q.
            GetPrecomputePtOfP(&ptPre, k2, curBit, preMulPt);
            PtAdd(&ptQ, &ptQ, &ptPre);
        }
    }

    // Refer to the output range of the operation chain. Reduce the Y and Z coordinates.
    FelemReduce(&ptQ.y, &ptQ.y);
    FelemReduce(&ptQ.z, &ptQ.z);
    // do the modulo operation then output.
    FelemContract(&ptQ.x, &ptQ.x);
    FelemContract(&ptQ.y, &ptQ.y);
    FelemContract(&ptQ.z, &ptQ.z);

    PtAssign(out, &ptQ);
}

/*
 * Convert Jacobian coordinates to affine coordinates by a given module inverse
 */
static void PtMakeAffineWithInv(Point *out, const Point *in, const Felem *zInv)
{
    Felem tmp;

    // 1/Z^2
    FelemSqrReduce(&tmp, zInv);

    // X/Z^2
    FelemMulReduce(&out->x, &in->x, &tmp);
    FelemContract(&out->x, &out->x);

    // 1/Z^3
    FelemMulReduce(&tmp, &tmp, zInv);

    // Y/Z^3
    FelemMulReduce(&out->y, &in->y, &tmp);
    FelemContract(&out->y, &out->y);

    FelemSetLimb(&out->z, 1);
}

/*
 * Obtain the pre-multiplication table of the input point pt, including 0pt-16pt.
 * The coordinates of all points are reduced.
 */
static int32_t GetPreMulPt(Point preMulPt[TABLE_P_SIZE], const ECC_Point *pt)
{
    int32_t ret;

    // 0pt
    (void)memset_s((void *)&preMulPt[0], sizeof(Point), 0, sizeof(Point));
    // 1pt
    ret = BN2Felem(&preMulPt[1].x, &pt->x);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    ret = BN2Felem(&preMulPt[1].y, &pt->y);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    ret = BN2Felem(&preMulPt[1].z, &pt->z);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    // 2pt ~ 15pt
    for (uint32_t i = 2; i < 15; i += 2) {
        PtDouble(&preMulPt[i], &preMulPt[i >> 1]);
        // Z coordinate after the doubled point is reduced.
        FelemReduce(&preMulPt[i].z, &preMulPt[i].z);

        PtAdd(&preMulPt[i + 1], &preMulPt[i], &preMulPt[1]);
    }
    // 16pt
    PtDouble(&preMulPt[16], &preMulPt[16 >> 1]);
    //  Z coordinate of the 16pt after the doubled point 16pt is reduced.
    FelemReduce(&preMulPt[16].z, &preMulPt[16].z);
ERR:
    return ret;
}

int32_t ECP224_PointMulAdd(
    ECC_Para *para, ECC_Point *r, const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt)
{
    int32_t retVal;
    Felem fK1;
    Felem fK2;
    Point preMulPt[TABLE_P_SIZE];
    Point out;

    // Check the input parameters.
    GOTO_ERR_IF(CheckParaValid(para, CRYPT_ECC_NISTP224), retVal);
    GOTO_ERR_IF(CheckPointValid(r, CRYPT_ECC_NISTP224), retVal);
    GOTO_ERR_IF(CheckBnValid(k1, FELEM_BITS), retVal);
    GOTO_ERR_IF(CheckBnValid(k2, FELEM_BITS), retVal);
    GOTO_ERR_IF(CheckPointValid(pt, CRYPT_ECC_NISTP224), retVal);
    // Special treatment of infinity points
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }

    GOTO_ERR_IF_EX(BN2Felem(&fK1, k1), retVal);
    GOTO_ERR_IF_EX(BN2Felem(&fK2, k2), retVal);
    GOTO_ERR_IF_EX(GetPreMulPt(preMulPt, pt), retVal);

    PtMul(&out, &fK1, &fK2, preMulPt);
    GOTO_ERR_IF_EX(Felem2BN(&r->x, &out.x), retVal);
    GOTO_ERR_IF_EX(Felem2BN(&r->y, &out.y), retVal);
    GOTO_ERR_IF_EX(Felem2BN(&r->z, &out.z), retVal);
ERR:
    return retVal;
}

int32_t ECP224_PointMul(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt)
{
    int32_t retVal;
    Felem felemK;
    Point preMulPt[TABLE_P_SIZE];
    Point out;

    // Check the input parameters.
    GOTO_ERR_IF(CheckParaValid(para, CRYPT_ECC_NISTP224), retVal);
    GOTO_ERR_IF(CheckPointValid(r, CRYPT_ECC_NISTP224), retVal);
    GOTO_ERR_IF(CheckBnValid(k, FELEM_BITS), retVal);
    if (pt != NULL) {
        GOTO_ERR_IF(CheckPointValid(pt, CRYPT_ECC_NISTP224), retVal);
        // Special treatment of infinity points
        if (BN_IsZero(&pt->z)) {
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
            return CRYPT_ECC_POINT_AT_INFINITY;
        }
    }

    GOTO_ERR_IF_EX(BN2Felem(&felemK, k), retVal);
    //  When pt is NULL, r = k * G
    if (pt == NULL) {
        PtMul(&out, &felemK, NULL, NULL);
    } else {   //  If pt is not null, r = k * pt
        GOTO_ERR_IF_EX(GetPreMulPt(preMulPt, pt), retVal);
        PtMul(&out, NULL, &felemK, preMulPt);
    }

    GOTO_ERR_IF_EX(Felem2BN(&r->x, &out.x), retVal);
    GOTO_ERR_IF_EX(Felem2BN(&r->y, &out.y), retVal);
    GOTO_ERR_IF_EX(Felem2BN(&r->z, &out.z), retVal);
ERR:
    return retVal;
}

int32_t ECP224_Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *pt)
{
    int32_t retVal;
    Point out;
    Felem zInv;

    // Check the input parameters.
    GOTO_ERR_IF(CheckParaValid(para, CRYPT_ECC_NISTP224), retVal);
    GOTO_ERR_IF(CheckPointValid(r, CRYPT_ECC_NISTP224), retVal);
    GOTO_ERR_IF(CheckPointValid(pt, CRYPT_ECC_NISTP224), retVal);
    // Special treatment of infinity points
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }

    GOTO_ERR_IF_EX(BN2Felem(&out.x, &pt->x), retVal);
    GOTO_ERR_IF_EX(BN2Felem(&out.y, &pt->y), retVal);
    GOTO_ERR_IF_EX(BN2Felem(&out.z, &pt->z), retVal);

    FelemInv(&zInv, &out.z);
    PtMakeAffineWithInv(&out, &out, &zInv);

    GOTO_ERR_IF_EX(Felem2BN(&r->x, &out.x), retVal);
    GOTO_ERR_IF_EX(Felem2BN(&r->y, &out.y), retVal);
    GOTO_ERR_IF_EX(Felem2BN(&r->z, &out.z), retVal);
ERR:
    return retVal;
}


#endif /* defined(HITLS_CRYPTO_CURVE_NISTP224) && defined(HITLS_CRYPTO_NIST_USE_ACCEL) */

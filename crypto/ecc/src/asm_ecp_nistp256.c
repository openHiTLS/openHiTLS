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

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "crypt_errno.h"
#include "crypt_bn.h"
#include "ecp_nistp256.h"
#include "crypt_ecc.h"
#include "ecc_local.h"
#include "bsl_err_internal.h"
#include "asm_ecp_nistp256.h"
#include "securec.h"

#if defined(HITLS_SIXTY_FOUR_BITS)
    // 1 is on the field with Montgomery, 1 * RR * R' mod P = R mod P = R - P
    static const Coord g_oneMont = {{
        0x0000000000000001,
        0xffffffff00000000,
        0xffffffffffffffff,
        0x00000000fffffffe
    }};
    static const Coord g_rrModP = {{
        0x0000000000000003,
        0xfffffffbffffffff,
        0xfffffffffffffffe,
        0x00000004fffffffd
    }};
#elif defined(HITLS_THIRTY_TWO_BITS)
    // 1 is on the field with Montgomery, 1 * RR * R' mod P = R mod P = R - P
    static const Coord g_oneMont = {{
        0x00000001,
        0x00000000,
        0x00000000,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xfffffffe,
        0x00000000
    }};
    static const Coord g_rrModP = {{
        0x00000003,
        0x00000000,
        0xffffffff,
        0xfffffffb,
        0xfffffffe,
        0xffffffff,
        0xfffffffd,
        0x00000004
    }};
#else
#error BN_UINT MUST be 4 or 8
#endif

// If the value is 0, all Fs are returned. If the value is not 0, 0 is returned.
static BN_UINT IsZero(const Coord *a)
{
    BN_UINT ret = a->value[0];
    for (uint32_t i = 1; i < P256_SIZE; i++) {
        ret |= a->value[i];
    }
    return BN_IsZeroUintConsttime(ret);
}

// r = cond == 0 ? r : a, the input parameter cond can only be 0 or 1.
// If cond is 0, the value remains unchanged. If cond is 1, copy a.
static void CopyConditional(Coord *r, const Coord *a, BN_UINT cond)
{
    BN_UINT mask1 = ~cond & (cond - 1);
    BN_UINT mask2 = ~mask1;

    for (uint32_t i = 0; i < P256_SIZE; i++) {
        r->value[i] = (r->value[i] & mask1) ^ (a->value[i] & mask2);
    }
}
#ifdef HITLS_CRYPTO_ECC_SMALL_FOOTPRINT

static const BN_UINT g_P256PreTable1[32][8] = {
    {0x18A9143C, 0x79E730D4, 0x5FEDB601, 0x75BA95FC, 0x77622510, 0x79FB732B, 0xA53755C6, 0x18905F76},
    {0xCE95560A, 0xDDF25357, 0xBA19E45C, 0x8B4AB8E4, 0xDD21F325, 0xD2E88688, 0x25885D85, 0x8571FF18},
    {0xA0BE5D0E, 0xF2675562, 0x4D1BB068, 0x4B524D25, 0xA9B75B8C, 0xBC2C5FF2, 0xD9A6F548, 0x4F326643},
    {0x1258835E, 0x50DD6844, 0x676090E0, 0x7D21BEEE, 0xF4A17B42, 0xB0B62C65, 0xB3CEC3B0, 0x60DFAE28},
    {0xB113F918, 0x531E7B64, 0x920A681D, 0x26B5D70A, 0x24C37044, 0x04E52F8F, 0xBB7C375B, 0xBC7C9542},
    {0xF2E26375, 0xB63A044B, 0xE922A3D0, 0xD842A342, 0xA9292D57, 0x9EED2ECA, 0x49AC7832, 0xFE27D2C2},
    {0x0B639942, 0xB0AB5401, 0x19379664, 0xA6E12F57, 0x1D040ABC, 0xC535F8B4, 0xA75EEF24, 0xEF255C54},
    {0xAECEB0EA, 0xB236F734, 0x9D879E2F, 0x38FCC8C1, 0x180CACAB, 0x674D8FDC, 0xF624DF06, 0x0A18BAD4},
    {0x60530D0A, 0x83FC8091, 0x7BC23DC8, 0x58C24F52, 0xA653AF5A, 0xECDE2F1F, 0xB10E511E, 0xB2E2A374},
    {0x9BEBE1E4, 0xF0C54B32, 0xADE42270, 0x239C25DF, 0x9F22B433, 0xD866F55E, 0xED17EFD3, 0x1E513CA2},
    {0xF5A32632, 0x4E066713, 0x4B36F498, 0x431F75D4, 0x70BD5F07, 0x40AE279F, 0x239EC23D, 0x252CDB93},
    {0x7312A246, 0xC18DDDF8, 0x23A9E561, 0x5B77673C, 0x1715FEDE, 0x020F09C3, 0xA580CFC5, 0xABEF6451},
    {0xC7F68782, 0x34DFBFC4, 0x08AC2685, 0x2C6A80D6, 0x08D0255B, 0x5479E1BC, 0x9110C616, 0x42EB9DE0},
    {0x10B4ACBA, 0x97991DD8, 0x94D997C7, 0xF36ACC8F, 0x69DDC036, 0xD05AD78B, 0xE68B4243, 0x1AC7E528},
    {0xA8636D07, 0x8E86CB3D, 0x2BE46DA2, 0xC79C42AC, 0xAA01E0E1, 0xED70E08A, 0xE3B69272, 0x773579FC},
    {0x4D8464C3, 0xBC0FE555, 0xCF54E071, 0x9E87A057, 0x3913B1D3, 0xDA655B0A, 0x9A55DBA4, 0x052774D4},
    {0xE37542CA, 0xB1F5C026, 0x72E01034, 0x0B860CF3, 0x025289F2, 0x3A7C10E4, 0x92901032, 0xD2197D5F},
    {0x267CA2F6, 0xFA06F835, 0xBF6E43AA, 0x8FCB9A29, 0x7ED9F8E7, 0x465F6C11, 0xE6077AAF, 0x8A50A5B3},
    {0x1D323961, 0x579345DF, 0x94CD3BC4, 0x45B79EAD, 0x423668D2, 0x50B664BE, 0x42BC26EA, 0x19DD5B75},
    {0x3677AE8F, 0xC7C1FBAA, 0x5D033158, 0x7B2E711A, 0x8942AC93, 0x8AECB50A, 0x8A16718C, 0xE255438B},
    {0x7972BCDF, 0x840DBCBF, 0xBD11900C, 0xB5C8444F, 0x16520CEE, 0x78B2B290, 0xBE88D914, 0xE19F13A3},
    {0x49D3C0DF, 0x052DDC89, 0xE0B4224B, 0xC9FC183C, 0xCF31E0BB, 0x2C8DD074, 0xA26B1441, 0x872C7B95},
    {0xCB22715E, 0x202E5C5A, 0x288F8243, 0x88E93D23, 0xDC7EACE6, 0xDF1D1F52, 0x373183F8, 0xC6B38B3B},
    {0x3EAC9C4B, 0x77798B7F, 0x6BFA9835, 0xA9D37DFF, 0xFAAC41C9, 0xAFF4A447, 0x0FCB6036, 0xF14FD13C},
    {0x300C0E39, 0xD6C8E4B7, 0x3E37F58A, 0x37AD4A1A, 0xE5E8CDFB, 0x763330F5, 0x870EA133, 0x62BF8C2C},
    {0x763CCAC9, 0x03FBC63A, 0xFB1886C0, 0xC889D8A5, 0xBE49D9FE, 0xF0486DE5, 0x62C23338, 0xAF9A8778},
    {0x3C2943FF, 0x121E6A71, 0x6374C47E, 0x0468565C, 0x2826F138, 0xD66FE993, 0x7748E3AC, 0x4E2CFAF1},
    {0x4708A6C8, 0xE9BAAA2C, 0x66FFB5B4, 0xA3845C8C, 0xB77C8FAC, 0xAD3E293E, 0x440A35E8, 0x00B5CFA9},
    {0x83E1A246, 0x3B446994, 0xF6B819A2, 0x11C5CED4, 0xAFF79A46, 0xC79D4660, 0x5F22411A, 0x423BBDC1},
    {0xA964039D, 0x22652251, 0xE738657B, 0x808D6753, 0x4E909DC8, 0xC0CA19E3, 0x34AB0D07, 0x0E036E47},
    {0x27EAFCC0, 0xBE47DD50, 0xEC7E66DB, 0x23DF1041, 0x78A4DDDD, 0x18C977FF, 0x9D2D152E, 0xB51565D7},
    {0x78F4A4DE, 0x24F6A6D5, 0x7D86B2CA, 0xBBC15B20, 0x1D3B43CA, 0xA064D39C, 0x52200839, 0x55248667}
};

static BN_UINT g_P256PreTable2[32][8] = {
    {0x879FBBED, 0xF2369F0B, 0xDA9D1869, 0x0FF0AE86, 0x56766F45, 0x5251D759, 0x2BE8D0FC, 0x4984D8C0},
    {0xD21008F0, 0x7ECC95A6, 0x3A1A1C49, 0x29BD54A0, 0xD26C50F3, 0xAB9828C5, 0x51D0D251, 0x32C0087C},
    {0xD22F29E5, 0x0B268F56, 0x7AB08B3B, 0x719EEC8A, 0x60D0130F, 0xAD161F7D, 0x2008F88B, 0xC7024EE5},
    {0x4B8BDFDA, 0x3749D68C, 0x3EE37D69, 0x4CB4F908, 0x9E465260, 0xB3C747DA, 0x7AAAADC9, 0x281B9078},
    {0x72507CC1, 0x3242C777, 0xB6E8F987, 0xBB765B9A, 0x228B3DC1, 0x5E91FBA5, 0x54DC2A2A, 0x730901A9},
    {0x828696AE, 0x6370A21D, 0x75646BFA, 0xCC2F4905, 0x237784F1, 0x01F114A0, 0x009A4C20, 0xF5F89CD0},
    {0x03303E3B, 0xA4D2DB97, 0xC1B2AAE9, 0xBBDB05DE, 0x55313BC8, 0x0B7733EB, 0x8A3A23E6, 0x687D086A},
    {0x25B2C566, 0x8A33CFA4, 0x49D49C37, 0x43A3E99A, 0x9FD87530, 0x0919B0FE, 0xA82C4B51, 0x199C937F},
    {0xF4D94635, 0x3E4F0526, 0x45E58E46, 0xE188E72D, 0xE4CEDA38, 0x02F92BC3, 0xAA4B33D5, 0x1A92AEA7},
    {0x866C03CA, 0x1A438EF9, 0xA7BF988E, 0x69169768, 0x74A9567E, 0x1CB2E6D3, 0x3580C528, 0xDBDEDD90},
    {0xD579C0FC, 0x69555846, 0x6D84F2A2, 0xC85D836E, 0xEA9DC9DC, 0x011C08ED, 0xBD603A5A, 0x04E67DA8},
    {0x291E5A86, 0x86FE81E5, 0x3B2F8734, 0x90A02FA1, 0x18BCBB29, 0xCFEF077C, 0x9439214A, 0x76874965},
    {0x6FD3B088, 0x530FD801, 0x3DFFB8A6, 0x2F275D20, 0x8206C863, 0x80F114AF, 0x30D71D8B, 0x99E6CB82},
    {0x05951494, 0x1D9D0D66, 0xF5103EEF, 0xD58D1195, 0x0EB40C4D, 0x9CC0DED8, 0xD9F91EE2, 0x159D671D},
    {0x9F735CF1, 0xD167DC63, 0x49C000C4, 0xB500AB70, 0x8855D474, 0xFB87877B, 0xD573CD41, 0xAFFE8C2E},
    {0x2E2C9D16, 0x54466F46, 0x6431737F, 0x8E26FC02, 0x4132C46E, 0x16949E17, 0x24DBC94A, 0x15F08BD6},
    {0x7D5B7F06, 0x135642E1, 0xBB317C9C, 0x23E3F419, 0xA9AB3DC8, 0x1BA92F6B, 0x06306027, 0x5522405F},
    {0xB64C41A3, 0x9D43CDA2, 0x3B7AA075, 0x7641AE10, 0x8C127B54, 0xD229A5AF, 0x05A5988F, 0x8229BD57},
    {0xD06D0A87, 0x1A79DC7D, 0xDFC0B72E, 0xFA2F7833, 0x64F09BE1, 0x2736B5A9, 0xABB29A1D, 0xAE3C9A8F},
    {0x115A58C1, 0x46529D35, 0xF9D1AD2C, 0xBC95E4E0, 0xD3B8F0EF, 0xB3712870, 0x8B5A559E, 0xF9AF6B96},
    {0x68DDD750, 0x51C331F9, 0x52CD7E0F, 0xC295A734, 0x7D1C2CED, 0xC823583E, 0x35F6CDDA, 0x46B45733},
    {0x72424DA2, 0x29175E1E, 0xB844983B, 0x54EA9F95, 0x93590D28, 0x493EA1E8, 0x1E8BE02A, 0x042AE28B},
    {0xE1CEB7C2, 0x258BAC66, 0x4DAC8CBB, 0xF4259758, 0xE92EBB1A, 0xD50983F2, 0xCA2AE0D0, 0xBF120E4E},
    {0x55CD49CD, 0xA3E7617E, 0x71519648, 0xFD5B07FF, 0xAFD703ED, 0xDAAE5103, 0x4172130C, 0xB040AD2E},
    {0xB56E4851, 0xA44E8DF6, 0x5098DE84, 0x03AF7EC9, 0x04AB4AB1, 0xBAD114C5, 0xDC7F874F, 0x1E580877},
    {0x26B4F612, 0xF3789204, 0x1457C827, 0xFA91B824, 0x75180CAB, 0x38F9A52C, 0x434E8BD0, 0x809DEEC3},
    {0x8A92C081, 0x6C6A83EF, 0xE838637D, 0x407FB0A9, 0x9ACBC6DC, 0xCF209F0B, 0x8CDABE07, 0xE77A8729},
    {0x2944ED0D, 0x93F7910F, 0x00AAFA33, 0xA14A1F63, 0x796111CC, 0x64619B60, 0x114C6685, 0xF0A78CFE},
    {0xB8F6993B, 0x51853136, 0x99F6300D, 0x17757FDD, 0xCD3B39D4, 0xA71459A4, 0x7A7B100E, 0x3C9243C7},
    {0x7B8E2675, 0x65F45BAA, 0x2C6F3386, 0x27A2701C, 0xC5A639E2, 0xFC4965A0, 0x50DA7A2D, 0xD8B38CE4},
    {0xF9ACA1B3, 0xD4C30E05, 0xA5EFC245, 0x038F18B6, 0x4780D032, 0xAB58BAA7, 0xBDF44DC7, 0x64E42435},
    {0x899537D0, 0x6156AF9B, 0x31841CB5, 0x8C35EE88, 0x61452838, 0xAEEDA2F0, 0xB6A1E175, 0x388434B4}
};

static const BN_UINT g_p256P[P256_SIZE] __attribute__((aligned(16))) = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
};

static const BN_UINT g_P256N[P256_SIZE] __attribute__((aligned(16))) = {
    0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
    0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF,
};

#define P256_COMB_SIZE 5
#define P256_COMB_WIDTH ((256 + P256_COMB_SIZE - 1) / P256_COMB_SIZE) // ⌈256/5⌉ == 52

// (index) / 32 -> Locate to a specific block, such as 3-th.
// i % 32, check the i-th bit of the 3-th block.
#define GetBits(buf, idx) (((buf)[(idx) / 32] >> ((idx) % 32)) & 1)

/*
 * ref <A comb method to render ECC resistant against Side Channel Attacks> section 4.2.1
 *
 * Coding Example:
 *   8  7  6  5  4  3  2  1  0
 * ( 1  0  1  1  0  0  1  0  1 ) = 2^0 + 2^2 + 2^5 + 2^6 + 2^8
 *
 * Set window = 3
 * step 1. obtain an original comb-table with window = 3, encoded into 9/3 = 3 blocks
 * |  6-th bit   3-th bit   0-th bit  |            |  1  0  1  |
 * |  7-th bit   4-th bit   1-th bit  | -------->  |  0  0  0  |
 * |  8-th bit   5-th bit   2-th bit  |            |  1  1  1  |
 *
 * step 2. Encode each row of the original comb table as odd (the last bit is always 1),
 * if the second row borrows from the first row, the sign bit is set to 1.
 *    [sign]                                                  [sign]
 * |    0     1  0  1  | => 2^0 + 2^2                     |     1     1  0  1  |  => - 2^0 - 2^2 (is borrowed)
 * |    0     0  0  0  | =>                   -------->   |     0     1  0  1  |  =>  2^1 + 2^3
 * |    0     1  1  1  | => 2^5 + 2^6 + 2^8               |     0     1  1  1  |  =>  2^5 + 2^6 + 2^8 (Remain unchanged)
 */
static void ECP_P256CombRecode(uint8_t recode[], const BN_UINT m[])
{
    BN_UINT index = 0;
    // step 1. Obtain the original comb table
    for (BN_UINT i = 0; i < P256_COMB_WIDTH; i++) {
        for (BN_UINT j = 0; j < P256_COMB_WIDTH; j++) {
            index = i + P256_COMB_WIDTH * j;
            if (index < 256) { // 256/5 -> The blocks-num is rounded up, which may result in the bits greater than 256.
                recode[i] |= GetBits(m, index) << j;
            }
        }
    }
    // Encode into an odd comb table
    uint8_t carry = 0;
    uint8_t tmp, adjust;

    for (BN_UINT i = 1; i <= P256_COMB_WIDTH; i++) {
        tmp = recode[i] & carry; // If there is a carry from the previous layer
        recode[i] = recode[i] ^ carry;
        carry = tmp;
        adjust = 1 - (recode[i] & 0x01);
        // Check whether the current block is an odd number. The adjust = 0: odd, adjust = 1: even.
        carry |= recode[i] & (recode[i - 1] * adjust);
        recode[i] = recode[i] ^ (recode[i - 1] * adjust); // recode[i] and recode[i - 1] do binary addition.
        recode[i - 1] |= adjust << 7; // If the low bit is borrowed, <<7 can set the highest bit to 1 for marked.
    }
}

#define P256_MASK 0x7Fu

static void ECP_P256ConstSelect(BN_UINT z[P256_SIZE], const BN_UINT x[P256_SIZE], BN_UINT mask)
{
    const BN_UINT rmask = -mask;
    for (BN_UINT i = 0; i < P256_SIZE; i++) {
        z[i] = (z[i] & ~rmask) | (x[i] & rmask);
    }
}

static void ECP_P256SelectPoint(P256_AffinePoint *R, const BN_UINT table[][P256_SIZE], uint8_t i)
{
    BN_UINT tmp[P256_SIZE] __attribute__((aligned(P256_BYTES)));
    uint8_t index = (i & P256_MASK) >> 1;
    (void)memcpy_s(R->x.value, sizeof(tmp), table[index * 2], sizeof(tmp)); // *2: represent the y-coordinate.
    (void)memcpy_s(R->y.value, sizeof(tmp), table[index * 2 + 1], sizeof(tmp));
    ECP_P256SubModP(tmp, g_p256P, R->y.value); // Take the negative point
    ECP_P256ConstSelect(R->y.value, tmp, i >> 7); // 1 << 7: Determine whether to take the negative.
}

static BN_UINT g_one[P256_SIZE] = {1};
static int32_t P256IsOne(const BN_UINT x[P256_SIZE])
{
    return memcmp(x, g_one, sizeof(g_one)) == 0;
}

static int P256Cmp(const BN_UINT a[P256_SIZE], const BN_UINT b[P256_SIZE])
{
    int i;
    for (i = P256_SIZE - 1; i >= 0; i--) {
        if (a[i] > b[i]) {
            return 1;
        } else if (a[i] < b[i]) {
            return -1;
        }
    }
    return 0;
}

static const BN_UINT g_orderHalfCeil[P256_SIZE] __attribute__((aligned(16))) = {
    0x7e3192a9, 0x79dce561, 0xd38bcf42, 0xde737d56,
    0xffffffff, 0x7fffffff, 0x80000000, 0x7fffffff
};

static void ECP256_InvModN(uint32_t z[P256_SIZE], const uint32_t x[P256_SIZE])
{
    BN_UINT u[P256_SIZE] __attribute__((aligned(P256_BYTES)));
    BN_UINT v[P256_SIZE] __attribute__((aligned(P256_BYTES)));
    BN_UINT x1[P256_SIZE] __attribute__((aligned(P256_BYTES))) = {1, 0, 0, 0};
    BN_UINT x2[P256_SIZE] __attribute__((aligned(P256_BYTES))) = {0};
    (void)memcpy_s(u, sizeof(u), x, sizeof(BN_UINT) * P256_SIZE);
    (void)memcpy_s(v, sizeof(v), g_P256N, sizeof(BN_UINT) * P256_SIZE);

    while (P256IsOne(u) == 0 && P256IsOne(v) == 0) {
        while (u[0] % 2 == 0) { // Check if it is divisible by 2.
            ECP_P256BnRshift1(u);
            if (x1[0] % 2 == 0) { // Check if it is divisible by 2.
                ECP_P256BnRshift1(x1);
            } else {
                ECP_P256BnRshift1(x1);
                ECP_P256AddModN(x1, x1, g_orderHalfCeil);
            }
        }
        while (v[0] % 2 == 0) { // Check if it is divisible by 2.
            ECP_P256BnRshift1(v);
            if (x2[0] % 2 == 0) { // Check if it is divisible by 2.
                ECP_P256BnRshift1(x2);
            } else {
                ECP_P256BnRshift1(x2);
                ECP_P256AddModN(x2, x2, g_orderHalfCeil);
            }
        }
        if (P256Cmp(u, v) >= 0) {
            ECP_P256SubModN(u, u, v);
            ECP_P256SubModN(x1, x1, x2);
        } else {
            ECP_P256SubModN(v, v, u);
            ECP_P256SubModN(x2, x2, x1);
        }
    }
    if (P256IsOne(u) != 0) {
        (void)memcpy_s(z, sizeof(BN_UINT) * P256_SIZE, x1, sizeof(x1));
    } else {
        (void)memcpy_s(z, sizeof(BN_UINT) * P256_SIZE, x2, sizeof(x2));
    }
}

static const BN_UINT g_polyHalfCeil[P256_SIZE] __attribute__((aligned(16))) = {
    0x00000000, 0x00000000, 0x80000000, 0x00000000,
    0x00000000, 0x80000000, 0x80000000, 0x7fffffff
};

static void ECP256_InvModP(uint32_t z[P256_SIZE], const uint32_t x[P256_SIZE])
{
    BN_UINT u[P256_SIZE] __attribute__((aligned(P256_BYTES)));
    BN_UINT v[P256_SIZE] __attribute__((aligned(P256_BYTES)));
    BN_UINT x1[P256_SIZE] __attribute__((aligned(P256_BYTES))) = {1, 0, 0, 0};
    BN_UINT x2[P256_SIZE] __attribute__((aligned(P256_BYTES))) = {0};
    (void)memcpy_s(u, sizeof(u), x, sizeof(u));
    (void)memcpy_s(v, sizeof(v), g_p256P, sizeof(v));

    while (P256IsOne(u) == 0 && P256IsOne(v) == 0) {
        while (u[0] % 2 == 0) { // Check if it is divisible by 2.
            ECP_P256BnRshift1(u);
            if (x1[0] % 2 == 0) { // Check if it is divisible by 2.
                ECP_P256BnRshift1(x1);
            } else {
                ECP_P256BnRshift1(x1);
                ECP_P256AddModP(x1, x1, g_polyHalfCeil);
            }
        }
        while (v[0] % 2 == 0) { // Check if it is divisible by 2.
            ECP_P256BnRshift1(v);
            if (x2[0] % 2 == 0) { // Check if it is divisible by 2.
                ECP_P256BnRshift1(x2);
            } else {
                ECP_P256BnRshift1(x2);
                ECP_P256AddModP(x2, x2, g_polyHalfCeil);
            }
        }
        if (P256Cmp(u, v) >= 0) {
            ECP_P256SubModP(u, u, v);
            ECP_P256SubModP(x1, x1, x2);
        } else {
            ECP_P256SubModP(v, v, u);
            ECP_P256SubModP(x2, x2, x1);
        }
    }
    if (P256IsOne(u) == 1) {
        (void)memcpy_s(z, sizeof(BN_UINT) * P256_SIZE, x1, sizeof(x1));
    } else {
        (void)memcpy_s(z, sizeof(BN_UINT) * P256_SIZE, x2, sizeof(x2));
    }
}

#else
// Jacobian affine -> Jacobian projection, (X,Y)->(X,Y,Z)
static void Affine2Jproj(P256_Point *r, const P256_AffinePoint *a, BN_UINT mask)
{
    for (uint32_t i = 0; i < P256_SIZE; i++) {
        r->x.value[i] = a->x.value[i] & mask;
        r->y.value[i] = a->y.value[i] & mask;
        r->z.value[i] = g_oneMont.value[i] & mask;
    }
}

// r = a^-1 mod p = a^(p-2) mod p
// p-2 = 0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffd
static void ECP256_ModInverse(Coord *r, const Coord *a)
{
    // a^(0x3), a^(0xc) = a^(0b1100), a^(0xf), a^(0xf0), a^(0xff)
    // a^(0xff00), a^(0xffff), a^(0xffff0000), a^(0xffffffff)
    Coord a3, ac, af, af0, a2f, a2f20, a4f, a4f40, a8f, ans;
    uint32_t i;
    // 0x3 = 0b11 = 0b10 + 0b01
    ECP256_Sqr(&a3, a);                 // a^2
    ECP256_Mul(&a3, &a3, a);            // a^3 = a^2 * a
    // 0xf = 0b1111 = 0b1100 + 0b11, 0b11->0b1100 requires *4, and the exponent*4(2^2) requires twice square operations
    ECP256_Sqr(&af, &a3);               // a^6  = (a^3)^2
    ECP256_Sqr(&ac, &af);               // a^12 = (a^3)^2 = a^(0xc)
    ECP256_Mul(&af, &ac, &a3);          // a^f  = a^15 = a^12 * a^3
    // 0xff = 0b11111111 = 0b11110000 + 0b1111, 0b1111->0b11110000 requires *16,
    // the exponent*16(2^4) requires 4 times square operations
    ECP256_Sqr(&a2f, &af);              // a^(0b11110)   = (a^f)^2
    ECP256_Sqr(&a2f, &a2f);             // a^(0b111100)  = (a^(0b11110))^2
    ECP256_Sqr(&a2f, &a2f);             // a^(0b1111000) = (a^(0b111100))^2
    ECP256_Sqr(&af0, &a2f);             // a^(0xf0)      = a^(0b11110000)   = (a^(0b1111000))^2
    ECP256_Mul(&a2f, &af0, &af);        // a^(0xff)      = a^(0xf0) * a^(0xf)
    // a^(0xffff)
    ECP256_Sqr(&a2f20, &a2f);
    for (i = 1; i < 8; i++) {           // need to left shift by 8 bits
        ECP256_Sqr(&a2f20, &a2f20);
    }
    // When the loop ends, &a2f20 = a^(0xff00)
    ECP256_Mul(&a4f, &a2f20, &a2f);     // a^(0xffff) = a^(0xff00) * a^(0xff)
    // a^(0xffffffff)
    ECP256_Sqr(&a4f40, &a4f);
    for (i = 1; i < 16; i++) {          // need to left shift by 16 bits
        ECP256_Sqr(&a4f40, &a4f40);
    }
    // When the loop ends, &a4f40 = a^(0xffff0000)
    ECP256_Mul(&a8f, &a4f40, &a4f);     // a^(0xffffffff) = a^(0xffff0000) * a^(0xffff)
    // a^(0xffffffff 00000001)
    ECP256_Sqr(&ans, &a8f);
    for (i = 1; i < 32; i++) {          // need to left shift by 32 bits
        ECP256_Sqr(&ans, &ans);
    }
    ECP256_Mul(&ans, &ans, a);          // a^(0xffffffff 00000001) = a^(0xffffffff 00000000) * a
    // a^(0xffffffff 00000001 00000000 00000000 00000000 ffffffff)
    for (i = 0; i < 32 * 4; i++) {      // need to left shift by 32 * 4 bits
        ECP256_Sqr(&ans, &ans);
    }
    ECP256_Mul(&ans, &ans, &a8f);
    // a^(0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff)
    for (i = 0; i < 32; i++) {          // need to left shift by 32 bits
        ECP256_Sqr(&ans, &ans);
    }
    ECP256_Mul(&ans, &ans, &a8f);
    // a^(0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffd)
    for (i = 0; i < 32; i++) {          // need to left shift by 32 bits
        ECP256_Sqr(&ans, &ans);
    }
    // a^(0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff 00000000)
    ECP256_Mul(&ans, &ans, &a4f40);     // a^(0xffff0000)
    ECP256_Mul(&ans, &ans, &a2f20);     // a^(0xff00)
    ECP256_Mul(&ans, &ans, &af0);       // a^(0xf0)
    ECP256_Mul(&ans, &ans, &ac);        // a^(0xc)
    ECP256_Mul(r, &ans, a);             // a^(0x1)
}

#endif

static int32_t ECP256_GetAffine(ECC_Point *r, P256_Point *pt)
{
    Coord zInv3;
    Coord zInv2;
    Coord res_x;
    Coord res_y;
    int32_t ret;
    if (IsZero(&(pt->z)) != 0) {
        ret = CRYPT_ECC_POINT_AT_INFINITY;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
#ifdef HITLS_CRYPTO_ECC_SMALL_FOOTPRINT
    ECP256_InvModP(zInv3.value, pt->z.value);
    ECP256_Mul(&(pt->x), &(pt->x), &g_rrModP);
    ECP256_Mul(&(pt->y), &(pt->y), &g_rrModP);
    ECP256_Mul(&zInv3, &zInv3, &g_rrModP);
#else
    ECP256_ModInverse(&zInv3, &(pt->z));        // zInv
#endif
    ECP256_Sqr(&zInv2, &zInv3);                 // zInv^2
    ECP256_Mul(&zInv3, &zInv2, &zInv3);         // zInv^3
    ECP256_Mul(&res_x, &(pt->x), &zInv2);       // xMont = x / (z^2)
    ECP256_Mul(&res_y, &(pt->y), &zInv3);       // yMont = y / (z^3)
    ECP256_FromMont(&res_x, &res_x);
    ECP256_FromMont(&res_y, &res_y);
    ret = BN_Array2BN(&r->x, res_x.value, P256_SIZE);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Array2BN(&r->y, res_y.value, P256_SIZE);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_SetLimb(&r->z, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#if defined(HITLS_CRYPTO_ECC_ARMV7)
int32_t ECP256_ModOrderInv(const ECC_Para *para, BN_BigNum *r, const BN_BigNum *a)
{
    if (a == NULL || r == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (para->id != CRYPT_ECC_NISTP256) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (BN_IsZero(a) == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_INVERSE_INPUT_ZERO);
        return CRYPT_ECC_INVERSE_INPUT_ZERO;
    }
    if (BN_Cmp(para->n, a) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_NO_INVERSE);
        return CRYPT_BN_ERR_NO_INVERSE;
    }
#ifdef HITLS_CRYPTO_ECC_SMALL_FOOTPRINT
    ECP256_InvModN(r->data, a->data);
    r->size = P256_SIZE;
    BN_FixSize(r);
    return CRYPT_SUCCESS;
#else
    return ECP_ModOrderInv(para, r, a);
#endif
}
#endif

static void ECP256_P256Point2EccPoint(ECC_Point *r, const P256_Point *pt)
{
    Coord xTemp;
    Coord yTemp;
    Coord zTemp;
    ECP256_FromMont(&xTemp, &(pt->x));
    ECP256_FromMont(&yTemp, &(pt->y));
    ECP256_FromMont(&zTemp, &(pt->z));
    (void)BN_Array2BN(&r->x, xTemp.value, P256_SIZE);
    (void)BN_Array2BN(&r->y, yTemp.value, P256_SIZE);
    (void)BN_Array2BN(&r->z, zTemp.value, P256_SIZE);
}

static void ECP256_EccPoint2P256Point(P256_Point *r, const ECC_Point *pt)
{
    (void)BN_BN2Array(&pt->x, r->x.value, P256_SIZE);
    (void)BN_BN2Array(&pt->y, r->y.value, P256_SIZE);
    (void)BN_BN2Array(&pt->z, r->z.value, P256_SIZE);
    ECP256_Mul(&(r->x), &(r->x), &g_rrModP);
    ECP256_Mul(&(r->y), &(r->y), &g_rrModP);
    ECP256_Mul(&(r->z), &(r->z), &g_rrModP);
}

int32_t ECP256_Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *pt)
{
    if (r == NULL || pt == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (para->id != CRYPT_ECC_NISTP256 || r->id != CRYPT_ECC_NISTP256 || pt->id != CRYPT_ECC_NISTP256) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    P256_Point temp;
#ifdef HITLS_CRYPTO_ECC_SMALL_FOOTPRINT
    (void)BN_BN2Array(&pt->x, (temp.x.value), P256_SIZE);
    (void)BN_BN2Array(&pt->y, (temp.y.value), P256_SIZE);
    (void)BN_BN2Array(&pt->z, (temp.z.value), P256_SIZE);
#else
    ECP256_EccPoint2P256Point(&temp, pt);
#endif
    return ECP256_GetAffine(r, &temp);
}

// The value of 'in' contains a maximum of six bits. The input parameter must be & 0b111111 in advance.
static uint32_t Recodew5(uint32_t in)
{
    // Shift rightwards by 5 bits to get the most significant bit, check whether the most significant bit is 1.
    uint32_t sign = (in >> 5) - 1;
    uint32_t data = (1 << 6) - 1 - in;      // (6 Ones)0b111111 - in
    data = (data & ~sign) | (in & sign);
    data = (data >> 1) + (data & 1);

    return (data << 1) + (~sign & 1);
}

#ifndef HITLS_CRYPTO_ECC_SMALL_FOOTPRINT
// The value of 'in' contains a maximum of six bits. The input parameter must be & 0b11111111 in advance.
static uint32_t Recodew7(uint32_t in)
{
    // Shift rightwards by 7 bits to get the most significant bit, check whether the most significant bit is 1.
    uint32_t sign = (in >> 7) - 1;
    uint32_t data = (1 << 8) - 1 - in;      // (8 Ones)0b11111111 - in
    data = (data & ~sign) | (in & sign);
    data = (data >> 1) + (data & 1);

    return (data << 1) + (~sign & 1);
}
#endif

static void ECP256_PreCompWindow(P256_Point table[16], P256_Point *pt)
{
    P256_Point temp[4];
    ECP256_Scatterw5(table, pt, 1);
    ECP256_PointDouble(&temp[0], pt);                 // 2G
    ECP256_Scatterw5(table, &temp[0], 2);             // Discretely save temp[0] to the 2nd position of the table.
    ECP256_PointAdd(&temp[1], &temp[0], pt);          // temp[0] = 3G = 2G + G
    ECP256_Scatterw5(table, &temp[1], 3);             // Discretely saves temp[1] to the 3rd position of the table.
    ECP256_PointDouble(&temp[2], &temp[0]);           // temp[2] = 4G = 2G * 2
    ECP256_Scatterw5(table, &temp[2], 4);             // Discretely save temp[2] to the 4th position in the table.
    ECP256_PointAdd(&temp[3], &temp[2], pt);          // temp[3] = 5G = 4G + G = = temp[2] + pt
    ECP256_Scatterw5(table, &temp[3], 5);             // Discretely save temp[3] to the 5th position in the table.
    ECP256_PointDouble(&temp[0], &temp[1]);           // temp[0] = 6G = 3G * 2
    ECP256_Scatterw5(table, &temp[0], 6);             // Discretely save temp[0] to the 6th position in the table.
    ECP256_PointAdd(&temp[1], &temp[0], pt);          // temp[1] = 7G = 6G + G
    ECP256_Scatterw5(table, &temp[1], 7);             // Discretely save temp[1] to the 7th position in the table.
    ECP256_PointDouble(&temp[2], &temp[2]);           // temp[2] = 8G = 4G * 2
    ECP256_Scatterw5(table, &temp[2], 8);             // Discretely save temp[2] to the 8th position in the table.
    ECP256_PointDouble(&temp[3], &temp[3]);           // temp[3] = 10G = 5G * 2
    ECP256_Scatterw5(table, &temp[3], 10);            // Discretely save temp[3] to the 10th position in the table.
    ECP256_PointAdd(&temp[3], &temp[3], pt);          // temp[3] = 11G = 10G + G
    ECP256_Scatterw5(table, &temp[3], 11);            // Discretely save temp[3] to the 11th position in the table.
    ECP256_PointDouble(&temp[0], &temp[0]);           // temp[0] = 12G = 6G * 2
    ECP256_Scatterw5(table, &temp[0], 12);            // Discretely save temp[0] to the 12th position in the table.
    ECP256_PointAdd(&temp[3], &temp[2], pt);          // temp[3] = 9G = 8G + G = temp[2] + pt
    ECP256_Scatterw5(table, &temp[3], 9);             // Discretely save temp[3] to the 9th position in the table.
    ECP256_PointAdd(&temp[3], &temp[0], pt);          // temp[3] = 13G = 12G + G
    ECP256_Scatterw5(table, &temp[3], 13);            // Discretely save temp[3] to the 13th position of the table.
    ECP256_PointDouble(&temp[1], &temp[1]);           // temp[1] = 14G = 7G * 2
    ECP256_Scatterw5(table, &temp[1], 14);            // Discretely saves temp[1] to the 14th position of the table.
    ECP256_PointAdd(&temp[0], &temp[1], pt);          // temp[0] = 15G = 14G + G = temp[1] + pt
    ECP256_Scatterw5(table, &temp[0], 15);            // Discretely save temp[0] to the 15th position of the table.
    ECP256_PointDouble(&temp[1], &temp[2]);           // temp[1] = 16G = 8G * 2 = temp[2] * 2
    ECP256_Scatterw5(table, &temp[1], 16);            // Discretely saves temp[1] to the 16th position of the table.
}

static void CRYPT_ECP256_PointDouble5Times(P256_Point *r)
{
    ECP256_PointDouble(r, r);
    ECP256_PointDouble(r, r);
    ECP256_PointDouble(r, r);
    ECP256_PointDouble(r, r);
    ECP256_PointDouble(r, r);
}

// r = k*point
// Ensure that m is not empty and is in the range (0, n-1)
static void ECP256_WindowMul(P256_Point *r, const BN_BigNum *k, const ECC_Point *point)
{
    uint8_t kOctets[33]; // m big endian byte stream. Apply for 33 bytes and reserve one byte for the following offset.
    uint32_t mLen = BN_Bytes(k);
    // Offset during byte stream conversion. Ensure that the valid data of the mOctet is in the upper bits.
    uint32_t offset = sizeof(kOctets) - mLen;
    P256_Point table[16]; // The pre-computation window is 2 ^ (5 - 1) = 16 points
    P256_Point temp; // Apply for temporary space of two points.
    Coord tempY;
    (void)BN_Bn2Bin(k, kOctets + offset, &mLen);
    for (uint32_t i = 0; i < offset; i++) {
        kOctets[i] = 0;
    }

    ECP256_EccPoint2P256Point(&temp, point);

    ECP256_PreCompWindow(table, &temp);

    // The first byte is the first two bits of kOctets[1].
    // The subscript starts from 0. Therefore, it is bit 0 + 8 and bit 1 + 8 = 9.
    uint32_t scans = 9;
    uint32_t index;   // position of the byte to be scanned.
    // Number of bits to be shifted rightwards by the current byte.
    // Each byte needs to be moved backward by a maximum of 7 bits.
    uint32_t shift = 7 - (scans % 8);
    uint32_t w = 5;                     // Window size = 5
    // the recode mask, the window size is 5, thus the value is 6 bits, mask = 0b111111 = 0x3f
    uint32_t mask = (1u << (w + 1)) - 1;
    uint32_t wCode = kOctets[1];
    wCode = (wCode >> shift) & mask;
    wCode = Recodew5(wCode);
    ECP256_Gatherw5(&temp, table, wCode >> 1);
    (void)memcpy_s(r, sizeof(P256_Point), &temp, sizeof(P256_Point));

    // 5 bits is obtained each time. The total number of bits is 256 + 8 (1 byte reserved) = 264 bits.
    // Therefore, the last time can be scanned to 264-5 = 259 bits.
    while (scans < 259) {
        // Double the point for 5 times
        CRYPT_ECP256_PointDouble5Times(r);

        scans += w;                 // Number of bits in the next scan.
        index = scans / 8;          // Location of the byte to be scanned. (1 byte = 8 bits)
        // Number of bits to be shifted rightwards by the current byte.
        // Each byte needs to be moved backward by a maximum of 7 bits. (1 byte = 8 bits)
        shift = 7 - (scans % 8);
        // Shift the upper byte by 8 bits to left, concatenate the current byte, and then shift to get the current wCode
        wCode = kOctets[index] | (kOctets[index - 1] << 8);
        wCode = (wCode >> shift) & mask;
        wCode = Recodew5(wCode);
        ECP256_Gatherw5(&temp, table, wCode >> 1);
        ECP256_Neg(&tempY, &(temp.y));
        // If the least significant bit of the code is 1, plus -(wCode >> 1) times point.
        CopyConditional(&(temp.y), &tempY, wCode & 1);
        ECP256_PointAdd(r, r, &temp);
    }

    // Special processing of the last block
    CRYPT_ECP256_PointDouble5Times(r);

    wCode = kOctets[32]; // Obtain the last byte, that is, kOctets[32].
    wCode = (wCode << 1) & mask;
    wCode = Recodew5(wCode);
    ECP256_Gatherw5(&temp, table, wCode >> 1);
    ECP256_Neg(&tempY, &(temp.y));
    // If the least significant bit of the code is 1, plus -(wCode >> 1) times point.
    CopyConditional(&(temp.y), &tempY, wCode & 1);
    ECP256_PointAdd(r, r, &temp);
}
#ifdef HITLS_CRYPTO_ECC_SMALL_FOOTPRINT

static void ComputeK1G(P256_Point *k1G, const BN_BigNum *k1)
{
    uint8_t idx;
    uint8_t width;
    uint8_t odd;
    uint8_t x[P256_COMB_WIDTH + 1] = {0};
    BN_UINT tmpK[P256_SIZE] __attribute__((aligned(P256_BYTES))) = {0};
    BN_UINT scalar[P256_SIZE] __attribute__((aligned(P256_BYTES)));
    P256_AffinePoint item;

    (void)memcpy_s(tmpK, sizeof(BN_UINT) * P256_SIZE, k1->data, sizeof(BN_UINT) * k1->size);
    while (P256Cmp(tmpK, g_P256N) > 0) {
        ECP_P256Sub(tmpK, tmpK, g_P256N); // Ensure that k < n
    }
    odd = ((tmpK[0] & 0x01) == 0); // Preserve the parity state of k.
    ECP_P256SubModN(scalar, g_P256N, tmpK); // Constant time processing for the case when k is even
    ECP_P256ConstSelect(scalar, tmpK, 1 - odd); // cal (N-K)*G

    ECP_P256CombRecode(x, scalar); // odd-comb
    ECP_P256SelectPoint((P256_AffinePoint *)k1G, g_P256PreTable2, x[P256_COMB_WIDTH]);
    (void)memcpy_s(k1G->z.value, sizeof(BN_UINT) * P256_SIZE, g_oneMont.value, sizeof(BN_UINT) * P256_SIZE);

    width = P256_COMB_WIDTH >> 1; // take half of the window.
    idx = width;
    while (idx != 0) {
        idx--;
        ECP256_PointDouble(k1G, k1G);
        ECP_P256SelectPoint(&item, g_P256PreTable1, x[idx]);
        ECP256_AddAffine(k1G, k1G, &item);
        ECP_P256SelectPoint(&item, g_P256PreTable2, x[idx + width]);
        ECP256_AddAffine(k1G, k1G, &item);
    }

    ECP_P256SubModP(scalar, g_p256P, k1G->y.value); // Is (N-K)*G reduced back to K*G ?
    ECP_P256ConstSelect(k1G->y.value, scalar, odd);
}

#else

static void ComputeK1G(P256_Point *k1G, const BN_BigNum *k1)
{
    uint8_t kOctets[33]; // applies for 33 bytes and reserves one byte for the following offset. 256 bits are 32 bytes.
    Coord tempY;
    P256_AffinePoint k1GAffine;
    const ECP256_TableRow *preCompTable = NULL; // precompute window size is 2 ^(7 - 1) = 64
    preCompTable = ECP256_GetPreCompTable();

    uint32_t kLen = BN_Bytes(k1);
    // Offset during byte stream conversion. Ensure that the valid data of the mOctet is in the upper bits.
    uint32_t offset = sizeof(kOctets) - kLen;
    (void)BN_Bn2Bin(k1, kOctets + offset, &kLen);
    for (uint32_t i = 0; i < offset; i++) {
        kOctets[i] = 0;
    }

    uint32_t w = 7; // Window size = 7
    // the recode mask, the window size is 7, thus 8 bits are used (one extra bit is the sign bit).
    // mask = 0b11111111 = 0xff
    uint32_t mask = (1u << (w + 1)) - 1;
    uint32_t wCode = (kOctets[32] << 1) & mask; // Last byte kOctets[32] is the least significant 7 bits.
    wCode = Recodew7(wCode);
    ECP256_Gatherw7(&k1GAffine, preCompTable[0], wCode >> 1);
    ECP256_Neg(&tempY, &(k1GAffine.y));
    // If the least significant bit of the code is 1, plus -(wCode >> 1) times point.
    CopyConditional(&(k1GAffine.y), &tempY, wCode & 1);
    // If the x and y coordinates of k1GAffine are both 0, then the infinity is all Fs; otherwise, the infinity is 0.
    BN_UINT infinity = IsZero(&(k1GAffine.x)) & IsZero(&(k1GAffine.y));
    Affine2Jproj(k1G, &k1GAffine, ~infinity);

    uint32_t scans = 0;
    uint32_t index, shift;
    // pre-computation table is table[37][64]. The table is queried every 7 bits (valid bits) of 256 bits. 256/7 = 36.57
    for (uint32_t i = 1; i < 37; i++) {
        scans += w;
        index = 32 - ((scans - 1) / 8); // The subscript of the last byte is 32, and 8 means 8 bits(1byte)
        shift = (scans - 1) % 8; // 8 means 8 bits(1byte)
        wCode = kOctets[index] | (kOctets[index - 1] << 8); // 8 means 8 bits(1byte)
        wCode = (wCode >> shift) & mask;
        wCode = Recodew7(wCode);
        ECP256_Gatherw7(&k1GAffine, preCompTable[i], wCode >> 1);
        ECP256_Neg(&tempY, &(k1GAffine.y));
        // If the least significant bit of the code is 1, plus -(wCode >> 1) times point.
        CopyConditional(&(k1GAffine.y), &tempY, wCode & 1);
        ECP256_AddAffine(k1G, k1G, &k1GAffine);
    }
}

#endif

static int32_t ECP256_PointMulCheck(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt)
{
    bool flag = (para == NULL || r == NULL || k == NULL);
    uint32_t bits;
    if (flag) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != CRYPT_ECC_NISTP256 || r->id != CRYPT_ECC_NISTP256) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (pt != NULL) {
        if (pt->id != CRYPT_ECC_NISTP256) {
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
            return CRYPT_ECC_POINT_ERR_CURVE_ID;
        }
        // Special processing for the infinite point.
        if (BN_IsZero(&pt->z)) {
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
            return CRYPT_ECC_POINT_AT_INFINITY;
        }
    }
    bits = BN_Bits(k);
    if (bits > 256) {   // 256 is the number of bits in the curve mode
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_MUL_ERR_K_LEN);
        return CRYPT_ECC_POINT_MUL_ERR_K_LEN;
    }

    return CRYPT_SUCCESS;
}

// if pt == NULL, r = k * G, otherwise r = k * pt
int32_t ECP256_PointMul(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt)
{
    P256_Point rTemp = {0};
    int32_t ret = ECP256_PointMulCheck(para, r, k, pt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (pt == NULL) {
        ComputeK1G(&rTemp, k);
    } else {
        ECP256_WindowMul(&rTemp, k, pt);
    }

    ECP256_P256Point2EccPoint(r, &rTemp);

    return ret;
}

static int32_t ECP256_PointMulAddCheck(
    ECC_Para *para, ECC_Point *r, const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt)
{
    bool flag = (para == NULL || r == NULL || k1 == NULL || k2 == NULL || pt == NULL);
    uint32_t bits1, bits2;
    if (flag) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != CRYPT_ECC_NISTP256 || r->id != CRYPT_ECC_NISTP256 || pt->id != CRYPT_ECC_NISTP256) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    // Special processing of the infinite point.
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    bits1 = BN_Bits(k1);
    bits2 = BN_Bits(k2);
    if (bits1 > 256 || bits2 > 256) {   // 256 is the number of bits in the curve mode
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_MUL_ERR_K_LEN);
        return CRYPT_ECC_POINT_MUL_ERR_K_LEN;
    }

    return CRYPT_SUCCESS;
}

// r = k1 * G + k2 * pt
int32_t ECP256_PointMulAdd(ECC_Para *para, ECC_Point *r, const BN_BigNum *k1, const BN_BigNum *k2,
    const ECC_Point *pt)
{
    int32_t ret = ECP256_PointMulAddCheck(para, r, k1, k2, pt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    P256_Point k2Pt;
    P256_Point k1G = {0};

    ECP256_WindowMul(&k2Pt, k2, pt);
    ComputeK1G(&k1G, k1);
    ECP256_PointAdd(&k1G, &k1G, &k2Pt);
    ECP256_P256Point2EccPoint(r, &k1G);
    return ret;
}
#endif /* defined(HITLS_CRYPTO_CURVE_NISTP256) && defined(HITLS_CRYPTO_NIST_USE_ACCEL) */

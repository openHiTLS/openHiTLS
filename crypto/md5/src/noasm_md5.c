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
#ifdef HITLS_CRYPTO_MD5

#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "md5_core.h"
#include "crypt_md5.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

/* F, G, H and I are basic MD5 functions. */
#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~(z))))

#define FF(a, b, c, d, x, s, ac)              \
    do {                                      \
        (a) += F((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s));               \
        (a) += (b);                           \
    } while (0)

#define GG(a, b, c, d, x, s, ac)              \
    do {                                      \
        (a) += G((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s));               \
        (a) += (b);                           \
    } while (0)

#define HH(a, b, c, d, x, s, ac)              \
    do {                                      \
        (a) += H((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s));               \
        (a) += (b);                           \
    } while (0)

#define II(a, b, c, d, x, s, ac)              \
    do {                                      \
        (a) += I((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s));               \
        (a) += (b);                           \
    } while (0)

/* Constants for MD5_Compress routine. */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static const uint32_t T[64] = {
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,

    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,

    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,

    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
};

/* see RFC1321 chapter 3.4 Step 4 https://www.rfc-editor.org/rfc/rfc1321 */
void MD5_Compress(uint32_t state[4], const uint8_t *data, uint32_t blockCnt)
    {
    uint32_t w[16] = {0};
    const uint8_t *input = data;
    uint32_t count = blockCnt;

    while (count > 0) {
        /* convert data to 32 bits for calculation */
        w[0] = GET_UINT32_LE(input, 0);
        w[1] = GET_UINT32_LE(input, 4);
        w[2] = GET_UINT32_LE(input, 8);
        w[3] = GET_UINT32_LE(input, 12);
        w[4] = GET_UINT32_LE(input, 16);
        w[5] = GET_UINT32_LE(input, 20);
        w[6] = GET_UINT32_LE(input, 24);
        w[7] = GET_UINT32_LE(input, 28);
        w[8] = GET_UINT32_LE(input, 32);
        w[9] = GET_UINT32_LE(input, 36);
        w[10] = GET_UINT32_LE(input, 40);
        w[11] = GET_UINT32_LE(input, 44);
        w[12] = GET_UINT32_LE(input, 48);
        w[13] = GET_UINT32_LE(input, 52);
        w[14] = GET_UINT32_LE(input, 56);
        w[15] = GET_UINT32_LE(input, 60);

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];

        FF(a, b, c, d, w[0],  S11, T[0]);
        FF(d, a, b, c, w[1],  S12, T[1]);
        FF(c, d, a, b, w[2],  S13, T[2]);
        FF(b, c, d, a, w[3],  S14, T[3]);
        FF(a, b, c, d, w[4],  S11, T[4]);
        FF(d, a, b, c, w[5],  S12, T[5]);
        FF(c, d, a, b, w[6],  S13, T[6]);
        FF(b, c, d, a, w[7],  S14, T[7]);
        FF(a, b, c, d, w[8],  S11, T[8]);
        FF(d, a, b, c, w[9],  S12, T[9]);
        FF(c, d, a, b, w[10], S13, T[10]);
        FF(b, c, d, a, w[11], S14, T[11]);
        FF(a, b, c, d, w[12], S11, T[12]);
        FF(d, a, b, c, w[13], S12, T[13]);
        FF(c, d, a, b, w[14], S13, T[14]);
        FF(b, c, d, a, w[15], S14, T[15]);

        GG(a, b, c, d, w[1],  S21, T[16]);
        GG(d, a, b, c, w[6],  S22, T[17]);
        GG(c, d, a, b, w[11], S23, T[18]);
        GG(b, c, d, a, w[0],  S24, T[19]);
        GG(a, b, c, d, w[5],  S21, T[20]);
        GG(d, a, b, c, w[10], S22, T[21]);
        GG(c, d, a, b, w[15], S23, T[22]);
        GG(b, c, d, a, w[4],  S24, T[23]);
        GG(a, b, c, d, w[9],  S21, T[24]);
        GG(d, a, b, c, w[14], S22, T[25]);
        GG(c, d, a, b, w[3],  S23, T[26]);
        GG(b, c, d, a, w[8],  S24, T[27]);
        GG(a, b, c, d, w[13], S21, T[28]);
        GG(d, a, b, c, w[2],  S22, T[29]);
        GG(c, d, a, b, w[7],  S23, T[30]);
        GG(b, c, d, a, w[12], S24, T[31]);

        HH(a, b, c, d, w[5],  S31, T[32]);
        HH(d, a, b, c, w[8],  S32, T[33]);
        HH(c, d, a, b, w[11], S33, T[34]);
        HH(b, c, d, a, w[14], S34, T[35]);
        HH(a, b, c, d, w[1],  S31, T[36]);
        HH(d, a, b, c, w[4],  S32, T[37]);
        HH(c, d, a, b, w[7],  S33, T[38]);
        HH(b, c, d, a, w[10], S34, T[39]);
        HH(a, b, c, d, w[13], S31, T[40]);
        HH(d, a, b, c, w[0],  S32, T[41]);
        HH(c, d, a, b, w[3],  S33, T[42]);
        HH(b, c, d, a, w[6],  S34, T[43]);
        HH(a, b, c, d, w[9],  S31, T[44]);
        HH(d, a, b, c, w[12], S32, T[45]);
        HH(c, d, a, b, w[15], S33, T[46]);
        HH(b, c, d, a, w[2],  S34, T[47]);

        II(a, b, c, d, w[0],  S41, T[48]);
        II(d, a, b, c, w[7],  S42, T[49]);
        II(c, d, a, b, w[14], S43, T[50]);
        II(b, c, d, a, w[5],  S44, T[51]);
        II(a, b, c, d, w[12], S41, T[52]);
        II(d, a, b, c, w[3],  S42, T[53]);
        II(c, d, a, b, w[10], S43, T[54]);
        II(b, c, d, a, w[1],  S44, T[55]);
        II(a, b, c, d, w[8],  S41, T[56]);
        II(d, a, b, c, w[15], S42, T[57]);
        II(c, d, a, b, w[6],  S43, T[58]);
        II(b, c, d, a, w[13], S44, T[59]);
        II(a, b, c, d, w[4],  S41, T[60]);
        II(d, a, b, c, w[11], S42, T[61]);
        II(c, d, a, b, w[2],  S43, T[62]);
        II(b, c, d, a, w[9],  S44, T[63]);

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;

        input += CRYPT_MD5_BLOCKSIZE;
        count--;
    }
}
#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif // HITLS_CRYPTO_MD5

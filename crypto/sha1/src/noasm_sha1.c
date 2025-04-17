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
#if defined(HITLS_CRYPTO_SHA1) && !defined(HITLS_CRYPTO_SHA1_SMALL_MEM)

#include <stdlib.h>
#include "securec.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "crypt_sha1.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

/* e767 is because H is defined in SHA1 and MD5.
But the both the macros are different. So masked
this error */

#define K0 0x5A827999
#define K1 0x6ED9EBA1
#define K2 0x8F1BBCDC
#define K3 0xCA62C1D6

#define F0(b, c, d) (((b) & (c)) | ((~(b)) & (d)))
#define F1(b, c, d) (((b) ^ (c)) ^ (d))
#define F2(b, c, d) (((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define F3(b, c, d) (((b) ^ (c)) ^ (d))

#define ROUND00_15(s, a, b, c, d, e, temp, w, Kt)   \
    do { \
        (temp) = ROTL32(a, 5) + F##Kt(b, c, d) + (e) + (w)[s] + K##Kt; \
        (b) = ROTL32(b, 30); \
    } while (0)

#define ROUND16_79(t, a, b, c, d, e, temp, w, Kt)   \
    do { \
        (w)[(t) & 0xF] = ROTL32( \
            (w)[((t) + 13) & 0xF] ^ (w)[((t) + 8) & 0xF] ^ (w)[((t) + 2) & 0xF] ^ (w)[(t) & 0xF], 1); \
        ROUND00_15((t) & 0xF, a, b, c, d, e, temp, w, Kt); \
    } while (0)

const uint8_t *SHA1_Step(const uint8_t *input, uint32_t len, uint32_t *h)
{
    uint32_t temp;
    uint32_t w[16];
    const uint8_t *data = input;
    uint32_t dataLen = len;

    while (dataLen >= CRYPT_SHA1_BLOCKSIZE) {
        /* Convert data into 32 bits for calculation. */
        w[0] = GET_UINT32_BE(data, 0);
        w[1] = GET_UINT32_BE(data, 4);
        w[2] = GET_UINT32_BE(data, 8);
        w[3] = GET_UINT32_BE(data, 12);
        w[4] = GET_UINT32_BE(data, 16);
        w[5] = GET_UINT32_BE(data, 20);
        w[6] = GET_UINT32_BE(data, 24);
        w[7] = GET_UINT32_BE(data, 28);
        w[8] = GET_UINT32_BE(data, 32);
        w[9] = GET_UINT32_BE(data, 36);
        w[10] = GET_UINT32_BE(data, 40);
        w[11] = GET_UINT32_BE(data, 44);
        w[12] = GET_UINT32_BE(data, 48);
        w[13] = GET_UINT32_BE(data, 52);
        w[14] = GET_UINT32_BE(data, 56);
        w[15] = GET_UINT32_BE(data, 60);

        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];

        // Required by referring to section 6.2 in rfc3174. To ensure performance,
        // the variables A\b\c\d\e\TEMP are reused cyclically.
        ROUND00_15(0, a, b, c, d, e, temp, w, 0);
        ROUND00_15(1, temp, a, b, c, d, e, w, 0);
        ROUND00_15(2, e, temp, a, b, c, d, w, 0);
        ROUND00_15(3, d, e, temp, a, b, c, w, 0);
        ROUND00_15(4, c, d, e, temp, a, b, w, 0);
        ROUND00_15(5, b, c, d, e, temp, a, w, 0);
        ROUND00_15(6, a, b, c, d, e, temp, w, 0);
        ROUND00_15(7, temp, a, b, c, d, e, w, 0);
        ROUND00_15(8, e, temp, a, b, c, d, w, 0);
        ROUND00_15(9, d, e, temp, a, b, c, w, 0);
        ROUND00_15(10, c, d, e, temp, a, b, w, 0);
        ROUND00_15(11, b, c, d, e, temp, a, w, 0);
        ROUND00_15(12, a, b, c, d, e, temp, w, 0);
        ROUND00_15(13, temp, a, b, c, d, e, w, 0);
        ROUND00_15(14, e, temp, a, b, c, d, w, 0);
        ROUND00_15(15, d, e, temp, a, b, c, w, 0);

        ROUND16_79(16, c, d, e, temp, a, b, w, 0);
        ROUND16_79(17, b, c, d, e, temp, a, w, 0);
        ROUND16_79(18, a, b, c, d, e, temp, w, 0);
        ROUND16_79(19, temp, a, b, c, d, e, w, 0);

        ROUND16_79(20, e, temp, a, b, c, d, w, 1);
        ROUND16_79(21, d, e, temp, a, b, c, w, 1);
        ROUND16_79(22, c, d, e, temp, a, b, w, 1);
        ROUND16_79(23, b, c, d, e, temp, a, w, 1);
        ROUND16_79(24, a, b, c, d, e, temp, w, 1);
        ROUND16_79(25, temp, a, b, c, d, e, w, 1);
        ROUND16_79(26, e, temp, a, b, c, d, w, 1);
        ROUND16_79(27, d, e, temp, a, b, c, w, 1);
        ROUND16_79(28, c, d, e, temp, a, b, w, 1);
        ROUND16_79(29, b, c, d, e, temp, a, w, 1);
        ROUND16_79(30, a, b, c, d, e, temp, w, 1);
        ROUND16_79(31, temp, a, b, c, d, e, w, 1);
        ROUND16_79(32, e, temp, a, b, c, d, w, 1);
        ROUND16_79(33, d, e, temp, a, b, c, w, 1);
        ROUND16_79(34, c, d, e, temp, a, b, w, 1);
        ROUND16_79(35, b, c, d, e, temp, a, w, 1);
        ROUND16_79(36, a, b, c, d, e, temp, w, 1);
        ROUND16_79(37, temp, a, b, c, d, e, w, 1);
        ROUND16_79(38, e, temp, a, b, c, d, w, 1);
        ROUND16_79(39, d, e, temp, a, b, c, w, 1);

        ROUND16_79(40, c, d, e, temp, a, b, w, 2);
        ROUND16_79(41, b, c, d, e, temp, a, w, 2);
        ROUND16_79(42, a, b, c, d, e, temp, w, 2);
        ROUND16_79(43, temp, a, b, c, d, e, w, 2);
        ROUND16_79(44, e, temp, a, b, c, d, w, 2);
        ROUND16_79(45, d, e, temp, a, b, c, w, 2);
        ROUND16_79(46, c, d, e, temp, a, b, w, 2);
        ROUND16_79(47, b, c, d, e, temp, a, w, 2);
        ROUND16_79(48, a, b, c, d, e, temp, w, 2);
        ROUND16_79(49, temp, a, b, c, d, e, w, 2);
        ROUND16_79(50, e, temp, a, b, c, d, w, 2);
        ROUND16_79(51, d, e, temp, a, b, c, w, 2);
        ROUND16_79(52, c, d, e, temp, a, b, w, 2);
        ROUND16_79(53, b, c, d, e, temp, a, w, 2);
        ROUND16_79(54, a, b, c, d, e, temp, w, 2);
        ROUND16_79(55, temp, a, b, c, d, e, w, 2);
        ROUND16_79(56, e, temp, a, b, c, d, w, 2);
        ROUND16_79(57, d, e, temp, a, b, c, w, 2);
        ROUND16_79(58, c, d, e, temp, a, b, w, 2);
        ROUND16_79(59, b, c, d, e, temp, a, w, 2);

        ROUND16_79(60, a, b, c, d, e, temp, w, 3);
        ROUND16_79(61, temp, a, b, c, d, e, w, 3);
        ROUND16_79(62, e, temp, a, b, c, d, w, 3);
        ROUND16_79(63, d, e, temp, a, b, c, w, 3);
        ROUND16_79(64, c, d, e, temp, a, b, w, 3);
        ROUND16_79(65, b, c, d, e, temp, a, w, 3);
        ROUND16_79(66, a, b, c, d, e, temp, w, 3);
        ROUND16_79(67, temp, a, b, c, d, e, w, 3);
        ROUND16_79(68, e, temp, a, b, c, d, w, 3);
        ROUND16_79(69, d, e, temp, a, b, c, w, 3);
        ROUND16_79(70, c, d, e, temp, a, b, w, 3);
        ROUND16_79(71, b, c, d, e, temp, a, w, 3);
        ROUND16_79(72, a, b, c, d, e, temp, w, 3);
        ROUND16_79(73, temp, a, b, c, d, e, w, 3);
        ROUND16_79(74, e, temp, a, b, c, d, w, 3);
        ROUND16_79(75, d, e, temp, a, b, c, w, 3);
        ROUND16_79(76, c, d, e, temp, a, b, w, 3);
        ROUND16_79(77, b, c, d, e, temp, a, w, 3);
        ROUND16_79(78, a, b, c, d, e, temp, w, 3);
        ROUND16_79(79, temp, a, b, c, d, e, w, 3);

        // Let H0 = H0 + a, H1 = H1 + b, H2 = H2 + c, H3 = H3 + d, H4 = H4 + e.
        // Because A, B, C, D and E are reused, after the last round of conversion, A = e, b = temp, c = a, d = b, e = c
        h[0] += e; // H[0] += a
        h[1] += temp; // H[1] += b
        h[2] += a; // H[2] += c
        h[3] += b; // H[3] += d
        h[4] += c; // H[4] += e

        data += CRYPT_SHA1_BLOCKSIZE;
        dataLen -= CRYPT_SHA1_BLOCKSIZE;
    }

    return data;
}

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA1 && !HITLS_CRYPTO_SHA1_SMALL_MEM

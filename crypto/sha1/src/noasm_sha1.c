/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SHA1

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

#define ROUND00_16(s, a, b, c, d, e, temp, w, Kt)   \
    do { \
        (temp) = ROTL32(a, 5) + F##Kt(b, c, d) + (e) + (w)[s] + K##Kt; \
        (b) = ROTL32(b, 30); \
    } while (0)

#define ROUND16_80(t, a, b, c, d, e, temp, w, Kt)   \
    do { \
        (w)[(t) & 0xF] = ROTL32( \
            (w)[((t) + 13) & 0xF] ^ (w)[((t) + 8) & 0xF] ^ (w)[((t) + 2) & 0xF] ^ (w)[(t) & 0xF], 1); \
        ROUND00_16((t) & 0xF, a, b, c, d, e, temp, w, Kt); \
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
        ROUND00_16(0, a, b, c, d, e, temp, w, 0);
        ROUND00_16(1, temp, a, b, c, d, e, w, 0);
        ROUND00_16(2, e, temp, a, b, c, d, w, 0);
        ROUND00_16(3, d, e, temp, a, b, c, w, 0);
        ROUND00_16(4, c, d, e, temp, a, b, w, 0);
        ROUND00_16(5, b, c, d, e, temp, a, w, 0);
        ROUND00_16(6, a, b, c, d, e, temp, w, 0);
        ROUND00_16(7, temp, a, b, c, d, e, w, 0);
        ROUND00_16(8, e, temp, a, b, c, d, w, 0);
        ROUND00_16(9, d, e, temp, a, b, c, w, 0);
        ROUND00_16(10, c, d, e, temp, a, b, w, 0);
        ROUND00_16(11, b, c, d, e, temp, a, w, 0);
        ROUND00_16(12, a, b, c, d, e, temp, w, 0);
        ROUND00_16(13, temp, a, b, c, d, e, w, 0);
        ROUND00_16(14, e, temp, a, b, c, d, w, 0);
        ROUND00_16(15, d, e, temp, a, b, c, w, 0);

        ROUND16_80(16, c, d, e, temp, a, b, w, 0);
        ROUND16_80(17, b, c, d, e, temp, a, w, 0);
        ROUND16_80(18, a, b, c, d, e, temp, w, 0);
        ROUND16_80(19, temp, a, b, c, d, e, w, 0);

        ROUND16_80(20, e, temp, a, b, c, d, w, 1);
        ROUND16_80(21, d, e, temp, a, b, c, w, 1);
        ROUND16_80(22, c, d, e, temp, a, b, w, 1);
        ROUND16_80(23, b, c, d, e, temp, a, w, 1);
        ROUND16_80(24, a, b, c, d, e, temp, w, 1);
        ROUND16_80(25, temp, a, b, c, d, e, w, 1);
        ROUND16_80(26, e, temp, a, b, c, d, w, 1);
        ROUND16_80(27, d, e, temp, a, b, c, w, 1);
        ROUND16_80(28, c, d, e, temp, a, b, w, 1);
        ROUND16_80(29, b, c, d, e, temp, a, w, 1);
        ROUND16_80(30, a, b, c, d, e, temp, w, 1);
        ROUND16_80(31, temp, a, b, c, d, e, w, 1);
        ROUND16_80(32, e, temp, a, b, c, d, w, 1);
        ROUND16_80(33, d, e, temp, a, b, c, w, 1);
        ROUND16_80(34, c, d, e, temp, a, b, w, 1);
        ROUND16_80(35, b, c, d, e, temp, a, w, 1);
        ROUND16_80(36, a, b, c, d, e, temp, w, 1);
        ROUND16_80(37, temp, a, b, c, d, e, w, 1);
        ROUND16_80(38, e, temp, a, b, c, d, w, 1);
        ROUND16_80(39, d, e, temp, a, b, c, w, 1);

        ROUND16_80(40, c, d, e, temp, a, b, w, 2);
        ROUND16_80(41, b, c, d, e, temp, a, w, 2);
        ROUND16_80(42, a, b, c, d, e, temp, w, 2);
        ROUND16_80(43, temp, a, b, c, d, e, w, 2);
        ROUND16_80(44, e, temp, a, b, c, d, w, 2);
        ROUND16_80(45, d, e, temp, a, b, c, w, 2);
        ROUND16_80(46, c, d, e, temp, a, b, w, 2);
        ROUND16_80(47, b, c, d, e, temp, a, w, 2);
        ROUND16_80(48, a, b, c, d, e, temp, w, 2);
        ROUND16_80(49, temp, a, b, c, d, e, w, 2);
        ROUND16_80(50, e, temp, a, b, c, d, w, 2);
        ROUND16_80(51, d, e, temp, a, b, c, w, 2);
        ROUND16_80(52, c, d, e, temp, a, b, w, 2);
        ROUND16_80(53, b, c, d, e, temp, a, w, 2);
        ROUND16_80(54, a, b, c, d, e, temp, w, 2);
        ROUND16_80(55, temp, a, b, c, d, e, w, 2);
        ROUND16_80(56, e, temp, a, b, c, d, w, 2);
        ROUND16_80(57, d, e, temp, a, b, c, w, 2);
        ROUND16_80(58, c, d, e, temp, a, b, w, 2);
        ROUND16_80(59, b, c, d, e, temp, a, w, 2);

        ROUND16_80(60, a, b, c, d, e, temp, w, 3);
        ROUND16_80(61, temp, a, b, c, d, e, w, 3);
        ROUND16_80(62, e, temp, a, b, c, d, w, 3);
        ROUND16_80(63, d, e, temp, a, b, c, w, 3);
        ROUND16_80(64, c, d, e, temp, a, b, w, 3);
        ROUND16_80(65, b, c, d, e, temp, a, w, 3);
        ROUND16_80(66, a, b, c, d, e, temp, w, 3);
        ROUND16_80(67, temp, a, b, c, d, e, w, 3);
        ROUND16_80(68, e, temp, a, b, c, d, w, 3);
        ROUND16_80(69, d, e, temp, a, b, c, w, 3);
        ROUND16_80(70, c, d, e, temp, a, b, w, 3);
        ROUND16_80(71, b, c, d, e, temp, a, w, 3);
        ROUND16_80(72, a, b, c, d, e, temp, w, 3);
        ROUND16_80(73, temp, a, b, c, d, e, w, 3);
        ROUND16_80(74, e, temp, a, b, c, d, w, 3);
        ROUND16_80(75, d, e, temp, a, b, c, w, 3);
        ROUND16_80(76, c, d, e, temp, a, b, w, 3);
        ROUND16_80(77, b, c, d, e, temp, a, w, 3);
        ROUND16_80(78, a, b, c, d, e, temp, w, 3);
        ROUND16_80(79, temp, a, b, c, d, e, w, 3);

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

#endif // HITLS_CRYPTO_SHA1

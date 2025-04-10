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

/**
 * An implementation of sha1 that has 70% less in rom but lower performance.
 */
#include "hitls_build.h"
#if defined(HITLS_CRYPTO_SHA1) && defined(HITLS_CRYPTO_SHA1_SMALL_MEM)

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

typedef struct {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t w[16];
} SHA1_CTX;

#define F0(b, c, d) (((b) & (c)) | ((~(b)) & (d)))
#define F1(b, c, d) (((b) ^ (c)) ^ (d))
#define F2(b, c, d) (((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define F3(b, c, d) (((b) ^ (c)) ^ (d))

#define ROUND00_15(s, a, b, c, d, e, Kt) \
    do { \
        temp = ROTL32(a, 5) + F##Kt(b, c, d) + (e) + (ctx.w)[s] + K##Kt; \
        e = d; \
        d = c; \
        c = ROTL32(b, 30); \
        b = a; \
        a = temp; \
    } while (0)

#define ROUND16_79(s, a, b, c, d, e, Kt) \
    do { \
        (ctx.w)[(s) & 0xF] = ROTL32( \
            (ctx.w)[((s) + 13) & 0xF] ^ (ctx.w)[((s) + 8) & 0xF] ^ (ctx.w)[((s) + 2) & 0xF] ^ (ctx.w)[(s) & 0xF], 1); \
        ROUND00_15((s) & 0xF, a, b, c, d, e, Kt); \
    } while (0)

const uint8_t *SHA1_Step(const uint8_t *input, uint32_t len, uint32_t *h)
{
    SHA1_CTX ctx = {0};
    uint32_t temp;
    const uint8_t *data = input;
    uint32_t dataLen = len;

    while (dataLen >= CRYPT_SHA1_BLOCKSIZE) {
        for (int i = 0; i < 16; ++i) {
            ctx.w[i] = GET_UINT32_BE(data, i * 4);
        }

        ctx.a = h[0];
        ctx.b = h[1];
        ctx.c = h[2];
        ctx.d = h[3];
        ctx.e = h[4];

        // Round 0-15
        for (uint32_t s = 0; s < 16; ++s) {
            ROUND00_15(s, ctx.a, ctx.b, ctx.c, ctx.d, ctx.e, 0);
        }

        // Round 16-79
        for (uint32_t s = 16; s < 20; ++s) {
            ROUND16_79(s, ctx.a, ctx.b, ctx.c, ctx.d, ctx.e, 0);
        }
        for (uint32_t s = 20; s < 40; ++s) {
            ROUND16_79(s, ctx.a, ctx.b, ctx.c, ctx.d, ctx.e, 1);
        }
        for (uint32_t s = 40; s < 60; ++s) {
            ROUND16_79(s, ctx.a, ctx.b, ctx.c, ctx.d, ctx.e, 2);
        }
        for (uint32_t s = 60; s < 80; ++s) {
            ROUND16_79(s, ctx.a, ctx.b, ctx.c, ctx.d, ctx.e, 3);
        }

        h[0] += ctx.a;
        h[1] += ctx.b;
        h[2] += ctx.c;
        h[3] += ctx.d;
        h[4] += ctx.e;

        data += CRYPT_SHA1_BLOCKSIZE;
        dataLen -= CRYPT_SHA1_BLOCKSIZE;
    }

    return data;
}

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA1 && HITLS_CRYPTO_SHA1_SMALL_MEM

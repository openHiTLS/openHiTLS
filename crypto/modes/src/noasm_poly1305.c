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
#if defined(HITLS_CRYPTO_CHACHA20) && defined(HITLS_CRYPTO_CHACHA20POLY1305)

#include "bsl_sal.h"
#include "crypt_utils.h"
#include "poly1305_core.h"

// Information required by initializing the assembly,
// for example, ctx->table. However, the C language does not calculate the table.
void Poly1305InitForAsm(Poly1305Ctx *ctx)
{
    (void)ctx;
}


// Operation for blocks. The return value is the length of the remaining unprocessed data.
uint32_t Poly1305Block(Poly1305Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t padbit)
{
    uint32_t a[5], r[4];
    uint64_t b[8];
    // RFC_7539-2.5.1 for loop internal operation
    a[0] = ctx->acc[0];
    a[1] = ctx->acc[1];
    a[2] = ctx->acc[2];
    a[3] = ctx->acc[3];
    a[4] = ctx->acc[4];
    r[0] = ctx->r[0];
    r[1] = ctx->r[1];
    r[2] = ctx->r[2];
    r[3] = ctx->r[3];

    const uint8_t *off = data;
    uint32_t len = dataLen;

    while (len >= POLY1305_BLOCKSIZE) {
        // a = acc + inputret
        b[0] = (uint64_t)a[0] + GET_UINT32_LE(off, 0);
        b[1] = (uint64_t)a[1] + GET_UINT32_LE(off, 4) + (b[0] >> 32);
        b[2] = (uint64_t)a[2] + GET_UINT32_LE(off, 8) + (b[1] >> 32);
        b[3] = (uint64_t)a[3] + GET_UINT32_LE(off, 12) + (b[2] >> 32);

        a[0] = (uint32_t)b[0];
        a[1] = (uint32_t)b[1];
        a[2] = (uint32_t)b[2];
        a[3] = (uint32_t)b[3];
        // Upper 32 bits of b[3] carry to a[4]. Because a[4] <= 4, this processing can never overflow
        a[4] += (uint32_t)(b[3] >> 32) + padbit;

        /* Lower bits of the data product. Because the high bits of each term of r are processed,
           there is no carry in the following polynomial multiplication and addition. */
        b[0] = (uint64_t)a[0] * r[0];
        b[1] = (uint64_t)a[0] * r[1] + (uint64_t)a[1] * r[0];
        b[2] = (uint64_t)a[0] * r[2] + (uint64_t)a[1] * r[1] + (uint64_t)a[2] * r[0];
        b[3] = (uint64_t)a[0] * r[3] + (uint64_t)a[1] * r[2] + (uint64_t)a[2] * r[1] + (uint64_t)a[3] * r[0];

        /**
         * Higher bits of the data product. Because the high bits of each term of r are processed,
         * there is no carry in the following polynomial multiplication and addition.
         */
        // (Ensure that the calculation (b[4] * 5) does not overflow, calculate (a[4] * r[0]) items later.)
        b[4] = (uint64_t)a[1] * r[3] + (uint64_t)a[2] * r[2] + (uint64_t)a[3] * r[1];
        b[5] = (uint64_t)a[2] * r[3] + (uint64_t)a[3] * r[2] + (uint64_t)a[4] * r[1];
        b[6] = (uint64_t)a[3] * r[3] + (uint64_t)a[4] * r[2];
        b[7] = (uint64_t)a[4] * r[3];
        /**
         * The upper bits are multiplied by 5/4, because r1, r[2], r3 is processed,
         * so the above values are divisible by 4. Because the high bits of each term of r are processed,
         * there is no carry in the following polynomial multiplication and addition: (3 * 5) < 0xF
         */
        b[4] = (b[4] >> 2) + b[4];
        b[5] = (b[5] >> 2) + b[5];
        b[6] = (b[6] >> 2) + b[6];
        b[7] = (b[7] >> 2) + b[7];
        /* After offset 130 bits, the combination is obtained a0 = b[4] * 5 + b[0]....
           Because the high bits of each term of r are processed,
           there is no carry in the following polynomial multiplication and addition. */
        b[0] += (b[4] & 0xFFFFFFFF);
        b[1] += (b[0] >> 32) + (b[4] >> 32) + (b[5] & 0xFFFFFFFF);
        b[2] += (b[1] >> 32) + (b[5] >> 32) + (b[6] & 0xFFFFFFFF);
        b[3] += (b[2] >> 32) + (b[6] >> 32) + (b[7] & 0xFFFFFFFF);
        a[4] = a[4] * r[0] + (uint32_t)(b[3] >> 32) + (uint32_t)(b[7] >> 32);
        b[0] = (uint32_t)b[0];
        b[1] = (uint32_t)b[1];
        b[2] = (uint32_t)b[2];
        b[3] = (uint32_t)b[3];
        // Shift the upper bits of a4 by 130 bits and then multiply it by 5.
        // The amount of a4 data is small and carry cannot be occurred.
        b[0] += (a[4] >> 2) + (a[4] & 0xFFFFFFFC);
        a[4] &= 0x3;

        /* Process carry */
        b[1] += (b[0] >> 32);
        b[2] += (b[1] >> 32);
        b[3] += (b[2] >> 32);
        a[4] += (uint32_t)(b[3] >> 32);

        a[0] = (uint32_t)b[0];
        a[1] = (uint32_t)b[1];
        a[2] = (uint32_t)b[2];
        a[3] = (uint32_t)b[3];
        len -= POLY1305_BLOCKSIZE;
        off += POLY1305_BLOCKSIZE;
    }

    ctx->acc[0] = a[0];
    ctx->acc[1] = a[1];
    ctx->acc[2] = a[2];
    ctx->acc[3] = a[3];
    ctx->acc[4] = a[4];

    // Clear sensitive information.
    BSL_SAL_CleanseData(a, sizeof(a));
    BSL_SAL_CleanseData(r, sizeof(r));
    BSL_SAL_CleanseData(b, sizeof(b));
    return len;
}

void Poly1305Last(Poly1305Ctx *ctx, uint8_t mac[POLY1305_TAGSIZE])
{
    uint32_t a[5];
    uint64_t b[5];
    a[0] = ctx->acc[0];
    a[1] = ctx->acc[1];
    a[2] = ctx->acc[2];
    a[3] = ctx->acc[3];
    a[4] = ctx->acc[4];
    /* Check whether it is greater than p. */
    b[0] = (uint64_t)(a[0]) + 5;
    b[1] = a[1] + (b[0] >> 32);
    b[2] = a[2] + (b[1] >> 32);
    b[3] = a[3] + (b[2] >> 32);
    b[4] = a[4] + (b[3] >> 32);
    /* Obtain the mask. If there is a carry, the number is greater than p. */
    if ((b[4] & 0x4) == 0) {    // b[4] & 0x4 is bit131.
        b[0] = a[0];
        b[1] = a[1];
        b[2] = a[2];
        b[3] = a[3];
    }
    // Adding s at the end does not require modulo processing.
    b[0] = ctx->s[0] + (b[0] & 0xffffffff);
    b[1] = ctx->s[1] + (b[1] & 0xffffffff) + (b[0] >> 32);
    b[2] = ctx->s[2] + (b[2] & 0xffffffff) + (b[1] >> 32);
    b[3] = ctx->s[3] + (b[3] & 0xffffffff) + (b[2] >> 32);
    PUT_UINT32_LE(b[0], mac, 0);
    PUT_UINT32_LE(b[1], mac, 4);
    PUT_UINT32_LE(b[2], mac, 8);
    PUT_UINT32_LE(b[3], mac, 12);

    // Clear sensitive information.
    BSL_SAL_CleanseData(a, sizeof(a));
    BSL_SAL_CleanseData(b, sizeof(b));
}

// Clear the residual sensitive information in the register.
// This function is implemented only when the assembly function is enabled.
void Poly1305CleanRegister(void)
{
    return;
}
#endif
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
#ifdef HITLS_CRYPTO_CHACHA20

#include "crypt_utils.h"
#include "chacha20_local.h"

void CHACHA20_Update(CRYPT_CHACHA20_Ctx *ctx, const uint8_t *in,
    uint8_t *out, uint32_t len)
{
    const uint8_t *offIn = in;
    uint8_t *offOut = out;
    uint32_t tLen = len;
    // one block is processed each time
    while (tLen >= CHACHA20_STATEBYTES) {
        CHACHA20_Block(ctx);
        // Process 64 bits at a time
        DATA64_XOR(ctx->last.u, offIn, offOut, CHACHA20_STATEBYTES);
        offIn += CHACHA20_STATEBYTES;
        offOut += CHACHA20_STATEBYTES;
        tLen -= CHACHA20_STATEBYTES;
    }
}
#endif // HITLS_CRYPTO_CHACHA20

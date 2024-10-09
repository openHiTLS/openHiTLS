/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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

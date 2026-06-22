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
#ifdef HITLS_CRYPTO_FRODOKEM
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypt_errno.h"
#include "eal_md_local.h"
#include "bsl_errno.h"
#include "frodo_local.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"

#define FRODO_MAX_SEED_LEN 64
#define FRODO_PREFIX_LEN   1

void FrodoCommonPack(uint8_t *out, const uint32_t outLen, const uint16_t *in, const uint32_t inLen, const uint8_t lsb)
{
    (void)outLen;
    if (lsb == 16) {
        for (uint32_t i = 0; i < inLen; i++) {
            out[i * 2 + 0] = in[i] >> 8;
            out[i * 2 + 1] = in[i] & 0xFF;
        }
        return;
    }

    // lsb = 15
    for (uint32_t i = 0; i < inLen; i += 8) {
        uint16_t a0 = in[0] & 0x7FFF;
        uint16_t a1 = in[1] & 0x7FFF;
        uint16_t a2 = in[2] & 0x7FFF;
        uint16_t a3 = in[3] & 0x7FFF;
        uint16_t a4 = in[4] & 0x7FFF;
        uint16_t a5 = in[5] & 0x7FFF;
        uint16_t a6 = in[6] & 0x7FFF;
        uint16_t a7 = in[7] & 0x7FFF;

        a0 = (a0 << 1) | (a1 >> 14);
        a1 = (a1 << 2) | (a2 >> 13);
        a2 = (a2 << 3) | (a3 >> 12);
        a3 = (a3 << 4) | (a4 >> 11);
        a4 = (a4 << 5) | (a5 >> 10);
        a5 = (a5 << 6) | (a6 >> 9);
        a6 = (a6 << 7) | (a7 >> 8);

        out[0] = a0 >> 8;
        out[1] = a0 & 0xFF;
        out[2] = a1 >> 8;
        out[3] = a1 & 0xFF;
        out[4] = a2 >> 8;
        out[5] = a2 & 0xFF;
        out[6] = a3 >> 8;
        out[7] = a3 & 0xFF;
        out[8] = a4 >> 8;
        out[9] = a4 & 0xFF;
        out[10] = a5 >> 8;
        out[11] = a5 & 0xFF;
        out[12] = a6 >> 8;
        out[13] = a6 & 0xFF;
        out[14] = a7;

        in += 8;
        out += 15;
    }
}

void FrodoCommonUnpack(uint16_t *out, const uint32_t outLen, const uint8_t *in, const uint32_t inLen,
                       const uint8_t lsb)
{
    if (lsb == 16) {
        for (uint32_t i = 0; i < outLen; i++) {
            out[i] = (in[i * 2] << 8) | in[i * 2 + 1];
        }
        return;
    }

    // lsb = 15
    for (uint32_t i = 0; i < inLen; i += 15) {
        out[0] = (in[0] << 7) | (in[1] >> 1);
        out[1] = ((in[1] & 0x01) << 14) | (in[2] << 6) | (in[3] >> 2);
        out[2] = ((in[3] & 0x03) << 13) | (in[4] << 5) | (in[5] >> 3);
        out[3] = ((in[5] & 0x07) << 12) | (in[6] << 4) | (in[7] >> 4);
        out[4] = ((in[7] & 0x0F) << 11) | (in[8] << 3) | (in[9] >> 5);
        out[5] = ((in[9] & 0x1F) << 10) | (in[10] << 2) | (in[11] >> 6);
        out[6] = ((in[11] & 0x3F) << 9) | (in[12] << 1) | (in[13] >> 7);
        out[7] = ((in[13] & 0x7F) << 8) | in[14];

        in += 15;
        out += 8;
    }
}

void FrodoCommonEncodeLe16(uint8_t *out, const uint16_t *in, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        out[2 * i] = (uint8_t)(in[i] & 0xffu);
        out[2 * i + 1] = (uint8_t)(in[i] >> 8);
    }
}

void FrodoCommonDecodeLe16(uint16_t *out, const uint8_t *in, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        out[i] = (uint16_t)in[2 * i] | ((uint16_t)in[2 * i + 1] << 8);
    }
}

int32_t FrodoExpandShakeDs(uint8_t *out, uint32_t outlen, uint8_t ds, const uint8_t *seed, uint32_t seedlen,
                           const FrodoKemParams *params, void *libCtx)
{
    uint8_t in[FRODO_PREFIX_LEN + FRODO_MAX_SEED_LEN] = {0};
    in[0] = ds;
    memcpy(in + FRODO_PREFIX_LEN, seed, seedlen);
    uint32_t len = outlen;
    int32_t ret = EAL_Md(params->hashId, libCtx, NULL, in, 1 + seedlen, out, &len, false, libCtx != NULL);
    BSL_SAL_CleanseData(in, sizeof(in));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif

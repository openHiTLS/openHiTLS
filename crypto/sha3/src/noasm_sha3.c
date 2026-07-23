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
#ifdef HITLS_CRYPTO_SHA3

#include <stdlib.h>
#include <string.h>
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "crypt_sha3.h"
#include "sha3_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

// Absorbing function of the sponge structure
const uint8_t *SHA3_Absorb(uint8_t *state, const uint8_t *in, uint32_t inLen, uint32_t r)
{
    const uint8_t *data = (const uint8_t *)in;
    uint64_t *pSt = (uint64_t *)(uintptr_t)state;
    uint32_t dataLen = inLen;
    // Divide one block data into some uint64_t data (8 bytes) and perform XOR with the status variable.
    uint32_t blockInWord = r / 8;

    while (dataLen >= r) {
        for (uint32_t i = 0; i < blockInWord; i++) {
            uint64_t oneLane = GET_UINT64_LE(data, i << 3);
            pSt[i] ^= oneLane;
        }

        // Process one block data.
        SHA3_Keccak(state);
        dataLen -= r;
        data += r;
    }

    return (const uint8_t *)data;
}

// Squeezing function of the sponge structure
void SHA3_Squeeze(uint8_t *state, uint8_t *out, uint32_t outLen, uint32_t r, bool isNeedKeccak)
{
    uint32_t dataLen = outLen;
    uint32_t copyLen;
    // Divide one block data into some uint64_t data (8 bytes) and perform XOR with the status variable.
    uint32_t blockInWord = r / 8;
    uint64_t *oneLane = (uint64_t *)(uintptr_t)state;
    uint8_t outTmp[168];  // 168 = (1600 - 128 * 2) / 8, blockSize of the shake128 algorithm is the maximum.

    while (dataLen > 0) {
        copyLen = (dataLen > r) ? r : dataLen;

        for (uint32_t i = 0; i < blockInWord; i++) {
            PUT_UINT64_LE(oneLane[i], outTmp, i << 3); // left shift by 3 bits equals i * 8.
        }
        memcpy(out + outLen - dataLen, outTmp, copyLen);
        dataLen -= copyLen;
        if (dataLen > 0 || isNeedKeccak) {
            SHA3_Keccak(state);
        }
    }
}

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA3

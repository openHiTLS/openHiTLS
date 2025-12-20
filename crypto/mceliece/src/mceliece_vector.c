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
#ifdef HITLS_CRYPTO_CLASSIC_MCELIECE
#include <stdint.h>

void VectorSetBit(uint8_t *vec, const uint32_t bitIdx, const uint32_t value)
{
    uint32_t byteIdx = bitIdx >> 3; // bitidx/8
    uint32_t bitPos = bitIdx & 7; // mod 8
    if (value != 0) {
        vec[byteIdx] |= (1 << bitPos);
    } else {
        vec[byteIdx] &= ~(1 << bitPos);
    }
}

uint32_t VectorGetBit(const uint8_t *vec, const uint32_t bitIdx)
{
    uint32_t byteIdx = bitIdx >> 3; // bitidx/8
    uint32_t bitPos = bitIdx & 7; // mod 8
    return (vec[byteIdx] >> bitPos) & 1; // lsb
}

int32_t VectorWeight(const uint8_t *vec, const int32_t lenBytes)
{
    int32_t weight = 0;
    for (int32_t i = 0; i < lenBytes; i++) {
        uint8_t byte = vec[i];
        // Brian Kernighan alg.
        while (byte) {
            byte &= byte - 1;
            weight++;
        }
    }
    return weight;
}
#endif

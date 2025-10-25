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

#include "mceliece_vector.h"

void VectorSetBit(uint8_t *vec, int bitIdx, bool value)
{
    int byteIdx = bitIdx >> 3;
    int bitPos = bitIdx & 7;
    if (value) {
        vec[byteIdx] |= (1 << bitPos);
    } else {
        vec[byteIdx] &= ~(1 << bitPos);
    }
}

int VectorGetBit(const uint8_t *vec, int bitIdx)
{
    int byteIdx = bitIdx >> 3;
    int bitPos = bitIdx & 7;
    return (vec[byteIdx] >> bitPos) & 1;
}

int VectorWeight(const uint8_t *vec, int lenBytes)
{
    int weight = 0;
    for (int i = 0; i < lenBytes; i++) {
        uint8_t byte = vec[i];
        // Brian Kernighan alg.
        while (byte) {
            byte &= byte - 1;
            weight++;
        }
    }
    return weight;
}
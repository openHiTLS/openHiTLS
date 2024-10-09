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
#ifdef HITLS_CRYPTO_GCM

#include "bsl_sal.h"
#include "crypt_utils.h"
#include "modes_local.h"

/* table[i] = (P^4)*i, P = 0x4000000000000000, i = 0...16 */
static const uint64_t TABLE_P4_BITS[16] = {
    0x0000000000000000, 0x1c20000000000000, 0x3840000000000000, 0x2460000000000000,
    0x7080000000000000, 0x6ca0000000000000, 0x48c0000000000000, 0x54e0000000000000,
    0xe100000000000000, 0xfd20000000000000, 0xd940000000000000, 0xc560000000000000,
    0x9180000000000000, 0x8da0000000000000, 0xa9c0000000000000, 0xb5e0000000000000
};

// Calculate n*H, n is in 0 .... 16
void GcmTableGen4bit(uint8_t key[GCM_BLOCKSIZE], MODES_GCM_GF128 hTable[16])
{
    uint32_t i;
    uint32_t j;
    const uint64_t r = 0xE100000000000000;
    hTable[0].h = 0;
    hTable[0].l = 0;
    // The intermediate term of the table (16 / 2 = = 8) is H itself.
    hTable[8].h = Uint64FromBeBytes(key);
    // The intermediate term of the table (16 / 2 = = 8) is H itself.
    hTable[8].l = Uint64FromBeBytes(key + sizeof(uint64_t));

    for (i = 4; i > 0; i >>= 1) { // 4-bit table, the value of the 2^n item is calculated first.
        // cyclically shift to right by 1bit. The upper 1 bit of h is combined with the lower 63 bits of l.
        hTable[i].l = (hTable[ i * 2].h << 63) | (hTable[ i * 2].l >> 1);
        hTable[i].h = (hTable[ i * 2].h >> 1) ^ ((hTable[ i * 2].l & 1) * r); // the value of the 2^n item
    }
    for (i = 1; i < 16; i <<= 1) {
        for (j = 1; j < i; j++) {
            hTable[i + j].h = hTable[i].h ^ hTable[j].h;
            hTable[i + j].l = hTable[i].l ^ hTable[j].l;
        }
    }
}

// Calculate t = t * H
void GcmHashMultiBlock(uint8_t t[GCM_BLOCKSIZE], const MODES_GCM_GF128 hTable[16], const uint8_t *in, uint32_t inLen)
{
    MODES_GCM_GF128 x;
    uint8_t r;
    uint8_t h, l, tag;   // Ciphertext information, digest information, and non-sensitive information.
    const uint8_t *tempIn = in;
    for (uint32_t i = 0; i < inLen; i += GCM_BLOCKSIZE) {
        uint8_t cnt = GCM_BLOCKSIZE - 1;
        x.h = 0;
        x.l = 0;
        while (1) {
            tag = t[cnt] ^ tempIn[cnt];

            l = tag & 0xf;
            h = (tag >> 4) & 0xf;
            x.h ^= hTable[l].h;
            x.l ^= hTable[l].l;

            r = (x.l & 0xf);
            // Cyclically shift to right by 4 bits. The upper 4 bits of h is combined with the lower 60 bits of l.
            x.l  = (x.h << 60) | (x.l >> 4);
            x.h  = (x.h >> 4); // Cyclically shift to right by 4 bits.
            x.h ^= TABLE_P4_BITS[r];

            x.h ^= hTable[h].h;
            x.l ^= hTable[h].l;
            if (cnt == 0) {
                break;
            }
            cnt--;
            r = (x.l & 0xf);
            // Cyclically shift to right by 4 bits. The upper 4 bits of h is combined with the lower 60 bits of l.
            x.l  = (x.h << 60) | (x.l >> 4);
            x.h  = (x.h >> 4); // Cyclically shift to right by 4 bits.
            x.h ^= TABLE_P4_BITS[r];
        }
        tempIn += GCM_BLOCKSIZE;
        Uint64ToBeBytes(x.h, t);
        Uint64ToBeBytes(x.l, t + 8);
    }
    // Clear sensitive information.
    BSL_SAL_CleanseData(&x, sizeof(MODES_GCM_GF128));
    BSL_SAL_CleanseData(&r, sizeof(uint8_t));
}
#endif
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

#include "mceliece_rng.h"
#include "securec.h"

typedef struct {
    unsigned char Key[32];
    unsigned char V[16];
    int reseed_counter;
} McElieceAES256CTRDrbgStruct;

static McElieceAES256CTRDrbgStruct g_McElieceDrbgCtx;
static int g_256Ready = 0;
static CRYPT_EAL_CipherCtx *g_RandCtx = NULL;

static inline void DrbgSetAES256Key(const uint8_t key[32])
{
    g_RandCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES256_ECB);
    if (g_RandCtx == NULL) {
        fprintf(stderr, "ERROR! CRYPT_EAL_CipherNewCtx failed!\n");
        exit(1);
    } else {
        if (CRYPT_EAL_CipherInit(g_RandCtx, key, 32, NULL, 0, true) != 0) {
            fprintf(stderr, "ERROR! CRYPT_EAL_CipherInit failed!\n");
            CRYPT_EAL_CipherFreeCtx(g_RandCtx);
        }
        if (CRYPT_EAL_CipherSetPadding(g_RandCtx, CRYPT_PADDING_NONE) != 0) {
            fprintf(stderr, "ERROR! CRYPT_EAL_CipherSetPadding failed!\n");
            CRYPT_EAL_CipherFreeCtx(g_RandCtx);
        }
        g_256Ready = 1;
    }
}

static inline void ModeCTRIncBE(uint8_t V[16])
{
    for (int i = 15; i >= 0; i--) {
        if (V[i] == 0xFF) {
            V[i] = 0x00;
        } else {
            V[i]++;
            break;
        }
    }
}

static inline void McElieceDrbgAES256Block(const uint8_t in[16], uint8_t out[16])
{
    int outlen = 16;
    int32_t ret = CRYPT_EAL_CipherUpdate(g_RandCtx, in, 16, out, &outlen);
    if (ret != 0) {
        fprintf(stderr, "ERROR! CRYPT_EAL_CipherUpdate failed! : %d\n", ret);
        exit(1);
    }
}

static void McElieceAES256CTRDrbgUpdate(unsigned char *provided_data, unsigned char *Key, unsigned char *V)
{
    uint8_t temp[48];
    uint8_t block[16];

    for (int i = 0; i < 3; i++) {
        ModeCTRIncBE(V);
        McElieceDrbgAES256Block(V, block);
        memcpy(&temp[16 * i], block, 16);
    }

    if (provided_data != NULL) {
        for (int i = 0; i < 48; i++)
            temp[i] ^= provided_data[i];
    }

    memcpy(Key, temp, 32);
    memcpy(V, temp + 32, 16);

    DrbgSetAES256Key(Key);
}

void McElieceRandombytesInit(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength)
{
    (void)security_strength;
    uint8_t seed_material[48];

    memcpy(seed_material, entropy_input, 48);
    if (personalization_string) {
        for (int i = 0; i < 48; i++) {
            seed_material[i] ^= personalization_string[i];
        }
    }
    memset(g_McElieceDrbgCtx.Key, 0x00, 32);
    memset(g_McElieceDrbgCtx.V, 0x00, 16);

    DrbgSetAES256Key(g_McElieceDrbgCtx.Key);
    McElieceAES256CTRDrbgUpdate(seed_material, g_McElieceDrbgCtx.Key, g_McElieceDrbgCtx.V);
    g_McElieceDrbgCtx.reseed_counter = 1;
}

void McElieceRandombytes(uint8_t *x, uint32_t xlen)
{
    uint8_t block[16];
    unsigned long long produced = 0;

    if (!g_256Ready) {
        memset(g_McElieceDrbgCtx.Key, 0, 32);
        DrbgSetAES256Key(g_McElieceDrbgCtx.Key);
    }

    while (xlen > 0) {
        ModeCTRIncBE(g_McElieceDrbgCtx.V);
        McElieceDrbgAES256Block(g_McElieceDrbgCtx.V, block);

        size_t take = (xlen >= 16) ? 16u : (size_t)xlen;
        memcpy(x + produced, block, take);
        produced += take;
        xlen -= take;
    }

    McElieceAES256CTRDrbgUpdate(NULL, g_McElieceDrbgCtx.Key, g_McElieceDrbgCtx.V);
    g_McElieceDrbgCtx.reseed_counter++;
}
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
#include "mceliece_local.h"

#define PQC_ALG_ID_MCELIECE_COUNT 12

static McelieceParams g_allMcelieceParams[PQC_ALG_ID_MCELIECE_COUNT] = {
    /* [PQC_ALG_ID_MCELIECE_6688128] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6688128,
        .m = 13,
        .n = 6688,
        .t = 128,
        .mt = 1664,
        .k = 5024,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 836,
        .mtBytes = 208,
        .kBytes = 628,
        .privateKeyBytes = 13932,
        .publicKeyBytes = 1044992,
        .cipherBytes = 208,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_6688128_F] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6688128_F,
        .m = 13,
        .n = 6688,
        .t = 128,
        .mt = 1664,
        .k = 5024,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 836,
        .mtBytes = 208,
        .kBytes = 628,
        .privateKeyBytes = 13932,
        .publicKeyBytes = 1044992,
        .cipherBytes = 208,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_6688128_PC] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6688128_PC,
        .m = 13,
        .n = 6688,
        .t = 128,
        .mt = 1664,
        .k = 5024,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 836,
        .mtBytes = 208,
        .kBytes = 628,
        .privateKeyBytes = 13932,
        .publicKeyBytes = 1044992,
        .cipherBytes = 240,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 1,
    },
    /* [PQC_ALG_ID_MCELIECE_6688128_PCF] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6688128_PCF,
        .m = 13,
        .n = 6688,
        .t = 128,
        .mt = 1664,
        .k = 5024,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 836,
        .mtBytes = 208,
        .kBytes = 628,
        .privateKeyBytes = 13932,
        .publicKeyBytes = 1044992,
        .cipherBytes = 240,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 1,
    },
    /* [PQC_ALG_ID_MCELIECE_6960119] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6960119,
        .m = 13,
        .n = 6960,
        .t = 119,
        .mt = 1547,
        .k = 5413,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 870,
        .mtBytes = 194,
        .kBytes = 677,
        .privateKeyBytes = 13948,
        .publicKeyBytes = 1047319,
        .cipherBytes = 194,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_6960119_F] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6960119_F,
        .m = 13,
        .n = 6960,
        .t = 119,
        .mt = 1547,
        .k = 5413,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 870,
        .mtBytes = 194,
        .kBytes = 677,
        .privateKeyBytes = 13948,
        .publicKeyBytes = 1047319,
        .cipherBytes = 194,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_6960119_PC] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6960119_PC,
        .m = 13,
        .n = 6960,
        .t = 119,
        .mt = 1547,
        .k = 5413,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 870,
        .mtBytes = 226,
        .kBytes = 677,
        .privateKeyBytes = 13948,
        .publicKeyBytes = 1047319,
        .cipherBytes = 226,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 1,
    },
    /* [PQC_ALG_ID_MCELIECE_6960119_PCF] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_6960119_PCF,
        .m = 13,
        .n = 6960,
        .t = 119,
        .mt = 1547,
        .k = 5413,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 870,
        .mtBytes = 226,
        .kBytes = 677,
        .privateKeyBytes = 13948,
        .publicKeyBytes = 1047319,
        .cipherBytes = 226,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 1,
    },
    /* [PQC_ALG_ID_MCELIECE_8192128] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_8192128,
        .m = 13,
        .n = 8192,
        .t = 128,
        .mt = 1664,
        .k = 6528,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 1024,
        .mtBytes = 208,
        .kBytes = 816,
        .privateKeyBytes = 14120,
        .publicKeyBytes = 1357824,
        .cipherBytes = 208,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_8192128_F] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_8192128_F,
        .m = 13,
        .n = 8192,
        .t = 128,
        .mt = 1664,
        .k = 6528,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 1024,
        .mtBytes = 208,
        .kBytes = 816,
        .privateKeyBytes = 14120,
        .publicKeyBytes = 1357824,
        .cipherBytes = 208,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_8192128_PC] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_8192128_PC,
        .m = 13,
        .n = 8192,
        .t = 128,
        .mt = 1664,
        .k = 6528,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 1024,
        .mtBytes = 208,
        .kBytes = 816,
        .privateKeyBytes = 14120,
        .publicKeyBytes = 1357824,
        .cipherBytes = 240,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 1,
    },
    /* [PQC_ALG_ID_MCELIECE_8192128_PCF] */
    {
        .algId = CRYPT_KEM_TYPE_MCELIECE_8192128_PCF,
        .m = 13,
        .n = 8192,
        .t = 128,
        .mt = 1664,
        .k = 6528,
        .q = 8192,
        .q1 = 8191,
        .nBytes = 1024,
        .mtBytes = 208,
        .kBytes = 816,
        .privateKeyBytes = 14120,
        .publicKeyBytes = 1357824,
        .cipherBytes = 240,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 1,
    },
};

McelieceParams *McelieceGetParamsById(int32_t algId)
{
    const int32_t base = CRYPT_KEM_TYPE_MCELIECE_6688128;
    const int32_t max = CRYPT_KEM_TYPE_MCELIECE_8192128_PCF;

    if ((algId - base) > (max - base)) {
        return NULL;
    }

    return &g_allMcelieceParams[algId - base];
}
#endif

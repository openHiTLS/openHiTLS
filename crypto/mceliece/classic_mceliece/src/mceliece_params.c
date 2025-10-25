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

#include "internal/mceliece_params.h"
#include "mceliece_types.h"
#include <stddef.h>

static McelieceParams all_mceliece_params[PQC_ALG_ID_MCELIECE_COUNT] = {
    /* [PQC_ALG_ID_MCELIECE_6688128] */
    {
        .name = "mceliece6688128",
        .m = 13,
        .n = 6688,
        .t = 128,
        .mt = 1664, .k = 5024, .q = 8192, .q1 = 8191,
        .nBytes = 836, .mtBytes = 208, .kBytes = 628,
        .privateKeyBytes = 13932,
        .publicKeyBytes = 1044992,
        .cipherBytes = 208,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_6688128_F] */
    {
        .name = "mceliece6688128f",
        .m = 13,
        .n = 6688,
        .t = 128,
        .mt = 1664, .k = 5024, .q = 8192, .q1 = 8191,
        .nBytes = 836, .mtBytes = 208, .kBytes = 628,
        .privateKeyBytes = 13932,
        .publicKeyBytes = 1044992,
        .cipherBytes = 208,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_6688128_PC] */
    {
        .name = "mceliece6688128pc",
        .m = 13,
        .n = 6688,
        .t = 128,
        .mt = 1664, .k = 5024, .q = 8192, .q1 = 8191,
        .nBytes = 836, .mtBytes = 208, .kBytes = 628,
        .privateKeyBytes = 13932,
        .publicKeyBytes = 1044992,
        .cipherBytes = 240,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 1,
    },
    /* [PQC_ALG_ID_MCELIECE_6688128_PCF] */
    {
        .name = "mceliece6688128pcf",
        .m = 13,
        .n = 6688,
        .t = 128,
        .mt = 1664, .k = 5024, .q = 8192, .q1 = 8191,
        .nBytes = 836, .mtBytes = 208, .kBytes = 628,
        .privateKeyBytes = 13932,
        .publicKeyBytes = 1044992,
        .cipherBytes = 240,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 1,
    },
    /* [PQC_ALG_ID_MCELIECE_6960119] */
    {
        .name = "mceliece6960119",
        .m = 13,
        .n = 6960,
        .t = 119,
        .mt = 1547, .k = 5413, .q = 8192, .q1 = 8191,
        .nBytes = 870, .mtBytes = 194, .kBytes = 677,
        .privateKeyBytes = 13948,
        .publicKeyBytes = 1047319,
        .cipherBytes = 194,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_6960119_F] */
    {
        .name = "mceliece6960119f",
        .m = 13,
        .n = 6960,
        .t = 119,
        .mt = 1547, .k = 5413, .q = 8192, .q1 = 8191,
        .nBytes = 870, .mtBytes = 194, .kBytes = 677,
        .privateKeyBytes = 13948,
        .publicKeyBytes = 1047319,
        .cipherBytes = 194,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 0,
    },
    /* [PQC_ALG_ID_MCELIECE_6960119_PC] */
    {
        .name = "mceliece6960119pc",
        .m = 13,
        .n = 6960,
        .t = 119,
        .mt = 1547, .k = 5413, .q = 8192, .q1 = 8191,
        .nBytes = 870, .mtBytes = 194, .kBytes = 677,
        .privateKeyBytes = 13948,
        .publicKeyBytes = 1047319,
        .cipherBytes = 226,
        .sharedKeyBytes = 32,
        .semi = 0,
        .pc = 1,
    },
    /* [PQC_ALG_ID_MCELIECE_6960119_PCF] */
    {
        .name = "mceliece6960119pcf",
        .m = 13,
        .n = 6960,
        .t = 119,
        .mt = 1547, .k = 5413, .q = 8192, .q1 = 8191,
        .nBytes = 870, .mtBytes = 194, .kBytes = 677,
        .privateKeyBytes = 13948,
        .publicKeyBytes = 1047319,
        .cipherBytes = 226,
        .sharedKeyBytes = 32,
        .semi = 1,
        .pc = 1,
    },
    /* [PQC_ALG_ID_MCELIECE_8192128] */
     {
         .name = "mceliece8192128",
         .m = 13,
         .n = 8192,
         .t = 128,
         .mt = 1664, .k = 6528, .q = 8192, .q1 = 8191,
         .nBytes = 1024, .mtBytes = 208, .kBytes = 816,
         .privateKeyBytes = 14120,
         .publicKeyBytes = 1357824,
         .cipherBytes = 208,
         .sharedKeyBytes = 32,
         .semi = 0,
         .pc = 0,
     },
     /* [PQC_ALG_ID_MCELIECE_8192128_F] */
     {
         .name = "mceliece8192128f",
         .m = 13,
         .n = 8192,
         .t = 128,
         .mt = 1664, .k = 6528, .q = 8192, .q1 = 8191,
         .nBytes = 1024, .mtBytes = 208, .kBytes = 816,
         .privateKeyBytes = 14120,
         .publicKeyBytes = 1357824,
         .cipherBytes = 208,
         .sharedKeyBytes = 32,
         .semi = 1,
         .pc = 0,
     },
     /* [PQC_ALG_ID_MCELIECE_8192128_PC] */
     {
         .name = "mceliece8192128pc",
         .m = 13,
         .n = 8192,
         .t = 128,
         .mt = 1664, .k = 6528, .q = 8192, .q1 = 8191,
         .nBytes = 1024, .mtBytes = 208, .kBytes = 816,
         .privateKeyBytes = 14120,
         .publicKeyBytes = 1357824,
         .cipherBytes = 240,
         .sharedKeyBytes = 32,
         .semi = 0,
         .pc = 1,
     },
     /* [PQC_ALG_ID_MCELIECE_8192128_PCF] */
     {
         .name = "mceliece8192128pcf",
         .m = 13,
         .n = 8192,
         .t = 128,
         .mt = 1664, .k = 6528, .q = 8192, .q1 = 8191,
         .nBytes = 1024, .mtBytes = 208, .kBytes = 816,
         .privateKeyBytes = 14120,
         .publicKeyBytes = 1357824,
         .cipherBytes = 240,
         .sharedKeyBytes = 32,
         .semi = 1,
         .pc = 1,
     },
};

McelieceParams* McelieceGetParamsById(const PQC_Mceliece_AlgWithParamId alg_id)
{
    const int base = PQC_ALG_ID_MCELIECE_6688128;
    const int max  = PQC_ALG_ID_MCELIECE_8192128_PCF;

    if ((unsigned)(alg_id - base) > (max - base)) {
        return NULL;
    }

    return &all_mceliece_params[alg_id - base];
}

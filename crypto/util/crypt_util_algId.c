/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_RSA

#include "crypt_local_types.h"
#include "crypt_utils.h"
typedef struct {
    CRYPT_MD_AlgId id;
    uint32_t mdSize;
} CRYPT_MdInfo;

uint32_t CRYPT_MD_GetSizeById(CRYPT_MD_AlgId id)
{
    // need synchronize with enum CRYPT_MD_AlgId
    static CRYPT_MdInfo mdInfo[] = {
        {.id = CRYPT_MD_MD4, .mdSize = 16},
        {.id = CRYPT_MD_MD5, .mdSize = 16},
        {.id = CRYPT_MD_SHA1, .mdSize = 20},
        {.id = CRYPT_MD_SHA224, .mdSize = 28},
        {.id = CRYPT_MD_SHA256, .mdSize = 32},
        {.id = CRYPT_MD_SHA384, .mdSize = 48},
        {.id = CRYPT_MD_SHA512, .mdSize = 64},
        {.id = CRYPT_MD_SHA3_224, .mdSize = 28},
        {.id = CRYPT_MD_SHA3_256, .mdSize = 32},
        {.id = CRYPT_MD_SHA3_384, .mdSize = 48},
        {.id = CRYPT_MD_SHA3_512, .mdSize = 64},
        {.id = CRYPT_MD_SHAKE128, .mdSize = 0},
        {.id = CRYPT_MD_SHAKE256, .mdSize = 0},
        {.id = CRYPT_MD_SM3, .mdSize = 32},
        {.id = CRYPT_MD_MAX, .mdSize = 0},
    };
    uint32_t i = 0;

    while (mdInfo[i].id != CRYPT_MD_MAX) {
        if (mdInfo[i].id == id) {
            return mdInfo[i].mdSize;
        }
        i++;
    }

    return 0;
}
#endif

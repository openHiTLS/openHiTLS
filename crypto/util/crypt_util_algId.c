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
#ifdef HITLS_CRYPTO_RSA

#include "crypt_local_types.h"
#include "crypt_utils.h"
typedef struct {
    CRYPT_MD_AlgId id;
    uint32_t mdSize;
} CRYPT_MdInfo;

uint32_t CRYPT_GetMdSizeById(CRYPT_MD_AlgId id)
{
    // need synchronize with enum CRYPT_MD_AlgId
    static CRYPT_MdInfo mdInfo[] = {
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

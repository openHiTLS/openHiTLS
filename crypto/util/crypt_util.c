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
#include <stdio.h>
#include "crypt_utils.h"
#include "crypt_algid.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "bsl_init.h"

#define CRYPT_INIT_ABILITY_CPU_POS   0
#define CRYPT_INIT_ABILITY_BSL_POS   1
#define CRYPT_INIT_ABILITY_RAND_POS  2

#define CRYPT_INIT_ABILITY_BITMAP(value, pos) (((value) >> (pos)) & 0x1)
#define CRYPT_INIT_SUPPORT_ABILITY(cap, pos) (CRYPT_INIT_ABILITY_BITMAP(cap, pos) != 0)

int32_t CRYPT_EAL_Init(uint64_t opts, void* data, uint32_t datalen)
{
    (void)data;
    (void)datalen;
    int32_t ret = CRYPT_SUCCESS;

    if (CRYPT_INIT_SUPPORT_ABILITY(opts, CRYPT_INIT_ABILITY_BSL_POS)) {
#ifdef HITLS_BSL_INIT
        ret = BSL_GLOBAL_Init();
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
#else
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;

#endif
    }

    if (CRYPT_INIT_SUPPORT_ABILITY(opts, CRYPT_INIT_ABILITY_RAND_POS)) {
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_DRBG)
        ret = CRYPT_EAL_RandInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0);
        if (ret != CRYPT_SUCCESS) {
            if (CRYPT_INIT_SUPPORT_ABILITY(opts, CRYPT_INIT_ABILITY_BSL_POS)) {
                BSL_GLOBAL_DeInit();
            }
            return ret;
        }
#else
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_ALG_NOT_SUPPORT);
        return CRYPT_DRBG_ALG_NOT_SUPPORT;
#endif
    }
    return ret;
}

void CRYPT_EAL_Cleanup(uint64_t opts)
{
    if (CRYPT_INIT_SUPPORT_ABILITY(opts, CRYPT_INIT_ABILITY_RAND_POS)) {
#if defined(HITLS_CRYPTO_DRBG) && defined(HITLS_CRYPTO_ENTROPY)
        CRYPT_EAL_RandDeinit();
#endif
    }

    if (CRYPT_INIT_SUPPORT_ABILITY(opts, CRYPT_INIT_ABILITY_BSL_POS)) {
#ifdef HITLS_BSL_INIT
        BSL_GLOBAL_DeInit();
#endif
    }
}

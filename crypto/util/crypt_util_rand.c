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
#if defined(HITLS_CRYPTO_DRBG) || defined(HITLS_CRYPTO_CURVE25519) || \
    defined(HITLS_CRYPTO_RSA) || defined(HITLS_CRYPTO_BN)

#include <stdlib.h>
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "crypt_util_rand.h"

static CRYPT_RandFunc g_randFunc = NULL;

void CRYPT_RandRegist(CRYPT_RandFunc func)
{
    g_randFunc = func;
}

int32_t CRYPT_Rand(uint8_t *rand, uint32_t randLen)
{
    if (g_randFunc == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NO_REGIST_RAND);
        return CRYPT_NO_REGIST_RAND;
    }
    int32_t ret = g_randFunc(rand, randLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif

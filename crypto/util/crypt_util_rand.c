/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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

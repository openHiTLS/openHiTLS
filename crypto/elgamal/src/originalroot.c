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
#ifdef HITLS_CRYPTO_ELGAMAL

#include <stdbool.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_elgamal.h"
#include "elgamal_local.h"
#include "crypt_utils.h"
#include "crypt_params_key.h"

int32_t OriginalRoot(void *libCtx, BN_BigNum *g, const BN_BigNum *p, const BN_BigNum *q, uint32_t bits)
{
    int32_t ret;
    if (g == NULL || p == NULL || q == NULL ) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BN_Optimizer *optimizer = BN_OptimizerCreate();
    if (optimizer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BN_OptimizerDestroy(optimizer);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    BN_BigNum *x1 = BN_Create(bits);
    BN_BigNum *x2 = BN_Create(bits);
    BN_BigNum *x_top = BN_Create(bits);
    if (x1 == NULL || x2 == NULL || x_top == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BN_OptimizerDestroy(optimizer);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = BN_SubLimb(x_top, p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    while (true) {
        ret = BN_RandRangeEx(libCtx, g, x_top);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }

        ret = BN_ModSqr(x1, g, p, optimizer);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        if (BN_IsOne(x1)) {
            continue;
        }

        ret = BN_ModExp(x2, g, q, p, optimizer);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }

        if (!BN_IsOne(x2)) {
            break;
        }
    }
EXIT:
    BN_Destroy(x_top);
    BN_Destroy(x2);
    BN_Destroy(x1);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

#endif /* HITLS_CRYPTO_ELGAMAL */
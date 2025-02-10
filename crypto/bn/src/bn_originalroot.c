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
#ifdef HITLS_CRYPTO_BN

#include <stdbool.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "bn_basic.h"
#include "bn_bincal.h"
#include "bn_optimizer.h"

int32_t BN_OriginalRoot(BN_BigNum *g, const BN_BigNum *p, const BN_BigNum *q, BN_Optimizer *opt)
{
    int32_t ret;
    if (g == NULL || p == NULL || q == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BN_BigNum *x1 = OptimizerGetBn(opt, p->size);
    BN_BigNum *x2 = OptimizerGetBn(opt, p->size);
    BN_BigNum *x_top = OptimizerGetBn(opt, p->size);
    if (x1 == NULL || x2 == NULL || x_top == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        goto OUT;
    }

    ret = BN_SubLimb(x_top, p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto OUT;
    }

    while (true) {
        ret = BN_RandRange(g, x_top);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto OUT;
        }

        ret = BN_ModSqr(x1, g, p, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto OUT;
        }
        if (BN_IsOne(x1)) {
            continue;
        }

        ret = BN_ModExp(x2, g, q, p, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto OUT;
        }

        if (!BN_IsOne(x2)) {
            break;
        }
    }
OUT:
    OptimizerEnd(opt); // Release occupation from the optimizer.
    return ret;
}

#endif /* HITLS_CRYPTO_BN */
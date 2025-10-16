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

int32_t BN_Lcm(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, BN_Optimizer *opt)
{
    if (r == NULL || a == NULL || b == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BN_BigNum *gcd = BN_Create(BN_Bits(r));
    if (gcd == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BN_Gcd(gcd, a, b, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BN_Destroy(gcd);
        return ret;
    }
    if (BN_IsOne(gcd) == false) {
        ret = BN_Div(r, NULL, a, gcd, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BN_Destroy(gcd);
            return ret;
        }
        BN_Destroy(gcd);
        return BN_Mul(r, r, b, opt);
    }
    BN_Destroy(gcd); // a and b are coprime.
    return BN_Mul(r, a, b, opt);
}
#endif /* HITLS_CRYPTO_BN */
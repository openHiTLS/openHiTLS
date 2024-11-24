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
#include "crypt_bn.h"
#include "bn_basic.h"
#include "bn_bincal.h"
#include "bn_optimizer.h"



int32_t BarrettContextInit(BN_BigNum *mu, const BN_BigNum *n, BN_Optimizer *opt) {
    if (n == NULL || mu == NULL) 
    {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret; 
    ret = OptimizerStart(opt); // use the optimizer
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_BigNum *temp = OptimizerGetBn(opt, 2 * n->size);
    uint32_t k;
    k = BN_Bits(n);
    bool invalidInput = (temp == NULL);
    if (invalidInput) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        goto ERR;
    }
    
    // 计算 mu = 2^(2k) / n
    ret = BN_SetBit(temp, 2 * k);  
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Div(mu, NULL, temp, n, opt);  
     if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }  
ERR:
    OptimizerEnd(opt);
    return ret;
}

// Barrett reduction function(ecc), calculates r = a mod n,(0 < a < 2n, n != 2^x)
int32_t BN_BarrettReduction_ecc(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *n, const BN_BigNum *mu, BN_Optimizer *opt) {
    if (r == NULL || a == NULL || n == NULL || mu == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret; 
    ret = OptimizerStart(opt); 
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t k;
    k = BN_Bits(n);
    BN_BigNum *q1 = OptimizerGetBn(opt, a->size);
    BN_BigNum *q2 = OptimizerGetBn(opt, a->size + n->size);
    BN_BigNum *q3 = OptimizerGetBn(opt, a->size + n->size);
    BN_BigNum *temp = OptimizerGetBn(opt, n->size + 1);
    BN_BigNum *r2 = OptimizerGetBn(opt, a->size + n->size);
    bool invalidInput = (q1 == NULL || q2 == NULL || q3 == NULL || temp == NULL || r2 == NULL);
    if (invalidInput) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        goto ERR;
    }
    /*Step 1: Calculate q1 = a / 2^(k-1)*/ 
    ret = BN_Rshift(q1, a,  k-1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }   
    // Step 2: Calculate q2 = q1 * m
    ret = BN_Mul(q2, q1, mu, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }   
    // Step 3: Calculate q3 = q2 / 2^(k+1) 
    ret = BN_Rshift(q3, q2,  k + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }   
    // Step 4: Calculate r2 = q3 * n
    ret = BN_SetBit(temp, k + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }   
    ret = BN_Mul(r2, q3, n, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }    
    // Step 5: Calculate r = a - r2,Since a<2n, there is no need to do mod calculations
    ret = BN_Sub(r, a, r2);     
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }   
    // Step 6: If r is negative, adjust r
    if (BN_IsNegative(r)) {
        ret = BN_Add(r, r, temp);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }   
    }
    // Step 7: If r is greater than or equal to n, subtract n
    if (BN_Cmp(r, n) >= 0) {
        ret = BN_Sub(r, r, n);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }   
    }
ERR:
    OptimizerEnd(opt); // Release occupation from the optimizer.
    return ret; 
}
// Barrett reduction function, calculates r = a mod n,(0 <= a < n ^ 2, n != 2^x)
int32_t BN_BarrettReduction(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *n, const BN_BigNum *mu, BN_Optimizer *opt) {
    if (r == NULL || a == NULL || n == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret; 
    ret = OptimizerStart(opt); 
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t k;
    k = BN_Bits(n);
    BN_BigNum *q1 = OptimizerGetBn(opt, a->size);
    BN_BigNum *q2 = OptimizerGetBn(opt, a->size + k + 1);
    BN_BigNum *q3 = OptimizerGetBn(opt, a->size + k + 1);
    BN_BigNum *r1 = OptimizerGetBn(opt, a->size);
    BN_BigNum *temp1 = OptimizerGetBn(opt, k + 1);
    BN_BigNum *r2 = OptimizerGetBn(opt, a->size + k + 1);
    bool invalidInput = (q1 == NULL || q2 == NULL || q3 == NULL || r1 == NULL || temp1 == NULL || r2 == NULL);
    if (invalidInput) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        goto ERR;
    }
   
    /*Step 1: Calculate q1 = a / 2^(k-1)*/  
    ret = BN_Rshift(q1, a,  k-1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }   
    // Step 2: Calculate q2 = q1 * m
    ret = BN_Mul(q2, q1, mu, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }   
    // Step 3: Calculate q3 = q2 / 2^(k+1)
    ret = BN_Rshift(q3, q2,  k+1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }   
    // Step 4: Calculate r1 = a mod 2^(k+1)
    ret = BN_SetBit(temp1, k + 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }   
    ret = BN_Mod(r1, a, temp1, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }   
    // Step 5: Calculate r2 = q3 * n mod 2^(k+1)
    ret = BN_Mul(r2, q3, n, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }    
    ret = BN_Mod(r2, r2, temp1, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }   
    // Step 6: Calculate r = r1 - r2
    ret = BN_Sub(r, r1, r2);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }   
    // Step 7: If r is negative, adjust r
    if (BN_IsNegative(r)) {
        ret = BN_Add(r, r, temp1);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }   
    }
    // Step 8: If r is greater than or equal to n, subtract n
    if (BN_Cmp(r, n) >= 0) {
        ret = BN_Sub(r, r, n);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }   
    }  
ERR:
    OptimizerEnd(opt); 
    return ret;
}

#endif /* HITLS_CRYPTO_BN */
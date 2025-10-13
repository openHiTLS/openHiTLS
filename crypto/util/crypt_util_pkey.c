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

#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"

#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_PKEY)
#include "crypt_params_key.h"

int32_t CRYPT_GetPkeyProcessParams(BSL_Param *params, CRYPT_EAL_ProcessFuncCb *processCb, void **args)
{
    BSL_Param *processParam = BSL_PARAM_FindParam(params, CRYPT_PARAM_PKEY_PROCESS_FUNC);
    if (processParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret = BSL_PARAM_GetPtrValue(processParam, CRYPT_PARAM_PKEY_PROCESS_FUNC,
        BSL_PARAM_TYPE_FUNC_PTR, (void **)processCb, NULL);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (*processCb == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    BSL_Param *argsParam = BSL_PARAM_FindParam(params, CRYPT_PARAM_PKEY_PROCESS_ARGS);
    if (argsParam != NULL) {
        GOTO_ERR_IF(BSL_PARAM_GetPtrValue(argsParam, CRYPT_PARAM_PKEY_PROCESS_ARGS,
            BSL_PARAM_TYPE_CTX_PTR, args, NULL), ret);
    }
ERR:
    return ret;
}
#endif

#if (defined(HITLS_CRYPTO_DH_CHECK) || defined(HITLS_CRYPTO_DSA_CHECK))

#include "crypt_bn.h"

/*
 * check safe-prime group (no q) FFC private key
*/
static int32_t FFCSafePrimePrvCheck(const BN_BigNum *x, const BN_BigNum *p)
{
    if (x == NULL || p == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_SUCCESS;
    uint32_t N = BN_Bits(p); // N: agreed-upon bit length
    BN_BigNum *max = BN_Create(N);
    BN_BigNum *one = BN_Create(1);
    if (max == NULL || one == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }
    (void)BN_SetLimb(max, 1);
    (void)BN_SetLimb(one, 1);
    ret = BN_Lshift(max, max, N); // max = 2^N
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    // x >= 1
    if (BN_Cmp(one, x) >= 0) {
        ret = CRYPT_INVALID_KEY;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    (void)BN_SubLimb(max, max, 1);
    if (BN_Cmp(x, max) > 0) {    // x > 2^N - 1
        ret = CRYPT_INVALID_KEY;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
EXIT:
    BN_Destroy(max);
    BN_Destroy(one);
    return ret;
}

int32_t CRYPT_FFC_PrvCheck(const void *x, const void *p, const void *q)
{
    if (x == NULL || p == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (q != NULL) {
        int32_t ret;
        BN_BigNum *qTmp = BN_Create(BN_Bits(q));
        if (qTmp == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        ret = BN_SubLimb(qTmp, q, 1);
        if (ret != CRYPT_SUCCESS) {
            BN_Destroy(qTmp);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        // check 1 <= x <= q - 1
        if (BN_IsZero(x) == true || BN_IsNegative(x) == true || BN_Cmp(x, qTmp) > 0) {
            ret = CRYPT_INVALID_KEY;
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_KEY);
        }
        BN_Destroy(qTmp);
        return ret;
    }
    return FFCSafePrimePrvCheck(x, p);
}

/*
 * SP800-56a 5.6.2.1.4
 * for check an FFC key pair is valid.
*/
int32_t CRYPT_FFC_KeyPairCheck(const void *x, const void *y, const void *p, const void *g)
{
    int32_t ret;
    if (x == NULL || y == NULL || p == NULL || g == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BN_Mont *mont = BN_MontCreate(p);
    BN_BigNum *yTmp = BN_Create(BN_Bits(p));
    if (yTmp == NULL || mont == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_MontExpConsttime(yTmp, g, x, mont, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (BN_Cmp(yTmp, y) != 0) {
        ret = CRYPT_PAIRWISE_CHECK_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
ERR:
    BN_Destroy(yTmp);
    BN_MontDestroy(mont);
    return ret;
}

#endif // HITLS_CRYPTO_DH_CHECK || HITLS_CRYPTO_DSA_CHECK

#if defined(HITLS_CRYPTO_PROVIDER) && (defined(HITLS_CRYPTO_RSA) || defined(HITLS_CRYPTO_ECDSA) || \
    defined(HITLS_CRYPTO_DSA))
#include "securec.h"
int32_t CRYPT_PkeySetMdAttr(const char *mdAttr, uint32_t len, char **pkeyMdAttr)
{
    if (mdAttr == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    BSL_SAL_FREE(*pkeyMdAttr);
    *pkeyMdAttr = BSL_SAL_Malloc(len + 1); // +1 for '\0'
    if (*pkeyMdAttr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memcpy_s(*pkeyMdAttr, len + 1, mdAttr, len);
    (*pkeyMdAttr)[len] = '\0';
    return CRYPT_SUCCESS;
}
#endif
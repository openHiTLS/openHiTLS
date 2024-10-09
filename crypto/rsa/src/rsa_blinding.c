/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_RSA

#include "crypt_utils.h"
#include "crypt_rsa.h"
#include "rsa_local.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "securec.h"
#include "bsl_err_internal.h"

RSA_Blind *RSA_BlindNewCtx(void)
{
    RSA_Blind *ret = BSL_SAL_Malloc(sizeof(RSA_Blind));
    if (ret == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ret, sizeof(RSA_Blind), 0, sizeof(RSA_Blind));
    return ret;
}


void RSA_BlindFreeCtx(RSA_Blind *b)
{
    if (b == NULL) {
        return;
    }
    BN_Destroy(b->a);
    BN_Destroy(b->ai);
    BSL_SAL_FREE(b);
}

static int32_t BlindUpdate(RSA_Blind *b, BN_BigNum *n, BN_Optimizer *opt)
{
    int32_t ret = BN_ModMul(b->a, b->a, b->a, n, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_ModMul(b->ai, b->ai, b->ai, n, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

int32_t RSA_BlindCovert(RSA_Blind *b, BN_BigNum *data, BN_BigNum *n, BN_Optimizer *opt)
{
    int32_t ret;

    ret = BlindUpdate(b, n, opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    // 8. z = m * x mod n
    ret = BN_ModMul(data, data, b->a, n, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return ret;
}

int32_t RSA_BlindInvert(RSA_Blind *b, BN_BigNum *data, BN_BigNum *n, BN_Optimizer *opt)
{
    int32_t ret;
    ret = BN_ModMul(data, data, b->ai, n, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

static int32_t RSA_CreateBlind(RSA_Blind *b, uint32_t bits)
{
    b->a = BN_Create(bits);
    if (b->a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    b->ai = BN_Create(bits);
    if (b->ai == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

int32_t RSA_BlindCreateParam(RSA_Blind *b, BN_BigNum *e, BN_BigNum *n, BN_Optimizer *opt)
{
    int32_t ret;
    if (b == NULL || e == NULL || n == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BN_Destroy(b->a);
    BN_Destroy(b->ai);
    b->a = NULL;
    b->ai = NULL;

    ret = RSA_CreateBlind(b, BN_Bits(n));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto END;
    }

    ret = BN_RandRange(b->a, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto END;
    }

    ret = BN_ModInv(b->ai, b->a, n, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto END;
    }

    ret = BN_ModExp(b->a, b->a, e, n, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto END;
    }
    return ret;
END:
    BN_Destroy(b->a);
    BN_Destroy(b->ai);
    b->a = NULL;
    b->ai = NULL;
    return ret;
}
#endif // HITLS_CRYPTO_RSA

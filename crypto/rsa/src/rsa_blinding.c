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
#if defined(HITLS_CRYPTO_RSA_BLINDING) || defined(HITLS_CRYPTO_RSA_BSSA)

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
    BN_Destroy(b->r);
    BN_Destroy(b->rInv);
    BSL_SAL_FREE(b);
}

static int32_t BlindUpdate(RSA_Blind *b, BN_BigNum *n, BN_Optimizer *opt)
{
    int32_t ret = BN_ModMul(b->r, b->r, b->r, n, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_ModMul(b->rInv, b->rInv, b->rInv, n, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
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
    ret = BN_ModMul(data, data, b->r, n, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

int32_t RSA_BlindInvert(RSA_Blind *b, BN_BigNum *data, BN_BigNum *n, BN_Optimizer *opt)
{
    int32_t ret = BN_ModMul(data, data, b->rInv, n, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t RSA_CreateBlind(RSA_Blind *b, uint32_t bits)
{
    // create a BigNum
    b->r = BN_Create(bits);
    if (b->r == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    b->rInv = BN_Create(bits);
    if (b->rInv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

/*
 * Initializes blind signature parameters for an RSA key.
 * Ref. https://www.rfc-editor.org/rfc/rfc9474.html#name-blind
 *
 * As RFC-9474 Section 2.1, we need to do this.
 * 1. Generates a random blinding factor r
 * 2. Computes r^(-1) mod n (modular inverse)
 * 3. Computes r^e mod n (where e is the public exponent)
 */
int32_t RSA_BlindCreateParam(void *libCtx, RSA_Blind *b, BN_BigNum *e, BN_BigNum *n, uint32_t bits, BN_Optimizer *opt)
{
    int32_t ret;
    if (b == NULL || e == NULL || n == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BN_Destroy(b->r);
    BN_Destroy(b->rInv);
    b->r = NULL;
    b->rInv = NULL;

    ret = RSA_CreateBlind(b, bits);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto END;
    }

    // b->r = random_integer_uniform(1, n)
    ret = BN_RandRangeEx(libCtx, b->r, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto END;
    }

    // b->rInv = inverse_mod(r, n)
    ret = BN_ModInv(b->rInv, b->r, n, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto END;
    }

    // b->r = RSAVP1(pk, r)
    ret = BN_ModExp(b->r, b->r, e, n, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto END;
    }
    return ret;
END:
    BN_Destroy(b->r);
    BN_Destroy(b->rInv);
    b->r = NULL;
    b->rInv = NULL;
    return ret;
}
#endif /* HITLS_CRYPTO_RSA_BLINDING || HITLS_CRYPTO_RSA_BSSA */
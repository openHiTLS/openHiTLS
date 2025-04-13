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

#include <stdint.h>
#include "crypt_errno.h"
#include "bn_bincal.h"
#include "bn_asm.h"
#if defined(HITLS_CRYPTO_BN_X8664) && defined(__x86_64__)
#include "crypt_utils.h"
#endif

int32_t MontSqrBin(BN_UINT *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime)
{
    if (mont->mSize > 1) {
#if defined(HITLS_CRYPTO_BN_X8664) && defined(__x86_64__)
        if (IsSupportBMI2() && IsSupportADX()) {
            MontMulx_Asm(r, r, r, mont->mod, mont->k0, mont->mSize);
            return CRYPT_SUCCESS;
        }
#endif
        MontMul_Asm(r, r, r, mont->mod, mont->k0, mont->mSize);
        return CRYPT_SUCCESS;
    }
    return MontSqrBinCore(r, mont, opt, consttime);
}

int32_t MontMulBin(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, BN_Mont *mont,
    BN_Optimizer *opt, bool consttime)
{
    if (mont->mSize > 1) {
#if defined(HITLS_CRYPTO_BN_X8664) && defined(__x86_64__)
        if (IsSupportBMI2() && IsSupportADX()) {
            MontMulx_Asm(r, a, b, mont->mod, mont->k0, mont->mSize);
            return CRYPT_SUCCESS;
        }
#endif
        MontMul_Asm(r, a, b, mont->mod, mont->k0, mont->mSize);
        return CRYPT_SUCCESS;
    }
    return MontMulBinCore(r, a, b, mont, opt, consttime);
}

int32_t MontEncBin(BN_UINT *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime)
{
    if (mont->mSize > 1) {
#if defined(HITLS_CRYPTO_BN_X8664) && defined(__x86_64__)
        if (IsSupportBMI2() && IsSupportADX()) {
            MontMulx_Asm(r, r, mont->montRR, mont->mod, mont->k0, mont->mSize);
            return CRYPT_SUCCESS;
        }
#endif
        MontMul_Asm(r, r, mont->montRR, mont->mod, mont->k0, mont->mSize);
        return CRYPT_SUCCESS;
    }
    return MontEncBinCore(r, mont, opt, consttime);
}

void Reduce(BN_UINT *r, BN_UINT *x, const BN_UINT *one, const BN_UINT *m, uint32_t mSize, BN_UINT m0)
{
    if (mSize <= 1) {
        ReduceCore(r, x, m, mSize, m0);
        return;
    }
#if defined(HITLS_CRYPTO_BN_X8664) && defined(__x86_64__)
    if (IsSupportBMI2() && IsSupportADX()) {
        MontMulx_Asm(r, x, one, m, m0, mSize);
        return;
    }
#endif
    MontMul_Asm(r, x, one, m, m0, mSize);
    return;
}
#endif /* HITLS_CRYPTO_BN */

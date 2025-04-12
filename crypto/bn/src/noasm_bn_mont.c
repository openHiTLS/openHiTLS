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
#include <stdbool.h>
#include "bn_bincal.h"

/* reduce(r * r) */
int32_t MontSqrBin(BN_UINT *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime)
{
    return MontSqrBinCore(r, mont, opt, consttime);
}

int32_t MontMulBin(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, BN_Mont *mont,
    BN_Optimizer *opt, bool consttime)
{
    return MontMulBinCore(r, a, b, mont, opt, consttime);
}

int32_t MontEncBin(BN_UINT *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime)
{
    return MontEncBinCore(r, mont, opt, consttime);
}

void Reduce(BN_UINT *r, BN_UINT *x, const BN_UINT *one, const BN_UINT *m, uint32_t mSize, BN_UINT m0)
{
    (void)one;
    ReduceCore(r, x, m, mSize, m0);
}

#endif /* HITLS_CRYPTO_BN */

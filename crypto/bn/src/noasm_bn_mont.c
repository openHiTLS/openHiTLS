/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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

void Reduce(BN_UINT *r, BN_UINT *x, const BN_UINT *m, uint32_t mSize, BN_UINT m0)
{
    ReduceCore(r, x, m, mSize, m0);
}
#endif /* HITLS_CRYPTO_BN */

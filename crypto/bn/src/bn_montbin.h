/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef BN_MONTBIN_H
#define BN_MONTBIN_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include <stdint.h>
#include "crypt_bn.h"

#ifdef __cplusplus
extern "c" {
#endif

/* r = reduce(r * r) mod mont */
int32_t MontSqrBin(BN_UINT *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime);

/* r = reduce(a * b) mod mont */
int32_t MontMulBin(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, BN_Mont *mont,
    BN_Optimizer *opt, bool consttime);

/* r = reduce(r * montRR) mod mont */
int32_t MontEncBin(BN_UINT *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime);

/* r = reduce(x * 1) mod m = (x * R') mod m */
void Reduce(BN_UINT *r, BN_UINT *x, const BN_UINT *m, uint32_t mSize, BN_UINT m0);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_BN

#endif // BN_MONTBIN_H

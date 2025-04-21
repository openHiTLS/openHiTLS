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
void Reduce(BN_UINT *r, BN_UINT *x, const BN_UINT *one, const BN_UINT *m, uint32_t mSize, BN_UINT m0);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_BN */

#endif
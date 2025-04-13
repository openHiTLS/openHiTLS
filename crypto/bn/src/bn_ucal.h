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

#ifndef BN_UCAL_H
#define BN_UCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include "bn_basic.h"

#ifdef __cplusplus
extern "C" {
#endif

/* unsigned BigNum subtraction, caution: The input parameter validity must be ensured during external invoking. */
int32_t USub(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b);

/* unsigned BigNum add fraction, caution: The input parameter validity must be ensured during external invoking. */
void UDec(BN_BigNum *r, const BN_BigNum *a, BN_UINT w);

/* unsigned BigNum addition, caution: The input parameter validity must be ensured during external invoking. */
int32_t UAdd(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_BN */

#endif
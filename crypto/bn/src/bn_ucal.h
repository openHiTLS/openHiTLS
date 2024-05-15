/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
void USub(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b);

/* unsigned BigNum sub fraction, caution: The input parameter validity must be ensured during external invoking. */
void UInc(BN_BigNum *r, const BN_BigNum *a, BN_UINT w);

/* unsigned BigNum add fraction, caution: The input parameter validity must be ensured during external invoking. */
void UDec(BN_BigNum *r, const BN_BigNum *a, BN_UINT w);

/* unsigned BigNum addition, caution: The input parameter validity must be ensured during external invoking. */
void UAdd(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_BN

#endif // BN_UCAL_H

/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef DSA_LOCAL_H
#define DSA_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_DSA

#include "crypt_bn.h"
#include "crypt_dsa.h"
#include "sal_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define DSA_MIN_PBITS 1024 // The minimum specification of DSA: 1024 bits
#define DSA_MAX_PBITS 3072 // The maximum specification of DSA: 3072 bits
#define DSA_MIN_QBITS 160  // The minimum specification of parameter q of DSA

/* DSA key parameters */
struct DSA_Para {
    BN_BigNum *p;
    BN_BigNum *q;
    BN_BigNum *g;
};

/* DSA key ctx */
struct DSA_Ctx {
    BN_BigNum *x; // private key
    BN_BigNum *y; // public key
    CRYPT_DSA_Para *para; // key parameter
    BSL_SAL_RefCount references;
};

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_DSA

#endif // DSA_LOCAL_H

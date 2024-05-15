/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef DH_LOCAL_H
#define DH_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_DH

#include "crypt_bn.h"
#include "crypt_dh.h"
#include "sal_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define DH_MIN_PBITS 768  // Minimum DH specification: 768 bits
#define DH_MAX_PBITS 8192 // Maximum DH specification: 8192 bits
#define DH_MIN_QBITS 160  // Minimum specification of DH parameter Q: 160 bits

/* DH key parameter */
struct DH_Para {
    BN_BigNum *p;
    BN_BigNum *q;
    BN_BigNum *g;
    CRYPT_PKEY_ParaId id;
};

/* DH key context */
struct DH_Ctx {
    BN_BigNum *x; // Private key
    BN_BigNum *y; // Public key
    CRYPT_DH_Para *para; // key parameter
    BSL_SAL_RefCount references;
};

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_DH

#endif // CRYPT_DH_H

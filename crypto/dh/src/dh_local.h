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
    uint32_t flags;
    void *libCtx;
};

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_DH

#endif // CRYPT_DH_H

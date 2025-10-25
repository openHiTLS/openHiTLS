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
    CRYPT_MD_AlgId signMdId;
    uint8_t flag;
    void *libCtx;
    char *mdAttr;
};

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_DSA

#endif // DSA_LOCAL_H

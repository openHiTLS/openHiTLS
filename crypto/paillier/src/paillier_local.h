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
#ifndef PAILLIER_LOCAL_H
#define PAILLIER_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_PAILLIER

#include "crypt_paillier.h"
#include "crypt_bn.h"
#include "crypt_local_types.h"
#include "crypt_types.h"
#include "sal_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef struct {
    BN_BigNum *n;  // modulo Value - converted.Not in char
    BN_BigNum *g;  // modulo Value -converted.Not in char
    BN_BigNum *n2; // square of n
} CRYPT_PAILLIER_PubKey;

typedef struct {
    BN_BigNum *n;       // pub key n needed for decryption
    BN_BigNum *lambda;  // modulo Value - converted.Not in char
    BN_BigNum *mu;      // modulo Value -converted.Not in char
    BN_BigNum *n2;      // pub key n2 needed for decryption
} CRYPT_PAILLIER_PrvKey;

struct PAILLIER_Para {
    BN_BigNum *p;   // prime factor p
    BN_BigNum *q;   // prime factor q
    uint32_t bits;  // length in bits of modulus
};

struct PAILLIER_Ctx {
    CRYPT_PAILLIER_PubKey *pubKey;
    CRYPT_PAILLIER_PrvKey *prvKey;
    CRYPT_PAILLIER_Para *para;
    BSL_SAL_RefCount references;
    void *libCtx;
};

CRYPT_PAILLIER_PrvKey *Paillier_NewPrvKey(uint32_t bits);
CRYPT_PAILLIER_PubKey *Paillier_NewPubKey(uint32_t bits);
void PAILLIER_FreePrvKey(CRYPT_PAILLIER_PrvKey *prvKey);
void PAILLIER_FreePubKey(CRYPT_PAILLIER_PubKey *pubKey);
CRYPT_PAILLIER_Para *CRYPT_Paillier_DupPara(const CRYPT_PAILLIER_Para *para);

#define PAILLIER_FREE_PRV_KEY(prvKey_)               \
do {                                            \
        PAILLIER_FreePrvKey((prvKey_));              \
        (prvKey_) = NULL;                       \
    } while (0)

#define PAILLIER_FREE_PUB_KEY(pubKey_)               \
    do {                                        \
        PAILLIER_FreePubKey((pubKey_));              \
        (pubKey_) = NULL;                       \
    } while (0)

#define PAILLIER_FREE_PARA(para_)                    \
    do {                                        \
        CRYPT_PAILLIER_FreePara((para_));            \
        (para_) = NULL;                         \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_PAILLIER
#endif // PAILLIER_LOCAL_H
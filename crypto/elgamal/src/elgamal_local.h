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

#ifndef ELGAMAL_LOCAL_H
#define ELGAMAL_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ELGAMAL

#include "crypt_elgamal.h"
#include "crypt_bn.h"
#include "crypt_local_types.h"
#include "crypt_types.h"
#include "sal_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef struct {
    BN_BigNum *p; // prime factor p
    BN_BigNum *g; // primitive root of p
    BN_BigNum *y; // y = g^x (mod p)
    BN_BigNum *q; // prime factor q
} CRYPT_ELGAMAL_PubKey;

typedef struct {
    BN_BigNum *p; // prime factor p
    BN_BigNum *g; // primitive root of g
    BN_BigNum *x; // pub key x needed for decryption
} CRYPT_ELGAMAL_PrvKey;

struct ELGAMAL_Para {
    BN_BigNum *q; // prime factor q
    uint32_t k_bits; // security parameter k
    uint32_t bits; // length in bits of modulus
};

struct ELGAMAL_Ctx {
    CRYPT_ELGAMAL_PubKey *pubKey;
    CRYPT_ELGAMAL_PrvKey *prvKey;
    CRYPT_ELGAMAL_Para *para;
    BSL_SAL_RefCount references;
    void *libCtx;
};

CRYPT_ELGAMAL_PrvKey *ElGamal_NewPrvKey(uint32_t bits);
CRYPT_ELGAMAL_PubKey *ElGamal_NewPubKey(uint32_t bits);
void ELGAMAL_FreePrvKey(CRYPT_ELGAMAL_PrvKey *prvKey);
void ELGAMAL_FreePubKey(CRYPT_ELGAMAL_PubKey *pubKey);
CRYPT_ELGAMAL_Para *CRYPT_ElGamal_DupPara(const CRYPT_ELGAMAL_Para *para);

#define ELGAMAL_FREE_PRV_KEY(prvKey_)  \
    do {                               \
        ELGAMAL_FreePrvKey((prvKey_)); \
        (prvKey_) = NULL;              \
    } while (0)

#define ELGAMAL_FREE_PUB_KEY(pubKey_)  \
    do {                               \
        ELGAMAL_FreePubKey((pubKey_)); \
        (pubKey_) = NULL;              \
    } while (0)

#define ELGAMAL_FREE_PARA(para_)         \
    do {                                 \
        CRYPT_ELGAMAL_FreePara((para_)); \
        (para_) = NULL;                  \
    } while (0)
#ifdef __cplusplus
}
#endif
#endif // HITLS_CRYPTO_ELGAMAL
#endif // ELGAMAL_LOCAL_H
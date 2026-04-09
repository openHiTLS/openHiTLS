#ifndef ECDSA_INTERNAL_H
#define ECDSA_INTERNAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ECDSA

#include <stdint.h>
#include "crypt_bn.h"
#include "crypt_ecdsa.h"
#include "crypt_algid.h"

#ifdef HITLS_CRYPTO_HMAC
/**
 * RFC 6979 deterministic k generation state. Initialize once, then call ECDSA_Rfc6979Next() for each
 * candidate k so retries (e.g. r == 0 or s == 0 in ECDSA) advance the DRBG instead of repeating the same k.
 */
typedef struct ECDSA_Rfc6979State {
    uint8_t *bx;
    uint8_t *bh;
    uint8_t *v;
    uint8_t *key;
    uint8_t *t;
    uint8_t *blob;
    uint32_t qLen;
    uint32_t hLen;
    uint32_t tcap;
    const CRYPT_ECDSA_Ctx *ctx;
    const BN_BigNum *paraN;
    CRYPT_MAC_AlgId macId;
    uint32_t qlenBits;
    uint32_t hlenBits;
    BN_BigNum *tmpK;
} ECDSA_Rfc6979State;

void ECDSA_Rfc6979Free(ECDSA_Rfc6979State *st);
int32_t ECDSA_Rfc6979Init(ECDSA_Rfc6979State *st, const CRYPT_ECDSA_Ctx *ctx, const BN_BigNum *paraN,
    CRYPT_MD_AlgId mdId, const uint8_t *hash, uint32_t hashLen);
int32_t ECDSA_Rfc6979Next(ECDSA_Rfc6979State *st, BN_BigNum *k);
#endif /* HITLS_CRYPTO_HMAC */

#endif /* HITLS_CRYPTO_ECDSA */

#endif /* ECDSA_INTERNAL_H */

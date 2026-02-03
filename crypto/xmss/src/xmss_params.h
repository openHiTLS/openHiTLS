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

#ifndef XMSS_PARAMS_H
#define XMSS_PARAMS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_XMSS

#include <stdint.h>
#include <stddef.h>
#include "crypt_algid.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum hash output length (for SHA512) */
#define XMSS_MAX_N 64

/* Maximum message digest size (same as max hash output) */
#define XMSS_MAX_MDSIZE 64

/* Maximum seed size */
#define XMSS_MAX_SEED_SIZE 64

/* Maximum tree height */
#define XMSS_MAX_H 60

/* Maximum WOTS+ parameter */
#define XMSS_MAX_WOTS_W 16

/* Maximum WOTS+ signature length (len * n) */
#define XMSS_MAX_WOTS_LEN 67

/* XDR algorithm type length (RFC 9802) */
#define HASH_SIGN_XDR_ALG_TYPE_LEN 4

/*
 * XMSS Parameters Structure
 *
 * This structure contains all parameters needed for XMSS operations.
 */
typedef struct {
    CRYPT_PKEY_ParaId algId;

    /* Security parameters */
    uint32_t n; // Security parameter (hash output length in bytes)

    /* Tree parameters */
    uint32_t h; // Total tree height (number of layers in XMSSMT)
    uint32_t d; // Number of layers (1 = XMSS, >1 = XMSSMT)
    uint32_t hp; // Height of each layer = h / d

    /* WOTS+ parameters */
    uint32_t wotsW; // Winternitz parameter
    /* the number of n-byte string elements in a WOTS+ private key,
      public key, and signature.  It is computed as len = len_1 + len_2,
      with len_1 = ceil(8n / log_2(w)) and len_2 = floor(log_2(len_1 *
      (w - 1)) / log_2(w)) + 1. */
    uint32_t wotsLen;

    /* Output sizes */
    uint32_t pkBytes; // Public key size.
    // Standard XMSS (RFC 8391): 4 (OID) + n (root) + n (SEED) = 4 + 2*n

    uint32_t sigBytes; // Signature size.
    // XMSS:   4 (idx) + n (r) + wotsLen*n + h*n
    // XMSSMT: 4 (idx) + n (r) + d * (wotsLen*n + hp*n)

    /* RFC 9802 X.509 support */
    uint8_t xdrAlgId[HASH_SIGN_XDR_ALG_TYPE_LEN]; // 4-byte XDR OID (RFC 8391)

    /* Hash algorithm parameters for generic hash function implementation */
    CRYPT_MD_AlgId mdId; // Hash algorithm ID (e.g., CRYPT_MD_SHA256)
    uint32_t paddingLen; // Padding length for domain separation
} XmssParams;

const XmssParams *FindXmssPara(CRYPT_PKEY_ParaId algId);

/*
 * Find XMSS parameters pointer by XDR algorithm ID (RFC 9802)
 *
 * Returns a pointer to the global parameter table entry.
 * This is more memory efficient than copying the structure.
 *
 * @param xdrId  XDR algorithm ID (32-bit value, big-endian)
 *
 * @return Pointer to XmssParams in global table, or NULL if not found
 */
const XmssParams *XmssParams_FindByXdrId(uint32_t xdrId);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_XMSS
#endif // XMSS_PARAMS_H

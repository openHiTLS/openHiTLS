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
#ifndef XMSS_MAX_N
#define XMSS_MAX_N 64
#endif

/* Maximum message digest size (same as max hash output) */
#ifndef XMSS_MAX_MDSIZE
#define XMSS_MAX_MDSIZE 64
#endif

/* Maximum seed size */
#ifndef XMSS_MAX_SEED_SIZE
#define XMSS_MAX_SEED_SIZE 64
#endif

/* Maximum tree height */
#ifndef XMSS_MAX_H
#define XMSS_MAX_H 60
#endif

/* Maximum WOTS+ parameter */
#ifndef XMSS_MAX_WOTS_W
#define XMSS_MAX_WOTS_W 16
#endif

/* Maximum WOTS+ signature length (len * n) */
#ifndef XMSS_MAX_WOTS_LEN
#define XMSS_MAX_WOTS_LEN 67
#endif

/* XDR algorithm type length (RFC 9802) */
#ifndef HASH_SIGN_XDR_ALG_TYPE_LEN
#define HASH_SIGN_XDR_ALG_TYPE_LEN 4
#endif

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
    uint32_t h; // Tree height

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
    // XMSS: 4 (idx) + n (r) + wotsLen*n + h*n

    /* RFC 9802 X.509 support */
    uint8_t xdrAlgId[HASH_SIGN_XDR_ALG_TYPE_LEN]; // 4-byte XDR OID (RFC 8391)

    /* Hash algorithm parameters for generic hash function implementation */
    CRYPT_MD_AlgId mdId; // Hash algorithm ID (e.g., CRYPT_MD_SHA256)
    uint32_t paddingLen; // Padding length for domain separation
} XmssParams;

const XmssParams *XmssParams_FindByAlgId(CRYPT_PKEY_ParaId algId);

/*
 * Find XMSS parameters pointer by XMSS XDR algorithm ID.
 *   RFC 8391 defines two SEPARATE XDR enums that share the SAME value range:
 *     - Appendix B: enum xmss_algorithm_type       (XMSS,    starts at 0x00000001)
 *     - Appendix C: enum xmssmt_algorithm_type      (XMSS^MT, starts at 0x00000001)
 *   IANA also maintains them as two independent sub-registries.
 *   For example, 0x00000001 means XMSS-SHA2_10_256 (d=1) AND
 *                 XMSSMT-SHA2_20/2_256 (d=2) simultaneously.
 *   The 4-byte XDR value alone is ambiguous; this function searches only
 *   the XMSS namespace. XMSSMT callers must use XmssmtParams_FindByXdrId().
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

#endif /* HITLS_CRYPTO_XMSS */
#endif /* XMSS_PARAMS_H */

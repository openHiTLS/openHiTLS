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

#ifndef XMSSMT_PARAMS_H
#define XMSSMT_PARAMS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_XMSSMT

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
 * XMSSMT Parameters Structure
 *
 * XMSSMT is a multi-tree algorithm, so it carries both the total height h and
 * the layer decomposition d/hp.
 */
typedef struct {
    CRYPT_PKEY_ParaId algId;

    uint32_t n; // Security parameter (hash output length in bytes)
    uint32_t h; // Total tree height
    uint32_t d; // Number of layers
    uint32_t hp; // Height of each layer = h / d

    uint32_t wotsW; // Winternitz parameter
    uint32_t wotsLen; // Number of n-byte string elements in a WOTS+ signature.

    uint32_t pkBytes; // Public key size.
    uint32_t sigBytes; // Signature size.

    uint8_t xdrAlgId[HASH_SIGN_XDR_ALG_TYPE_LEN]; // 4-byte XMSSMT XDR OID
    CRYPT_MD_AlgId mdId;
    uint32_t paddingLen;
} XmssmtParams;

const XmssmtParams *XmssmtParams_FindByAlgId(CRYPT_PKEY_ParaId algId);

/*
 * Find XMSSMT parameters pointer by XMSSMT XDR algorithm ID.
 *
 * RFC 8391 defines XMSS and XMSSMT as separate XDR namespaces whose numeric
 * values overlap. The X.509 outer OID must select this XMSSMT namespace before
 * this lookup is used.
 *
 * @param xdrId  XDR algorithm ID (32-bit value, big-endian)
 *
 * @return Pointer to XmssmtParams in the XMSSMT global table, or NULL if not found
 */
const XmssmtParams *XmssmtParams_FindByXdrId(uint32_t xdrId);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_XMSSMT */
#endif /* XMSSMT_PARAMS_H */

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

/*
 * hbs_address.h — shared address-type constants for HBS algorithms (design doc §2.1)
 *
 * This header collects the address-type numeric constants that are referenced
 * across multiple HBS modules (xmss/, slh_dsa/, hbs_tree.c).  Centralising
 * them here prevents the magic-number duplication that previously existed in
 * xmss_address.h and slh_dsa_local.h.
 *
 * Usage:
 *   Algorithm-specific modules (xmss_address.h, slh_dsa_local.h) may continue
 *   to define their own symbolic aliases (e.g. XMSS_ADRS_TYPE_OTS,
 *   WOTS_HASH) whose numeric values must equal the shared constants below.
 *   hbs_tree.c uses the HBS_ADRS_TYPE_* constants directly to avoid importing
 *   algorithm-specific headers into the common layer.
 *
 * LMS note:
 *   LMS does not use a structured address type field; domain separation is
 *   achieved via inline D_LEAF / D_INTR / D_MESG / D_PBLC constants defined
 *   in lms_local.h.  No LMS-specific constants are listed here.
 */

#ifndef HBS_ADDRESS_H
#define HBS_ADDRESS_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT) || defined(HITLS_CRYPTO_SLH_DSA)

#ifdef __cplusplus
extern "C" {
#endif

/*
 * XMSS address types (RFC 8391 §2.7.3)
 * These values are also used by hbs_tree.c when operating on XMSS trees.
 */
#define HBS_ADRS_TYPE_OTS   0u /**< WOTS+ hash address (OTS key-pair address) */
#define HBS_ADRS_TYPE_LTREE 1u /**< L-tree address (WOTS+ public-key compression) */
#define HBS_ADRS_TYPE_HASH  2u /**< Hash-tree address (internal Merkle node) */

/*
 * SLH-DSA address types (FIPS 205 §4.2)
 * Numerical values chosen to match the FIPS 205 specification directly.
 * Algorithm-specific code in slh_dsa_local.h re-exports these as the
 * AdrsType enum for readability; the numeric values must stay in sync.
 */
#define HBS_ADRS_TYPE_WOTS_HASH  0u /**< WOTS+ chain hash address */
#define HBS_ADRS_TYPE_WOTS_PK    1u /**< WOTS+ public-key compression address */
#define HBS_ADRS_TYPE_TREE       2u /**< Merkle tree hash address */
#define HBS_ADRS_TYPE_FORS_TREE  3u /**< FORS tree hash address */
#define HBS_ADRS_TYPE_FORS_ROOTS 4u /**< FORS roots compression address */
#define HBS_ADRS_TYPE_WOTS_PRF   5u /**< WOTS+ PRF address (secret-key derivation) */
#define HBS_ADRS_TYPE_FORS_PRF   6u /**< FORS PRF address (secret-key derivation) */

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_XMSS || HITLS_CRYPTO_XMSSMT || HITLS_CRYPTO_SLH_DSA */
#endif /* HBS_ADDRESS_H */

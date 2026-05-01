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

#ifndef LMS_ADDRESS_H
#define LMS_ADDRESS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_LMS

#include <stdint.h>
#include "lms_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup lms_address LMS Address Operations
 * @brief Domain-separated hash input construction for LMS
 *
 * RFC 8554 uses domain separation to ensure different hash operations
 * produce independent outputs. This module centralizes buffer construction
 * logic for all LMS hash operations.
 */

/**
 * @ingroup lms_address
 * @brief Build OTS iteration buffer (I || q || k || j || prev)
 *
 * Used in LM-OTS chain function for iterative hashing.
 * Format: I(16) || q(4) || k(2) || j(1) || prev(n)
 *
 * @param buffer [OUT] Output buffer (must be at least LMS_ITER_LEN(n) bytes)
 * @param I      [IN]  Tree identifier (16 bytes)
 * @param q      [IN]  Leaf index
 * @param k      [IN]  Chain index
 * @param j      [IN]  Iteration index
 * @param prev   [IN]  Previous hash value (n bytes)
 * @param n      [IN]  Hash output length
 */
void LmsAdrs_BuildOtsIterInput(uint8_t *buffer, const uint8_t *I, uint32_t q, uint32_t k, uint32_t j,
                               const uint8_t *prev, uint32_t n);

/**
 * @ingroup lms_address
 * @brief Build leaf node buffer (I || r || D || pk)
 *
 * Used for computing leaf node hashes in the Merkle tree.
 * Format: I(16) || r(4) || D(2) || pk(n)
 * D = LMS_D_LEAF (0x8282)
 *
 * @param buffer [OUT] Output buffer (must be at least LMS_LEAF_LEN(n) bytes)
 * @param I      [IN]  Tree identifier (16 bytes)
 * @param r      [IN]  Node index
 * @param pk     [IN]  OTS public key (n bytes)
 * @param n      [IN]  Hash output length
 */
void LmsAdrs_BuildLeafInput(uint8_t *buffer, const uint8_t *I, uint32_t r, const uint8_t *pk, uint32_t n);

/**
 * @ingroup lms_address
 * @brief Build internal node buffer (I || r || D || left || right)
 *
 * Used for computing internal node hashes in the Merkle tree.
 * Format: I(16) || r(4) || D(2) || left(n) || right(n)
 * D = LMS_D_INTR (0x8383)
 *
 * @param buffer [OUT] Output buffer (must be at least LMS_INTR_LEN(n) bytes)
 * @param I      [IN]  Tree identifier (16 bytes)
 * @param r      [IN]  Node index
 * @param left   [IN]  Left child hash (n bytes)
 * @param right  [IN]  Right child hash (n bytes)
 * @param n      [IN]  Hash output length
 */
void LmsAdrs_BuildInternalInput(uint8_t *buffer, const uint8_t *I, uint32_t r, const uint8_t *left,
                                const uint8_t *right, uint32_t n);

/**
 * @ingroup lms_address
 * @brief Build message hash buffer (I || q || D || C)
 *
 * Used for hashing the message with randomizer in LM-OTS signing.
 * Format: I(16) || q(4) || D(2) || C(n)
 * D = LMS_D_MESG (0x8181)
 *
 * @param buffer [OUT] Output buffer (must be at least LMS_MESG_PREFIX_LEN(n) bytes)
 * @param I      [IN]  Tree identifier (16 bytes)
 * @param q      [IN]  Leaf index
 * @param C      [IN]  Randomizer (n bytes)
 * @param n      [IN]  Hash output length
 */
void LmsAdrs_BuildMsgInput(uint8_t *buffer, const uint8_t *I, uint32_t q, const uint8_t *C, uint32_t n);

/**
 * @ingroup lms_address
 * @brief Build OTS public key buffer (I || q || D || chains)
 *
 * Used for computing the final OTS public key hash.
 * Format: I(16) || q(4) || D(2) || chains(p*n)
 * D = LMS_D_PBLC (0x8080)
 *
 * @param buffer [OUT] Output buffer (must be at least LMS_PBLC_PREFIX_LEN + p*n bytes)
 * @param I      [IN]  Tree identifier (16 bytes)
 * @param q      [IN]  Leaf index
 * @param chains [IN]  Chain values (p * n bytes)
 * @param p      [IN]  Number of chains
 * @param n      [IN]  Hash output length
 */
void LmsAdrs_BuildOtsPubKeyInput(uint8_t *buffer, const uint8_t *I, uint32_t q, const uint8_t *chains, uint32_t p,
                                 uint32_t n);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_LMS */
#endif /* LMS_ADDRESS_H */

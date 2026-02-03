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

#ifndef XMSS_ADDRESS_H
#define XMSS_ADDRESS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_XMSS

#include <stdint.h>
#include <stddef.h>

typedef struct CryptAdrsOps CryptAdrsOps;

/*
 * XMSS Address Structure (32 bytes, RFC 8391 standard)
 *
 * This structure follows the RFC 8391 XMSS address format.
 * The interpretation of bytes 16-31 depends on the address type:
 *
 * Common fields (all types):
 * | Bytes 0-3   | layer address | Layer index in multi-tree XMSSMT
 * | Bytes 4-11  | tree address  | Tree index within layer
 * | Bytes 12-15 | type          | Address type (OTS=0, LTREE=1, HASH=2)
 *
 * Type-specific fields:
 * - For OTS Hash Address (type=0):
 *   | Bytes 16-19 | OTS address   | WOTS+ key pair index (keyPairAddr)
 *   | Bytes 20-23 | chain address | WOTS+ chain index (chainAddr)
 *   | Bytes 24-27 | hash address  | WOTS+ hash iteration (hashAddr)
 *   | Bytes 28-31 | keyAndMask    | Key/mask index (0, 1, or 2)
 *
 * - For L-tree Address (type=1):
 *   | Bytes 16-19 | L-tree addr   | L-tree index (keyPairAddr)
 *   | Bytes 20-23 | tree height   | Height in L-tree (uses chainAddr field)
 *   | Bytes 24-27 | tree index    | Node index in L-tree (uses hashAddr field)
 *   | Bytes 28-31 | keyAndMask    | Key/mask index
 *
 * - For Tree Hash Address (type=2):
 *   | Bytes 16-19 | padding       | Zero padding
 *   | Bytes 20-23 | tree height   | Height in tree (uses chainAddr field)
 *   | Bytes 24-27 | tree index    | Node index in tree (uses hashAddr field)
 *   | Bytes 28-31 | keyAndMask    | Key/mask index
 *
 * All fields are stored in big-endian format.
 */
typedef union {
    struct {
        uint8_t layerAddr[4]; // Bytes 0-3: Layer address (for XMSSMT)
        uint8_t treeAddr[8]; // Bytes 4-11: Tree address
        uint8_t type[4]; // Bytes 12-15: Address type
        uint8_t keyPairAddr[4]; // Bytes 16-19: WOTS+ key pair address
        uint8_t chainAddr[4]; // Bytes 20-23: WOTS+ chain address
        uint8_t hashAddr[4]; // Bytes 24-27: WOTS+ hash address
        uint8_t keyAndMask[4]; // Bytes 28-31: Key/mask index
    } fields;
    uint8_t bytes[32];
} XmssAdrs;

#define MAX_ADRS_SIZE 32

/* Address types (RFC 8391 Section 2.5) */
#define XMSS_ADRS_TYPE_OTS   0 // WOTS+ address
#define XMSS_ADRS_TYPE_LTREE 1 // L-tree address (compress WOTS+ pk)
#define XMSS_ADRS_TYPE_HASH  2 // Tree hash address

/*
 * Set keyAndMask field (for ROBUST mode)
 * index: 0 for key, 1 for first bitmask, 2 for second bitmask
 *
 * This is the only direct function exposed because it's used internally
 * by xmss_hash.c which doesn't have access to CryptAdrsOps.
 */
void XmssAdrs_SetKeyAndMask(void *adrs, uint32_t index);

/*
 * Initialize CryptAdrsOps with XMSS address operations
 *
 * @param ops [out] Generic address operations table to initialize
 *
 * @return CRYPT_SUCCESS on success
 */
int32_t XmssAdrsOps_Init(CryptAdrsOps *ops);

#endif // HITLS_CRYPTO_XMSS
#endif // XMSS_ADDRESS_H

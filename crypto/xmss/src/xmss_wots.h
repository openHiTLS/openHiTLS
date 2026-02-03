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

#ifndef XMSS_WOTS_H
#define XMSS_WOTS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_XMSS

#include <stdint.h>
#include <stddef.h>
#include "xmss_address.h"
#include "xmss_local.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * XMSS WOTS+ Context
 * This structure encapsulates the parameters needed for WOTS+ operations
 * Uses generic interfaces for hash functions and address operations
 */
typedef struct {
    void *coreCtx; // Pointer to original context (CryptXmssCtx or CryptSlhDsaCtx)
    uint32_t n; // Hash output length
    uint32_t wotsLen; // WOTS+ chain length
    const CryptHashFuncs *hashFuncs; // Generic hash function table (pointer)
    const CryptAdrsOps *adrsOps; // Generic address operation function pointers
    const uint8_t *pubSeed; // Public seed (for key derivation)
    const uint8_t *skSeed; // Private seed (for WOTS+ key generation)
    bool isXmss;
} XmssWotsCtx;

/*
 * Compute a WOTS+ chain
 *
 * Iteratively applies the F function to compute a chain segment.
 *
 * @param x       Input value (n bytes)
 * @param xLen    Length of input (must be n)
 * @param start   Starting position in chain
 * @param steps   Number of steps to iterate (not end position!)
 * @param pubSeed Public seed for hash function
 * @param adrs    Address for domain separation
 * @param ctx     WOTS+ context
 * @param output  Output chain result (n bytes)
 *
 * @return CRYPT_SUCCESS on success
 */
int32_t XmssWots_Chain(const uint8_t *x, uint32_t xLen, uint32_t start, uint32_t steps, const uint8_t *pubSeed,
                       void *adrs, const XmssWotsCtx *ctx, uint8_t *output);

/*
 * Generate a WOTS+ public key from a private key
 *
 * Computes the WOTS+ public key by chaining each private key element.
 *
 * @param pub     Output WOTS+ public key (n bytes)
 * @param adrs    Address for domain separation
 * @param ctx     WOTS+ context
 *
 * @return CRYPT_SUCCESS on success
 */
int32_t XmssWots_GeneratePublicKey(uint8_t *pub, void *adrs, const XmssWotsCtx *ctx);

/*
 * Sign a message using WOTS+
 *
 * @param sig     Output WOTS+ signature (len * n bytes)
 * @param sigLen  Input: buffer size, Output: actual signature length
 * @param msg     Message to sign (n bytes - already hashed)
 * @param msgLen  Length of message (must be n)
 * @param adrs    Address for domain separation
 * @param ctx     WOTS+ context
 *
 * @return CRYPT_SUCCESS on success
 */
int32_t XmssWots_Sign(uint8_t *sig, uint32_t *sigLen, const uint8_t *msg, uint32_t msgLen, void *adrs,
                      const XmssWotsCtx *ctx);

/*
 * Compute a WOTS+ public key from a signature and message
 *
 * Reconstructs the WOTS+ public key from the signature by completing
 * the chains from the signature values.
 *
 * @param msg     Message that was signed (n bytes)
 * @param msgLen  Length of message (must be n)
 * @param sig     WOTS+ signature (len * n bytes)
 * @param sigLen  Length of signature
 * @param adrs    Address for domain separation
 * @param ctx     WOTS+ context
 * @param pub     Output reconstructed WOTS+ public key (n bytes)
 *
 * @return CRYPT_SUCCESS on success
 */
int32_t XmssWots_PkFromSig(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, void *adrs,
                           const XmssWotsCtx *ctx, uint8_t *pub);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_XMSS
#endif // XMSS_WOTS_H

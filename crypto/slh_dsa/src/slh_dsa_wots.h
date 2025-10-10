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

#ifndef CRYPT_SLH_DSA_WOTS_H
#define CRYPT_SLH_DSA_WOTS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SLH_DSA

#include <stdint.h>
#include "crypt_slh_dsa.h"

/**
 * @brief Compute a WOTS+ public key from a private key
 *
 * @param pub Output WOTS+ public key
 * @param seed Public seed for chain computation
 * @param adrs Address structure for domain separation
 * @return int 0 on success, error code otherwise
 */
int WotsGeneratePublicKey(uint8_t *pub, SlhDsaAdrs *adrs, const CryptSlhDsaCtx *ctx);

/**
 * @brief Sign a message using WOTS+
 *
 * @param sig Output WOTS+ signature
 * @param sigLen Length of the signature
 * @param msg Input message to sign
 * @param msgLen Length of the message
 * @param adrs Address structure for domain separation
 * @param ctx SLH-DSA context
 * @return int 0 on success, error code otherwise
 */
int32_t WotsSign(uint8_t *sig, uint32_t *sigLen, const uint8_t *msg, uint32_t msgLen, SlhDsaAdrs *adrs,
                 const CryptSlhDsaCtx *ctx);

/**
 * @brief Compute a WOTS+ public key from a signature and message
 *
 * @param msg Input message that was signed
 * @param msgLen Length of the message
 * @param sig WOTS+ signature
 * @param sigLen Length of the signature
 * @param adrs Address structure for domain separation
 * @param ctx SLH-DSA context
 * @param pub Output reconstructed WOTS+ public key, the length is n
 * @return int 0 on success, error code otherwise
 */
int32_t WotsPubKeyFromSig(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, SlhDsaAdrs *adrs,
                      const CryptSlhDsaCtx *ctx, uint8_t *pub);

/**
 * @brief Compute a WOTS+ chain
 *
 * @param x Input private key value to chain
 * @param xLen Length of the input private key value
 * @param start Starting position in the chain
 * @param end Ending position in the chain
 * @param seed Public seed for chain computation
 * @param adrs Address structure for domain separation
 * @param ctx SLH-DSA context
 * @param output Output chain result, the length is n
 * @return int 0 on success, error code otherwise
 */
int32_t WotsChain(const uint8_t *x, uint32_t xLen, uint32_t start, uint32_t end, const uint8_t *seed, SlhDsaAdrs *adrs,
                  const CryptSlhDsaCtx *ctx, uint8_t *output);

#endif // HITLS_CRYPTO_SLH_DSA
#endif // CRYPT_SLH_DSA_WOTS_H
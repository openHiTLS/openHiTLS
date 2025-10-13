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

#ifndef CRYPT_SLH_DSA_FORS_H
#define CRYPT_SLH_DSA_FORS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SLH_DSA

#include <stdint.h>
#include "crypt_slh_dsa.h"
#include "slh_dsa_local.h"

/**
 * @brief Sign a message using FORS
 *
 * @param md Input message to sign (already hashed to appropriate length)
 * @param mdLen Length of the message
 * @param adrs Address structure for domain separation
 * @param ctx Context
 * @param sig Output signature
 * @param sigLen Length of the signature
 * @return int 0 on success, error code otherwise
 */
int32_t ForsSign(const uint8_t *md, uint32_t mdLen, SlhDsaAdrs *adrs, const CryptSlhDsaCtx *ctx, uint8_t *sig,
                 uint32_t *sigLen);

/**
 * @brief Verify a FORS signature
 *
 * @param sig Input signature
 * @param sigLen Length of the signature
 * @param md Input message that was signed
 * @param mdLen Length of the message
 * @param adrs Address structure for domain separation
 * @param ctx Context
 * @param pk Output public key
 * @return int 0 if signature is valid, error code otherwise
 */
int32_t ForsPkFromSig(const uint8_t *sig, uint32_t sigLen, const uint8_t *md, uint32_t mdLen, SlhDsaAdrs *adrs,
                      const CryptSlhDsaCtx *ctx, uint8_t *pk);

/**
 * @brief Generate a FORS private value
 *
 * @param adrs Address structure for domain separation
 * @param idx Tree index
 * @param ctx Context
 * @param sk Output private value, the length is n
 * @return int 0 on success, error code otherwise
 */
int32_t ForsGenPrvKey(const SlhDsaAdrs *adrs, uint32_t idx, const CryptSlhDsaCtx *ctx, uint8_t *sk);

/**
 * @brief Generate a FORS node
 *
 * @param idx Tree index
 * @param height Height of the tree
 * @param adrs Address structure for domain separation
 * @param ctx Context
 * @param node Output node, the length is n
 * @return int 0 on success, error code otherwise
 */
int32_t ForsNode(uint32_t idx, uint32_t height, SlhDsaAdrs *adrs, const CryptSlhDsaCtx *ctx, uint8_t *node);

#endif // HITLS_CRYPTO_SLH_DSA
#endif // CRYPT_SLH_DSA_FORS_H
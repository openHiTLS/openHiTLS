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

#ifndef CRYPT_SLH_DSA_XMSS_H
#define CRYPT_SLH_DSA_XMSS_H

#include "slh_dsa.h"
#include "slh_dsa_wots.h"
#include <stdint.h>

#ifdef HITLS_CRYPTO_SLH_DSA

/**
 * @brief Sign a message using XMSS
 * 
 * @param sig Output XMSS signature
 * @param sigLen Length of the signature
 * @param msg Input message to sign
 * @param msgLen Length of the message
 * @param idx Index of the used WOTS+ key pair
 * @param adrs Address structure for domain separation
 * @param ctx SLH-DSA context
 * @return int 0 on success, error code otherwise
 */
int32_t XmssSign(const uint8_t *msg, size_t msgLen, uint32_t idx, SlhDsaAdrs *adrs, const SlhDsaCtx *ctx, uint8_t *sig,
                 uint32_t *sigLen);

/**
 * @brief Compute an internal node of the XMSS tree
 * 
 * @param node Output internal node
 * @param idx Node index at the given height
 * @param height Node height in the tree
 * @param adrs Address structure for domain separation
 * @param ctx SLH-DSA context
 * @return int 0 on success, error code otherwise
 */
int32_t XmssNode(SlhDsaN *node, uint32_t idx, uint32_t height, SlhDsaAdrs *adrs, const SlhDsaCtx *ctx);

/**
 * @brief Compute a public key from a signature and message
 * 
 * @param idx Index of the used WOTS+ key pair
 * @param sig Signature
 * @param sigLen Length of the signature
 * @param msg Message
 * @param msgLen Length of the message
 * @param adrs Address structure for domain separation
 * @param ctx SLH-DSA context
 * @param pk Output public key
 * @return int 0 on success, error code otherwise
 */
int32_t XmssPkFromSig(uint32_t idx, const uint8_t *sig, uint32_t sigLen, const uint8_t *msg, uint32_t msgLen,
                      SlhDsaAdrs *adrs, const SlhDsaCtx *ctx, SlhDsaN *pk);

#endif // HITLS_CRYPTO_SLH_DSA
#endif // CRYPT_SLH_DSA_XMSS_H
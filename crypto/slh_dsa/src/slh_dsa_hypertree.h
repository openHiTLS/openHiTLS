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

#ifndef CRYPT_SLH_DSA_HYPERTREE_H
#define CRYPT_SLH_DSA_HYPERTREE_H

#include <stdint.h>
#include "slh_dsa_local.h"

#ifdef HITLS_CRYPTO_SLH_DSA

/**
 * @brief Sign a message using Hypertree
 *
 * @param msg Input message to sign
 * @param msgLen Length of the message
 * @param treeIdx Index of the tree to use
 * @param leafIdx Index of the leaf to use
 * @param ctx Context of SLH-DSA
 * @param sig Output signature
 * @param sigLen Length of the signature
 * @return int 0 on success, error code otherwise
 */
int32_t HypertreeSign(const uint8_t *msg, uint32_t msgLen, uint64_t treeIdx, uint32_t leafIdx,
                      const CryptSlhDsaCtx *ctx, uint8_t *sig, uint32_t *sigLen);

/**
 * @brief Verify a Hypertree signature
 *
 * @param msg Input message that was signed
 * @param msgLen Length of the message
 * @param sig Hypertree signature to verify
 * @param sigLen Length of the signature
 * @param treeIdx Index of the tree to use
 * @param leafIdx Index of the leaf to use
 * @param ctx Context of SLH-DSA
 * @return int 0 if signature is valid, error code otherwise
 */
int32_t HypertreeVerify(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, uint64_t treeIdx,
                        uint32_t leafIdx, const CryptSlhDsaCtx *ctx);

#endif // HITLS_CRYPTO_SLH_DSA
#endif // CRYPT_SLH_DSA_HYPERTREE_H
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

#ifndef SLH_DSA_HASH_H
#define SLH_DSA_HASH_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SLH_DSA

#include <stdint.h>

/*
 * Initialize SLH-DSA hash functions for a given algorithm
 *
 * This function sets up the hash function pointers in the SLH-DSA context
 * based on the algorithm parameters.
 *
 * @param ctx   SLH-DSA context (will be initialized with hash function pointer)
 */
void SlhDsaInitHashFuncs(CryptSlhDsaCtx *ctx);

#endif // HITLS_CRYPTO_SLH_DSA
#endif // SLH_DSA_HASH_H

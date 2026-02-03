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

#ifndef XMSS_HASH_H
#define XMSS_HASH_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_XMSS

#include "xmss_common.h"
#include "xmss_local.h"
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize XMSS hash functions for a given algorithm
 *
 * This function sets up the hash function pointers in the XMSS context
 * based on the algorithm parameters.
 *
 * @param ctx   XMSS context (will be initialized with hash function pointer)
 *
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t XmssInitHashFuncs(CryptXmssCtx *ctx);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_XMSS
#endif // XMSS_HASH_H

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
/* Check the dependency of the configuration features. The check rules are as follows:
 * Non-deterministic feature dependency needs to be checked.
 * For example, feature a depends on feature b or c:
 * if feature a is defined, at least one of feature b and c must be defined.
 */

#ifndef HITLS_CONFIG_CHECK_H
#define HITLS_CONFIG_CHECK_H

#if defined(HITLS_BSL_SAL_MEM) || defined(HITLS_BSL_SAL_LOCK) || defined(HITLS_BSL_SAL_THREAD) || \
    defined(HITLS_BSL_SAL_TIME) || defined(HITLS_BSL_SAL_FILE) || defined(HITLS_BSL_SAL_NET) ||   \
    defined(HITLS_BSL_SAL_STR) || defined(HITLS_BSL_SAL_DL)
    #ifndef HITLS_BSL_SAL_LINUX
    #error "[HiTLS] sal_* only work with HITLS_BSL_SAL_LINUX."
    #endif
#endif

#if defined(HITLS_CRYPTO_HMAC) && !defined(HITLS_CRYPTO_MD)
#error "[HiTLS] The hmac must work with hash."
#endif

#if defined(HITLS_CRYPTO_DRBG_HASH) && !defined(HITLS_CRYPTO_MD)
#error "[HiTLS] The drbg_hash must work with hash."
#endif

#if defined(HITLS_CRYPTO_ENTROPY) && !defined(HITLS_CRYPTO_DRBG)
#error "[HiTLS] The entropy must work with at leaset one drbg algorithm."
#endif

#if defined(HITLS_CRYPTO_PKEY) && !defined(HITLS_CRYPTO_MD)
#error "[HiTLS] The pkey must work with hash."
#endif

#if defined(HITLS_CRYPTO_BN) && !(defined(HITLS_THIRTY_TWO_BITS) || defined(HITLS_SIXTY_FOUR_BITS))
#error "[HiTLS] To use bn, the number of system bits must be specified first."
#endif

#endif /* HITLS_CONFIG_CHECK_H */

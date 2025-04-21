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

#ifndef ASMCAP_LOCAL_H
#define ASMCAP_LOCAL_H
 
#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ASM_CHECK
#include "crypt_ealinit.h"
 
#ifdef __cplusplus
extern "c" {
#endif

#if defined(HITLS_CRYPTO_CIPHER)
#if defined(HITLS_CRYPTO_AES_ASM)

int32_t CRYPT_AES_AsmCheck(void);
#endif // HITLS_CRYPTO_AES_ASM

#if defined(HITLS_CRYPTO_CHACHA20_ASM)
int32_t CRYPT_CHACHA20_AsmCheck(void);
#endif // HITLS_CRYPTO_CHACHA20

#if defined(HITLS_CRYPTO_CHACHA20POLY1305_ASM)
int32_t CRYPT_POLY1305_AsmCheck(void);
#endif // HITLS_CRYPTO_CHACHA20POLY1305

#if defined(HITLS_CRYPTO_SM4_ASM)
int32_t CRYPT_SM4_AsmCheck(void);
#endif // HITLS_CRYPTO_SM4

#if defined(HITLS_CRYPTO_GCM_ASM)
int32_t CRYPT_GHASH_AsmCheck(void);
#endif // HITLS_CRYPTO_GCM

#endif // HITLS_CRYPTO_CIPHER

#if defined(HITLS_CRYPTO_MD)
#if defined(HITLS_CRYPTO_MD5_ASM)
int32_t CRYPT_MD5_AsmCheck(void);
#endif // HITLS_CRYPTO_MD5
#if defined(HITLS_CRYPTO_SHA1_ASM)
int32_t CRYPT_SHA1_AsmCheck(void);
#endif // HITLS_CRYPTO_SHA1

#if defined(HITLS_CRYPTO_SHA2_ASM)
int32_t CRYPT_SHA2_AsmCheck(void);
#endif // HITLS_CRYPTO_SHA2

#if defined(HITLS_CRYPTO_SM3_ASM)
int32_t CRYPT_SM3_AsmCheck(void);
#endif // HITLS_CRYPTO_SM3
#endif // HITLS_CRYPTO_MD


#if defined(HITLS_CRYPTO_PKEY)

#if defined(HITLS_CRYPTO_BN_ASM)
int32_t CRYPT_BN_AsmCheck(void);
#endif // HITLS_CRYPTO_BN_ASM

#if defined(HITLS_CRYPTO_CURVE_NISTP256_ASM)
int32_t CRYPT_ECP256_AsmCheck(void);
#endif // HITLS_CRYPTO_ECC

#endif // HITLS_CRYPTO_PKEY
#ifdef __cplusplus
}
#endif
 
#endif // HITLS_CRYPTO_ASM_CHECK
#endif // ASMCAP_LOCAL_H
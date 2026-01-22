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

#ifndef CRYPTO_TEST_UTIL_H
#define CRYPTO_TEST_UTIL_H

#include "hitls_build.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif

void TestMemInit(void);

int TestRandInit(void);

void TestRandDeInit(void);

bool IsMdAlgDisabled(int id);

bool IsHmacAlgDisabled(int id);

bool IsMacAlgDisabled(int id);

bool IsDrbgHashAlgDisabled(int id);

bool IsDrbgHmacAlgDisabled(int id);

int GetAvailableRandAlgId(void);

bool IsRandAlgDisabled(int id);

bool IsAesAlgDisabled(int id);

bool IsSm4AlgDisabled(int id);

bool IsCipherAlgDisabled(int id);

bool IsCmacAlgDisabled(int id);

bool IsCurveDisabled(int eccId);

bool IsCurve25519AlgDisabled(int id);

int32_t TestSimpleRand(uint8_t *buff, uint32_t len);
int32_t TestSimpleRandEx(void *libCtx, uint8_t *buff, uint32_t len);

#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_MAC)
uint32_t TestGetMacLen(int algId);
void TestMacSameAddr(int algId, Hex *key, Hex *data, Hex *mac);
void TestMacAddrNotAlign(int algId, Hex *key, Hex *data, Hex *mac);
#endif

#ifdef HITLS_CRYPTO_CIPHER
CRYPT_EAL_CipherCtx *TestCipherNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t id, const char *attrName, int isProvider);
#endif

#ifdef HITLS_CRYPTO_PKEY
CRYPT_EAL_PkeyCtx *TestPkeyNewCtx(
    CRYPT_EAL_LibCtx *libCtx, int32_t id, uint32_t operType, const char *attrName, int isProvider);
#endif

#ifdef __aarch64__
#define AARCH64_PUT_CANARY()                                          \
    double canaryd = 1.1;                                            \
    register double d8 asm("d8");                                     \
    register double d9 asm("d9");                                     \
    register double d10 asm("d10");                                   \
    register double d11 asm("d11");                                   \
    register double d12 asm("d12");                                   \
    register double d13 asm("d13");                                   \
    register double d14 asm("d14");                                   \
    register double d15 asm("d15");                                   \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d8) : "w"(canaryd) :);  \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d9) : "w"(canaryd) :);  \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d10) : "w"(canaryd) :); \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d11) : "w"(canaryd) :); \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d12) : "w"(canaryd) :); \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d13) : "w"(canaryd) :); \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d14) : "w"(canaryd) :); \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d15) : "w"(canaryd) :); \
    long canaryx = 0x12345678;                                        \
    register int x19 asm("x19");                                      \
    register int x20 asm("x20");                                      \
    register int x21 asm("x21");                                      \
    register int x22 asm("x22");                                      \
    register int x23 asm("x23");                                      \
    register int x24 asm("x24");                                      \
    register int x25 asm("x25");                                      \
    register int x26 asm("x26");                                      \
    register int x27 asm("x27");                                      \
    register int x28 asm("x28");                                      \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x19) : "r"(canaryx) :);   \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x20) : "r"(canaryx) :);   \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x21) : "r"(canaryx) :);   \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x22) : "r"(canaryx) :);   \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x23) : "r"(canaryx) :);   \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x24) : "r"(canaryx) :);   \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x25) : "r"(canaryx) :);   \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x26) : "r"(canaryx) :);   \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x27) : "r"(canaryx) :);   \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x28) : "r"(canaryx) :);

#define AARCH64_CHECK_CANARY()   \
    ASSERT_TRUE(d8 == canaryd);  \
    ASSERT_TRUE(d9 == canaryd);  \
    ASSERT_TRUE(d10 == canaryd); \
    ASSERT_TRUE(d11 == canaryd); \
    ASSERT_TRUE(d12 == canaryd); \
    ASSERT_TRUE(d13 == canaryd); \
    ASSERT_TRUE(d14 == canaryd); \
    ASSERT_TRUE(d15 == canaryd); \
    ASSERT_TRUE(x19 == canaryx); \
    ASSERT_TRUE(x20 == canaryx); \
    ASSERT_TRUE(x21 == canaryx); \
    ASSERT_TRUE(x22 == canaryx); \
    ASSERT_TRUE(x23 == canaryx); \
    ASSERT_TRUE(x24 == canaryx); \
    ASSERT_TRUE(x25 == canaryx); \
    ASSERT_TRUE(x26 == canaryx); \
    ASSERT_TRUE(x27 == canaryx); \
    ASSERT_TRUE(x28 == canaryx);
#else
#define AARCH64_PUT_CANARY()
#define AARCH64_CHECK_CANARY()
#endif

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_TEST_UTIL_H
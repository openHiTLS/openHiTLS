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
int TestRandInitEx(void *libCtx);

void TestRandDeInit(void);

int TestRandInitSelfCheck(void);
#ifndef AEAD_MAX_TAG_LEN
#define AEAD_MAX_TAG_LEN 16
#endif

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

void TestErrClear(void);
bool TestIsErrStackEmpty(void);
bool TestIsErrStackNotEmpty(void);

int32_t TestSimpleRand(uint8_t *buff, uint32_t len);
int32_t TestSimpleRandEx(void *libCtx, uint8_t *buff, uint32_t len);
int32_t TestSimpleRandExSelfCheck(void *libCtx, uint8_t *buff, uint32_t len);

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
/*
 * The current AArch64 smoke tests call into assembly through public APIs.
 * These canaries verify the callee-saved part of the ABI contract across
 * those calls.
 *
 * before call                               after call
 *   d8  = 1.0      --------------------->     d8  == 1.0
 *   d9  = 2.0      --------------------->     d9  == 2.0
 *   d10 = 3.0      --------------------->     d10 == 3.0
 *   ...                                      ...
 *   d15 = 8.0      --------------------->     d15 == 8.0
 *
 *   x19 = 0x1919..  --------------------->     x19 == 0x1919..
 *   x20 = 0x2020..  --------------------->     x20 == 0x2020..
 *   x21 = 0x2121..  --------------------->     x21 == 0x2121..
 *   ...                                      ...
 *   x28 = 0x2828..  --------------------->     x28 == 0x2828..
 *
 * d8-d15:
 *   AAPCS64 requires the low 64 bits of d8-d15 to survive a call.
 *   Distinct sentinels catch both clobber and wrong restore order.
 *
 * x19-x28:
 *   AAPCS64 requires full 64-bit preservation of x19-x28.
 *   Distinct 64-bit sentinels catch clobber, truncation, and swapped restore.
 */
#define AARCH64_PUT_CANARY()                                                    \
    double canaryd8 = 1.0;                                                      \
    double canaryd9 = 2.0;                                                      \
    double canaryd10 = 3.0;                                                     \
    double canaryd11 = 4.0;                                                     \
    double canaryd12 = 5.0;                                                     \
    double canaryd13 = 6.0;                                                     \
    double canaryd14 = 7.0;                                                     \
    double canaryd15 = 8.0;                                                     \
    register double d8 asm("d8");                                               \
    register double d9 asm("d9");                                               \
    register double d10 asm("d10");                                             \
    register double d11 asm("d11");                                             \
    register double d12 asm("d12");                                             \
    register double d13 asm("d13");                                             \
    register double d14 asm("d14");                                             \
    register double d15 asm("d15");                                             \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d8) : "w"(canaryd8) :);           \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d9) : "w"(canaryd9) :);           \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d10) : "w"(canaryd10) :);         \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d11) : "w"(canaryd11) :);         \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d12) : "w"(canaryd12) :);         \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d13) : "w"(canaryd13) :);         \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d14) : "w"(canaryd14) :);         \
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d15) : "w"(canaryd15) :);         \
    unsigned long canaryx19 = 0x1919191919191919UL;                             \
    unsigned long canaryx20 = 0x2020202020202020UL;                             \
    unsigned long canaryx21 = 0x2121212121212121UL;                             \
    unsigned long canaryx22 = 0x2222222222222222UL;                             \
    unsigned long canaryx23 = 0x2323232323232323UL;                             \
    unsigned long canaryx24 = 0x2424242424242424UL;                             \
    unsigned long canaryx25 = 0x2525252525252525UL;                             \
    unsigned long canaryx26 = 0x2626262626262626UL;                             \
    unsigned long canaryx27 = 0x2727272727272727UL;                             \
    unsigned long canaryx28 = 0x2828282828282828UL;                             \
    register unsigned long x19 asm("x19");                                       \
    register unsigned long x20 asm("x20");                                       \
    register unsigned long x21 asm("x21");                                       \
    register unsigned long x22 asm("x22");                                       \
    register unsigned long x23 asm("x23");                                       \
    register unsigned long x24 asm("x24");                                       \
    register unsigned long x25 asm("x25");                                       \
    register unsigned long x26 asm("x26");                                       \
    register unsigned long x27 asm("x27");                                       \
    register unsigned long x28 asm("x28");                                       \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x19) : "r"(canaryx19) :);           \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x20) : "r"(canaryx20) :);           \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x21) : "r"(canaryx21) :);           \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x22) : "r"(canaryx22) :);           \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x23) : "r"(canaryx23) :);           \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x24) : "r"(canaryx24) :);           \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x25) : "r"(canaryx25) :);           \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x26) : "r"(canaryx26) :);           \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x27) : "r"(canaryx27) :);           \
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x28) : "r"(canaryx28) :);

/* Only the AAPCS64-required callee-saved state is asserted here. */
#define AARCH64_CHECK_CANARY()      \
    ASSERT_TRUE(d8 == canaryd8);    \
    ASSERT_TRUE(d9 == canaryd9);    \
    ASSERT_TRUE(d10 == canaryd10);  \
    ASSERT_TRUE(d11 == canaryd11);  \
    ASSERT_TRUE(d12 == canaryd12);  \
    ASSERT_TRUE(d13 == canaryd13);  \
    ASSERT_TRUE(d14 == canaryd14);  \
    ASSERT_TRUE(d15 == canaryd15);  \
    ASSERT_TRUE(x19 == canaryx19);  \
    ASSERT_TRUE(x20 == canaryx20);  \
    ASSERT_TRUE(x21 == canaryx21);  \
    ASSERT_TRUE(x22 == canaryx22);  \
    ASSERT_TRUE(x23 == canaryx23);  \
    ASSERT_TRUE(x24 == canaryx24);  \
    ASSERT_TRUE(x25 == canaryx25);  \
    ASSERT_TRUE(x26 == canaryx26);  \
    ASSERT_TRUE(x27 == canaryx27);  \
    ASSERT_TRUE(x28 == canaryx28);
#else
#define AARCH64_PUT_CANARY()
#define AARCH64_CHECK_CANARY()
#endif

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_TEST_UTIL_H

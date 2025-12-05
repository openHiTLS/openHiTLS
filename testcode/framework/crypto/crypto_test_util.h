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

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_TEST_UTIL_H
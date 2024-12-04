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

#ifdef __cplusplus
extern "C" {
#endif

void TestMemInit(void);

int TestRandInit(void);

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

int32_t TestSimpleRand(uint8_t *buff, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_TEST_UTIL_H
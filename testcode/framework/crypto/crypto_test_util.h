/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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

int GetAvailableRandAlgId();

bool IsRandAlgDisabled(int id);

bool IsAesAlgDisabled(int id);

bool IsSm4AlgDisabled(int id);

bool IsCipherAlgDisabled(int id);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_TEST_UTIL_H
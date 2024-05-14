/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef STUB_CRYPT_H
#define STUB_CRYPT_H
#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief Stub the test framework
*/
void FRAME_RegCryptMethod(void);

void FRAME_DeRegCryptMethod(void);

#ifdef __cplusplus
}
#endif

#endif // STUB_CRYPT_H

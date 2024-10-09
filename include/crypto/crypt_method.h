/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/**
 * @defgroup crypt_method
 * @ingroup crypt
 * @brief methods of crypto
 */

#ifndef CRYPT_METHOD_H
#define CRYPT_METHOD_H

#include <stdint.h>
#include <stdbool.h>
#include "crypt_types.h"
#include "crypt_algid.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define CRYPT_EAL_INIT_CPU   0x01
#define CRYPT_EAL_INIT_BSL   0x02
#define CRYPT_EAL_INIT_RAND  0x04

/**
 * @ingroup crypt_method
 * @brief CRYPTO initialization
 *
 * @param opts   [IN] Bit information to be initialized, the first three bits are used at present.
 *                    The first bit is CRYPT_EAL_INIT_CPU marked as "CPU ", the second bit is BSL
 *                    CRYPT_EAL_INIT_BSL marked as "BSL", and the third bit is CRYPT_EAL_INIT_RAND
 *                    marked as "RAND".
 * @retval #CRYPT_SUCCESS, if successful.
 *         For other error codes, see the crypt_errno.h file.
 */
int32_t CRYPT_EAL_Init(uint64_t opts);

/**
 * @ingroup crypt_method
 * @brief   release the CRYPTO initialization memory.
 *
 * @param opts   [IN] information about the bits to be deinitialized, which is the same as that of CRYPT_EAL_Init.
 */
void CRYPT_EAL_Cleanup(uint64_t opts);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_METHOD_H

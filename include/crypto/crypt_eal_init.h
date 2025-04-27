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

/**
 * @defgroup crypt_method
 * @ingroup crypt
 * @brief methods of crypto
 */

#ifndef CRYPT_EAL_INIT_H
#define CRYPT_EAL_INIT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define CRYPT_EAL_INIT_CPU              0x01
#define CRYPT_EAL_INIT_BSL              0x02
#define CRYPT_EAL_INIT_RAND             0x04
#define CRYPT_EAL_INIT_PROVIDER         0x08
#define CRYPT_EAL_INIT_LOCK             0x10
#define CRYPT_EAL_INIT_PROVIDER_RAND    0x20

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

#endif // CRYPT_EAL_INIT_H

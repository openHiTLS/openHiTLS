/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_SCRYPT_H
#define CRYPT_SCRYPT_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SCRYPT

#include <stdint.h>
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef int32_t (*PBKDF2_PRF)(const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth,
    const uint8_t *key, uint32_t keyLen,
    const uint8_t *salt, uint32_t saltLen,
    uint32_t iterCnt, uint8_t *out, uint32_t len);

/**
 * @brief scrypt Password-based key derivation function
 *
 * @param pbkdf2Prf [IN] pbkdf2 function pointer.
 * @param macMeth [IN] HMAC algorithm method. Only the HMAC method is supported.
 * @param mdMeth [IN] md algorithm method
 * @param key [IN] Password, a string entered by the user.
 * @param keyLen [IN] Password length, which can be any length, including 0.
 * @param salt [IN] Salt value, a string entered by the user.
 * @param saltLen [IN] Salt value length, which can be any length, including 0.
 * @param n [IN] CPU and memory consumption parameters. The value must be a power of 2, between 1 and 2 ^ (128 * r / 8)
 * @param r [IN] Block size parameter, which can be any positive integer except 0, where r * p < 2 ^ 30
 * @param p [IN] Parallelization parameter, which can be any positive integer but 0. p <= (2 ^ 32 - 1) * 32 / (128 * r)
 * @param out [OUT] Derived key, which cannot be empty.
 * @param len [IN] Length of the derived key. Range: (0, 0xFFFFFFFF]
 *
 * @return Success: CRYPT_SUCCESS
 *         For other error codes, see crypt_errno.h
 */
int32_t CRYPT_SCRYPT(PBKDF2_PRF pbkdf2Prf, const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth,
    const uint8_t *key, uint32_t keyLen, const uint8_t *salt, uint32_t saltLen, uint32_t n,
    uint32_t r, uint32_t p, uint8_t *out, uint32_t len);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_SCRYPT

#endif // CRYPT_SCRYPT_H

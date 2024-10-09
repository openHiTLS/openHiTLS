/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef PBKDF2_LOCAL_H
#define PBKDF2_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_PBKDF2

#include <stdint.h>
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @brief PBKDF Password-based key derivation function
 *
 * @param macMeth [IN] Pointer to the HMAC algorithm method
 * @param mdMeth [IN] MD algorithm method pointer
 * @param key [IN] Password, a string entered by the user.
 * @param keyLen [IN] Password length, which can be any length, including 0.
 * @param salt [IN] Salt value, a string entered by the user.
 * @param saltLen [IN] Salt value length, which can be any length, including 0.
 * @param iterCnt [IN] Iteration times. The value can be any positive integer that is not 0.
 *                The value can be 1000 in special performance cases. The default value is 10000,
 *                10000000 is recommended in cases where performance is insensitive or security requirements are high.
 * @param out [OUT] Derived key.
 * @param len [IN] Length of the derived key. The value range is [1, 0xFFFFFFFF].
 *
 * @return Success: CRYPT_SUCCESS
 *         For other error codes, see crypt_errno.h
 */
int32_t CRYPT_PBKDF2_HMAC(const EAL_MacMethod *macMeth, CRYPT_MAC_AlgId macId, const EAL_MdMethod *mdMeth,
    const uint8_t *key, uint32_t keyLen,
    const uint8_t *salt, uint32_t saltLen,
    uint32_t iterCnt, uint8_t *out, uint32_t len);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_PBKDF2

#endif // PBKDF2_LOCAL_H

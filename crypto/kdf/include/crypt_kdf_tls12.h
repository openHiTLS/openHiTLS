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

#ifndef CRYPT_KDF_TLS12_H
#define CRYPT_KDF_TLS12_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_KDFTLS12

#include <stdint.h>
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @brief   KDF-TLS1.2
 *
 * @param macMeth [IN] Pointer to the HMAC algorithm method
 * @param mdMeth [IN] Pointer to the MD algorithm method
 * @param key [IN] Key, byte array entered by the user.
 * @param keyLen [IN] Key length, any length
 * @param label [IN] Label, byte array entered by the user. Combined with the seed as the PRF input data.
 * @param labelLen [IN] Label length, any length
 * @param seed [IN] Seed, byte array entered by a user, used as the PRF input data.
 * @param seedLen [IN] Seed length, any length
 * @param out [OUT] Derive key.
 * @param outLen [IN] Length of the derived key. The value range is [1, 0xFFFFFFFF].
 *
 * @return If the operation is successful, the CRYPT_SUCCESS is returned.
 * For other error codes, see the crypt_errno.h.
 */
int32_t CRYPT_KDF_TLS12(const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth, const uint8_t *key, uint32_t keyLen,
    const uint8_t *label, uint32_t labelLen, const uint8_t *seed, uint32_t seedLen, uint8_t *out, uint32_t len);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_KDFTLS12

#endif // CRYPT_KDF_TLS12_H

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

#ifndef CRYPT_HKDF_H
#define CRYPT_HKDF_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HKDF

#include <stdint.h>
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @brief HKdf Key derivation algorithm
 *
 * @param macMeth [in] HMAC algorithm method. Only the HMAC method is supported.
 * @param mdMeth [in] md algorithm method
 * @param key [IN] Password, a string entered by the user.
 * @param keyLen [IN] The password length is any length, including 0.
 * @param salt [IN] Salt value, a string entered by the user.
 * @param saltLen [IN] Salt value length, including 0.
 * @param info [in] Additional information
 * @param infoLen [in] Length of the extra information, which can be any length, including 0.
 * @param out [OUT] Derive key.
 * @param outLen [IN] Derived key length, is any integer other than 0. The maximum value is as follows:
 *                    The maximum value of CRYPT_MAC_HMAC_SHA1 is 5100.
 *                    The maximum value of CRYPT_MAC_HMAC_SHA224 is 7140.
 *                    The maximum value of CRYPT_MAC_HMAC_SHA256 is 8160.
 *                    The maximum value of CRYPT_MAC_HMAC_SHA384 is 12240.
 *                    The maximum value of CRYPT_MAC_HMAC_SHA512 is 16320,
 *
 * @return CRYPT_OK succeeded.
 * For other error codes, see ht_error.h.
 */

int32_t CRYPT_HKDF(const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth, const uint8_t *key, uint32_t keyLen,
    const uint8_t *salt, uint32_t saltLen, const uint8_t *info, uint32_t infoLen, uint8_t *out, uint32_t len);

/**
 * @brief Extract function of the HKDf algorithm
 *
 * @param macMeth [in] HMAC algorithm method. Only the HMAC method is supported.
 * @param mdMeth [in] md algorithm method
 * @param key [IN] Password, a string entered by the user.
 * @param keyLen [IN] The password length, which can be any length, including 0.
 * @param salt [IN] Salt value, a string entered by the user.
 * @param saltLen [IN] Salt value length, including 0.
 * @param prk [OUT] Pseudo-random key
 * @param prkLen [OUT] Pseudo-random key length
 *
 * @return CRYPT_OK succeeded.
 * For other error codes, see ht_error.h.
 */
int32_t CRYPT_HKDF_Extract(const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth, const uint8_t *key, uint32_t keyLen,
    const uint8_t *salt, uint32_t saltLen, uint8_t *prk, uint32_t *prkLen);

/**
 * @brief Expand function for the HKdf algorithm
 *
 * @param macMeth [in] HMAC algorithm method. Only the HMAC method is supported.
 * @param mdMeth [in] md algorithm method
 * @param prk [IN] Pseudo-random key, at least the length of hash (generally the output of the Extract function)
 * @param prkLen [IN] Pseudo-random key length
 * @param info [in] Additional information
 * @param infoLen [in] Length of the extra information, which can be any length, including 0.
 * @param out [OUT] Derive key.
 * @param outLen [IN] length of the derived key, any integer other than 0. The maximum value is as follows:
 *                    The maximum value of CRYPT_MAC_HMAC_SHA1 is 5100.
 *                    The maximum value of CRYPT_MAC_HMAC_SHA224 is 7140.
 *                    The maximum value of CRYPT_MAC_HMAC_SHA256 is 8160.
 *                    The maximum value of CRYPT_MAC_HMAC_SHA384 is 12240.
 *                    The maximum value of CRYPT_MAC_HMAC_SHA512 is 16320,
 *
 * @return CRYPT_OK succeeded.
 * For other error codes, see ht_error.h.
 */
int32_t CRYPT_HKDF_Expand(const EAL_MacMethod *macMeth, const EAL_MdMethod *mdMeth, const uint8_t *prk, uint32_t prkLen,
    const uint8_t *info, uint32_t infoLen, uint8_t *out, uint32_t outLen);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_HKDF

#endif // CRYPT_HKDF_H

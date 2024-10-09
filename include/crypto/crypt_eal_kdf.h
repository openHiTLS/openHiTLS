/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/**
 * @defgroup crypt_eal_kdf
 * @ingroup crypt
 * @brief kdf of crypto module
 */

#ifndef CRYPT_EAL_KDF_H
#define CRYPT_EAL_KDF_H

#include <stdbool.h>
#include <stdint.h>
#include "crypt_algid.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
/**
 * @ingroup crypt_eal_kdf
 * @brief   scrypt Password-based key derivation function
 *
 * @param   key [IN] Password, a string input by the user.
 * @param   keyLen [IN] Password length, including 0
 * @param   salt [IN] Salt value, a string input by the user.
 * @param   saltLen [IN] Salt value length, including 0
 * @param   n [IN] CPU and memory consumption parameters.
 *                 The value must be a power of 2, greater than 1 and less than 2 ^ (128 * r / 8)
 * @param   r [IN] Block size parameter, any positive integer not 0 where r * p < 2 ^ 30
 * @param   p [IN] Parallelization parameter, any positive integer not 0; p <= (2 ^ 32 - 1) * 32 / (128 * r)
 * @param   out [OUT] Derived key, which cannot be null.
 * @param   len [IN] Length of the derived key. Range: (0, 0xFFFFFFFF]
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_Scrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *salt, uint32_t saltLen, uint32_t n,
    uint32_t r, uint32_t p, uint8_t *out, uint32_t len);

/**
 * @ingroup crypt_eal_kdf
 * @brief   PBKDF password-based key derivation function
 *
 * @param   id [IN] HMAC algorithm ID (Only the HMAC algorithm ID is supported, including
 *                CRYPT_MAC_HMAC_MD5, CRYPT_MAC_HMAC_SHA1, and CRYPT_MAC_HMAC_SHA224,
 *                CRYPT_MAC_HMAC_SHA256, CRYPT_MAC_HMAC_SHA384, CRYPT_MAC_HMAC_SHA512,
 *                CRYPT_MAC_HMAC_SM3)
 * @param   key [IN] Password, a string input by the user.
 * @param   keyLen [IN] The password length is any length, including 0.
 * @param   salt [IN] Salt value, a string input by the user.
 * @param   saltLen [IN] Salt value length, including 0.
 * @param   it [IN] Iteration times. The value can be a positive integer that is not 0. The value
 *                  can be 1000 in special performance scenarios. The default value is 10000,
 *                  10000000 is recommended in scenarios where performance is insensitive or
 *                  security requirements are high.
 * @param   out [OUT] Derive the key.
 * @param   len [IN] Length of the derived key. The value range is [1, 0xFFFFFFFF].
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_Pbkdf2(CRYPT_MAC_AlgId id, const uint8_t *key, uint32_t keyLen, const uint8_t *salt,
    uint32_t saltLen, uint32_t it, uint8_t *out, uint32_t len);

/**
 * @ingroup crypt_eal_kdf
 * @brief   PKCS5 PBKDF This MPI encapsulates the CRYPT_EAL_Pbkdf2 API. By default, the CRYPT_MAC_HMAC_SHA256
 * algorithm is used for calculation.
 *
 * @param   key [IN] Password, a string input by the user.
 * @param   keyLen [IN] Password length, which is a positive integer not 0.
 * @param   salt [IN] Salt value, a string input by the user.
 * @param   saltLen [IN] Salt length, any positive integer that is not 0.
 * @param   it [IN] Iteration times, the value can be a positive integer that is not 0. The value
 * can be 1000 in special performance scenarios. The default value is 10000, 10000000 is recommended
 * in scenarios where performance is insensitive or security requirements are high.
 * @param   out [OUT] Derive the key.
 * @param   len [IN] Length of the derived key, the value range is [1, 0xFFFFFFFF].
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
#define CRYPT_EAL_PKCS5_PBKDF2(key, keyLen, salt, saltLen, it, out, len)  \
        CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA256, key, keyLen, salt, saltLen, it, out, len)

/**
 * @ingroup crypt_eal_kdf
 * @brief   HKDF
 *
 * @param   id [IN] MAC algorithm ID (Only the HMAC algorithm ID is supported, including
 * CRYPT_MAC_HMAC_SHA1, CRYPT_MAC_HMAC_SHA224, CRYPT_MAC_HMAC_SHA256, CRYPT_MAC_HMAC_SHA384, CRYPT_MAC_HMAC_SHA512)
 * @param   key [IN] Password, a string input by the user.
 * @param   keyLen [IN] Key length, any length
 * @param   salt [IN] Salt value, a string input by the user.
 * @param   saltLen [IN] Salt length, any length
 * @param   info [IN] Additional information about the user, which is optional.
 * @param   infoLen [IN] Length of the additional information. The value can be 0. [0,0xFFFFFFFF]
 * @param   out [OUT] Derive the key.
 * @param   len [IN] Derived key length, any integer other than 0. The maximum value is as follows:
 *                      The maximum value of CRYPT_MAC_HMAC_SHA1 is 5100.
 *                      The maximum value of CRYPT_MAC_HMAC_SHA224 is 7140.
 *                      The maximum value of CRYPT_MAC_HMAC_SHA256 is 8160.
 *                      The maximum value of CRYPT_MAC_HMAC_SHA384 is 12240.
 *                      The maximum value of CRYPT_MAC_HMAC_SHA512 is 16320.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_Hkdf(CRYPT_MAC_AlgId id, const uint8_t *key, uint32_t keyLen, const uint8_t *salt, uint32_t saltLen,
    const uint8_t *info, uint32_t infoLen, uint8_t *out, uint32_t len);

/**
 * @ingroup crypt_eal_kdf
 * @brief   HKDF
 *
 * @param   id [IN] MAC algorithm ID (Only the HMAC algorithm ID is supported, including CRYPT_MAC_HMAC_SHA1,
 * CRYPT_MAC_HMAC_SHA224, CRYPT_MAC_HMAC_SHA256, CRYPT_MAC_HMAC_SHA384, CRYPT_MAC_HMAC_SHA512)
 * @param   key [IN] Password, a string input by the user.
 * @param   keyLen [IN] Key length, any length
 * @param   salt [IN] Salt value, a string input by the user.
 * @param   saltLen [IN] Salt length, any length
 * @param   out [OUT] Pseudorandom key
 * @param   len [OUT] Pseudorandom key length
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_HkdfExtract(CRYPT_MAC_AlgId id, const uint8_t *key, uint32_t keyLen,
    const uint8_t *salt, uint32_t saltLen, uint8_t *out, uint32_t *len);

/**
 * @ingroup crypt_eal_kdf
 * @brief   HKDF
 *
 * @param   id [IN] MAC algorithm ID (Only the HMAC algorithm ID is supported, including CRYPT_MAC_HMAC_SHA1,
 * CRYPT_MAC_HMAC_SHA224, CRYPT_MAC_HMAC_SHA256, CRYPT_MAC_HMAC_SHA384, CRYPT_MAC_HMAC_SHA512)
 * @param   key [IN] Pseudorandom key, at least hashLen (generally the output of the Extract function)
 * @param   keyLen [IN] Pseudorandom key length
 * @param   info [IN] Additional information about the user, which is optional.
 * @param   infoLen [IN] Length of the additional information. The value can be 0. [0,0xFFFFFFFF]
 * @param   out [OUT] Derive the key.
 * @param   len [IN] Derived key length, any integer other than 0. The maximum value is as follows:
 *                      The maximum value of CRYPT_MAC_HMAC_SHA1 is 5100.
 *                      The maximum value of CRYPT_MAC_HMAC_SHA224 is 7140.
 *                      The maximum value of CRYPT_MAC_HMAC_SHA256 is 8160.
 *                      The maximum value of CRYPT_MAC_HMAC_SHA384 is 12240.
 *                      The maximum value of CRYPT_MAC_HMAC_SHA512 is 16320,
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_HkdfExpand(CRYPT_MAC_AlgId id, const uint8_t *key, uint32_t keyLen,
    const uint8_t *info, uint32_t infoLen, uint8_t *out, uint32_t len);

/**
 * @ingroup crypt_eal_kdf
 * @brief   KDF-TLS1.2
 *
 * @param   id [IN] MAC algorithm ID (Only some HMAC algorithm IDs are supported.)
 *                  These include CRYPT_MAC_HMAC_SHA256, CRYPT_MAC_HMAC_SHA384, and CRYPT_MAC_HMAC_SHA512)
 * @param   key [IN] Key, string input by the user.
 * @param   keyLen [IN] Key length, any length.
 * @param   label [IN] Label, string input by the user, combined with the seed as the PRF input data.
 * @param   labelLen [IN] Label length, any length.
 * @param   seed [IN] Seed, string input by the user, used as the input data of the PRF.
 * @param   seedLen [IN] Seed length, any length.
 * @param   out [OUT] Derive the key.
 * @param   len [IN] Derived key length. the value range is [1, 0xFFFFFFFF].
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_KdfTls12(CRYPT_MAC_AlgId id, const uint8_t *key, uint32_t keyLen, const uint8_t *label,
    uint32_t labelLen, const uint8_t *seed, uint32_t seedLen,  uint8_t *out, uint32_t len);

/**
 * @ingroup crypt_eal_kdf
 * @brief   Check whether the given HKDF algorithm ID is valid.
 *
 * @param   id [IN] HKDF algorithm ID.
 *
 * @retval  true, if valid.
 *          false, if invalid.
 */
bool CRYPT_EAL_HkdfIsValidAlgId(CRYPT_MAC_AlgId id);

/**
 * @ingroup crypt_eal_kdf
 * @brief   Check whether the given PBKDF2 algorithm ID is valid.
 *
 * @param   id [IN] PBKDF2 algorithm ID.
 *
 * @retval  true, if valid.
 *          false, if invalid.
 */
bool CRYPT_EAL_Pbkdf2IsValidAlgId(CRYPT_MAC_AlgId id);

/**
 * @ingroup crypt_eal_kdf
 * @brief   Check whether the given KDFTLS12 algorithm ID is a valid KDFTLS12 algorithm ID.
 *
 * @param   id [IN] KDFTLS12 algorithm ID
 *
 * @retval  true, if valid.
 *          false, if invalid.
 */
bool CRYPT_EAL_Kdftls12IsValidAlgId(CRYPT_MAC_AlgId id);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_KDF_H
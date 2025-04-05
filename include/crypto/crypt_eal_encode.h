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
 * @defgroup crypt_eal_encode
 * @ingroup crypt
 * @brief pubkey encode/decode of crypto module
 */

#ifndef CRYPT_EAL_ENCODE_H
#define CRYPT_EAL_ENCODE_H

#include <stdint.h>

#include "bsl_types.h"
#include "crypt_eal_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @ingroup crypt_eal_encode
 * @brief   Decode formatted buffer of pkey
 *
 * @param   format [IN] the buffer format.
 * @param   type [IN] the type of pkey.
 * @param   encode [IN] the encoded asn1 buffer.
 * @param   pwd [IN] the password, maybe NULL for unencrypted private key / public key.
 * @param   pwdlen [IN] the length of password.
 * @param   ealPKey [OUT] created CRYPT_EAL_PkeyCtx which parsed from the ans1 buffer.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_DecodeBuffKey(int32_t format, int32_t type,
    BSL_Buffer *encode, const uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPKey);

/**
 * @ingroup crypt_eal_encode
 * @brief   Decode formatted buffer of pkey with provider
 *
 * @param   libCtx [IN] the library context of provider.
 * @param   attrName [IN] provider attribute name, maybe NULL.
 * @param   format [IN] the buffer format.
 * @param   type [IN] the type of pkey.
 * @param   encode [IN] the encoded asn1 buffer.
 * @param   pwd [IN] the password buffer, maybe NULL for unencrypted private key / public key.
 * @param   ealPKey [OUT] created CRYPT_EAL_PkeyCtx which parsed from the ans1 buffer.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_ProviderDecodeBuffKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, int32_t format, int32_t type,
    BSL_Buffer *encode, const BSL_Buffer *pwd, CRYPT_EAL_PkeyCtx **ealPKey);

/**
 * @ingroup crypt_eal_encode
 * @brief   Decode formatted file of pkey
 *
 * @param   format [IN] the file format.
 * @param   type [IN] the type of pkey.
 * @param   path [IN] the encoded file path.
 * @param   pwd [IN] the password, maybe NULL for unencrypted private key / public key.
 * @param   pwdlen [IN] the length of password.
 * @param   ealPKey [OUT] created CRYPT_EAL_PkeyCtx which parsed from the path.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_DecodeFileKey(int32_t format, int32_t type, const char *path,
    uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPKey);

/**
 * @ingroup crypt_eal_encode
 * @brief   Decode formatted file of pkey with extended parameters
 *
 * @param   libCtx [IN] the library context of provider.
 * @param   attrName [IN] provider attribute name, maybe NULL.
 * @param   format [IN] the file format.
 * @param   type [IN] the type of pkey.
 * @param   path [IN] the encoded file path.
 * @param   pwd [IN] the password buffer, maybe NULL for unencrypted private key / public key.
 * @param   ealPKey [OUT] created CRYPT_EAL_PkeyCtx which parsed from the path.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_ProviderDecodeFileKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, int32_t format, int32_t type,
    const char *path, const BSL_Buffer *pwd, CRYPT_EAL_PkeyCtx **ealPKey);

/**
 * @ingroup crypt_eal_encode
 * @brief   Encode formatted buffer of pkey
 *
 * @param   ealPKey [IN] CRYPT_EAL_PkeyCtx to encode.
 * @param   encodeParam [IN] pkcs8 encode params.
 * @param   format [IN] the buffer format.
 * @param   type [IN] the type of pkey.
 * @param   encode [OUT] the encoded asn1 buffer.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_EncodeBuffKey(CRYPT_EAL_PkeyCtx *ealPKey, const CRYPT_EncodeParam *encodeParam,
    int32_t format, int32_t type, BSL_Buffer *encode);

/**
 * @ingroup crypt_eal_encode
 * @brief   Encode formatted buffer of pkey with provider
 *
 * @param   libCtx [IN] the library context of provider.
 * @param   attrName [IN] provider attribute name, maybe NULL.
 * @param   ealPKey [IN] CRYPT_EAL_PkeyCtx to encode.
 * @param   encodeParam [IN] pkcs8 encode params.
 * @param   format [IN] the buffer format.
 * @param   type [IN] the type of pkey.
 * @param   encode [OUT] the encoded asn1 buffer.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_ProviderEncodeBuffKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPKey,
    const CRYPT_EncodeParam *encodeParam, int32_t format, int32_t type, BSL_Buffer *encode);

/**
 * @ingroup crypt_eal_encode
 * @brief   Encode formatted file of pkey
 *
 * @param   ealPKey [IN] CRYPT_EAL_PkeyCtx to encode.
 * @param   encodeParam [IN] pkcs8 encode params.
 * @param   format [IN] the file format.
 * @param   type [IN] the type of pkey.
 * @param   path [IN] the encoded file path.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_EncodeFileKey(CRYPT_EAL_PkeyCtx *ealPKey, const CRYPT_EncodeParam *encodeParam,
    int32_t format, int32_t type, const char *path);

/**
 * @ingroup crypt_eal_encode
 * @brief   Encode formatted file of pkey with provider
 *
 * @param   libCtx [IN] the library context of provider.
 * @param   attrName [IN] provider attribute name, maybe NULL.
 * @param   ealPKey [IN] CRYPT_EAL_PkeyCtx to encode.
 * @param   encodeParam [IN] pkcs8 encode params.
 * @param   format [IN] the file format.
 * @param   type [IN] the type of pkey.
 * @param   path [IN] the encoded file path.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_ProviderEncodeFileKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx *ealPKey,
    const CRYPT_EncodeParam *encodeParam, int32_t format, int32_t type, const char *path);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_ENCODE_H
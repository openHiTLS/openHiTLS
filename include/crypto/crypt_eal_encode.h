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

#include "bsl_type.h"
#include "crypt_eal_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef enum {
    CRYPT_ENCODE_UNKNOW,
    CRYPT_PRIKEY_PKCS8_UNENCRYPT,
    CRYPT_PRIKEY_PKCS8_ENCRYPT,
    CRYPT_PRIKEY_RSA,
    CRYPT_PRIKEY_ECC,
    CRYPT_PUBKEY_SUBKEY,
    CRYPT_PUBKEY_RSA
} CRYPT_ENCODE_TYPE;

/**
 * @ingroup crypt_eal_encode
 * @brief   Parse formatted buffer of pubkey
 *
 * @param   format [IN] the buffer format.
 * @param   type [IN] the type of pubkey.
 * @param   encode [IN] the encoded asn1 buffer.
 * @param   ealPubKey [OUT] created CRYPT_EAL_PkeyCtx which parsed from the ans1 buffer.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_ParseBuffPubKey(BSL_ParseFormat format, int32_t type,
    BSL_Buffer *encode, CRYPT_EAL_PkeyCtx **ealPubKey);

/**
 * @ingroup crypt_eal_encode
 * @brief   Parse formatted file of pubkey
 *
 * @param   format [IN] the file format.
 * @param   type [IN] the type of pubkey.
 * @param   path [IN] the encoded file path.
 * @param   ealPubKey [OUT] created CRYPT_EAL_PkeyCtx which parsed from the path.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_ParseFilePubKey(BSL_ParseFormat format, int32_t type, const char *path,
    CRYPT_EAL_PkeyCtx **ealPubKey);

/**
 * @ingroup crypt_eal_encode
 * @brief   Parse formatted buffer of private-key
 *
 * @param   format [IN] the buffer format.
 * @param   type [IN] the type of private-key.
 * @param   encode [IN] the encoded asn1 buffer.
 * @param   pwd [IN] the password, maybe NULL for unencrypted private key.
 * @param   pwdlen [IN] the length of password.
 * @param   ealPriKey [OUT] created CRYPT_EAL_PkeyCtx which parsed from the ans1 buffer.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_ParseBuffPriKey(BSL_ParseFormat format, int32_t type,
    BSL_Buffer *encode, uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPriKey);

/**
 * @ingroup crypt_eal_encode
 * @brief   Parse formatted file of private-key
 *
 * @param   format [IN] the file format.
 * @param   type [IN] the type of private-key.
 * @param   path [IN] the encoded file path.
 * @param   pwd [IN] the password, maybe NULL for unencrypted private key.
 * @param   pwdlen [IN] the length of password.
 * @param   ealPriKey [OUT] created CRYPT_EAL_PkeyCtx which parsed from the path.
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
 */
int32_t CRYPT_EAL_ParseFilePriKey(BSL_ParseFormat format, int32_t type, const char *path,
    uint8_t *pwd, uint32_t pwdlen, CRYPT_EAL_PkeyCtx **ealPriKey);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_ENCODE_H
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

#ifndef AUTH_OTP_H
#define AUTH_OTP_H

#include <stdint.h>
#include "bsl_params.h"
#include "bsl_obj.h"
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup auth_otp
 *
 * otp context structure.
 */
typedef struct Otp_Ctx HITLS_AUTH_OtpCtx;

typedef enum {
    HITLS_AUTH_OTP_HOTP = 1,
    HITLS_AUTH_OTP_TOTP = 2,
} HITLS_AUTH_OtpType;

/* Commands for parameter operations and retrieval */
typedef enum {
    HITLS_AUTH_OTP_SET_CTX_DIGITS = 1, /** Set the digits of ctx */
    HITLS_AUTH_OTP_SET_CTX_HASHALGID = 2, /** Set the hash algorithm id of ctx */
    HITLS_AUTH_OTP_SET_CTX_TOTP_TIMESTEPSIZE = 3, /** Set the time step size of TOTP ctx */
    HITLS_AUTH_OTP_SET_CTX_TOTP_STARTOFFSET = 4, /** Set the start offset of TOTP ctx */
    HITLS_AUTH_OTP_SET_CTX_TOTP_VALIDWINDOW = 5, /** Set the valid window of TOTP ctx */
    HITLS_AUTH_OTP_GET_CTX_PROTOCOLTYPE = 6, /** Get the protocol type from ctx */
    HITLS_AUTH_OTP_GET_CTX_KEY = 7, /** Get the key from ctx */
    HITLS_AUTH_OTP_GET_CTX_DIGITS = 8, /** Get the digits from ctx */
    HITLS_AUTH_OTP_GET_CTX_HASHALGID = 9, /** Get the hash algorithm id from ctx */
    HITLS_AUTH_OTP_GET_CTX_TOTP_TIMESTEPSIZE = 10, /** Get the time step size from TOTP ctx */
    HITLS_AUTH_OTP_GET_CTX_TOTP_STARTOFFSET = 11, /** Get the start offset from TOTP ctx */
    HITLS_AUTH_OTP_GET_CTX_TOTP_VALIDWINDOW = 12, /** Get the valid window from TOTP ctx */
} HITLS_AUTH_OtpCmd;

/* HMAC hashing algorithm used in TOTP. */
typedef enum {
    HITLS_AUTH_OTP_CRYPTO_SHA1 = BSL_CID_HMAC_SHA1,
    HITLS_AUTH_OTP_CRYPTO_SHA256 = BSL_CID_HMAC_SHA256,
    HITLS_AUTH_OTP_CRYPTO_SHA512 = BSL_CID_HMAC_SHA512
} HITLS_AUTH_OtpCryptAlgId;

typedef enum {
    HITLS_AUTH_OTP_RANDOM_CB = 1,
    HITLS_AUTH_OTP_HMAC_CB = 2,
} HITLS_AUTH_OtpCryptCbType;

/**
 * @ingroup auth_otp
 * @brief   Compute HMAC of the key and input data.
 *
 * @param   libCtx [IN] Library context.
 * @param   attrName [IN] Specify expected attribute values.
 * @param   algId [IN] Algorithm identifier, defined in HITLS_AUTH_OtpCryptAlgId.
 * @param   key [IN] Key used in HMAC.
 * @param   keyLen [IN] Length of key.
 * @param   input [IN] Input data used in HMAC.
 * @param   inputLen [IN] Length of input data.
 * @param   digest [OUT] Buffer to store the computed hmac.
 * @param   digestLen [IN/OUT] Size of hmac buffer/Length of computed hmac.
 *
 * @retval  #0, if successful.
 *          other error codes, failed.
 */
typedef int32_t (*HITLS_AUTH_OtpHmac)(void *libCtx, const char *attrName, int32_t algId, const uint8_t *key,
                                      uint32_t keyLen, const uint8_t *input, uint32_t inputLen, uint8_t *hmac,
                                      uint32_t *hmacLen);

/**
 * @ingroup auth_otp
 * @brief   Generate random bytes.
 *
 * @param   buffer [IN] Buffer to store random bytes.
 * @param   bufferLen [IN] Length of buffer.
 *
 * @retval  #0, if successful.
 *          other error codes, failed.
 */
typedef int32_t (*HITLS_AUTH_OtpRandom)(uint8_t *buffer, uint32_t bufferLen);

/**
 * @ingroup auth_otp
 * @brief   Create a new OTP context object, all library callbacks by default are set when created.
 * @param   protocolType [IN] Type of protocol to use, defined in HITLS_AUTH_OtpType.
 *
 * @retval  HITLS_AUTH_OtpCtx pointer.
 *          NULL, if the operation fails.
 */
HITLS_AUTH_OtpCtx *HITLS_AUTH_OtpNewCtx(int32_t protocolType);

/**
 * @ingroup auth_otp
 * @brief   Create a new OTP context object with provider, all library callbacks by default are set when created.
 * @param   libCtx [IN] Library context
 * @param   protocolType [IN] Type of protocol to use, defined in HITLS_AUTH_OtpType.
 * @param   attrName [IN] Specify expected attribute values
 *
 * @retval  HITLS_AUTH_OtpCtx pointer.
 *          NULL, if the operation fails.
 */
HITLS_AUTH_OtpCtx *HITLS_AUTH_ProviderOtpNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t protocolType, const char *attrName);

/**
 * @ingroup auth_otp
 * @brief   Free a OTP context object.
 *
 * @param   ctx [IN] Context to be freed.
 */
void HITLS_AUTH_OtpFreeCtx(HITLS_AUTH_OtpCtx *ctx);

/**
 * @ingroup auth_otp
 * @brief   Set cryptographic callback functions for the context. When setting callbacks,
 *          the input callbacks will be checked. Non-NULL callbacks will override the default callbacks.
 *
 * @param   ctx [IN/OUT] Otp context.
 * @param   cbType [IN] Callback type, defined in HITLS_AUTH_OtpCryptCbType.
 * @param   cryptCb [IN] Callback functions to be set.
 *
 * @retval  #HITLS_AUTH_SUCCESS, if successful.
 *          For other error codes, see auth_errno.h.
 */
int32_t HITLS_AUTH_OtpSetCryptCb(HITLS_AUTH_OtpCtx *ctx, int32_t cbType, void *cryptCb);

/**
 * @ingroup auth_otp
 * @brief   Set or generate a random OTP key.
 *
 * @param   ctx [IN/OUT] Otp context.
 * @param   key [IN] Key/Secret used in OTP.
 * @param   keyLen [IN] Length of key.
 *
 * @retval  #HITLS_AUTH_SUCCESS, if successful.
 *          For other error codes, see auth_errno.h.
 */
int32_t HITLS_AUTH_OtpInit(HITLS_AUTH_OtpCtx *ctx, uint8_t *key, uint32_t keyLen);

/**
 * @ingroup auth_otp
 * @brief   Generate an OTP.
 *
 * @param   ctx [IN] Otp context.
 * @param   params [IN] Params use in generate.
 * @param   otp [OUT] Buffer to store the OTP.
 * @param   otpLen [IN/OUT] Size of OTP buffer/Length of generated OTP.
 *
 * @retval  #HITLS_AUTH_SUCCESS, if successful.
 *          For other error codes, see auth_errno.h.
 */
int32_t HITLS_AUTH_OtpGen(HITLS_AUTH_OtpCtx *ctx, const BSL_Param *param, char *otp, uint32_t *otpLen);

/**
 * @ingroup auth_otp
 * @brief   Validate the OTP.
 *
 * @param   ctx [IN] Otp context.
 * @param   params [IN] Params used in validate.
 * @param   otp [IN] OTP to validate.
 * @param   otpLen [IN] Length of OTP.
 * @param   matched [OUT] The moving factor (counter/time step) where the match was found, only valid when the
 *          validation is successful. This is useful for scenarios such as when a TOTP value should only be used
 *          once. This parameter can be NULL if you don't care about it.
 *
 * @retval  #HITLS_AUTH_SUCCESS, if successful.
 *          For other error codes, see auth_errno.h.
 */
int32_t HITLS_AUTH_OtpValidate(HITLS_AUTH_OtpCtx *ctx, const BSL_Param *param, const char *otp, const uint32_t otpLen,
                               uint64_t *matched);

/**
 * @ingroup auth_otp
 * @brief   Control interface for getting/setting various parameters in OTP Ctx.
 *
 * @param   ctx [IN] Otp context.
 * @param   cmd [IN] Command to execute, defined in HITLS_AUTH_OtpCmd.
 * @param   param [IN/OUT] Command parameters.
 * @param   paramLen [IN] Length of parameters.
 *
 * @retval  #HITLS_AUTH_SUCCESS, if successful.
 *          For other error codes, see auth_errno.h.
 */
int32_t HITLS_AUTH_OtpCtxCtrl(HITLS_AUTH_OtpCtx *ctx, int32_t cmd, void *param, uint32_t paramLen);

#ifdef __cplusplus
}
#endif

#endif // AUTH_OTP_H
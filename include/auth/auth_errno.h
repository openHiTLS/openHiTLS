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

#ifndef AUTH_ERRNO_H
#define AUTH_ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HITLS_AUTH_SUCCESS = 0,                           /* Operation completed successfully */

    HITLS_AUTH_PRIVPASS_INVALID_INPUT = 0x05010001,        /* Invalid input parameters */
    HITLS_AUTH_PRIVPASS_INVALID_CMD,                       /* Invalid command */
    HITLS_AUTH_PRIVPASS_INVALID_ALG,                       /* Invalid algorithm specified */
    HITLS_AUTH_PRIVPASS_INVALID_TOEKN_PROTOCOL_TYPE,       /* Invalid protocol type */
    HITLS_AUTH_PRIVPASS_INVALID_TOKEN_TYPE,                /* Invalid token type */
    HITLS_AUTH_PRIVPASS_BUFFER_NOT_ENOUGH,                 /* Buffer size is insufficient */
    HITLS_AUTH_PRIVPASS_INVALID_CRYPTO_METHOD,             /* Invalid cryptographic method */
    HITLS_AUTH_PRIVPASS_INVALID_CRYPTO_CALLBACK_TYPE,      /* Invalid cryptographic callback type */
    HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE_PARAM,     /* Invalid token challenge param */
    HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE,           /* Invalid token challenge */
    HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE_REQ,       /* Invalid token challenge request */
    HITLS_AUTH_PRIVPASS_NO_TOKEN_CHALLENGE_TYPE,           /* Token challenge type is missing */
    HITLS_AUTH_PRIVPASS_NO_TOKEN_CHALLENGE_ISSUERNAME,     /* Token challenge issuer name is missing */
    HITLS_AUTH_PRIVPASS_NO_TOKEN_CHALLENGE_REDEMPTION,     /* Token challenge redemption context is missing */
    HITLS_AUTH_PRIVPASS_INVALID_ISSUER_NAME,               /* Invalid issuer name */
    HITLS_AUTH_PRIVPASS_INVALID_REDEMPTION,                /* Invalid redemption */
    HITLS_AUTH_PRIVPASS_INVALID_ORIGIN_INFO,               /* Invalid origin info */
    HITLS_AUTH_PRIVPASS_NO_TOKEN_CHALLENGE_REQUEST,        /* Token challenge request is missing */
    HITLS_AUTH_PRIVPASS_NO_PUBKEY_INFO,                    /* Public key information is missing */
    HITLS_AUTH_PRIVPASS_NO_PRVKEY_INFO,                    /* Private key information is missing */
    HITLS_AUTH_PRIVPASS_NO_KEYPAIR_CHECK_CALLBACK,         /* Key pair check callback is not set */
    HITLS_AUTH_PRIVPASS_INVALID_TOKEN_REQUEST,             /* Invalid token request */
    HITLS_AUTH_PRIVPASS_INVALID_TOKEN_RESPONSE,            /* Invalid token response */
    HITLS_AUTH_PRIVPASS_INVALID_TOKEN_INSTANCE,            /* Invalid token instance */
    HITLS_AUTH_PRIVPASS_INVALID_TOKEN_KEYID,               /* Invalid token key id */
    HITLS_AUTH_PRIVPASS_INVALID_TOKEN_BLINDED_MSG,         /* Invalid blinded message in token */
    HITLS_AUTH_PRIVPASS_INVALID_TOKEN_CHALLENGE_DIGEST,    /* Invalid token challenge digest */
    HITLS_AUTH_PRIVPASS_CHECK_KEYPAIR_FAILED,              /* Key pair verification failed */
    HITLS_AUTH_PRIVPASS_INVALID_PUBKEY_TYPE,          /* Invalid pubkey type, now only support rsa */
    HITLS_AUTH_PRIVPASS_INVALID_PUBKEY_PADDING_INFO,  /* Invalid pubkey padding info, now only support rsa-pss */
    HITLS_AUTH_PRIVPASS_INVALID_PUBKEY_PADDING_MD,    /* Invalid pubkey padding md, now only support rsa-pss-sha384 */
    HITLS_AUTH_PRIVPASS_INVALID_PUBKEY_BITS,               /* Invalid pubkey bits, now only support rsa-2048 */
    HITLS_AUTH_PRIVPASS_INVALID_PRVKEY_TYPE,               /* Invalid prikey type, now only support rsa */
    HITLS_AUTH_PRIVPASS_INVALID_PRVKEY_BITS,               /* Invalid prikey bits, now only support rsa-2048 */
    HITLS_AUTH_PRIVPASS_NO_ISSUERNAME,                     /* No issuer name in token challenge */
    HITLS_AUTH_PRIVPASS_NO_RESPONSE_INFO,                  /* No response info in token response */
    HITLS_AUTH_PRIVPASS_NO_BLINDEDMSG,                     /* No blinded message in token request */
    HITLS_AUTH_PRIVPASS_NO_AUTHENTICATOR,                  /* No authenticator in token */

    HITLS_AUTH_OTP_INVALID_INPUT = 0x05020001,             /* Invalid input parameters */
    HITLS_AUTH_OTP_INVALID_PROTOCOL_TYPE,                  /* Invalid protocol type */
    HITLS_AUTH_OTP_INVALID_CMD,                            /* Invalid command */
    HITLS_AUTH_OTP_INVALID_CRYPTO_CALLBACK_TYPE,           /* Invalid cryptographic callback type */
    HITLS_AUTH_OTP_BUFFER_NOT_ENOUGH,                      /* Buffer size is insufficient */
    HITLS_AUTH_OTP_NO_COUNTER,                             /* Counter is missing */
    HITLS_AUTH_OTP_NO_CURTIME,                             /* Current time is missing */
    HITLS_AUTH_OTP_VALIDATE_MISMATCH,                      /* The otp to validate does not match target value. */
} HITLS_AUTH_ERRNO;

#ifdef __cplusplus
}
#endif

#endif // AUTH_ERRNO_H
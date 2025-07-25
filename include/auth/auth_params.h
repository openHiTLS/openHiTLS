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

#ifndef AUTH_PARAMS_H
#define AUTH_PARAMS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Base value for Private Pass Token parameters */
#define AUTH_PARAM_PRIVPASS_TOKEN                     20000
#define AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REQUEST                       (AUTH_PARAM_PRIVPASS_TOKEN + 1)
#define AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_TYPE                          (AUTH_PARAM_PRIVPASS_TOKEN + 2)
#define AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ISSUERNAME                    (AUTH_PARAM_PRIVPASS_TOKEN + 3)
#define AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_REDEMPTION                    (AUTH_PARAM_PRIVPASS_TOKEN + 4)
#define AUTH_PARAM_PRIVPASS_TOKENCHALLENGE_ORIGININFO                    (AUTH_PARAM_PRIVPASS_TOKEN + 5)
#define AUTH_PARAM_PRIVPASS_TOKENREQUEST_TYPE                            (AUTH_PARAM_PRIVPASS_TOKEN + 6)
#define AUTH_PARAM_PRIVPASS_TOKENREQUEST_TRUNCATEDTOKENKEYID             (AUTH_PARAM_PRIVPASS_TOKEN + 7)
#define AUTH_PARAM_PRIVPASS_TOKENREQUEST_BLINDEDMSG                      (AUTH_PARAM_PRIVPASS_TOKEN + 9)
#define AUTH_PARAM_PRIVPASS_TOKENRESPONSE_INFO                           (AUTH_PARAM_PRIVPASS_TOKEN + 10)
#define AUTH_PARAM_PRIVPASS_TOKEN_TYPE                                   (AUTH_PARAM_PRIVPASS_TOKEN + 11)
#define AUTH_PARAM_PRIVPASS_TOKEN_NONCE                                  (AUTH_PARAM_PRIVPASS_TOKEN + 12)
#define AUTH_PARAM_PRIVPASS_TOKEN_CHALLENGEDIGEST                        (AUTH_PARAM_PRIVPASS_TOKEN + 13)
#define AUTH_PARAM_PRIVPASS_TOKEN_TOKENKEYID                             (AUTH_PARAM_PRIVPASS_TOKEN + 14)
#define AUTH_PARAM_PRIVPASS_TOKEN_AUTHENTICATOR                          (AUTH_PARAM_PRIVPASS_TOKEN + 15)
#define AUTH_PARAM_PRIVPASS_CTX_TOKENKEYID                               (AUTH_PARAM_PRIVPASS_TOKEN + 16)
#define AUTH_PARAM_PRIVPASS_CTX_TRUNCATEDTOKENKEYID                      (AUTH_PARAM_PRIVPASS_TOKEN + 17)
#define AUTH_PARAM_PRIVPASS_CTX_NONCE                                    (AUTH_PARAM_PRIVPASS_TOKEN + 18)

/* Base value for One Time Password parameters */
#define AUTH_PARAM_OTP                       20100
#define AUTH_PARAM_OTP_HOTP_COUNTER          (AUTH_PARAM_OTP + 1)
#define AUTH_PARAM_OTP_TOTP_CURTIME          (AUTH_PARAM_OTP + 2)
#define AUTH_PARAM_OTP_CTX_PROTOCOLTYPE      (AUTH_PARAM_OTP + 3)
#define AUTH_PARAM_OTP_CTX_KEY               (AUTH_PARAM_OTP + 4)
#define AUTH_PARAM_OTP_CTX_DIGITS            (AUTH_PARAM_OTP + 5)
#define AUTH_PARAM_OTP_CTX_HASHALGID         (AUTH_PARAM_OTP + 6)
#define AUTH_PARAM_OTP_CTX_TOTP_TIMESTEPSIZE (AUTH_PARAM_OTP + 7)
#define AUTH_PARAM_OTP_CTX_TOTP_STARTOFFSET  (AUTH_PARAM_OTP + 8)
#define AUTH_PARAM_OTP_CTX_TOTP_VALIDWINDOW  (AUTH_PARAM_OTP + 9)

#ifdef __cplusplus
}
#endif

#endif

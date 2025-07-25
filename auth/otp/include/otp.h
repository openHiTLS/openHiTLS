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

#ifndef OTP_H
#define OTP_H

#include <stdint.h>
#include "bsl_sal.h"
#include "bsl_types.h"
#include "auth_params.h"
#include "auth_otp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OTP_DEFAULT_DIGITS              6
#define OTP_MIN_DIGITS                  6
#define OTP_MAX_DIGITS                  8
#define OTP_TOTP_DEFAULT_TIME_STEP_SIZE 30
#define OTP_TOTP_DEFAULT_START_OFFSET   0
#define OTP_TOTP_DEFAULT_VALID_WINDOW   1

typedef struct {
    HITLS_AUTH_OtpHmac hmac;
    HITLS_AUTH_OtpRandom random;
} OtpCryptCb;

typedef struct {
    uint32_t timeStepSize;
    BslUnixTime startOffset;
    uint32_t validWindow;
} TotpCtx;

/* Main context structure for OTP operations */
struct Otp_Ctx {
    CRYPT_EAL_LibCtx *libCtx; // Provider context
    const char *attrName; // Provider attribute name
    int32_t protocolType;
    BSL_Buffer key;
    uint32_t digits;
    int32_t hashAlgId;
    void *ctx; // Protocol-specific fields
    OtpCryptCb method; // Cryptographic callbacks
};

/**
 * @brief   Get the default cryptographic callback functions.
 * @retval  OtpCryptCb structure containing default callbacks.
 */
OtpCryptCb OtpCryptDefaultCb(void);

#ifdef __cplusplus
}
#endif

#endif // OTP_H
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

#include <stdint.h>
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "auth_errno.h"
#include "auth_params.h"
#include "auth_otp.h"
#include "crypt_errno.h"
#include "otp.h"

int32_t HITLS_AUTH_OtpInit(HITLS_AUTH_OtpCtx *ctx, uint8_t *key, uint32_t keyLen)
{
    if (ctx == NULL || keyLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
        return HITLS_AUTH_OTP_INVALID_INPUT;
    }

    if (ctx->key.data != NULL) {
        BSL_SAL_Free(ctx->key.data);
    }

    ctx->key.dataLen = keyLen;
    ctx->key.data = (uint8_t *)BSL_SAL_Malloc(ctx->key.dataLen);
    if (ctx->key.data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    if (key == NULL) {
        int32_t ret = ctx->method.random(ctx->key.data, ctx->key.dataLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_Free(ctx->key.data);
            ctx->key.data = NULL;
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } else {
        (void)memcpy_s(ctx->key.data, ctx->key.dataLen, key, keyLen);
    }

    return HITLS_AUTH_SUCCESS;
}

typedef enum {
    OTP_HMAC_SHA1SIZE = 20,
    OTP_HMAC_SHA256SIZE = 32,
    OTP_HMAC_SHA512SIZE = 64,
} OTP_HmacSize;

int32_t GenericOtpGen(HITLS_AUTH_OtpCtx *ctx, uint64_t movingFactor, char *otp, uint32_t *otpLen)
{
    // Put movingFactor value into byte array
    uint8_t counter[sizeof(movingFactor)];
    for (uint32_t i = 0; i < sizeof(movingFactor); i++) {
        counter[sizeof(movingFactor) - 1 - i] = (movingFactor >> (8 * i)) & 0xFF; // 8: the number of bits in a byte.
    }

    // Compute HMAC hash
    uint8_t hmac[OTP_HMAC_SHA512SIZE];
    uint32_t hmacLen;
    switch (ctx->hashAlgId) {
        case HITLS_AUTH_OTP_CRYPTO_SHA1:
            hmacLen = OTP_HMAC_SHA1SIZE;
            break;
        case HITLS_AUTH_OTP_CRYPTO_SHA256:
            hmacLen = OTP_HMAC_SHA256SIZE;
            break;
        case HITLS_AUTH_OTP_CRYPTO_SHA512:
            hmacLen = OTP_HMAC_SHA512SIZE;
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
            return HITLS_AUTH_OTP_INVALID_INPUT;
    }
    uint32_t ret = ctx->method.hmac(ctx->libCtx, ctx->attrName, ctx->hashAlgId, ctx->key.data, ctx->key.dataLen,
                                    (uint8_t *)&counter, sizeof(counter), hmac, &hmacLen);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Dynamic truncation
    uint8_t offset = hmac[hmacLen - 1] & 0x0F;
    uint32_t binOtp = BSL_ByteToUint32(&hmac[offset]) & 0x7FFFFFFF;

    // Stringify
    for (uint32_t i = 0, div = 10, mod = 1; i < ctx->digits; i++, div *= 10, mod *= 10) { // 10: decimal number
        otp[ctx->digits - i - 1] = '0' + binOtp % div / mod;
    }

    *otpLen = ctx->digits;
    return HITLS_AUTH_SUCCESS;
}

int32_t HotpGen(HITLS_AUTH_OtpCtx *ctx, const BSL_Param *param, char *otp, uint32_t *otpLen, uint64_t *movingFactorOut)
{
    uint64_t movingFactor = 0;
    uint32_t movingFactorLen = (uint32_t)sizeof(movingFactor);
    const BSL_Param *tmpParam = BSL_PARAM_FindConstParam(param, AUTH_PARAM_OTP_HOTP_COUNTER);
    if (tmpParam == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_NO_COUNTER);
        return HITLS_AUTH_OTP_NO_COUNTER;
    }
    int32_t ret = BSL_PARAM_GetValue(tmpParam, AUTH_PARAM_OTP_HOTP_COUNTER, BSL_PARAM_TYPE_OCTETS, &movingFactor,
                                     &movingFactorLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (movingFactorOut != NULL) {
        *movingFactorOut = movingFactor;
    }

    return GenericOtpGen(ctx, movingFactor, otp, otpLen);
}

int32_t TotpGen(HITLS_AUTH_OtpCtx *ctx, const BSL_Param *param, const int32_t offset, char *otp, uint32_t *otpLen,
                uint64_t *movingFactorOut)
{
    uint64_t curTime = 0;
    uint32_t curTimeLen = (uint32_t)sizeof(curTime);
    const BSL_Param *tmpParam = BSL_PARAM_FindConstParam(param, AUTH_PARAM_OTP_TOTP_CURTIME);
    if (tmpParam == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_NO_CURTIME);
        return HITLS_AUTH_OTP_NO_CURTIME;
    }
    int32_t ret =
        BSL_PARAM_GetValue(tmpParam, AUTH_PARAM_OTP_TOTP_CURTIME, BSL_PARAM_TYPE_OCTETS, &curTime, &curTimeLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    TotpCtx *totpCtx = (TotpCtx *)ctx->ctx;
    uint64_t movingFactor = ((curTime - totpCtx->startOffset) / totpCtx->timeStepSize) + offset;

    if (movingFactorOut != NULL) {
        *movingFactorOut = movingFactor;
    }

    return GenericOtpGen(ctx, movingFactor, otp, otpLen);
}

int32_t HITLS_AUTH_OtpGen(HITLS_AUTH_OtpCtx *ctx, const BSL_Param *param, char *otp, uint32_t *otpLen)
{
    if (ctx == NULL || ctx->key.data == NULL || param == NULL || otp == NULL || otpLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
        return HITLS_AUTH_OTP_INVALID_INPUT;
    }

    if (*otpLen < ctx->digits) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
        return HITLS_AUTH_OTP_INVALID_INPUT;
    }

    switch (ctx->protocolType) {
        case HITLS_AUTH_OTP_HOTP:
            return HotpGen(ctx, param, otp, otpLen, NULL);
        case HITLS_AUTH_OTP_TOTP:
            return TotpGen(ctx, param, 0, otp, otpLen, NULL);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_PROTOCOL_TYPE);
            return HITLS_AUTH_OTP_INVALID_PROTOCOL_TYPE;
    }
}

int32_t HotpValidate(HITLS_AUTH_OtpCtx *ctx, const BSL_Param *param, const char *otp, const uint32_t otpLen,
                     uint64_t *matched)
{
    char targetOtp[OTP_MAX_DIGITS + 1] = {0};
    uint32_t targetOtpLen = sizeof(targetOtp);
    uint64_t movingFactor;
    int32_t ret = HotpGen(ctx, param, targetOtp, &targetOtpLen, &movingFactor);
    if (ret != HITLS_AUTH_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (strncmp(otp, targetOtp, otpLen) != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_VALIDATE_MISMATCH);
        return HITLS_AUTH_OTP_VALIDATE_MISMATCH;
    }

    if (matched != NULL) {
        *matched = movingFactor;
    }
    return HITLS_AUTH_SUCCESS;
}

int32_t TotpValidate(HITLS_AUTH_OtpCtx *ctx, const BSL_Param *param, const char *otp, const uint32_t otpLen,
                     uint64_t *matched)
{
    int32_t ret;
    char targetOtp[OTP_MAX_DIGITS + 1] = {0};
    uint32_t targetOtpLen = sizeof(targetOtp);
    uint32_t validWindow = ((TotpCtx *)ctx->ctx)->validWindow;
    uint64_t movingFactor;

    for (int64_t offset = -(int64_t)validWindow; offset < (int64_t)validWindow + 1; offset++) {
        ret = TotpGen(ctx, param, offset, targetOtp, &targetOtpLen, &movingFactor);
        if (ret != HITLS_AUTH_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        if (strncmp(otp, targetOtp, otpLen) == 0) {
            if (matched != NULL) {
                *matched = movingFactor;
            }
            return HITLS_AUTH_SUCCESS;
        }
    }

    BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_VALIDATE_MISMATCH);
    return HITLS_AUTH_OTP_VALIDATE_MISMATCH;
}

int32_t HITLS_AUTH_OtpValidate(HITLS_AUTH_OtpCtx *ctx, const BSL_Param *param, const char *otp, const uint32_t otpLen,
                               uint64_t *matched)
{
    if (ctx == NULL || ctx->key.data == NULL || param == NULL || otp == NULL || otpLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
        return HITLS_AUTH_OTP_INVALID_INPUT;
    }

    if (otpLen != ctx->digits) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_VALIDATE_MISMATCH);
        return HITLS_AUTH_OTP_VALIDATE_MISMATCH;
    }

    switch (ctx->protocolType) {
        case HITLS_AUTH_OTP_HOTP:
            return HotpValidate(ctx, param, otp, otpLen, matched);
        case HITLS_AUTH_OTP_TOTP:
            return TotpValidate(ctx, param, otp, otpLen, matched);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_PROTOCOL_TYPE);
            return HITLS_AUTH_OTP_INVALID_PROTOCOL_TYPE;
    }
}
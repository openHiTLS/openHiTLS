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

#include "auth_errno.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "auth_otp.h"
#include "otp.h"
#include "bsl_sal.h"

int32_t OtpHmac(void *libCtx, const char *attrName, int32_t algId, const uint8_t *key, uint32_t keyLen,
                const uint8_t *input, uint32_t inputLen, uint8_t *digest, uint32_t *digestLen)
{
    (void)libCtx;
    (void)attrName;
    if (key == NULL || keyLen == 0 || input == NULL || inputLen == 0 || digest == NULL || digestLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
        return HITLS_AUTH_OTP_INVALID_INPUT;
    }

    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    uint32_t hmacSize = CRYPT_EAL_GetMacLen(ctx);
    if (hmacSize == 0 || *digestLen < hmacSize) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
        CRYPT_EAL_MacFreeCtx(ctx);
        return HITLS_AUTH_OTP_INVALID_INPUT;
    }

    int32_t ret = CRYPT_EAL_MacInit(ctx, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_MacFreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_EAL_MacUpdate(ctx, input, inputLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_MacFreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_EAL_MacFinal(ctx, digest, digestLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_EAL_MacFreeCtx(ctx);
        return ret;
    }

    CRYPT_EAL_MacFreeCtx(ctx);
    return CRYPT_SUCCESS;
}

int32_t OtpRandom(uint8_t *buffer, uint32_t bufferLen)
{
    if (buffer == NULL || bufferLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
        return HITLS_AUTH_OTP_INVALID_INPUT;
    }
    return CRYPT_EAL_RandbytesEx(NULL, buffer, bufferLen);
}

OtpCryptCb OtpCryptDefaultCb(void)
{
    OtpCryptCb method = {
        .hmac = OtpHmac,
        .random = OtpRandom,
    };
    return method;
}
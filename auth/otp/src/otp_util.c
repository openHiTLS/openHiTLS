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
#include "auth_errno.h"
#include "auth_otp.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "otp.h"

int32_t OtpSetCtxContent(HITLS_AUTH_OtpCtx *ctx, int32_t cmd, void *param)
{
    int32_t ret;
    uint32_t valueLen;
    BSL_Param *input;
    switch (cmd) {
        case HITLS_AUTH_OTP_SET_CTX_DIGITS:
            input = BSL_PARAM_FindParam(param, AUTH_PARAM_OTP_CTX_DIGITS);
            if (input == NULL || input->valueType != BSL_PARAM_TYPE_UINT32) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            uint32_t digits;
            valueLen = sizeof(digits);
            ret = BSL_PARAM_GetValue(input, AUTH_PARAM_OTP_CTX_DIGITS, BSL_PARAM_TYPE_UINT32, &digits, &valueLen);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
            if (digits < OTP_MIN_DIGITS || digits > OTP_MAX_DIGITS) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            ctx->digits = digits;
            return HITLS_AUTH_SUCCESS;
        case HITLS_AUTH_OTP_SET_CTX_HASHALGID:
            input = BSL_PARAM_FindParam(param, AUTH_PARAM_OTP_CTX_HASHALGID);
            if (input == NULL || input->valueType != BSL_PARAM_TYPE_OCTETS) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            int32_t hashAlgId;
            valueLen = sizeof(hashAlgId);
            ret = BSL_PARAM_GetValue(input, AUTH_PARAM_OTP_CTX_HASHALGID, BSL_PARAM_TYPE_OCTETS, &hashAlgId, &valueLen);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
            if (hashAlgId != HITLS_AUTH_OTP_CRYPTO_SHA1 && hashAlgId != HITLS_AUTH_OTP_CRYPTO_SHA256 &&
                hashAlgId != HITLS_AUTH_OTP_CRYPTO_SHA512) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            ctx->hashAlgId = hashAlgId;
            return HITLS_AUTH_SUCCESS;
        case HITLS_AUTH_OTP_SET_CTX_TOTP_TIMESTEPSIZE:
            input = BSL_PARAM_FindParam(param, AUTH_PARAM_OTP_CTX_TOTP_TIMESTEPSIZE);
            if (input == NULL || input->valueType != BSL_PARAM_TYPE_UINT32) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            uint32_t timeStepSize;
            valueLen = sizeof(timeStepSize);
            ret = BSL_PARAM_GetValue(input, AUTH_PARAM_OTP_CTX_TOTP_TIMESTEPSIZE, BSL_PARAM_TYPE_UINT32, &timeStepSize,
                                     &valueLen);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
            if (timeStepSize == 0) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            ((TotpCtx *)(ctx->ctx))->timeStepSize = timeStepSize;
            return HITLS_AUTH_SUCCESS;
        case HITLS_AUTH_OTP_SET_CTX_TOTP_STARTOFFSET:
            input = BSL_PARAM_FindParam(param, AUTH_PARAM_OTP_CTX_TOTP_STARTOFFSET);
            if (input == NULL || input->valueType != BSL_PARAM_TYPE_OCTETS) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            valueLen = sizeof(((TotpCtx *)(ctx->ctx))->startOffset);
            return BSL_PARAM_GetValue(input, AUTH_PARAM_OTP_CTX_TOTP_STARTOFFSET, BSL_PARAM_TYPE_OCTETS,
                                      &((TotpCtx *)(ctx->ctx))->startOffset, &valueLen);
        case HITLS_AUTH_OTP_SET_CTX_TOTP_VALIDWINDOW:
            input = BSL_PARAM_FindParam(param, AUTH_PARAM_OTP_CTX_TOTP_VALIDWINDOW);
            if (input == NULL || input->valueType != BSL_PARAM_TYPE_UINT32) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            valueLen = sizeof(((TotpCtx *)(ctx->ctx))->validWindow);
            return BSL_PARAM_GetValue(input, AUTH_PARAM_OTP_CTX_TOTP_VALIDWINDOW, BSL_PARAM_TYPE_UINT32,
                                      &((TotpCtx *)(ctx->ctx))->validWindow, &valueLen);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_CMD);
            return HITLS_AUTH_OTP_INVALID_CMD;
    }
}

static int32_t OtpGetCtxContent(HITLS_AUTH_OtpCtx *ctx, int32_t cmd, void *param)
{
    BSL_Param *output;
    switch (cmd) {
        case HITLS_AUTH_OTP_GET_CTX_PROTOCOLTYPE:
            output = BSL_PARAM_FindParam(param, AUTH_PARAM_OTP_CTX_PROTOCOLTYPE);
            if (output == NULL || output->valueType != BSL_PARAM_TYPE_OCTETS) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            return BSL_PARAM_SetValue(output, AUTH_PARAM_OTP_CTX_PROTOCOLTYPE, BSL_PARAM_TYPE_OCTETS,
                                      &ctx->protocolType, sizeof(ctx->protocolType));
        case HITLS_AUTH_OTP_GET_CTX_KEY:
            output = BSL_PARAM_FindParam(param, AUTH_PARAM_OTP_CTX_KEY);
            if (output == NULL || output->valueType != BSL_PARAM_TYPE_OCTETS_PTR) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            if (output->valueLen < ctx->key.dataLen) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_BUFFER_NOT_ENOUGH);
                return HITLS_AUTH_OTP_BUFFER_NOT_ENOUGH;
            }
            (void)memcpy_s(output->value, output->valueLen, ctx->key.data, ctx->key.dataLen);
            output->useLen = ctx->key.dataLen;
            return HITLS_AUTH_SUCCESS;
        case HITLS_AUTH_OTP_GET_CTX_DIGITS:
            output = BSL_PARAM_FindParam(param, AUTH_PARAM_OTP_CTX_DIGITS);
            if (output == NULL || output->valueType != BSL_PARAM_TYPE_UINT32) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            return BSL_PARAM_SetValue(output, AUTH_PARAM_OTP_CTX_DIGITS, BSL_PARAM_TYPE_UINT32, &ctx->digits,
                                      sizeof(ctx->digits));
        case HITLS_AUTH_OTP_GET_CTX_HASHALGID:
            output = BSL_PARAM_FindParam(param, AUTH_PARAM_OTP_CTX_HASHALGID);
            if (output == NULL || output->valueType != BSL_PARAM_TYPE_OCTETS) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            return BSL_PARAM_SetValue(output, AUTH_PARAM_OTP_CTX_HASHALGID, BSL_PARAM_TYPE_OCTETS, &ctx->hashAlgId,
                                      sizeof(ctx->hashAlgId));
        case HITLS_AUTH_OTP_GET_CTX_TOTP_TIMESTEPSIZE:
            output = BSL_PARAM_FindParam(param, AUTH_PARAM_OTP_CTX_TOTP_TIMESTEPSIZE);
            if (output == NULL || output->valueType != BSL_PARAM_TYPE_UINT32) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            return BSL_PARAM_SetValue(output, AUTH_PARAM_OTP_CTX_TOTP_TIMESTEPSIZE, BSL_PARAM_TYPE_UINT32,
                                      &((TotpCtx *)(ctx->ctx))->timeStepSize,
                                      sizeof(((TotpCtx *)(ctx->ctx))->timeStepSize));
        case HITLS_AUTH_OTP_GET_CTX_TOTP_STARTOFFSET:
            output = BSL_PARAM_FindParam(param, AUTH_PARAM_OTP_CTX_TOTP_STARTOFFSET);
            if (output == NULL || output->valueType != BSL_PARAM_TYPE_OCTETS) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            return BSL_PARAM_SetValue(output, AUTH_PARAM_OTP_CTX_TOTP_STARTOFFSET, BSL_PARAM_TYPE_OCTETS,
                                      &((TotpCtx *)(ctx->ctx))->startOffset,
                                      sizeof(((TotpCtx *)(ctx->ctx))->startOffset));
        case HITLS_AUTH_OTP_GET_CTX_TOTP_VALIDWINDOW:
            output = BSL_PARAM_FindParam(param, AUTH_PARAM_OTP_CTX_TOTP_VALIDWINDOW);
            if (output == NULL || output->valueType != BSL_PARAM_TYPE_UINT32) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            return BSL_PARAM_SetValue(output, AUTH_PARAM_OTP_CTX_TOTP_VALIDWINDOW, BSL_PARAM_TYPE_UINT32,
                                      &((TotpCtx *)(ctx->ctx))->validWindow,
                                      sizeof(((TotpCtx *)(ctx->ctx))->validWindow));
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_CMD);
            return HITLS_AUTH_OTP_INVALID_CMD;
    }
}

int32_t HITLS_AUTH_OtpCtxCtrl(HITLS_AUTH_OtpCtx *ctx, int32_t cmd, void *param, uint32_t paramLen)
{
    (void)paramLen;
    switch (cmd) {
        case HITLS_AUTH_OTP_SET_CTX_DIGITS:
        case HITLS_AUTH_OTP_SET_CTX_HASHALGID:
            return OtpSetCtxContent(ctx, cmd, param);
        case HITLS_AUTH_OTP_SET_CTX_TOTP_TIMESTEPSIZE:
        case HITLS_AUTH_OTP_SET_CTX_TOTP_STARTOFFSET:
        case HITLS_AUTH_OTP_SET_CTX_TOTP_VALIDWINDOW:
            if (ctx->protocolType != HITLS_AUTH_OTP_TOTP) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            return OtpSetCtxContent(ctx, cmd, param);
        case HITLS_AUTH_OTP_GET_CTX_PROTOCOLTYPE:
        case HITLS_AUTH_OTP_GET_CTX_DIGITS:
        case HITLS_AUTH_OTP_GET_CTX_KEY:
        case HITLS_AUTH_OTP_GET_CTX_HASHALGID:
            return OtpGetCtxContent(ctx, cmd, param);
        case HITLS_AUTH_OTP_GET_CTX_TOTP_TIMESTEPSIZE:
        case HITLS_AUTH_OTP_GET_CTX_TOTP_STARTOFFSET:
        case HITLS_AUTH_OTP_GET_CTX_TOTP_VALIDWINDOW:
            if (ctx->protocolType != HITLS_AUTH_OTP_TOTP) {
                BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
                return HITLS_AUTH_OTP_INVALID_INPUT;
            }
            return OtpGetCtxContent(ctx, cmd, param);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_CMD);
            return HITLS_AUTH_OTP_INVALID_CMD;
    }
}

TotpCtx *OtpNewTotpCtx()
{
    TotpCtx *ctx = (TotpCtx *)BSL_SAL_Calloc(1u, sizeof(TotpCtx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->timeStepSize = OTP_TOTP_DEFAULT_TIME_STEP_SIZE;
    ctx->startOffset = OTP_TOTP_DEFAULT_START_OFFSET;
    ctx->validWindow = OTP_TOTP_DEFAULT_VALID_WINDOW;
    return ctx;
}

HITLS_AUTH_OtpCtx *HITLS_AUTH_OtpNewCtx(int32_t protocolType) {
    return HITLS_AUTH_ProviderOtpNewCtx(NULL, protocolType, NULL);
}

HITLS_AUTH_OtpCtx *HITLS_AUTH_ProviderOtpNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t protocolType, const char *attrName)
{
    if (protocolType != HITLS_AUTH_OTP_HOTP && protocolType != HITLS_AUTH_OTP_TOTP) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_PROTOCOL_TYPE);
        return NULL;
    }

    HITLS_AUTH_OtpCtx *ctx = (HITLS_AUTH_OtpCtx *)BSL_SAL_Calloc(1u, sizeof(HITLS_AUTH_OtpCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    ctx->libCtx = libCtx;
    ctx->attrName = attrName;
    ctx->protocolType = protocolType;
    ctx->digits = OTP_DEFAULT_DIGITS;
    switch (protocolType) {
        case HITLS_AUTH_OTP_HOTP:
        case HITLS_AUTH_OTP_TOTP:
            ctx->hashAlgId = HITLS_AUTH_OTP_CRYPTO_SHA1;
            break;
        default:
            break;
    }
    switch (protocolType) {
        case HITLS_AUTH_OTP_TOTP: {
            TotpCtx *totpCtx = OtpNewTotpCtx();
            if (totpCtx == NULL) {
                BSL_SAL_Free(ctx);
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                return NULL;
            }
            ctx->ctx = (void *)totpCtx;
            break;
        }
        case HITLS_AUTH_OTP_HOTP:
        default:
            break;
    }
    ctx->method = OtpCryptDefaultCb();
    return ctx;
}

void OtpFreeTotpCtx(TotpCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    BSL_SAL_Free(ctx);
}

void HITLS_AUTH_OtpFreeCtx(HITLS_AUTH_OtpCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    BSL_SAL_ClearFree((void *)ctx->key.data, ctx->key.dataLen);

    switch (ctx->protocolType) {
        case HITLS_AUTH_OTP_TOTP:
            OtpFreeTotpCtx(ctx->ctx);
            break;
        case HITLS_AUTH_OTP_HOTP:
        default:
            break;
    }

    BSL_SAL_Free(ctx);
}

int32_t HITLS_AUTH_OtpSetCryptCb(HITLS_AUTH_OtpCtx *ctx, int32_t cbType, void *cryptCb)
{
    if (ctx == NULL || cryptCb == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_INPUT);
        return HITLS_AUTH_OTP_INVALID_INPUT;
    }
    switch (cbType) {
        case HITLS_AUTH_OTP_RANDOM_CB:
            ctx->method.random = (HITLS_AUTH_OtpRandom)cryptCb;
            break;
        case HITLS_AUTH_OTP_HMAC_CB:
            ctx->method.hmac = (HITLS_AUTH_OtpHmac)cryptCb;
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_AUTH_OTP_INVALID_CRYPTO_CALLBACK_TYPE);
            return HITLS_AUTH_OTP_INVALID_CRYPTO_CALLBACK_TYPE;
    }
    return HITLS_AUTH_SUCCESS;
}
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

#include "hitls_build.h"
#ifdef HITLS_BSL_BASE64
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_base64_internal.h"
#include "bsl_base64.h"

/* BASE64 mapping table */
static const uint8_t BASE64_DECODE_MAP_TABLE[] = {
    67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 64U, 67U, 67U, 64U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U,
    67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 64U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 62U, 67U, 66U,
    67U, 63U, 52U, 53U, 54U, 55U, 56U, 57U, 58U, 59U, 60U, 61U, 67U, 67U, 67U, 65U, 67U, 67U, 67U, 0U,  1U,  2U,  3U,
    4U,  5U,  6U,  7U,  8U,  9U,  10U, 11U, 12U, 13U, 14U, 15U, 16U, 17U, 18U, 19U, 20U, 21U, 22U, 23U, 24U, 25U, 67U,
    67U, 67U, 67U, 67U, 67U, 26U, 27U, 28U, 29U, 30U, 31U, 32U, 33U, 34U, 35U, 36U, 37U, 38U, 39U, 40U, 41U, 42U, 43U,
    44U, 45U, 46U, 47U, 48U, 49U, 50U, 51U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U,
    67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U,
    67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U,
    67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U,
    67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U,
    67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U, 67U,
    67U, 67U, 67U};


BSL_Base64Ctx *BSL_BASE64_CtxNew(void)
{
    return BSL_SAL_Malloc(sizeof(BSL_Base64Ctx));
}

void BSL_BASE64_CtxFree(BSL_Base64Ctx *ctx)
{
    BSL_SAL_FREE(ctx);
}

void BSL_BASE64_CtxClear(BSL_Base64Ctx *ctx)
{
    BSL_SAL_CleanseData(ctx, (uint32_t)sizeof(BSL_Base64Ctx));
}

static int32_t BslBase64EncodeParamsValidate(const uint8_t *srcBuf, const uint32_t srcBufLen,
    const char *dstBuf, uint32_t *dstBufLen)
{
    if (srcBuf == NULL || srcBufLen == 0U || dstBuf == NULL || dstBufLen == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    /* The length of dstBuf of the user must be at least (srcBufLen+2)/3*4+1 */
    if (*dstBufLen < BSL_BASE64_ENC_ENOUGH_LEN(srcBufLen)) {
        BSL_ERR_PUSH_ERROR(BSL_BASE64_BUF_NOT_ENOUGH);
        return BSL_BASE64_BUF_NOT_ENOUGH;
    }

    return BSL_SUCCESS;
}

static void BslBase64ArithEncodeProc(const uint8_t *srcBuf, const uint32_t srcBufLen,
    char *dstBuf, uint32_t *dstBufLen)
{
    /* base64-encoding mapping table */
    static const char *base64Letter = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint32_t dstIdx = 0U;
    const uint8_t *tmpBuf = srcBuf;
    uint32_t tmpLen;

    /* @alias Encode characters based on the BASE64 encoding rule. */
    for (tmpLen = srcBufLen; tmpLen > 2U; tmpLen -= 3U) {
        dstBuf[dstIdx] = base64Letter[(tmpBuf[0] >> 2U) & 0x3FU];
        dstIdx++;
        dstBuf[dstIdx] = base64Letter[((tmpBuf[0] & 0x3U) << 4U) | ((tmpBuf[1U] & 0xF0U) >> 4U)];
        dstIdx++;
        dstBuf[dstIdx] = base64Letter[((tmpBuf[1U] & 0x0FU) << 2U) | ((tmpBuf[2U] & 0xC0U) >> 6U)];
        dstIdx++;
        dstBuf[dstIdx] = base64Letter[tmpBuf[2U] & 0x3FU];
        dstIdx++;
        tmpBuf = &tmpBuf[3U];
    }

    /* Handle the case where the remaining length is not 0. */
    if (tmpLen > 0U) {
        /* Padded the first byte. */
        dstBuf[dstIdx] = base64Letter[(tmpBuf[0] >> 2U) & 0x3FU];
        dstIdx++;
        if (tmpLen == 1U) {
            /* Process the case where the remaining length is 1. */
            dstBuf[dstIdx] = base64Letter[((tmpBuf[0U] & 0x3U) << 4U)];
            dstIdx++;
            dstBuf[dstIdx] = '=';
            dstIdx++;
        } else {
            /* Process the case where the remaining length is 2. */
            dstBuf[dstIdx] = base64Letter[((tmpBuf[0U] & 0x3U) << 4U) | ((tmpBuf[1U] & 0xF0U) >> 4U)];
            dstIdx++;
            dstBuf[dstIdx] = base64Letter[((tmpBuf[1U] & 0x0Fu) << 2U)];
            dstIdx++;
        }
        /* Fill the last '='. */
        dstBuf[dstIdx++] = '=';
    }
    /* Fill terminator. */
    dstBuf[dstIdx] = '\0';
    *dstBufLen = dstIdx;
}

/* Encode the entire ctx->buf, 48 characters in total, and return the number of decoded characters. */
static void BslBase64EncodeBlock(BSL_Base64Ctx *ctx, const uint8_t **srcBuf, uint32_t *srcBufLen,
    char **dstBuf, uint32_t *dstBufLen, uint32_t remainLen)
{
    uint32_t tmpOutLen = 0;
    uint32_t offset = 0;

    BslBase64ArithEncodeProc(*srcBuf, ctx->length, *dstBuf, &tmpOutLen);

    ctx->num = 0;

    offset = ((remainLen == 0) ? (ctx->length) : remainLen);
    *srcBuf += offset;
    *srcBufLen -= offset;
    *dstBufLen += tmpOutLen;
    *dstBuf += tmpOutLen;

    if ((ctx->flags & BSL_BASE64_FLAGS_NO_NEWLINE) == 0) {
        *(*dstBuf) = '\n';
        (*dstBuf)++;
        (*dstBufLen)++;
    }
    *(*dstBuf) = '\0';
}

static void BslBase64EncodeProcess(BSL_Base64Ctx *ctx, const uint8_t **srcBuf, uint32_t *srcBufLen,
    char *dstBuf, uint32_t *dstBufLen)
{
    uint32_t remainLen = 0;
    const uint8_t *bufTmp = &(ctx->buf[0]);
    char *dstBufTmp = dstBuf;

    if (ctx->num != 0) {
        remainLen = ctx->length - ctx->num;
        (void)memcpy_s(&(ctx->buf[ctx->num]), remainLen, *srcBuf, remainLen);
        BslBase64EncodeBlock(ctx, &bufTmp, srcBufLen, &dstBufTmp, dstBufLen, remainLen);
        *srcBuf += remainLen;
        remainLen = 0;
    }

    const uint8_t *srcBufTmp = *srcBuf;
    /* Encoding every 48 characters. */
    while (*srcBufLen >= ctx->length) {
        BslBase64EncodeBlock(ctx, &srcBufTmp, srcBufLen, &dstBufTmp, dstBufLen, remainLen);
    }
    *srcBuf = srcBufTmp;
}

static int32_t BslBase64DecodeCheck(const char src, uint32_t *paddingCnt)
{
    uint32_t padding = 0;
    /* 66U is the header identifier '-' (invalid), and 66U or above are invalid characters beyond the range. */
    if (BASE64_DECODE_MAP_TABLE[(uint8_t)src] == 66U) {
        BSL_ERR_PUSH_ERROR(BSL_BASE64_HEADER);
        return BSL_BASE64_HEADER;
    }
    if (BASE64_DECODE_MAP_TABLE[(uint8_t)src] > 66U) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    /* 65U is the padding character '=' and also EOF identifier. */
    if (BASE64_DECODE_MAP_TABLE[(uint8_t)src] == 65U) {
        if (*paddingCnt < BASE64_PAD_MAX) {
            padding++;
        } else { /* paddingCnt > 2 */
            BSL_ERR_PUSH_ERROR(BSL_BASE64_INVALID);
            return BSL_BASE64_INVALID;
        }
    }
    /* illegal behavior: data after padding. */
    if (*paddingCnt > 0 && BASE64_DECODE_MAP_TABLE[(uint8_t)src] < 64U) {
        BSL_ERR_PUSH_ERROR(BSL_BASE64_DATA_AFTER_PADDING);
        return BSL_BASE64_DATA_AFTER_PADDING;
    }

    *paddingCnt += padding;
    return BSL_SUCCESS;
}

int32_t BSL_BASE64_Encode(const uint8_t *srcBuf, const uint32_t srcBufLen, char *dstBuf, uint32_t *dstBufLen)
{
    int32_t ret = BslBase64EncodeParamsValidate(srcBuf, srcBufLen, (const char *)dstBuf, dstBufLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    BslBase64ArithEncodeProc(srcBuf, srcBufLen, dstBuf, dstBufLen); /* executes the encoding algorithm */

    return BSL_SUCCESS;
}

static void BslBase64DecodeRemoveBlank(const uint8_t *buf, const uint32_t bufLen, uint8_t *destBuf, uint32_t *destLen)
{
    uint32_t fast = 0;
    uint32_t slow = 0;
    for (; fast < bufLen; fast++) {
        if (BASE64_DECODE_MAP_TABLE[buf[fast]] != 64U) { /* when the character is not ' ' or '\r', '\n' */
            destBuf[slow++] = buf[fast];
        }
    }
    *destLen = slow;
}

static int32_t BslBase64DecodeCheckAndRmvEqualSign(uint8_t *buf, uint32_t *bufLen)
{
    int32_t ret = BSL_SUCCESS;
    uint32_t i = 0;
    bool hasEqualSign = false;
    uint32_t len = *bufLen;
    for (; i < len; i++) {
        /* Check whether the characters are invalid characters in the Base64 mapping table. */
        if (BASE64_DECODE_MAP_TABLE[buf[i]] > 65U) {
            /* 66U is the status code of invalid characters. */
            return BSL_BASE64_INVALID_CHARACTER;
        }
        /* Process the '=' */
        if (BASE64_DECODE_MAP_TABLE[buf[i]] == 65U) {
            hasEqualSign = true;
            /* 65U is the status code with the '=' */
            if (i == len - 1) {
                break;
            } else if (i == len - BASE64_PAD_MAX) {
                ret = (buf[i + 1] == '=') ? BSL_SUCCESS : BSL_BASE64_INVALID_CHARACTER;
                buf[i + 1] = '\0';
                break;
            } else {
                return BSL_BASE64_INVALID_CHARACTER;
            }
        }
    }
    if (ret == BSL_SUCCESS) {
        if (hasEqualSign == true) {
            buf[i] = '\0';
        }
        *bufLen = i;
    }
    return ret;
}

static int32_t BslBase64Normalization(const char *srcBuf, const uint32_t srcBufLen, uint8_t *filterBuf,
    uint32_t *filterBufLen)
{
    (void)memset_s(filterBuf, *filterBufLen, 0, *filterBufLen);
    BslBase64DecodeRemoveBlank((const uint8_t *)srcBuf, srcBufLen, filterBuf, filterBufLen);
    if (*filterBufLen == 0 || ((*filterBufLen) % BASE64_DECODE_BYTES != 0)) {
        return BSL_BASE64_INVALID_ENCODE;
    }
    return BslBase64DecodeCheckAndRmvEqualSign(filterBuf, filterBufLen);
}

/* can ensure that dstBuf and dstBufLen are sufficient and that srcBuf does not contain invalid characters */
static int32_t BslBase64DecodeBuffer(const uint8_t *srcBuf, const uint32_t srcBufLen, uint8_t *dstBuf,
    uint32_t *dstBufLen)
{
    uint32_t idx = 0U;
    uint32_t tmpLen;
    const uint8_t *tmp = srcBuf;

    for (tmpLen = srcBufLen; tmpLen > 4U; tmpLen -= 4U) {
        dstBuf[idx] = (BASE64_DECODE_MAP_TABLE[tmp[0U]] << 2U) | (BASE64_DECODE_MAP_TABLE[tmp[1U]] >> 4U);
        idx++;
        dstBuf[idx] = (BASE64_DECODE_MAP_TABLE[tmp[1U]] << 4U) | (BASE64_DECODE_MAP_TABLE[tmp[2U]] >> 2U);
        idx++;
        dstBuf[idx] = (BASE64_DECODE_MAP_TABLE[tmp[2U]] << 6U) | BASE64_DECODE_MAP_TABLE[tmp[3U]];
        idx++;
        tmp = &tmp[4U];
    }

    /* processing of less than four characters */
    if (tmpLen > 1U) {
        /* process the case of one character */
        dstBuf[idx] = (BASE64_DECODE_MAP_TABLE[tmp[0U]] << 2U) | (BASE64_DECODE_MAP_TABLE[tmp[1U]] >> 4U);
        idx++;
    }

    if (tmpLen > 2U) {
        /* process the case of two characters */
        dstBuf[idx] = (BASE64_DECODE_MAP_TABLE[tmp[1U]] << 4U) | (BASE64_DECODE_MAP_TABLE[tmp[2U]] >> 2U);
        idx++;
    }

    if (tmpLen > 3U) {
        /* process the case of three characters */
        dstBuf[idx] = (BASE64_DECODE_MAP_TABLE[tmp[2U]] << 6U) | BASE64_DECODE_MAP_TABLE[tmp[3U]];
        idx++;
    }
    *dstBufLen = idx;
    return BSL_SUCCESS;
}

static int32_t BslBase64ArithDecodeProc(const char *srcBuf, const uint32_t srcBufLen, uint8_t *dstBuf,
    uint32_t *dstBufLen)
{
    uint8_t *buf = NULL;
    uint32_t bufLen; /* length to be decoded after redundant characters are deleted */
    int32_t ret;

    buf = BSL_SAL_Malloc((uint32_t)srcBufLen);
    if (buf == NULL) {
        return BSL_MALLOC_FAIL;
    }
    bufLen = srcBufLen;
    /* Delete the extra white space characters (\r\n, space, '=') */
    ret = BslBase64Normalization(srcBuf, srcBufLen, buf, &bufLen);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(buf);
        return ret;
    }

    /* Decode the base64 character string. */
    ret = BslBase64DecodeBuffer(buf, (const uint32_t)bufLen, dstBuf, dstBufLen);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(buf);
        return ret;
    }

    BSL_SAL_FREE(buf);
    return BSL_SUCCESS;
}

/* Ensure that dstBuf and dstBufLen are correctly created. */
int32_t BSL_BASE64_Decode(const char *srcBuf, const uint32_t srcBufLen, uint8_t *dstBuf, uint32_t *dstBufLen)
{
    int32_t ret;

    /* An error is returned when a parameter is abnormal. */
    if (srcBuf == NULL || dstBuf == NULL || dstBufLen == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    /* The length of dstBuf of the user must be at least (srcBufLen+3)/4*3. */
    if (*dstBufLen < BSL_BASE64_DEC_ENOUGH_LEN(srcBufLen)) {
        BSL_ERR_PUSH_ERROR(BSL_BASE64_BUF_NOT_ENOUGH);
        return BSL_BASE64_BUF_NOT_ENOUGH;
    }

    ret = BslBase64ArithDecodeProc(srcBuf, srcBufLen, dstBuf, dstBufLen);  /* start decoding */
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

int32_t BSL_BASE64_EncodeInit(BSL_Base64Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    ctx->length = HITLS_BASE64_CTX_LENGTH;
    ctx->num = 0;
    ctx->flags = 0;
    return BSL_SUCCESS;
}

int32_t BSL_BASE64_EncodeUpdate(BSL_Base64Ctx *ctx, const uint8_t *srcBuf, uint32_t srcBufLen,
    char *dstBuf, uint32_t *dstBufLen)
{
    /* ensure the validity of dstBuf */
    if (ctx == NULL || srcBuf == NULL || dstBuf == NULL || srcBufLen == 0 || dstBufLen == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (ctx->length != HITLS_BASE64_CTX_LENGTH) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    /* By default, the user selects the line feed, considers the terminator,
       and checks whether the length meets the (srcBufLen + ctx->num)/48*65+1 requirement. */
    if (*dstBufLen < ((srcBufLen + ctx->num) / HITLS_BASE64_CTX_LENGTH * (BASE64_DECODE_BLOCKSIZE + 1) + 1)) {
        BSL_ERR_PUSH_ERROR(BSL_BASE64_BUF_NOT_ENOUGH);
        return BSL_BASE64_BUF_NOT_ENOUGH;
    }

    *dstBufLen = 0;

    /* If srcBuf is too short for a buf, store it in the buf first. */
    if (srcBufLen < ctx->length - ctx->num) {
        (void)memcpy_s(&(ctx->buf[ctx->num]), srcBufLen, srcBuf, srcBufLen);
        ctx->num += srcBufLen;
        return BSL_SUCCESS;
    }

    BslBase64EncodeProcess(ctx, &srcBuf, &srcBufLen, dstBuf, dstBufLen);

    /* If the remaining bytes are less than 48 bytes, store the bytes in the buf and wait for next processing. */
    if (srcBufLen != 0) {
        /* Ensure that srcBufLen < 48 */
        (void)memcpy_s(&(ctx->buf[0]), srcBufLen, srcBuf, srcBufLen);
    }
    ctx->num = srcBufLen;
    return BSL_SUCCESS;
}

int32_t BSL_BASE64_EncodeFinal(BSL_Base64Ctx *ctx, char *dstBuf, uint32_t *dstBufLen)
{
    uint32_t tmpDstLen = 0;
    if (ctx == NULL || dstBuf == NULL || dstBufLen == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (ctx->num == 0) {
        *dstBufLen = 0;
        return BSL_SUCCESS;
    }

    if (*dstBufLen < BSL_BASE64_ENC_ENOUGH_LEN((ctx->num))) {
        BSL_ERR_PUSH_ERROR(BSL_BASE64_BUF_NOT_ENOUGH);
        return BSL_BASE64_BUF_NOT_ENOUGH;
    }

    BslBase64ArithEncodeProc((const uint8_t *)ctx->buf, ctx->num, dstBuf, &tmpDstLen);
    if ((ctx->flags & BSL_BASE64_FLAGS_NO_NEWLINE) == 0) {
        dstBuf[tmpDstLen++] = '\n';
    }
    dstBuf[tmpDstLen] = '\0';
    *dstBufLen = tmpDstLen;
    ctx->num = 0;
    return BSL_SUCCESS;
}

int32_t BSL_BASE64_DecodeInit(BSL_Base64Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    ctx->num = 0;
    ctx->length = 0;
    ctx->flags = 0;
    ctx->paddingCnt = 0;
    return BSL_SUCCESS;
}

int32_t BSL_BASE64_DecodeUpdate(BSL_Base64Ctx *ctx, const char *srcBuf, const uint32_t srcBufLen,
    uint8_t *dstBuf, uint32_t *dstBufLen)
{
    if (ctx == NULL || srcBuf == NULL || dstBuf == NULL || srcBufLen == 0 || dstBufLen == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    /* Estimated maximum value. By default, the input srcBuf is without line feed. Each line contains 64 characters.
       Check whether the length meets the (srcBufLen + ctx->num)/64*48 requirement. */
    if (*dstBufLen < ((srcBufLen + ctx->num) / BASE64_DECODE_BLOCKSIZE * HITLS_BASE64_CTX_LENGTH)) {
        BSL_ERR_PUSH_ERROR(BSL_BASE64_BUF_NOT_ENOUGH);
        return BSL_BASE64_BUF_NOT_ENOUGH;
    }

    uint32_t num = ctx->num;
    uint32_t totalLen = 0;
    uint32_t decodeLen = 0;
    uint8_t *tmpBuf = ctx->buf;
    int32_t ret = BSL_SUCCESS;
    uint8_t *dstTmp = dstBuf;

    for (uint32_t i = 0U; i < srcBufLen; i++) {
        ret = BslBase64DecodeCheck(srcBuf[i], &ctx->paddingCnt);
        if (ret != BSL_SUCCESS) {
            *dstBufLen = 0;
            if (ret == BSL_BASE64_HEADER) {
                *dstBufLen = totalLen;
            }
            return ret;
        }

        if (BASE64_DECODE_MAP_TABLE[(uint8_t)srcBuf[i]] < 64U) { /* 0U ~ 63U are valid characters */
            /* If num >= 64, it indicates that someone has modified the ctx.
               If this happens, refuse to write any more data. */
            if (num >= BASE64_DECODE_BLOCKSIZE) {
                *dstBufLen = 0;
                ctx->num = num;
                BSL_ERR_PUSH_ERROR(BSL_BASE64_ILLEGALLY_MODIFIED);
                return BSL_BASE64_ILLEGALLY_MODIFIED;
            }
            tmpBuf[num++] = (uint8_t)srcBuf[i]; /* save valid base64 characters */
        }

        /* A round of block decoding is performed every time the num reaches 64, and then the buf is cleared. */
        if (num == BASE64_DECODE_BLOCKSIZE) {
            ret = BslBase64DecodeBuffer(tmpBuf, num, dstTmp, &decodeLen);
            if (ret != BSL_SUCCESS) {
                *dstBufLen = 0;
                ctx->num = 0;
                BSL_ERR_PUSH_ERROR(BSL_BASE64_DECODE_FAILED);
                return BSL_BASE64_DECODE_FAILED;
            }
            num = 0;
            totalLen += decodeLen;
            dstTmp += decodeLen;
        }
    }
    *dstBufLen = totalLen;
    ctx->num = num;
    return BSL_SUCCESS;
}

int32_t BSL_BASE64_DecodeFinal(BSL_Base64Ctx *ctx, uint8_t *dstBuf, uint32_t *dstBufLen)
{
    int32_t ret = BSL_SUCCESS;
    uint32_t totalLen = 0;

    if (ctx == NULL || dstBuf == NULL || dstBufLen == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    if (ctx->num == 0) {
        *dstBufLen = 0;
        return ret;
    }

    if (*dstBufLen < BSL_BASE64_DEC_ENOUGH_LEN((ctx->num))) {
        BSL_ERR_PUSH_ERROR(BSL_BASE64_BUF_NOT_ENOUGH);
        return BSL_BASE64_BUF_NOT_ENOUGH;
    }

    ret = BslBase64DecodeBuffer((const uint8_t *)ctx->buf, ctx->num, dstBuf, &totalLen);
    ctx->num = 0;
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_BASE64_DECODE_FAILED);
        return BSL_BASE64_DECODE_FAILED;
    }
    
    *dstBufLen = totalLen;
    return ret;
}

int32_t BSL_BASE64_SetFlags(BSL_Base64Ctx *ctx, uint32_t flags)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    ctx->flags |= flags;
    return BSL_SUCCESS;
}

int32_t BSL_Base64GetNum(BSL_Base64Ctx *ctx, uint32_t *num)
{
    if (ctx == NULL || num == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    *num = ctx->num;
    return BSL_SUCCESS;
}
#endif /* HITLS_BSL_BASE64 */

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
#ifdef HITLS_BSL_UIO_BASE64

#include <stdlib.h>
#include <stdbool.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "bsl_uio.h"
#include "uio_abstraction.h"
#include "bsl_base64_internal.h"
#include "bsl_base64.h"

#define UIO_BASE64_ENC_ENOUGH_LEN(len) ((((len) + 2) / 3 * 4) + 1)

typedef struct {
    /* Fast pointer to the part that is encoded/decoded but not read/written in the context in the buf. */
    uint32_t bufLen;
    /* Slow pointer to the read/written to the next-UIO in the buf. */
    uint32_t bufUsed;
    /* used to find the start when decoding */
    uint32_t tmpLen;
    int encode;
    /* == 0 indicates that the UIO read is complete */
    int isContinue;
    bool inPemBlock;
    /* buf stores the encoded/decoded part. The length is calculated based on the encoding length. (sufficient space) */
    uint8_t buf[BASE64_CTX_BUF_SIZE];
    /* tmp saves the part that is read and written but not encoded or decoded */
    uint8_t tmp[BASE64_BLOCK_SIZE];
    BSL_Base64Ctx *base64Ctx;
} Base64Ctx;

typedef enum {
    BASE64_NONE,
    BASE64_ENCODE,
    BASE64_DECODE
} Base64Mode;

static void Base64WriteInit(BSL_UIO *uio, Base64Ctx *ctx)
{
    (void)BSL_UIO_ClearFlags(uio, (BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY));

    if (ctx->encode != BASE64_ENCODE) {
        ctx->encode = BASE64_ENCODE;
        ctx->bufLen = 0;
        ctx->bufUsed = 0;
        ctx->tmpLen = 0;
        (void)BSL_BASE64_EncodeInit(ctx->base64Ctx);
    }
    
    if ((uio->flags & BSL_UIO_FLAGS_BASE64_NO_NEWLINE) != 0) {
        (void)BSL_BASE64_SetFlags(ctx->base64Ctx, BSL_BASE64_FLAGS_NO_NEWLINE);
    }
}

static void Base64ReadInit(BSL_UIO *uio, Base64Ctx *ctx)
{
    (void)BSL_UIO_ClearFlags(uio, (BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY));

    if (ctx->encode != BASE64_DECODE) {
        ctx->encode = BASE64_DECODE;
        ctx->bufLen = 0;
        ctx->bufUsed = 0;
        ctx->tmpLen = 0;
        ctx->inPemBlock = false;
        (void)BSL_BASE64_DecodeInit(ctx->base64Ctx);
    }

    if ((uio->flags & BSL_UIO_FLAGS_BASE64_NO_NEWLINE) != 0) {
        (void)BSL_BASE64_SetFlags(ctx->base64Ctx, BSL_BASE64_FLAGS_NO_NEWLINE);
    }
}

/**
 * The write function calls Base64WriteRefreshBuf for the first time
 * to process the characters that are not written to 'next' in time in ctx->buf.
 * And this function is invoked in the loop body and the last time.
 * ctx->bufLen indicates the length of the encoding after the entire block(1024) or tail of buf is processed at a time.
 * The encoding result is placed to the next-UIO in the loop.
 */
static int32_t Base64WriteRefreshBuf(BSL_UIO *uio, BSL_UIO *next, Base64Ctx *ctx)
{
    int32_t ret = BSL_SUCCESS;

    uint32_t len = ctx->bufLen - ctx->bufUsed;
    uint32_t wLen = 0;
    while (len > 0) {
        ret = BSL_UIO_Write(next, &(ctx->buf[ctx->bufUsed]), len, &wLen);
        if (ret != BSL_SUCCESS || wLen == 0) {
            (void)BSL_UIO_SetFlagsFromNext(uio);
            return ret;
        }
        len -= wLen;
        ctx->bufUsed += wLen;
    }
    ctx->bufUsed = 0;
    ctx->bufLen = 0;
    return ret;
}

static int32_t Base64Create(BSL_UIO *uio)
{
    Base64Ctx *ctx = NULL;
    if ((ctx = BSL_SAL_Calloc(1, sizeof(*ctx))) == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ctx->isContinue = 1;
    ctx->inPemBlock = false;
    ctx->base64Ctx = BSL_BASE64_CtxNew();
    if (ctx->base64Ctx == NULL) {
        BSL_SAL_FREE(ctx);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    uio->ctx = ctx;
    uio->init = true;
    return BSL_SUCCESS;
}

static int32_t Base64Destroy(BSL_UIO *uio)
{
    if (uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    Base64Ctx *ctx = uio->ctx;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    uio->ctx = NULL;
    BSL_BASE64_CtxFree(ctx->base64Ctx);
    BSL_SAL_FREE(ctx);
    uio->init = false;
    return BSL_SUCCESS;
}

static int32_t Base64Write(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    int32_t ret = BSL_SUCCESS;
    *writeLen = 0;
    uint32_t wLen = 0;
    const uint8_t *tmpbuf = (const uint8_t *)buf;
    uint32_t tmpLen = len;
    Base64Ctx *ctx = (Base64Ctx *)uio->ctx;
    BSL_UIO *next = BSL_UIO_Next(uio);
    if (ctx == NULL || next == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    Base64WriteInit(uio, ctx);
    /* Prevent context from being tampered with */
    if (ctx->bufUsed > ctx->bufLen || ctx->bufLen > (uint32_t)sizeof(ctx->buf)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    ret = Base64WriteRefreshBuf(uio, next, ctx); /* In this case, all data to be processed is written. */
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    while (tmpLen > 0) {
        uint32_t n = (tmpLen > BASE64_BLOCK_SIZE) ? BASE64_BLOCK_SIZE : tmpLen;

        ctx->bufLen = HITLS_BASE64_ENCODE_LENGTH(n);
        ret = (int32_t)BSL_BASE64_EncodeUpdate(ctx->base64Ctx, tmpbuf, n, (char *)ctx->buf, &ctx->bufLen);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        wLen += n;
        tmpbuf = tmpbuf + n;
        tmpLen -= n;

        ret = Base64WriteRefreshBuf(uio, next, ctx);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    *writeLen = wLen;
    return ret;
}

static int32_t Base64ReadRefreshBuf(Base64Ctx *ctx, uint8_t **buf, uint32_t *len, uint32_t *rLen)
{
    if (ctx->bufLen == 0) {
        return BSL_SUCCESS;
    }
    if (ctx->bufLen < ctx->bufUsed) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    uint32_t dif = ((ctx->bufLen - ctx->bufUsed > (*len)) ? (*len) : (ctx->bufLen - ctx->bufUsed));
    if (ctx->bufUsed + dif > BASE64_CTX_BUF_SIZE) {
        BSL_ERR_PUSH_ERROR(BSL_BASE64_BUF_NOT_ENOUGH);
        return BSL_BASE64_BUF_NOT_ENOUGH;
    }
    (void)memcpy_s(*buf, *len, &(ctx->buf[ctx->bufUsed]), dif);
    *buf += dif;
    *len -= dif;

    *rLen += dif;
    ctx->bufUsed += dif;
    if (ctx->bufLen == ctx->bufUsed) {
        ctx->bufLen = 0;
        ctx->bufUsed = 0;
    }
    return BSL_SUCCESS;
}

static int32_t Base64ReadTmp(BSL_UIO *uio, BSL_UIO *next, Base64Ctx *ctx, uint32_t *rLen)
{
    int32_t ret = BSL_SUCCESS;
    ret = BSL_UIO_Read(next, &(ctx->tmp[ctx->tmpLen]), BASE64_BLOCK_SIZE - ctx->tmpLen, rLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (*rLen == 0) {
        /* Read/Write retry is set, waiting for the user to continue the next read operation. */
        if ((next->flags & BSL_UIO_FLAGS_SHOULD_RETRY) != 0) {
            (void)BSL_UIO_SetFlagsFromNext(uio);
            return BSL_SUCCESS; /* Read and write retry should return success */
        }
        /* When the length obtained by the read operation of next UIO is 0 and ctx->tmpLen != 0,
           it indicates that the to-be-read UIO is completely read,
           and the following loop operation will be performed. */
        ctx->isContinue = 0;
    }
    *rLen += ctx->tmpLen;
    ctx->tmpLen = *rLen;
    return ret;
}

#define PEM_BEGIN_PREFIX "-----BEGIN"
#define PEM_END_PREFIX "-----END"

static bool IsPemBeginLine(const uint8_t *line, uint32_t lineLen)
{
    uint32_t beginLen = (uint32_t)strlen(PEM_BEGIN_PREFIX);

    return lineLen >= beginLen && memcmp(line, PEM_BEGIN_PREFIX, beginLen) == 0;
}

static bool IsPemEndLine(const uint8_t *line, uint32_t lineLen)
{
    uint32_t endLen = (uint32_t)strlen(PEM_END_PREFIX);

    return lineLen >= endLen && memcmp(line, PEM_END_PREFIX, endLen) == 0;
}

static int32_t Base64ReadPemEnd(Base64Ctx *ctx, uint32_t *total)
{
    uint32_t num = 0;
    int32_t ret = BSL_SUCCESS;

    num = (uint32_t)(sizeof(ctx->buf) - *total);
    ret = (int32_t)BSL_BASE64_DecodeFinal(ctx->base64Ctx, ctx->buf + *total, &num);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_BASE64_DECODE_FAILED);
        return BSL_BASE64_DECODE_FAILED;
    }
    *total += num;

    ctx->inPemBlock = false;
    return BSL_SUCCESS;
}

static int32_t Base64ReadPem(Base64Ctx *ctx, uint32_t *rLen)
{
    uint8_t *lineStart = ctx->tmp;
    uint8_t *p = ctx->tmp;
    uint8_t *end = ctx->tmp + *rLen;
    uint32_t total = 0;
    uint32_t num = 0;
    int32_t ret = BSL_SUCCESS;

    while (p < end) {
        if (*p++ != '\n') {
            continue;
        }

        uint32_t lineLen = (uint32_t)(p - lineStart);

        if (IsPemBeginLine(lineStart, lineLen)) {
            ctx->inPemBlock = true;
            (void)BSL_BASE64_DecodeInit(ctx->base64Ctx);
            lineStart = p;
            continue;
        }

        if (IsPemEndLine(lineStart, lineLen)) {
            ret = Base64ReadPemEnd(ctx, &total);
            if (ret != BSL_SUCCESS) {
                return ret;
            }

            lineStart = p;
            continue;
        }

        if (ctx->inPemBlock) {
            num = HITLS_BASE64_DECODE_LENGTH((uint32_t)(p - lineStart));
            ret = (int32_t)BSL_BASE64_DecodeUpdate(ctx->base64Ctx, (const char *)lineStart,
                (uint32_t)(p - lineStart), ctx->buf + total, &num);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(BSL_BASE64_DECODE_FAILED);
                return BSL_BASE64_DECODE_FAILED;
            }
            total += num;
        }

        lineStart = p;
    }

    uint32_t remain = (uint32_t)(end - lineStart);
    if (remain > 0) {
        (void)memmove_s(ctx->tmp, sizeof(ctx->tmp), lineStart, remain);
    }
    ctx->tmpLen = remain;

    *rLen = total;
    return ret;
}

static int32_t Base64ReadProcess(BSL_UIO *uio, Base64Ctx *ctx, uint32_t *rLen)
{
    int32_t ret = BSL_SUCCESS;

    /* When reading a PEM file, user shoule set the flag with a line feed and set the pem flag. */
    if (((uio->flags & BSL_UIO_FLAGS_BASE64_NO_NEWLINE) == 0) && (uio->flags & BSL_UIO_FLAGS_BASE64_PEM) != 0) {
        ret = Base64ReadPem(ctx, rLen);
        return ret;
    }

    uint32_t tmpRLen = HITLS_BASE64_DECODE_LENGTH(*rLen);
    ret = (int32_t)BSL_BASE64_DecodeUpdate(ctx->base64Ctx, (const char *)ctx->tmp, (*rLen), ctx->buf, &tmpRLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_BASE64_DECODE_FAILED);
        return BSL_BASE64_DECODE_FAILED;
    }

    ctx->tmpLen = 0;
    *rLen = tmpRLen; /* Set rLen to the actual length of the decoding output parameter. */
    return ret;
}

static int32_t Base64ReadFinal(Base64Ctx *ctx, uint8_t **buf, uint32_t *len, uint32_t *total)
{
    uint32_t rLen = HITLS_BASE64_DECODE_LENGTH(BASE64_DECODE_BLOCKSIZE);
    int32_t ret = (int32_t)BSL_BASE64_DecodeFinal(ctx->base64Ctx, ctx->buf, &rLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_BASE64_DECODE_FAILED);
        return BSL_BASE64_DECODE_FAILED;
    }

    ctx->bufLen += rLen;
    return Base64ReadRefreshBuf(ctx, buf, len, total);
}

static int32_t Base64Read(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    int32_t ret = BSL_SUCCESS;
    uint32_t rLen = 0;
    uint32_t total = 0;
    uint8_t *bufTmp = (uint8_t *)buf;
    Base64Ctx *ctx = (Base64Ctx *)uio->ctx;
    BSL_UIO *next = BSL_UIO_Next(uio);
    if (ctx == NULL || next == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    bool isPem = (((uio->flags & BSL_UIO_FLAGS_BASE64_NO_NEWLINE) == 0) &&
        ((uio->flags & BSL_UIO_FLAGS_BASE64_PEM) != 0));

    Base64ReadInit(uio, ctx);

    ret = Base64ReadRefreshBuf(ctx, &bufTmp, &len, &total); /* Process remaining data of ctx->buf */
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    /* If 0 characters are read, stop reading. The value of len may not be 0,
       because if the buf is too short, the data may be stored in tmp and decoded in final. */
    while (len > 0 && ctx->isContinue > 0) {
        rLen = 0;
        ret = Base64ReadTmp(uio, next, ctx, &rLen);
        /* ctx->tmpLen == 0: does not read anything, or the tmp has been completely processed. */
        if (ret != BSL_SUCCESS || ctx->tmpLen == 0) {
            break;
        }
        /* buffer is not full and the read/write retry flag is set, more data can be read continually. */
        if ((rLen < BASE64_BLOCK_SIZE) && (ctx->isContinue > 0)) {
            continue;
        }
        ret = Base64ReadProcess(uio, ctx, &rLen);
        if (ret != BSL_SUCCESS) {
            break;
        }
        ctx->bufLen += rLen;
        ctx->bufUsed = 0;
        ret = Base64ReadRefreshBuf(ctx, &bufTmp, &len, &total);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    }

    if (!isPem && ctx->isContinue == 0 && len > 0) {
        ret = Base64ReadFinal(ctx, &bufTmp, &len, &total);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    }

    (void)BSL_UIO_SetFlagsFromNext(uio);
    *readLen = total;
    return ret;
}

static int32_t Base64Wpending(Base64Ctx *ctx, BSL_UIO *next, int32_t cmd, int32_t larg, void *parg)
{
    int32_t ret = BSL_SUCCESS;
    if (ctx->bufLen < ctx->bufUsed) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    if (ctx->bufLen == ctx->bufUsed) {
        if ((ctx->encode != BASE64_NONE) && (ctx->base64Ctx->num != 0)) {
            return ret;
        } else {
            ret = BSL_UIO_Ctrl(next, cmd, larg, parg);
        }
    }
    return ret;
}

static int32_t Base64Pending(Base64Ctx *ctx, BSL_UIO *next, int32_t cmd, int32_t larg, void *parg)
{
    int32_t ret = BSL_SUCCESS;
    if (ctx->bufLen < ctx->bufUsed) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    if (ctx->bufLen == ctx->bufUsed) {
        ret = BSL_UIO_Ctrl(next, cmd, larg, parg);
    }
    return ret;
}

/* The tail processing of characters written by BASE64 is placed in Base64Write(). */
/* CTRL-flush processes the next-UIO part. */
static int32_t Base64Flush(BSL_UIO *uio, BSL_UIO *next, int32_t cmd, int32_t larg, void *parg)
{
    Base64Ctx *ctx = (Base64Ctx *)uio->ctx;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    bool again = true;
    int32_t ret = BSL_SUCCESS;

    while (again) {
        while (ctx->bufLen != ctx->bufUsed) {
            ret = Base64WriteRefreshBuf(uio, next, ctx);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        }
        if (ctx->encode == BASE64_ENCODE && ctx->base64Ctx->num != 0) {
            ctx->bufLen = UIO_BASE64_ENC_ENOUGH_LEN(HITLS_BASE64_CTX_LENGTH);
            ret = (int32_t)BSL_BASE64_EncodeFinal(ctx->base64Ctx, (char *)ctx->buf, &ctx->bufLen);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
            continue;
        }
        again = false;
    }

    /* Flush the next UIO. */
    return BSL_UIO_Ctrl(next, cmd, larg, parg);
}

static int32_t Base64Reset(BSL_UIO *uio, BSL_UIO *next, int32_t cmd, int32_t larg, void *parg)
{
    Base64Ctx *ctx = (Base64Ctx *)uio->ctx;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    ctx->isContinue = 1;
    ctx->encode = BASE64_NONE;
    return BSL_UIO_Ctrl(next, cmd, larg, parg);
}

static int32_t Base64Ctrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    if (uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    BSL_UIO *next = BSL_UIO_Next(uio);
    if (next == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    Base64Ctx *ctx = (Base64Ctx *)uio->ctx;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    switch (cmd) {
        case BSL_UIO_WPENDING:
            return Base64Wpending(ctx, next, cmd, larg, parg);
        case BSL_UIO_PENDING:
            return Base64Pending(ctx, next, cmd, larg, parg);
        /* When write is complete, the last data block in the UIO should be refreshed in the base64-UIO. */
        case BSL_UIO_FLUSH:
            return Base64Flush(uio, next, cmd, larg, parg);
        case BSL_UIO_INFO:
            return BSL_UIO_Ctrl(next, cmd, larg, parg);
        case BSL_UIO_RESET:
            return Base64Reset(uio, next, cmd, larg, parg);
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
    return BSL_UIO_FAIL;
}

static int Base64Put(BSL_UIO *uio, const char *buf, uint32_t *writeLen)
{
    uint32_t len = 0;
    if (buf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    len = (uint32_t)strlen(buf);
    return Base64Write(uio, buf, len, writeLen);
}

const BSL_UIO_Method *BSL_UIO_Base64Method(void)
{
    static const BSL_UIO_Method base64Method = {
        BSL_UIO_BASE64,
        Base64Write,
        Base64Read,
        Base64Ctrl,
        Base64Put,
        NULL,
        Base64Create,
        Base64Destroy,
    };
    return &base64Method;
}
#endif /* HITLS_BSL_UIO_BASE64 */

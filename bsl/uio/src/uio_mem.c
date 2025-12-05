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
#ifdef HITLS_BSL_UIO_MEM

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_buffer.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "uio_base.h"
#include "uio_abstraction.h"
#include "bsl_uio.h"

typedef struct {
    BSL_BufMem *buf;
    BSL_BufMem *tmpBuf; // only used in read-only mode
    size_t readIndex;
    int32_t eof; // Behavior when reading empty memory. If the value is not 0, retry will be set.
} UIO_BufMem;

static int32_t MemNewBuf(BSL_UIO *uio, int32_t len, void *buf)
{
    if (buf == NULL || len < 0) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    
    UIO_BufMem *ubm = BSL_UIO_GetCtx(uio);
    if (ubm == NULL || ubm->buf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    BSL_BufMem *bm = ubm->buf;
    if (bm->data != NULL && (uio->flags & BSL_UIO_FLAGS_MEM_READ_ONLY) == 0) {
        /* If the UIO mode is not read-only, need to release the memory first.
         * Otherwise, the internal memory applied for the read/write mode will be overwritten,
         */
        BSL_ERR_PUSH_ERROR(BSL_UIO_MEM_NOT_NULL);
        return BSL_UIO_MEM_NOT_NULL;
    }
    if (ubm->tmpBuf == NULL) {
        ubm->tmpBuf = BSL_BufMemNew();
        if (ubm->tmpBuf == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
    }

    ubm->readIndex = 0;
    ubm->eof = 0; // Read-only memory, and retry is not required.
    bm->length = (size_t)len;
    bm->max = (size_t)len;
    bm->data = (void *)buf;
    uio->flags = BSL_UIO_FLAGS_MEM_READ_ONLY;
    return BSL_SUCCESS;
}

static int32_t UioBufMemSync(UIO_BufMem *ubm)
{
    if (ubm != NULL && ubm->readIndex != 0) {
        if (memmove_s(ubm->buf->data, ubm->buf->length, ubm->buf->data + ubm->readIndex,
            ubm->buf->length - ubm->readIndex) != EOK) {
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            return BSL_UIO_FAIL;
        }
        ubm->buf->length -= ubm->readIndex;
        ubm->readIndex = 0;
    }
    return BSL_SUCCESS;
}

static int32_t MemWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    if (BSL_UIO_GetCtx(uio) == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if ((uio->flags & BSL_UIO_FLAGS_MEM_READ_ONLY) != 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_WRITE_NOT_ALLOWED);
        return BSL_UIO_WRITE_NOT_ALLOWED;
    }
    (void)BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
    *writeLen = 0;
    if (len == 0) {
        return BSL_SUCCESS;
    }
    UIO_BufMem *ubm = BSL_UIO_GetCtx(uio);
    if (ubm == NULL || ubm->buf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    if (UioBufMemSync(ubm) != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_MEMMOVE_FAIL);
        return BSL_MEMMOVE_FAIL;
    }

    const size_t origLen = ubm->buf->length;
    if (BSL_BufMemGrowClean(ubm->buf, origLen + len) == 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_MEM_GROW_FAIL);
        return BSL_UIO_MEM_GROW_FAIL;
    }

    // memory grow guarantee of success here
    (void)memcpy_s(ubm->buf->data + origLen, len, buf, len);

    *writeLen = len;
    return BSL_SUCCESS;
}

static int32_t MemRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    if (BSL_UIO_GetCtx(uio) == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    (void)BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
    *readLen = 0;
    UIO_BufMem *ubm = BSL_UIO_GetCtx(uio);
    if (ubm == NULL || ubm->buf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    size_t real = (size_t)len;
    if (real > ubm->buf->length - ubm->readIndex) {
        real = ubm->buf->length - ubm->readIndex;
    }
    if (buf != NULL && real > 0) {
        (void)memcpy_s(buf, len, ubm->buf->data + ubm->readIndex, real);
        ubm->readIndex += real;
        *readLen = (uint32_t)real;
    }
    if (*readLen > 0) {
        return BSL_SUCCESS;
    }
    /* when real equals 0, it is necessary to determine whether to retry based on eof */
    if (ubm->eof != 0) { // retry if eof is not zero
        (void)BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_READ | BSL_UIO_FLAGS_SHOULD_RETRY);
    }
    return BSL_SUCCESS;
}

static int32_t MemPending(BSL_UIO *uio, int32_t larg, uint64_t *ret)
{
    if (ret == NULL || larg != sizeof(uint64_t)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    UIO_BufMem *ubm = BSL_UIO_GetCtx(uio);
    if (ubm == NULL || ubm->buf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }

    *ret = (uint64_t)(ubm->buf->length - ubm->readIndex);
    return BSL_SUCCESS;
}

static int32_t MemWpending(int32_t larg, uint64_t *ret)
{
    if (larg != sizeof(uint64_t) || ret == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    *ret = 0; // For the UIO of the mem type, return 0
    return BSL_SUCCESS;
}

static int32_t MemInfo(BSL_UIO *uio, int32_t larg, BSL_UIO_CtrlGetInfoParam *ret)
{
    if (ret == NULL || larg != sizeof(BSL_UIO_CtrlGetInfoParam)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    UIO_BufMem *ubm = BSL_UIO_GetCtx(uio);
    if (ubm == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    BSL_BufMem *bm = ubm->buf;
    if (bm == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    ret->data = (uint8_t *)(&bm->data[ubm->readIndex]);
    ret->size = bm->length - ubm->readIndex; // overflow error
    return BSL_SUCCESS;
}

static int32_t MemGetPtr(BSL_UIO *uio, int32_t size, BSL_BufMem **ret)
{
    if (ret == NULL || size != (int32_t)sizeof(BSL_BufMem *)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    UIO_BufMem *ubm = BSL_UIO_GetCtx(uio);
    if (ubm == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    if ((uio->flags & BSL_UIO_FLAGS_MEM_READ_ONLY) == 0) {
        if (UioBufMemSync(ubm) != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(BSL_MEMMOVE_FAIL);
            return BSL_MEMMOVE_FAIL;
        }
        *ret = ubm->buf;
    } else {
        /* when reset to read-only mode, can read from the beginning.
         * Temporary buf is not used to manage memory. */
        ubm->tmpBuf->data = ubm->buf->data + ubm->readIndex;
        ubm->tmpBuf->length = ubm->buf->length - ubm->readIndex;
        ubm->tmpBuf->max = ubm->buf->max - ubm->readIndex;
        *ret = ubm->tmpBuf;
    }
    return BSL_SUCCESS;
}

static int32_t MemSetEof(BSL_UIO *uio, int32_t larg, const int32_t *eof)
{
    if (eof == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (larg != (int32_t)sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    UIO_BufMem *ubm = BSL_UIO_GetCtx(uio);
    if (ubm == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }

    ubm->eof = *eof;
    return BSL_SUCCESS;
}

static int32_t MemGetEof(BSL_UIO *uio, int32_t size, int32_t *eof)
{
    if (eof == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (size != (int32_t)sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    UIO_BufMem *ubm = BSL_UIO_GetCtx(uio);
    if (ubm == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }

    *eof = ubm->eof;
    return BSL_SUCCESS;
}

static int32_t MemReset(BSL_UIO *uio)
{
    UIO_BufMem *ubm = BSL_UIO_GetCtx(uio);
    if (ubm == NULL || ubm->buf == NULL || ubm->buf->data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if ((uio->flags & BSL_UIO_FLAGS_MEM_READ_ONLY) != 0) {
        // Read-only mode: The read index is reset and data can be read again
        ubm->readIndex = 0;
    } else {
        // Read/Write mode: Clear all data
        (void)memset_s(ubm->buf->data, ubm->buf->max, 0, ubm->buf->max);
        ubm->buf->length = 0;
        ubm->readIndex = 0;
    }
    return BSL_SUCCESS;
}

static int32_t MemFlush(int32_t larg, void *parg)
{
    if (parg != NULL || larg != 0) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    return BSL_SUCCESS;
}

static int32_t MemCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    switch (cmd) {
        case BSL_UIO_PENDING:
            return MemPending(uio, larg, parg);
        case BSL_UIO_MEM_GET_INFO:
            return MemInfo(uio, larg, parg);
        case BSL_UIO_WPENDING:
            return MemWpending(larg, parg);
        case BSL_UIO_FLUSH:
            return MemFlush(larg, parg);
        case BSL_UIO_MEM_NEW_BUF:
            return MemNewBuf(uio, larg, parg);
        case BSL_UIO_MEM_GET_PTR:
            return MemGetPtr(uio, larg, parg);
        case BSL_UIO_MEM_SET_EOF:
            return MemSetEof(uio, larg, parg);
        case BSL_UIO_MEM_GET_EOF:
            return MemGetEof(uio, larg, parg);
        case BSL_UIO_RESET:
            return MemReset(uio);
        default:
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            return BSL_UIO_FAIL;
    }
}

static int32_t MemPuts(BSL_UIO *uio, const char *buf, uint32_t *writeLen)
{
    uint32_t len = 0;
    if (buf != NULL) {
        len = (uint32_t)strlen(buf);
    }
    return MemWrite(uio, buf, len, writeLen);
}

static int32_t MemGets(BSL_UIO *uio, char *buf, uint32_t *readLen)
{
    uint32_t cnt = 0;
    int32_t ret;
    UIO_BufMem *ubm = BSL_UIO_GetCtx(uio);
    if (ubm == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    BSL_BufMem *bm = ubm->buf;
    if (bm == NULL) {
        return BSL_NULL_INPUT;
    }
    if (*readLen == 0) {
        return BSL_SUCCESS;
    }
    uint32_t len = (uint32_t)((*readLen - 1) >= (bm->length - ubm->readIndex) ?
        (bm->length - ubm->readIndex) : (*readLen - 1));
    if (len == 0) { /* No data to read */
        *buf = '\0';
        *readLen = 0;
        return BSL_SUCCESS;
    }
    char *pre = bm->data + ubm->readIndex;
    /* len greater than 0 */
    while (cnt < len) {
        cnt++;
        if (*pre++ == '\n') {
            break;
        }
    }
    ret = MemRead(uio, buf, cnt, readLen);
    if (ret == BSL_SUCCESS) {
        buf[cnt] = '\0';
    }
    return ret;
}

static int32_t MemDestroy(BSL_UIO *uio)
{
    UIO_BufMem *ubm = BSL_UIO_GetCtx(uio);
    if (BSL_UIO_GetIsUnderlyingClosedByUio(uio) && ubm != NULL) {
        if ((uio->flags & BSL_UIO_FLAGS_MEM_READ_ONLY) != 0) {
            ubm->buf->data = NULL;
            if (ubm->tmpBuf != NULL) {
                ubm->tmpBuf->data = NULL;
                BSL_BufMemFree(ubm->tmpBuf);
            }
        }
        BSL_BufMemFree(ubm->buf);
        BSL_SAL_FREE(ubm);
    }

    BSL_UIO_SetCtx(uio, NULL);
    uio->init = false;
    return BSL_SUCCESS;
}

static int32_t MemCreate(BSL_UIO *uio)
{
    UIO_BufMem *ubm = BSL_SAL_Calloc(1, sizeof(UIO_BufMem));
    if (ubm == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ubm->buf = BSL_BufMemNew();
    if (ubm->buf == NULL) {
        BSL_SAL_FREE(ubm);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    ubm->eof = -1;
    BSL_UIO_SetCtx(uio, ubm);
    BSL_UIO_SetIsUnderlyingClosedByUio(uio, true); // memory buffer is created here and will be closed here by default.
    uio->init = true;
    return BSL_SUCCESS;
}

const BSL_UIO_Method *BSL_UIO_MemMethod(void)
{
    static const BSL_UIO_Method METHOD = {
        BSL_UIO_MEM,
        MemWrite,
        MemRead,
        MemCtrl,
        MemPuts,
        MemGets,
        MemCreate,
        MemDestroy
    };
    return &METHOD;
}

#endif /* HITLS_BSL_UIO_MEM */

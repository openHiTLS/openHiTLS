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
#ifdef HITLS_BSL_UIO_FILE

#include <stdio.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_errno.h"
#include "uio_base.h"
#include "uio_abstraction.h"
#include "sal_file.h"
#include "bsl_uio.h"

static int32_t FileWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    if (BSL_UIO_GetCtx(uio) == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    *writeLen = 0;
    if (len == 0) {
        return BSL_SUCCESS;
    }
    bsl_sal_file_handle f = BSL_UIO_GetCtx(uio);
    int32_t ret = BSL_SAL_FileWrite(f, buf, 1, len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    *writeLen = len;
    return BSL_SUCCESS;
}

static int32_t FileRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    if (BSL_UIO_GetCtx(uio) == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    *readLen = 0;
    size_t rLen;
    bsl_sal_file_handle f = BSL_UIO_GetCtx(uio);
    int32_t ret = BSL_SAL_FileRead(f, buf, 1, len, &rLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    *readLen = (uint32_t)rLen;
    return BSL_SUCCESS;
}

static int32_t FileDestroy(BSL_UIO *uio)
{
    if (BSL_UIO_GetIsUnderlyingClosedByUio(uio)) { // the closing of the file is specified by the user
        bsl_sal_file_handle f = BSL_UIO_GetCtx(uio);
        if (f != NULL) {
            BSL_SAL_FileClose(f);
            BSL_UIO_SetCtx(uio, NULL);
        }
    }
    uio->init = false;
    return BSL_SUCCESS;
}

static int32_t FileOpen(BSL_UIO *uio, uint32_t flags, const char *filename)
{
    if (filename == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    bsl_sal_file_handle f = BSL_UIO_GetCtx(uio);
    if (f != NULL) {
        if (BSL_UIO_GetIsUnderlyingClosedByUio(uio)) {
            BSL_SAL_FileClose(f);
            BSL_UIO_SetCtx(uio, NULL);
        } else {
            return BSL_UIO_EXIST_CONTEXT_NOT_RELEASED;
        }
    }

    const char *mode = NULL;
    bsl_sal_file_handle fileHandle = NULL;

    if ((flags & BSL_UIO_FILE_APPEND) != 0) {
        mode = ((flags & BSL_UIO_FILE_READ) != 0) ? "a+" : "a";
    } else if ((flags & BSL_UIO_FILE_READ) != 0) {
        mode = ((flags & BSL_UIO_FILE_WRITE) != 0) ? "r+" : "r";
    } else if ((flags & BSL_UIO_FILE_WRITE) != 0) {
        mode = "w";
    } else {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FILE_OPEN_FAIL);
        return BSL_UIO_FILE_OPEN_FAIL;
    }

    if (BSL_SAL_FileOpen(&fileHandle, filename, mode) != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FILE_OPEN_FAIL);
        return BSL_UIO_FILE_OPEN_FAIL;
    }

    BSL_UIO_SetCtx(uio, (void *)fileHandle);
    uio->init = true;
    return BSL_SUCCESS;
}

static int32_t FilePending(BSL_UIO *uio, int32_t larg, uint64_t *ret)
{
    if (ret == NULL || larg != sizeof(*ret)) {
        return BSL_INVALID_ARG;
    }
    bsl_sal_file_handle f = BSL_UIO_GetCtx(uio);
    if (f == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    long current; // save the current
    if (SAL_FileTell(f, &current) != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }
    if (SAL_FileSeek(f, 0, SEEK_END) != BSL_SUCCESS) { // move to the end
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }

    long max; // get the length
    if (SAL_FileTell(f, &max) != BSL_SUCCESS || max < current) {  // error, including < 0, should restore the current
        (void)SAL_FileSeek(f, current, SEEK_SET);
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }

    *ret = (uint64_t)(max - current); // save the remaining length
    (void)SAL_FileSeek(f, current, SEEK_SET); // recover it
    return BSL_SUCCESS;
}

static int32_t FileWpending(int32_t larg, int64_t *ret)
{
    if (larg != sizeof(int64_t) || ret == NULL) {
        return BSL_INVALID_ARG;
    }
    *ret = 0; // should return 0 if it's file UIO
    return BSL_SUCCESS;
}

static int32_t FileSetPtr(BSL_UIO *uio, int32_t isClosed, FILE *fp)
{
    if (fp == NULL || (isClosed != 0 && isClosed != 1)) {
        return BSL_INVALID_ARG;
    }
    bsl_sal_file_handle file = BSL_UIO_GetCtx(uio);
    if (file != NULL) {
        if (BSL_UIO_GetIsUnderlyingClosedByUio(uio)) {
            BSL_SAL_FileClose(file);
            BSL_UIO_SetCtx(uio, NULL);
        } else {
            return BSL_UIO_EXIST_CONTEXT_NOT_RELEASED;
        }
    }
    BSL_UIO_SetCtx(uio, fp);
    BSL_UIO_SetIsUnderlyingClosedByUio(uio, isClosed);
    uio->init = true;
    return BSL_SUCCESS;
}

static int32_t FileReset(BSL_UIO *uio)
{
    if (BSL_UIO_GetCtx(uio) == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    bsl_sal_file_handle *f = BSL_UIO_GetCtx(uio);
    if (SAL_FileSeek(f, 0, SEEK_SET) != 0) {
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }
    return BSL_SUCCESS;
}

static int32_t FileGetEof(BSL_UIO *uio, int32_t larg, bool *isEof)
{
    if (larg != 1 || isEof == NULL) {
        return BSL_INVALID_ARG;
    }
    *isEof = false;

    if (BSL_UIO_GetCtx(uio) == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }

    FILE *f = BSL_UIO_GetCtx(uio);
    if (feof(f) != 0) {
        *isEof = true;
    }
    return BSL_SUCCESS;
}

static int32_t FileCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    if (larg < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    switch (cmd) {
        case BSL_UIO_FILE_OPEN:
            return FileOpen(uio, (uint32_t)larg, parg);
        case BSL_UIO_PENDING:
            return FilePending(uio, larg, parg);
        case BSL_UIO_WPENDING:
            return FileWpending(larg, parg);
        case BSL_UIO_FILE_PTR:
            return FileSetPtr(uio, larg, parg);
        case BSL_UIO_RESET:
            return FileReset(uio);
        case BSL_UIO_FILE_GET_EOF:
            return FileGetEof(uio, larg, parg);
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
    return BSL_UIO_FAIL;
}

static int32_t FileGets(BSL_UIO *uio, char *buf, uint32_t *readLen)
{
    if (BSL_UIO_GetCtx(uio) == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    (void)BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
    bsl_sal_file_handle f = BSL_UIO_GetCtx(uio);
    if (SAL_FGets(f, buf, (int32_t)*readLen) == NULL) {
        *readLen = 0;
        if (SAL_FileError(f) == false) { // read the end of the file successfully
            return BSL_SUCCESS;
        }
        (void)BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_READ | BSL_UIO_FLAGS_SHOULD_RETRY);
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }
    *readLen = (uint32_t)strlen(buf);

    return BSL_SUCCESS;
}

static int32_t FilePuts(BSL_UIO *uio, const char *buf, uint32_t *writeLen)
{
    uint32_t len = 0;
    if (buf != NULL) {
        len = (uint32_t)strlen(buf);
    }
    return FileWrite(uio, buf, len, writeLen);
}

const BSL_UIO_Method *BSL_UIO_FileMethod(void)
{
    static const BSL_UIO_Method METHOD = {
        BSL_UIO_FILE,
        FileWrite,
        FileRead,
        FileCtrl,
        FilePuts,
        FileGets,
        NULL,
        FileDestroy,
    };
    return &METHOD;
}
#endif /* HITLS_BSL_UIO_FILE */

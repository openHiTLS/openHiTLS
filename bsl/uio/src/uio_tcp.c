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
#ifdef HITLS_BSL_UIO_TCP

#include <unistd.h>
#include <string.h>
#include "bsl_binlog_id.h"
#include "bsl_err_internal.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "sal_net.h"
#include "uio_base.h"
#include "uio_abstraction.h"

typedef struct {
    int32_t fd;
} TcpPrameters;

static int32_t TcpNew(BSL_UIO *uio)
{
    if (uio->ctx != NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05079, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: ctx is already existed.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }

    TcpPrameters *parameters = (TcpPrameters *)BSL_SAL_Calloc(1u, sizeof(TcpPrameters));
    if (parameters == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05065, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Uio: tcp param malloc fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
        return BSL_UIO_FAIL;
    }

    parameters->fd = -1;
    uio->ctx = parameters;
    uio->ctxLen = sizeof(TcpPrameters);
    // Specifies whether to be closed by uio when setting fd.
    // The default value of init is 0. Set the value of init to 1 after the fd is set.
    return BSL_SUCCESS;
}

static int32_t TcpSocketDestroy(BSL_UIO *uio)
{
    if (uio == NULL) {
        return BSL_SUCCESS;
    }
    uio->init = false;
    TcpPrameters *ctx = BSL_UIO_GetCtx(uio);
    if (ctx != NULL) {
        if (BSL_UIO_GetIsUnderlyingClosedByUio(uio) && ctx->fd != -1) {
            (void)BSL_SAL_SockClose(ctx->fd);
        }
        BSL_SAL_FREE(ctx);
        BSL_UIO_SetCtx(uio, NULL);
    }
    return BSL_SUCCESS;
}

static int32_t TcpSocketWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    *writeLen = 0;
    int32_t err = 0;
    int32_t fd = BSL_UIO_GetFd(uio);
    if (fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    int32_t ret = SAL_Write(fd, buf, len, &err);
    (void)BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
    if (ret > 0) {
        *writeLen = (uint32_t)ret;
        return BSL_SUCCESS;
    }
    // If the value of ret is less than or equal to 0, check errno first.
    if (UioIsNonFatalErr(err)) { // Indicates the errno for determining whether retry is allowed.
        (void)BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_WRITE | BSL_UIO_FLAGS_SHOULD_RETRY);
        return BSL_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
    return BSL_UIO_IO_EXCEPTION;
}

static int32_t TcpSocketRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    *readLen = 0;

    int32_t err = 0;
    (void)BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
    int32_t fd = BSL_UIO_GetFd(uio);
    if (fd < 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
        return BSL_UIO_IO_EXCEPTION;
    }
    int32_t ret = SAL_Read(fd, buf, len, &err);
    if (ret > 0) { // Success
        *readLen = (uint32_t)ret;
        return BSL_SUCCESS;
    }
    // If the value of ret is less than or equal to 0, check errno first.
    if (UioIsNonFatalErr(err)) { // Indicates the errno for determining whether retry is allowed.
        (void)BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_READ | BSL_UIO_FLAGS_SHOULD_RETRY);
        return BSL_SUCCESS;
    }
    if (ret == 0) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EOF);
        return BSL_UIO_IO_EOF;
    }
    BSL_ERR_PUSH_ERROR(BSL_UIO_IO_EXCEPTION);
    return BSL_UIO_IO_EXCEPTION;
}

static int32_t TcpSetFd(BSL_UIO *uio, int32_t size, const int32_t *fd)
{
    if (fd == NULL || uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (size != (int32_t)sizeof(*fd)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    TcpPrameters *ctx = BSL_UIO_GetCtx(uio);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (ctx->fd != -1) {
        if (BSL_UIO_GetIsUnderlyingClosedByUio(uio)) {
            (void)BSL_SAL_SockClose(ctx->fd);
        }
    }
    ctx->fd = *fd;
    uio->init = true;
    return BSL_SUCCESS;
}

static int32_t TcpGetFd(BSL_UIO *uio, int32_t size, int32_t *fd)
{
    if (fd == NULL || uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (size != (int32_t)sizeof(*fd)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    TcpPrameters *ctx = BSL_UIO_GetCtx(uio);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    *fd = ctx->fd;
    return BSL_SUCCESS;
}

static int32_t TcpSocketCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    switch (cmd) {
        case BSL_UIO_SET_FD:
            return TcpSetFd(uio, larg, parg);
        case BSL_UIO_GET_FD:
            return TcpGetFd(uio, larg, parg);
        case BSL_UIO_FLUSH:
            return BSL_SUCCESS;
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
    return BSL_UIO_FAIL;
}

static int32_t TcpSocketPuts(BSL_UIO *uio, const char *buf, uint32_t *writeLen)
{
    uint32_t len = (uint32_t)strlen(buf);
    return TcpSocketWrite(uio, buf, len, writeLen);
}

const BSL_UIO_Method *BSL_UIO_TcpMethod(void)
{
    static const BSL_UIO_Method method = {
        BSL_UIO_TCP,
        TcpSocketWrite,
        TcpSocketRead,
        TcpSocketCtrl,
        TcpSocketPuts,
        NULL,
        TcpNew,
        TcpSocketDestroy
    };
    return &method;
}

#endif /* HITLS_BSL_UIO_TCP */

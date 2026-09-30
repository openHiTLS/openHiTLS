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

#ifdef HITLS_TLS_FEATURE_MODE_ASYNC

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "bsl_async.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "tls_binlog_id.h"
#include "conn_async.h"

static int32_t HITLS_AsyncDispatch(const HITLS_ASYNC_ARGS *args)
{
    switch (args->op) {
        case HITLS_ASYNC_OP_CONNECT:
            return HITLS_ConnectInternal(args->ctx);
        case HITLS_ASYNC_OP_ACCEPT:
            return HITLS_AcceptInternal(args->ctx);
        case HITLS_ASYNC_OP_DO_HANDSHAKE:
            return HITLS_DoHandShakeInternal(args->ctx);
        case HITLS_ASYNC_OP_READ:
            return HITLS_ReadInternal(args->ctx, args->param.read.data, args->param.read.bufSize,
                                      args->param.read.readLen);
        case HITLS_ASYNC_OP_PEEK:
            return HITLS_PeekInternal(args->ctx, args->param.read.data, args->param.read.bufSize,
                                      args->param.read.readLen);
        case HITLS_ASYNC_OP_WRITE:
            return HITLS_WriteInternal(args->ctx, args->param.write.data, args->param.write.dataLen,
                                       args->param.write.writeLen);
        default:
            return HITLS_INTERNAL_EXCEPTION;
    }
}

static int32_t HITLS_AsyncTaskEntry(void *arg)
{
    return HITLS_AsyncDispatch((const HITLS_ASYNC_ARGS *)arg);
}

static bool HITLS_AsyncArgsIsSame(const HITLS_ASYNC_ARGS *saved, const HITLS_ASYNC_ARGS *now)
{
    if (saved->ctx != now->ctx || saved->op != now->op) {
        return false;
    }
    switch (now->op) {
        case HITLS_ASYNC_OP_CONNECT:
        case HITLS_ASYNC_OP_ACCEPT:
        case HITLS_ASYNC_OP_DO_HANDSHAKE:
            return true;
        case HITLS_ASYNC_OP_READ:
        case HITLS_ASYNC_OP_PEEK:
            return saved->param.read.data == now->param.read.data &&
                   saved->param.read.bufSize == now->param.read.bufSize &&
                   saved->param.read.readLen == now->param.read.readLen;
        case HITLS_ASYNC_OP_WRITE:
            return saved->param.write.data == now->param.write.data &&
                   saved->param.write.dataLen == now->param.write.dataLen &&
                   saved->param.write.writeLen == now->param.write.writeLen;
        default:
            return false;
    }
}

int32_t HITLS_AsyncNotifyBridge(void *arg)
{
    HITLS_Ctx *ctx = (HITLS_Ctx *)arg;
    if (ctx == NULL) {
        return BSL_ASYNC_ERR_STATE_CONFLICT;
    }
    HITLS_AsyncCallback callback = ctx->config.tlsConfig.asyncCallback;
    if (callback == NULL) {
        return BSL_ASYNC_ERR_STATE_CONFLICT;
    }
    /* The return value is a private contract between the application and the
     * producer: the protocol layer only transports it, never interprets it. */
    return callback(ctx, ctx->config.tlsConfig.asyncCallbackArg);
}

static int32_t HITLS_AsyncEnsureNotifyCtx(HITLS_Ctx *ctx)
{
    if (ctx->asyncNotifyCtx != NULL) {
        return HITLS_SUCCESS;
    }
    BSL_ASYNC_NotifyCtx *notifyCtx = BSL_ASYNC_NotifyCtxNew();
    if (notifyCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17424, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "async notify ctx alloc fail",
                              0, 0, 0, 0);
        return HITLS_ASYNC_ERR_FRAMEWORK;
    }
    /* Install the bridge only in the callback mode so that a producer's
     * GetCallback reports "unset" in the handle mode. */
    if (ctx->config.tlsConfig.asyncCallback != NULL) {
        (void)BSL_ASYNC_NotifyCtxSetCallback(notifyCtx, HITLS_AsyncNotifyBridge, ctx);
    }
    ctx->asyncNotifyCtx = notifyCtx;
    return HITLS_SUCCESS;
}

int32_t HITLS_AsyncRun(const HITLS_ASYNC_ARGS *args)
{
    if (args == NULL || args->ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    HITLS_Ctx *ctx = args->ctx;

    /* The async mode is off: run the business path directly, creating no async object. */
    if ((ctx->config.tlsConfig.modeSupport & HITLS_MODE_ASYNC) == 0) {
        return HITLS_AsyncDispatch(args);
    }

    /* The build or the platform has no resumable-context backend. */
    if (!BSL_ASYNC_IsSupported()) {
        ctx->rwstate = HITLS_NOTHING;
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17425, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "async backend unsupported",
                              0, 0, 0, 0);
        return HITLS_ASYNC_ERR_UNSUPPORTED;
    }

    /* A paused task exists: this call must match the first call; the task stays paused otherwise. */
    if (ctx->asyncTask != NULL && !HITLS_AsyncArgsIsSame(&ctx->asyncArgs, args)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17426, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "async resume args mismatch",
                              0, 0, 0, 0);
        return HITLS_ASYNC_ERR_OPERATION_BUSY;
    }

    int32_t ret = HITLS_AsyncEnsureNotifyCtx(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ctx->rwstate = HITLS_NOTHING;
    /* Keep the first-call args; a resume must not overwrite them. */
    if (ctx->asyncTask == NULL) {
        ctx->asyncArgs = *args;
    }

    int32_t taskRet = HITLS_INTERNAL_EXCEPTION;
    BSL_ASYNC_TaskParam param = {0};
    param.notifyCtx = ctx->asyncNotifyCtx;
    param.func = HITLS_AsyncTaskEntry;
    param.args = &ctx->asyncArgs;
    param.argsSize = sizeof(ctx->asyncArgs);
    int32_t asyncRet = BSL_ASYNC_StartTask(&ctx->asyncTask, &taskRet, &param);

    switch (asyncRet) {
        case BSL_ASYNC_FINISH:
            /* The physical task was reclaimed by the framework and *task is NULL. */
            (void)memset(&ctx->asyncArgs, 0, sizeof(ctx->asyncArgs));
            return taskRet;
        case BSL_ASYNC_PAUSE:
            ctx->rwstate = HITLS_ASYNC_PAUSED;
            return HITLS_ASYNC_ERR_PAUSED;
        case BSL_ASYNC_NO_JOB:
            ctx->rwstate = HITLS_ASYNC_NO_JOBS;
            (void)memset(&ctx->asyncArgs, 0, sizeof(ctx->asyncArgs));
            return HITLS_ASYNC_ERR_NO_JOB;
        case BSL_ASYNC_WRONG_EXEC_CTX:
            /* Non-destructive rejection: the task still belongs to its owner thread. */
            ctx->rwstate = HITLS_ASYNC_PAUSED;
            return HITLS_ASYNC_ERR_WRONG_THREAD;
        case BSL_ASYNC_UNSUPPORTED:
            ctx->rwstate = HITLS_NOTHING;
            (void)memset(&ctx->asyncArgs, 0, sizeof(ctx->asyncArgs));
            return HITLS_ASYNC_ERR_UNSUPPORTED;
        default:
            /* BSL_ASYNC_ERR: no task was established, or the framework converged it safely. */
            ctx->rwstate = HITLS_NOTHING;
            (void)memset(&ctx->asyncArgs, 0, sizeof(ctx->asyncArgs));
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17427, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "async framework error",
                                  0, 0, 0, 0);
            return HITLS_ASYNC_ERR_FRAMEWORK;
    }
}

#endif /* HITLS_TLS_FEATURE_MODE_ASYNC */

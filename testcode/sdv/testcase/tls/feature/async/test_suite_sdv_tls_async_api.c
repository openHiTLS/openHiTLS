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

/* BEGIN_HEADER */
/* INCLUDE_BASE test_suite_sdv_tls_async */
#include "hitls_build.h"
/* END_HEADER */

/**
 * @test SDV_TLS_ASYNC_MODE_CFG_TC001
 * @title Async mode bit round-trip on the config and inheritance by HITLS_New
 * @brief
 *   1. Set, query and clear HITLS_MODE_ASYNC on a config. Expected: the bit follows each call.
 *   2. Create a connection from the enabled config. Expected: the private config inherits the bit.
 * @expect
 *   1. Success on every set/get/clear and the bit value matches.
 *   2. The connection reports the async mode bit after HITLS_New.
 @ */
/* BEGIN_CASE */
void SDV_TLS_ASYNC_MODE_CFG_TC001(void)
{
#ifndef HITLS_TLS_FEATURE_MODE_ASYNC
    SKIP_TEST();
#else
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    HITLS_Ctx *ctx = NULL;
    ASSERT_TRUE(config != NULL);
    uint32_t mode = 0;
    ASSERT_EQ(HITLS_CFG_GetModeSupport(config, &mode), HITLS_SUCCESS);
    ASSERT_EQ(mode & HITLS_MODE_ASYNC, 0);
    ASSERT_EQ(HITLS_CFG_SetModeSupport(config, HITLS_MODE_ASYNC), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_GetModeSupport(config, &mode), HITLS_SUCCESS);
    ASSERT_EQ(mode & HITLS_MODE_ASYNC, HITLS_MODE_ASYNC);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_GetModeSupport(ctx, &mode), HITLS_SUCCESS);
    ASSERT_EQ(mode & HITLS_MODE_ASYNC, HITLS_MODE_ASYNC);
    ASSERT_EQ(HITLS_ClearModeSupport(ctx, HITLS_MODE_ASYNC), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_GetModeSupport(ctx, &mode), HITLS_SUCCESS);
    ASSERT_EQ(mode & HITLS_MODE_ASYNC, 0);
EXIT:
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
#endif
}
/* END_CASE */

/**
 * @test SDV_TLS_ASYNC_CALLBACK_CFG_TC002
 * @title Config-level async callback set/get and NULL rules
 * @brief
 *   1. Set and get an async callback with its argument on a config.
 *   2. Call HITLS_CFG_SetAsyncCallback with a NULL callback and a non-NULL arg.
 *   3. Clear the callback with (NULL, NULL) and query again.
 * @expect
 *   1. The getter returns exactly what was set.
 *   2. HITLS_INVALID_INPUT is returned and nothing changes.
 *   3. The getter outputs NULL for both outputs after the clear.
 @ */
/* BEGIN_CASE */
void SDV_TLS_ASYNC_CALLBACK_CFG_TC002(void)
{
#ifndef HITLS_TLS_FEATURE_MODE_ASYNC
    SKIP_TEST();
#else
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    HITLS_AsyncCallback callback = NULL;
    void *arg = NULL;
    ASSERT_EQ(HITLS_CFG_SetAsyncCallback(config, TestAsyncCallbackOne, (void *)1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_GetAsyncCallback(config, &callback, &arg), HITLS_SUCCESS);
    ASSERT_TRUE(callback == TestAsyncCallbackOne);
    ASSERT_TRUE(arg == (void *)1);
    ASSERT_EQ(HITLS_CFG_SetAsyncCallback(config, NULL, (void *)1), HITLS_INVALID_INPUT);
    ASSERT_EQ(HITLS_CFG_GetAsyncCallback(config, &callback, &arg), HITLS_SUCCESS);
    ASSERT_TRUE(callback == TestAsyncCallbackOne);
    ASSERT_EQ(HITLS_CFG_SetAsyncCallback(config, NULL, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_GetAsyncCallback(config, &callback, &arg), HITLS_SUCCESS);
    ASSERT_TRUE(callback == NULL);
    ASSERT_TRUE(arg == NULL);
    ASSERT_EQ(HITLS_CFG_SetAsyncCallback(NULL, TestAsyncCallbackOne, NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_GetAsyncCallback(config, NULL, &arg), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_GetAsyncCallback(config, &callback, NULL), HITLS_NULL_INPUT);
EXIT:
    HITLS_CFG_FreeConfig(config);
#endif
}
/* END_CASE */

/**
 * @test SDV_TLS_ASYNC_CALLBACK_CTX_TC003
 * @title Connection-level async callback set/get and config inheritance
 * @brief
 *   1. Configure a callback on the config and create a connection.
 *   2. Override the callback on the connection and query it.
 *   3. Call HITLS_SetAsyncCallback with a NULL callback and a non-NULL arg.
 * @expect
 *   1. The connection inherits the config callback after HITLS_New.
 *   2. The getter returns the overridden pair.
 *   3. HITLS_INVALID_INPUT is returned and the previous setting is kept.
 @ */
/* BEGIN_CASE */
void SDV_TLS_ASYNC_CALLBACK_CTX_TC003(void)
{
#ifndef HITLS_TLS_FEATURE_MODE_ASYNC
    SKIP_TEST();
#else
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    HITLS_Ctx *ctx = NULL;
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetAsyncCallback(config, TestAsyncCallbackOne, (void *)1), HITLS_SUCCESS);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    HITLS_AsyncCallback callback = NULL;
    void *arg = NULL;
    /* Inherited from the config by the private-config copy. */
    ASSERT_EQ(HITLS_GetAsyncCallback(ctx, &callback, &arg), HITLS_SUCCESS);
    ASSERT_TRUE(callback == TestAsyncCallbackOne);
    ASSERT_TRUE(arg == (void *)1);
    ASSERT_EQ(HITLS_SetAsyncCallback(ctx, TestAsyncCallbackTwo, (void *)2), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_GetAsyncCallback(ctx, &callback, &arg), HITLS_SUCCESS);
    ASSERT_TRUE(callback == TestAsyncCallbackTwo);
    ASSERT_TRUE(arg == (void *)2);
    ASSERT_EQ(HITLS_SetAsyncCallback(ctx, NULL, (void *)3), HITLS_INVALID_INPUT);
    ASSERT_EQ(HITLS_GetAsyncCallback(ctx, &callback, &arg), HITLS_SUCCESS);
    ASSERT_TRUE(callback == TestAsyncCallbackTwo);
    ASSERT_EQ(HITLS_SetAsyncCallback(ctx, NULL, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_GetAsyncCallback(ctx, &callback, &arg), HITLS_SUCCESS);
    ASSERT_TRUE(callback == NULL);
    ASSERT_TRUE(arg == NULL);
    ASSERT_EQ(HITLS_SetAsyncCallback(NULL, TestAsyncCallbackOne, NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_GetAsyncCallback(ctx, NULL, &arg), HITLS_NULL_INPUT);
EXIT:
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
#endif
}
/* END_CASE */

/**
 * @test SDV_TLS_ASYNC_QUERY_INVALID_TC004
 * @title Async query interface parameter and state validation
 * @brief
 *   1. Call the three query interfaces with NULL parameters.
 *   2. Call them with an inconsistent handle list (NULL handles with a non-zero capacity).
 *   3. Call them on a connection that has never paused.
 * @expect
 *   1. HITLS_NULL_INPUT.
 *   2. HITLS_INVALID_INPUT.
 *   3. HITLS_ASYNC_ERR_NOT_PAUSED.
 @ */
/* BEGIN_CASE */
void SDV_TLS_ASYNC_QUERY_INVALID_TC004(void)
{
#ifndef HITLS_TLS_FEATURE_MODE_ASYNC
    SKIP_TEST();
#else
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    HITLS_Ctx *ctx = NULL;
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    int32_t status = BSL_ASYNC_NOTIFY_STATUS_OK;
    BSL_ASYNC_NotifyHandleList list = {0};
    BSL_ASYNC_NotifyHandleList addList = {0};
    BSL_ASYNC_NotifyHandleList delList = {0};
    ASSERT_EQ(HITLS_GetAsyncStatus(NULL, &status), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_GetAsyncStatus(ctx, NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_GetAllAsyncNotifyHandles(NULL, &list), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_GetAllAsyncNotifyHandles(ctx, NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_GetChangedAsyncNotifyHandles(NULL, &addList, &delList), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_GetChangedAsyncNotifyHandles(ctx, NULL, &delList), HITLS_NULL_INPUT);
    list.capacity = 1; /* handles stays NULL: inconsistent list */
    ASSERT_EQ(HITLS_GetAllAsyncNotifyHandles(ctx, &list), HITLS_INVALID_INPUT);
    addList.capacity = 1;
    ASSERT_EQ(HITLS_GetChangedAsyncNotifyHandles(ctx, &addList, &delList), HITLS_INVALID_INPUT);
    /* Never paused: no outstanding async task. */
    list.capacity = 0;
    addList.capacity = 0;
    ASSERT_EQ(HITLS_GetAsyncStatus(ctx, &status), HITLS_ASYNC_ERR_NOT_PAUSED);
    ASSERT_EQ(HITLS_GetAllAsyncNotifyHandles(ctx, &list), HITLS_ASYNC_ERR_NOT_PAUSED);
    ASSERT_EQ(HITLS_GetChangedAsyncNotifyHandles(ctx, &addList, &delList), HITLS_ASYNC_ERR_NOT_PAUSED);
EXIT:
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
#endif
}
/* END_CASE */

/**
 * @test SDV_TLS_ASYNC_GETERROR_TC005
 * @brief
 *   1. Call HITLS_GetError with success and async direct return codes.
 * @expect
 *   1. Success maps to HITLS_SUCCESS; async codes without the matching rwstate
 *      do not map to HITLS_WANT_ASYNC / HITLS_WANT_ASYNC_JOB.
 @ */
/* BEGIN_CASE */
void SDV_TLS_ASYNC_GETERROR_TC005(void)
{
#ifndef HITLS_TLS_FEATURE_MODE_ASYNC
    SKIP_TEST();
#else
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    HITLS_Ctx *ctx = NULL;
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_GetError(NULL, HITLS_ASYNC_ERR_PAUSED), HITLS_ERR_SYSCALL);
    ASSERT_EQ(HITLS_GetError(ctx, HITLS_SUCCESS), HITLS_SUCCESS);
    /* rwstate is not HITLS_ASYNC_PAUSED: no WANT_ASYNC mapping. */
    ASSERT_NE(HITLS_GetError(ctx, HITLS_ASYNC_ERR_PAUSED), HITLS_WANT_ASYNC);
    ASSERT_NE(HITLS_GetError(ctx, HITLS_ASYNC_ERR_NO_JOB), HITLS_WANT_ASYNC_JOB);
EXIT:
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
#endif
}
/* END_CASE */

/**
 * @test SDV_TLS_ASYNC_BACKEND_UNSUPPORTED_TC006
 * @brief
 *   1. Enable the async mode and drive the six protocol entries on a backend that
 *      reports no support.
 * @expect
 *   1. Every entry returns HITLS_ASYNC_ERR_UNSUPPORTED with rwstate HITLS_NOTHING,
 *      no outstanding task is left, and Clear/Close are not rejected.
 @ */
/* BEGIN_CASE */
void SDV_TLS_ASYNC_BACKEND_UNSUPPORTED_TC006(void)
{
#ifndef HITLS_TLS_FEATURE_MODE_ASYNC
    SKIP_TEST();
#else
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    HITLS_Ctx *ctx = NULL;
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetModeSupport(config, HITLS_MODE_ASYNC), HITLS_SUCCESS);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    uint8_t buf[8] = {0};
    uint32_t len = 0;
    ASSERT_EQ(HITLS_Connect(ctx), HITLS_ASYNC_ERR_UNSUPPORTED);
    ASSERT_EQ(HITLS_Accept(ctx), HITLS_ASYNC_ERR_UNSUPPORTED);
    ASSERT_EQ(HITLS_DoHandShake(ctx), HITLS_ASYNC_ERR_UNSUPPORTED);
    ASSERT_EQ(HITLS_Read(ctx, buf, sizeof(buf), &len), HITLS_ASYNC_ERR_UNSUPPORTED);
    ASSERT_EQ(HITLS_Peek(ctx, buf, sizeof(buf), &len), HITLS_ASYNC_ERR_UNSUPPORTED);
    ASSERT_EQ(HITLS_Write(ctx, buf, sizeof(buf), &len), HITLS_ASYNC_ERR_UNSUPPORTED);
    uint8_t rwstate = 0;
    ASSERT_EQ(HITLS_GetRwstate(ctx, &rwstate), HITLS_SUCCESS);
    ASSERT_EQ(rwstate, HITLS_NOTHING);
    int32_t status = BSL_ASYNC_NOTIFY_STATUS_OK;
    ASSERT_EQ(HITLS_GetAsyncStatus(ctx, &status), HITLS_ASYNC_ERR_NOT_PAUSED);
    /* No outstanding task: Clear and Close are not rejected. */
    ASSERT_EQ(HITLS_Clear(ctx), HITLS_SUCCESS);
    ASSERT_NE(HITLS_Close(ctx), HITLS_ASYNC_ERR_OPERATION_BUSY);
EXIT:
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
#endif
}
/* END_CASE */

/**
 * @test SDV_TLS_ASYNC_ENTRY_VALIDATE_TC007
 * @brief
 *   1. Call the six protocol entries with a NULL ctx while the async mode is on.
 *   2. Call Read/Peek/Write with invalid parameters while the async mode is off
 *      (the entry validation lives in the internal workers).
 * @expect
 *   1. A NULL ctx returns HITLS_NULL_INPUT from the async controller entry.
 *   2. Parameter errors return HITLS_NULL_INPUT from the internal workers.
 @ */
/* BEGIN_CASE */
void SDV_TLS_ASYNC_ENTRY_VALIDATE_TC007(void)
{
#ifndef HITLS_TLS_FEATURE_MODE_ASYNC
    SKIP_TEST();
#else
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    HITLS_Config *plainConfig = HITLS_CFG_NewTLS13Config();
    HITLS_Ctx *ctx = NULL;
    HITLS_Ctx *plainCtx = NULL;
    ASSERT_TRUE(config != NULL);
    ASSERT_TRUE(plainConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetModeSupport(config, HITLS_MODE_ASYNC), HITLS_SUCCESS);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    plainCtx = HITLS_New(plainConfig);
    ASSERT_TRUE(plainCtx != NULL);
    uint8_t buf[8] = {0};
    uint32_t len = 0;
    /* NULL ctx: guarded by the async controller entry in the async mode. */
    ASSERT_EQ(HITLS_Connect(NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_Accept(NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_DoHandShake(NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_Read(NULL, buf, sizeof(buf), &len), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_Peek(NULL, buf, sizeof(buf), &len), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_Write(NULL, buf, sizeof(buf), &len), HITLS_NULL_INPUT);
    /* Parameter errors: validated by the internal workers on the direct path. */
    ASSERT_EQ(HITLS_Read(plainCtx, NULL, sizeof(buf), &len), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_Read(plainCtx, buf, sizeof(buf), NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_Peek(plainCtx, NULL, sizeof(buf), &len), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_Peek(plainCtx, buf, sizeof(buf), NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_Write(plainCtx, NULL, sizeof(buf), &len), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_Write(plainCtx, buf, 0, &len), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_Write(plainCtx, buf, sizeof(buf), NULL), HITLS_NULL_INPUT);
    (void)ctx;
EXIT:
    HITLS_Free(ctx);
    HITLS_Free(plainCtx);
    HITLS_CFG_FreeConfig(config);
    HITLS_CFG_FreeConfig(plainConfig);
#endif
}
/* END_CASE */

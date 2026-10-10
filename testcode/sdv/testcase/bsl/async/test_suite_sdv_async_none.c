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

/* INCLUDE_BASE test_suite_sdv_async */

/* BEGIN_HEADER */
#if !defined(HITLS_BSL_ASYNC_UCONTEXT) || (!defined(HITLS_BSL_SAL_LINUX) && !defined(HITLS_BSL_SAL_DARWIN))
#define ASYNC_NO_BACKEND_TEST

static uint32_t g_freeCount;

static void CountFree(void *ptr)
{
    if (ptr != NULL) {
        g_freeCount++;
    }
    free(ptr);
}

static void UnusedEntry(void *arg)
{
    (void)arg;
}
#endif
/* END_HEADER */

/**
 * @test SDV_BSL_ASYNC_NONE_TC001
 * @precon No coroutine backend
 * @brief Reject host or task context creation without allocating or changing the output.
 * @expect STATE_CONFLICT is pushed once; the output remains unchanged.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NONE_TC001(int taskContext)
{
#ifdef ASYNC_NO_BACKEND_TEST
    int sentinel;
    BSL_ASYNC_Coroutine *co = (BSL_ASYNC_Coroutine *)&sentinel;
    int32_t ret;

    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(NULL), BSL_NULL_INPUT);
    BSL_ERR_ClearError();
    InjectArm(-1);
    if (taskContext) {
        ret = BSL_SAL_CoroutineCreate(&co, 0, UnusedEntry, NULL);
    } else {
        ret = BSL_SAL_CoroutineInitCurrent(&co);
    }
    ASSERT_EQ(ret, BSL_ASYNC_ERR_STATE_CONFLICT);
    ASSERT_TRUE(co == (BSL_ASYNC_Coroutine *)&sentinel);
    ASSERT_EQ(g_allocCount, 0);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_ASYNC_ERR_STATE_CONFLICT);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
EXIT:
    InjectDisarm();
    if (co != (BSL_ASYNC_Coroutine *)&sentinel) {
        BSL_SAL_CoroutineDestroy(co);
    }
#else
    (void)taskContext;
    SKIP_TEST();
#endif
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_ASYNC_NONE_TC002
 * @precon No coroutine backend; POSIX thread-local storage
 * @brief Repeat domain initialization with or without preallocated tasks, then try task startup.
 * @expect Initialization rolls back with STATE_CONFLICT; startup returns UNSUPPORTED without allocations.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NONE_TC002(int initialTasks)
{
#if defined(ASYNC_NO_BACKEND_TEST) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_TaskParam param = {NULL, jobSync, NULL, 0};
    int32_t ret = -1;

    BSL_ASYNC_CleanupThread();
    BSL_ERR_ClearError();
    for (uint32_t i = 0; i < 2; i++) {
        InjectArm(-1);
        g_freeCount = 0;
        (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, CountFree);
        ASSERT_EQ(BSL_ASYNC_InitThread(1, (uint32_t)initialTasks, 0), BSL_ASYNC_ERR_STATE_CONFLICT);
        ASSERT_EQ(g_allocCount, g_freeCount);
        ASSERT_EQ(BSL_ERR_GetLastError(), BSL_ASYNC_ERR_STATE_CONFLICT);
        ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
        ASSERT_TRUE(BSL_ASYNC_GetCurrentTask() == NULL);
        BSL_ERR_ClearError();
    }
    InjectArm(-1);
    ASSERT_TRUE(!BSL_SAL_CoroutineIsSupported());
    ASSERT_TRUE(!BSL_ASYNC_IsSupported());
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_UNSUPPORTED);
    ASSERT_EQ(g_allocCount, 0);
    ASSERT_TRUE(task == NULL);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
EXIT:
    BSL_ASYNC_CleanupThread();
    InjectDisarm();
#else
    (void)initialTasks;
    SKIP_TEST();
#endif
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_ASYNC_NONE_TC003
 * @precon No coroutine backend
 * @brief Check null arguments, rejected switching and no-op destruction.
 * @expect Null arguments fail, Destroy is a no-op that pushes no error and
 * has no return value (destruction cannot fail), and switching returns STATE_CONFLICT.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_NONE_TC003(void)
{
#ifdef ASYNC_NO_BACKEND_TEST
    BSL_ASYNC_Coroutine *co = NULL;

    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(NULL), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_SAL_CoroutineCreate(NULL, 0, UnusedEntry, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, 0, NULL, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(NULL, NULL), BSL_NULL_INPUT);
    BSL_ERR_ClearError();
    BSL_SAL_CoroutineDestroy(NULL);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
    co = BSL_SAL_Malloc(1);
    ASSERT_TRUE(co != NULL);
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(co, co), BSL_ASYNC_ERR_STATE_CONFLICT);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_ASYNC_ERR_STATE_CONFLICT);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
    /* No coroutine object can exist on this build: destruction of any
     * pointer is a no-op that pushes no error and frees nothing. */
    BSL_SAL_CoroutineDestroy(co);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
EXIT:
    BSL_SAL_FREE(co);
#else
    SKIP_TEST();
#endif
    return;
}
/* END_CASE */

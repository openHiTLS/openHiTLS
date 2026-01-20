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

#include <unistd.h>
#include <pthread.h>
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "sal_atomic.h"

#define TEST_THREAD_ATOMICADD_CNT 1000000
#define TEST_ATOMIC_ADD_PID_CNT 3
#define TEST_ATOMIC_SUB_PID_CNT 3
int g_threadStartNum = 0;
static BSL_SAL_ThreadLockHandle g_lock = NULL;

static void *TestAtomicAdd(void *arg)
{
    (void)arg;
    int ref = 0;
    int ret = 0;
    for (int i = 0; i < TEST_THREAD_ATOMICADD_CNT; i++) {
        ret = BSL_SAL_AtomicAdd(&g_threadStartNum, 1, &ref, g_lock);
        if (ret != BSL_SUCCESS) {
            return NULL;
        }
    }
    return NULL;
}

static void *TestAtomicSub(void *arg)
{
    (void)arg;
    int ref = 0;
    int ret = 0;
    for (int i = 0; i < TEST_THREAD_ATOMICADD_CNT; i++) {
        ret = BSL_SAL_AtomicAdd(&g_threadStartNum, -1, &ref, g_lock);
        if (ret != BSL_SUCCESS) {
            return NULL;
        }
    }
    return NULL;
}
/* END_HEADER */

/**
 * @test SDV_BSL_SAL_ATOMIC_ADD_TC001
 * @title atomic add test.
 * @precon nan
 * @brief
 *    1. Create thread lock. Expected result 1 is obtained.
 *    2. Create 3 threads to perform addition and one thread to perform subtraction. Expected result 2 is obtained.
 *    3. Check whether the value after execution is consistent with the expected value. Expected result 3 is obtained.
 *    4. Create 2 threads to perform subtraction. Expected result 4 is obtained.
 * @expect
 *    1. create success
 *    2. create success
 *    3. The value at the end of the thread is the same as expected.
 *    4. The value at the end of the thread is the same as expected.
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_ATOMIC_ADD_TC001(void)
{
    ASSERT_TRUE(BSL_SAL_ThreadLockNew(&g_lock) == BSL_SUCCESS);

    pthread_t pid[TEST_ATOMIC_ADD_PID_CNT];
    pthread_t pid2[TEST_ATOMIC_SUB_PID_CNT];
    size_t i;
    for (i = 0u; i < TEST_ATOMIC_ADD_PID_CNT; i++) {
        pthread_create(&pid[i], NULL, TestAtomicAdd, NULL);
    }
    pthread_create(&pid2[0], NULL, TestAtomicSub, NULL);

    for (i = 0u; i < TEST_ATOMIC_ADD_PID_CNT; i++) {
        pthread_join(pid[i], NULL);
    }
    pthread_join(pid2[0], NULL);

    ASSERT_EQ(g_threadStartNum, (TEST_ATOMIC_ADD_PID_CNT - 1) * TEST_THREAD_ATOMICADD_CNT);

    for (i = 1; i < TEST_ATOMIC_SUB_PID_CNT; i++) {
        pthread_create(&pid2[i], NULL, TestAtomicSub, NULL);
    }

    for (i = 1; i < TEST_ATOMIC_SUB_PID_CNT; i++) {
        pthread_join(pid2[i], NULL);
    }
    ASSERT_EQ(g_threadStartNum, 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    g_threadStartNum = 0;
    BSL_SAL_ThreadLockFree(g_lock);
    return;
}
/* END_CASE */

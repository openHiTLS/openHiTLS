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
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
#include <errno.h>
#include <pthread.h>
#include "stub_utils.h"

typedef void (*KeyCleanup)(void *);
STUB_DEFINE_RET2(int, pthread_key_create, pthread_key_t *, KeyCleanup);

static int g_keyCreateError;

static int FailKeyCreate(pthread_key_t *key, KeyCleanup cleanup)
{
    *key = (pthread_key_t)17;
    (void)cleanup;
    return g_keyCreateError;
}
#endif
/* END_HEADER */

/**
 * @test SDV_BSL_ASYNC_THREADLOCAL_TC001
 * @precon POSIX backend with at least 128 available platform keys
 * @brief Keep 128 independent bindings, delete alternating keys, then recreate them.
 * @expect More than 64 keys remain independent through deletion and reuse.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_THREADLOCAL_TC001(void)
{
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    BSL_SAL_ThreadLocalKey keys[128];
    bool created[128] = {false};
    int values[128];

    for (uint32_t i = 0; i < 128; i++) {
        ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&keys[i], NULL), BSL_SUCCESS);
        created[i] = true;
        values[i] = (int)i;
        ASSERT_EQ(BSL_SAL_ThreadLocalSet(keys[i], &values[i]), BSL_SUCCESS);
    }
    for (uint32_t i = 0; i < 128; i++) {
        ASSERT_TRUE(BSL_SAL_ThreadLocalGet(keys[i]) == &values[i]);
    }
    for (uint32_t i = 0; i < 128; i += 2) {
        ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete(keys[i]), BSL_SUCCESS);
        created[i] = false;
    }
    for (uint32_t i = 0; i < 128; i += 2) {
        ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&keys[i], NULL), BSL_SUCCESS);
        created[i] = true;
        ASSERT_TRUE(BSL_SAL_ThreadLocalGet(keys[i]) == NULL);
        ASSERT_EQ(BSL_SAL_ThreadLocalSet(keys[i], &values[i]), BSL_SUCCESS);
    }
    for (uint32_t i = 0; i < 128; i++) {
        ASSERT_TRUE(BSL_SAL_ThreadLocalGet(keys[i]) == &values[i]);
    }
EXIT:
    for (uint32_t i = 0; i < 128; i++) {
        if (created[i]) {
            (void)BSL_SAL_ThreadLocalKeyDelete(keys[i]);
        }
    }
#else
    SKIP_TEST();
#endif
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_ASYNC_THREADLOCAL_TC002
 * @precon POSIX backend
 * @brief Use a SAL-created or native key while the BSL allocator fails.
 * @expect SAL and pthread share bindings without BSL allocations or a private registry.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_THREADLOCAL_TC002(int nativeKey)
{
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    BSL_SAL_ThreadLocalKey key = 0;
    pthread_key_t posixKey;
    bool created = false;
    int value = 1;
    int replacement = 2;

    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(NULL, NULL), BSL_NULL_INPUT);
    BSL_ERR_ClearError();
    InjectArm(0);
    if (nativeKey) {
        ASSERT_EQ(pthread_key_create(&posixKey, NULL), 0);
        key = (BSL_SAL_ThreadLocalKey)posixKey;
    } else {
        ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&key, NULL), BSL_SUCCESS);
        posixKey = (pthread_key_t)key;
    }
    created = true;
    ASSERT_EQ(pthread_setspecific(posixKey, &value), 0);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(key) == &value);
    ASSERT_EQ(BSL_SAL_ThreadLocalSet(key, &replacement), BSL_SUCCESS);
    ASSERT_TRUE(pthread_getspecific(posixKey) == &replacement);
    ASSERT_EQ(BSL_SAL_ThreadLocalSet(key, NULL), BSL_SUCCESS);
    ASSERT_TRUE(pthread_getspecific(posixKey) == NULL);
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete(key), BSL_SUCCESS);
    created = false;
    ASSERT_EQ(g_allocCount, 0);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
EXIT:
    InjectDisarm();
    if (created) {
        if (nativeKey) {
            (void)pthread_key_delete(posixKey);
        } else {
            (void)BSL_SAL_ThreadLocalKeyDelete(key);
        }
    }
#else
    (void)nativeKey;
    SKIP_TEST();
#endif
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_ASYNC_THREADLOCAL_TC003
 * @precon POSIX backend
 * @brief Inject platform key creation failure, then retry and delete the key.
 * @expect Failure preserves the output and existing binding, pushes once and allocates no BSL memory.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_THREADLOCAL_TC003(int platformError)
{
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
    BSL_SAL_ThreadLocalKey existing;
    BSL_SAL_ThreadLocalKey key = (BSL_SAL_ThreadLocalKey)UINTPTR_MAX;
    bool existingCreated = false;
    bool keyCreated = false;
    int value = 1;
    int32_t ret;

    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&existing, NULL), BSL_SUCCESS);
    existingCreated = true;
    ASSERT_EQ(BSL_SAL_ThreadLocalSet(existing, &value), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(NULL, NULL), BSL_NULL_INPUT);
    BSL_ERR_ClearError();
    g_keyCreateError = platformError;
    STUB_REPLACE(pthread_key_create, FailKeyCreate);
    InjectArm(-1);
    ret = BSL_SAL_ThreadLocalKeyCreate(&key, NULL);
    keyCreated = ret == BSL_SUCCESS;
    ASSERT_EQ(ret, BSL_SAL_ERR_NO_MEMORY);
    ASSERT_EQ(key, (BSL_SAL_ThreadLocalKey)UINTPTR_MAX);
    ASSERT_EQ(g_allocCount, 0);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SAL_ERR_NO_MEMORY);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(existing) == &value);
    STUB_RESTORE(pthread_key_create);
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&key, NULL), BSL_SUCCESS);
    keyCreated = true;
    ASSERT_EQ(BSL_SAL_ThreadLocalSet(key, &value), BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(key) == &value);
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete(key), BSL_SUCCESS);
    keyCreated = false;
    ASSERT_EQ(g_allocCount, 0);
EXIT:
    STUB_RESTORE(pthread_key_create);
    if (keyCreated) {
        (void)BSL_SAL_ThreadLocalKeyDelete(key);
    }
    InjectDisarm();
    if (existingCreated) {
        (void)BSL_SAL_ThreadLocalKeyDelete(existing);
    }
#else
    (void)platformError;
    SKIP_TEST();
#endif
    return;
}
/* END_CASE */

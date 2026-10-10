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
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "sal_coroutineimpl.h"
#if defined(__APPLE__) && defined(__MACH__) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE /* Otherwise incomplete ucontext_t structure */
#endif
#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
#include <errno.h>
#include <pthread.h>
#include <ucontext.h>
#endif

static uint32_t g_tlCleanupCount = 0;

static void tlCleanup(void *arg)
{
    (void)arg;
    g_tlCleanupCount++;
}

/* Resident test entry: never returns; every resume counts one
 * round and records the argument it was created with, then switches back to
 * the host. Call-environment misuse is core-guaranteed, the
 * backend keeps no state to detect it, so the entry exercises none of it. */
typedef struct {
    BSL_ASYNC_Coroutine *self;
    BSL_ASYNC_Coroutine *host;
    int calls;
    void *argSeen;
    int32_t switchRet;
} SalEntryArgs;

static void salEntry(void *arg)
{
    SalEntryArgs *a = (SalEntryArgs *)arg;
    while (true) {
        a->calls++;
        a->argSeen = a;
        a->switchRet = BSL_SAL_CoroutineSwitch(a->self, a->host);
    }
}

/* Guard-page probe entry (TC059): walks down its own stack until it crosses
 * the low PROT_NONE page; the access must kill the process by signal. */
static void salOverflowEntry(void *arg)
{
    (void)arg;
    char *probe = (char *)__builtin_frame_address(0);
    while (true) {
        probe -= 256;
        *probe = 1;
    }
}

/* ---------------------- callback backend fixtures ---------------------- */

/* Argument recorder of the dispatch test (TC060): every callback counts its
 * invocation and records the arguments the dispatch layer handed down. */
typedef struct {
    uint32_t isSupportedCalls;
    uint32_t initCalls;
    uint32_t createCalls;
    uint32_t switchCalls;
    uint32_t destroyCalls;
    uint32_t lastStackSize;
    BSL_SAL_CoroutineEntry lastEntry;
    void *lastArg;
    BSL_ASYNC_Coroutine *lastFrom;
    BSL_ASYNC_Coroutine *lastTo;
    bool probeRet;
    int32_t initRet;
    int32_t createRet;
    int32_t switchRet;
} CbRecorder;

static CbRecorder g_cbRec;

static bool CbProbe(void)
{
    g_cbRec.isSupportedCalls++;
    return g_cbRec.probeRet;
}

static int32_t CbInitCurrent(BSL_ASYNC_Coroutine **co)
{
    g_cbRec.initCalls++;
    if (g_cbRec.initRet == BSL_SUCCESS) {
        *co = (BSL_ASYNC_Coroutine *)0xC0;
    }
    return g_cbRec.initRet;
}

static int32_t CbCreate(BSL_ASYNC_Coroutine **co, uint32_t stackSize, BSL_SAL_CoroutineEntry entry, void *arg)
{
    g_cbRec.createCalls++;
    g_cbRec.lastStackSize = stackSize;
    g_cbRec.lastEntry = entry;
    g_cbRec.lastArg = arg;
    if (g_cbRec.createRet == BSL_SUCCESS) {
        *co = (BSL_ASYNC_Coroutine *)0xC1;
    }
    return g_cbRec.createRet;
}

static int32_t CbSwitch(BSL_ASYNC_Coroutine *from, BSL_ASYNC_Coroutine *to)
{
    g_cbRec.switchCalls++;
    g_cbRec.lastFrom = from;
    g_cbRec.lastTo = to;
    return g_cbRec.switchRet;
}

static void CbDestroy(BSL_ASYNC_Coroutine *co)
{
    (void)co;
    g_cbRec.destroyCalls++;
}

/* Registers the recorder set, or clears it again when clear is non-zero. */
static void CbRecorderRegister(int clear)
{
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_IS_SUPPORTED_CB_FUNC, clear ? NULL : (void *)CbProbe);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_INIT_CURRENT_CB_FUNC, clear ? NULL : (void *)CbInitCurrent);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_CREATE_CB_FUNC, clear ? NULL : (void *)CbCreate);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_SWITCH_CB_FUNC, clear ? NULL : (void *)CbSwitch);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_DESTROY_CB_FUNC, clear ? NULL : (void *)CbDestroy);
}

/* ---------------------- thread local callback fixtures ---------------------- */

/* Argument recorder of the thread local dispatch test (TC062): every
 * callback counts its invocation and records the arguments the dispatch
 * layer handed down. */
typedef struct {
    uint32_t createCalls;
    uint32_t deleteCalls;
    uint32_t getCalls;
    uint32_t setCalls;
    BSL_SAL_ThreadLocalCleanup lastCleanup;
    BSL_SAL_ThreadLocalKey lastDeleteKey;
    BSL_SAL_ThreadLocalKey lastGetKey;
    BSL_SAL_ThreadLocalKey lastSetKey;
    void *lastSetValue;
    BSL_SAL_ThreadLocalKey keyToReturn;
    void *getRet;
    int32_t createRet;
    int32_t deleteRet;
    int32_t setRet;
} TlCbRecorder;

static TlCbRecorder g_tlRec;

static int32_t TlCbKeyCreate(BSL_SAL_ThreadLocalKey *key, BSL_SAL_ThreadLocalCleanup cleanup)
{
    g_tlRec.createCalls++;
    g_tlRec.lastCleanup = cleanup;
    if (g_tlRec.createRet == BSL_SUCCESS) {
        *key = g_tlRec.keyToReturn;
    }
    return g_tlRec.createRet;
}

static int32_t TlCbKeyDelete(BSL_SAL_ThreadLocalKey key)
{
    g_tlRec.deleteCalls++;
    g_tlRec.lastDeleteKey = key;
    return g_tlRec.deleteRet;
}

static void *TlCbGet(BSL_SAL_ThreadLocalKey key)
{
    g_tlRec.getCalls++;
    g_tlRec.lastGetKey = key;
    return g_tlRec.getRet;
}

static int32_t TlCbSet(BSL_SAL_ThreadLocalKey key, void *value)
{
    g_tlRec.setCalls++;
    g_tlRec.lastSetKey = key;
    g_tlRec.lastSetValue = value;
    return g_tlRec.setRet;
}

/* Registers the recorder set, or clears it again when clear is non-zero. */
static void TlRecorderRegister(int clear)
{
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_KEY_CREATE_CB_FUNC, clear ? NULL : (void *)TlCbKeyCreate);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_KEY_DELETE_CB_FUNC, clear ? NULL : (void *)TlCbKeyDelete);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_GET_CB_FUNC, clear ? NULL : (void *)TlCbGet);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_SET_CB_FUNC, clear ? NULL : (void *)TlCbSet);
}

#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
/* Real callback backend of the framework test (TC063): native pthread keys,
 * proving the callback interface alone can carry the whole async framework. */
static uint32_t g_tlRealCreateCalls;
static uint32_t g_tlRealDeleteCalls;
static uint32_t g_tlRealGetCalls;
static uint32_t g_tlRealSetCalls;

static int32_t TlRealKeyCreate(BSL_SAL_ThreadLocalKey *key, BSL_SAL_ThreadLocalCleanup cleanup)
{
    pthread_key_t posixKey;
    if (pthread_key_create(&posixKey, cleanup) != 0) {
        return BSL_SAL_ERR_NO_MEMORY;
    }
    *key = (BSL_SAL_ThreadLocalKey)posixKey;
    g_tlRealCreateCalls++;
    return BSL_SUCCESS;
}

static int32_t TlRealKeyDelete(BSL_SAL_ThreadLocalKey key)
{
    g_tlRealDeleteCalls++;
    return pthread_key_delete((pthread_key_t)key) == 0 ? BSL_SUCCESS : BSL_INVALID_ARG;
}

static void *TlRealGet(BSL_SAL_ThreadLocalKey key)
{
    g_tlRealGetCalls++;
    return pthread_getspecific((pthread_key_t)key);
}

static int32_t TlRealSet(BSL_SAL_ThreadLocalKey key, void *value)
{
    int pr = pthread_setspecific((pthread_key_t)key, value);
    g_tlRealSetCalls++;
    if (pr == EINVAL) {
        return BSL_INVALID_ARG;
    }
    if (pr != 0) {
        return BSL_SAL_ERR_NO_MEMORY;
    }
    return BSL_SUCCESS;
}

/* Registers the real callback backend, or clears it again when clear is
 * non-zero. */
static void TlRealRegister(int clear)
{
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_KEY_CREATE_CB_FUNC, clear ? NULL : (void *)TlRealKeyCreate);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_KEY_DELETE_CB_FUNC, clear ? NULL : (void *)TlRealKeyDelete);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_GET_CB_FUNC, clear ? NULL : (void *)TlRealGet);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_SET_CB_FUNC, clear ? NULL : (void *)TlRealSet);
}
#endif

#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
/* Real callback backend of the framework test (TC061): the same ucontext
 * scheme as the built-in backend minus mmap and guard pages, proving the
 * callback interface alone can carry the whole async framework. */
typedef struct {
    ucontext_t uc;
    char *stack; /* malloc'd worker stack; NULL for the host wrapper */
    BSL_SAL_CoroutineEntry entry;
    void *arg;
} CbRealCtx;

static uint32_t g_realInitCalls;
static uint32_t g_realCreateCalls;
static uint32_t g_realSwitchCalls;
static uint32_t g_realDestroyCalls;

static void CbRealShim(
#if UINTPTR_MAX > UINT32_MAX
    uint32_t ptrLow, uint32_t ptrHigh
#else
    uint32_t ptrLow
#endif
)
{
    uintptr_t ptr = (uintptr_t)ptrLow;
#if UINTPTR_MAX > UINT32_MAX
    ptr |= ((uintptr_t)ptrHigh << 32);
#endif
    CbRealCtx *impl = (CbRealCtx *)ptr;
    impl->entry(impl->arg);
    /* A resident entry must never return. */
    abort();
}

static bool CbRealIsSupported(void)
{
    return true;
}

static int32_t CbRealInitCurrent(BSL_ASYNC_Coroutine **co)
{
    CbRealCtx *impl = malloc(sizeof(CbRealCtx));
    if (impl == NULL) {
        return BSL_MALLOC_FAIL;
    }
    if (getcontext(&impl->uc) != 0) {
        free(impl);
        return BSL_SAL_ERR_NO_MEMORY;
    }
    impl->stack = NULL;
    g_realInitCalls++;
    *co = (BSL_ASYNC_Coroutine *)impl;
    return BSL_SUCCESS;
}

static int32_t CbRealCreate(BSL_ASYNC_Coroutine **co, uint32_t stackSize, BSL_SAL_CoroutineEntry entry, void *arg)
{
    CbRealCtx *impl = malloc(sizeof(CbRealCtx));
    if (impl == NULL) {
        return BSL_MALLOC_FAIL;
    }
    if (stackSize == 0) {
        stackSize = 64 * 1024;
    }
    impl->stack = malloc(stackSize);
    if (impl->stack == NULL) {
        free(impl);
        return BSL_MALLOC_FAIL;
    }
    if (getcontext(&impl->uc) != 0) {
        free(impl->stack);
        free(impl);
        return BSL_SAL_ERR_NO_MEMORY;
    }
    impl->uc.uc_stack.ss_sp = impl->stack;
    impl->uc.uc_stack.ss_size = stackSize;
    impl->uc.uc_link = NULL;
    impl->entry = entry;
    impl->arg = arg;
    uintptr_t ptr = (uintptr_t)impl;
#if UINTPTR_MAX > UINT32_MAX
    makecontext(&impl->uc, (void (*)(void))CbRealShim, 2, (uint32_t)ptr, (uint32_t)(ptr >> 32));
#else
    makecontext(&impl->uc, (void (*)(void))CbRealShim, 1, (uint32_t)ptr);
#endif
    g_realCreateCalls++;
    *co = (BSL_ASYNC_Coroutine *)impl;
    return BSL_SUCCESS;
}

static int32_t CbRealSwitch(BSL_ASYNC_Coroutine *from, BSL_ASYNC_Coroutine *to)
{
    CbRealCtx *src = (CbRealCtx *)from;
    CbRealCtx *dst = (CbRealCtx *)to;

    g_realSwitchCalls++;
    if (src == dst) {
        return BSL_ASYNC_ERR_STATE_CONFLICT;
    }
    if (swapcontext(&src->uc, &dst->uc) != 0) {
        return BSL_ASYNC_ERR_COROUTINE_SWITCH;
    }
    return BSL_SUCCESS;
}

static void CbRealDestroy(BSL_ASYNC_Coroutine *co)
{
    CbRealCtx *impl = (CbRealCtx *)co;

    if (impl == NULL) {
        return;
    }
    free(impl->stack);
    free(impl);
    g_realDestroyCalls++;
}

/* Registers the real callback backend, or clears it again when clear is
 * non-zero. */
static void CbRealRegister(int clear)
{
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_IS_SUPPORTED_CB_FUNC, clear ? NULL : (void *)CbRealIsSupported);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_INIT_CURRENT_CB_FUNC, clear ? NULL : (void *)CbRealInitCurrent);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_CREATE_CB_FUNC, clear ? NULL : (void *)CbRealCreate);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_SWITCH_CB_FUNC, clear ? NULL : (void *)CbRealSwitch);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_DESTROY_CB_FUNC, clear ? NULL : (void *)CbRealDestroy);
}
#endif
/* END_HEADER */

/**
 * @test   SDV_BSL_ASYNC_SAL_TLS_TC045
 * @title  BSL_SAL_ThreadLocalKeyCreate success and failure
 * @precon nan
 * @brief
 *    1. Create a key with a cleanup callback and check the key value differs
 *       from the sentinel.
 *    2. Reset the output to the sentinel and create with a NULL output
 *       pointer, expect BSL_NULL_INPUT and the sentinel untouched.
 *    3. Delete the created key, expect BSL_SUCCESS.
 * @expect
 *    1. BSL_SUCCESS and the key value written.
 *    2. BSL_NULL_INPUT, output parameter not modified.
 *    3. BSL_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_TLS_TC045(void)
{
    BSL_SAL_ThreadLocalKey key = (BSL_SAL_ThreadLocalKey)0xDEADBEEF;
    BSL_SAL_ThreadLocalKey createdKey = 0;

    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&key, tlCleanup), BSL_SUCCESS);
    ASSERT_TRUE(key != (BSL_SAL_ThreadLocalKey)0xDEADBEEF);
    createdKey = key;
    key = (BSL_SAL_ThreadLocalKey)0xDEADBEEF;
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(NULL, tlCleanup), BSL_NULL_INPUT);
    ASSERT_TRUE(key == (BSL_SAL_ThreadLocalKey)0xDEADBEEF);
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete(createdKey), BSL_SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_TLS_TC046
 * @title  BSL_SAL_ThreadLocalKeyDelete and BSL_SAL_ThreadLocalGet
 * @precon nan
 * @brief Bind and read a value, then delete the key without invoking its cleanup callback.
 * @expect Set/Get returns the bound pointer; deletion succeeds without running cleanup.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_TLS_TC046(void)
{
    BSL_SAL_ThreadLocalKey key = 0;
    uint32_t cleanupBefore = 0;
    int v1 = 1;

    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&key, tlCleanup), BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(key) == NULL);
    ASSERT_EQ(BSL_SAL_ThreadLocalSet(key, &v1), BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(key) == &v1);
    cleanupBefore = g_tlCleanupCount;
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete(key), BSL_SUCCESS);
    ASSERT_EQ(g_tlCleanupCount - cleanupBefore, 0);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_TLS_TC047
 * @title  BSL_SAL_ThreadLocalSet overwrite and clear
 * @precon nan
 * @brief Overwrite a valid key's binding, clear it, then delete the key.
 * @expect Get returns the latest value before clearing and NULL afterwards.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_TLS_TC047(void)
{
    BSL_SAL_ThreadLocalKey key = 0;
    int v1 = 1;
    int v2 = 2;

    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&key, NULL), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_ThreadLocalSet(key, &v1), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_ThreadLocalSet(key, &v2), BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(key) == &v2);
    ASSERT_EQ(BSL_SAL_ThreadLocalSet(key, NULL), BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(key) == NULL);
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete(key), BSL_SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_TLS_TC048
 * @title  Multiple thread local keys stay independent
 * @precon nan
 * @brief
 *    1. Create two keys and bind a distinct value to the first one; the
 *       second key must still read NULL.
 *    2. Bind a value to the second key and verify both keys read their own
 *       values.
 *    3. Delete the first key while the second key keeps its value; then delete it.
 * @expect
 *    1. Five Get results are &v1, NULL, &v1, &v2 and &v2 in order.
 *    2. All Set/Delete calls return BSL_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_TLS_TC048(void)
{
    BSL_SAL_ThreadLocalKey k1 = 0;
    BSL_SAL_ThreadLocalKey k2 = 0;
    int v1 = 1;
    int v2 = 2;

    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&k1, NULL), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&k2, NULL), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_ThreadLocalSet(k1, &v1), BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(k1) == &v1);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(k2) == NULL);
    ASSERT_EQ(BSL_SAL_ThreadLocalSet(k2, &v2), BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(k1) == &v1);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(k2) == &v2);
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete(k1), BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(k2) == &v2);
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete(k2), BSL_SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_CORO_TC049
 * @title  BSL_SAL_CoroutineIsSupported capability probe
 * @precon nan
 * @brief
 *    1. Call the probe 100 times and verify every call returns the same
 *       value as the first one, and that the value is the expected one for
 *       this build (true with a backend selected, false on the no-backend build).
 *    2. On a backend build, run a create/switch/destroy round and verify the
 *       probe has not disturbed the backend state; on the no-backend build
 *       skip the remaining steps.
 * @expect
 *    1. 100 identical return values matching the build expectation.
 *    2. Backend build: InitCurrent/Create/Switch return BSL_SUCCESS, Destroy
 *       completes (no return value) and the entry ran exactly once.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_CORO_TC049(void)
{
    BSL_ASYNC_Coroutine *host = NULL;
    BSL_ASYNC_Coroutine *task = NULL;
    SalEntryArgs a = {0};
    bool first = BSL_SAL_CoroutineIsSupported();
    int i;

    for (i = 0; i < 100; i++) {
        ASSERT_EQ(BSL_SAL_CoroutineIsSupported(), first);
    }
    if (!first) {
        /* No-backend build: the capability declaration is the assertion. */
        SKIP_TEST();
    }
    ASSERT_TRUE(first);
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&host), BSL_SUCCESS);
    a.host = host;
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&task, 0, salEntry, &a), BSL_SUCCESS);
    a.self = task;
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, task), BSL_SUCCESS);
    ASSERT_EQ(a.calls, 1);
    BSL_SAL_CoroutineDestroy(task);
    BSL_SAL_CoroutineDestroy(host);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_CORO_TC050
 * @title  BSL_SAL_CoroutineInitCurrent parameter and allocation failure
 * @precon nan
 * @brief
 *    1. Call with a NULL output, expect BSL_NULL_INPUT.
 *    2. With the next allocation forced to fail, expect BSL_MALLOC_FAIL and
 *       the output sentinel untouched.
 *    3. Succeed and destroy the host context. Calling InitCurrent more than
 * once per domain is core-guaranteed: the backend keeps
 *       no initialization state, so no repeat-init rejection is asserted.
 * @expect
 *    1. BSL_NULL_INPUT.
 *    2. BSL_MALLOC_FAIL, sentinel preserved.
 *    3. BSL_SUCCESS with a non-NULL handle; Destroy completes (no return value).
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_CORO_TC050(void)
{
    BSL_ASYNC_Coroutine *host = (BSL_ASYNC_Coroutine *)0x5A5A;

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(NULL), BSL_NULL_INPUT);
    InjectArm(0);
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&host), BSL_MALLOC_FAIL);
    ASSERT_TRUE(host == (BSL_ASYNC_Coroutine *)0x5A5A);
    InjectDisarm();
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&host), BSL_SUCCESS);
    ASSERT_TRUE(host != NULL && host != (BSL_ASYNC_Coroutine *)0x5A5A);
    BSL_SAL_CoroutineDestroy(host);
EXIT:
    InjectDisarm();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_CORO_TC051
 * @title  BSL_SAL_CoroutineCreate stack size bounds
 * @precon nan
 * @brief
 *    1. Call with a NULL output or a NULL entry, expect BSL_NULL_INPUT with
 *       the output sentinel untouched.
 *    2. Create with stackSize codes {0, min, max, min-1, max+1, pagesize+1}:
 *       the first three and pagesize+1 succeed, min-1 and max+1 fail with
 *       BSL_INVALID_ARG leaving the sentinel untouched. Being called on the
 * host stack is core-guaranteed, so no call-environment
 *       rejection is asserted.
 * @expect
 *    1. BSL_NULL_INPUT, output untouched.
 *    2. Success for {0, min, max, pagesize+1}, BSL_INVALID_ARG for
 *       {min-1, max+1}, sentinel preserved on every failure.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_CORO_TC051(int sizeCode)
{
    BSL_ASYNC_Coroutine *host = NULL;
    BSL_ASYNC_Coroutine *co = (BSL_ASYNC_Coroutine *)0x5A5A;
    SalEntryArgs a = {0};
    uint32_t stackSize = 0;
    long pageSize = sysconf(_SC_PAGESIZE);
    int32_t expected = BSL_SUCCESS;

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_EQ(BSL_SAL_CoroutineCreate(NULL, 0, salEntry, &a), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, 0, NULL, &a), BSL_NULL_INPUT);
    ASSERT_TRUE(co == (BSL_ASYNC_Coroutine *)0x5A5A);

    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&host), BSL_SUCCESS);
    switch (sizeCode) {
        case 0:
            stackSize = 0;
            break;
        case 1:
            stackSize = BSL_SAL_COROUTINE_MIN_STACK_SIZE;
            break;
        case 2:
            stackSize = BSL_SAL_COROUTINE_MAX_STACK_SIZE;
            break;
        case 3:
            stackSize = BSL_SAL_COROUTINE_MIN_STACK_SIZE - 1;
            expected = BSL_INVALID_ARG;
            break;
        case 4:
            stackSize = BSL_SAL_COROUTINE_MAX_STACK_SIZE + 1;
            expected = BSL_INVALID_ARG;
            break;
        default:
            stackSize = (uint32_t)pageSize + 1;
            break;
    }
    a.host = host;
    co = (BSL_ASYNC_Coroutine *)0x5A5A;
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, stackSize, salEntry, &a), expected);
    if (expected == BSL_INVALID_ARG) {
        ASSERT_TRUE(co == (BSL_ASYNC_Coroutine *)0x5A5A);
    } else {
        ASSERT_TRUE(co != NULL);
        BSL_SAL_CoroutineDestroy(co);
    }
    BSL_SAL_CoroutineDestroy(host);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_CORO_TC052
 * @title  BSL_SAL_CoroutineCreate success path and failure rollback
 * @precon nan
 * @brief
 *    1. With the next allocation forced to fail, expect BSL_MALLOC_FAIL and
 *       the output sentinel untouched.
 *    2. Create successfully, switch in and verify the entry received the
 *       argument pointer it was created with.
 *    3. Create a second coroutine afterwards: the same domain keeps working
 *       after a failed creation.
 * @expect
 *    1. BSL_MALLOC_FAIL, sentinel preserved.
 *    2. BSL_SUCCESS and argSeen equals the argument address.
 *    3. BSL_SUCCESS; all destroys complete (no return value).
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_CORO_TC052(void)
{
    BSL_ASYNC_Coroutine *host = NULL;
    BSL_ASYNC_Coroutine *co = (BSL_ASYNC_Coroutine *)0x5A5A;
    BSL_ASYNC_Coroutine *co2 = NULL;
    SalEntryArgs a = {0};
    SalEntryArgs a2 = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&host), BSL_SUCCESS);
    a.host = host;
    InjectArm(0);
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, 0, salEntry, &a), BSL_MALLOC_FAIL);
    ASSERT_TRUE(co == (BSL_ASYNC_Coroutine *)0x5A5A);
    InjectDisarm();
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, 0, salEntry, &a), BSL_SUCCESS);
    a.self = co;
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, co), BSL_SUCCESS);
    ASSERT_TRUE(a.argSeen == &a);
    a2.host = host;
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co2, 0, salEntry, &a2), BSL_SUCCESS);
    BSL_SAL_CoroutineDestroy(co);
    BSL_SAL_CoroutineDestroy(co2);
    BSL_SAL_CoroutineDestroy(host);
EXIT:
    InjectDisarm();
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_CORO_TC053
 * @title  Two task coroutines alternate under one host context
 * @precon nan
 * @brief
 *    1. Create two coroutines and alternate four host-driven switches
 *       between them, checking each one's round counter and its own argument
 *       after every switch.
 * @expect
 *    1. Every switch returns BSL_SUCCESS; the counters advance one at a time
 *       and independently; each entry saw its own argument.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_CORO_TC053(void)
{
    BSL_ASYNC_Coroutine *host = NULL;
    BSL_ASYNC_Coroutine *coA = NULL;
    BSL_ASYNC_Coroutine *coB = NULL;
    SalEntryArgs aA = {0};
    SalEntryArgs aB = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&host), BSL_SUCCESS);
    aA.host = host;
    aB.host = host;
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&coA, 0, salEntry, &aA), BSL_SUCCESS);
    aA.self = coA;
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&coB, 0, salEntry, &aB), BSL_SUCCESS);
    aB.self = coB;
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, coA), BSL_SUCCESS);
    ASSERT_EQ(aA.calls, 1);
    ASSERT_EQ(aB.calls, 0);
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, coB), BSL_SUCCESS);
    ASSERT_EQ(aA.calls, 1);
    ASSERT_EQ(aB.calls, 1);
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, coA), BSL_SUCCESS);
    ASSERT_EQ(aA.calls, 2);
    ASSERT_EQ(aB.calls, 1);
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, coB), BSL_SUCCESS);
    ASSERT_EQ(aA.calls, 2);
    ASSERT_EQ(aB.calls, 2);
    ASSERT_TRUE(aA.argSeen == &aA);
    ASSERT_TRUE(aB.argSeen == &aB);
    BSL_SAL_CoroutineDestroy(coA);
    BSL_SAL_CoroutineDestroy(coB);
    BSL_SAL_CoroutineDestroy(host);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_CORO_TC054
 * @title  BSL_SAL_CoroutineSwitch parameter validation
 * @precon nan
 * @brief
 *    1. Reject NULL from/to and from == to; execution continues normally
 *       after every rejection. That 'from' is the running context is
 * core-guaranteed, so no such rejection is asserted.
 *    2. Verify the domain still works afterwards with a legal switch.
 * @expect
 *    1. BSL_NULL_INPUT / BSL_ASYNC_ERR_STATE_CONFLICT per case, no switch
 *       performed.
 *    2. The legal switch returns BSL_SUCCESS and the entry ran once.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_CORO_TC054(void)
{
    BSL_ASYNC_Coroutine *host = NULL;
    BSL_ASYNC_Coroutine *co = NULL;
    SalEntryArgs a = {0};
    int guard = 0;

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&host), BSL_SUCCESS);
    a.host = host;
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, 0, salEntry, &a), BSL_SUCCESS);
    a.self = co;
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(NULL, co), BSL_NULL_INPUT);
    ASSERT_EQ(guard, 0);
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(guard, 0);
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, host), BSL_ASYNC_ERR_STATE_CONFLICT);
    ASSERT_EQ(guard, 0);
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, co), BSL_SUCCESS);
    ASSERT_EQ(a.calls, 1);
    BSL_SAL_CoroutineDestroy(co);
    BSL_SAL_CoroutineDestroy(host);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_CORO_TC055
 * @title  BSL_SAL_CoroutineSwitch bidirectional loop
 * @precon nan
 * @brief
 *    1. Enter the coroutine twice: each entry round switches back to the
 *       host, which resumes it once more.
 *    2. Check the task-to-host direction also returns BSL_SUCCESS and that
 *       the second entry continues at its own switch point.
 * @expect
 *    1. Both host-to-task switches return BSL_SUCCESS.
 *    2. switchRet is BSL_SUCCESS and calls reaches 2.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_CORO_TC055(void)
{
    BSL_ASYNC_Coroutine *host = NULL;
    BSL_ASYNC_Coroutine *co = NULL;
    SalEntryArgs a = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&host), BSL_SUCCESS);
    a.host = host;
    a.calls = 0;
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, 0, salEntry, &a), BSL_SUCCESS);
    a.self = co;
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, co), BSL_SUCCESS);
    ASSERT_EQ(a.calls, 1);
    ASSERT_EQ(a.switchRet, BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, co), BSL_SUCCESS);
    ASSERT_EQ(a.calls, 2);
    BSL_SAL_CoroutineDestroy(co);
    BSL_SAL_CoroutineDestroy(host);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_CORO_TC056
 * @title  Host state is stable across many switch round trips
 * @precon nan
 * @brief
 *    1. Drive 100 round trips, advancing a host-side local counter before
 *       each switch and checking it right after.
 * @expect
 *    1. All 100 switches return BSL_SUCCESS, the host counter equals the
 *       round index every time, and the entry counter reaches 100.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_CORO_TC056(void)
{
    BSL_ASYNC_Coroutine *host = NULL;
    BSL_ASYNC_Coroutine *co = NULL;
    SalEntryArgs a = {0};
    int hostRounds = 0;
    int i;

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&host), BSL_SUCCESS);
    a.host = host;
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, 0, salEntry, &a), BSL_SUCCESS);
    a.self = co;
    for (i = 0; i < 100; i++) {
        hostRounds++;
        ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, co), BSL_SUCCESS);
        ASSERT_EQ(hostRounds, i + 1);
        ASSERT_EQ(a.calls, i + 1);
    }
    BSL_SAL_CoroutineDestroy(co);
    BSL_SAL_CoroutineDestroy(host);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_CORO_TC057
 * @title  BSL_SAL_CoroutineDestroy idempotence and destroy order
 * @precon nan
 * @brief
 *    1. Destroy(NULL) is an idempotent no-op.
 *    2. An inactive coroutine (entered once and switched back) is destroyed
 *       successfully.
 *    3. Coroutines are reused across logical rounds, not destroyed per
 *       round: a second coroutine runs two rounds on the same host.
 *    4. The destroy order is task before host, matching the core's
 *       reclamation order. Destroying a running coroutine or the host while
 * tasks are alive is core-guaranteed; the backend keeps
 *       no state to detect it, so no such rejection is asserted.
 * @expect
 *    1. Idempotent no-op for NULL (destruction cannot fail, no return value).
 *    2. The inactive coroutine is destroyed.
 *    3. Both switches into the reused coroutine return BSL_SUCCESS and its
 *       round counter reaches 2.
 *    4. Both ordered destroys complete.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_CORO_TC057(void)
{
    BSL_ASYNC_Coroutine *host = NULL;
    BSL_ASYNC_Coroutine *co = NULL;
    BSL_ASYNC_Coroutine *co2 = NULL;
    SalEntryArgs a = {0};
    SalEntryArgs a2 = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    BSL_SAL_CoroutineDestroy(NULL);
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&host), BSL_SUCCESS);
    a.host = host;
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, 0, salEntry, &a), BSL_SUCCESS);
    a.self = co;
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, co), BSL_SUCCESS);
    ASSERT_EQ(a.calls, 1);
    BSL_SAL_CoroutineDestroy(co);
    /* Reuse before the host is destroyed: a second task runs two rounds on
     * the same host context. */
    a2.host = host;
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co2, 0, salEntry, &a2), BSL_SUCCESS);
    a2.self = co2;
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, co2), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, co2), BSL_SUCCESS);
    ASSERT_EQ(a2.calls, 2);
    BSL_SAL_CoroutineDestroy(co2);
    BSL_SAL_CoroutineDestroy(host);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_CORO_TC058
 * @title  A coroutine created after a destroy is usable
 * @precon nan
 * @brief
 *    1. Create and destroy a coroutine, then create a new one on the same
 *       host and run one round trip.
 *    2. Destroy the host wrapper too, then re-initialize it: the SAL layer
 * keeps no initialization state, so the rebuilt host is
 *       a fresh non-NULL wrapper that still round-trips a new coroutine.
 * @expect
 *    1. The new coroutine is non-NULL, switches and receives its own
 *       argument; all destroys complete (no return value).
 *    2. host2 is non-NULL and differs from host; the co3 round trip succeeds
 *       and both destroys complete.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_CORO_TC058(void)
{
    BSL_ASYNC_Coroutine *host = NULL;
    BSL_ASYNC_Coroutine *host2 = NULL;
    BSL_ASYNC_Coroutine *co = NULL;
    BSL_ASYNC_Coroutine *co2 = NULL;
    BSL_ASYNC_Coroutine *co3 = NULL;
    SalEntryArgs a = {0};
    SalEntryArgs a2 = {0};
    SalEntryArgs a3 = {0};

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&host), BSL_SUCCESS);
    a.host = host;
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, 0, salEntry, &a), BSL_SUCCESS);
    a.self = co;
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, co), BSL_SUCCESS);
    BSL_SAL_CoroutineDestroy(co);
    a2.host = host;
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co2, 0, salEntry, &a2), BSL_SUCCESS);
    ASSERT_TRUE(co2 != NULL);
    a2.self = co2;
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, co2), BSL_SUCCESS);
    ASSERT_EQ(a2.calls, 1);
    ASSERT_TRUE(a2.argSeen == &a2);
    BSL_SAL_CoroutineDestroy(co2);
    BSL_SAL_CoroutineDestroy(host);
    /* Host rebuild after the wrapper was destroyed (steps 6-7). Creating
     * co3 first keeps the allocator from handing the destroyed wrapper's
     * block back to the rebuilt host, so the two host handles stay distinct
     * objects regardless of the allocator's recycling behavior. */
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co3, 0, salEntry, &a3), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&host2), BSL_SUCCESS);
    ASSERT_TRUE(host2 != NULL);
    ASSERT_TRUE(host2 != host);
    a3.host = host2;
    a3.self = co3;
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host2, co3), BSL_SUCCESS);
    ASSERT_EQ(a3.calls, 1);
    ASSERT_TRUE(a3.argSeen == &a3);
    BSL_SAL_CoroutineDestroy(co3);
    BSL_SAL_CoroutineDestroy(host2);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_CORO_TC059
 * @title  Stack page rounding and guard pages
 * @precon nan
 * @brief
 *    1. Create a coroutine with a non-page-aligned stack size (page size + 1)
 *       and run one round trip: the request is accepted and the stack works.
 *    2. In a forked child, enter a coroutine whose entry walks down its own
 *       stack past the low guard page; the child must die from a signal
 *       instead of corrupting adjacent memory.
 * @expect
 *    1. Create and Switch return BSL_SUCCESS; Destroy completes (no return value).
 *    2. The child is terminated by SIGSEGV or SIGBUS.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_CORO_TC059(void)
{
    BSL_ASYNC_Coroutine *host = NULL;
    BSL_ASYNC_Coroutine *co = NULL;
    SalEntryArgs a = {0};
    long pageSize = sysconf(_SC_PAGESIZE);
    pid_t pid;
    int status = 0;

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }
    ASSERT_TRUE(pageSize > 0);
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&host), BSL_SUCCESS);
    a.host = host;
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, (uint32_t)pageSize + 1, salEntry, &a), BSL_SUCCESS);
    a.self = co;
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(host, co), BSL_SUCCESS);
    BSL_SAL_CoroutineDestroy(co);
    BSL_SAL_CoroutineDestroy(host);

    pid = fork();
    if (pid == 0) {
        (void)signal(SIGSEGV, SIG_DFL);
        (void)signal(SIGBUS, SIG_DFL);
        /* Child: own host context, own coroutine, overflow the guard page.
         * No stdio after fork; the process is expected to die by signal. */
        BSL_ASYNC_Coroutine *chost = NULL;
        BSL_ASYNC_Coroutine *cco = NULL;
        if (BSL_SAL_CoroutineInitCurrent(&chost) == BSL_SUCCESS &&
            BSL_SAL_CoroutineCreate(&cco, (uint32_t)pageSize + 1, salOverflowEntry, NULL) == BSL_SUCCESS) {
            (void)BSL_SAL_CoroutineSwitch(chost, cco);
        }
        _exit(0);
    }
    ASSERT_TRUE(pid > 0);
    ASSERT_TRUE(waitpid(pid, &status, 0) == pid);
    ASSERT_TRUE(WIFSIGNALED(status));
    ASSERT_TRUE(WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_BSL_ASYNC_SAL_CORO_TC060
 * @title  Coroutine callback registration and dispatch precedence
 * @precon nan
 * @brief
 *    1. Register coroutine callbacks through BSL_SAL_CallBack_Ctrl;
 *       out-of-range types are rejected.
 *    2. A partial set never takes effect: with only four of the five
 *       callbacks registered the built-in backend keeps serving and no
 *       callback is invoked; completing the set activates it and the probe
 *       returns the callback's value.
 *    3. NULL-input checks still reject in the dispatch layer before any
 *       callback is invoked; Create/InitCurrent/Switch/Destroy dispatch to
 *       the callbacks with the arguments unchanged; a callback error is
 *       returned and pushed onto the error stack exactly once.
 *    4. Clearing any one callback deactivates the whole set again (built-in
 *       behavior returns), re-registering it reactivates the set, and
 *       clearing everything restores the built-in capability declaration.
 * @expect
 *    1. Every registration returns BSL_SUCCESS; foreign types return
 *       BSL_SAL_ERR_BAD_PARAM.
 *    2. While the set is incomplete IsSupported returns the built-in value
 *       with zero callback invocations and Create is served by the built-in
 *       backend (success on a backend build, STATE_CONFLICT otherwise);
 *       after the fifth registration the probe returns the callback value
 *       twice with two callback calls.
 *    3. NULL inputs return BSL_NULL_INPUT with zero callback invocations;
 *       callbacks observe the exact stackSize/entry/arg/from/to; a forced
 *       BSL_INVALID_ARG and BSL_SAL_ERR_NO_MEMORY are returned unchanged
 *       and each read once from the error stack; Destroy(NULL) stays in the
 *       dispatch layer.
 *    4. After clearing one callback IsSupported returns the built-in value
 *       and Create is built-in again with unchanged callback counters;
 *       after re-registering it the probe returns the callback value; after
 *       clearing all five the built-in declaration is restored.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_CORO_TC060(void)
{
    BSL_ASYNC_Coroutine *co = (BSL_ASYNC_Coroutine *)0x5A5A;
    SalEntryArgs a = {0};
    bool builtIn = BSL_SAL_CoroutineIsSupported();

    g_cbRec = (CbRecorder){0};

    /* Step 1: registration boundaries. */
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl((BSL_SAL_CB_FUNC_TYPE)(BSL_SAL_COROUTINE_DESTROY_CB_FUNC + 1), NULL),
              BSL_SAL_ERR_BAD_PARAM);
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MAX_FUNC_CB, NULL), BSL_SAL_ERR_BAD_PARAM);

    /* Step 2: a partial set is not used at all. Register four of the five
     * callbacks: the built-in backend keeps serving and no callback runs. */
    g_cbRec.probeRet = !builtIn;
    g_cbRec.initRet = BSL_SUCCESS;
    g_cbRec.createRet = BSL_SUCCESS;
    g_cbRec.switchRet = BSL_SUCCESS;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_IS_SUPPORTED_CB_FUNC, (void *)CbProbe), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_INIT_CURRENT_CB_FUNC, (void *)CbInitCurrent), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_CREATE_CB_FUNC, (void *)CbCreate), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_SWITCH_CB_FUNC, (void *)CbSwitch), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_CoroutineIsSupported(), builtIn);
    ASSERT_EQ(g_cbRec.isSupportedCalls, 0);
    if (builtIn) {
        /* The built-in backend serves Create and Destroy. */
        ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, BSL_SAL_COROUTINE_MIN_STACK_SIZE, salEntry, &a), BSL_SUCCESS);
        ASSERT_TRUE(co != NULL && co != (BSL_ASYNC_Coroutine *)0xC1);
        BSL_SAL_CoroutineDestroy(co);
    } else {
        ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, BSL_SAL_COROUTINE_MIN_STACK_SIZE, salEntry, &a),
                  BSL_ASYNC_ERR_STATE_CONFLICT);
    }
    co = (BSL_ASYNC_Coroutine *)0x5A5A;
    ASSERT_EQ(g_cbRec.createCalls, 0);
    ASSERT_EQ(g_cbRec.destroyCalls, 0);

    /* Completing the set activates it: the callback probe takes precedence
     * over the built-in one. */
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_DESTROY_CB_FUNC, (void *)CbDestroy), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_CoroutineIsSupported(), g_cbRec.probeRet);
    ASSERT_EQ(BSL_SAL_CoroutineIsSupported(), g_cbRec.probeRet);
    ASSERT_EQ(g_cbRec.isSupportedCalls, 2);

    /* Step 3: NULL inputs stay in the dispatch layer: no callback runs, the
     * output is untouched. */
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(NULL), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_SAL_CoroutineCreate(NULL, 0, salEntry, &a), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, 0, NULL, &a), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_SAL_CoroutineSwitch(NULL, (BSL_ASYNC_Coroutine *)0xD1), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_SAL_CoroutineSwitch((BSL_ASYNC_Coroutine *)0xD1, NULL), BSL_NULL_INPUT);
    ASSERT_TRUE(co == (BSL_ASYNC_Coroutine *)0x5A5A);
    ASSERT_EQ(g_cbRec.initCalls + g_cbRec.createCalls + g_cbRec.switchCalls + g_cbRec.destroyCalls, 0);

    /* Step 4a: a callback error is returned unchanged and pushed exactly
     * once (by the dispatch layer). */
    g_cbRec.createRet = BSL_INVALID_ARG;
    BSL_ERR_ClearError();
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, 4096, salEntry, &a), BSL_INVALID_ARG);
    ASSERT_TRUE(co == (BSL_ASYNC_Coroutine *)0x5A5A);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
    g_cbRec.initRet = BSL_SAL_ERR_NO_MEMORY;
    co = (BSL_ASYNC_Coroutine *)0x5A5A;
    BSL_ERR_ClearError();
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&co), BSL_SAL_ERR_NO_MEMORY);
    ASSERT_TRUE(co == (BSL_ASYNC_Coroutine *)0x5A5A);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SAL_ERR_NO_MEMORY);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);

    /* Step 4b: the success path hands the arguments down unchanged. */
    g_cbRec.initRet = BSL_SUCCESS;
    g_cbRec.createRet = BSL_SUCCESS;
    ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, 4096, salEntry, &a), BSL_SUCCESS);
    ASSERT_TRUE(co == (BSL_ASYNC_Coroutine *)0xC1);
    ASSERT_EQ(g_cbRec.lastStackSize, 4096);
    ASSERT_TRUE(g_cbRec.lastEntry == salEntry);
    ASSERT_TRUE(g_cbRec.lastArg == &a);
    ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&co), BSL_SUCCESS);
    ASSERT_TRUE(co == (BSL_ASYNC_Coroutine *)0xC0);
    ASSERT_EQ(BSL_SAL_CoroutineSwitch((BSL_ASYNC_Coroutine *)0xD1, (BSL_ASYNC_Coroutine *)0xD2), BSL_SUCCESS);
    ASSERT_TRUE(g_cbRec.lastFrom == (BSL_ASYNC_Coroutine *)0xD1);
    ASSERT_TRUE(g_cbRec.lastTo == (BSL_ASYNC_Coroutine *)0xD2);
    /* Destroy(NULL) is an idempotent no-op owned by the dispatch layer. */
    BSL_SAL_CoroutineDestroy(NULL);
    ASSERT_EQ(g_cbRec.destroyCalls, 0);
    BSL_SAL_CoroutineDestroy((BSL_ASYNC_Coroutine *)0xD3);
    ASSERT_EQ(g_cbRec.destroyCalls, 1);

    /* Step 5: clearing any one callback deactivates the whole set. */
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_IS_SUPPORTED_CB_FUNC, NULL), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_CoroutineIsSupported(), builtIn);
    ASSERT_EQ(g_cbRec.isSupportedCalls, 2);
    if (builtIn) {
        ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, BSL_SAL_COROUTINE_MIN_STACK_SIZE, salEntry, &a), BSL_SUCCESS);
        ASSERT_TRUE(co != NULL && co != (BSL_ASYNC_Coroutine *)0xC1);
        BSL_SAL_CoroutineDestroy(co);
    } else {
        ASSERT_EQ(BSL_SAL_CoroutineCreate(&co, BSL_SAL_COROUTINE_MIN_STACK_SIZE, salEntry, &a),
                  BSL_ASYNC_ERR_STATE_CONFLICT);
    }
    co = (BSL_ASYNC_Coroutine *)0x5A5A;
    ASSERT_EQ(g_cbRec.createCalls, 2);
    ASSERT_EQ(g_cbRec.destroyCalls, 1);

    /* Step 6: re-registering the missing callback reactivates the set. */
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_IS_SUPPORTED_CB_FUNC, (void *)CbProbe), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_CoroutineIsSupported(), g_cbRec.probeRet);
    ASSERT_EQ(g_cbRec.isSupportedCalls, 3);

    /* Step 7: clearing everything restores the built-in declaration. */
    CbRecorderRegister(1);
    ASSERT_EQ(BSL_SAL_CoroutineIsSupported(), builtIn);
    if (builtIn) {
        /* The built-in backend serves context requests again. */
        ASSERT_EQ(BSL_SAL_CoroutineInitCurrent(&co), BSL_SUCCESS);
        ASSERT_TRUE(co != NULL && co != (BSL_ASYNC_Coroutine *)0xC0);
        BSL_SAL_CoroutineDestroy(co);
    }
    co = NULL;
    ASSERT_EQ(g_cbRec.isSupportedCalls, 3);
EXIT:
    CbRecorderRegister(1);
    return;
}
/* END_CASE */

#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
/**
 * @test   SDV_BSL_ASYNC_SAL_CORO_TC061
 * @title  A callback backend drives the whole async framework
 * @precon nan
 * @brief
 *    1. Register four of the five callbacks of a ucontext-based callback
 *       backend: the set stays inactive and the capability declaration
 *       keeps its built-in value; completing the set activates it.
 *    2. Initialize an execution domain: the host context and every task
 *       coroutine must be created through the callbacks, also on a build
 *       whose built-in backend is available.
 *    3. Run one pausing task and one synchronous task to completion on the
 *       callback backend, then clean the domain up: contexts are destroyed
 *       through the callback too.
 *    4. Clear the callbacks and verify the capability declaration falls
 *       back to the pre-registration value.
 * @expect
 *    1. With four callbacks registered IsSupported returns the built-in
 *       value; after the fifth registration it returns 1.
 *    2. InitThread succeeds with exactly one callback InitCurrent and no
 *       Create before the first task.
 *    3. StartTask returns BSL_ASYNC_PAUSE then BSL_ASYNC_FINISH with the
 *       business value; the synchronous task finishes immediately; callback
 *       Create and Switch counts grow; after CleanupThread the callback
 *       Destroy count has grown.
 *    4. IsSupported returns the pre-registration value.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_CORO_TC061(void)
{
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_TaskParam param = {0};
    int32_t ret = 0;
    bool builtIn = BSL_SAL_CoroutineIsSupported();
    uint32_t destroysBefore = 0;
    uint32_t createsAfterFirst = 0;
    uint32_t switchesAfterFirst = 0;

    g_realInitCalls = 0;
    g_realCreateCalls = 0;
    g_realSwitchCalls = 0;
    g_realDestroyCalls = 0;
    BSL_ASYNC_CleanupThread();

    /* Step 1: a partial set stays inactive - four of the five callbacks
     * leave the capability declaration at the built-in value. */
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_IS_SUPPORTED_CB_FUNC, (void *)CbRealIsSupported);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_INIT_CURRENT_CB_FUNC, (void *)CbRealInitCurrent);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_CREATE_CB_FUNC, (void *)CbRealCreate);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_SWITCH_CB_FUNC, (void *)CbRealSwitch);
    ASSERT_EQ(BSL_SAL_CoroutineIsSupported(), builtIn);
    ASSERT_EQ(g_realInitCalls, 0);
    /* Completing the set activates the callback backend. */
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_COROUTINE_DESTROY_CB_FUNC, (void *)CbRealDestroy);
    ASSERT_TRUE(BSL_SAL_CoroutineIsSupported());

    /* Step 2: the domain (host context) is established through the
     * callbacks; no task coroutine exists yet. */
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(g_realInitCalls, 1);
    ASSERT_EQ(g_realCreateCalls, 0);

    /* Step 3: pausing task - create, switch in, switch back. */
    param.func = jobPauseOnce;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_PAUSE);
    ASSERT_TRUE(task != NULL);
    ASSERT_TRUE(g_realCreateCalls >= 1);
    ASSERT_TRUE(g_realSwitchCalls >= 1);
    createsAfterFirst = g_realCreateCalls;
    switchesAfterFirst = g_realSwitchCalls;
    destroysBefore = g_realDestroyCalls;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, NULL), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, JOB_SYNC_RET);
    ASSERT_TRUE(task == NULL);

    /* Synchronous task: recycles the physical coroutine through the same
     * callback backend (the entry still runs on the coroutine stack, so
     * switches grow while creations do not). */
    param.func = jobSync;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, JOB_SYNC_RET);
    ASSERT_TRUE(task == NULL);
    ASSERT_EQ(g_realCreateCalls, createsAfterFirst);
    ASSERT_TRUE(g_realSwitchCalls > switchesAfterFirst);

    /* Domain teardown destroys the contexts through the callback. */
    BSL_ASYNC_CleanupThread();
    ASSERT_TRUE(g_realDestroyCalls > destroysBefore);

    /* Step 4: clearing restores the built-in capability declaration. */
    CbRealRegister(1);
    ASSERT_EQ(BSL_SAL_CoroutineIsSupported(), builtIn);
EXIT:
    /* Teardown order: the live domain must be destroyed while the callback
     * backend is still registered (its contexts), then the callbacks are
     * cleared. */
    BSL_ASYNC_CleanupThread();
    CbRealRegister(1);
    return;
}
/* END_CASE */
#endif

/**
 * @test   SDV_BSL_ASYNC_SAL_TLS_TC062
 * @title  Thread local callback registration and dispatch precedence
 * @precon nan
 * @brief
 *    1. Register thread local callbacks through BSL_SAL_CallBack_Ctrl;
 *       out-of-range types are rejected.
 *    2. A partial set never takes effect: with only three of the four
 *       callbacks registered the built-in backend keeps serving and no
 *       callback is invoked; completing the set activates it and KeyCreate
 *       returns the callback's key with the cleanup callback forwarded.
 *    3. The NULL-input check still rejects in the dispatch layer before any
 *       callback is invoked; Delete/Get/Set dispatch to the callbacks with
 *       the arguments unchanged; a callback error is returned and pushed
 *       onto the error stack exactly once.
 *    4. Clearing any one callback deactivates the whole set (built-in
 *       behavior returns), re-registering it reactivates the set, and
 *       clearing everything restores the built-in backend.
 * @expect
 *    1. Every registration returns BSL_SUCCESS; foreign types return
 *       BSL_SAL_THREAD_LOCK_NO_REG_FUNC / BSL_SAL_ERR_BAD_PARAM.
 *    2. While the set is incomplete KeyCreate returns the pre-registration
 *       built-in result with zero callback invocations; after the fourth
 *       registration KeyCreate returns BSL_SUCCESS with the callback key.
 *    3. A NULL output returns BSL_NULL_INPUT with zero callback
 *       invocations; callbacks observe the exact key/value arguments; forced
 *       BSL_INVALID_ARG and BSL_SAL_ERR_NO_MEMORY are returned unchanged
 *       and each read once from the error stack.
 *    4. After clearing one callback KeyCreate returns the built-in result
 *       with unchanged callback counters; after re-registering it KeyCreate
 *       returns the callback key; after clearing all four a plain
 *       create/get/set/delete round works through the built-in backend.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_TLS_TC062(void)
{
    BSL_SAL_ThreadLocalKey key = 0;
    BSL_SAL_ThreadLocalKey probeKey = 0;
    int32_t builtInCreate = 0;
    uint32_t cbCallsBefore = 0;
    int v = 1;

    /* Built-in reference behavior, captured before any registration. */
    builtInCreate = BSL_SAL_ThreadLocalKeyCreate(&probeKey, NULL);
    if (builtInCreate == BSL_SUCCESS) {
        ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete(probeKey), BSL_SUCCESS);
    }

    g_tlRec = (TlCbRecorder){0};
    g_tlRec.createRet = BSL_SUCCESS;
    g_tlRec.deleteRet = BSL_SUCCESS;
    g_tlRec.setRet = BSL_SUCCESS;
    g_tlRec.keyToReturn = (BSL_SAL_ThreadLocalKey)0xC2;
    g_tlRec.getRet = &v;

    /* Step 1: registration boundaries. */
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl((BSL_SAL_CB_FUNC_TYPE)(BSL_SAL_THREAD_LOCAL_SET_CB_FUNC + 1), NULL),
              BSL_SAL_THREAD_LOCK_NO_REG_FUNC);
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_MAX_FUNC_CB, NULL), BSL_SAL_ERR_BAD_PARAM);

    /* Step 2: a partial set is not used at all. Register three of the four
     * callbacks: the built-in backend keeps serving and no callback runs. */
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_KEY_CREATE_CB_FUNC, (void *)TlCbKeyCreate), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_KEY_DELETE_CB_FUNC, (void *)TlCbKeyDelete), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_GET_CB_FUNC, (void *)TlCbGet), BSL_SUCCESS);
    key = 0;
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&key, tlCleanup), builtInCreate);
    if (builtInCreate == BSL_SUCCESS) {
        ASSERT_TRUE(key != (BSL_SAL_ThreadLocalKey)0xC2);
        ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete(key), BSL_SUCCESS);
    }
    ASSERT_EQ(g_tlRec.createCalls, 0);
    ASSERT_EQ(g_tlRec.deleteCalls, 0);
    ASSERT_EQ(g_tlRec.getCalls, 0);
    ASSERT_EQ(g_tlRec.setCalls, 0);

    /* Completing the set activates it. */
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_SET_CB_FUNC, (void *)TlCbSet), BSL_SUCCESS);
    key = 0;
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&key, tlCleanup), BSL_SUCCESS);
    ASSERT_TRUE(key == (BSL_SAL_ThreadLocalKey)0xC2);
    ASSERT_EQ(g_tlRec.createCalls, 1);
    ASSERT_TRUE(g_tlRec.lastCleanup == tlCleanup);

    /* Step 3: the NULL-input check stays in the dispatch layer: no
     * callback runs, the output is untouched. */
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(NULL, tlCleanup), BSL_NULL_INPUT);
    ASSERT_EQ(g_tlRec.createCalls, 1);

    /* Step 4a: a callback error is returned unchanged and pushed exactly
     * once (by the dispatch layer). */
    g_tlRec.createRet = BSL_INVALID_ARG;
    BSL_ERR_ClearError();
    key = 0;
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&key, tlCleanup), BSL_INVALID_ARG);
    ASSERT_TRUE(key == 0);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
    g_tlRec.setRet = BSL_SAL_ERR_NO_MEMORY;
    BSL_ERR_ClearError();
    ASSERT_EQ(BSL_SAL_ThreadLocalSet((BSL_SAL_ThreadLocalKey)0xD1, &v), BSL_SAL_ERR_NO_MEMORY);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SAL_ERR_NO_MEMORY);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
    g_tlRec.deleteRet = BSL_INVALID_ARG;
    BSL_ERR_ClearError();
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete((BSL_SAL_ThreadLocalKey)0xD1), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);

    /* Step 4b: the success path hands the arguments down unchanged. */
    g_tlRec.createRet = BSL_SUCCESS;
    g_tlRec.setRet = BSL_SUCCESS;
    g_tlRec.deleteRet = BSL_SUCCESS;
    key = 0;
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&key, NULL), BSL_SUCCESS);
    ASSERT_TRUE(key == (BSL_SAL_ThreadLocalKey)0xC2);
    ASSERT_EQ(BSL_SAL_ThreadLocalSet((BSL_SAL_ThreadLocalKey)0xD3, &v), BSL_SUCCESS);
    ASSERT_TRUE(g_tlRec.lastSetKey == (BSL_SAL_ThreadLocalKey)0xD3);
    ASSERT_TRUE(g_tlRec.lastSetValue == &v);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet((BSL_SAL_ThreadLocalKey)0xD2) == &v);
    ASSERT_TRUE(g_tlRec.lastGetKey == (BSL_SAL_ThreadLocalKey)0xD2);
    ASSERT_EQ(BSL_SAL_ThreadLocalSet((BSL_SAL_ThreadLocalKey)0xD3, NULL), BSL_SUCCESS);
    ASSERT_TRUE(g_tlRec.lastSetValue == NULL);
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete((BSL_SAL_ThreadLocalKey)0xC2), BSL_SUCCESS);
    ASSERT_TRUE(g_tlRec.lastDeleteKey == (BSL_SAL_ThreadLocalKey)0xC2);

    /* Step 5: clearing any one callback deactivates the whole set. */
    cbCallsBefore = g_tlRec.createCalls + g_tlRec.deleteCalls + g_tlRec.getCalls + g_tlRec.setCalls;
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_GET_CB_FUNC, NULL), BSL_SUCCESS);
    key = 0;
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&key, NULL), builtInCreate);
    if (builtInCreate == BSL_SUCCESS) {
        ASSERT_TRUE(key != (BSL_SAL_ThreadLocalKey)0xC2);
        ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete(key), BSL_SUCCESS);
    }
    ASSERT_EQ(g_tlRec.createCalls + g_tlRec.deleteCalls + g_tlRec.getCalls + g_tlRec.setCalls, cbCallsBefore);

    /* Step 6: re-registering the missing callback reactivates the set. */
    ASSERT_EQ(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_GET_CB_FUNC, (void *)TlCbGet), BSL_SUCCESS);
    key = 0;
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&key, NULL), BSL_SUCCESS);
    ASSERT_TRUE(key == (BSL_SAL_ThreadLocalKey)0xC2);

    /* Step 7: clearing everything restores the built-in backend. */
    TlRecorderRegister(1);
    key = 0;
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&key, NULL), builtInCreate);
    if (builtInCreate == BSL_SUCCESS) {
        ASSERT_TRUE(BSL_SAL_ThreadLocalGet(key) == NULL);
        ASSERT_EQ(BSL_SAL_ThreadLocalSet(key, &v), BSL_SUCCESS);
        ASSERT_TRUE(BSL_SAL_ThreadLocalGet(key) == &v);
        ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete(key), BSL_SUCCESS);
    }
EXIT:
    TlRecorderRegister(1);
    return;
}
/* END_CASE */

#if defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN)
/**
 * @test   SDV_BSL_ASYNC_SAL_TLS_TC063
 * @title  A pthread callback backend drives the whole async framework
 * @precon nan
 * @brief
 *    1. Register three of the four callbacks of a pthread-key-based
 *       callback backend: the set stays inactive and a plain key round
 *       keeps its built-in behavior; completing the set activates it.
 *    2. Initialize an execution domain: the thread local key and the
 *       domain binding must be created through the callbacks.
 *    3. Run one synchronous task to completion on the callback backend,
 *       then clean the domain up: the domain is unbound and the key is
 *       deleted through the callbacks.
 *    4. Clear the callbacks and verify plain key operations are served by
 *       the built-in backend again.
 * @expect
 *    1. With three callbacks registered a plain create/set/get/delete
 *       round succeeds with zero callback invocations.
 *    2. InitThread succeeds with exactly one callback KeyCreate and at
 *       least one callback Set.
 *    3. StartTask returns BSL_ASYNC_FINISH with the business value;
 *       callback Get calls grow; after CleanupThread the callback KeyDelete
 *       count is one and the Set count has grown.
 *    4. A plain key round succeeds with unchanged callback counters.
 */
/* BEGIN_CASE */
void SDV_BSL_ASYNC_SAL_TLS_TC063(void)
{
    BSL_ASYNC_Task *task = NULL;
    BSL_ASYNC_TaskParam param = {0};
    BSL_SAL_ThreadLocalKey key = 0;
    int32_t ret = 0;
    int v = 1;
    uint32_t getsBefore = 0;
    uint32_t setsBefore = 0;
    uint32_t cbCallsBefore = 0;

    if (!ASYNC_BACKEND_READY()) {
        SKIP_TEST();
    }

    /* Retire any domain left by earlier cases so the process key is gone
     * before the callback backend takes over. */
    BSL_ASYNC_CleanupThread();

    g_tlRealCreateCalls = 0;
    g_tlRealDeleteCalls = 0;
    g_tlRealGetCalls = 0;
    g_tlRealSetCalls = 0;

    /* Step 1: a partial set stays inactive - three of the four callbacks
     * leave key operations to the built-in backend. */
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_KEY_CREATE_CB_FUNC, (void *)TlRealKeyCreate);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_KEY_DELETE_CB_FUNC, (void *)TlRealKeyDelete);
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_GET_CB_FUNC, (void *)TlRealGet);
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&key, NULL), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_ThreadLocalSet(key, &v), BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(key) == &v);
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete(key), BSL_SUCCESS);
    ASSERT_EQ(g_tlRealCreateCalls, 0);
    ASSERT_EQ(g_tlRealDeleteCalls, 0);
    ASSERT_EQ(g_tlRealGetCalls, 0);
    ASSERT_EQ(g_tlRealSetCalls, 0);

    /* Completing the set activates the callback backend. */
    (void)BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCAL_SET_CB_FUNC, (void *)TlRealSet);

    /* Step 2: the execution domain (its key and binding) is established
     * through the callbacks. */
    ASSERT_EQ(BSL_ASYNC_InitThread(2, 0, 0), BSL_SUCCESS);
    ASSERT_EQ(g_tlRealCreateCalls, 1);
    ASSERT_TRUE(g_tlRealSetCalls >= 1);

    /* Step 3: a task runs on the callback-backed domain storage. */
    getsBefore = g_tlRealGetCalls;
    param.func = jobSync;
    ASSERT_EQ(BSL_ASYNC_StartTask(&task, &ret, &param), BSL_ASYNC_FINISH);
    ASSERT_EQ(ret, JOB_SYNC_RET);
    ASSERT_TRUE(task == NULL);
    ASSERT_TRUE(g_tlRealGetCalls > getsBefore);

    /* Domain teardown unbinds and deletes the key through the callbacks. */
    ASSERT_EQ(g_tlRealDeleteCalls, 0);
    setsBefore = g_tlRealSetCalls;
    BSL_ASYNC_CleanupThread();
    ASSERT_EQ(g_tlRealDeleteCalls, 1);
    ASSERT_TRUE(g_tlRealSetCalls > setsBefore);

    /* Step 4: clearing restores the built-in backend. */
    cbCallsBefore = g_tlRealCreateCalls + g_tlRealDeleteCalls + g_tlRealGetCalls + g_tlRealSetCalls;
    TlRealRegister(1);
    key = 0;
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyCreate(&key, NULL), BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(key) == NULL);
    ASSERT_EQ(BSL_SAL_ThreadLocalSet(key, &v), BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_ThreadLocalGet(key) == &v);
    ASSERT_EQ(BSL_SAL_ThreadLocalKeyDelete(key), BSL_SUCCESS);
    ASSERT_EQ(g_tlRealCreateCalls + g_tlRealDeleteCalls + g_tlRealGetCalls + g_tlRealSetCalls, cbCallsBefore);
EXIT:
    /* Teardown order: the live domain must be destroyed while the callback
     * backend is still registered (its key), then the callbacks are
     * cleared. */
    BSL_ASYNC_CleanupThread();
    TlRealRegister(1);
    return;
}
/* END_CASE */
#endif

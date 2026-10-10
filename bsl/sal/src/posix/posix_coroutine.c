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

/*
 * macOS quirk: without _XOPEN_SOURCE the SDK exposes an incomplete
 * ucontext_t (the structure the routines write into), and the
 * deprecated-declarations warnings carried by <ucontext.h> would fail the
 * zero-warning gate. The suppression is scoped to this single backend
 * translation unit.
 */
#if defined(__APPLE__) && defined(__MACH__) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE /* Otherwise incomplete ucontext_t structure */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#include "hitls_build.h"

#if defined(HITLS_BSL_ASYNC_UCONTEXT) && (defined(HITLS_BSL_SAL_LINUX) || defined(HITLS_BSL_SAL_DARWIN))

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <ucontext.h>
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "sal_coroutineimpl.h"

/*
 * ucontext coroutine backend.
 *
 * Thin primitive layer: this backend only saves, restores and releases
 * platform execution contexts and checks its own arguments. The dispatch
 * layer (sal_coroutine.c) owns the NULL-input checks and the error stack;
 * what remains here is 'from == to' and the stack size bounds. Call-site
 * conditions - being on the host stack, 'from' being the running context,
 * same execution domain and thread, destroying only inactive coroutines -
 * are asynchronous-scheduling concepts the bsl async core guarantees; this backend keeps no running, ownership or
 * live-task
 * state and does not detect those violations. Bypassing the core and
 * violating the calling environment is undefined behavior.
 */

typedef struct SAL_UC_Coroutine {
    ucontext_t uc;
    char *mapBase; /* mmap base including the low guard page; NULL for the host */
    size_t mapSize; /* total mapping size including both guard pages */
    BSL_SAL_CoroutineEntry entry;
    void *arg;
} SAL_UC_Coroutine;

/* makecontext passes arguments as ints: split the wrapper pointer to two
 * 32-bit halves on 64-bit ABIs. */
static void SAL_UC_EntryShim(
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
    SAL_UC_Coroutine *impl = (SAL_UC_Coroutine *)ptr;
    impl->entry(impl->arg);
    /* The resident entry must never return. */
    abort();
}

bool SAL_UC_CoroutineIsSupported(void)
{
    ucontext_t probe;
    return getcontext(&probe) == 0;
}

int32_t SAL_UC_CoroutineInitCurrent(BSL_ASYNC_Coroutine **co)
{
    SAL_UC_Coroutine *impl = NULL;

    impl = BSL_SAL_Calloc(1, sizeof(SAL_UC_Coroutine));
    if (impl == NULL) {
        return BSL_MALLOC_FAIL;
    }
    /* No worker stack is created: the wrapper only captures the current call
     * stack so the host can later be a Switch target. */
    if (getcontext(&impl->uc) != 0) {
        BSL_SAL_FREE(impl);
        return BSL_SAL_ERR_NO_MEMORY;
    }
    *co = (BSL_ASYNC_Coroutine *)impl;
    return BSL_SUCCESS;
}

int32_t SAL_UC_CoroutineCreate(BSL_ASYNC_Coroutine **co, uint32_t stackSize, BSL_SAL_CoroutineEntry entry, void *arg)
{
    SAL_UC_Coroutine *impl = NULL;
    long pageSize;
    size_t body;
    size_t total;
    uintptr_t ptr;

    if (stackSize == 0) {
        stackSize = BSL_SAL_COROUTINE_DEFAULT_STACK_SIZE;
    }
    if (stackSize < BSL_SAL_COROUTINE_MIN_STACK_SIZE || stackSize > BSL_SAL_COROUTINE_MAX_STACK_SIZE) {
        return BSL_INVALID_ARG;
    }
    pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) {
        return BSL_SAL_ERR_NO_MEMORY;
    }
    /* Round the requested size up to whole pages and add one PROT_NONE guard
     * page at each end: stacks grow downward, so the low page
     * turns an overflow into a signal instead of silent corruption. */
    body = ((stackSize + (size_t)pageSize - 1) / (size_t)pageSize) * (size_t)pageSize;
    total = body + 2 * (size_t)pageSize;

    impl = BSL_SAL_Calloc(1, sizeof(SAL_UC_Coroutine));
    if (impl == NULL) {
        return BSL_MALLOC_FAIL;
    }
    impl->mapBase = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (impl->mapBase == MAP_FAILED) {
        impl->mapBase = NULL;
        BSL_SAL_FREE(impl);
        return BSL_SAL_ERR_NO_MEMORY;
    }
    if (mprotect(impl->mapBase, (size_t)pageSize, PROT_NONE) != 0 ||
        mprotect(impl->mapBase + total - (size_t)pageSize, (size_t)pageSize, PROT_NONE) != 0) {
        (void)munmap(impl->mapBase, total);
        BSL_SAL_FREE(impl);
        return BSL_SAL_ERR_NO_MEMORY;
    }
    impl->mapSize = total;
    impl->entry = entry;
    impl->arg = arg;
    if (getcontext(&impl->uc) != 0) {
        /* Roll back in reverse order of allocation; no mapped stack stays. */
        (void)munmap(impl->mapBase, impl->mapSize);
        BSL_SAL_FREE(impl);
        return BSL_SAL_ERR_NO_MEMORY;
    }
    impl->uc.uc_stack.ss_sp = impl->mapBase + (size_t)pageSize;
    impl->uc.uc_stack.ss_size = body;
    impl->uc.uc_link = NULL;
    ptr = (uintptr_t)impl;
#if UINTPTR_MAX > UINT32_MAX
    makecontext(&impl->uc, (void (*)(void))SAL_UC_EntryShim, 2, (uint32_t)ptr, (uint32_t)(ptr >> 32));
#else
    makecontext(&impl->uc, (void (*)(void))SAL_UC_EntryShim, 1, (uint32_t)ptr);
#endif
    *co = (BSL_ASYNC_Coroutine *)impl;
    return BSL_SUCCESS;
}

int32_t SAL_UC_CoroutineSwitch(BSL_ASYNC_Coroutine *from, BSL_ASYNC_Coroutine *to)
{
    SAL_UC_Coroutine *src = (SAL_UC_Coroutine *)from;
    SAL_UC_Coroutine *dst = (SAL_UC_Coroutine *)to;

    if (src == dst) {
        return BSL_ASYNC_ERR_STATE_CONFLICT;
    }
    /* That the caller really runs on 'from', and that 'from' and 'to' belong
     * to the same execution domain and thread, is core-guaranteed; this backend does not track it. */
    if (swapcontext(&src->uc, &dst->uc) != 0) {
        /* Not switched: the current context keeps running. */
        return BSL_ASYNC_ERR_COROUTINE_SWITCH;
    }
    /* Resumed here: the resuming side performed the matching switch. */
    return BSL_SUCCESS;
}

void SAL_UC_CoroutineDestroy(BSL_ASYNC_Coroutine *co)
{
    SAL_UC_Coroutine *impl = (SAL_UC_Coroutine *)co;

    if (impl == NULL) {
        return;
    }
    /* A NULL mapBase is the host wrapper: it owns no mapped stack. That only
     * inactive tasks are destroyed, and the host last, is core-guaranteed; this backend does not track it. */
    if (impl->mapBase != NULL) {
        (void)munmap(impl->mapBase, impl->mapSize);
    }
    BSL_SAL_FREE(impl);
}

#endif

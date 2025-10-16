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

#ifndef SAL_ATOMIC_H
#define SAL_ATOMIC_H

#include <stdlib.h>
#include "bsl_sal.h"
#include "bsl_errno.h"

/* The value of __STDC_VERSION__ is determined by the compilation option -std.
   The atomic API is provided only when -std=gnu11 is used. */
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) && !defined(HITLS_ATOMIC_THREAD_LOCK)
#include <stdatomic.h>
#define SAL_HAVE_C11_ATOMICS
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

int BSL_SAL_AtomicAdd(int *val, int amount, int *ref, BSL_SAL_ThreadLockHandle lock);

/* Atom operation mode 1, which uses the function provided by C11. Only the int type is considered.
 * ATOMIC_INT_LOCK_FREE: If the value is 1, the operation MAY BE lock-free operation.
 * ATOMIC_INT_LOCK_FREE: If the value is 2, it's the lock-free operation.
 * memory_order_relaxed only ensures the atomicity of the current operation
 * and does not consider the synchronization between threads.
 */
#if defined(SAL_HAVE_C11_ATOMICS) && defined(ATOMIC_INT_LOCK_FREE) && ATOMIC_INT_LOCK_FREE > 0 && !defined(HITLS_ATOMIC_THREAD_LOCK)
#define SAL_USE_ATOMICS_LIB_FUNC
typedef struct {
    atomic_int count;
} BSL_SAL_RefCount;

static inline int BSL_SAL_AtomicUpReferences(BSL_SAL_RefCount *references, int *ret)
{
    *ret = atomic_fetch_add_explicit(&(references->count), 1, memory_order_relaxed) + 1;
    return BSL_SUCCESS;
}

static inline int BSL_SAL_AtomicDownReferences(BSL_SAL_RefCount *references, int *ret)
{
    *ret = atomic_fetch_sub_explicit(&(references->count), 1, memory_order_relaxed) - 1;
    if (*ret == 0) {
        atomic_thread_fence(memory_order_acquire);
    }
    return BSL_SUCCESS;
}

/* Atom operation mode 2, using the function provided by the GCC. */
#elif defined(__GNUC__) && defined(__ATOMIC_RELAXED) && __GCC_ATOMIC_INT_LOCK_FREE > 0 && !defined(HITLS_ATOMIC_THREAD_LOCK)
#define SAL_USE_ATOMICS_LIB_FUNC
typedef struct {
    int count;
} BSL_SAL_RefCount;

static inline int BSL_SAL_AtomicUpReferences(BSL_SAL_RefCount *references, int *ret)
{
    *ret = __atomic_fetch_add(&(references->count), 1, __ATOMIC_RELAXED) + 1;
    return BSL_SUCCESS;
}

static inline int BSL_SAL_AtomicDownReferences(BSL_SAL_RefCount *references, int *ret)
{
    *ret = __atomic_fetch_sub(&(references->count), 1, __ATOMIC_RELAXED) - 1;
    if (*ret == 0) {
        const int type = __ATOMIC_ACQUIRE;
        __atomic_thread_fence(type);
    }
    return BSL_SUCCESS;
}

// Atom operation mode 3, using read/write locks.
#else
typedef struct {
    int count;
    BSL_SAL_ThreadLockHandle lock;
} BSL_SAL_RefCount;

static inline int BSL_SAL_AtomicUpReferences(BSL_SAL_RefCount *references, int *ret)
{
    return BSL_SAL_AtomicAdd(&(references->count), 1, ret, references->lock);
}

static inline int BSL_SAL_AtomicDownReferences(BSL_SAL_RefCount *references, int *ret)
{
    return BSL_SAL_AtomicAdd(&(references->count), -1, ret, references->lock);
}
#endif

#ifdef SAL_USE_ATOMICS_LIB_FUNC
static inline int BSL_SAL_ReferencesInit(BSL_SAL_RefCount *references)
{
    references->count = 1;
    return BSL_SUCCESS;
}

static inline void BSL_SAL_ReferencesFree(BSL_SAL_RefCount *references)
{
    (void)references;
    return;
}
#else
static inline int BSL_SAL_ReferencesInit(BSL_SAL_RefCount *references)
{
    references->count = 1;
    return BSL_SAL_ThreadLockNew(&(references->lock));
}

static inline void BSL_SAL_ReferencesFree(BSL_SAL_RefCount *references)
{
    BSL_SAL_ThreadLockFree(references->lock);
    references->lock = NULL;
    return;
}
#endif

/**
 * @brief Atomic reference up control
 * @param references [IN] Reference count structure, can be NULL
 * @param val [OUT] Value to be added
 * @param len [IN] Length of the value
 * @return BSL_SUCCESS if successful, otherwise an error code
 */
int32_t BSL_SAL_AtomicRefUpCtrl(BSL_SAL_RefCount *references, void *val, uint32_t len);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // SAL_ATOMIC_H

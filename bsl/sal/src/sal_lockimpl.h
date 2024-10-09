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

#ifndef SAL_LOCKIMPL_H
#define SAL_LOCKIMPL_H

#include <stdint.h>
#include "hitls_build.h"
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef HITLS_BSL_SAL_LOCK
int32_t SAL_RwLockNew(BSL_SAL_ThreadLockHandle *lock);

int32_t SAL_RwReadLock(BSL_SAL_ThreadLockHandle rwLock);

int32_t SAL_RwWriteLock(BSL_SAL_ThreadLockHandle rwLock);

int32_t SAL_RwUnlock(BSL_SAL_ThreadLockHandle rwLock);

void SAL_RwLockFree(BSL_SAL_ThreadLockHandle rwLock);
#endif

#ifdef HITLS_BSL_SAL_THREAD
int32_t SAL_PthreadRunOnce(uint32_t *onceControl, BSL_SAL_ThreadInitRoutine initFunc);

uint64_t SAL_GetPid(void);
#endif

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // SAL_LOCKIMPL_H

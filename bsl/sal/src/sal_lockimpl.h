/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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

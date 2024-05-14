/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdint.h>
#include "securec.h"
#include "logger.h"
#include "lock.h"

Lock *OsLockNew(void)
{
    pthread_mutexattr_t attr;
    Lock *lock;

    if ((lock = (Lock *)malloc(sizeof(pthread_mutex_t))) == NULL) {
        LOG_ERROR("OAL_Malloc error");
        return NULL;
    }

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);

    if (pthread_mutex_init(lock, &attr) != 0) {
        LOG_ERROR("pthread_mutex_init error");
        pthread_mutexattr_destroy(&attr);
        free(lock);
        return NULL;
    }

    pthread_mutexattr_destroy(&attr);
    return lock;
}

int OsLock(Lock *lock)
{
    if (pthread_mutex_lock(lock) != 0) {
        LOG_ERROR("pthread_mutex_lock error");
        return -1;
    }
    return 0;
}

int OsUnLock(Lock *lock)
{
    if (pthread_mutex_unlock(lock) != 0) {
        LOG_ERROR("pthread_mutex_unlock error");
        return -1;
    }
    return 0;
}

void OsLockDestroy(Lock *lock)
{
    if (lock == NULL) {
        return;
    }
    pthread_mutex_destroy(lock);
    free(lock);
}

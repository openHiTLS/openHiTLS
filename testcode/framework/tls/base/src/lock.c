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

#include <pthread.h>
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

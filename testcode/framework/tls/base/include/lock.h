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

#ifndef __LOCK_H__
#define __LOCK_H__

#include <pthread.h>

typedef pthread_mutex_t Lock;

/**
* @brief  Create a lock resource
*/
Lock *OsLockNew(void);

/**
* @brief  Lock
*/
int OsLock(Lock *lock);

/**
* @brief  Unlock
*/
int OsUnLock(Lock *lock);

/**
* @brief  Release the lock resource
*/
void OsLockDestroy(Lock *lock);


#endif // __LOCK_H__
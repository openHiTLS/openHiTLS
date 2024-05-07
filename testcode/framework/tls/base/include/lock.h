/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
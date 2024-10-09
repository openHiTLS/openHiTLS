/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "sal_atomic.h"
#include "bsl_errno.h"

int BSL_SAL_AtomicAdd(int *val, int amount, int *ref, BSL_SAL_ThreadLockHandle lock)
{
    if (val == NULL || ref == NULL) {
        return BSL_NULL_INPUT;
    }
    int32_t ret = BSL_SAL_ThreadWriteLock(lock);
    if (ret != 0) {
        return ret;
    }
    *val += amount;
    *ref = *val;
    return BSL_SAL_ThreadUnlock(lock);
}

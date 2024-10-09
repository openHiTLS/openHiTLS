/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_BSL_HASH

#include "hash_local.h"

#ifdef __cplusplus
extern "C" {
#endif

bool IsMultiOverflow(uint32_t x, uint32_t y)
{
    bool ret = false;

    if ((x > 0) && (y > 0)) {
        ret = ((SIZE_MAX / x) < y) ? true : false;
    }

    return ret;
}

bool IsAddOverflow(uint32_t x, uint32_t y)
{
    return ((x + y) < x);
}

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_HASH */

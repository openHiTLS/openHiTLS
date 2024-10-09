/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_BSL_SAL_LINUX) && defined(HITLS_BSL_SAL_MEM)

#include <stdint.h>
#include <stdlib.h>

void *SAL_MallocImpl(uint32_t size)
{
    return malloc(size);
}

void SAL_FreeImpl(void *value)
{
    if (value == NULL) {
        return;
    }
    free(value);
}

#endif

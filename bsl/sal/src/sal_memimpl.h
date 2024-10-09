/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef SAL_MEMIMPL_H
#define SAL_MEMIMPL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_SAL_MEM

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void *SAL_MallocImpl(uint32_t size);

void SAL_FreeImpl(void *value);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_SAL_MEM */

#endif // SAL_MEMIMPL_H

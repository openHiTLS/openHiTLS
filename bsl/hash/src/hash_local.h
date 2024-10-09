/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HASH_LOCAL_H
#define HASH_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_HASH

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef struct {
    uintptr_t inputData;     /* Actual data input by the user. */
    uint32_t dataSize;       /* Actual input size */
} BSL_CstlUserData;

/* Check whether overflow occurs when two numbers are multiplied in the current system. */
bool IsMultiOverflow(uint32_t x, uint32_t y);

/* Check whether the sum of the two numbers overflows in the current system. */
bool IsAddOverflow(uint32_t x, uint32_t y);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_HASH */

#endif /* HASH_LOCAL_H */
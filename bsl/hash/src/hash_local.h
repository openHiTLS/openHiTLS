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
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

#ifndef BSL_BUFFER_H
#define BSL_BUFFER_H

#include "hitls_build.h"
#ifdef HITLS_BSL_BUFFER

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    size_t length;
    char *data;
    size_t max;
} BSL_BufMem;

BSL_BufMem *BSL_BufMemNew(void);
void BSL_BufMemFree(BSL_BufMem *a);
size_t BSL_BufMemGrowClean(BSL_BufMem *str, size_t len);

#ifdef __cplusplus
}
#endif

#endif
#endif
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
#include "hitls_build.h"
#ifdef HITLS_BSL_BUFFER
#include <string.h>
#include "bsl_sal.h"
#include "bsl_buffer.h"

BSL_BufMem *BSL_BufMemNew(void)
{
    BSL_BufMem *ret = NULL;
    ret = BSL_SAL_Malloc(sizeof(BSL_BufMem));
    if (ret == NULL) {
        return NULL;
    }
    
    ret->length = 0;
    ret->max = 0;
    ret->data = NULL;
    
    return ret;
}

void BSL_BufMemFree(BSL_BufMem *a)
{
    if (a == NULL) {
        return;
    }
    
    if (a->data != NULL) {
        BSL_SAL_FREE(a->data);
    }
    
    BSL_SAL_FREE(a);
}

size_t BSL_BufMemGrowClean(BSL_BufMem *str, size_t len)
{
    char *ret = NULL;
    if (str->length >= len) {
        if (len > str->max) {
            return 0;
        }
        memset(&(str->data[len]), 0, str->length - len);
        str->length = len;
        return len;
    }
    if (str->max >= len) {
        memset(&(str->data[str->length]), 0, len - str->length);
        str->length = len;
        return len;
    }
    const size_t n = ((len + 3) / 3) * 4; // actual growth size
    if (n < len || n > UINT32_MAX) { // does not meet growth requirements or overflows
        return 0;
    }
    ret = BSL_SAL_Malloc((uint32_t)n);
    if (ret == NULL) {
        return 0;
    }
    if (str->data != NULL) {
        if (str->max > n) {
            BSL_SAL_Free(ret);
            return 0;
        }
        memcpy(ret, str->data, str->max);
    }
    memset(&ret[str->length], 0, len - str->length);
    BSL_SAL_ClearFree(str->data, (uint32_t)str->max);
    str->data = ret;
    str->max = n;
    str->length = len;
    return len;
}

#endif
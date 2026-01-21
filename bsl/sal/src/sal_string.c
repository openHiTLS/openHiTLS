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
#ifdef HITLS_BSL_SAL_STR

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_sal.h"

int32_t BSL_SAL_StrcaseCmp(const char *str1, const char *str2)
{
    if (str1 == NULL || str2 == NULL) {
        return BSL_NULL_INPUT;
    }
    const char *tmpStr1 = str1;
    const char *tmpStr2 = str2;
    uint8_t t1 = 0;
    uint8_t t2 = 0;
    for (; (*tmpStr1 != '\0') && (*tmpStr2 != '\0'); tmpStr1++, tmpStr2++) {
        t1 = (uint8_t)*tmpStr1;
        t2 = (uint8_t)*tmpStr2;
        if (t1 >= 0x41 && t1 <= 0x5A) {    // 'A' is 0x41, 'Z' is 0x5A
            t1 = t1 + 0x20;                // 'a' - 'A' is  0x20
        }
        if (t2 >= 0x41 && t2 <= 0x5A) {
            t2 = t2 + 0x20;
        }
        if (t1 != t2) {
            break;
        }
    }
    return (int32_t)(*tmpStr1) - (int32_t)(*tmpStr2);
}

void *BSL_SAL_Memchr(const char *str, int32_t character, size_t count)
{
    if (str == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        if ((int32_t)str[i] == character) {
            return (void *)(uintptr_t)(str + i);
        }
    }
    return NULL;
}

int32_t BSL_SAL_Atoi(const char *str)
{
    int val = 0;
    if (str == NULL) {
        return 0;
    }
    if (sscanf_s(str, "%d", &val) != -1) {
        return (int32_t)val;
    }
    return 0;
}

uint32_t BSL_SAL_Strnlen(const char *string, uint32_t count)
{
    uint32_t n;
    const char *pscTemp = string;
    if (pscTemp == NULL) {
        return 0;
    }

    for (n = 0; (n < count) && (*pscTemp != '\0'); n++) {
        pscTemp++;
    }

    return n;
}
#endif // HITLS_BSL_SAL_STR

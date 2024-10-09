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
#if defined(HITLS_BSL_SAL_LINUX) && defined(HITLS_BSL_SAL_STR)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "bsl_errno.h"

int32_t BSL_SAL_StrcaseCmp(const char *str1, const char *str2)
{
    if (str1 == NULL || str2 == NULL) {
        return BSL_NULL_INPUT;
    }
    return strcasecmp(str1, str2);
}

void *BSL_SAL_Memchr(const char *str, int32_t character, size_t count)
{
    if (str == NULL) {
        return NULL;
    }
    return memchr(str, character, count);
}

int32_t BSL_SAL_Atoi(const char *str)
{
    if (str == NULL) {
        return 0;
    }
    return atoi(str);
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
#endif

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

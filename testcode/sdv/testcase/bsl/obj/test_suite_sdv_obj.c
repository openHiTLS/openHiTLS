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

/* BEGIN_HEADER */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_obj.h"
#include "bsl_obj_internal.h"
/* END_HEADER */

extern BslOidInfo g_oidTable[];
extern uint32_t g_tableSize;
/**
 * @test SDV_BSL_OBJ_CID_OID_FUNC_TC001
 * @title check whether the relative sequence of cid and oid tables is corrent
 * @expect success
 */
/* BEGIN_CASE */
void SDV_BSL_OBJ_CID_OID_FUNC_TC001()
{
    int32_t cidIndex = 0;
    int32_t oidIndex = 0;
    int32_t ret = 0;
    while (cidIndex < BSL_CID_MAX && oidIndex < (int32_t)g_tableSize) {
        if ((int32_t)g_oidTable[oidIndex].cid == cidIndex) {
            ret++;
            cidIndex++;
            oidIndex++;
            continue;
        }
        if ((int32_t)g_oidTable[oidIndex].cid > cidIndex) {
            cidIndex++;
            continue;
        }
        oidIndex++;
    }
    ASSERT_TRUE(ret == (int32_t)g_tableSize);
exit:
    return;
}

/* END_CASE */
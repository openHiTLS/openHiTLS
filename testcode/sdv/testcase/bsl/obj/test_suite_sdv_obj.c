/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
    BslCid id = BSL_OBJ_GetCIDFromOid(NULL);
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
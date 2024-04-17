/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef BSL_OBJ_INTERNAL_H
#define BSL_OBJ_INTERNAL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_OBJ

#include "bsl_obj.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BSL_OID_GLOBAL,
    BSL_OID_HEAP
} BslOidFlag;

typedef struct {
    uint32_t octedLen;
    char *octs;
    uint32_t flags;
} BslOidString;

typedef struct {
    BslOidString strOid;
    const char *oidName;
    BslCid cid;
} BslOidInfo;

BslCid BSL_OBJ_GetCIDFromOid(BslOidString *oid);

BslOidString *BSL_OBJ_GetOidFromCID(BslCid inputCid);

#ifdef __cplusplus
}
#endif

#endif

#endif // BSL_OBJ_INTERNAL_H
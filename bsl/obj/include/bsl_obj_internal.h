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
    uint32_t octetLen;
    char *octs;
    uint32_t flags;
} BslOidString;

typedef struct {
    BslOidString strOid;
    const char *oidName;
    BslCid cid;
} BslOidInfo;

typedef struct {
    BslCid cid;
    int32_t min;
    int32_t max;
} BslAsn1StrInfo;

BslCid BSL_OBJ_GetCIDFromOid(BslOidString *oid);

BslOidString *BSL_OBJ_GetOidFromCID(BslCid inputCid);

BslCid BSL_OBJ_GetHashIdFromSignId(BslCid signAlg);

BslCid BSL_OBJ_GetAsymIdFromSignId(BslCid signAlg);

const char *BSL_OBJ_GetOidNameFromOid(const BslOidString *oid);

BslCid BSL_OBJ_GetSignIdFromHashAndAsymId(BslCid asymAlg, BslCid hashAlg);

const BslAsn1StrInfo *BSL_OBJ_GetAsn1StrFromCid(BslCid cid);
#ifdef __cplusplus
}
#endif

#endif

#endif // BSL_OBJ_INTERNAL_H
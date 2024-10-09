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
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

#include <stdint.h>
#include "bsl_obj.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BSL_OID_GLOBAL,
    BSL_OID_HEAP
} BslOidFlag;

typedef struct {
    BslOidString strOid;
    const char *oidName;
    BslCid cid;
} BslOidInfo;

typedef struct {
    BslCid cid;
    int32_t min;
    int32_t max;
    const char *shortName;
} BslAsn1DnInfo;

int32_t OBJ_GetHashIdFromSignId(BslCid signAlg, BslCid *hashId);

BslCid BSL_OBJ_GetAsymAlgIdFromSignId(BslCid signAlg);

const char *BSL_OBJ_GetOidNameFromOid(const BslOidString *oid);

const char *BSL_OBJ_GetOidNameFromOidBuff(const uint8_t *oid, uint32_t oidLen);

BslCid BSL_OBJ_GetSignIdFromHashAndAsymId(BslCid asymAlg, BslCid hashAlg);

const BslAsn1DnInfo *BSL_OBJ_GetDnInfoFromCid(BslCid cid);

const char *BSL_OBJ_GetOidNameFromCID(BslCid ulCID);

const BslAsn1DnInfo *BSL_OBJ_GetDnInfoFromShortName(const char *shortName);

#ifdef HITLS_BSL_OBJ_CUSTOM
void BSL_OBJ_FreeSignHashTable(void);

void BSL_OBJ_FreeHashTable(void);
#endif // HITLS_BSL_OBJ_CUSTOM

BslCid BSL_OBJ_GetCidFromOidBuff(const uint8_t *oid, uint32_t oidLen);

#ifdef __cplusplus
}
#endif

#endif

#endif // BSL_OBJ_INTERNAL_H
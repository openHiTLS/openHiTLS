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
#ifdef HITLS_BSL_OBJ
#include <stddef.h>
#include "bsl_obj.h"
#include "bsl_obj_internal.h"
#include "securec.h"

typedef struct BslSignIdMap {
    BslCid signId;
    BslCid asymId;
    BslCid hashId;
} BSL_SignIdMap;

BSL_SignIdMap g_signIdMap[] = {
    {BSL_CID_SHA1WITHRSA, BSL_CID_RSA, BSL_CID_SHA1},
    {BSL_CID_SHA224WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SHA224},
    {BSL_CID_SHA256WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SHA256},
    {BSL_CID_SHA384WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SHA384},
    {BSL_CID_SHA512WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SHA512},
    {BSL_CID_RSASSAPSS, BSL_CID_RSA, BSL_CID_UNKNOWN},
    {BSL_CID_SM3WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SM3},
    {BSL_CID_DSAWITHSHA1, BSL_CID_DSA, BSL_CID_SHA1},
    {BSL_CID_DSAWITHSHA224, BSL_CID_DSA, BSL_CID_SHA224},
    {BSL_CID_DSAWITHSHA256, BSL_CID_DSA, BSL_CID_SHA256},
    {BSL_CID_DSAWITHSHA384, BSL_CID_DSA, BSL_CID_SHA384},
    {BSL_CID_DSAWITHSHA512, BSL_CID_DSA, BSL_CID_SHA512},
    {BSL_CID_ECDSAWITHSHA1, BSL_CID_ECDSA, BSL_CID_SHA1},
    {BSL_CID_ECDSAWITHSHA224, BSL_CID_ECDSA, BSL_CID_SHA224},
    {BSL_CID_ECDSAWITHSHA256, BSL_CID_ECDSA, BSL_CID_SHA256},
    {BSL_CID_ECDSAWITHSHA384, BSL_CID_ECDSA, BSL_CID_SHA384},
    {BSL_CID_ECDSAWITHSHA512, BSL_CID_ECDSA, BSL_CID_SHA512},
    {BSL_CID_SM2DSAWITHSM3, BSL_CID_SM2, BSL_CID_SM3},
    {BSL_CID_SM2DSAWITHSHA1, BSL_CID_SM2, BSL_CID_SHA1},
    {BSL_CID_SM2DSAWITHSHA256, BSL_CID_SM2, BSL_CID_SHA256},
};

BslCid BSL_OBJ_GetHashIdFromSignId(BslCid signAlg)
{
    if (signAlg == BSL_CID_UNKNOWN) {
        return BSL_CID_UNKNOWN;
    }
    for (uint32_t iter = 0; iter < sizeof(g_signIdMap) / sizeof(BSL_SignIdMap); iter++) {
        if (signAlg == g_signIdMap[iter].signId) {
            return g_signIdMap[iter].hashId;
        }
    }
    return BSL_CID_UNKNOWN;
}

BslCid BSL_OBJ_GetAsymIdFromSignId(BslCid signAlg)
{
    if (signAlg == BSL_CID_UNKNOWN) {
        return BSL_CID_UNKNOWN;
    }
    for (uint32_t iter = 0; iter < sizeof(g_signIdMap) / sizeof(BSL_SignIdMap); iter++) {
        if (signAlg == g_signIdMap[iter].signId) {
            return g_signIdMap[iter].asymId;
        }
    }
    return BSL_CID_UNKNOWN;
}
#endif
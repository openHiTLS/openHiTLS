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

#ifndef HITLS_CMS_UTIL_H
#define HITLS_CMS_UTIL_H

#include "hitls_build.h"
#ifdef HITLS_PKI_CMS
#include "bsl_asn1_internal.h"
#include "bsl_obj.h"
#include "hitls_cms_local.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef HITLS_PKI_CMS_SIGNEDDATA
typedef int32_t (*CMS_AttrDecoder)(HITLS_X509_AttrEntry *attr, void *out);

int32_t CMS_DecodeAttr(HITLS_X509_Attrs *attrs, BslCid attrCid, CMS_AttrDecoder attrDecode, void *out);

int32_t HITLS_CMS_CheckOrGetPqcMd(const CRYPT_EAL_PkeyCtx *key, bool hasSignedAttr, int32_t *mdId,
    bool isStream);

int32_t HITLS_CMS_PrepareSignKey(const CRYPT_EAL_PkeyCtx *prvKey, CRYPT_EAL_PkeyCtx **signKey, bool *freeSignKey);

#endif

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_CMS

#endif // HITLS_CMS_UTIL_H

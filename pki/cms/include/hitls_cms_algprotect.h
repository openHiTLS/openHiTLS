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

#ifndef HITLS_CMS_ALGPROTECT_H
#define HITLS_CMS_ALGPROTECT_H

#include "hitls_build.h"
#ifdef HITLS_PKI_CMS_SIGNEDDATA
#include "hitls_cms_local.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * RFC 6211 Section 2: the digest algorithm and exactly one of the signature
 * or MAC algorithms are copied into the protected attribute.
 */
typedef struct {
    CMS_AlgId digestAlgorithm;
    HITLS_X509_Asn1AlgId signatureAlgorithm;
    CMS_AlgId macAlgorithm;
} CMS_AlgorithmProtection;

int32_t CMS_ParseAlgorithmProtection(const BSL_Buffer *attrValue, CMS_AlgorithmProtection *algProtect);

int32_t CMS_EncodeAlgorithmProtection(const CMS_AlgorithmProtection *algProtect, BSL_Buffer *encode);

int32_t CMS_CreateAlgorithmProtectionAttr(const CMS_SignerInfo *signerInfo, HITLS_X509_AttrEntry **outAttr);

int32_t CMS_GetAlgorithmProtection(const BSL_Param *params, CRYPT_PKEY_AlgId keyAlgId, bool *hasAlgProtection);

int32_t CMS_CheckAlgorithmProtectionAttr(CMS_SignerInfo *si);

int32_t CMS_VerifyAlgorithmProtection(CMS_SignerInfo *si);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_PKI_CMS_SIGNEDDATA */
#endif /* HITLS_CMS_ALGPROTECT_H */

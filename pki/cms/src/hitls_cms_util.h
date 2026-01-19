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

/**
 * @brief Get default digest algorithm for ML-DSA variant
 * @param mldsaVariant ML-DSA variant CID
 * @param useSignedAttrs Whether signed attributes will be used
 * @return Recommended digest algorithm CID
 */
BslCid HITLS_CMS_GetDefaultMlDsaDigestAlg(BslCid mldsaVariant, bool useSignedAttrs);

/**
 * @brief Check if PQC algorithm parameters should be omitted
 * @param algId Algorithm identifier CID
 * @return true if parameters must be omitted
 */
bool HITLS_CMS_PqcShouldOmitParams(BslCid algId);

/**
 * @brief Check if algorithm is a PQC signature algorithm
 * @param algId Algorithm identifier CID
 * @return true if it's a PQC signature algorithm
 */
bool HITLS_CMS_IsPqcSignAlg(BslCid algId);

/**
 * @brief Validate PQC signature algorithm and digest combination
 * @param signAlgId Signature algorithm CID
 * @param digestAlg Digest algorithm CID
 * @return HITLS_PKI_SUCCESS if valid, error code otherwise
 */
int32_t HITLS_CMS_ValidatePqcSignDigest(BslCid signAlgId, BslCid digestAlg);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_CMS

#endif // HITLS_CMS_UTIL_H

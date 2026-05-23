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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Get default digest algorithm for ML-DSA variant
 * @param mldsaVariant ML-DSA variant CID
 * @param useSignedAttrs Whether signed attributes will be used
 * @return Recommended digest algorithm CID
 */
BslCid HITLS_CMS_GetDefaultMlDsaDigestAlg(BslCid mldsaVariant, bool useSignedAttrs);

/**
 * @brief Get default digest algorithm for SLH-DSA variant
 * @param slhdsaVariant SLH-DSA variant CID
 * @param useSignedAttrs Whether signed attributes will be used
 * @return Recommended digest algorithm CID
 */
BslCid HITLS_CMS_GetDefaultSlhDsaDigestAlg(BslCid slhdsaVariant, bool useSignedAttrs);

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

/**
 * @brief Validate ML-DSA signature algorithm and digest combination
 * @param mldsaVariant ML-DSA variant CID
 * @param digestAlg Digest algorithm CID
 * @param useSignedAttrs true for signedAttrs-present path (general table),
 *        false for no-signedAttrs path (RFC 9882: SHA-512 only)
 * @return HITLS_PKI_SUCCESS if valid, error code otherwise
 */
int32_t HITLS_CMS_ValidateMlDsaDigestAlg(BslCid mldsaVariant, BslCid digestAlg, bool useSignedAttrs);

/**
 * @brief Validate SLH-DSA signature algorithm and digest combination
 * @param slhdsaVariant SLH-DSA variant CID
 * @param digestAlg Digest algorithm CID
 * @param useSignedAttrs true for RFC 9814 signedAttrs-present path, false for no-signedAttrs compatibility path
 * @return HITLS_PKI_SUCCESS if valid, error code otherwise
 */
int32_t HITLS_CMS_ValidateSlhDsaDigestAlg(BslCid slhdsaVariant, BslCid digestAlg, bool useSignedAttrs);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_CMS

#endif // HITLS_CMS_UTIL_H

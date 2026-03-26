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
#ifdef HITLS_PKI_CMS_SIGNEDDATA
#include "bsl_err_internal.h"
#include "bsl_obj_internal.h"
#include "hitls_pki_errno.h"
#include "hitls_cms_local.h"

/**
 * RFC 9882 Section 4: Digest Algorithm Requirements
 * - ML-DSA-44 (128-bit security): Requires digest with >= 128-bit collision strength
 *   Acceptable: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256
 * - ML-DSA-65 (192-bit security): Requires digest with >= 192-bit collision strength
 *   Acceptable: SHA-384, SHA-512, SHA3-384, SHA3-512, SHAKE256
 * - ML-DSA-87 (256-bit security): Requires digest with >= 256-bit collision strength
 *   Acceptable: SHA-512, SHA3-512, SHAKE256
 *
 * SHA-512 MUST be supported for all ML-DSA variants.
 * SHAKE256 SHOULD be supported (produces 512 bits output in CMS context).
 */
typedef struct {
    BslCid algId;
    const BslCid *digestList;
    uint32_t count;
} MlDsaDigestEntry;

static const BslCid MLDSA44_DIGEST[] = {
    BSL_CID_SHA256, BSL_CID_SHA384, BSL_CID_SHA512,
    BSL_CID_SHA3_256, BSL_CID_SHA3_384, BSL_CID_SHA3_512,
    BSL_CID_SHAKE128, BSL_CID_SHAKE256,
};
static const BslCid MLDSA65_DIGEST[] = {
    BSL_CID_SHA384, BSL_CID_SHA512,
    BSL_CID_SHA3_384, BSL_CID_SHA3_512,
    BSL_CID_SHAKE256,
};
static const BslCid MLDSA87_DIGEST[] = {
    BSL_CID_SHA512, BSL_CID_SHA3_512, BSL_CID_SHAKE256,
};

#define MLDSA_ARRAY_SIZE(arr) (uint32_t)(sizeof(arr) / sizeof((arr)[0]))

static const MlDsaDigestEntry MLDSA_DIGEST_TABLE[] = {
    { BSL_CID_ML_DSA_44, MLDSA44_DIGEST, MLDSA_ARRAY_SIZE(MLDSA44_DIGEST) },
    { BSL_CID_ML_DSA_65, MLDSA65_DIGEST, MLDSA_ARRAY_SIZE(MLDSA65_DIGEST) },
    { BSL_CID_ML_DSA_87, MLDSA87_DIGEST, MLDSA_ARRAY_SIZE(MLDSA87_DIGEST) },
};

static int32_t CMS_ValidateMlDsaDigestAlg(BslCid algId, BslCid mdId)
{
    for (uint32_t i = 0; i < MLDSA_ARRAY_SIZE(MLDSA_DIGEST_TABLE); i++) {
        if (MLDSA_DIGEST_TABLE[i].algId != algId) {
            continue;
        }
        for (uint32_t j = 0; j < MLDSA_DIGEST_TABLE[i].count; j++) {
            if (MLDSA_DIGEST_TABLE[i].digestList[j] == mdId) {
                return HITLS_PKI_SUCCESS;
            }
        }
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_MLDSA_INVALID_DIGEST);
        return HITLS_CMS_ERR_MLDSA_INVALID_DIGEST;
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
    return HITLS_CMS_ERR_INVALID_ALGO;
}

/**
 * According to RFC 9882, when signed attributes are not used,
 * implementations MUST specify SHA-512 to minimize interoperability failures.
 * When signed attributes are used, SHAKE256 is recommended as it's used internally in ML-DSA.
 */
BslCid HITLS_CMS_GetDefaultMlDsaDigestAlg(BslCid mldsaVariant, bool useSignedAttrs)
{
    if (mldsaVariant != BSL_CID_ML_DSA_44 &&
        mldsaVariant != BSL_CID_ML_DSA_65 &&
        mldsaVariant != BSL_CID_ML_DSA_87) {
        return BSL_CID_UNKNOWN;
    }
    return useSignedAttrs ? BSL_CID_SHAKE256 : BSL_CID_SHA512;
}

/**
 * According to RFC 9882 Section 3 for ML-DSA:
 * "The parameters field MUST be omitted when encoding an ML-DSA AlgorithmIdentifier."
 *
 * This function can be extended for other PQC algorithms as needed.
 */
bool HITLS_CMS_PqcShouldOmitParams(BslCid algId)
{
    if (algId == BSL_CID_ML_DSA_44 ||
        algId == BSL_CID_ML_DSA_65 ||
        algId == BSL_CID_ML_DSA_87) {
        return true;
    }
    if (algId >= BSL_CID_SLH_DSA_SHA2_128S && algId <= BSL_CID_SLH_DSA_SHAKE_256F) {
        return true;
    }

    return false;
}

bool HITLS_CMS_IsPqcSignAlg(BslCid algId)
{
    if (algId == BSL_CID_ML_DSA ||
        algId == BSL_CID_ML_DSA_44 ||
        algId == BSL_CID_ML_DSA_65 ||
        algId == BSL_CID_ML_DSA_87) {
        return true;
    }

    if (algId == BSL_CID_SLH_DSA || (algId >= BSL_CID_SLH_DSA_SHA2_128S &&
        algId <= BSL_CID_SLH_DSA_SHAKE_256F)) {
        return true;
    }

    return false;
}

int32_t HITLS_CMS_ValidatePqcSignDigest(BslCid signAlgId, BslCid digestAlg)
{
    if (signAlgId == BSL_CID_ML_DSA ||
        signAlgId == BSL_CID_ML_DSA_44 ||
        signAlgId == BSL_CID_ML_DSA_65 ||
        signAlgId == BSL_CID_ML_DSA_87) {
        return CMS_ValidateMlDsaDigestAlg(signAlgId, digestAlg);
    }

    // For other PQC algorithms, add validation as needed
    // Currently, just return success for SLH-DSA and others
    return HITLS_PKI_SUCCESS;
}

#endif // HITLS_PKI_CMS_SIGNEDDATA

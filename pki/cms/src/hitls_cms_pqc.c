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

typedef struct {
    BslCid algId;
    BslCid defaultDigest;
    BslCid noAttrFallback;
} SlhDsaDigestEntry;

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

#define PQC_ARRAY_SIZE(arr) (uint32_t)(sizeof(arr) / sizeof((arr)[0]))

static const MlDsaDigestEntry MLDSA_DIGEST_TABLE[] = {
    { BSL_CID_ML_DSA_44, MLDSA44_DIGEST, PQC_ARRAY_SIZE(MLDSA44_DIGEST) },
    { BSL_CID_ML_DSA_65, MLDSA65_DIGEST, PQC_ARRAY_SIZE(MLDSA65_DIGEST) },
    { BSL_CID_ML_DSA_87, MLDSA87_DIGEST, PQC_ARRAY_SIZE(MLDSA87_DIGEST) },
};

static const SlhDsaDigestEntry SLHDSA_DIGEST_TABLE[] = {
    { BSL_CID_SLH_DSA_SHA2_128S, BSL_CID_SHA256, BSL_CID_UNKNOWN },
    { BSL_CID_SLH_DSA_SHA2_128F, BSL_CID_SHA256, BSL_CID_UNKNOWN },
    { BSL_CID_SLH_DSA_SHA2_192S, BSL_CID_SHA512, BSL_CID_SHA256 },
    { BSL_CID_SLH_DSA_SHA2_192F, BSL_CID_SHA512, BSL_CID_SHA256 },
    { BSL_CID_SLH_DSA_SHA2_256S, BSL_CID_SHA512, BSL_CID_SHA256 },
    { BSL_CID_SLH_DSA_SHA2_256F, BSL_CID_SHA512, BSL_CID_SHA256 },
    { BSL_CID_SLH_DSA_SHAKE_128S, BSL_CID_SHAKE128, BSL_CID_SHA256 },
    { BSL_CID_SLH_DSA_SHAKE_128F, BSL_CID_SHAKE128, BSL_CID_SHA256 },
    { BSL_CID_SLH_DSA_SHAKE_192S, BSL_CID_SHAKE256, BSL_CID_SHA256 },
    { BSL_CID_SLH_DSA_SHAKE_192F, BSL_CID_SHAKE256, BSL_CID_SHA256 },
    { BSL_CID_SLH_DSA_SHAKE_256S, BSL_CID_SHAKE256, BSL_CID_SHA256 },
    { BSL_CID_SLH_DSA_SHAKE_256F, BSL_CID_SHAKE256, BSL_CID_SHA256 },
};

int32_t HITLS_CMS_ValidateMlDsaDigestAlg(BslCid mldsaVariant, BslCid digestAlg, bool useSignedAttrs)
{
    /**
     * RFC 9882 Section 3: When signed attributes are not used,
     * implementations MUST use SHA-512.
     */
    if (!useSignedAttrs) {
        if (mldsaVariant != BSL_CID_ML_DSA_44 &&
            mldsaVariant != BSL_CID_ML_DSA_65 &&
            mldsaVariant != BSL_CID_ML_DSA_87) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
            return HITLS_CMS_ERR_INVALID_ALGO;
        }
        if (digestAlg != BSL_CID_SHA512) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_MLDSA_INVALID_DIGEST);
            return HITLS_CMS_ERR_MLDSA_INVALID_DIGEST;
        }
        return HITLS_PKI_SUCCESS;
    }

    for (uint32_t i = 0; i < PQC_ARRAY_SIZE(MLDSA_DIGEST_TABLE); i++) {
        if (MLDSA_DIGEST_TABLE[i].algId != mldsaVariant) {
            continue;
        }
        for (uint32_t j = 0; j < MLDSA_DIGEST_TABLE[i].count; j++) {
            if (MLDSA_DIGEST_TABLE[i].digestList[j] == digestAlg) {
                return HITLS_PKI_SUCCESS;
            }
        }
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_MLDSA_INVALID_DIGEST);
        return HITLS_CMS_ERR_MLDSA_INVALID_DIGEST;
    }

    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
    return HITLS_CMS_ERR_INVALID_ALGO;
}

int32_t HITLS_CMS_ValidateSlhDsaDigestAlg(BslCid slhdsaVariant, BslCid digestAlg, bool useSignedAttrs)
{
    for (uint32_t i = 0; i < PQC_ARRAY_SIZE(SLHDSA_DIGEST_TABLE); i++) {
        const SlhDsaDigestEntry *entry = &SLHDSA_DIGEST_TABLE[i];
        if (entry->algId != slhdsaVariant) {
            continue;
        }
        if (digestAlg == entry->defaultDigest ||
            (!useSignedAttrs && entry->noAttrFallback != BSL_CID_UNKNOWN && digestAlg == entry->noAttrFallback)) {
            return HITLS_PKI_SUCCESS;
        }
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_SLHDSA_INVALID_DIGEST);
        return HITLS_CMS_ERR_SLHDSA_INVALID_DIGEST;
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

BslCid HITLS_CMS_GetDefaultSlhDsaDigestAlg(BslCid slhdsaVariant, bool useSignedAttrs)
{
    (void)useSignedAttrs;
    for (uint32_t i = 0; i < PQC_ARRAY_SIZE(SLHDSA_DIGEST_TABLE); i++) {
        if (SLHDSA_DIGEST_TABLE[i].algId == slhdsaVariant) {
            return SLHDSA_DIGEST_TABLE[i].defaultDigest;
        }
    }
    return BSL_CID_UNKNOWN;
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
        return HITLS_CMS_ValidateMlDsaDigestAlg(signAlgId, digestAlg, true);
    }

    if (signAlgId >= BSL_CID_SLH_DSA_SHA2_128S && signAlgId <= BSL_CID_SLH_DSA_SHAKE_256F) {
        return HITLS_CMS_ValidateSlhDsaDigestAlg(signAlgId, digestAlg, true);
    }

    // For other PQC algorithms, add validation as needed
    return HITLS_PKI_SUCCESS;
}

#endif // HITLS_PKI_CMS_SIGNEDDATA

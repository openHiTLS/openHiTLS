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
#include "hitls_cms_algprotect.h"
#include "hitls_cms_util.h"

#if defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_SLH_DSA) || defined(HITLS_CRYPTO_COMPOSITE)
static int32_t NormalizeCmsPqcOperationState(CRYPT_EAL_PkeyCtx *key, BslCid signAlgId)
{
    CRYPT_PKEY_AlgId keyAlgId = CRYPT_EAL_PkeyGetId(key);
#if defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_SLH_DSA)
    if (keyAlgId == CRYPT_PKEY_ML_DSA || keyAlgId == CRYPT_PKEY_SLH_DSA) {
        return X509_NormalizePqcOperationState(key, keyAlgId, signAlgId);
    }
#endif
#ifdef HITLS_CRYPTO_COMPOSITE
    if (keyAlgId == CRYPT_PKEY_COMPOSITE) {
        return CRYPT_EAL_PkeyCtrl(key, CRYPT_CTRL_SET_CTX_INFO, NULL, 0);
    }
#endif
    return HITLS_PKI_SUCCESS;
}

static int32_t SetCmsSignParam(CRYPT_EAL_PkeyCtx *signKey, int32_t mdId,
    const HITLS_X509_SignAlgParam *algParam, HITLS_X509_Asn1AlgId *signAlgId)
{
    (void)mdId;
    (void)algParam;
    return NormalizeCmsPqcOperationState(signKey, signAlgId->algId);
}
#endif

/**
 * RFC 9882 Section 3.3, Table 1: suitable digest algorithms when signed
 * attributes are present. RFC 9882 permits verifiers to reject weaker choices;
 * this implementation applies that policy during signing and verification.
 * - ML-DSA-44 (128-bit security): digest with >= 128-bit collision strength
 *   Acceptable: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256
 * - ML-DSA-65 (192-bit security): digest with >= 192-bit collision strength
 *   Acceptable: SHA-384, SHA-512, SHA3-384, SHA3-512, SHAKE256
 * - ML-DSA-87 (256-bit security): digest with >= 256-bit collision strength
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

static bool IsMlDsaAlg(BslCid algId)
{
    return algId >= BSL_CID_ML_DSA_44 && algId <= BSL_CID_ML_DSA_87;
}

static bool IsSlhDsaAlg(BslCid algId)
{
    return algId >= BSL_CID_SLH_DSA_SHA2_128S && algId <= BSL_CID_SLH_DSA_SHAKE_256F;
}

static bool IsHashSlhDsaAlg(BslCid algId)
{
    return algId >= BSL_CID_HASH_SLH_DSA_SHA2_128S_WITH_SHA256 &&
        algId <= BSL_CID_HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256;
}

static bool IsCompositeProfile(BslCid algId)
{
    return algId >= BSL_CID_MLDSA44_RSA2048_PSS_SHA256 && algId <= BSL_CID_MLDSA87_ECDSA_P521_SHA512;
}

static const BslCid *CMS_GetSlhDsaDigestList(BslCid algId, uint32_t *count)
{
    if (algId >= BSL_CID_SLH_DSA_SHA2_128S && algId <= BSL_CID_SLH_DSA_SHAKE_128F) {
        *count = MLDSA_ARRAY_SIZE(MLDSA44_DIGEST);
        return MLDSA44_DIGEST;
    }
    if (algId >= BSL_CID_SLH_DSA_SHA2_192S && algId <= BSL_CID_SLH_DSA_SHAKE_192F) {
        *count = MLDSA_ARRAY_SIZE(MLDSA65_DIGEST);
        return MLDSA65_DIGEST;
    }
    if (algId >= BSL_CID_SLH_DSA_SHA2_256S && algId <= BSL_CID_SLH_DSA_SHAKE_256F) {
        *count = MLDSA_ARRAY_SIZE(MLDSA87_DIGEST);
        return MLDSA87_DIGEST;
    }
    *count = 0;
    return NULL;
}

static int32_t CMS_ValidateSlhDsaDigestAlg(BslCid algId, BslCid mdId)
{
    uint32_t count;
    const BslCid *digestList = CMS_GetSlhDsaDigestList(algId, &count);
    for (uint32_t i = 0; i < count; i++) {
        if (digestList[i] == mdId) {
            return HITLS_PKI_SUCCESS;
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
    return HITLS_CMS_ERR_INVALID_ALGO;
}

static BslCid CMS_GetSlhDsaDefaultDigestAlg(BslCid algId)
{
    /* RFC 9814 Section 4: without signed attributes, digestAlgorithm SHOULD
     * identify the hash used by the selected SLH-DSA parameter set, with an
     * output of 256 bits for category 1 and 512 bits for categories 3 and 5.
     */
    if (algId == BSL_CID_SLH_DSA_SHA2_128S || algId == BSL_CID_SLH_DSA_SHA2_128F) {
        return BSL_CID_SHA256;
    }
    if (algId == BSL_CID_SLH_DSA_SHAKE_128S || algId == BSL_CID_SLH_DSA_SHAKE_128F) {
        return BSL_CID_SHAKE128;
    }
    if (algId == BSL_CID_SLH_DSA_SHA2_192S || algId == BSL_CID_SLH_DSA_SHA2_192F ||
        algId == BSL_CID_SLH_DSA_SHA2_256S || algId == BSL_CID_SLH_DSA_SHA2_256F) {
        return BSL_CID_SHA512;
    }
    if (algId == BSL_CID_SLH_DSA_SHAKE_192S || algId == BSL_CID_SLH_DSA_SHAKE_192F ||
        algId == BSL_CID_SLH_DSA_SHAKE_256S || algId == BSL_CID_SLH_DSA_SHAKE_256F) {
        return BSL_CID_SHAKE256;
    }
    return BSL_CID_UNKNOWN;
}

/**
 * RFC 9882 Section 3.3: when signed attributes are not used,
 * implementations MUST specify SHA-512 to minimize interoperability failures.
 * When signed attributes are used, this implementation selects SHAKE256, which
 * RFC 9882 says SHOULD be supported because it is used internally in ML-DSA.
 */
static BslCid GetDefaultPqcDigestAlg(BslCid signAlgId, bool useSignedAttrs)
{
    if (signAlgId == BSL_CID_ML_DSA_44 || signAlgId == BSL_CID_ML_DSA_65 ||
        signAlgId == BSL_CID_ML_DSA_87) {
        return useSignedAttrs ? BSL_CID_SHAKE256 : BSL_CID_SHA512;
    }
    if (IsSlhDsaAlg(signAlgId)) {
        return CMS_GetSlhDsaDefaultDigestAlg(signAlgId);
    }
    if (IsCompositeProfile(signAlgId)) {
        int32_t mdId = BSL_CID_UNKNOWN;
        /* draft-ietf-lamps-cms-composite-sigs-05 Section 3.4: each
         * composite signature profile has one mandatory digest algorithm.
         */
        if (OBJ_GetHashIdFromSignId(signAlgId, &mdId) == BSL_SUCCESS) {
            return (BslCid)mdId;
        }
    }
    return BSL_CID_UNKNOWN;
}


static int32_t ValidateCompositeDigestAlg(BslCid signAlgId, BslCid digestAlg)
{
    int32_t fixedMdId = BSL_CID_UNKNOWN;
    /* draft-ietf-lamps-cms-composite-sigs-05 Sections 3.3 and 3.4:
     * composite signatures are pre-hash-only and digestAlgorithm MUST
     * match the digest fixed by the composite signature OID.
     */
    int32_t ret = OBJ_GetHashIdFromSignId(signAlgId, &fixedMdId);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    if (digestAlg != (BslCid)fixedMdId) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t CheckOrGetMdForMlDsa(BslCid algId, bool hasSignedAttr, int32_t *mdId, bool isStream)
{
    if (!hasSignedAttr && isStream) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC);
        return HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC;
    }
    if (!hasSignedAttr) {
        BslCid md = GetDefaultPqcDigestAlg(algId, false);
        if (md != BSL_CID_UNKNOWN) {
            *mdId = md;
        }
        return HITLS_PKI_SUCCESS;
    }
    return CMS_ValidateMlDsaDigestAlg(algId, (BslCid)*mdId);
}

static int32_t CheckOrGetMdForSlhDsa(BslCid algId, bool hasSignedAttr, int32_t *mdId, bool isStream)
{
    if (!IsSlhDsaAlg(algId)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    if (!hasSignedAttr && isStream) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC);
        return HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC;
    }
    if (*mdId == BSL_CID_UNKNOWN) {
        *mdId = GetDefaultPqcDigestAlg(algId, hasSignedAttr);
    }
    if (hasSignedAttr) {
        return CMS_ValidateSlhDsaDigestAlg(algId, (BslCid)*mdId);
    }
    return HITLS_PKI_SUCCESS;
}

static int32_t CheckOrGetMdForComposite(BslCid algId, int32_t *mdId)
{
    if (*mdId == BSL_CID_UNKNOWN) {
        *mdId = GetDefaultPqcDigestAlg(algId, false);
        if (*mdId == BSL_CID_UNKNOWN) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
            return HITLS_CMS_ERR_INVALID_ALGO;
        }
    }
    return ValidateCompositeDigestAlg(algId, (BslCid)*mdId);
}

int32_t HITLS_CMS_CheckOrGetPqcMd(const CRYPT_EAL_PkeyCtx *key, bool hasSignedAttr, int32_t *mdId,
    bool isStream)
{
    CRYPT_PKEY_AlgId keyAlgId = CRYPT_EAL_PkeyGetId(key);
    BslCid algId;
    if (keyAlgId == CRYPT_PKEY_ML_DSA) {
        algId = (BslCid)CRYPT_EAL_PkeyGetParaId(key);
        return CheckOrGetMdForMlDsa(algId, hasSignedAttr, mdId, isStream);
    }
    if (keyAlgId == CRYPT_PKEY_SLH_DSA) {
        algId = (BslCid)CRYPT_EAL_PkeyGetParaId(key);
        return CheckOrGetMdForSlhDsa(algId, hasSignedAttr, mdId, isStream);
    }
    if (keyAlgId == CRYPT_PKEY_COMPOSITE) {
        algId = (BslCid)CRYPT_EAL_PkeyGetParaId(key);
        return CheckOrGetMdForComposite(algId, mdId);
    }
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_CMS_PrepareSignKey(const CRYPT_EAL_PkeyCtx *prvKey, CRYPT_EAL_PkeyCtx **signKey, bool *freeSignKey)
{
    *signKey = (CRYPT_EAL_PkeyCtx *)(uintptr_t)prvKey;
    *freeSignKey = false;
#if defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_SLH_DSA) || defined(HITLS_CRYPTO_COMPOSITE)
    CRYPT_PKEY_AlgId keyAlgId = CRYPT_EAL_PkeyGetId(prvKey);
    if (keyAlgId == CRYPT_PKEY_ML_DSA || keyAlgId == CRYPT_PKEY_SLH_DSA || keyAlgId == CRYPT_PKEY_COMPOSITE) {
        HITLS_X509_Asn1AlgId signAlgId = {.algId = (BslCid)CRYPT_EAL_PkeyGetParaId(prvKey)};
        return X509_PrepareSignKey(prvKey, signKey, BSL_CID_UNKNOWN, NULL, &signAlgId, freeSignKey,
            SetCmsSignParam);
    }
#endif
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_CMS_CheckPqcSignAlgAndDigest(const CMS_SignerInfo *si, bool isStream)
{
    BslCid signAlgId = (BslCid)si->sigAlg.algId;
    bool hasSignedAttr = (si->signedAttrs != NULL && BSL_LIST_COUNT(si->signedAttrs->list) > 0);
    BslCid digestAlg = (BslCid)si->digestAlg.id;
    if (IsMlDsaAlg(signAlgId)) {
        if (hasSignedAttr) {
            return CMS_ValidateMlDsaDigestAlg(signAlgId, digestAlg);
        }
        if (isStream) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC);
            return HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC;
        }
        return HITLS_PKI_SUCCESS;
    }

    if (IsSlhDsaAlg(signAlgId)) {
        if (!hasSignedAttr && isStream) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC);
            return HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC;
        }
        if (hasSignedAttr) {
            return CMS_ValidateSlhDsaDigestAlg(signAlgId, digestAlg);
        }
        return HITLS_PKI_SUCCESS;
    }

    if (IsCompositeProfile(signAlgId)) {
        return ValidateCompositeDigestAlg(signAlgId, digestAlg);
    }

    if (IsHashSlhDsaAlg(signAlgId)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    return HITLS_PKI_SUCCESS;
}

#endif // HITLS_PKI_CMS_SIGNEDDATA

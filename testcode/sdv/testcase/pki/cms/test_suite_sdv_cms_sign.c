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

/* BEGIN_HEADER */

#include "bsl_sal.h"
#include <string.h>
#include "bsl_types.h"
#include "bsl_log.h"
#include "sal_file.h"
#include "bsl_init.h"
#include "bsl_params.h"
#include "crypt_codecskey.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "hitls_cms_local.h"
#include "hitls_cms_algprotect.h"
#include "hitls_cert_local.h"
#include "hitls_x509_local.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_cms.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_x509.h"
#include "hitls_pki_params.h"
#include "bsl_obj_internal.h"
#include "bsl_list.h"
#include "stub_utils.h"
/* END_HEADER */

STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);
STUB_DEFINE_RET2(int32_t, HITLS_X509_CheckKey, HITLS_X509_Cert *, CRYPT_EAL_PkeyCtx *);
STUB_DEFINE_RET1(int32_t, BSL_SAL_SysTimeGet, BSL_TIME *);

static HITLS_X509_AttrEntry *TestFindCmsAttr(HITLS_X509_Attrs *attrs, BslCid cid)
{
    if (attrs == NULL) {
        return NULL;
    }
    for (HITLS_X509_AttrEntry *attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_FIRST(attrs->list);
        attr != NULL; attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_NEXT(attrs->list)) {
        if (attr->cid == cid) {
            return attr;
        }
    }
    return NULL;
}

static void TestMarkExplicitTrustAnchor(HITLS_X509_Cert *cert)
{
    /* The vector certificates are deliberately end-entity certificates, but
     * the openHiTLS store accepts only CA certificates as explicit trust
     * anchors.  Adjust only the trust copy's in-memory CA metadata; its signed
     * DER, signature, public key, and the vector file remain unchanged. */
    HITLS_X509_CertExt *ext = (HITLS_X509_CertExt *)cert->tbs.ext.extData;
    ext->extFlags |= HITLS_X509_EXT_FLAG_BCONS;
    ext->isCa = true;
}

static int32_t TestReparseCms(HITLS_CMS *cms)
{
    BSL_Buffer encode = {0};
    HITLS_CMS *parsedCms = NULL;
    int32_t ret = HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encode);
    if (ret == HITLS_PKI_SUCCESS) {
        ret = HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encode, &parsedCms);
    }
    BSL_SAL_FREE(encode.data);
    HITLS_CMS_Free(parsedCms);
    return ret;
}

typedef enum {
    TEST_CMS_DIGEST_EXPLICIT,
    TEST_CMS_DIGEST_DEFAULT,
} TestCmsDigestMode;

typedef enum {
    TEST_CMS_ALG_PROTECT_DEFAULT,
    TEST_CMS_ALG_PROTECT_ENABLE,
    TEST_CMS_ALG_PROTECT_DISABLE,
} TestCmsAlgProtectMode;

typedef struct {
    bool hasSignedAttrs;
    TestCmsDigestMode digestMode;
    TestCmsAlgProtectMode algProtectMode;
    BslCid contentType;
} TestCmsSignOptions;

typedef struct {
    BslCid algId;
    CRYPT_PKEY_ParaId paraId;
    bool isMlDsa;
    bool isSlhDsa;
    bool isComposite;
    CRYPT_EAL_PkeyCtx *key;
    HITLS_X509_Cert *cert;
    HITLS_X509_Cert *caCert;
    HITLS_X509_List *certs;
    HITLS_X509_List *caCerts;
    bool certListed;
    bool caCertListed;
    HITLS_CMS *cms;
    HITLS_CMS *parsed;
    BSL_Buffer message;
    BSL_Buffer encoded;
    uint32_t signerVersion;
    int32_t mdId;
    bool detached;
    bool noSignedAttrs;
    bool algProtection;
    uint64_t storeFlags;
    BSL_Param params[9];
} TestCmsSignFixture;

static int32_t TestCmsConfigureKey(TestCmsSignFixture *fixture, const char *keyPath)
{
    int32_t keyType = fixture->algId == BSL_CID_ECDSA ? CRYPT_PRIKEY_ECC : CRYPT_PRIKEY_PKCS8_UNENCRYPT;
    int32_t ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, keyType, keyPath, NULL, 0, &fixture->key);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (fixture->algId == BSL_CID_RSA) {
        int32_t mdId = CRYPT_MD_SHA256;
        return CRYPT_EAL_PkeyCtrl(fixture->key, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &mdId, sizeof(mdId));
    }
    if (fixture->algId != BSL_CID_RSASSAPSS) {
        return CRYPT_SUCCESS;
    }
    int32_t pad = CRYPT_EMSA_PSS;
    ret = CRYPT_EAL_PkeyCtrl(fixture->key, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(pad));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_MD_AlgId hash = (CRYPT_MD_AlgId)BSL_CID_SHA256;
    CRYPT_MD_AlgId mgf = (CRYPT_MD_AlgId)BSL_CID_SHA256;
    int32_t saltLen = 32;
    BSL_Param params[] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hash, sizeof(hash), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mgf, sizeof(mgf), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END
    };
    return CRYPT_EAL_PkeyCtrl(fixture->key, CRYPT_CTRL_SET_RSA_EMSA_PSS, params, 0);
}

static int32_t TestCmsConfigurePqcState(TestCmsSignFixture *fixture)
{
    if (!fixture->isMlDsa && !fixture->isSlhDsa && !fixture->isComposite) {
        return CRYPT_SUCCESS;
    }
    uint8_t context[] = "non-empty CMS test context";
    int32_t ret = CRYPT_EAL_PkeyCtrl(fixture->key, CRYPT_CTRL_SET_CTX_INFO, context, sizeof(context));
    if (ret != CRYPT_SUCCESS || fixture->isComposite) {
        return ret;
    }
    int32_t enabled = 1;
    ret = CRYPT_EAL_PkeyCtrl(fixture->key, CRYPT_CTRL_SET_PREHASH_MODE, &enabled, sizeof(enabled));
    if (ret != CRYPT_SUCCESS || !fixture->isMlDsa) {
        return ret;
    }
    return CRYPT_EAL_PkeyCtrl(fixture->key, CRYPT_CTRL_SET_MLDSA_MUMSG_FLAG, &enabled, sizeof(enabled));
}

static int32_t TestCmsFixtureInit(TestCmsSignFixture *fixture, int algId, const char *caPath,
    const char *certPath, const char *keyPath, const char *msgPath)
{
    (void)memset(fixture, 0, sizeof(*fixture));
    fixture->algId = (BslCid)algId;
    TestMemInit();
    int32_t ret = TestRandInit();
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = BSL_SAL_ReadFile(msgPath, &fixture->message.data, &fixture->message.dataLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &fixture->cert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, caPath, &fixture->caCert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = TestCmsConfigureKey(fixture, keyPath);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (algId == BSL_CID_ML_DSA || algId == BSL_CID_SLH_DSA || algId == BSL_CID_COMPOSITE) {
        fixture->paraId = CRYPT_EAL_PkeyGetParaId(fixture->key);
    } else {
        fixture->paraId = CRYPT_PKEY_PARAID_MAX;
    }
    fixture->isMlDsa = fixture->paraId >= CRYPT_MLDSA_TYPE_MLDSA_44 &&
        fixture->paraId <= CRYPT_MLDSA_TYPE_MLDSA_87;
    fixture->isSlhDsa = fixture->paraId >= CRYPT_SLH_DSA_SHA2_128S &&
        fixture->paraId <= CRYPT_SLH_DSA_SHAKE_256F;
    fixture->isComposite = fixture->paraId >= CRYPT_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256 &&
        fixture->paraId <= CRYPT_COMPOSITE_MLDSA87_ECDSA_P521_SHA512;
    ret = TestCmsConfigurePqcState(fixture);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    fixture->cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    if (fixture->cms == NULL) {
        return BSL_MALLOC_FAIL;
    }
    fixture->certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    fixture->caCerts = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (fixture->certs == NULL || fixture->caCerts == NULL) {
        return BSL_MALLOC_FAIL;
    }
    ret = BSL_LIST_AddElement(fixture->certs, fixture->cert, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    fixture->certListed = true;
    ret = BSL_LIST_AddElement(fixture->caCerts, fixture->caCert, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    fixture->caCertListed = true;
    if (fixture->isComposite) {
        TestMarkExplicitTrustAnchor(fixture->caCert);
    }
    return HITLS_PKI_SUCCESS;
}

static void TestCmsFixtureClear(TestCmsSignFixture *fixture)
{
    BSL_SAL_FREE(fixture->message.data);
    BSL_SAL_FREE(fixture->encoded.data);
    HITLS_CMS_Free(fixture->cms);
    HITLS_CMS_Free(fixture->parsed);
    CRYPT_EAL_PkeyFreeCtx(fixture->key);
    if (!fixture->certListed) {
        HITLS_X509_CertFree(fixture->cert);
    }
    if (!fixture->caCertListed) {
        HITLS_X509_CertFree(fixture->caCert);
    }
    BSL_LIST_FREE(fixture->certs, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(fixture->caCerts, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
}

static int32_t TestCmsSelectDigest(TestCmsSignFixture *fixture, bool hasSignedAttrs)
{
    fixture->mdId = BSL_CID_SHA256;
    if (fixture->isMlDsa && fixture->paraId == CRYPT_MLDSA_TYPE_MLDSA_44 && hasSignedAttrs) {
        fixture->mdId = BSL_CID_SHAKE128;
    } else if (fixture->paraId == CRYPT_MLDSA_TYPE_MLDSA_65 ||
        fixture->paraId == CRYPT_MLDSA_TYPE_MLDSA_87 ||
        (fixture->paraId >= CRYPT_SLH_DSA_SHA2_192S && fixture->paraId <= CRYPT_SLH_DSA_SHAKE_256F)) {
        fixture->mdId = BSL_CID_SHA512;
    } else if (fixture->paraId == CRYPT_SLH_DSA_SHAKE_128S ||
        fixture->paraId == CRYPT_SLH_DSA_SHAKE_128F) {
        fixture->mdId = BSL_CID_SHAKE128;
    } else if (fixture->isComposite) {
        return OBJ_GetHashIdFromSignId((BslCid)fixture->paraId, &fixture->mdId);
    }
    return BSL_SUCCESS;
}

static int32_t TestCmsBuildParams(TestCmsSignFixture *fixture, const TestCmsSignOptions *options)
{
    int32_t ret = TestCmsSelectDigest(fixture, options->hasSignedAttrs);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    fixture->signerVersion = fixture->algId == BSL_CID_ECDSA ?
        HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3 : HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    fixture->noSignedAttrs = !options->hasSignedAttrs;
    fixture->algProtection = options->algProtectMode == TEST_CMS_ALG_PROTECT_ENABLE;
    fixture->storeFlags = HITLS_X509_VFY_FLAG_PARTIAL_CHAIN;
    uint32_t index = 0;
    fixture->params[index++] = (BSL_Param){HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32,
        &fixture->signerVersion, sizeof(fixture->signerVersion), 0};
    if (options->digestMode == TEST_CMS_DIGEST_EXPLICIT) {
        fixture->params[index++] = (BSL_Param){HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32,
            &fixture->mdId, sizeof(fixture->mdId), 0};
    }
    fixture->params[index++] = (BSL_Param){HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL,
        &fixture->detached, sizeof(fixture->detached), 0};
    fixture->params[index++] = (BSL_Param){HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL,
        &fixture->noSignedAttrs, sizeof(fixture->noSignedAttrs), 0};
    fixture->params[index++] = (BSL_Param){HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR,
        fixture->certs, sizeof(HITLS_X509_List *), 0};
    fixture->params[index++] = (BSL_Param){HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR,
        fixture->caCerts, sizeof(HITLS_X509_List *), 0};
    fixture->params[index++] = (BSL_Param){HITLS_CMS_PARAM_STORE_FLAGS, BSL_PARAM_TYPE_UINT64,
        &fixture->storeFlags, sizeof(fixture->storeFlags), 0};
    if (options->algProtectMode != TEST_CMS_ALG_PROTECT_DEFAULT) {
        fixture->params[index++] = (BSL_Param){HITLS_CMS_PARAM_SET_ALG_PROTECTION, BSL_PARAM_TYPE_BOOL,
            &fixture->algProtection, sizeof(fixture->algProtection), 0};
    }
    fixture->params[index] = (BSL_Param)BSL_PARAM_END;
    return HITLS_PKI_SUCCESS;
}

static int32_t TestCmsSignAndParse(TestCmsSignFixture *fixture, const TestCmsSignOptions *options)
{
    if (options->contentType != BSL_CID_UNKNOWN) {
        fixture->cms->ctx.signedData->encapCont.contentType = options->contentType;
    }
    int32_t ret = TestCmsBuildParams(fixture, options);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_CMS_DataSign(fixture->cms, fixture->key, fixture->cert, &fixture->message, fixture->params);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, fixture->cms, NULL, &fixture->encoded);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &fixture->encoded, &fixture->parsed);
}

static int32_t TestCmsExpectedDefaultDigest(const TestCmsSignFixture *fixture, bool hasSignedAttrs)
{
    if (fixture->isMlDsa) {
        return hasSignedAttrs ? BSL_CID_SHAKE256 : BSL_CID_SHA512;
    }
    if (fixture->paraId == CRYPT_SLH_DSA_SHA2_128S || fixture->paraId == CRYPT_SLH_DSA_SHA2_128F) {
        return BSL_CID_SHA256;
    }
    if (fixture->paraId == CRYPT_SLH_DSA_SHAKE_128S || fixture->paraId == CRYPT_SLH_DSA_SHAKE_128F) {
        return BSL_CID_SHAKE128;
    }
    if (fixture->paraId == CRYPT_SLH_DSA_SHAKE_192S || fixture->paraId == CRYPT_SLH_DSA_SHAKE_192F ||
        fixture->paraId == CRYPT_SLH_DSA_SHAKE_256S || fixture->paraId == CRYPT_SLH_DSA_SHAKE_256F ||
        fixture->paraId == CRYPT_COMPOSITE_MLDSA87_ED448_SHAKE256) {
        return BSL_CID_SHAKE256;
    }
    if (fixture->paraId == CRYPT_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256 ||
        fixture->paraId == CRYPT_COMPOSITE_MLDSA44_RSA2048_PKCS15_SHA256 ||
        fixture->paraId == CRYPT_COMPOSITE_MLDSA44_ECDSA_P256_SHA256) {
        return BSL_CID_SHA256;
    }
    return BSL_CID_SHA512;
}

static int32_t TestCmsCheckRoundTrip(TestCmsSignFixture *fixture, const TestCmsSignOptions *options,
    int32_t expectedDigest)
{
    CMS_SignedData *signedData = fixture->parsed->ctx.signedData;
    CMS_SignerInfo *signer = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(signedData->signerInfos);
    if (signer == NULL || (fixture->algId == BSL_CID_RSASSAPSS && signer->sigAlg.algId != BSL_CID_RSASSAPSS)) {
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    if ((fixture->isMlDsa || fixture->isSlhDsa || fixture->isComposite) &&
        signer->sigAlg.algId != (BslCid)fixture->paraId) {
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    if (expectedDigest != BSL_CID_UNKNOWN && signer->digestAlg.id != expectedDigest) {
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    bool expectedProtection = options->hasSignedAttrs &&
        (options->algProtectMode == TEST_CMS_ALG_PROTECT_ENABLE ||
        (options->algProtectMode == TEST_CMS_ALG_PROTECT_DEFAULT &&
        (fixture->isMlDsa || fixture->isSlhDsa || fixture->isComposite)));
    HITLS_X509_AttrEntry *attr = TestFindCmsAttr(signer->signedAttrs, BSL_CID_PKCS9_AT_ALGORITHM_PROTECTION);
    if ((attr != NULL) != expectedProtection) {
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    if (attr != NULL) {
        CMS_AlgorithmProtection protection = {0};
        BSL_Buffer value = {attr->attrValue.buff, attr->attrValue.len};
        int32_t ret = CMS_ParseAlgorithmProtection(&value, &protection);
        if (ret != HITLS_PKI_SUCCESS || protection.digestAlgorithm.id != signer->digestAlg.id ||
            protection.signatureAlgorithm.algId != signer->sigAlg.algId) {
            return HITLS_CMS_ERR_INVALID_DATA;
        }
    }
    int32_t ret = HITLS_CMS_DataVerify(fixture->parsed, NULL, fixture->params, NULL);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return HITLS_CMS_DataVerify(fixture->parsed, &fixture->message, fixture->params, NULL);
}

/*
 * @test   SDV_CMS_SIGNEDDATA_MALLOC_TC001
 * @title  Test malloc CMS SignedData
 * @brief
 *    1. Malloc CMS SignedData with valid cid
 *    2. Malloc CMS SignedData with NULL parameter
 *    3. Malloc CMS SignedData with invalid cid
 * @expect
 *    1. Success
 *    2. No abort
 *    3. Returns NULL
 */
/* BEGIN_CASE */
void SDV_CMS_SIGNEDDATA_MALLOC_TC001(void)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    SKIP_TEST();
#else
    HITLS_CMS *cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(NULL);
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIMPLEDATA);
    ASSERT_EQ(cms, NULL);
    HITLS_CMS_Free(cms);
EXIT:
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CMS_ALG_PROTECTION_INVALID_TC001(void)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    SKIP_TEST();
#else
    BSL_Buffer encoded = {0};
    BSL_Buffer repeated = {0};
    BSL_Buffer emptyMac = {0};
    BSL_Buffer invalidPqc = {0};
    CMS_AlgorithmProtection algProtect = {
        .digestAlgorithm.id = BSL_CID_SHA256,
        .signatureAlgorithm.algId = BSL_CID_RSA,
        .macAlgorithm.id = BSL_CID_HMAC_SHA256,
    };
    ASSERT_EQ(CMS_EncodeAlgorithmProtection(&algProtect, &encoded), HITLS_CMS_ERR_INVALID_PARAM);
    TestErrClear();

    algProtect.macAlgorithm.id = BSL_CID_UNKNOWN;
    ASSERT_EQ(CMS_EncodeAlgorithmProtection(&algProtect, &encoded), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(encoded.dataLen > 2 && (encoded.data[1] & 0x80) == 0);
    ASSERT_EQ(encoded.data[encoded.dataLen - 2], BSL_ASN1_TAG_NULL);
    encoded.data[encoded.dataLen - 2] = BSL_ASN1_TAG_OCTETSTRING;
    /* Legacy signature parameters are decoded but not checked here. */
    ASSERT_EQ(CMS_ParseAlgorithmProtection(&encoded, &algProtect), HITLS_PKI_SUCCESS);
    encoded.data[encoded.dataLen - 2] = BSL_ASN1_TAG_NULL;
    TestErrClear();

    emptyMac.dataLen = encoded.dataLen + 2;
    emptyMac.data = BSL_SAL_Malloc(emptyMac.dataLen);
    ASSERT_NE(emptyMac.data, NULL);
    (void)memcpy(emptyMac.data, encoded.data, encoded.dataLen);
    emptyMac.data[1] += 2;
    emptyMac.data[encoded.dataLen] = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 2;
    emptyMac.data[encoded.dataLen + 1] = 0;
    ASSERT_EQ(CMS_ParseAlgorithmProtection(&emptyMac, &algProtect), HITLS_CMS_ERR_INVALID_DATA);
    TestErrClear();

    repeated.dataLen = encoded.dataLen * 2;
    repeated.data = BSL_SAL_Malloc(repeated.dataLen);
    ASSERT_NE(repeated.data, NULL);
    (void)memcpy(repeated.data, encoded.data, encoded.dataLen);
    (void)memcpy(repeated.data + encoded.dataLen, encoded.data, encoded.dataLen);
    ASSERT_EQ(CMS_ParseAlgorithmProtection(&repeated, &algProtect), HITLS_CMS_ERR_INVALID_DATA);
    TestErrClear();

    BSL_SAL_FREE(encoded.data);
    algProtect = (CMS_AlgorithmProtection){
        .digestAlgorithm.id = BSL_CID_SHA256,
        .signatureAlgorithm = {
            .algId = BSL_CID_RSASSAPSS,
            .rsaPssParam = {
                .saltLen = 20,
                .mdId = (CRYPT_MD_AlgId)BSL_CID_SHA1,
                .mgfId = (CRYPT_MD_AlgId)BSL_CID_SHA1,
            },
        },
    };
    ASSERT_EQ(CMS_EncodeAlgorithmProtection(&algProtect, &encoded), HITLS_PKI_SUCCESS);
    CMS_AlgorithmProtection decoded = {0};
    ASSERT_EQ(CMS_ParseAlgorithmProtection(&encoded, &decoded), HITLS_PKI_SUCCESS);
    ASSERT_EQ(decoded.signatureAlgorithm.rsaPssParam.mdId, BSL_CID_SHA1);
    ASSERT_EQ(decoded.signatureAlgorithm.rsaPssParam.mgfId, BSL_CID_SHA1);
    ASSERT_EQ(decoded.signatureAlgorithm.rsaPssParam.saltLen, 20);

    const BslCid pqcAlgs[] = {
        BSL_CID_ML_DSA_44,
        BSL_CID_SLH_DSA_SHA2_128S,
        BSL_CID_MLDSA44_RSA2048_PSS_SHA256,
    };
    for (uint32_t i = 0; i < sizeof(pqcAlgs) / sizeof(pqcAlgs[0]); i++) {
        BSL_SAL_FREE(encoded.data);
        algProtect = (CMS_AlgorithmProtection){
            .digestAlgorithm.id = BSL_CID_SHA256,
            .signatureAlgorithm.algId = pqcAlgs[i],
        };
        ASSERT_EQ(CMS_EncodeAlgorithmProtection(&algProtect, &encoded), HITLS_PKI_SUCCESS);
        BslOidString *oid = BSL_OBJ_GetOID(pqcAlgs[i]);
        ASSERT_NE(oid, NULL);
        uint32_t sigOffset = encoded.dataLen - oid->octetLen - 4;
        ASSERT_TRUE((encoded.data[1] & 0x80) == 0);
        ASSERT_EQ(encoded.data[sigOffset], BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 1);
        ASSERT_EQ(encoded.data[sigOffset + 1], oid->octetLen + 2);

        invalidPqc.dataLen = encoded.dataLen + 2;
        invalidPqc.data = BSL_SAL_Malloc(invalidPqc.dataLen);
        ASSERT_NE(invalidPqc.data, NULL);
        (void)memcpy(invalidPqc.data, encoded.data, encoded.dataLen);
        invalidPqc.data[1] += 2;
        invalidPqc.data[sigOffset + 1] += 2;
        invalidPqc.data[encoded.dataLen] = BSL_ASN1_TAG_NULL;
        invalidPqc.data[encoded.dataLen + 1] = 0;
        ASSERT_EQ(CMS_ParseAlgorithmProtection(&invalidPqc, &decoded), HITLS_X509_ERR_SIGN_PARAM);
        BSL_SAL_FREE(invalidPqc.data);
        TestErrClear();
    }
EXIT:
    BSL_SAL_FREE(encoded.data);
    BSL_SAL_FREE(repeated.data);
    BSL_SAL_FREE(emptyMac.data);
    BSL_SAL_FREE(invalidPqc.data);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_PARSE_SIGNEDDATA_VERIFY_DETACHED_TC001
 * @title  Verify CMS SignedData (detached/attached) with re-encode and negative cases
 * @brief
 *    1. Parse CMS SignedData from file and re-encode; compare with original
 *    2. For detached: verify requires external message; NULL/empty message returns NO_CONTENT
 *    3. For attached: verify succeeds with NULL message; wrong external message returns CONTENT_MISMATCH
 *    4. Re-verify same output buffer returns INVALID_DATA to avoid reuse
 *    5. Tamper contentType then verify; returns VERSION_INVALID
 * @expect
 *    1. Parse and re-encode equal
 *    2. Detached: NO_CONTENT on NULL/empty; success with correct msg
 *    3. Attached: success with NULL or correct msg; CONTENT_MISMATCH on wrong msg
 *    4. INVALID_DATA on re-verify of output buffer
 *    5. VERSION_INVALID after contentType tamper
 */
/* BEGIN_CASE */
void SDV_CMS_PARSE_SIGNEDDATA_VERIFY_TEST_TC001(char *p7path, char *msgpath, int isDetached, char *caPath, int version3)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    (void)p7path;
    (void)msgpath;
    (void)isDetached;
    (void)caPath;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    BSL_Buffer output = {0};
    BSL_Buffer P7Buff = {0};
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_List *caCertList = NULL;
    HITLS_X509_List *signerCertList = NULL;
    BSL_Buffer encodebuff = {0};
    ASSERT_EQ(BSL_SAL_ReadFile(p7path, &P7Buff.data, &P7Buff.dataLen), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, caPath, &caCert), HITLS_PKI_SUCCESS);
    ASSERT_NE(caCert, NULL);
    caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertList, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(caCertList, caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    uint64_t storeFlags = HITLS_X509_VFY_FLAG_PARTIAL_CHAIN;
    BSL_Param params[4] = {
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, 0, 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, p7path, &cms), HITLS_PKI_SUCCESS);
    /* RFC examples omit certificates to keep the CMS object small.  Reuse the
     * supplied trust certificate as the external signer certificate in that
     * case, and allow an explicitly trusted self-signed test certificate to
     * terminate a partial chain. */
    if (BSL_LIST_COUNT(cms->ctx.signedData->certs) == 0) {
        HITLS_X509_Cert *signerCert = HITLS_X509_CertDup(caCert);
        ASSERT_NE(signerCert, NULL);
        signerCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
        ASSERT_NE(signerCertList, NULL);
        ASSERT_EQ(BSL_LIST_AddElement(signerCertList, signerCert, BSL_LIST_POS_END), BSL_SUCCESS);
        TestMarkExplicitTrustAnchor(caCert);
        params[1] = (BSL_Param){HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS,
            BSL_PARAM_TYPE_CTX_PTR, signerCertList, 0, 0};
        params[2] = (BSL_Param){HITLS_CMS_PARAM_STORE_FLAGS, BSL_PARAM_TYPE_UINT64,
            &storeFlags, sizeof(storeFlags), 0};
        params[3] = (BSL_Param)BSL_PARAM_END;
    }
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encodebuff), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("encode compare", encodebuff.data, encodebuff.dataLen, P7Buff.data, P7Buff.dataLen);
    BSL_Buffer msgBuff = {NULL, 0};
    BSL_Buffer nullMsgBuf = {NULL, 0};
    ASSERT_EQ(BSL_SAL_ReadFile(msgpath, &msgBuff.data, &msgBuff.dataLen), BSL_SUCCESS);
    BSL_Buffer wrongMsgBuf = {msgBuff.data + 1, msgBuff.dataLen - 1};
    ASSERT_TRUE(TestIsErrStackEmpty());
    if (isDetached) {
        ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuff, params, NULL), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataVerify(cms, NULL, NULL, NULL), HITLS_CMS_ERR_SIGNEDDATA_NO_CONTENT);
        ASSERT_EQ(HITLS_CMS_DataVerify(cms, &nullMsgBuf, params, NULL), HITLS_CMS_ERR_SIGNEDDATA_NO_CONTENT);
        ASSERT_NE(HITLS_CMS_DataVerify(cms, &wrongMsgBuf, params, NULL), HITLS_PKI_SUCCESS);
        cms->ctx.signedData->encapCont.contentType = BSL_CID_PKCS7_ENVELOPEDDATA;
        if (version3 == 1) {
            ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuff, params, &output), HITLS_CMS_ERR_ENCAPCONT_TYPE);
        } else {
            ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuff, params, &output), HITLS_CMS_ERR_VERSION_INVALID);
        }
    } else {
        ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuff, params, NULL), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataVerify(cms, NULL, params, NULL), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_CMS_DataVerify(cms, &wrongMsgBuf, params, &output), HITLS_CMS_ERR_SIGNEDDATA_CONTENT_MISMATCH);
        ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuff, params, &output), HITLS_PKI_SUCCESS);
        ASSERT_COMPARE("verifyed data", output.data, output.dataLen, msgBuff.data, msgBuff.dataLen);
        ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuff, params, &output), HITLS_CMS_ERR_INVALID_DATA);
        cms->ctx.signedData->encapCont.contentType = BSL_CID_PKCS7_ENVELOPEDDATA;
        if (version3 == 1) {
            ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuff, params, &output), HITLS_CMS_ERR_ENCAPCONT_TYPE);
        } else {
            ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuff, params, &output), HITLS_CMS_ERR_VERSION_INVALID);
        }
    }
EXIT:
    HITLS_CMS_Free(cms);
    BSL_SAL_FREE(P7Buff.data);
    BSL_SAL_FREE(encodebuff.data);
    BSL_LIST_FREE(signerCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_SAL_FREE(msgBuff.data);
    BSL_SAL_FREE(output.data);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_PARSE_SIGNEDDATA_VERIFY_FAIL_TC001
 * @title  Reject invalid external CMS SignedData
 */
/* BEGIN_CASE */
void SDV_CMS_PARSE_SIGNEDDATA_VERIFY_FAIL_TC001(char *p7path, char *caPath, int expectedRet)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    (void)p7path;
    (void)caPath;
    (void)expectedRet;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_List *caCertList = NULL;

    ASSERT_EQ(HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, p7path, &cms), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, caPath, &caCert), HITLS_PKI_SUCCESS);
    caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertList, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(caCertList, caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[2] = {
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, 0, 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, NULL, params, NULL), expectedRet);
    TestErrClear();
EXIT:
    HITLS_CMS_Free(cms);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_PARSE_SIGNEDDATA_STREAM_VERIFY_TC001
 * @title  Stream-verify external detached SignedData
 */
/* BEGIN_CASE */
void SDV_CMS_PARSE_SIGNEDDATA_STREAM_VERIFY_TC001(char *p7path, char *msgpath, char *caPath)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    (void)p7path;
    (void)msgpath;
    (void)caPath;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_List *caCertList = NULL;
    BSL_Buffer msg = {0};

    ASSERT_EQ(HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, p7path, &cms), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(msgpath, &msg.data, &msg.dataLen), BSL_SUCCESS);
    ASSERT_TRUE(msg.dataLen > 1);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, caPath, &caCert), HITLS_PKI_SUCCESS);
    caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertList, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(caCertList, caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[2] = {
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, 0, 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msg, params, NULL), HITLS_PKI_SUCCESS);

    BSL_Buffer first = {msg.data, 1};
    BSL_Buffer rest = {msg.data + 1, msg.dataLen - 1};
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_VERIFY, cms, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &first), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &rest), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, params), HITLS_PKI_SUCCESS);

    first = (BSL_Buffer){msg.data, msg.dataLen - 1};
    rest = (BSL_Buffer){msg.data + msg.dataLen - 1, 1};
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_VERIFY, cms, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &first), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &rest), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, params), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_CMS_Free(cms);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_SAL_FREE(msg.data);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_PARSE_SIGNEDDATA_ASN1_BOUNDARY_TC001
 * @title  Reject malformed large SLH-DSA SignedData
 */
/* BEGIN_CASE */
void SDV_CMS_PARSE_SIGNEDDATA_ASN1_BOUNDARY_TC001(char *p7path, int mode)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    (void)p7path;
    (void)mode;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    BSL_Buffer input = {0};

    ASSERT_EQ(BSL_SAL_ReadFile(p7path, &input.data, &input.dataLen), BSL_SUCCESS);
    ASSERT_TRUE(input.dataLen > 6);
    if (mode == 0) {
        input.dataLen--;
    } else if (mode == 1) {
        uint32_t lenBytes = input.data[1] & 0x7f;
        ASSERT_TRUE((input.data[1] & 0x80) != 0 && lenBytes > 0 && lenBytes <= 4);
        input.data[1 + lenBytes]++;
    } else {
        input.data[1] = 0x84;
    }
    ASSERT_NE(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &input, &cms), HITLS_PKI_SUCCESS);
    TestErrClear();
EXIT:
    HITLS_CMS_Free(cms);
    BSL_SAL_FREE(input.data);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_PARSE_SIGNEDDATA_SIGNEDATTRS_INVALID_TC001
 * @title  Parse CMS SignedData with invalid signedAttrs
 * @brief
 *    1. Parse CMS SignedData with repeated required signedAttrs
 *    2. Parse CMS SignedData with multi-value signedAttrs SET
 * @expect
 *    1-2. Returns HITLS_CMS_ERR_SIGNEDDATA_SIGNEDATTRS_INVALID
 */
/* BEGIN_CASE */
void SDV_CMS_PARSE_SIGNEDDATA_SIGNEDATTRS_INVALID_TC001(char *p7path)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    (void)p7path;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    ASSERT_EQ(HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, p7path, &cms),
        HITLS_CMS_ERR_SIGNEDDATA_SIGNEDATTRS_INVALID);
EXIT:
    HITLS_CMS_Free(cms);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_PARSE_SIGNEDDATA_ENC_DEC_FILE_TC001
 * @title  Parse, encode and verify CMS SignedData from file
 * @brief
 *    1. Parse detached/attached CMS SignedData from file
 *    2. Encode to file
 *    3. Parse encoded file
 *    4. Verify with external message
 * @expect
 *    1-4. All operations successful
 */
/* BEGIN_CASE */
void SDV_CMS_PARSE_SIGNEDDATA_ENC_DEC_FILE_TC001(char *p7path, char *msgpath, int isDetached, char *caPath)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    (void)p7path;
    (void)msgpath;
    (void)isDetached;
    (void)caPath;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_CMS *cms1 = NULL;
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_List *caCertList = NULL;
    const char *writePath = "./p7_signeddata.p7s";
    BSL_Buffer msgBuff = {NULL, 0};
    ASSERT_EQ(BSL_SAL_ReadFile(msgpath, &msgBuff.data, &msgBuff.dataLen), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, caPath, &caCert), HITLS_PKI_SUCCESS);
    ASSERT_NE(caCert, NULL);
    caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertList, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(caCertList, caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[2] = {
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, 0, 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, p7path, &cms), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_GenFile(BSL_FORMAT_ASN1, cms, NULL, writePath), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, writePath, &cms1), HITLS_PKI_SUCCESS);
    if (isDetached) {
        ASSERT_EQ(HITLS_CMS_DataVerify(cms1, NULL, NULL, NULL), HITLS_CMS_ERR_SIGNEDDATA_NO_CONTENT);
        ASSERT_EQ(HITLS_CMS_DataVerify(cms1, &msgBuff, params, NULL), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_CMS_DataVerify(cms1, NULL, params, NULL), HITLS_PKI_SUCCESS);
        ASSERT_TRUE(TestIsErrStackEmpty());
    }
EXIT:
    HITLS_CMS_Free(cms);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_SAL_FREE(msgBuff.data);
    HITLS_CMS_Free(cms1);
    remove(writePath);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SIGNEDDATA_VERIFY_INVALID_SIGNDATA_TC001
 * @title  Verify CMS SignedData with no signer info
 * @brief
 *    1. Parse CMS SignedData with no signer info
 *    2. Verify with NULL CMS parameter
 *    3. Verify with no signer info
 * @expect
 *    1. Parse successful
 *    2. Returns HITLS_CMS_ERR_NULL_POINTER
 *    3. Returns HITLS_CMS_ERR_SIGNEDDATA_NO_SIGNERINFO
 */
/* BEGIN_CASE */
void SDV_CMS_SIGNEDATA_VERIFY_WITH_NO_SIGNERINFO_TC001(Hex *buff, Hex *msg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    (void)buff;
    (void)msg;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    BSL_Buffer buffBuff = {buff->x, buff->len};
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &buffBuff, &cms), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataVerify(NULL, (BSL_Buffer *)msg, NULL, NULL), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, (BSL_Buffer *)msg, NULL, NULL), HITLS_CMS_ERR_SIGNEDDATA_NO_SIGNERINFO);
EXIT:
    HITLS_CMS_Free(cms);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SIGNEDATA_VERIFY_WITH_INVALID_VERISON_TC001
 * @title  Verify CMS SignedData with invalid version
 * @brief
 *    1. Parse CMS SignedData with invalid SignerInfo version
 *    2. Verify SignedData
 * @expect
 *    1. Parse successful
 *    2. Returns HITLS_CMS_ERR_VERSION_INVALID
 */
/* BEGIN_CASE */
void SDV_CMS_SIGNEDATA_VERIFY_WITH_INVALID_VERISON_TC001(Hex *buff, Hex *msg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    (void)buff;
    (void)msg;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    BSL_Buffer buffBuff = {buff->x, buff->len};
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &buffBuff, &cms), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, (BSL_Buffer *)msg, NULL, NULL), HITLS_CMS_ERR_VERSION_INVALID);
EXIT:
    HITLS_CMS_Free(cms);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_ENCODE_SIGNEDDATA_TC001
 * @title  Encode CMS SignedData
 * @brief
 *    1. Parse CMS SignedData from buffer
 *    2. Encode CMS SignedData to buffer
 *    3. Parse encoded buffer again
 * @expect
 *    1. Parse successful
 *    2. Encode successful
 *    3. Parse successful
 */
/* BEGIN_CASE */
void SDV_CMS_ENCODE_SIGNEDDATA_TC001(Hex *buff)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    (void)buff;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_CMS *cms1 = NULL;

    ASSERT_EQ(HITLS_CMS_ParseSignedData(NULL, NULL, (BSL_Buffer *)buff, &cms), HITLS_PKI_SUCCESS);
    BSL_Buffer encode = {0};
    ASSERT_EQ(HITLS_CMS_GenSignedDataBuff(BSL_FORMAT_ASN1, cms, &encode), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("encode compare", encode.data, encode.dataLen, buff->x, buff->len);
    ASSERT_EQ(HITLS_CMS_ParseSignedData(NULL, NULL, &encode, &cms1), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_FREE(encode.data);
    HITLS_CMS_Free(cms1);
    HITLS_CMS_Free(cms);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_PARSE_SIGNEDDATA_ENCODE_INVALID_TC001
 * @title  Test invalid encode CMS SignedData
 * @brief
 *    1. Parse CMS SignedData
 *    2. Encode with NULL output buffer
 *    3. Encode with NULL CMS
 *    4. Encode with invalid cid
 * @expect
 *    1. Parse successful
 *    2-4. Returns appropriate error codes
 */
/* BEGIN_CASE */
void SDV_CMS_PARSE_SIGNEDDATA_ENCODE_INVALID_TC001(Hex *buff)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    (void)buff;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_CMS *cms1 = NULL;
    BSL_Buffer buffBuff = {buff->x, buff->len};
    BSL_Buffer encode = {0};
    const char *writePath = "./p7_signeddata.p7s";
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &buffBuff, &cms), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, NULL), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, NULL, NULL, &encode), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encode), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encode), HITLS_CMS_ERR_INVALID_DATA);
    cms1 = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms1, NULL);
    BSL_SAL_FREE(encode.data);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_PEM, cms1, NULL, &encode), HITLS_CMS_ERR_INVALID_FORMAT);
    ASSERT_NE(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms1, NULL, &encode), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_GenFile(BSL_FORMAT_PEM, cms, NULL, writePath), HITLS_CMS_ERR_INVALID_FORMAT);
    ASSERT_EQ(HITLS_CMS_GenFile(BSL_FORMAT_ASN1, NULL, NULL, NULL), HITLS_CMS_ERR_NULL_POINTER);
EXIT:
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(cms1);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SIGNERINFOGEN_SET_DN_TC001
 * @title  Test SignerInfo creation with issuerName and serialNumber (version 1)
 * @brief
 *    1. Load certificate and extract issuer name and serial number
 *    2. Create SignerInfo with version 1 using DataSign
 *    3. Verify SignerInfo structure matches certificate
 * @expect
 *    1-3. All operations successful, SignerInfo created with correct version and fields
 */
/* BEGIN_CASE */
void SDV_CMS_SIGNERINFOGEN_SET_DN_TC001(void)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_BSL_SAL_FILE)
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_CMS *cms = NULL;
    CMS_SignerInfo *signerInfo = NULL;
    uint8_t data[10] = {0}; // choose 10 to test
    BSL_Buffer msgBuf = {(uint8_t *)data, 10};
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/cert.pem", &cert), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cert != NULL);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/key.pem", NULL, 0, &pkey), CRYPT_SUCCESS);
        int32_t pkcsv15 = CRYPT_MD_SHA256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    // Extract issuer name and serial number
    BSL_ASN1_List *issuerName1 = NULL;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN, &issuerName1, sizeof(BSL_ASN1_List *)),
        HITLS_PKI_SUCCESS);
    ASSERT_NE(issuerName1, NULL);

    BSL_Buffer serialNum = {0};
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM, &serialNum, sizeof(BSL_Buffer)), HITLS_PKI_SUCCESS);
    ASSERT_NE(serialNum.data, NULL);
    ASSERT_TRUE(serialNum.dataLen > 0);

    // Call HITLS_CMS_DataSign to create signerinfo
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId = BSL_CID_SHA256;
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[4] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, 0, 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey, cert, &msgBuf, params), HITLS_PKI_SUCCESS);
    signerInfo = BSL_LIST_GET_FIRST(cms->ctx.signedData->signerInfos);
    ASSERT_NE(signerInfo, NULL);
    BSL_ASN1_List *issuerName2 = signerInfo->issuerName;
    HITLS_X509_NameNode *dest1 = BSL_LIST_GET_FIRST(issuerName1);
    HITLS_X509_NameNode *dest2 = BSL_LIST_GET_FIRST(issuerName2);
    if (dest1 != NULL) {
        ASSERT_TRUE(dest2 != NULL);
    }
    while (dest1 != NULL && dest2 != NULL) {
        ASSERT_COMPARE("issuerName compare", dest1->nameValue.buff, dest1->nameValue.len, dest2->nameValue.buff,
            dest2->nameValue.len);
        dest1 = (HITLS_X509_NameNode *)BSL_LIST_GET_NEXT(issuerName1);
        dest2 = (HITLS_X509_NameNode *)BSL_LIST_GET_NEXT(issuerName2);
        if (dest1 != NULL) {
            ASSERT_TRUE(dest2 != NULL);
        }
    }
    ASSERT_COMPARE("serialNum compare", signerInfo->certSerialNum.data, signerInfo->certSerialNum.dataLen,
        serialNum.data, serialNum.dataLen);

    // Verify SignerInfo structure
    ASSERT_EQ(signerInfo->version, HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SIGNERINFOGEN_SET_SKI_TC002
 * @title  Test SignerInfo creation with subjectKeyIdentifier (version 3)
 * @brief
 *    1. Load certificate and extract subject key identifier
 *    2. Create SignerInfo with version 3 using DataSign
 *    3. Verify SignerInfo structure matches certificate SKI
 * @expect
 *    1-3. All operations successful, SignerInfo created with correct version and SKI
 */
/* BEGIN_CASE */
void SDV_CMS_SIGNERINFOGEN_SET_SKI_TC002(void)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_BSL_SAL_FILE)
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    HITLS_X509_Cert *cert = NULL;
    CMS_SignerInfo *signerInfo = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_CMS *cms = NULL;
    uint8_t data[10] = {0}; // choose 10 to test
    BSL_Buffer msgBuf = {(uint8_t *)data, 10};
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/cert.pem", &cert), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cert != NULL);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/key.pem", NULL, 0, &pkey), CRYPT_SUCCESS);
    int32_t pkcsv15 = CRYPT_MD_SHA256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    // Extract SKI from certificate
    HITLS_X509_ExtSki ski = {0};
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SKI, &ski, sizeof(HITLS_X509_ExtSki)), HITLS_PKI_SUCCESS);
    ASSERT_NE(ski.kid.data, NULL);
    ASSERT_TRUE(ski.kid.dataLen > 0);

    // Call HITLS_CMS_DataSign to create signer info only
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3;
    int32_t mdId = BSL_CID_SHA256;
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[4] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey, cert, &msgBuf, params), HITLS_PKI_SUCCESS);
    signerInfo = BSL_LIST_GET_FIRST(cms->ctx.signedData->signerInfos);
    ASSERT_NE(signerInfo, NULL);
    // Verify SignerInfo structure
    ASSERT_EQ(signerInfo->version, HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3);
    ASSERT_COMPARE("ski compare", signerInfo->subjectKeyId.kid.data, signerInfo->subjectKeyId.kid.dataLen,
        ski.kid.data, ski.kid.dataLen);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_ADDSIGNERINFO_RSA_PSS_TC001
 * @title  Test DataSign with RSA-PSS padding
 * @brief
 *    1. Load RSA key and set PSS padding with parameters
 *    2. Create SignerInfo and sign with RSA-PSS
 *    3. Verify signature algorithm is RSASSAPSS with correct parameters
 * @expect
 *    1-3. All operations successful, signature created with RSA-PSS
 */
/* BEGIN_CASE */
void SDV_CMS_ADDSIGNERINFO_RSA_PSS_TC001(char *certPath, char *keyPath, char *msg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_BSL_SAL_FILE)
    (void)msg;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *cert = NULL;
    HITLS_CMS *cms = NULL;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    ASSERT_EQ(BSL_SAL_ReadFile(msg, &data, &dataLen), HITLS_PKI_SUCCESS);
    // Load certificate and key
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keyPath, NULL, 0, &pkey),
        CRYPT_SUCCESS);
    // Set RSA-PSS padding
    int32_t pad = CRYPT_EMSA_PSS;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(pad)), CRYPT_SUCCESS);

    // Set PSS parameters
    CRYPT_MD_AlgId pssHash = (CRYPT_MD_AlgId)BSL_CID_SHA256;
    CRYPT_MD_AlgId pssMgf = (CRYPT_MD_AlgId)BSL_CID_SHA256;
    int32_t pssSaltLen = 20;
    BSL_Param pssParams[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &pssHash, sizeof(pssHash), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &pssMgf, sizeof(pssMgf), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &pssSaltLen, sizeof(pssSaltLen), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParams, 0), CRYPT_SUCCESS);

    // Create CMS SignedData
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    BSL_Buffer msgBuf = {data, dataLen};
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId = BSL_CID_SHA256;
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[4] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey, cert, &msgBuf, params), HITLS_PKI_SUCCESS);

    // Get signerInfo back from cms to verify
    CMS_SignedData *signedData = cms->ctx.signedData;
    CMS_SignerInfo *addedSignerInfo = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(signedData->signerInfos);
    ASSERT_NE(addedSignerInfo, NULL);

    // Verify signature algorithm is RSA-PSS
    ASSERT_EQ(addedSignerInfo->sigAlg.algId, BSL_CID_RSASSAPSS);
    ASSERT_EQ(addedSignerInfo->sigAlg.rsaPssParam.mdId, BSL_CID_SHA256);
    ASSERT_EQ(addedSignerInfo->sigAlg.rsaPssParam.mgfId, BSL_CID_SHA256);
    ASSERT_EQ(addedSignerInfo->sigAlg.rsaPssParam.saltLen, 20);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_FREE(data);
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_ADDSIGNERINFO_RSA_PKCSV15_TC001
 * @title  Test DataSign with RSA PKCS#1 v1.5 padding
 * @brief
 *    1. Load RSA key and set PKCS#1 v1.5 padding
 *    2. Create SignerInfo and sign with PKCS#1 v1.5
 *    3. Verify signature algorithm is correct for RSA with SHA256
 * @expect
 *    1-3. All operations successful, signature created with PKCS#1 v1.5
 */
/* BEGIN_CASE */
void SDV_CMS_ADDSIGNERINFO_RSA_PKCSV15_TC001(char *certPath, char *keyPath, char *msg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_RSA) || !defined(HITLS_BSL_SAL_FILE)
    (void)certPath;
    (void)keyPath;
    (void)msg;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *cert = NULL;
    HITLS_CMS *cms = NULL;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(msg, &data, &dataLen);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Load certificate and key
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &cert), HITLS_PKI_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keyPath, NULL, 0, &pkey),
        CRYPT_SUCCESS);

    int32_t pkcsv15 = CRYPT_MD_SHA256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)),
        CRYPT_SUCCESS);

    // Create CMS SignedData
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    // Create SignerInfo and sign
    BSL_Buffer msgBuf = {data, dataLen};
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId = BSL_CID_SHA256;
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[4] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey, cert, &msgBuf, params), HITLS_PKI_SUCCESS);

    // Get signerInfo back from cms to verify
    CMS_SignedData *signedData = cms->ctx.signedData;
    CMS_SignerInfo *addedSignerInfo = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(signedData->signerInfos);
    ASSERT_NE(addedSignerInfo, NULL);

    // Verify signature algorithm is standard RSA.
    ASSERT_EQ(addedSignerInfo->sigAlg.algId, BSL_CID_RSA);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_FREE(data);
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_ADDSIGNERINFO_ECC_KEY_TC001
 * @title  Test DataSign with ECC P256 curve
 * @brief
 *    1. Load ECC P256 key and certificate
 *    2. Create SignerInfo and sign with ECC P256
 *    3. Verify signature algorithm is ECDSA with SHA256
 * @expect
 *    1-3. All operations successful, signature created with ECC P256
 */
/* BEGIN_CASE */
void SDV_CMS_ADDSIGNERINFO_ECC_KEY_TC001(char *certPath, char *keyPath, char *msg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_ECC) || !defined(HITLS_BSL_SAL_FILE)
    (void)certPath;
    (void)keyPath;
    (void)msg;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *cert = NULL;
    HITLS_CMS *cms = NULL;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(msg, &data, &dataLen);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // Load certificate and key
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &cert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_ECC, keyPath, NULL, 0, &pkey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Create CMS SignedData
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    // Create SignerInfo and sign
    BSL_Buffer msgBuf = {data, dataLen};
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId = BSL_CID_SHA256;
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);

    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[4] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey, cert, &msgBuf, params), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    // Get signerInfo back from cms to verify
    CMS_SignedData *signedData = cms->ctx.signedData;
    CMS_SignerInfo *addedSignerInfo = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(signedData->signerInfos);
    ASSERT_NE(addedSignerInfo, NULL);

    // Verify signature algorithm is ECDSA with SHA256
    BslCid expectedAlgId = BSL_OBJ_GetSignIdFromHashAndAsymId(BSL_CID_ECDSA, BSL_CID_SHA256);
    ASSERT_EQ(addedSignerInfo->sigAlg.algId, expectedAlgId);

EXIT:
    BSL_SAL_FREE(data);
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_CTRL_ADD_CERT_TC001
 * @title  Test adding certificate to CMS
 * @brief
 *    1. Create CMS SignedData and sign with certificate
 *    2. Generate CMS buffer
 *    3. Parse and verify certificate was added to CMS
 * @expect
 *    1-3. All operations successful, certificate included in generated CMS
 */
/* BEGIN_CASE */
void SDV_CMS_CTRL_ADD_CERT_TC001(char *certPath, char *keyPath, char *msg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_BSL_SAL_FILE)
    (void)certPath;
    (void)keyPath;
    (void)msg;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *cert = NULL;
    HITLS_CMS *cms = NULL;
    HITLS_CMS *cms1 = NULL;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;

    // Read message data
    int32_t ret = BSL_SAL_ReadFile(msg, &data, &dataLen);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    // Load certificate
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &cert), HITLS_PKI_SUCCESS);
    // Load private key
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keyPath, NULL, 0, &pkey),
        CRYPT_SUCCESS);
    // Create CMS SignedData
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    // Extract issuer and serial from certificate
    BSL_ASN1_List *issuerName = NULL;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN, &issuerName, sizeof(BSL_ASN1_List *)),
        HITLS_PKI_SUCCESS);

    BSL_Buffer serialNum = {0};
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM, &serialNum, sizeof(BSL_Buffer)), HITLS_PKI_SUCCESS);

    int32_t pkcsv15 = CRYPT_MD_SHA256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    BSL_Buffer msgBuf = {data, dataLen};
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId = BSL_CID_SHA256;
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[4] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey, cert, &msgBuf, params), HITLS_PKI_SUCCESS);

    // Generate CMS buffer
    BSL_Buffer cmsBuffer = {0};
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &cmsBuffer), HITLS_PKI_SUCCESS);
    ASSERT_NE(cmsBuffer.data, NULL);
    ASSERT_NE(cmsBuffer.dataLen, 0);

    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &cmsBuffer, &cms1), HITLS_PKI_SUCCESS);
    // Verify certificate was added to CMS
    CMS_SignedData *signedData = cms1->ctx.signedData;
    ASSERT_NE(signedData->certs, NULL);
    ASSERT_EQ(BSL_LIST_COUNT(signedData->certs), 1);

    // Verify a certificate exists in the list
    HITLS_X509_Cert *addedCert = (HITLS_X509_Cert *)BSL_LIST_GET_FIRST(signedData->certs);
    ASSERT_NE(addedCert, NULL);

    // Verify the certificate content matches by comparing serial numbers
    BSL_Buffer addedSerial = {0};
    ASSERT_EQ(HITLS_X509_CertCtrl(addedCert, HITLS_X509_GET_SERIALNUM, &addedSerial, sizeof(BSL_Buffer)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(addedSerial.dataLen, serialNum.dataLen);
    ASSERT_EQ(memcmp(addedSerial.data, serialNum.data, serialNum.dataLen), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_FREE(data);
    BSL_SAL_FREE(cmsBuffer.data);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(cms1);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_VERIFY_DIGEST_ALG_NOT_IN_LIST_TC001
 * @title  Verify fails when digest algorithm not in digestAlgorithms list
 * @brief
 *    1. Parse CMS SignedData
 *    2. Clear the digestAlgorithms list
 *    3. Verify SignedData
 * @expect
 *    1. Parse successful
 *    2. Clear successful
 *    3. Returns HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH
 */
/* BEGIN_CASE */
void SDV_CMS_VERIFY_DIGEST_ALG_NOT_IN_LIST_TC001(Hex *buff, Hex *msg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    (void)buff;
    (void)msg;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;

    // Parse CMS SignedData
    BSL_Buffer buffBuff = {buff->x, buff->len};
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &buffBuff, &cms), HITLS_PKI_SUCCESS);

    CMS_SignedData *signedData = cms->ctx.signedData;
    ASSERT_NE(signedData, NULL);
    ASSERT_NE(signedData->digestAlg, NULL);

    // Clear digestAlgorithms list
    BSL_LIST_FREE(signedData->digestAlg, (BSL_LIST_PFUNC_FREE)CMS_AlgIdFree);
    signedData->digestAlg = BSL_LIST_New(sizeof(CMS_AlgId));
    ASSERT_NE(signedData->digestAlg, NULL);
    // Verify should fail because digestAlgorithms list is empty
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, (BSL_Buffer *)msg, NULL, NULL), HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH);

EXIT:
    HITLS_CMS_Free(cms);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SIGNEDDATA_ROUNDTRIP_TC001
 * @title  Generate, parse, and verify SignedData
 */
/* BEGIN_CASE */
void SDV_CMS_SIGNEDDATA_ROUNDTRIP_TC001(int algId, char *caPath, char *certPath, char *keyPath, char *msgPath,
    int hasSignedAttrs)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_BSL_SAL_FILE)
    (void)algId;
    (void)caPath;
    (void)certPath;
    (void)keyPath;
    (void)msgPath;
    (void)hasSignedAttrs;
    SKIP_TEST();
#else
    TestCmsSignFixture fixture = {0};
    TestCmsSignOptions options = {
        .hasSignedAttrs = (bool)hasSignedAttrs,
        .digestMode = TEST_CMS_DIGEST_EXPLICIT,
        .algProtectMode = TEST_CMS_ALG_PROTECT_DEFAULT,
        .contentType = BSL_CID_UNKNOWN,
    };
    ASSERT_EQ(TestCmsFixtureInit(&fixture, algId, caPath, certPath, keyPath, msgPath), HITLS_PKI_SUCCESS);
    ASSERT_EQ(TestCmsSignAndParse(&fixture, &options), HITLS_PKI_SUCCESS);
    ASSERT_EQ(TestCmsCheckRoundTrip(&fixture, &options, BSL_CID_UNKNOWN), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestCmsFixtureClear(&fixture);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_DEFAULT_DIGEST_TC001
 * @title  Select the profile default digest
 */
/* BEGIN_CASE */
void SDV_CMS_DEFAULT_DIGEST_TC001(int algId, char *caPath, char *certPath, char *keyPath, char *msgPath,
    int hasSignedAttrs)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_BSL_SAL_FILE)
    (void)algId;
    (void)caPath;
    (void)certPath;
    (void)keyPath;
    (void)msgPath;
    (void)hasSignedAttrs;
    SKIP_TEST();
#else
    TestCmsSignFixture fixture = {0};
    TestCmsSignOptions options = {
        .hasSignedAttrs = (bool)hasSignedAttrs,
        .digestMode = TEST_CMS_DIGEST_DEFAULT,
        .algProtectMode = TEST_CMS_ALG_PROTECT_DEFAULT,
        .contentType = BSL_CID_UNKNOWN,
    };
    ASSERT_EQ(TestCmsFixtureInit(&fixture, algId, caPath, certPath, keyPath, msgPath), HITLS_PKI_SUCCESS);
    ASSERT_EQ(TestCmsSignAndParse(&fixture, &options), HITLS_PKI_SUCCESS);
    int32_t expectedDigest = TestCmsExpectedDefaultDigest(&fixture, options.hasSignedAttrs);
    ASSERT_EQ(TestCmsCheckRoundTrip(&fixture, &options, expectedDigest), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestCmsFixtureClear(&fixture);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_ALG_PROTECTION_GEN_TC001
 * @title  Enable or disable CMSAlgorithmProtection
 */
/* BEGIN_CASE */
void SDV_CMS_ALG_PROTECTION_GEN_TC001(int algId, char *caPath, char *certPath, char *keyPath, char *msgPath,
    int enabled)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_BSL_SAL_FILE)
    (void)algId;
    (void)caPath;
    (void)certPath;
    (void)keyPath;
    (void)msgPath;
    (void)enabled;
    SKIP_TEST();
#else
    TestCmsSignFixture fixture = {0};
    TestCmsSignOptions options = {
        .hasSignedAttrs = true,
        .digestMode = TEST_CMS_DIGEST_EXPLICIT,
        .algProtectMode = enabled ? TEST_CMS_ALG_PROTECT_ENABLE : TEST_CMS_ALG_PROTECT_DISABLE,
        .contentType = BSL_CID_UNKNOWN,
    };
    ASSERT_EQ(TestCmsFixtureInit(&fixture, algId, caPath, certPath, keyPath, msgPath), HITLS_PKI_SUCCESS);
    ASSERT_EQ(TestCmsSignAndParse(&fixture, &options), HITLS_PKI_SUCCESS);
    ASSERT_EQ(TestCmsCheckRoundTrip(&fixture, &options, BSL_CID_UNKNOWN), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestCmsFixtureClear(&fixture);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_ALG_PROTECTION_REJECT_TC001
 * @title  Reject inconsistent CMSAlgorithmProtection
 */
/* BEGIN_CASE */
void SDV_CMS_ALG_PROTECTION_REJECT_TC001(int algId, char *caPath, char *certPath, char *keyPath, char *msgPath)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_BSL_SAL_FILE)
    (void)algId;
    (void)caPath;
    (void)certPath;
    (void)keyPath;
    (void)msgPath;
    SKIP_TEST();
#else
    TestCmsSignFixture fixture = {0};
    BSL_Buffer macValue = {0};
    TestCmsSignOptions options = {
        .hasSignedAttrs = true,
        .digestMode = TEST_CMS_DIGEST_EXPLICIT,
        .algProtectMode = TEST_CMS_ALG_PROTECT_ENABLE,
        .contentType = BSL_CID_UNKNOWN,
    };
    ASSERT_EQ(TestCmsFixtureInit(&fixture, algId, caPath, certPath, keyPath, msgPath), HITLS_PKI_SUCCESS);
    ASSERT_EQ(TestCmsSignAndParse(&fixture, &options), HITLS_PKI_SUCCESS);
    ASSERT_EQ(TestCmsCheckRoundTrip(&fixture, &options, BSL_CID_UNKNOWN), HITLS_PKI_SUCCESS);

    CMS_SignerInfo *signer = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(fixture.parsed->ctx.signedData->signerInfos);
    HITLS_X509_AttrEntry *algAttr =
        TestFindCmsAttr(signer->signedAttrs, BSL_CID_PKCS9_AT_ALGORITHM_PROTECTION);
    ASSERT_NE(algAttr, NULL);
    if (algId == BSL_CID_RSASSAPSS) {
        int32_t savedSaltLen = signer->sigAlg.rsaPssParam.saltLen;
        signer->sigAlg.rsaPssParam.saltLen++;
        ASSERT_EQ(HITLS_CMS_DataVerify(fixture.parsed, &fixture.message, fixture.params, NULL),
            HITLS_CMS_ERR_ALG_PROTECTION_MISMATCH);
        signer->sigAlg.rsaPssParam.saltLen = savedSaltLen;
        TestErrClear();
        goto CHECK_ERROR_STACK;
    }

    BSL_ASN1_Buffer savedDigestParam = signer->digestAlg.param;
    signer->digestAlg.param = (BSL_ASN1_Buffer){BSL_ASN1_TAG_NULL, 0, NULL};
    ASSERT_EQ(HITLS_CMS_DataVerify(fixture.parsed, &fixture.message, fixture.params, NULL), HITLS_PKI_SUCCESS);
    signer->digestAlg.param = (BSL_ASN1_Buffer){BSL_ASN1_TAG_OCTETSTRING, 0, NULL};
    ASSERT_EQ(HITLS_CMS_DataVerify(fixture.parsed, &fixture.message, fixture.params, NULL),
        HITLS_CMS_ERR_ALG_PROTECTION_MISMATCH);
    signer->digestAlg.param = savedDigestParam;
    TestErrClear();

    BslCid savedSignAlg = signer->sigAlg.algId;
    signer->sigAlg.algId = BSL_CID_ECDSAWITHSHA256;
    ASSERT_EQ(HITLS_CMS_DataVerify(fixture.parsed, &fixture.message, fixture.params, NULL),
        HITLS_CMS_ERR_ALG_PROTECTION_MISMATCH);
    signer->sigAlg.algId = savedSignAlg;
    TestErrClear();

    CMS_AlgorithmProtection macProtection = {
        .digestAlgorithm = signer->digestAlg,
        .macAlgorithm.id = BSL_CID_HMAC_SHA256,
    };
    ASSERT_EQ(CMS_EncodeAlgorithmProtection(&macProtection, &macValue), HITLS_PKI_SUCCESS);
    BSL_ASN1_Buffer savedAttrValue = algAttr->attrValue;
    algAttr->attrValue.buff = macValue.data;
    algAttr->attrValue.len = macValue.dataLen;
    int32_t verifyRet = HITLS_CMS_DataVerify(fixture.parsed, &fixture.message, fixture.params, NULL);
    algAttr->attrValue = savedAttrValue;
    ASSERT_EQ(verifyRet, HITLS_CMS_ERR_ALG_PROTECTION_MISMATCH);
    TestErrClear();

    HITLS_X509_AttrEntry *duplicate = BSL_SAL_Calloc(1, sizeof(HITLS_X509_AttrEntry));
    ASSERT_NE(duplicate, NULL);
    *duplicate = *algAttr;
    duplicate->attrValue.buff = BSL_SAL_Dump(algAttr->attrValue.buff, algAttr->attrValue.len);
    ASSERT_NE(duplicate->attrValue.buff, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(signer->signedAttrs->list, duplicate, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(TestReparseCms(fixture.parsed), HITLS_CMS_ERR_SIGNEDDATA_SIGNEDATTRS_INVALID);
    BSL_LIST_DeleteNode(signer->signedAttrs->list, BSL_LIST_LastNode(signer->signedAttrs->list),
        (BSL_LIST_PFUNC_FREE)HITLS_X509_AttrEntryFree);
    TestErrClear();

    duplicate = BSL_SAL_Calloc(1, sizeof(HITLS_X509_AttrEntry));
    ASSERT_NE(duplicate, NULL);
    *duplicate = *algAttr;
    duplicate->attrValue.buff = BSL_SAL_Dump(algAttr->attrValue.buff, algAttr->attrValue.len);
    ASSERT_NE(duplicate->attrValue.buff, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(signer->unsignedAttrs->list, duplicate, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(TestReparseCms(fixture.parsed), HITLS_CMS_ERR_SIGNEDDATA_SIGNEDATTRS_INVALID);
    BSL_LIST_DeleteNode(signer->unsignedAttrs->list, BSL_LIST_LastNode(signer->unsignedAttrs->list),
        (BSL_LIST_PFUNC_FREE)HITLS_X509_AttrEntryFree);
    TestErrClear();

CHECK_ERROR_STACK:
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_FREE(macValue.data);
    TestCmsFixtureClear(&fixture);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_PQC_POLICY_TC001
 * @title  Enforce PQC SignedData profile rules
 */
/* BEGIN_CASE */
void SDV_CMS_PQC_POLICY_TC001(int algId, char *caPath, char *certPath, char *keyPath, char *msgPath,
    int hasSignedAttrs)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_BSL_SAL_FILE)
    (void)algId;
    (void)caPath;
    (void)certPath;
    (void)keyPath;
    (void)msgPath;
    (void)hasSignedAttrs;
    SKIP_TEST();
#else
    TestCmsSignFixture fixture = {0};
    TestCmsSignOptions options = {
        .hasSignedAttrs = (bool)hasSignedAttrs,
        .digestMode = TEST_CMS_DIGEST_EXPLICIT,
        .algProtectMode = TEST_CMS_ALG_PROTECT_DISABLE,
        .contentType = BSL_CID_UNKNOWN,
    };
    ASSERT_EQ(TestCmsFixtureInit(&fixture, algId, caPath, certPath, keyPath, msgPath), HITLS_PKI_SUCCESS);
    ASSERT_EQ(TestCmsSignAndParse(&fixture, &options), HITLS_PKI_SUCCESS);
    ASSERT_EQ(TestCmsCheckRoundTrip(&fixture, &options, BSL_CID_UNKNOWN), HITLS_PKI_SUCCESS);

    CMS_SignerInfo *signer = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(fixture.parsed->ctx.signedData->signerInfos);
    if (fixture.isMlDsa && !options.hasSignedAttrs) {
        ASSERT_EQ(signer->digestAlg.id, BSL_CID_SHA512);
        BSL_ASN1_Buffer savedParam = signer->digestAlg.param;
        signer->digestAlg.id = BSL_CID_SHA256;
        signer->digestAlg.param = (BSL_ASN1_Buffer){BSL_ASN1_TAG_OCTETSTRING, 0, NULL};
        ASSERT_EQ(HITLS_CMS_DataVerify(fixture.parsed, &fixture.message, fixture.params, NULL), HITLS_PKI_SUCCESS);
        signer->digestAlg.id = BSL_CID_SHA512;
        signer->digestAlg.param = savedParam;
    } else if (fixture.isSlhDsa && !options.hasSignedAttrs) {
        BslCid savedDigest = signer->digestAlg.id;
        signer->digestAlg.id = BSL_CID_SHA384;
        ASSERT_EQ(HITLS_CMS_DataVerify(fixture.parsed, &fixture.message, fixture.params, NULL), HITLS_PKI_SUCCESS);
        signer->digestAlg.id = BSL_CID_AES128_CBC;
        ASSERT_EQ(HITLS_CMS_DataVerify(fixture.parsed, &fixture.message, fixture.params, NULL), HITLS_PKI_SUCCESS);
        signer->digestAlg.id = savedDigest;
    } else {
        BslCid savedDigest = signer->digestAlg.id;
        signer->digestAlg.id = savedDigest == BSL_CID_SHA256 ? BSL_CID_SHA512 : BSL_CID_SHA256;
        ASSERT_EQ(HITLS_CMS_DataVerify(fixture.parsed, &fixture.message, fixture.params, NULL),
            HITLS_CMS_ERR_INVALID_ALGO);
        signer->digestAlg.id = savedDigest;
        TestErrClear();

        BslCid savedSignAlg = signer->sigAlg.algId;
        signer->sigAlg.algId = fixture.isSlhDsa ?
            (savedSignAlg == BSL_CID_SLH_DSA_SHA2_128S ?
            BSL_CID_SLH_DSA_SHA2_128F : BSL_CID_SLH_DSA_SHA2_128S) :
            (savedSignAlg == BSL_CID_MLDSA44_RSA2048_PSS_SHA256 ?
            BSL_CID_MLDSA44_RSA2048_PKCS15_SHA256 : BSL_CID_MLDSA44_RSA2048_PSS_SHA256);
        ASSERT_EQ(HITLS_CMS_DataVerify(fixture.parsed, &fixture.message, fixture.params, NULL),
            HITLS_X509_ERR_VFY_SIGNALG_NOT_MATCH);
        signer->sigAlg.algId = savedSignAlg;
        TestErrClear();
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestCmsFixtureClear(&fixture);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_ATTACHED_MULTI_SIGNER_TC001
 * @title  Add two signers to attached SignedData
 */
/* BEGIN_CASE */
void SDV_CMS_ATTACHED_MULTI_SIGNER_TC001(int algId, char *caPath, char *certPath, char *keyPath, char *msgPath)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_BSL_SAL_FILE)
    (void)algId;
    (void)caPath;
    (void)certPath;
    (void)keyPath;
    (void)msgPath;
    SKIP_TEST();
#else
    TestCmsSignFixture fixture = {0};
    TestCmsSignOptions options = {
        .hasSignedAttrs = true,
        .digestMode = TEST_CMS_DIGEST_EXPLICIT,
        .algProtectMode = TEST_CMS_ALG_PROTECT_DEFAULT,
        .contentType = BSL_CID_UNKNOWN,
    };
    ASSERT_EQ(TestCmsFixtureInit(&fixture, algId, caPath, certPath, keyPath, msgPath), HITLS_PKI_SUCCESS);
    ASSERT_EQ(TestCmsSignAndParse(&fixture, &options), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataSign(fixture.cms, fixture.key, fixture.cert, &fixture.message, fixture.params),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(fixture.cms->ctx.signedData->signerInfos), 2);
    ASSERT_EQ(HITLS_CMS_DataVerify(fixture.cms, NULL, fixture.params, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataVerify(fixture.cms, &fixture.message, fixture.params, NULL), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestCmsFixtureClear(&fixture);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_CONTENT_TYPE_TC001
 * @title  Preserve a non-id-data content type
 */
/* BEGIN_CASE */
void SDV_CMS_CONTENT_TYPE_TC001(int algId, char *caPath, char *certPath, char *keyPath, char *msgPath,
    int contentType)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_BSL_SAL_FILE)
    (void)algId;
    (void)caPath;
    (void)certPath;
    (void)keyPath;
    (void)msgPath;
    (void)contentType;
    SKIP_TEST();
#else
    TestCmsSignFixture fixture = {0};
    TestCmsSignOptions options = {
        .hasSignedAttrs = true,
        .digestMode = TEST_CMS_DIGEST_EXPLICIT,
        .algProtectMode = TEST_CMS_ALG_PROTECT_DEFAULT,
        .contentType = (BslCid)contentType,
    };
    ASSERT_EQ(TestCmsFixtureInit(&fixture, algId, caPath, certPath, keyPath, msgPath), HITLS_PKI_SUCCESS);
    ASSERT_EQ(TestCmsSignAndParse(&fixture, &options), HITLS_PKI_SUCCESS);
    ASSERT_EQ(TestCmsCheckRoundTrip(&fixture, &options, BSL_CID_UNKNOWN), HITLS_PKI_SUCCESS);
    ASSERT_EQ(fixture.parsed->ctx.signedData->encapCont.contentType, contentType);
    ASSERT_TRUE(!fixture.parsed->ctx.signedData->detached);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestCmsFixtureClear(&fixture);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_GEN_DETACHED_SIGNEDDATA_MULTI_SIGNER_TC001
 * @title  Generate detached CMS SignedData with multiple signers
 * @brief
 *    1. Load two different RSA certificates and keys
 *    2. Create two SignerInfo structures and add both to CMS
 *    3. Generate detached SignedData buffer
 *    4. Parse and verify with one-shot and streaming APIs
 * @expect
 *    1-4. All operations successful, multi-signer detached SignedData verified
 */
/* BEGIN_CASE */
void SDV_CMS_GEN_DETACHED_SIGNEDDATA_MULTI_SIGNER_TC001(char *capath, char *capath2,  char *certPath1, char *keyPath1,
    char *certPath2, char *keyPath2, char *msg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_BSL_SAL_FILE)
    (void)capath;
    (void)capath2;
    (void)certPath1;
    (void)keyPath1;
    (void)certPath2;
    (void)keyPath2;
    (void)msg;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey1 = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_Cert *caCert2 = NULL;
    HITLS_X509_Cert *cert1 = NULL;
    HITLS_X509_Cert *cert2 = NULL;
    HITLS_CMS *cms = NULL;
    HITLS_CMS *parsedCms = NULL;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;

    // Read message data
    ASSERT_EQ(BSL_SAL_ReadFile(msg, &data, &dataLen), HITLS_PKI_SUCCESS);

    // Load first certificate and key
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath1, &cert1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, capath, &caCert), HITLS_PKI_SUCCESS);
    if (strcmp(capath2, capath) != 0) {
        ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, capath2, &caCert2), HITLS_PKI_SUCCESS);
    }

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keyPath1, NULL, 0, &pkey1),
        CRYPT_SUCCESS);

    // Load second certificate and key
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath2, &cert2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keyPath2, NULL, 0, &pkey2),
        CRYPT_SUCCESS);
    int32_t alg1 = CRYPT_EAL_PkeyGetId(pkey1);
    int32_t alg2 = CRYPT_EAL_PkeyGetId(pkey2);
    int32_t pkcsv15 = CRYPT_MD_SHA256;
    if (alg1 == BSL_CID_RSA) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey1, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    }
    if (alg2 == BSL_CID_RSA) {
        pkcsv15 = CRYPT_MD_SHA384;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey2, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    }

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    // Add SignerInfo and sign
    BSL_Buffer msgBuf = {data, dataLen};
    int32_t version1 = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId1 = BSL_CID_SHA256;
    HITLS_X509_List *caCertchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(caCertchain, caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    if (caCert2 != NULL) {
        ASSERT_EQ(BSL_LIST_AddElement(caCertchain, caCert2, BSL_LIST_POS_END), BSL_SUCCESS);
    }
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert1, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert2, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params1[5] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version1, sizeof(version1), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId1, sizeof(mdId1), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey1, cert1, &msgBuf, params1), HITLS_PKI_SUCCESS);
    int32_t version2 = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3;
    int32_t mdId2 = BSL_CID_SHA384;
    BSL_Param params2[5] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version2, sizeof(version2), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId2, sizeof(mdId2), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey2, cert2, &msgBuf, params2), HITLS_PKI_SUCCESS);

    BSL_Buffer cmsBuffer = {0};
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &cmsBuffer), HITLS_PKI_SUCCESS);
    ASSERT_NE(cmsBuffer.data, NULL);

    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &cmsBuffer, &parsedCms), HITLS_PKI_SUCCESS);

    // Verify there are 2 signers
    CMS_SignedData *signedData = parsedCms->ctx.signedData;
    ASSERT_EQ(BSL_LIST_COUNT(signedData->signerInfos), 2);

    // Verify with external message
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuf, params1, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataVerify(parsedCms, &msgBuf, params1, NULL), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_VERIFY, parsedCms, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(parsedCms, &msgBuf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataFinal(parsedCms, params2), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_FREE(data);
    BSL_SAL_FREE(cmsBuffer.data);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(parsedCms);
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_STREAM_SIGN_DETACHED_TC001
 * @title  Test streaming signature/verification for detached CMS SignedData
 * @brief
 *    1. Initialize streaming signature, update with message chunks, finalize
 *    2. Generate and parse detached SignedData, with 2 signerinfos
 *    3. Verify with one-shot API and streaming API (Init/Update/Final)
 * @expect
 *    1-3. streaming signature and verification operations successful
 */
/* BEGIN_CASE */
void SDV_CMS_STREAM_SIGN_DETACHED_TC001(char *capath, char *cert1Path, char *key1Path, char *capath2, char *cert2Path,
    char *key2Path, char *msg)
{
#ifndef HITLS_PKI_CMS_SIGNEDDATA
    (void)capath;
    (void)cert1Path;
    (void)key1Path;
    (void)capath2;
    (void)cert2Path;
    (void)key2Path;
    (void)msg;
    SKIP_TEST();
#else
    TestRandInit();
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_Cert *caCert2 = NULL;
    HITLS_X509_Cert *cert1 = NULL;
    HITLS_X509_Cert *cert2 = NULL;
    CRYPT_EAL_PkeyCtx *pkey1 = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    BSL_Buffer encode = {0};

    // Load certificate
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, cert1Path, &cert1), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cert1 != NULL);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, cert2Path, &cert2), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cert2 != NULL);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, capath, &caCert), HITLS_PKI_SUCCESS);
    if (strcmp(capath, capath2) != 0) {
        ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, capath2, &caCert2), HITLS_PKI_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, key1Path, NULL, 0, &pkey1),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_ECC, key2Path, NULL, 0, &pkey2),
        CRYPT_SUCCESS);
    ASSERT_TRUE(pkey1 != NULL);
    ASSERT_TRUE(pkey2 != NULL);
    int32_t alg1 = CRYPT_EAL_PkeyGetId(pkey1);
    if (alg1 == BSL_CID_RSA) {
        int32_t pkcsv15 = CRYPT_MD_SHA256;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey1, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)),
            CRYPT_SUCCESS);
    }
    // Create CMS SignedData (detached by default)
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_TRUE(cms != NULL);
    int32_t mdId1 = BSL_CID_SHA256;
    int32_t mdId2 = BSL_CID_SHA384;
    HITLS_X509_List *caCertchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(caCertchain, caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    if (caCert2 != NULL) {
        ASSERT_EQ(BSL_LIST_AddElement(caCertchain, caCert2, BSL_LIST_POS_END), BSL_SUCCESS);
    }
    HITLS_X509_List *untrustedCertchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(untrustedCertchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(untrustedCertchain, cert2, BSL_LIST_POS_END), BSL_SUCCESS);
    // Set message digest algorithm
    BSL_Param signParams[2] = {
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId1, sizeof(mdId1), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_Ctrl(cms, HITLS_CMS_SET_MSG_MD, &mdId2, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_SIGN, cms, signParams), HITLS_PKI_SUCCESS);
    // Update with message in chunks
    size_t msgLen = strlen(msg);
    size_t chunkSize = msgLen / 3;  // Split into 3 chunks

    // First chunk
    BSL_Buffer msgBuf = {(uint8_t *)msg, chunkSize};
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf), HITLS_PKI_SUCCESS);
    // Second chunk
    BSL_Buffer msgBuf1 = {(uint8_t *)msg + chunkSize, chunkSize};
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf1), HITLS_PKI_SUCCESS);
    // Third chunk
    BSL_Buffer msgBuf2 = {(uint8_t *)msg + 2 * chunkSize, msgLen - 2 * chunkSize};
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf2), HITLS_PKI_SUCCESS);

    // Finalize signature
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3;
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert1, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params1[7] = {
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, pkey1, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        {HITLS_CMS_PARAM_DEVICE_CERT, BSL_PARAM_TYPE_CTX_PTR, cert1, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId1, sizeof(mdId1), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, params1), HITLS_PKI_SUCCESS);

    // Generate CMS buffer
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encode), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(encode.data != NULL && encode.dataLen > 0);

    // Parse the generated CMS
    HITLS_CMS *cms2 = NULL;
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encode, &cms2), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cms2 != NULL);
    if (CRYPT_EAL_PkeyGetId(pkey1) == CRYPT_PKEY_ML_DSA) {
        CMS_SignerInfo *si = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(cms2->ctx.signedData->signerInfos);
        ASSERT_NE(si, NULL);
        ASSERT_NE(TestFindCmsAttr(si->signedAttrs, BSL_CID_PKCS9_AT_ALGORITHM_PROTECTION), NULL);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());
    BSL_Param verifyParams1[7] = {
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    BSL_Buffer allMsgBuf = {(uint8_t *)msg, msgLen};
    // Verify signature with external message using one-shot API
    ASSERT_EQ(HITLS_CMS_DataVerify(cms2, &allMsgBuf, NULL, NULL), HITLS_X509_ERR_VFY_ISSUE_CERT_NOT_FOUND_LOCALLY);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms2, &allMsgBuf, verifyParams1, NULL), HITLS_PKI_SUCCESS);

    // Initialize streaming verification
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_VERIFY, cms2, NULL), HITLS_PKI_SUCCESS);

    // Update with message in chunks (same chunking as signing)
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms2, &msgBuf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms2, &msgBuf1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms2, &msgBuf2), HITLS_PKI_SUCCESS);
    // Finalize verification
    ASSERT_EQ(HITLS_CMS_DataFinal(cms2, verifyParams1), HITLS_PKI_SUCCESS);

    BSL_Param params2[7] = {
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, pkey2, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        {HITLS_CMS_PARAM_DEVICE_CERT, BSL_PARAM_TYPE_CTX_PTR, cert2, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId2, sizeof(mdId2), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, params2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &allMsgBuf, NULL, NULL), HITLS_X509_ERR_VFY_ISSUE_CERT_NOT_FOUND_LOCALLY);
    BSL_Param verifyParams2[7] = {
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &allMsgBuf, verifyParams2, NULL), HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_CERT);
    BSL_Param verifyParams3[7] = {
        {HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, untrustedCertchain,
            sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &allMsgBuf, verifyParams3, NULL), HITLS_PKI_SUCCESS);

    // Initialize streaming verification
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_VERIFY, cms, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, verifyParams3), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_FREE(encode.data);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(cms2);
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(untrustedCertchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_STREAM_SIGN_NO_SIGNED_ATTRS_TC001
 * @title  Test streaming signature for detached SignedData without signedAttrs
 * @brief
 *    1. Generate detached SignedData without signedAttrs using streaming signing
 *    2. Parse generated SignedData
 *    3. Verify it with one-shot and streaming verification
 * @expect
 *    1-3. streaming signature can be verified with the original message
 */
/* BEGIN_CASE */
void SDV_CMS_STREAM_SIGN_NO_SIGNED_ATTRS_TC001(char *capath, char *certPath, char *keyPath, char *msg, int hasSignedAttrs)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_BSL_SAL_FILE)
    (void)capath;
    (void)certPath;
    (void)keyPath;
    (void)msg;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *caCert = NULL;
    HITLS_CMS *cms = NULL;
    HITLS_CMS *parsedCms = NULL;
    HITLS_X509_List *caCertchain = NULL;
    HITLS_X509_List *certchain = NULL;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    BSL_Buffer cmsBuffer = {0};

    ASSERT_EQ(BSL_SAL_ReadFile(msg, &data, &dataLen), HITLS_PKI_SUCCESS);
    ASSERT_NE(dataLen, 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, capath, &caCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keyPath, NULL, 0, &pkey),
        CRYPT_SUCCESS);
    if (CRYPT_EAL_PkeyGetId(pkey) == CRYPT_PKEY_RSA) {
        int32_t pkcsv15 = CRYPT_MD_SHA256;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)),
            CRYPT_SUCCESS);
    }

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    caCertchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(caCertchain, caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert, BSL_LIST_POS_END), BSL_SUCCESS);

    int32_t mdId = BSL_CID_SHA256;
    BSL_Param initParams[2] = {
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_SIGN, cms, initParams), HITLS_PKI_SUCCESS);

    uint32_t chunkSize = dataLen / 3;
    BSL_Buffer msgBuf1 = {data, chunkSize};
    BSL_Buffer msgBuf2 = {data + chunkSize, chunkSize};
    BSL_Buffer msgBuf3 = {data + 2 * chunkSize, dataLen - 2 * chunkSize};
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf3), HITLS_PKI_SUCCESS);

    int32_t signerVersion = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    bool isDetached = true;
    bool hasNoSignedAttrs = !((bool)hasSignedAttrs);
    BSL_Param signParams[8] = {
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, pkey, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        {HITLS_CMS_PARAM_DEVICE_CERT, BSL_PARAM_TYPE_CTX_PTR, cert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &signerVersion, sizeof(signerVersion), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &isDetached, sizeof(isDetached), 0},
        {HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL, &hasNoSignedAttrs, sizeof(hasNoSignedAttrs), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, signParams), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &cmsBuffer), HITLS_PKI_SUCCESS);
    ASSERT_NE(cmsBuffer.data, NULL);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &cmsBuffer, &parsedCms), HITLS_PKI_SUCCESS);

    BSL_Buffer msgBuf = {data, dataLen};
    BSL_Param verifyParams[2] = {
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataVerify(parsedCms, &msgBuf, verifyParams, NULL), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_VERIFY, parsedCms, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(parsedCms, &msgBuf1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(parsedCms, &msgBuf2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(parsedCms, &msgBuf3), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataFinal(parsedCms, verifyParams), HITLS_PKI_SUCCESS);

EXIT:
    BSL_SAL_FREE(data);
    BSL_SAL_FREE(cmsBuffer.data);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(parsedCms);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_STREAM_VERIFY_NO_SIGNED_ATTRS_TC001
 * @title  Support streaming verification for detached SignedData without signedAttrs
 * @brief
 *    1. Generate detached SignedData without signedAttrs using one-shot signing
 *    2. Verify the SignedData with one-shot API
 *    3. Verify the SignedData with streaming API using the correct message
 *    4. Verify the SignedData with streaming API using a different message
 * @expect
 *    1-3. one-shot and streaming verification succeed with the correct message
 *    4. streaming verification fails with a different message
 */
/* BEGIN_CASE */
void SDV_CMS_STREAM_VERIFY_NO_SIGNED_ATTRS_TC001(char *capath, char *certPath, char *keyPath, char *msg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_BSL_SAL_FILE)
    (void)capath;
    (void)certPath;
    (void)keyPath;
    (void)msg;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *caCert = NULL;
    HITLS_CMS *cms = NULL;
    HITLS_CMS *parsedCms = NULL;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    uint8_t *wrongData = NULL;

    ASSERT_EQ(BSL_SAL_ReadFile(msg, &data, &dataLen), HITLS_PKI_SUCCESS);
    ASSERT_NE(dataLen, 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, capath, &caCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keyPath, NULL, 0, &pkey),
        CRYPT_SUCCESS);
    if (CRYPT_EAL_PkeyGetId(pkey) == CRYPT_PKEY_RSA) {
        int32_t pkcsv15 = CRYPT_MD_SHA256;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)),
            CRYPT_SUCCESS);
    }

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    BSL_Buffer msgBuf = {data, dataLen};
    int32_t signerVersion = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId = BSL_CID_SHA256;
    bool isDetached = true;
    bool hasNoSignedAttrs = true;
    HITLS_X509_List *caCertchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(caCertchain, caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param signParams[7] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &signerVersion, sizeof(signerVersion), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &isDetached, sizeof(isDetached), 0},
        {HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL, &hasNoSignedAttrs, sizeof(hasNoSignedAttrs), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey, cert, &msgBuf, signParams), HITLS_PKI_SUCCESS);

    BSL_Buffer cmsBuffer = {0};
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &cmsBuffer), HITLS_PKI_SUCCESS);
    ASSERT_NE(cmsBuffer.data, NULL);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &cmsBuffer, &parsedCms), HITLS_PKI_SUCCESS);

    BSL_Param verifyParams[2] = {
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataVerify(parsedCms, &msgBuf, verifyParams, NULL), HITLS_PKI_SUCCESS);

    size_t chunkSize = dataLen / 3;
    BSL_Buffer msgBuf1 = {data, chunkSize};
    BSL_Buffer msgBuf2 = {data + chunkSize, chunkSize};
    BSL_Buffer msgBuf3 = {data + 2 * chunkSize, dataLen - (uint32_t)(2 * chunkSize)};

    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_VERIFY, parsedCms, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(parsedCms, &msgBuf1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(parsedCms, &msgBuf2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(parsedCms, &msgBuf3), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataFinal(parsedCms, verifyParams), HITLS_PKI_SUCCESS);

    wrongData = BSL_SAL_Dump(data, dataLen);
    ASSERT_NE(wrongData, NULL);
    wrongData[dataLen - 1] ^= 0x01;
    BSL_Buffer wrongMsgBuf1 = {wrongData, chunkSize};
    BSL_Buffer wrongMsgBuf2 = {wrongData + chunkSize, chunkSize};
    BSL_Buffer wrongMsgBuf3 = {wrongData + 2 * chunkSize, dataLen - (uint32_t)(2 * chunkSize)};
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_VERIFY, parsedCms, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(parsedCms, &wrongMsgBuf1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(parsedCms, &wrongMsgBuf2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(parsedCms, &wrongMsgBuf3), HITLS_PKI_SUCCESS);
    ASSERT_NE(HITLS_CMS_DataFinal(parsedCms, verifyParams), HITLS_PKI_SUCCESS);

EXIT:
    BSL_SAL_FREE(data);
    BSL_SAL_FREE(wrongData);
    BSL_SAL_FREE(cmsBuffer.data);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(parsedCms);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_STREAM_NODETACHED_TEST_TC001
 * @title  Test streaming APIs with non-detached CMS SignedData
 * @brief
 *    1. Create non-detached CMS SignedData
 *    2. Use streaming signature API (Init/Update/Final)
 *    3. Generate CMS buffer and parse it back
 *    4. Use streaming verification API (Init/Update/Final)
 * @expect
 *    1-4. Streaming operations succeed, one-shot API works
 */
/* BEGIN_CASE */
void SDV_CMS_STREAM_NODETACHED_TEST_TC001(void)
{
#ifndef HITLS_PKI_CMS_SIGNEDDATA
    SKIP_TEST();
#else
    TestRandInit();
    HITLS_CMS *cms = NULL;
    HITLS_CMS *cms2 = NULL;
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *caCert = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BSL_Buffer encode = {0};

    // Load certificate
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/cert.pem", &cert), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cert != NULL);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/asn1/cms/signeddata/ca_cert.pem", &caCert), HITLS_PKI_SUCCESS);
    // Load key
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/key.pem", NULL, 0, &pkey), CRYPT_SUCCESS);
    ASSERT_TRUE(pkey != NULL);

    int32_t pkcsv15 = CRYPT_MD_SHA256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    // Create CMS SignedData in non-detached mode
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_TRUE(cms != NULL);

    int32_t mdId = BSL_CID_SHA256;
    // Set message digest algorithm
    ASSERT_EQ(HITLS_CMS_Ctrl(cms, HITLS_CMS_SET_MSG_MD, &mdId, 0), HITLS_PKI_SUCCESS);

    // Initialize and update streaming signature
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_SIGN, cms, NULL), HITLS_PKI_SUCCESS);
    const char *msg1 = "This is the test message";
    BSL_Buffer msgBuf = {(uint8_t *)msg1, strlen(msg1)};

    // Try to finalize streaming signature on non-detached CMS
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    bool isDetached = false; // thid param is not useful in stream.
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    HITLS_X509_List *caCertchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(caCertchain, caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[8] = {
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, pkey, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        {HITLS_CMS_PARAM_DEVICE_CERT, BSL_PARAM_TYPE_CTX_PTR, cert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &isDetached, sizeof(isDetached), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, params), HITLS_PKI_SUCCESS);

    // Generate and parse CMS
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encode), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encode, &cms2), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cms2 != NULL);
    // Try to initialize streaming verification on non-detached CMS - should fail
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_VERIFY, cms2, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms2, &msgBuf), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(HITLS_CMS_DataFinal(cms2, NULL), HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_CERT);
    BSL_Param verifyParams1[8] = {
        {HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataFinal(cms2, verifyParams1), HITLS_X509_ERR_VFY_ISSUE_CERT_NOT_FOUND_LOCALLY);
    TestErrClear();
    BSL_Param verifyParams2[8] = {
        {HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataFinal(cms2, verifyParams2), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_FREE(encode.data);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(cms2);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_MIXED_SING_VERIFY_TC001
 * @title  Test mixing streaming and one-shot signature/verification APIs
 * @brief
 *    1. Use streaming signature API for first signer
 *    2. Use one-shot signature API for second signer
 *    3. Generate and parse CMS buffer
 *    4. Verify using both one-shot and streaming APIs
 * @expect
 *    1-4. All operations succeed, APIs can be mixed freely for detached SignedData
 */
/* BEGIN_CASE */
void SDV_CMS_MIXED_SING_VERIFY_TC001(void)
{
#ifndef HITLS_PKI_CMS_SIGNEDDATA
    SKIP_TEST();
#else
    TestRandInit();
    HITLS_CMS *cms = NULL;
    HITLS_CMS *cms2 = NULL;
    HITLS_X509_Cert *cert1 = NULL;
    HITLS_X509_Cert *cert2 = NULL;
    HITLS_X509_Cert *caCert = NULL;
    CRYPT_EAL_PkeyCtx *pkey1 = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    BSL_Buffer encode = {0};
    char *msg = "Test message for mixed streaming and one-shot signing";
    size_t msgLen = strlen(msg);

    // Load first certificate and key (RSA-PKCS#1 v1.5)
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/cert.pem", &cert1), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cert1 != NULL);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/asn1/cms/signeddata/ca_cert.pem", &caCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/key.pem", NULL, 0, &pkey1), CRYPT_SUCCESS);
    ASSERT_TRUE(pkey1 != NULL);
    int32_t pkcsv15 = CRYPT_MD_SHA256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey1, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    // Load second certificate and key (RSA-PSS)
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/asn1/cms/signeddata/rsa-pss/cert.pem", &cert2), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cert2 != NULL);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        "../testdata/cert/asn1/cms/signeddata/rsa-pss/key.pem", NULL, 0, &pkey2), CRYPT_SUCCESS);
    ASSERT_TRUE(pkey2 != NULL);
    int32_t pad = CRYPT_EMSA_PSS;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey2, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(pad)), CRYPT_SUCCESS);
    CRYPT_MD_AlgId pssHash = (CRYPT_MD_AlgId)BSL_CID_SHA256;
    CRYPT_MD_AlgId pssMgf = (CRYPT_MD_AlgId)BSL_CID_SHA256;
    int32_t pssSaltLen = 32;
    BSL_Param pssParams[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &pssHash, sizeof(pssHash), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &pssMgf, sizeof(pssMgf), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &pssSaltLen, sizeof(pssSaltLen), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey2, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParams, 0), CRYPT_SUCCESS);

    // Create detached CMS SignedData
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_TRUE(cms != NULL);

    // Create first SignerInfo using one-shot signature
    BSL_Buffer initMsgBuf = {(uint8_t *)msg, msgLen};
    int32_t version1 = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId = BSL_CID_SHA256;
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    HITLS_X509_List *caCertchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(caCertchain, caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert1, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert2, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[5] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version1, sizeof(version1), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey1, cert1, &initMsgBuf, params), HITLS_PKI_SUCCESS);

    // Sign first SignerInfo using streaming API
    // Set message digest algorithm
    ASSERT_EQ(HITLS_CMS_Ctrl(cms, HITLS_CMS_SET_MSG_MD, &mdId, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_SIGN, cms, NULL), HITLS_PKI_SUCCESS);
    size_t chunkSize = msgLen / 3;
    BSL_Buffer msgBuf = {(uint8_t *)msg, chunkSize};
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf), HITLS_PKI_SUCCESS);
    BSL_Buffer msgBuf1 = {(uint8_t *)msg + chunkSize, chunkSize};
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf1), HITLS_PKI_SUCCESS);
    BSL_Buffer msgBuf2 = {(uint8_t *)msg + 2 * chunkSize, msgLen - 2 * chunkSize};
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf2), HITLS_PKI_SUCCESS);

    BSL_Param signParams[7] = {
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, pkey1, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        {HITLS_CMS_PARAM_DEVICE_CERT, BSL_PARAM_TYPE_CTX_PTR, cert1, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version1, sizeof(version1), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, signParams), HITLS_PKI_SUCCESS);
    BSL_Param signParam2[7] = {
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, pkey2, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        {HITLS_CMS_PARAM_DEVICE_CERT, BSL_PARAM_TYPE_CTX_PTR, cert2, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, signParam2), HITLS_PKI_SUCCESS);

    // Generate and parse CMS
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encode), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(encode.data != NULL && encode.dataLen > 0);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encode, &cms2), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cms2 != NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());

    // Verify all SignerInfos using one-shot API first
    ASSERT_EQ(HITLS_CMS_DataVerify(cms2, &initMsgBuf, NULL, NULL), HITLS_X509_ERR_VFY_ISSUE_CERT_NOT_FOUND_LOCALLY);
    TestErrClear();
    ASSERT_EQ(HITLS_CMS_DataVerify(cms2, &initMsgBuf, params, NULL), HITLS_PKI_SUCCESS);

    // Verify all SignerInfos using streaming API (verifies both signers simultaneously)
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_VERIFY, cms2, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms2, &msgBuf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms2, &msgBuf1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms2, &msgBuf2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataFinal(cms2, params), HITLS_PKI_SUCCESS);

    // re-initialize streaming signature for first SignerInfo again
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_SIGN, cms, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, signParams), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_FREE(encode.data);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(cms2);
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_NODETACHED_DIFF_MSG_FAIL_TC001
 * @title  Test non-detached SignedData with different messages should fail
 * @brief
 *    1. Create non-detached CMS SignedData
 *    2. Add first SignerInfo with message1 (succeeds)
 *    3. Try to add second SignerInfo with different message2
 * @expect
 *    1. Creation successful
 *    2. First signer addition succeeds
 *    3. Second signer addition fails with HITLS_CMS_ERR_SIGNEDDATA_CONTENT_MISMATCH
 */
/* BEGIN_CASE */
void SDV_CMS_NODETACHED_DIFF_MSG_FAIL_TC001(void)
{
#ifndef HITLS_PKI_CMS_SIGNEDDATA
    SKIP_TEST();
#else
    TestRandInit();
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *cert1 = NULL;
    HITLS_X509_Cert *cert2 = NULL;
    HITLS_X509_Cert *caCert = NULL;
    CRYPT_EAL_PkeyCtx *pkey1 = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;

    // Load first certificate and key
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/cert.pem", &cert1), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cert1 != NULL);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/asn1/cms/signeddata/ca_cert.pem", &caCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/key.pem", NULL, 0, &pkey1), CRYPT_SUCCESS);
    ASSERT_TRUE(pkey1 != NULL);
    int32_t pkcsv15 = CRYPT_MD_SHA256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey1, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    // Load second certificate and key
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/asn1/cms/signeddata/rsa-pss/cert.pem", &cert2), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cert2 != NULL);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        "../testdata/cert/asn1/cms/signeddata/rsa-pss/key.pem", NULL, 0, &pkey2), CRYPT_SUCCESS);
    ASSERT_TRUE(pkey2 != NULL);
    int32_t pad = CRYPT_EMSA_PSS;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey2, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(pad)), CRYPT_SUCCESS);
    CRYPT_MD_AlgId pssHash = (CRYPT_MD_AlgId)BSL_CID_SHA256;
    CRYPT_MD_AlgId pssMgf = (CRYPT_MD_AlgId)BSL_CID_SHA256;
    int32_t pssSaltLen = 32;
    BSL_Param pssParams[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &pssHash, sizeof(pssHash), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &pssMgf, sizeof(pssMgf), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &pssSaltLen, sizeof(pssSaltLen), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey2, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParams, 0), CRYPT_SUCCESS);

    // Create CMS SignedData in non-detached mode
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_TRUE(cms != NULL);

    // Add first signerInfo with message1 - should succeed
    char *msg1 = "This is the first message";
    BSL_Buffer msgBuf1 = {(uint8_t *)msg1, strlen(msg1)};
    int32_t version1 = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId1 = BSL_CID_SHA256;
    bool isDetached = false;
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    HITLS_X509_List *caCertchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_NE(caCertchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert1, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert2, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(caCertchain, caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params1[6] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version1, sizeof(version1), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId1, sizeof(mdId1), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &isDetached, sizeof(isDetached), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey1, cert1, &msgBuf1, params1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, NULL, params1, NULL),  HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    // Create second SignerInfo
    char *msg2 = "This is a different message";
    BSL_Buffer msgBuf2 = {(uint8_t *)msg2, strlen(msg2)};
    int32_t version2 = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3;
    int32_t mdId2 = BSL_CID_SHA256;
    BSL_Param params2[6] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version2, sizeof(version2), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId2, sizeof(mdId2), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &isDetached, sizeof(isDetached), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey2, cert2, &msgBuf2, params2), HITLS_CMS_ERR_SIGNEDDATA_CONTENT_MISMATCH);
EXIT:
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    BSL_LIST_FREE(caCertchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SIGNEDDATA_INVALID_TC001
 * @title  Test streaming APIs with NULL parameters
 * @brief
 *    1. Test DataSignInit/Update/Final with NULL parameters
 *    2. Test DataVerifyInit/Update/Final with NULL parameters
 * @expect
 *    1-2. All return appropriate error codes (NULL_POINTER or INVALID_PARAM)
 */
/* BEGIN_CASE */
void SDV_CMS_SIGNEDDATA_INVALID_TC001(void)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_SHA256)
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    const uint8_t msg[] = "test message";
    HITLS_X509_Cert *cert = NULL;

    TestRandInit();
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_SIGN, NULL, NULL), HITLS_CMS_ERR_NULL_POINTER);
    BSL_Buffer msgBuf = {(uint8_t *)msg, sizeof(msg)};
    ASSERT_EQ(HITLS_CMS_DataUpdate(NULL, &msgBuf), HITLS_CMS_ERR_NULL_POINTER);

    // Create minimal cms and signerInfo for remaining tests
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_TRUE(cms != NULL);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/cert.pem", &cert), HITLS_PKI_SUCCESS);

    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId = BSL_CID_SHA256;
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[6] = {
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, pkey, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        {HITLS_CMS_PARAM_DEVICE_CERT, BSL_PARAM_TYPE_CTX_PTR, cert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataFinal(NULL, params), HITLS_CMS_ERR_NULL_POINTER);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/key.pem", NULL, 0, &pkey), CRYPT_SUCCESS);
    ASSERT_TRUE(pkey != NULL);

    BSL_Param paramsNoKey[5] = {
        {HITLS_CMS_PARAM_DEVICE_CERT, BSL_PARAM_TYPE_CTX_PTR, cert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, paramsNoKey), HITLS_CMS_ERR_INVALID_STATE);
    BSL_Param paramsNoCert[5] = {
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, pkey, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, paramsNoCert), HITLS_CMS_ERR_INVALID_STATE);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_VERIFY, NULL, NULL), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_VERIFY, cms, NULL), HITLS_CMS_ERR_SIGNEDDATA_NO_SIGNERINFO);
    ASSERT_EQ(HITLS_CMS_DataUpdate(NULL, &msgBuf), HITLS_CMS_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf), HITLS_CMS_ERR_INVALID_STATE);
    ASSERT_EQ(HITLS_CMS_DataFinal(NULL, NULL), HITLS_CMS_ERR_NULL_POINTER);

EXIT:
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SIGNEDDATA_INVALID_TC002
 * @title  Test streaming operations without proper initialization
 * @brief
 *    1. Call SignUpdate without SignInit
 *    2. Call SignFinal without SignInit
 *    3. Call VerifyUpdate without VerifyInit
 *    4. Call VerifyFinal without VerifyInit
 * @expect
 *    1-4. All return appropriate error codes (CTX_IS_NOT_INIT or INVALID_PARAM)
 */
/* BEGIN_CASE */
void SDV_CMS_SIGNEDDATA_INVALID_TC002(void)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t msg[] = "test message";
    HITLS_X509_Cert *cert = NULL;

    TestRandInit();

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_TRUE(cms != NULL);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/key.pem", NULL, 0, &pkey), CRYPT_SUCCESS);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/cert.pem", &cert), HITLS_PKI_SUCCESS);

    int32_t pkcsv15 = CRYPT_MD_SHA256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    BSL_Buffer msgBuf = {msg, sizeof(msg)};
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_SIGN, cms, NULL), HITLS_CMS_ERR_SIGNEDDATA_NO_FIND_HASH);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf), HITLS_CMS_ERR_INVALID_STATE);
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId = BSL_CID_SHA256;
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[6] = {
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, pkey, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        {HITLS_CMS_PARAM_DEVICE_CERT, BSL_PARAM_TYPE_CTX_PTR, cert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, params), HITLS_CMS_ERR_INVALID_STATE);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_VERIFY, cms, NULL), HITLS_CMS_ERR_SIGNEDDATA_NO_SIGNERINFO);
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf), HITLS_CMS_ERR_INVALID_STATE);
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, NULL), HITLS_CMS_ERR_INVALID_STATE);
EXIT:
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_STREAM_INCORRECT_SEQUENCE_TC001
 * @title  Test streaming operations with incorrect call sequence
 * @brief
 *    1. Call Init, Update, Final normally, then call Update again
 *    2. Call Final again after Final
 *    3. Call Init twice without Update/Final in between
 * @expect
 *    1. Update after Final returns error
 *    2. Second Final succeeds
 *    3. Second Init succeeds (reinitialization)
 */
/* BEGIN_CASE */
void SDV_CMS_STREAM_INCORRECT_SEQUENCE_TC001(void)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *cert = NULL;
    char *msg = "test message";

    TestRandInit();

    // Setup
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_TRUE(cms != NULL);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/cert.pem", &cert), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cert != NULL);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        "../testdata/cert/asn1/cms/signeddata/rsa-pkcsv5/key.pem", NULL, 0, &pkey), CRYPT_SUCCESS);
    ASSERT_TRUE(pkey != NULL);

    int32_t pkcsv15 = CRYPT_MD_SHA256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    // Update after Final
    // Set message digest algorithm
    uint32_t mdId = BSL_CID_SHA256;
    ASSERT_EQ(HITLS_CMS_Ctrl(cms, HITLS_CMS_SET_MSG_MD, &mdId, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_SIGN, cms, NULL), HITLS_PKI_SUCCESS);
    BSL_Buffer msgBuf = {(uint8_t *)msg, strlen(msg)};
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf), HITLS_PKI_SUCCESS);
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[6] = {
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, pkey, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        {HITLS_CMS_PARAM_DEVICE_CERT, BSL_PARAM_TYPE_CTX_PTR, cert, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, params), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    // Try to update after final, Should fail.
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf), HITLS_CMS_ERR_INVALID_STATE);
    // Call Final again, will be sucecss.
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, params), HITLS_PKI_SUCCESS);

    // Call Init twice - second Init should succeed (reinitialization)
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_SIGN, cms, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_SIGN, cms, NULL), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SIGNEDDATA_PARSE_ENCODE_STUB_TC001
 * @title  Test encode and parse with memory allocation failures
 * @brief
 *    1. Parse CMS SignedData successfully to count malloc calls
 *    2. Test parse with systematic malloc failures
 *    3. Encode CMS SignedData successfully to count malloc calls
 *    4. Test encode with systematic malloc failures
 * @expect
 *    1. Parse successful
 *    2. All parse malloc failures return error
 *    3. Encode successful
 *    4. All encode malloc failures return error
 */
/* BEGIN_CASE */
void SDV_CMS_SIGNEDDATA_PARSE_ENCODE_STUB_TC001(Hex *buff)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    (void)buff;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    HITLS_CMS *cms1 = NULL;
    TestRandInit();
    BSL_Buffer encode = {0};
    uint32_t totalMallocCount = 0;

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_ParseSignedData(NULL, NULL, (BSL_Buffer *)buff, &cms), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        (void)HITLS_CMS_ParseSignedData(NULL, NULL, (BSL_Buffer *)buff, &cms1);
        HITLS_CMS_Free(cms1);
        cms1 = NULL;
    }

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_GenSignedDataBuff(BSL_FORMAT_ASN1, cms, &encode), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    BSL_SAL_Free(encode.data);
    encode.data = NULL;

    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ASSERT_NE(HITLS_CMS_GenSignedDataBuff(BSL_FORMAT_ASN1, cms, &encode), HITLS_PKI_SUCCESS);
    }
EXIT:
    HITLS_CMS_Free(cms);
    STUB_RESTORE(BSL_SAL_Malloc);
#endif
}
/* END_CASE */

/**
 * @brief Helper structure to hold certificate chain and key materials
 */
typedef struct {
    HITLS_X509_Cert *rootCert;
    HITLS_X509_Cert *caCert;
    HITLS_X509_Cert *device1Cert;
    HITLS_X509_Cert *device2Cert;
    HITLS_X509_Crl *crl;
    HITLS_X509_Crl *crlEmpty;
    CRYPT_EAL_PkeyCtx *pkey1;
    CRYPT_EAL_PkeyCtx *pkey2;
} TestCertChainCtx;

/**
 * @brief Load certificate chain, CRLs and private keys from files
 * @param basePath Base directory path
 * @param ctx Output context to store loaded materials
 * @return HITLS_PKI_SUCCESS on success, error code otherwise
 */
static int32_t LoadCertChainAndKeys(const char *basePath, TestCertChainCtx *ctx)
{
    memset(ctx, 0, sizeof(TestCertChainCtx));
    char rootPath[256];
    char caPath[256];
    char device1CertPath[256];
    char device1KeyPath[256];
    char device2CertPath[256];
    char device2KeyPath[256];
    char crlPath[256];
    char crlEmptyPath[256];

    (void)snprintf(rootPath, sizeof(rootPath), "%s/root_ca.crt", basePath);
    (void)snprintf(caPath, sizeof(caPath), "%s/mid_ca.crt", basePath);
    (void)snprintf(device1CertPath, sizeof(device1CertPath), "%s/device1.crt", basePath);
    (void)snprintf(device1KeyPath, sizeof(device1KeyPath), "%s/device1.key", basePath);
    (void)snprintf(device2CertPath, sizeof(device2CertPath), "%s/device2.crt", basePath);
    (void)snprintf(device2KeyPath, sizeof(device2KeyPath), "%s/device2.key", basePath);
    (void)snprintf(crlPath, sizeof(crlPath), "%s/mid_ca_revocation.crl", basePath);
    (void)snprintf(crlEmptyPath, sizeof(crlEmptyPath), "%s/mid_ca_empty.crl", basePath);

    int32_t ret = 0;
    // Load certificates
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, rootPath, &ctx->rootCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, caPath, &ctx->caCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, device1CertPath, &ctx->device1Cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, device2CertPath, &ctx->device2Cert), HITLS_PKI_SUCCESS);

    // Load CRLs
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_UNKNOWN, crlPath, &ctx->crl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_UNKNOWN, crlEmptyPath, &ctx->crlEmpty), HITLS_PKI_SUCCESS);

    // Load private keys
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        device1KeyPath, NULL, 0, &ctx->pkey1), HITLS_PKI_SUCCESS);
    int32_t pkcsv15 = CRYPT_MD_SHA256;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx->pkey1, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)),
        HITLS_PKI_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        device2KeyPath, NULL, 0, &ctx->pkey2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx->pkey2, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)),
        HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    return ret;
}

/**
 * @test   SDV_CMS_SIGN_VERIFY_WITH_CERT_CHAIN_CRL_TC001
 * @title  Sign and verify with certificate chain and CRL
 * @brief
 *    1. Read certificate chain and CRL from files
 *    2. Sign with device1 (not in CRL), add chain and CRL, verify
 *    3. Sign with device2 (in CRL), add chain and CRL, verify
 * @expect
 *    1. Read successful
 *    2. Device1 verification succeeds
 *    3. Device2 verification fails with HITLS_CMS_ERR_VERIFY_FAIL
 */
/* BEGIN_CASE */
void SDV_CMS_SIGN_VERIFY_WITH_CERT_CHAIN_CRL_TC001(char *basePath, char *msg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_PKI_X509_CRL)
    (void)basePath;
    (void)msg;
    SKIP_TEST();
#else
    TestRandInit();
    HITLS_CMS *cms = NULL;
    HITLS_CMS *cms2 = NULL;
    BSL_Buffer encode1 = {0};
    BSL_Buffer encode2 = {0};
    TestCertChainCtx certCtx = {0};

    // Load certificate chain, CRLs and private keys
    ASSERT_EQ(LoadCertChainAndKeys(basePath, &certCtx), HITLS_PKI_SUCCESS);
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId = BSL_CID_SHA256;
    bool isDetached = false;
    HITLS_X509_List *deviceCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(deviceCertList, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(deviceCertList, certCtx.device1Cert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(deviceCertList, certCtx.device2Cert, BSL_LIST_POS_END), BSL_SUCCESS);
    HITLS_X509_List *crlList = BSL_LIST_New(sizeof(HITLS_X509_Crl *));
    ASSERT_NE(crlList, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(crlList, certCtx.crl, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(crlList, certCtx.crlEmpty, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[6] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &isDetached, sizeof(isDetached), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, deviceCertList, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CRL_LISTS, BSL_PARAM_TYPE_CTX_PTR, crlList, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, certCtx.caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, certCtx.rootCert, BSL_LIST_POS_END), BSL_SUCCESS);
    int32_t purpose = HITLS_X509_VFY_PURPOSE_ANY;
    BSL_Param verifyParams[3] = {
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, chain, 0, 0},
        BSL_PARAM_END,
        BSL_PARAM_END
    };
    BSL_Buffer msgBuf = {(uint8_t *)msg, strlen(msg)};
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_EQ(HITLS_CMS_DataSign(cms, certCtx.pkey1, certCtx.device1Cert, &msgBuf, params), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encode1), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(encode1.data != NULL && encode1.dataLen > 0);
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encode1, &cms2), HITLS_PKI_SUCCESS);
    ASSERT_NE(cms2, NULL);
    // no issuer
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuf, NULL, NULL), HITLS_X509_ERR_VFY_ISSUE_CERT_NOT_FOUND_LOCALLY);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms2, &msgBuf, NULL, NULL), HITLS_X509_ERR_VFY_ISSUE_CERT_NOT_FOUND_LOCALLY);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuf, verifyParams, NULL), HITLS_X509_ERR_VFY_PURPOSE_UNMATCH);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms2, &msgBuf, verifyParams, NULL), HITLS_X509_ERR_VFY_PURPOSE_UNMATCH);
    TestErrClear();
    verifyParams[1] = (BSL_Param){HITLS_CMS_PARAM_VERIFY_PURPOSE, BSL_PARAM_TYPE_INT32,
        &purpose, sizeof(purpose), 0};
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuf, verifyParams, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms2, &msgBuf, verifyParams, NULL), HITLS_PKI_SUCCESS);

EXIT:
    BSL_SAL_FREE(encode1.data);
    BSL_SAL_FREE(encode2.data);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(cms2);
    CRYPT_EAL_PkeyFreeCtx(certCtx.pkey1);
    CRYPT_EAL_PkeyFreeCtx(certCtx.pkey2);
    BSL_LIST_FREE(deviceCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(crlList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SIGN_VERIFY_WITH_CERT_CHAIN_CRL_TC001
 * @title  Sign and verify with certificate chain and CRL
 * @brief
 *    1. Read certificate chain and CRL from files
 *    2. Sign with device1 (not in CRL), add chain and CRL, verify
 *    3. Sign with device2 (in CRL), add chain and CRL, verify
 * @expect
 *    1. Read successful
 *    2. Device1 verification succeeds
 *    3. Device2 verification fails with HITLS_CMS_ERR_VERIFY_FAIL
 */
/* BEGIN_CASE */
void SDV_CMS_SIGN_VERIFY_WITH_CERT_CHAIN_CRL_TC002(char *basePath, char *msg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_PKI_X509_CRL)
    (void)basePath;
    (void)msg;
    SKIP_TEST();
#else
    TestRandInit();
    HITLS_CMS *cms = NULL;
    HITLS_CMS *cms2 = NULL;
    BSL_Buffer encode1 = {0};
    BSL_Buffer encode2 = {0};
    TestCertChainCtx certCtx = {0};

    // Load certificate chain, CRLs and private keys
    ASSERT_EQ(LoadCertChainAndKeys(basePath, &certCtx), HITLS_PKI_SUCCESS);
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId = BSL_CID_SHA256;
    bool isDetached = false;
    HITLS_X509_List *deviceCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(deviceCertList, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(deviceCertList, certCtx.device1Cert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(deviceCertList, certCtx.device2Cert, BSL_LIST_POS_END), BSL_SUCCESS);
    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(chain, certCtx.caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(chain, certCtx.rootCert, BSL_LIST_POS_END), BSL_SUCCESS);
    HITLS_X509_List *crlList = BSL_LIST_New(sizeof(HITLS_X509_Crl *));
    ASSERT_NE(crlList, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(crlList, certCtx.crl, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(crlList, certCtx.crlEmpty, BSL_LIST_POS_END), BSL_SUCCESS);
    uint64_t storeFlag = 0;
    BSL_Param params[8] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &isDetached, sizeof(isDetached), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, deviceCertList, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, chain, 0, 0},
        {HITLS_CMS_PARAM_CRL_LISTS, BSL_PARAM_TYPE_CTX_PTR, crlList, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_STORE_FLAGS, BSL_PARAM_TYPE_UINT64, &storeFlag, sizeof(storeFlag), 0},
        BSL_PARAM_END
    };

    BSL_Buffer msgBuf = {(uint8_t *)msg, strlen(msg)};
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);
    version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    ASSERT_EQ(HITLS_CMS_DataSign(cms, certCtx.pkey1, certCtx.device1Cert, &msgBuf, params), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encode1), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(encode1.data != NULL && encode1.dataLen > 0);
    // Parse and verify device1's signed CMS - should succeed (device1 not in CRL)
    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encode1, &cms2), HITLS_PKI_SUCCESS);
    ASSERT_NE(cms2, NULL);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuf, params, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms2, &msgBuf, params, NULL), HITLS_PKI_SUCCESS);

    // for test part chain verify.
    HITLS_X509_List *partChain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(partChain, NULL);
    int ref;
    ASSERT_EQ(HITLS_X509_CertCtrl(certCtx.caCert, HITLS_X509_REF_UP, &ref, sizeof(int32_t)), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(partChain, certCtx.caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    BSL_Param partiChain[4] = {
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, partChain, 0, 0},
        {HITLS_CMS_PARAM_CRL_LISTS, BSL_PARAM_TYPE_CTX_PTR, crlList, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_STORE_FLAGS, BSL_PARAM_TYPE_UINT64, &storeFlag, sizeof(storeFlag), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataVerify(cms2, &msgBuf, partiChain, NULL), HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
    storeFlag = HITLS_X509_VFY_FLAG_PARTIAL_CHAIN;
    ASSERT_EQ(HITLS_CMS_DataVerify(cms2, &msgBuf, partiChain, NULL), BSL_SUCCESS);

    HITLS_CMS_Free(cms2);
    cms2 = NULL;

    // set second signerInfo.
    version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3;
    ASSERT_EQ(HITLS_CMS_DataSign(cms, certCtx.pkey2, certCtx.device2Cert, &msgBuf, params), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &encode2), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(encode2.data != NULL && encode2.dataLen > 0);

    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &encode2, &cms2), HITLS_PKI_SUCCESS);
    ASSERT_NE(cms2, NULL);
    // Verify device2's signed CMS - should fail (device2 in CRL)
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuf, NULL, NULL), HITLS_X509_ERR_VFY_ISSUE_CERT_NOT_FOUND_LOCALLY);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms2, &msgBuf, NULL, NULL), HITLS_X509_ERR_VFY_ISSUE_CERT_NOT_FOUND_LOCALLY);

    ASSERT_EQ(HITLS_CMS_DataVerify(cms2, &msgBuf, params, NULL), HITLS_PKI_SUCCESS);
    storeFlag = HITLS_X509_VFY_FLAG_CRL_DEV | HITLS_X509_VFY_FLAG_CRL_LITE;
    ASSERT_EQ(HITLS_CMS_DataVerify(cms2, &msgBuf, params, NULL), HITLS_X509_ERR_VFY_CERT_REVOKED);
EXIT:
    BSL_SAL_FREE(encode1.data);
    BSL_SAL_FREE(encode2.data);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(cms2);
    CRYPT_EAL_PkeyFreeCtx(certCtx.pkey1);
    CRYPT_EAL_PkeyFreeCtx(certCtx.pkey2);
    BSL_LIST_FREE(deviceCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(crlList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    BSL_LIST_FREE(partChain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SIGN_VERIFY_WITH_CERT_CHAIN_CRL_TC003
 * @title  Verify with input certificate chain parameter
 * @brief
 *    1. Read certificate chain and CRL, sign with device1
 *    2. Build certificate chain manually in StoreCtx
 *    3. Verify with input certificate chain using one-shot API
 *    4. Create detached SignedData and verify with streaming API using input chain
 * @expect
 *    1-4. Verification succeeds with input chain, fails without chain
 */
/* BEGIN_CASE */
void SDV_CMS_SIGN_VERIFY_WITH_CERT_CHAIN_CRL_TC003(char *basePath, char *msg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_PKI_X509_CRL)
    (void)basePath;
    (void)msg;
    SKIP_TEST();
#else
    TestRandInit();
    HITLS_CMS *cms = NULL;
    HITLS_CMS *cms2 = NULL;
    BSL_Buffer encode1 = {0};
    BSL_Buffer encode2 = {0};
    TestCertChainCtx certCtx = {0};

    // Load certificate chain, CRLs and private keys
    ASSERT_EQ(LoadCertChainAndKeys(basePath, &certCtx), HITLS_PKI_SUCCESS);
    HITLS_X509_List *deviceCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(deviceCertList, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(deviceCertList, certCtx.device1Cert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(deviceCertList, certCtx.device2Cert, BSL_LIST_POS_END), BSL_SUCCESS);
    HITLS_X509_List *cachain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(cachain, NULL);
    HITLS_X509_List *midchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(midchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(cachain, certCtx.rootCert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(midchain, certCtx.caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    int32_t mdId = BSL_CID_SHA256;
    HITLS_X509_List *crlList = BSL_LIST_New(sizeof(HITLS_X509_Crl *));
    ASSERT_NE(crlList, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(crlList, certCtx.crl, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(crlList, certCtx.crlEmpty, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[6] = {
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, deviceCertList, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, cachain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, midchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CRL_LISTS, BSL_PARAM_TYPE_CTX_PTR, crlList, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    BSL_Buffer msgBuf = {(uint8_t *)msg, strlen(msg)};
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);
    ASSERT_EQ(HITLS_CMS_DataSign(cms, certCtx.pkey1, certCtx.device1Cert, &msgBuf, params), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    BSL_Param verifyParams1[2] = {
        {HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, midchain, 0, 0},
        BSL_PARAM_END
    };
    BSL_Param verifyParams2[2] = {
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, cachain, 0, 0},
        BSL_PARAM_END
    };
    BSL_Param verifyParams3[2] = { // wrong ca list.
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, midchain, 0, 0},
        BSL_PARAM_END
    };

    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuf, params, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuf, verifyParams1, NULL), HITLS_X509_ERR_VFY_ISSUE_CERT_NOT_FOUND_LOCALLY);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuf, verifyParams2, NULL), HITLS_X509_ERR_VFY_ISSUE_CERT_NOT_FOUND_LOCALLY);
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuf, verifyParams3, NULL), HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
EXIT:
    BSL_SAL_FREE(encode1.data);
    BSL_SAL_FREE(encode2.data);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(cms2);
    CRYPT_EAL_PkeyFreeCtx(certCtx.pkey1);
    CRYPT_EAL_PkeyFreeCtx(certCtx.pkey2);
    BSL_LIST_FREE(deviceCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(cachain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(midchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(crlList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    TestRandDeInit();
#endif
}
/* END_CASE */

static int32_t STUB_HITLS_X509_CheckKey(HITLS_X509_Cert *cert, CRYPT_EAL_PkeyCtx *prvKey)
{
    (void)cert;
    (void)prvKey;
    return HITLS_PKI_SUCCESS;
}

/**
 * @test   SDV_CMS_HASH_SLH_SIGN_REJECT_TC001
 * @title  Reject every HashSLH-DSA parameter set during CMS signing and verification
 */
/* BEGIN_CASE */
void SDV_CMS_HASH_SLH_SIGN_REJECT_TC001(char *certPath)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_SLH_DSA)
    (void)certPath;
    SKIP_TEST();
#else
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_CMS *cms = NULL;
    CMS_SignerInfo signerInfo = {0};
    BSL_Buffer msg = {(uint8_t *)"HashSLH", 7};
    CRYPT_PKEY_ParaId hashProfiles[] = {
        CRYPT_HASH_SLH_DSA_SHA2_128S_WITH_SHA256, CRYPT_HASH_SLH_DSA_SHA2_128F_WITH_SHA256,
        CRYPT_HASH_SLH_DSA_SHA2_192S_WITH_SHA512, CRYPT_HASH_SLH_DSA_SHA2_192F_WITH_SHA512,
        CRYPT_HASH_SLH_DSA_SHA2_256S_WITH_SHA512, CRYPT_HASH_SLH_DSA_SHA2_256F_WITH_SHA512,
        CRYPT_HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128, CRYPT_HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128,
        CRYPT_HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256, CRYPT_HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256,
        CRYPT_HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256, CRYPT_HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256
    };
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &cert), HITLS_PKI_SUCCESS);
    STUB_REPLACE(HITLS_X509_CheckKey, STUB_HITLS_X509_CheckKey);
    signerInfo.digestAlg.id = BSL_CID_SHA256;
    for (uint32_t i = 0; i < sizeof(hashProfiles) / sizeof(hashProfiles[0]); i++) {
        signerInfo.sigAlg.algId = (BslCid)hashProfiles[i];
        ASSERT_EQ(HITLS_CMS_CheckPqcSignAlgAndDigest(&signerInfo, false), HITLS_CMS_ERR_INVALID_ALGO);
        TestErrClear();

        pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SLH_DSA);
        ASSERT_NE(pkey, NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, hashProfiles[i]), CRYPT_SUCCESS);
        cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
        ASSERT_NE(cms, NULL);
        ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey, cert, &msg, NULL), HITLS_CMS_ERR_INVALID_ALGO);
        HITLS_CMS_Free(cms);
        cms = NULL;
        CRYPT_EAL_PkeyFreeCtx(pkey);
        pkey = NULL;
    }
EXIT:
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CMS_HSS_POLICY_TC001(void)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_CRYPTO_HSS_LMS)
    SKIP_TEST();
#else
    CMS_SignerInfo signerInfo = {0};

    signerInfo.sigAlg.algId = BSL_CID_HSS_LMS;
    signerInfo.digestAlg.id = BSL_CID_SHA256;
    ASSERT_EQ(HITLS_CMS_CheckPqcSignAlgAndDigest(&signerInfo, false), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_CheckPqcSignAlgAndDigest(&signerInfo, true), HITLS_CMS_ERR_NOT_SUPPORT_STREAM_PQC);
    TestErrClear();

    signerInfo.digestAlg.id = BSL_CID_SHA512;
    ASSERT_EQ(HITLS_CMS_CheckPqcSignAlgAndDigest(&signerInfo, false), HITLS_CMS_ERR_INVALID_ALGO);
    TestErrClear();
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_SIGN_VERIFY_STUB_TC001
 * @title  Sign and verify with streaming API
 * @brief
 *    1. for test stub malloc in HITLS_CMS_DataSign and HITLS_CMS_DataVerify.
 * @expect
 *    1. No memory leaks.
 */
/* BEGIN_CASE */
void SDV_CMS_SIGN_VERIFY_STUB_TC001(char *basePath, char *msg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_PKI_X509_CRL)
    (void)basePath;
    (void)msg;
    SKIP_TEST();
#else
    TestRandInit();
    HITLS_CMS *cms = NULL;
    HITLS_CMS *cms1 = NULL;
    HITLS_CMS *warmCms = NULL;
    BSL_Buffer encode1 = {0};
    BSL_Buffer encode2 = {0};
    TestCertChainCtx certCtx = {0};
    // Load certificate chain, CRLs and private keys
    ASSERT_EQ(LoadCertChainAndKeys(basePath, &certCtx), HITLS_PKI_SUCCESS);
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId = BSL_CID_SHA256;
    HITLS_X509_List *cachain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(cachain, NULL);
    HITLS_X509_List *midchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(midchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(cachain, certCtx.rootCert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(midchain, certCtx.caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(midchain, certCtx.device1Cert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(midchain, certCtx.device2Cert, BSL_LIST_POS_END), BSL_SUCCESS);

    HITLS_X509_List *crlList = BSL_LIST_New(sizeof(HITLS_X509_Crl *));
    ASSERT_NE(crlList, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(crlList, certCtx.crl, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(crlList, certCtx.crlEmpty, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[6] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, cachain, 0, 0},
        {HITLS_CMS_PARAM_UNTRUSTED_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, midchain, 0, 0},
        {HITLS_CMS_PARAM_CRL_LISTS, BSL_PARAM_TYPE_CTX_PTR, crlList, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    BSL_Buffer msgBuf = {(uint8_t *)msg, strlen(msg)};
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);
    cms1 = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms1, NULL);
    warmCms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(warmCms, NULL);
    ASSERT_EQ(HITLS_CMS_DataSign(warmCms, certCtx.pkey1, certCtx.device1Cert, &msgBuf, params), HITLS_PKI_SUCCESS);
    HITLS_CMS_Free(warmCms);
    warmCms = NULL;
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_REPLACE(HITLS_X509_CheckKey, STUB_HITLS_X509_CheckKey);
    uint32_t totalMallocCount = 0;
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_CMS_DataSign(cms, certCtx.pkey1, certCtx.device1Cert, &msgBuf, params), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    ASSERT_TRUE(TestIsErrStackEmpty());
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_EnableMallocFail(true);
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ASSERT_NE(HITLS_CMS_DataSign(cms1, certCtx.pkey1, certCtx.device1Cert, &msgBuf, params), HITLS_PKI_SUCCESS);
        STUB_EnableMallocFail(false);
        HITLS_CMS_Free(cms1);
        cms1 = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
        ASSERT_NE(cms1, NULL);
    }

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();

    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuf, params, NULL), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        // some malloc fail may not impact verify in device cert choice.
        (void)HITLS_CMS_DataVerify(cms, &msgBuf, params, NULL);
    }

EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    BSL_SAL_FREE(encode1.data);
    BSL_SAL_FREE(encode2.data);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(cms1);
    HITLS_CMS_Free(warmCms);
    CRYPT_EAL_PkeyFreeCtx(certCtx.pkey1);
    CRYPT_EAL_PkeyFreeCtx(certCtx.pkey2);
    BSL_LIST_FREE(cachain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(midchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(crlList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
    TestRandDeInit();
#endif
}
/* END_CASE */

static int32_t STUB_BSL_SAL_SysTimeGet(BSL_TIME *sysTime)
{
    if (sysTime == NULL) {
        return -1;
    }
    memset(sysTime, 1, sizeof(BSL_TIME));
    sysTime->year = 2055;  // >= 2050
    return BSL_SUCCESS;
}

/*
 * @test   SDV_CMS_SIGNINGTIME_GENERALIZEDTIME_TC001
 * @title  CreateSigningTimeAttr encodes GeneralizedTime when year >= 2050
 * @brief
 *    1. Stub BSL_SAL_SysTimeGet to return a BSL_TIME with year = 2055
 *    2. Run HITLS_CMS_DataSign to build signedAttrs including signing-time
 *    3. Locate signing-time attribute and check time tag is GeneralizedTime (0x18)
 * @expect
 *    1. DataSign succeeds
 *    2. Signing-time attribute exists
 *    3. attr->attrValue.buff[0] == 0x18 (GeneralizedTime)
 */
/* BEGIN_CASE */
void SDV_CMS_SIGNINGTIME_GENERALIZEDTIME_TC001(char *certPath, char *keyPath, char *msg)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_BSL_SAL_FILE)
    (void)certPath;
    (void)keyPath;
    (void)msg;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    // Prepare cert/key
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &cert), HITLS_PKI_SUCCESS);
    ASSERT_NE(cert, NULL);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_ECC, keyPath, NULL, 0, &pkey), CRYPT_SUCCESS);
    // Create CMS ctx
    HITLS_CMS *cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    ASSERT_EQ(BSL_SAL_ReadFile(msg, &data, &dataLen), HITLS_PKI_SUCCESS);
    BSL_Buffer msgBuf = {data, dataLen};

    STUB_REPLACE(BSL_SAL_SysTimeGet, STUB_BSL_SAL_SysTimeGet);
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId = BSL_CID_SHA256;
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[4] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };

    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey, cert, &msgBuf, params), HITLS_PKI_SUCCESS);
    CMS_SignedData *signedData = cms->ctx.signedData;
    ASSERT_NE(signedData, NULL);
    CMS_SignerInfo *si = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(signedData->signerInfos);
    ASSERT_NE(si, NULL);
    bool found = false;
    for (HITLS_X509_AttrEntry *attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_FIRST(si->signedAttrs->list);
         attr != NULL; attr = (HITLS_X509_AttrEntry *)BSL_LIST_GET_NEXT(si->signedAttrs->list)) {
        if (attr->cid == BSL_CID_PKCS9_AT_SIGNINGTIME) {
            ASSERT_NE(attr->attrValue.buff, NULL);
            ASSERT_TRUE(attr->attrValue.len > 0);
            ASSERT_EQ(attr->attrValue.buff[0], BSL_ASN1_TAG_GENERALIZEDTIME);
            found = true;
            break;
        }
    }
    ASSERT_TRUE(found);

EXIT:
    STUB_RESTORE(BSL_SAL_SysTimeGet);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_SAL_FREE(data);
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_MLDSA_INVALID_HASH_VERIFY_TC001
 * @title Test ML-DSA CMS verification with invalid hash algorithm
 * @precon nan
 * @brief
 *    1. Parse CMS file that uses ML-DSA with non-compliant hash algorithm (e.g., SHA-256 for MLDSA65/87)
 *    2. Load CA certificate
 *    3. Call HITLS_CMS_DataVerify
 * @expect
 *    1. Parsing should succeed
 *    2. Verification should fail with HITLS_CMS_ERR_MLDSA_INVALID_DIGEST error
 */
/* BEGIN_CASE */
void SDV_CMS_MLDSA_INVALID_HASH_VERIFY_TC001(char *p7path, char *msgpath, char *caPath)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    (void)p7path;
    (void)msgpath;
    (void)caPath;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    BSL_Buffer msgBuff = {NULL, 0};
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_List *caCertList = NULL;

    // Parse CMS file with invalid hash algorithm
    ASSERT_EQ(HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, p7path, &cms), HITLS_PKI_SUCCESS);

    // Read message file
    ASSERT_EQ(BSL_SAL_ReadFile(msgpath, &msgBuff.data, &msgBuff.dataLen), BSL_SUCCESS);

    // Parse CA certificate
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, caPath, &caCert), HITLS_PKI_SUCCESS);
    ASSERT_NE(caCert, NULL);

    // Create CA certificate list
    caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertList, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(caCertList, caCert, BSL_LIST_POS_END), BSL_SUCCESS);

    // Set up parameters with CA certificate list
    BSL_Param params[2] = {
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, 0, 0},
        BSL_PARAM_END
    };

    // Verify should fail with MLDSA_INVALID_DIGEST error
    // The CMS uses SHA-256 which does not meet RFC 9882 requirements for MLDSA65/87
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuff, params, NULL), HITLS_CMS_ERR_MLDSA_INVALID_DIGEST);

EXIT:
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_SAL_FREE(msgBuff.data);
    HITLS_CMS_Free(cms);
    return;
#endif
}
/* END_CASE */

/**
 * @test SDV_CMS_MLDSA_SIGNALG_MISMATCH_VERIFY_TC001
 * @title Test ML-DSA CMS verification with mismatched signatureAlgorithm
 * @precon nan
 * @brief
 *    1. Parse a valid ML-DSA CMS file
 *    2. Tamper SignerInfo.signatureAlgorithm to a non-PQC OID
 *    3. Call HITLS_CMS_DataVerify
 * @expect
 *    1. Parsing should succeed
 *    2. Verification should fail with HITLS_X509_ERR_VFY_SIGNALG_NOT_MATCH
 */
/* BEGIN_CASE */
void SDV_CMS_MLDSA_SIGNALG_MISMATCH_VERIFY_TC001(char *p7path, char *msgpath, char *caPath)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA)
    (void)p7path;
    (void)msgpath;
    (void)caPath;
    SKIP_TEST();
#else
    HITLS_CMS *cms = NULL;
    BSL_Buffer msgBuff = {NULL, 0};
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_List *caCertList = NULL;

    ASSERT_EQ(HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, p7path, &cms), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile(msgpath, &msgBuff.data, &msgBuff.dataLen), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, caPath, &caCert), HITLS_PKI_SUCCESS);
    ASSERT_NE(caCert, NULL);

    caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertList, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(caCertList, caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params[2] = {
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, 0, 0},
        BSL_PARAM_END
    };

    CMS_SignedData *signedData = cms->ctx.signedData;
    ASSERT_NE(signedData, NULL);
    CMS_SignerInfo *si = (CMS_SignerInfo *)BSL_LIST_GET_FIRST(signedData->signerInfos);
    ASSERT_NE(si, NULL);
    // tamper the algId of signerInfo
    si->sigAlg.algId = BSL_CID_ECDSAWITHSHA256;

    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuff, params, NULL), HITLS_X509_ERR_VFY_SIGNALG_NOT_MATCH);
    si->sigAlg.algId = BSL_CID_ML_DSA_44;
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuff, params, NULL), HITLS_X509_ERR_VFY_SIGNALG_NOT_MATCH);
EXIT:
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_SAL_FREE(msgBuff.data);
    HITLS_CMS_Free(cms);
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_GEN_SIGNEDDATA_INVALID_HASH_TC001
 * @title  Test PQC CMS digest algorithm policy
 * @brief
 *    1. Load a PQC certificate and key
 *    2. Sign with the selected digest algorithm and signedAttrs policy
 *    3. Verify successfully generated SignedData
 * @expect
 *    1-3. Suitable digests succeed; unsuitable digests are rejected
 */
/* BEGIN_CASE */
void SDV_CMS_GEN_SIGNEDDATA_INVALID_HASH_TC001(char *capath, char *certPath, char *keyPath, char *msg, int isDetached,
    int hasSignedAttr, int mdId, int ecpRes)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_BSL_SAL_FILE)
    (void)capath;
    (void)certPath;
    (void)keyPath;
    (void)msg;
    (void)isDetached;
    (void)hasSignedAttr;
    (void)mdId;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey1 = NULL;
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_Cert *cert1 = NULL;
    HITLS_CMS *cms = NULL;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;

    // Read message data
    ASSERT_EQ(BSL_SAL_ReadFile(msg, &data, &dataLen), HITLS_PKI_SUCCESS);

    // Load first certificate and key
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &cert1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, capath, &caCert), HITLS_PKI_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keyPath, NULL, 0, &pkey1),
        CRYPT_SUCCESS);

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    // Add SignerInfo and sign
    BSL_Buffer msgBuf = {data, dataLen};
    int32_t version1 = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId1 = (int32_t)mdId;
    bool isDetached1 = (bool)isDetached;
    bool hasNoSignedAttr1 = !(bool)hasSignedAttr;
    HITLS_X509_List *caCertchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(caCertchain, caCert, BSL_LIST_POS_END), BSL_SUCCESS);

    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert1, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params1[7] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version1, sizeof(version1), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId1, sizeof(mdId1), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &isDetached1, sizeof(isDetached1), 0},
        {HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL, &hasNoSignedAttr1, sizeof(hasNoSignedAttr1), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey1, cert1, &msgBuf, params1), ecpRes);
    if (ecpRes == HITLS_PKI_SUCCESS) {
        ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuf, params1, NULL), HITLS_PKI_SUCCESS);
    }
EXIT:
    BSL_SAL_FREE(data);
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_STREAM_SIGN_DETACHED_TC001
 * @title  Test streaming signature/verification for detached CMS SignedData
 * @brief
 *    1. Initialize streaming signature, update with message chunks, finalize
 *    2. Generate and parse detached SignedData, with 2 signerinfos
 *    3. Verify with one-shot API and streaming API (Init/Update/Final)
 * @expect
 *    1-3. streaming signature and verification operations successful
 */
/* BEGIN_CASE */
void SDV_CMS_STREAM_SIGN_INVALID_HASH_TC001(char *capath, char *certPath, char *keyPath, char *msg, int isDetached,
    int hasSignedAttr, int mdId, int ecpRes)
{
#ifndef HITLS_PKI_CMS_SIGNEDDATA
    (void)capath;
    (void)certPath;
    (void)keyPath;
    (void)msg;
    (void)isDetached;
    (void)mdId;
    SKIP_TEST();
#else
    TestRandInit();
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_Cert *cert1 = NULL;
    CRYPT_EAL_PkeyCtx *pkey1 = NULL;

    // Load certificate
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath, &cert1), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cert1 != NULL);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, capath, &caCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keyPath, NULL, 0, &pkey1),
        CRYPT_SUCCESS);
    ASSERT_TRUE(pkey1 != NULL);

    // Create CMS SignedData (detached by default)
    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_TRUE(cms != NULL);
    int32_t mdId1 = (int32_t)mdId;
    HITLS_X509_List *caCertchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(caCertchain, caCert, BSL_LIST_POS_END), BSL_SUCCESS);

    // Set message digest algorithm
    BSL_Param signParams[2] = {
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId1, sizeof(mdId1), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_Ctrl(cms, HITLS_CMS_SET_MSG_MD, &mdId1, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataInit(HITLS_CMS_OPT_SIGN, cms, signParams), HITLS_PKI_SUCCESS);
    // Update with message in chunks
    size_t msgLen = strlen(msg);
    size_t chunkSize = msgLen / 3;  // Split into 3 chunks

    // First chunk
    BSL_Buffer msgBuf = {(uint8_t *)msg, chunkSize};
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf), HITLS_PKI_SUCCESS);
    // Second chunk
    BSL_Buffer msgBuf1 = {(uint8_t *)msg + chunkSize, chunkSize};
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf1), HITLS_PKI_SUCCESS);
    // Third chunk
    BSL_Buffer msgBuf2 = {(uint8_t *)msg + 2 * chunkSize, msgLen - 2 * chunkSize};
    ASSERT_EQ(HITLS_CMS_DataUpdate(cms, &msgBuf2), HITLS_PKI_SUCCESS);

    // Finalize signature
    int32_t version = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3;
    bool isDetached1 = (bool)isDetached;
    bool hasNoSignedAttr1 = !(bool)hasSignedAttr;
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert1, BSL_LIST_POS_END), BSL_SUCCESS);
    BSL_Param params1[8] = {
        {HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR, pkey1, sizeof(CRYPT_EAL_PkeyCtx *), 0},
        {HITLS_CMS_PARAM_DEVICE_CERT, BSL_PARAM_TYPE_CTX_PTR, cert1, sizeof(HITLS_X509_Cert *), 0},
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version, sizeof(version), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId1, sizeof(mdId1), 0},
        {HITLS_CMS_PARAM_DETACHED, BSL_PARAM_TYPE_BOOL, &isDetached1, sizeof(isDetached1), 0},
        {HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL, &hasNoSignedAttr1, sizeof(hasNoSignedAttr1), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataFinal(cms, params1), ecpRes);
EXIT:
    HITLS_CMS_Free(cms);
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
#endif
}
/* END_CASE */

/**
 * @test   SDV_CMS_GEN_DETACHED_SIGNEDDATA_MULTI_SIGNER_TC001
 * @title  Generate detached CMS SignedData with multiple signers
 * @brief
 *    1. Load two different RSA certificates and keys
 *    2. Create two SignerInfo structures and add both to CMS
 *    3. Generate detached SignedData buffer
 *    4. Parse and verify with one-shot and streaming APIs
 * @expect
 *    1-4. All operations successful, multi-signer detached SignedData verified
 */
/* BEGIN_CASE */
void SDV_CMS_GEN_MULTI_SIGNER_WITH_DIFF_SIGNEDATTR_TC001(char *capath, char *capath2,  char *certPath1, char *keyPath1,
    char *certPath2, char *keyPath2, char *msg, int flag)
{
#if !defined(HITLS_PKI_CMS_SIGNEDDATA) || !defined(HITLS_BSL_SAL_FILE)
    (void)capath;
    (void)capath2;
    (void)certPath1;
    (void)keyPath1;
    (void)certPath2;
    (void)keyPath2;
    (void)msg;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey1 = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_Cert *caCert2 = NULL;
    HITLS_X509_Cert *cert1 = NULL;
    HITLS_X509_Cert *cert2 = NULL;
    HITLS_CMS *cms = NULL;
    HITLS_CMS *parsedCms = NULL;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;

    // Read message data
    ASSERT_EQ(BSL_SAL_ReadFile(msg, &data, &dataLen), HITLS_PKI_SUCCESS);

    // Load first certificate and key
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath1, &cert1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, capath, &caCert), HITLS_PKI_SUCCESS);
    if (strcmp(capath2, capath) != 0) {
        ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, capath2, &caCert2), HITLS_PKI_SUCCESS);
    }

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keyPath1, NULL, 0, &pkey1),
        CRYPT_SUCCESS);

    // Load second certificate and key
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, certPath2, &cert2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keyPath2, NULL, 0, &pkey2),
        CRYPT_SUCCESS);
    int32_t alg1 = CRYPT_EAL_PkeyGetId(pkey1);
    int32_t alg2 = CRYPT_EAL_PkeyGetId(pkey2);
    int32_t pkcsv15 = CRYPT_MD_SHA256;
    if (alg1 == BSL_CID_RSA) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey1, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    }
    if (alg2 == BSL_CID_RSA) {
        pkcsv15 = CRYPT_MD_SHA384;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey2, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    }

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    ASSERT_NE(cms, NULL);

    // Add SignerInfo and sign
    BSL_Buffer msgBuf = {data, dataLen};
    int32_t version1 = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V1;
    int32_t mdId1 = BSL_CID_SHA256;
    HITLS_X509_List *caCertchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(caCertchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(caCertchain, caCert, BSL_LIST_POS_END), BSL_SUCCESS);
    if (caCert2 != NULL) {
        ASSERT_EQ(BSL_LIST_AddElement(caCertchain, caCert2, BSL_LIST_POS_END), BSL_SUCCESS);
    }
    HITLS_X509_List *certchain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(certchain, NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert1, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(certchain, cert2, BSL_LIST_POS_END), BSL_SUCCESS);
    bool noSignedAttr = (bool)flag;
    BSL_Param params1[6] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version1, sizeof(version1), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId1, sizeof(mdId1), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL, &noSignedAttr, sizeof(noSignedAttr), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey1, cert1, &msgBuf, params1), HITLS_PKI_SUCCESS);
    int32_t version2 = HITLS_CMS_SIGNEDDATA_SIGNERINFO_V3;
    int32_t mdId2 = BSL_CID_SHA384;
    noSignedAttr = !(bool)flag;
    BSL_Param params2[6] = {
        {HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32, &version2, sizeof(version2), 0},
        {HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId2, sizeof(mdId2), 0},
        {HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, certchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertchain, sizeof(HITLS_X509_List *), 0},
        {HITLS_CMS_PARAM_NO_SIGNED_ATTRS, BSL_PARAM_TYPE_BOOL, &noSignedAttr, sizeof(noSignedAttr), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(HITLS_CMS_DataSign(cms, pkey2, cert2, &msgBuf, params2), HITLS_PKI_SUCCESS);

    BSL_Buffer cmsBuffer = {0};
    ASSERT_EQ(HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, &cmsBuffer), HITLS_PKI_SUCCESS);
    ASSERT_NE(cmsBuffer.data, NULL);

    ASSERT_EQ(HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, &cmsBuffer, &parsedCms), HITLS_PKI_SUCCESS);

    // Verify there are 2 signers
    CMS_SignedData *signedData = parsedCms->ctx.signedData;
    ASSERT_EQ(BSL_LIST_COUNT(signedData->signerInfos), 2);

    // Verify with external message
    ASSERT_EQ(HITLS_CMS_DataVerify(cms, &msgBuf, params1, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_CMS_DataVerify(parsedCms, &msgBuf, params1, NULL), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_FREE(data);
    BSL_SAL_FREE(cmsBuffer.data);
    HITLS_CMS_Free(cms);
    HITLS_CMS_Free(parsedCms);
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    BSL_LIST_FREE(certchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(caCertchain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    TestRandDeInit();
    return;
#endif
}
/* END_CASE */

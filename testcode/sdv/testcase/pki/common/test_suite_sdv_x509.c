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
#include <stdio.h>
#include <stdbool.h>
#include "sal_file.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_obj.h"
#include "bsl_types.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_codecskey.h"
#include "crypt_params_key.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_rand.h"
#include "crypt_util_rand.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_csr.h"
#include "bsl_init.h"
#include "bsl_pem_internal.h"
#include "hitls_pki_x509.h"
#include "hitls_cert_local.h"
#include "hitls_crl_local.h"
#include "hitls_csr_local.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_types.h"
#include "hitls_pki_utils.h"
#include "hitls_x509_verify.h"
#include "hitls_x509_local.h"
#include "stub_utils.h"
/* END_HEADER */

#if (defined(HITLS_CRYPTO_KEY_ENCODE) && defined(HITLS_CRYPTO_KEY_EPKI)) || \
    defined(HITLS_PKI_X509_CSR_GEN) || defined(HITLS_PKI_X509_CRT_GEN)
STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);
#endif

#define COMPOSITE_SAMPLE_PATH_MAX 512U

static inline void UnusedParam1(int param1, int param2, int param3)
{
    (void)param1;
    (void)param2;
    (void)param3;
}

static inline void UnusedParam2(int param1, int param2, void *param3)
{
    (void)param1;
    (void)param2;
    (void)param3;
}

static bool PkiSkipTest(int32_t algId, int32_t format)
{
#ifndef HITLS_BSL_PEM
    if (format == BSL_FORMAT_PEM) {
        return true;
    }
#else
    (void)format;
#endif
    switch (algId) {
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PKEY_RSA:
        case BSL_CID_RSASSAPSS:
            return false;
#endif
#ifdef HITLS_CRYPTO_ECDSA
        case CRYPT_PKEY_ECDSA:
            return false;
#endif
#ifdef HITLS_CRYPTO_SM2
        case CRYPT_PKEY_SM2:
            return false;
#endif
#ifdef HITLS_CRYPTO_ED25519
        case CRYPT_PKEY_ED25519:
            return false;
#endif
#ifdef HITLS_CRYPTO_X25519
        case CRYPT_PKEY_X25519:
            return false;
#endif
#ifdef HITLS_CRYPTO_XMSS
        case CRYPT_PKEY_XMSS:
            return false;
#endif
#ifdef HITLS_CRYPTO_MLDSA
        case CRYPT_PKEY_ML_DSA:
            return false;   // mldsa is not supported in this version
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
        case CRYPT_PKEY_SLH_DSA:
            return false;   // slhdsa is not supported in this version
#endif
#ifdef HITLS_CRYPTO_COMPOSITE
        case CRYPT_PKEY_COMPOSITE:
            return false;
#endif
        default:
            return true;
    }
}

static bool PkiSkipCompositeParaTest(int32_t paraId)
{
#ifndef HITLS_CRYPTO_COMPOSITE
    (void)paraId;
    return true;
#else
    switch (paraId) {
#if defined(HITLS_CRYPTO_RSA) && defined(HITLS_CRYPTO_RSA_GEN) && defined(HITLS_CRYPTO_RSA_SIGN) && \
    defined(HITLS_CRYPTO_RSA_VERIFY) && defined(HITLS_CRYPTO_RSA_EMSA_PSS)
        case CRYPT_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256:
        case CRYPT_COMPOSITE_MLDSA65_RSA3072_PSS_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_RSA4096_PSS_SHA512:
        case CRYPT_COMPOSITE_MLDSA87_RSA3072_PSS_SHA512:
        case CRYPT_COMPOSITE_MLDSA87_RSA4096_PSS_SHA512:
            return false;
#endif
#if defined(HITLS_CRYPTO_RSA) && defined(HITLS_CRYPTO_RSA_GEN) && defined(HITLS_CRYPTO_RSA_SIGN) && \
    defined(HITLS_CRYPTO_RSA_VERIFY) && defined(HITLS_CRYPTO_RSA_EMSA_PKCSV15)
        case CRYPT_COMPOSITE_MLDSA44_RSA2048_PKCS15_SHA256:
        case CRYPT_COMPOSITE_MLDSA65_RSA3072_PKCS15_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_RSA4096_PKCS15_SHA512:
            return false;
#endif
#if defined(HITLS_CRYPTO_ECDSA) && defined(HITLS_CRYPTO_CURVE_NISTP256)
        case CRYPT_COMPOSITE_MLDSA44_ECDSA_P256_SHA256:
        case CRYPT_COMPOSITE_MLDSA65_ECDSA_P256_SHA512:
            return false;
#endif
#if defined(HITLS_CRYPTO_ECDSA) && defined(HITLS_CRYPTO_CURVE_NISTP384)
        case CRYPT_COMPOSITE_MLDSA65_ECDSA_P384_SHA512:
        case CRYPT_COMPOSITE_MLDSA87_ECDSA_P384_SHA512:
            return false;
#endif
#if defined(HITLS_CRYPTO_ECDSA) && defined(HITLS_CRYPTO_CURVE_NISTP521)
        case CRYPT_COMPOSITE_MLDSA87_ECDSA_P521_SHA512:
            return false;
#endif
#if defined(HITLS_CRYPTO_ECDSA) && defined(HITLS_CRYPTO_CURVE_BP256R1)
        case CRYPT_COMPOSITE_MLDSA65_ECDSA_BRAINPOOLP256R1_SHA512:
            return false;
#endif
#if defined(HITLS_CRYPTO_ECDSA) && defined(HITLS_CRYPTO_CURVE_BP384R1)
        case CRYPT_COMPOSITE_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512:
            return false;
#endif
#if defined(HITLS_CRYPTO_ED25519)
        case CRYPT_COMPOSITE_MLDSA44_ED25519_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_ED25519_SHA512:
            return false;
#endif
        default:
            return true;
    }
#endif
}

static bool PkiSkipTestByParaId(int32_t algId, int32_t paraId, int32_t format)
{
    if (PkiSkipTest(algId, format)) {
        return true;
    }
    if (algId != CRYPT_PKEY_COMPOSITE) {
        return false;
    }
    return PkiSkipCompositeParaTest(paraId);
}

#if defined(HITLS_BSL_PEM) && defined(HITLS_BSL_SAL_FILE)
static int32_t CheckCompositeDecodedKey(CRYPT_EAL_PkeyCtx *key, int32_t expectParaId)
{
    ASSERT_EQ(CRYPT_EAL_PkeyGetId(key), CRYPT_PKEY_COMPOSITE);
    ASSERT_EQ(CRYPT_EAL_PkeyGetParaId(key), expectParaId);
    return CRYPT_SUCCESS;
EXIT:
    return -1;
}

static int32_t JoinCompositeSamplePath(char *path, uint32_t pathLen, const char *sampleDir, const char *fileName)
{
    int ret;
    ret = snprintf(path, pathLen, "%s/%s", sampleDir, fileName);
    if (ret < 0 || (uint32_t)ret >= pathLen) {
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_SUCCESS;
}

static int32_t ReadCompositeSampleFile(const char *sampleDir, const char *fileName,
    BSL_Buffer *data, char *path, uint32_t pathLen)
{
    int32_t ret = JoinCompositeSamplePath(path, pathLen, sampleDir, fileName);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return BSL_SAL_ReadFile(path, &data->data, &data->dataLen);
}

#if defined(HITLS_PKI_X509_CRT)
static int32_t CheckCompositeCertFields(HITLS_X509_Cert *cert, int32_t expectParaId, int32_t expectKeyUsage)
{
    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    int32_t signAlg = 0;
    int32_t keyUsage = 0;

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &pubKey, 0), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(pubKey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGetId(pubKey), CRYPT_PKEY_COMPOSITE);
    ASSERT_EQ(CRYPT_EAL_PkeyGetParaId(pubKey), expectParaId);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SIGNALG, &signAlg, sizeof(signAlg)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(signAlg, expectParaId);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_KUSAGE, &keyUsage, sizeof(keyUsage)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(keyUsage, expectKeyUsage);
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    return CRYPT_SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    return -1;
}
#endif

#if defined(HITLS_PKI_X509_CSR)
static int32_t CheckCompositeCsrFields(HITLS_X509_Csr *csr, int32_t expectParaId)
{
    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    int32_t signAlg = 0;

    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_GET_PUBKEY, &pubKey, 0), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(pubKey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGetId(pubKey), CRYPT_PKEY_COMPOSITE);
    ASSERT_EQ(CRYPT_EAL_PkeyGetParaId(pubKey), expectParaId);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_GET_SIGNALG, &signAlg, sizeof(signAlg)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(signAlg, expectParaId);
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    return CRYPT_SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    return -1;
}
#endif

#if defined(HITLS_PKI_X509_CRL)
static int32_t CheckCompositeCrlFields(HITLS_X509_Crl *crl, int32_t expectParaId)
{
    ASSERT_EQ(crl->signAlgId.algId, expectParaId);
    ASSERT_EQ(crl->tbs.signAlgId.algId, expectParaId);
    return CRYPT_SUCCESS;
EXIT:
    return -1;
}
#endif
#endif

#if defined(HITLS_PKI_X509_CRL_GEN)
int32_t HITLS_X509_EncodeCrlTbsRaw(HITLS_X509_CrlTbs *crlTbs, BSL_ASN1_Buffer *asn);
#endif

#if defined(HITLS_BSL_PEM) && defined(HITLS_PKI_X509_CRT_GEN)
#define COMPOSITE_TEST_CERT_CTX_SPECIFIC_TAG_VER 0
#define COMPOSITE_TEST_CERT_CTX_SPECIFIC_TAG_EXTENSION 3
#define COMPOSITE_TEST_CERT_TBS_SIZE 9
#define COMPOSITE_TEST_CERT_BRIEF_SIZE 3

static BSL_ASN1_TemplateItem g_compositeTestCertTbsTempl[] = {
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | COMPOSITE_TEST_CERT_CTX_SPECIFIC_TAG_VER,
     BSL_ASN1_FLAG_DEFAULT, 0},
        {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_DEFAULT, 1},
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_CHOICE, 0, 1},
        {BSL_ASN1_TAG_CHOICE, 0, 1},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | COMPOSITE_TEST_CERT_CTX_SPECIFIC_TAG_EXTENSION,
     BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 0},
};

static BSL_ASN1_TemplateItem g_compositeTestCertTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
        {BSL_ASN1_TAG_BITSTRING, 0, 1},
};

static int32_t EncodeParsedCompositeCertTbs(HITLS_X509_Cert *cert, BSL_ASN1_Buffer *encode)
{
    BSL_ASN1_Buffer signAlg = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL};
    BSL_ASN1_Buffer issuer = {0};
    BSL_ASN1_Buffer subject = {0};
    BSL_ASN1_Buffer pubkey = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL};
    BSL_ASN1_Buffer ext = {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED |
        COMPOSITE_TEST_CERT_CTX_SPECIFIC_TAG_EXTENSION, 0, NULL};
    BSL_Buffer pub = {0};
    uint8_t version = (uint8_t)cert->tbs.version;
    int32_t ret = HITLS_X509_EncodeSignAlgInfo(&cert->tbs.signAlgId, &signAlg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_EncodeNameList(cert->tbs.issuerName, &issuer);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    ret = HITLS_X509_EncodeNameList(cert->tbs.subjectName, &subject);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    ret = CRYPT_EAL_EncodePubKeyBuffInternal(cert->tbs.ealPubKey, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, false, &pub);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    if (cert->tbs.version == HITLS_X509_VERSION_3) {
        ret = HITLS_X509_EncodeExt(BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED |
            COMPOSITE_TEST_CERT_CTX_SPECIFIC_TAG_EXTENSION, cert->tbs.ext.extList, &ext);
        if (ret != HITLS_PKI_SUCCESS) {
            goto EXIT;
        }
    }
    pubkey.buff = pub.data;
    pubkey.len = pub.dataLen;

    BSL_ASN1_Buffer asns[COMPOSITE_TEST_CERT_TBS_SIZE] = {
        {BSL_ASN1_TAG_INTEGER, version == HITLS_X509_VERSION_1 ? 0 : 1,
            version == HITLS_X509_VERSION_1 ? NULL : &version},
        cert->tbs.serialNum,
        signAlg,
        issuer,
        {(cert->tbs.validTime.flag & BSL_TIME_BEFORE_IS_UTC) != 0 ? BSL_ASN1_TAG_UTCTIME :
            BSL_ASN1_TAG_GENERALIZEDTIME, sizeof(BSL_TIME), (uint8_t *)&cert->tbs.validTime.start},
        {(cert->tbs.validTime.flag & BSL_TIME_AFTER_IS_UTC) != 0 ? BSL_ASN1_TAG_UTCTIME :
            BSL_ASN1_TAG_GENERALIZEDTIME, sizeof(BSL_TIME), (uint8_t *)&cert->tbs.validTime.end},
        subject,
        pubkey,
        ext,
    };
    BSL_ASN1_Template templ = {g_compositeTestCertTbsTempl,
        sizeof(g_compositeTestCertTbsTempl) / sizeof(g_compositeTestCertTbsTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asns, COMPOSITE_TEST_CERT_TBS_SIZE, &encode->buff, &encode->len);
    if (ret == HITLS_PKI_SUCCESS) {
        encode->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    }

EXIT:
    BSL_SAL_Free(signAlg.buff);
    BSL_SAL_Free(issuer.buff);
    BSL_SAL_Free(subject.buff);
    BSL_SAL_Free(pubkey.buff);
    if (version == HITLS_X509_VERSION_3) {
        BSL_SAL_Free(ext.buff);
    }
    return ret;
}

static int32_t EncodeParsedCompositeCertDer(HITLS_X509_Cert *cert, BSL_Buffer *encode)
{
    BSL_ASN1_Buffer tbs = {0};
    BSL_ASN1_Buffer asns[COMPOSITE_TEST_CERT_BRIEF_SIZE] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL},
        {BSL_ASN1_TAG_BITSTRING, sizeof(BSL_ASN1_BitString), (uint8_t *)&cert->signature},
    };
    int32_t ret = EncodeParsedCompositeCertTbs(cert, &tbs);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    asns[0] = tbs;
    ret = HITLS_X509_EncodeSignAlgInfo(&cert->signAlgId, &asns[1]);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    BSL_ASN1_Template templ = {g_compositeTestCertTempl,
        sizeof(g_compositeTestCertTempl) / sizeof(g_compositeTestCertTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asns, COMPOSITE_TEST_CERT_BRIEF_SIZE, &encode->data, &encode->dataLen);

EXIT:
    BSL_SAL_Free(asns[1].buff);
    BSL_SAL_Free(tbs.buff);
    return ret;
}

static int32_t EncodeParsedCompositeCertPem(HITLS_X509_Cert *cert, BSL_Buffer *encode)
{
    BSL_Buffer der = {0};
    BSL_PEM_Symbol symbol = {BSL_PEM_CERT_BEGIN_STR, BSL_PEM_CERT_END_STR};
    int32_t ret = EncodeParsedCompositeCertDer(cert, &der);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_PEM_EncodeAsn1ToPem(der.data, der.dataLen, &symbol, (char **)&encode->data, &encode->dataLen);
    BSL_SAL_Free(der.data);
    return ret;
}

static int32_t CheckParsedCompositeCertRoundTrip(HITLS_X509_Cert *cert, BSL_Buffer *originPem,
    BSL_Buffer *roundTripPem)
{
    BSL_Buffer der = {0};

    ASSERT_EQ(EncodeParsedCompositeCertDer(cert, &der), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("cert der structural reencode", der.data, der.dataLen, cert->rawData, cert->rawDataLen);
    ASSERT_EQ(EncodeParsedCompositeCertPem(cert, roundTripPem), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("cert pem roundtrip", roundTripPem->data, roundTripPem->dataLen,
        originPem->data, originPem->dataLen);
    BSL_SAL_Free(der.data);
    return CRYPT_SUCCESS;
EXIT:
    BSL_SAL_Free(der.data);
    return -1;
}
#endif

#if defined(HITLS_BSL_PEM) && defined(HITLS_PKI_X509_CSR_GEN)
#define COMPOSITE_TEST_CSR_CTX_SPECIFIC_TAG_ATTRIBUTE 0
#define COMPOSITE_TEST_CSR_REQINFO_SIZE 4
#define COMPOSITE_TEST_CSR_BRIEF_SIZE 3

static BSL_ASN1_TemplateItem g_compositeTestCsrReqInfoTempl[] = {
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 0},
    {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | COMPOSITE_TEST_CSR_CTX_SPECIFIC_TAG_ATTRIBUTE,
        BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 0},
};

static BSL_ASN1_TemplateItem g_compositeTestCsrTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
        {BSL_ASN1_TAG_BITSTRING, 0, 1},
};

static int32_t EncodeParsedCompositeCsrReqInfo(HITLS_X509_Csr *csr, BSL_ASN1_Buffer *encode)
{
    BSL_ASN1_Buffer subject = {0};
    BSL_ASN1_Buffer publicKey = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL};
    BSL_ASN1_Buffer attributes = {0};
    BSL_Buffer pub = {0};
    uint8_t version = (uint8_t)csr->reqInfo.version;
    int32_t ret = HITLS_X509_EncodeNameList(csr->reqInfo.subjectName, &subject);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_EncodePubKeyBuffInternal(csr->reqInfo.ealPubKey, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, false,
        &pub);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
#ifdef HITLS_PKI_X509_CSR_ATTR
    ret = HITLS_X509_EncodeAttrList(BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED |
        COMPOSITE_TEST_CSR_CTX_SPECIFIC_TAG_ATTRIBUTE, csr->reqInfo.attributes, NULL, &attributes);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
#else
    attributes.tag = BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED |
        COMPOSITE_TEST_CSR_CTX_SPECIFIC_TAG_ATTRIBUTE;
#endif
    publicKey.buff = pub.data;
    publicKey.len = pub.dataLen;

    BSL_ASN1_Buffer asns[COMPOSITE_TEST_CSR_REQINFO_SIZE] = {
        {BSL_ASN1_TAG_INTEGER, 1, &version},
        subject,
        publicKey,
        attributes,
    };
    BSL_ASN1_Template templ = {g_compositeTestCsrReqInfoTempl,
        sizeof(g_compositeTestCsrReqInfoTempl) / sizeof(g_compositeTestCsrReqInfoTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asns, COMPOSITE_TEST_CSR_REQINFO_SIZE, &encode->buff, &encode->len);
    if (ret == HITLS_PKI_SUCCESS) {
        encode->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    }

EXIT:
    BSL_SAL_Free(subject.buff);
    BSL_SAL_Free(publicKey.buff);
    BSL_SAL_Free(attributes.buff);
    return ret;
}

static int32_t EncodeParsedCompositeCsrDer(HITLS_X509_Csr *csr, BSL_Buffer *encode)
{
    BSL_ASN1_Buffer reqInfo = {0};
    BSL_ASN1_Buffer asns[COMPOSITE_TEST_CSR_BRIEF_SIZE] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL},
        {BSL_ASN1_TAG_BITSTRING, sizeof(BSL_ASN1_BitString), (uint8_t *)&csr->signature},
    };
    int32_t ret = EncodeParsedCompositeCsrReqInfo(csr, &reqInfo);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    asns[0] = reqInfo;
    ret = HITLS_X509_EncodeSignAlgInfo(&csr->signAlgId, &asns[1]);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    BSL_ASN1_Template templ = {g_compositeTestCsrTempl,
        sizeof(g_compositeTestCsrTempl) / sizeof(g_compositeTestCsrTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asns, COMPOSITE_TEST_CSR_BRIEF_SIZE, &encode->data, &encode->dataLen);

EXIT:
    BSL_SAL_Free(asns[1].buff);
    BSL_SAL_Free(reqInfo.buff);
    return ret;
}

static int32_t EncodeParsedCompositeCsrPem(HITLS_X509_Csr *csr, BSL_Buffer *encode)
{
    BSL_Buffer der = {0};
    BSL_PEM_Symbol symbol = {BSL_PEM_CERT_REQ_BEGIN_STR, BSL_PEM_CERT_REQ_END_STR};
    int32_t ret = EncodeParsedCompositeCsrDer(csr, &der);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_PEM_EncodeAsn1ToPem(der.data, der.dataLen, &symbol, (char **)&encode->data, &encode->dataLen);
    BSL_SAL_Free(der.data);
    return ret;
}

static int32_t CheckParsedCompositeCsrRoundTrip(HITLS_X509_Csr *csr, BSL_Buffer *originPem, BSL_Buffer *roundTripPem)
{
    BSL_Buffer der = {0};

    ASSERT_EQ(EncodeParsedCompositeCsrDer(csr, &der), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("csr der structural reencode", der.data, der.dataLen, csr->rawData, csr->rawDataLen);
    ASSERT_EQ(EncodeParsedCompositeCsrPem(csr, roundTripPem), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("csr pem roundtrip", roundTripPem->data, roundTripPem->dataLen, originPem->data, originPem->dataLen);
    BSL_SAL_Free(der.data);
    return CRYPT_SUCCESS;
EXIT:
    BSL_SAL_Free(der.data);
    return -1;
}
#endif

#if defined(HITLS_BSL_PEM) && defined(HITLS_PKI_X509_CRL_GEN)
#define COMPOSITE_TEST_CRL_BRIEF_SIZE 3

static BSL_ASN1_TemplateItem g_compositeTestCrlTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_FLAG_HEADERONLY, 1},
        {BSL_ASN1_TAG_BITSTRING, 0, 1},
};

static int32_t EncodeParsedCompositeCrlDer(HITLS_X509_Crl *crl, BSL_Buffer *encode)
{
    BSL_ASN1_Buffer tbsValue = {0};
    BSL_ASN1_Buffer asns[COMPOSITE_TEST_CRL_BRIEF_SIZE] = {
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, NULL},
        {BSL_ASN1_TAG_BITSTRING, sizeof(BSL_ASN1_BitString), (uint8_t *)&crl->signature},
    };
    int32_t ret = HITLS_X509_EncodeCrlTbsRaw(&crl->tbs, &tbsValue);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    asns[0] = tbsValue;
    ret = HITLS_X509_EncodeSignAlgInfo(&crl->signAlgId, &asns[1]);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    BSL_ASN1_Template templ = {g_compositeTestCrlTempl,
        sizeof(g_compositeTestCrlTempl) / sizeof(g_compositeTestCrlTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asns, COMPOSITE_TEST_CRL_BRIEF_SIZE, &encode->data, &encode->dataLen);

EXIT:
    BSL_SAL_Free(asns[1].buff);
    BSL_SAL_Free(tbsValue.buff);
    return ret;
}

static int32_t EncodeParsedCompositeCrlPem(HITLS_X509_Crl *crl, BSL_Buffer *encode)
{
    BSL_Buffer der = {0};
    BSL_PEM_Symbol symbol = {BSL_PEM_CRL_BEGIN_STR, BSL_PEM_CRL_END_STR};
    int32_t ret = EncodeParsedCompositeCrlDer(crl, &der);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_PEM_EncodeAsn1ToPem(der.data, der.dataLen, &symbol, (char **)&encode->data, &encode->dataLen);
    BSL_SAL_Free(der.data);
    return ret;
}

static int32_t CheckParsedCompositeCrlRoundTrip(HITLS_X509_Crl *crl, BSL_Buffer *originPem, BSL_Buffer *roundTripPem)
{
    BSL_Buffer der = {0};

    ASSERT_EQ(EncodeParsedCompositeCrlDer(crl, &der), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("crl der structural reencode", der.data, der.dataLen, crl->rawData, crl->rawDataLen);
    ASSERT_EQ(EncodeParsedCompositeCrlPem(crl, roundTripPem), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("crl pem roundtrip", roundTripPem->data, roundTripPem->dataLen, originPem->data, originPem->dataLen);
    BSL_SAL_Free(der.data);
    return CRYPT_SUCCESS;
EXIT:
    BSL_SAL_Free(der.data);
    return -1;
}
#endif

#ifdef HITLS_CRYPTO_KEY_ENCODE

#ifdef HITLS_CRYPTO_RSA
static int32_t SetRsaPara(CRYPT_EAL_PkeyCtx *pkey)
{
    uint8_t e[] = {1, 0, 1};  // RSA public exponent
    CRYPT_EAL_PkeyPara para = {0};
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.e = e;
    para.para.rsaPara.eLen = 3; // public exponent length = 3
    para.para.rsaPara.bits = 1024; // 1024 is enough for test, and be quickly generated.
    return CRYPT_EAL_PkeySetPara(pkey, &para);
}

static int32_t SetRsaPssPara(CRYPT_EAL_PkeyCtx *pkey)
{
    CRYPT_MD_AlgId mdId = CRYPT_MD_SHA256;
    int32_t saltLen = 20; // 20 bytes salt
    BSL_Param pssParam[4] = {
    {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
    {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
    {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
    BSL_PARAM_END};
    return CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0);
}
#endif // HITLS_CRYPT_RSA

// if alg is ecc, algParam specifies curveId; if pqc, algParam specifies paramSet
static CRYPT_EAL_PkeyCtx *GenKey(int32_t algId, int32_t algParam)
{
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(algId == BSL_CID_RSASSAPSS ? BSL_CID_RSA : algId);
    ASSERT_NE(pkey, NULL);

    if (algId == CRYPT_PKEY_ECDSA) {
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algParam), CRYPT_SUCCESS);
    }

#ifdef HITLS_CRYPTO_RSA
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(SetRsaPara(pkey), CRYPT_SUCCESS);
    }
    if (algId == BSL_CID_RSASSAPSS) {
        ASSERT_EQ(SetRsaPara(pkey), CRYPT_SUCCESS);
        ASSERT_EQ(SetRsaPssPara(pkey), CRYPT_SUCCESS);
    }
#endif
#ifdef HITLS_CRYPTO_MLDSA
    if (algId == CRYPT_PKEY_ML_DSA) {
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algParam), CRYPT_SUCCESS);
    }
#endif
#ifdef HITLS_CRYPTO_XMSS
    if (algId == CRYPT_PKEY_XMSS) {
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algParam), CRYPT_SUCCESS);
    }
#endif
#ifdef HITLS_CRYPTO_SLH_DSA
    if (algId == CRYPT_PKEY_SLH_DSA) {
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algParam), CRYPT_SUCCESS);
    }
#endif
#ifdef HITLS_CRYPTO_COMPOSITE
    if (algId == CRYPT_PKEY_COMPOSITE) {
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algParam), CRYPT_SUCCESS);
    }
#endif
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    return pkey;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return NULL;
}

/**
 * Generate DER/PEM public/private key: rsa, ecc, sm2, ed25519, mldsa
 * if ecc alg, algParam specifies curveId; if pqc, algParam specifies paramSet
 */
static int32_t TestEncodeKey(int32_t algId, int32_t type, int32_t algParam, char *path)
{
    BSL_Buffer encode = {0};
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;

    CRYPT_EAL_PkeyCtx *pkey = GenKey(algId, algParam);
    ASSERT_NE(pkey, NULL);

#ifdef HITLS_BSL_SAL_FILE
    if (path != NULL) {
        ASSERT_EQ(CRYPT_EAL_EncodeFileKey(pkey, NULL, BSL_FORMAT_ASN1, type, path), CRYPT_SUCCESS);
    }
#ifdef HITLS_BSL_PEM
    if (path != NULL) {
        ASSERT_EQ(CRYPT_EAL_EncodeFileKey(pkey, NULL, BSL_FORMAT_PEM, type, path), CRYPT_SUCCESS);
    }
#endif
#else
    (void)path;
#endif
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_ASN1, type, &encode), CRYPT_SUCCESS);
    BSL_SAL_FREE(encode.data);
#ifdef HITLS_BSL_PEM
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_PEM, type, &encode), CRYPT_SUCCESS);
    BSL_SAL_FREE(encode.data);
#endif

    ret = CRYPT_SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}
#endif // HITLS_CRYPTO_KEY_ENCODE

#if defined(HITLS_PKI_X509_CRL_GEN) || defined(HITLS_PKI_X509_CSR_GEN) || defined(HITLS_PKI_X509_CRT_GEN)
static char g_sm2DefaultUserid[] = "1234567812345678";

static void SetSignParam(int32_t algId, int32_t mdId, HITLS_X509_SignAlgParam *algParam, CRYPT_RSA_PssPara *pssParam)
{
    if (algId == BSL_CID_RSASSAPSS) {
        algParam->algId = BSL_CID_RSASSAPSS;
        pssParam->mdId = mdId;
        pssParam->mgfId = mdId;
        pssParam->saltLen = 20; // 20 bytes salt
        algParam->rsaPss = *pssParam;
    }
    if (algId == BSL_CID_SM2DSA) {
        algParam->algId = BSL_CID_SM2DSAWITHSM3;
        algParam->sm2UserId.data = (uint8_t *)g_sm2DefaultUserid;
        algParam->sm2UserId.dataLen = (uint32_t)strlen(g_sm2DefaultUserid);
    }
}
#endif

#if defined(HITLS_PKI_X509_CRL_GEN) || defined(HITLS_PKI_X509_CRT_GEN)
static BslList* GenDNList(void)
{
    HITLS_X509_DN dnName1[1] = {{BSL_CID_AT_COMMONNAME, (uint8_t *)"OH", 2}};
    HITLS_X509_DN dnName2[1] = {{BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2}};

    BslList *dirNames = HITLS_X509_DnListNew();
    ASSERT_NE(dirNames, NULL);

    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName1, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName2, 1), HITLS_PKI_SUCCESS);
    return dirNames;

EXIT:
    HITLS_X509_DnListFree(dirNames);
    return NULL;
}

static BslList* GenGeneralNameList(void)
{
    char *str = "test";
    HITLS_X509_GeneralName *email = NULL;
    HITLS_X509_GeneralName *dns = NULL;
    HITLS_X509_GeneralName *dname = NULL;
    HITLS_X509_GeneralName *uri = NULL;
    HITLS_X509_GeneralName *ip = NULL;

    BslList *names = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
    ASSERT_NE(names, NULL);

    email = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    dns = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    dname = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    uri = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    ip = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    ASSERT_TRUE(email != NULL && dns != NULL && dname != NULL && uri != NULL && ip != NULL);

    email->type = HITLS_X509_GN_EMAIL;
    dns->type = HITLS_X509_GN_DNS;
    uri->type = HITLS_X509_GN_URI;
    dname->type = HITLS_X509_GN_DNNAME;
    ip->type = HITLS_X509_GN_IP;
    email->value.dataLen = strlen(str);
    dns->value.dataLen = strlen(str);
    uri->value.dataLen = strlen(str);
    dname->value.dataLen = sizeof(BslList *);
    ip->value.dataLen = strlen(str);
    email->value.data = BSL_SAL_Dump(str, strlen(str));
    dns->value.data = BSL_SAL_Dump(str, strlen(str));
    uri->value.data = BSL_SAL_Dump(str, strlen(str));
    dname->value.data = (uint8_t *)GenDNList();
    ip->value.data = BSL_SAL_Dump(str, strlen(str));
    ASSERT_TRUE(email->value.data != NULL && dns->value.data != NULL && uri->value.data != NULL && dname->value.data != NULL && ip->value.data != NULL);

    ASSERT_EQ(BSL_LIST_AddElement(names, email, BSL_LIST_POS_END), 0);
    ASSERT_EQ(BSL_LIST_AddElement(names, dns, BSL_LIST_POS_END), 0);
    ASSERT_EQ(BSL_LIST_AddElement(names, uri, BSL_LIST_POS_END), 0);
    ASSERT_EQ(BSL_LIST_AddElement(names, dname, BSL_LIST_POS_END), 0);
    ASSERT_EQ(BSL_LIST_AddElement(names, ip, BSL_LIST_POS_END), 0);

    return names;
EXIT:
    HITLS_X509_FreeGeneralName(email);
    HITLS_X509_FreeGeneralName(dns);
    HITLS_X509_FreeGeneralName(dname);
    HITLS_X509_FreeGeneralName(uri);
    HITLS_X509_FreeGeneralName(ip);
    BSL_LIST_FREE(names, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
    return NULL;
}
#endif

#ifdef HITLS_PKI_X509_CRL_GEN
static int32_t SetCrlEntry(HITLS_X509_Crl *crl)
{
    int32_t ret = 1;
    BSL_TIME revokeTime = {2030, 1, 1, 0, 0, 0, 0, 0};
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};
    HITLS_X509_RevokeExtReason reason = {0, 1};  // keyCompromise
    BSL_TIME invalidTime = revokeTime;
    HITLS_X509_RevokeExtTime invalidTimeExt = {false, invalidTime};

    BslList *names = NULL;
    HITLS_X509_CrlEntry *entry = HITLS_X509_CrlEntryNew();
    ASSERT_NE(entry, NULL);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_SERIALNUM, serialNum, sizeof(serialNum)),0);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME, &revokeTime, sizeof(BSL_TIME)),0);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REASON, &reason,
        sizeof(HITLS_X509_RevokeExtReason)), 0);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_INVALID_TIME, &invalidTimeExt,
        sizeof(HITLS_X509_RevokeExtTime)), 0);
    HITLS_X509_RevokeExtCertIssuer certIssuer = {true, NULL};
    certIssuer.issuerName = GenGeneralNameList();
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_CERTISSUER,
        &certIssuer, sizeof(HITLS_X509_RevokeExtCertIssuer)), 0);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_CERTISSUER, &names, sizeof(BslList *)), 0);
    ASSERT_EQ(names->count, 5);
    ASSERT_EQ(names->dataSize, sizeof(HITLS_X509_GeneralName));
    HITLS_X509_GeneralName *ptr = names->first->data;
    ASSERT_EQ(ptr->type, HITLS_X509_GN_EMAIL);
    ASSERT_EQ(ptr->value.dataLen, 4);
    ASSERT_EQ(memcmp(ptr->value.data, "test", ptr->value.dataLen), 0);
    ptr = names->last->data;
    ASSERT_EQ(ptr->type, HITLS_X509_GN_IP);
    ASSERT_EQ(ptr->value.dataLen, 4);
    ASSERT_EQ(memcmp(ptr->value.data, "test", ptr->value.dataLen), 0);

    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_CRL_ADD_REVOKED_CERT, entry, 0), 0);

    ret = 0;
EXIT:
    HITLS_X509_FreeGeneralNames(names);
    HITLS_X509_CrlEntryFree(entry);
    BSL_LIST_FREE(certIssuer.issuerName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
    return ret;
}
#endif // HITLS_PKI_X509_CRL_GEN

#if defined(HITLS_PKI_X509_CSR_GEN) && defined(HITLS_PKI_X509_CSR_ATTR)
static int32_t FillExt(HITLS_X509_Ext *ext)
{
    HITLS_X509_ExtBCons bCons = {true, false, 1};
    HITLS_X509_ExtKeyUsage ku = {true, HITLS_X509_EXT_KU_DIGITAL_SIGN | HITLS_X509_EXT_KU_NON_REPUDIATION};
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage)), 0);
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_BCONS, &bCons, sizeof(HITLS_X509_ExtBCons)), 0);
    return 0;
EXIT:
    return 1;
}
#endif // HITLS_PKI_X509_CSR_GEN

#ifdef HITLS_PKI_X509_CRT_GEN
static void FreeListData(void *data)
{
    (void)data;
    return;
}

static int32_t SetCertExt(HITLS_X509_Cert *cert)
{
    int32_t ret = 1;
    uint8_t kid[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    HITLS_X509_ExtBCons bCons = {true, true, 1};
    HITLS_X509_ExtKeyUsage ku = {true, HITLS_X509_EXT_KU_DIGITAL_SIGN | HITLS_X509_EXT_KU_NON_REPUDIATION};
    HITLS_X509_ExtAki aki = {true, {kid, sizeof(kid)}, NULL, {0}};
    HITLS_X509_ExtSki ski = {true, {kid, sizeof(kid)}};
    HITLS_X509_ExtExKeyUsage exku = {true, NULL};
    HITLS_X509_ExtSan san = {true, NULL};
    BSL_Buffer oidBuff = {0};
    BslOidString *oid = NULL;
    HITLS_X509_ExtGeneric customExt = {0};
    char *customOid1 = "1.2.3.4.5.6.7.8.9.1";
    uint8_t *customOidData = NULL;
    uint32_t customOidLen = 0;

    BslList *oidList = BSL_LIST_New(sizeof(BSL_Buffer));
    ASSERT_TRUE(oidList != NULL);
    oid = BSL_OBJ_GetOID(BSL_CID_KP_SERVERAUTH);
    ASSERT_NE(oid, NULL);
    oidBuff.data = (uint8_t *)oid->octs;
    oidBuff.dataLen = oid->octetLen;
    ASSERT_EQ(BSL_LIST_AddElement(oidList, &oidBuff, BSL_LIST_POS_END), 0);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_BCONS, &bCons, sizeof(HITLS_X509_ExtBCons)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SKI, &ski, sizeof(HITLS_X509_ExtSki)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_AKI, &aki, sizeof(HITLS_X509_ExtAki)), 0);

    exku.oidList = oidList;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_EXKUSAGE, &exku, sizeof(HITLS_X509_ExtExKeyUsage)), 0);

    san.names = GenGeneralNameList();
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SAN, &san, sizeof(HITLS_X509_ExtSan)), 0);

    customOidData = BSL_OBJ_GetOidFromNumericString(customOid1, strlen(customOid1), &customOidLen);
    ASSERT_NE(customOidData, NULL);
    customExt.oid.data = customOidData;
    customExt.oid.dataLen = customOidLen;
    customExt.value.data = kid;
    customExt.value.dataLen = sizeof(kid);
    customExt.critical = true;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_GENERIC, &customExt, sizeof(HITLS_X509_ExtGeneric)), 0);

    ret = 0;
EXIT:
    BSL_LIST_FREE(oidList, (BSL_LIST_PFUNC_FREE)FreeListData);
    BSL_LIST_FREE(san.names, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
    BSL_SAL_FREE(customOidData);
    return ret;
}
#endif // HITLS_PKI_X509_CRT_GEN

/* BEGIN_CASE */
void SDV_PKI_GEN_KEY_TC001(int algId, int type, int curveId)
{
#ifdef HITLS_CRYPTO_KEY_ENCODE
    if (PkiSkipTest(algId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }

    char *path = "tmp.key";
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(TestEncodeKey(algId, type, curveId, path), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestRandDeInit();
    remove(path);
#else
    UnusedParam1(algId, type, curveId);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_GEN_ENCKEY_TC001(int algId, int curveId, int symId, Hex *pwd)
{
#if defined(HITLS_CRYPTO_KEY_ENCODE) && defined(HITLS_CRYPTO_KEY_EPKI)
    if (PkiSkipTest(algId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }

    CRYPT_Pbkdf2Param param = {
        .pbesId = BSL_CID_PBES2,
        .pbkdfId = BSL_CID_PBKDF2,
        .hmacId = CRYPT_MAC_HMAC_SHA256,
        .symId = symId,
        .pwd = pwd->x,
        .pwdLen = pwd->len,
        .saltLen = 16,
        .itCnt = 2000,
    };
    CRYPT_EncodeParam paramEx = {CRYPT_DERIVE_PBKDF2, &param};
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BSL_Buffer encode = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    pkey = GenKey(algId, curveId);
    ASSERT_NE(pkey, NULL);

    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkey, &paramEx, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_ENCRYPT, &encode), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_SAL_FREE(encode.data);
#else
    (void)algId;
    (void)curveId;
    (void)symId;
    (void)pwd;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_KEY_FILE_TC001(int algId, int format, int type, char *path)
{
#if defined(HITLS_BSL_SAL_FILE) && defined(HITLS_CRYPTO_KEY_DECODE)
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    CRYPT_EAL_PkeyCtx *pkey = NULL;

    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(format, type, path, NULL, 0, &pkey), CRYPT_SUCCESS);
    ASSERT_NE(pkey, NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
#else
    (void)algId;
    (void)format;
    (void)type;
    (void)path;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_ENCKEY_FILE_TC001(int algId, int format, int type, char *path, Hex *pass)
{
#if defined(HITLS_BSL_SAL_FILE) && defined(HITLS_CRYPTO_KEY_DECODE) && defined(HITLS_CRYPTO_KEY_EPKI)
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    CRYPT_EAL_PkeyCtx *pkey = NULL;

    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(format, type, path, pass->x, pass->len, &pkey), CRYPT_SUCCESS);
    ASSERT_NE(pkey, NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
#else
    (void)algId;
    (void)format;
    (void)type;
    (void)path;
    (void)pass;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_KEY_BUFF_TC001(int algId, int format, int type, Hex *encode)
{
#ifdef HITLS_CRYPTO_KEY_DECODE
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    CRYPT_EAL_PkeyCtx *pkey = NULL;

    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(format, type, (BSL_Buffer *)encode, NULL, 0, &pkey), CRYPT_SUCCESS);
    ASSERT_NE(pkey, NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
#else
    (void)algId;
    (void)format;
    (void)type;
    (void)encode;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_GEN_CRL_TC001(int algId, int hashId, int curveId)
{
#ifdef HITLS_PKI_X509_CRL_GEN
    if (PkiSkipTest(algId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }

    char *path = "tmp.crl";
    HITLS_X509_Crl *crl = NULL;
    uint32_t version = 1;
    BslList *issuer = NULL;
    BSL_TIME beforeTime = {2025, 1, 1, 0, 0, 0, 0, 0};
    BSL_TIME afterTime = {2035, 1, 1, 0, 0, 0, 0, 0};
    uint8_t crlNumber[1] = {0x11};
    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    BSL_Buffer encode = {0};
    HITLS_X509_ExtCrlNumber crlNumberExt = {false, {crlNumber, 1}};

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *prvKey = GenKey(algId, curveId);
    ASSERT_NE(prvKey, NULL);
    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);

    issuer = GenDNList();
    ASSERT_NE(issuer, NULL);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_ISSUER_DN, issuer, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(SetCrlEntry(crl), 0);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_SET_CRLNUMBER, &crlNumberExt, sizeof(HITLS_X509_ExtCrlNumber)), 0);

    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CrlSign(hashId, prvKey, NULL, crl), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CrlSign(hashId, prvKey, &algParam, crl), HITLS_PKI_SUCCESS);
    }

#ifdef HITLS_BSL_SAL_FILE
    ASSERT_EQ(HITLS_X509_CrlGenFile(BSL_FORMAT_ASN1, crl, path), HITLS_PKI_SUCCESS);
#ifdef HITLS_BSL_PEM
    ASSERT_EQ(HITLS_X509_CrlGenFile(BSL_FORMAT_PEM, crl, path), HITLS_PKI_SUCCESS);
#endif
#endif
    ASSERT_EQ(HITLS_X509_CrlGenBuff(BSL_FORMAT_ASN1, crl, &encode), 0);
    BSL_SAL_FREE(encode.data);
#ifdef HITLS_BSL_PEM
    ASSERT_EQ(HITLS_X509_CrlGenBuff(BSL_FORMAT_PEM, crl, &encode), 0);
    BSL_SAL_FREE(encode.data);
#endif
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(prvKey);
    HITLS_X509_CrlFree(crl);
    HITLS_X509_DnListFree(issuer);
    remove(path);
#else
    UnusedParam1(algId, hashId, curveId);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_CRL_FILE_TC001(int algId, int format, char *path)
{
#if defined(HITLS_PKI_X509_CRL_PARSE) && defined(HITLS_BSL_SAL_FILE)
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Crl *crl = NULL;

    TestMemInit();
    ASSERT_EQ(HITLS_X509_CrlParseFile(format, path, &crl), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CrlFree(crl);
#else
    UnusedParam2(algId, format, path);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_CRL_BUFF_TC001(int algId, int format, Hex *encode)
{
#ifdef HITLS_PKI_X509_CRL_PARSE
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Crl *crl = NULL;

    TestMemInit();
    ASSERT_EQ(HITLS_X509_CrlParseBuff(format, (BSL_Buffer *)encode, &crl), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CrlFree(crl);
#else
    UnusedParam2(algId, format, encode);
    SKIP_TEST();
#endif
}
/* END_CASE */

#if defined(HITLS_PKI_X509_CSR_GEN) && defined(HITLS_PKI_X509_CSR_ATTR)
static int32_t TestSetCsrAttrs(HITLS_X509_Csr *csr)
{
    int32_t ret = -1;
    HITLS_X509_Attrs *attrs = NULL;
    HITLS_X509_Ext *ext = HITLS_X509_ExtNew(HITLS_X509_EXT_TYPE_CSR);
    ASSERT_NE(ext, NULL);

    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_CSR_GET_ATTRIBUTES, &attrs, sizeof(HITLS_X509_Attrs *)), 0);
    ASSERT_EQ(FillExt(ext), 0);
    ASSERT_EQ(HITLS_X509_AttrCtrl(attrs, HITLS_X509_ATTR_SET_REQUESTED_EXTENSIONS, ext, 0), 0);
    ret = 0;
EXIT:
    HITLS_X509_ExtFree(ext);
    return ret;
}
#endif

/* BEGIN_CASE */
void SDV_PKI_GEN_CSR_TC001(int algId, int hashId, int curveId)
{
#ifdef HITLS_PKI_X509_CSR_GEN
    if (PkiSkipTest(algId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }

    char *path = "tmp.csr";
    HITLS_X509_Csr *csr = NULL;
    BSL_Buffer encode = {0};
    HITLS_X509_DN dnName1[1] = {{BSL_CID_AT_COMMONNAME, (uint8_t *)"OH", 2}};
    HITLS_X509_DN dnName2[1] = {{BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2}};

    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    csr = HITLS_X509_CsrNew();
    ASSERT_NE(csr, NULL);

    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_SET_PUBKEY, key, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME, dnName1, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME, dnName2, 1), HITLS_PKI_SUCCESS);
#ifdef HITLS_PKI_X509_CSR_ATTR
    ASSERT_EQ(TestSetCsrAttrs(csr), 0);
#endif
    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CsrSign(hashId, key, NULL, csr), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CsrSign(hashId, key, &algParam, csr), HITLS_PKI_SUCCESS);
    }

#ifdef HITLS_BSL_SAL_FILE
    ASSERT_EQ(HITLS_X509_CsrGenFile(BSL_FORMAT_ASN1, csr, path), 0);
#ifdef HITLS_BSL_PEM
    ASSERT_EQ(HITLS_X509_CsrGenFile(BSL_FORMAT_PEM, csr, path), 0);
#endif
#endif
    ASSERT_EQ(HITLS_X509_CsrGenBuff(BSL_FORMAT_ASN1, csr, &encode), 0);
    BSL_SAL_FREE(encode.data);
#ifdef HITLS_BSL_PEM
    ASSERT_EQ(HITLS_X509_CsrGenBuff(BSL_FORMAT_PEM, csr, &encode), 0);
    BSL_SAL_FREE(encode.data);
#endif
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CsrFree(csr);
    remove(path);
#else
    UnusedParam1(algId, hashId, curveId);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_CSR_FILE_TC001(int algId, int format, char *path)
{
#if defined(HITLS_PKI_X509_CSR_PARSE) && defined(HITLS_BSL_SAL_FILE)
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Csr *csr = NULL;
    TestMemInit();
    ASSERT_EQ(HITLS_X509_CsrParseFile(format, path, &csr), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CsrFree(csr);
#else
    UnusedParam2(algId, format, path);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_CSR_BUFF_TC001(int algId, int format, Hex *encode)
{
#if defined(HITLS_PKI_X509_CSR_PARSE)
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Csr *csr = NULL;
    TestMemInit();
    ASSERT_EQ(HITLS_X509_CsrParseBuff(format, (BSL_Buffer *)encode, &csr), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CsrFree(csr);
#else
    UnusedParam2(algId, format, encode);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_GEN_CERT_TC001(int algId, int hashId, int curveId)
{
#ifdef HITLS_PKI_X509_CRT_GEN
    if (PkiSkipTest(algId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }

    char *path = "test_sdv_x509_tmp.cert";
    HITLS_X509_Cert *cert = NULL;
    uint32_t version = 2; // v3 cert
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};
    BSL_TIME beforeTime = {2025, 1, 1, 0, 0, 0, 0, 0};
    BSL_TIME afterTime = {2035, 1, 1, 0, 0, 0, 0, 0};
    BslList *dnList = NULL;

    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    BSL_Buffer encode = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    // set cert info
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, key, 0), HITLS_PKI_SUCCESS);
    dnList = GenDNList();
    ASSERT_NE(dnList, NULL);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, dnList, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, dnList, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(SetCertExt(cert), 0);

    // sign cert
    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, NULL, cert), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, &algParam, cert), HITLS_PKI_SUCCESS);
    }

    // generate cert file
#ifdef HITLS_BSL_SAL_FILE
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path), HITLS_PKI_SUCCESS);
#ifdef HITLS_BSL_PEM
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_PEM, cert, path), HITLS_PKI_SUCCESS);
#endif
#endif
    // generate cert buff
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &encode), 0);
    BSL_SAL_FREE(encode.data);
#ifdef HITLS_BSL_PEM
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_PEM, cert, &encode), 0);
    BSL_SAL_FREE(encode.data);
#endif
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_DnListFree(dnList);
    remove(path);
#else
    UnusedParam1(algId, hashId, curveId);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_CERT_FILE_TC001(int algId, int format, char *path)
{
#if defined(HITLS_PKI_X509_CRT_PARSE) && defined(HITLS_BSL_SAL_FILE)
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Cert *cert = NULL;
    TestMemInit();
    ASSERT_EQ(HITLS_X509_CertParseFile(format, path, &cert), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CertFree(cert);
#else
    UnusedParam2(algId, format, path);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_CERT_BUFF_TC001(int algId, int format, Hex *encode)
{
#ifdef HITLS_PKI_X509_CRT_PARSE
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Cert *cert = NULL;
    TestMemInit();
    ASSERT_EQ(HITLS_X509_CertParseBuff(format, (BSL_Buffer *)encode, &cert), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CertFree(cert);
#else
    UnusedParam2(algId, format, encode);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_CERT_FILE_CONTAIN_T61_TC001(int algId, int format, char *path)
{
#if defined(HITLS_PKI_X509_CRT_PARSE) && defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_BSL_SAL_FILE)
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *certCpy = NULL;
    BSL_Buffer buff = {0};

    TestMemInit();
    ASSERT_EQ(HITLS_X509_CertParseFile(format, path, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertGenBuff(format, cert, &buff), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseBuff(format, &buff, &certCpy), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(buff.data);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(certCpy);
#else
    UnusedParam2(algId, format, path);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_MLDSA_PQC_CERT_TC001(char *keypath)
{
#if defined(HITLS_PKI_X509_CRT_PARSE) && defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_BSL_SAL_FILE)
    HITLS_X509_Cert *cert = NULL;
    uint32_t version = 2; // v3 cert
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};
    BSL_TIME beforeTime = {2025, 1, 1, 0, 0, 0, 0, 0};
    BSL_TIME afterTime = {2035, 1, 1, 0, 0, 0, 0, 0};
    BslList *dnList = NULL;
    BSL_Buffer encode = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keypath, NULL, 0, &pkey),
              CRYPT_SUCCESS);
    ASSERT_NE(pkey, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    // set cert info
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, pkey, 0), HITLS_PKI_SUCCESS);
    dnList = GenDNList();
    ASSERT_NE(dnList, NULL);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, dnList, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, dnList, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(SetCertExt(cert), 0);

    // sign cert
    ASSERT_EQ(HITLS_X509_CertSign(CRYPT_MD_SHA256, pkey, NULL, cert), HITLS_PKI_SUCCESS);

    // generate cert buff
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_PEM, cert, &encode), HITLS_PKI_SUCCESS);
    BSL_SAL_FREE(encode.data);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
    HITLS_X509_DnListFree(dnList);
#else
    (void)keypath;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_MLDSA_PQC_CERT_TC002(char *keypath)
{
#if defined(HITLS_PKI_X509_CRT_PARSE) && defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_BSL_SAL_FILE)
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keypath, NULL, 0, &pkey),
              CRYPT_SUCCESS);
    ASSERT_EQ(pkey, NULL);
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
#else
    (void)keypath;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_MLDSA_PQCCert_TC003(int format, char *path)
{
#if defined(HITLS_PKI_X509_CRT_PARSE) && defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_BSL_SAL_FILE)
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *certCpy = NULL;
    BSL_Buffer buff = {0};

    TestMemInit();
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    BSL_SAL_ReadFile(path, &data, &dataLen);
    ASSERT_EQ(HITLS_X509_CertParseFile(format, path, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertGenBuff(format, cert, &buff), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("cert", buff.data, buff.dataLen, data, dataLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(buff.data);
    BSL_SAL_Free(data);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(certCpy);
#else
    (void)format;
    (void)path;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_PQCCert_TC004(int algId, int paraId, int format, int type, int use_default, int key_format, int keylen, char *path)
{
#if defined(HITLS_PKI_X509_CRT_PARSE) && defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_BSL_SAL_FILE) && \
    defined(HITLS_CRYPTO_CODECSKEY)
    if (PkiSkipTestByParaId(algId, paraId, format)) {
        SKIP_TEST();
    }
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    BSL_Buffer encodeAsn1 = {0};
    uint32_t outputFormats[] = {(uint32_t)key_format};
    BSL_Param encodeParam[] = {
        {CRYPT_PARAM_ENCODE_OUTPUT_FORMATS, BSL_PARAM_TYPE_UINT32_PTR, outputFormats, sizeof(outputFormats), 0},
        BSL_PARAM_END
    };
    const BSL_Param *encodeParamPtr = use_default != 0 ? NULL : encodeParam;
    CRYPT_EAL_PkeyCtx *pkey = GenKey(algId, paraId);
    ASSERT_NE(pkey, NULL);


        ASSERT_EQ(CRYPT_EAL_EncodeBuffKeyEx(pkey, encodeParamPtr, format, type, &encodeAsn1), CRYPT_SUCCESS);
    if (keylen > 0) {
        ASSERT_EQ(keylen, encodeAsn1.dataLen);
    }

    ASSERT_EQ(CRYPT_EAL_EncodeFileKeyEx(pkey, encodeParamPtr, format, type, path), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_FREE(encodeAsn1.data);
    CRYPT_EAL_PkeyFreeCtx(pkey);
#else
    (void)algId;
    (void)paraId;
    (void)format;
    (void)type;
    (void)use_default;
    (void)key_format;
    (void)keylen;
    (void)path;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_PQCCert_TC006(int algId, int paraId, int mdId)
{
#if defined(HITLS_PKI_X509_CRT_PARSE) && defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_BSL_SAL_FILE)
    if (PkiSkipTestByParaId(algId, paraId, BSL_FORMAT_PEM)) {
        SKIP_TEST();
    }
    char *path = "test_sdv_x509_tmp.cert";
    HITLS_X509_Cert *cert = NULL;
    uint32_t version = 2; // v3 cert
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};
    BSL_TIME beforeTime = {2025, 1, 1, 0, 0, 0, 0, 0};
    BSL_TIME afterTime = {2035, 1, 1, 0, 0, 0, 0, 0};
    BslList *dnList = NULL;
    BSL_Buffer encode = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *pkey = GenKey(algId, paraId);
    ASSERT_NE(pkey, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    // set cert info
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, pkey, 0), HITLS_PKI_SUCCESS);
    dnList = GenDNList();
    ASSERT_NE(dnList, NULL);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, dnList, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, dnList, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(SetCertExt(cert), 0);

    // sign cert
    ASSERT_EQ(HITLS_X509_CertSign(mdId, pkey, NULL, cert), HITLS_PKI_SUCCESS);

    // generate cert file
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_PEM, cert, path), HITLS_PKI_SUCCESS);
    // generate cert buff
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_PEM, cert, &encode), 0);
    BSL_SAL_FREE(encode.data);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
    HITLS_X509_DnListFree(dnList);
    remove(path);
#else
    (void)algId;
    (void)paraId;
    (void)mdId;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_PQCCert_TC007(int algId, int paraId, int mdId, char *keypath, char *pubkeypath)
{
#if defined(HITLS_PKI_X509_CRT_PARSE) && defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_BSL_SAL_FILE) && \
    defined(HITLS_CRYPTO_CODECSKEY)
    if (PkiSkipTestByParaId(algId, paraId, BSL_FORMAT_PEM)) {
        SKIP_TEST();
    }
    char *path = "test_sdv_x509_tmp.cert";
    HITLS_X509_Cert *cert = NULL;
    uint32_t version = 2; // v3 cert
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};
    BSL_TIME beforeTime = {2025, 1, 1, 0, 0, 0, 0, 0};
    BSL_TIME afterTime = {2035, 1, 1, 0, 0, 0, 0, 0};
    BslList *dnList = NULL;
    BSL_Buffer encode = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *certPubKey = NULL;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keypath, NULL, 0, &pkey), CRYPT_SUCCESS);
    ASSERT_NE(pkey, NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGetId(pkey), algId);
    ASSERT_EQ(CRYPT_EAL_PkeyGetParaId(pkey), paraId);
    certPubKey = pkey;
    if (algId == CRYPT_PKEY_COMPOSITE) {
        ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, pubkeypath, NULL, 0, &certPubKey), CRYPT_SUCCESS);
        ASSERT_NE(certPubKey, NULL);
        ASSERT_EQ(CRYPT_EAL_PkeyGetId(certPubKey), algId);
        ASSERT_EQ(CRYPT_EAL_PkeyGetParaId(certPubKey), paraId);
    }
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    // set cert info
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, certPubKey, 0), HITLS_PKI_SUCCESS);
    dnList = GenDNList();
    ASSERT_NE(dnList, NULL);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, dnList, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, dnList, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(SetCertExt(cert), 0);

    // sign cert
    ASSERT_EQ(HITLS_X509_CertSign(mdId, pkey, NULL, cert), HITLS_PKI_SUCCESS);

    // generate cert file
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_PEM, cert, path), HITLS_PKI_SUCCESS);
    // generate cert buff
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_PEM, cert, &encode), 0);
    BSL_SAL_FREE(encode.data);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestRandDeInit();
    if (certPubKey != pkey) {
        CRYPT_EAL_PkeyFreeCtx(certPubKey);
    }
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
    HITLS_X509_DnListFree(dnList);
    remove(path);
#else
    (void)algId;
    (void)paraId;
    (void)mdId;
    (void)keypath;
    (void)pubkeypath;
    SKIP_TEST();
#endif
}
/* END_CASE */

#if defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_CRYPTO_CODECSKEY) && defined(HITLS_BSL_SAL_FILE) && \
    defined(HITLS_PKI_X509_CSR)
static int32_t SetCertExtkid(HITLS_X509_Cert *cert, uint8_t *akid, uint8_t *skid)
{
    int32_t ret = 1;
    HITLS_X509_ExtBCons bCons = {true, true, -1};
    HITLS_X509_ExtKeyUsage ku = {true, HITLS_X509_EXT_KU_DIGITAL_SIGN | HITLS_X509_EXT_KU_KEY_CERT_SIGN | HITLS_X509_EXT_KU_NON_REPUDIATION};
    HITLS_X509_ExtAki aki = {false, {akid, sizeof(akid)}, NULL, {0}};
    HITLS_X509_ExtSki ski = {false, {skid, sizeof(skid)}};
    HITLS_X509_ExtSan san = {false, NULL};

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_BCONS, &bCons, sizeof(HITLS_X509_ExtBCons)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SKI, &ski, sizeof(HITLS_X509_ExtSki)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_AKI, &aki, sizeof(HITLS_X509_ExtAki)), 0);

    san.names = GenGeneralNameList();
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SAN, &san, sizeof(HITLS_X509_ExtSan)), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ret = 0;
EXIT:
    BSL_LIST_FREE(san.names, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
    return ret;
}
#endif
/* BEGIN_CASE */
void SDV_HITLS_GEN_CSR_CERT_TC001(int algId, int paraId, int mdId)
{
#if defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_CRYPTO_CODECSKEY) && defined(HITLS_BSL_SAL_FILE) && \
    defined(HITLS_PKI_X509_CSR)
    if (PkiSkipTestByParaId(algId, paraId, BSL_FORMAT_PEM)) {
        SKIP_TEST();
    }
    char *path = "tmpca.csr";
    char *pathcakey = "tmpcakey.pem";
    char *path1 = "tmpca1.cert";
    HITLS_X509_Csr *csr = NULL;
    BSL_Buffer encode = {0};
    HITLS_X509_DN dnName1[1] = {{BSL_CID_AT_COMMONNAME, (uint8_t *)"ROOT", 2}};
    HITLS_X509_DN dnName2[1] = {{BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2}};
    HITLS_X509_SignAlgParam algParam = {0};
    HITLS_X509_Cert *cert = NULL;
    uint32_t version = 2; // v3 cert
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};
    BSL_TIME beforeTime = {2025, 1, 1, 0, 0, 0, 0, 0};
    BSL_TIME afterTime = {2035, 1, 1, 0, 0, 0, 0, 0};
    uint8_t akid[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    BslList *dnList = NULL;
    BslList *subject = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    pkey = GenKey(algId, paraId);
    ASSERT_NE(pkey, NULL);
    ASSERT_EQ(CRYPT_EAL_EncodeFileKey(pkey, NULL, BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pathcakey), CRYPT_SUCCESS);

    csr = HITLS_X509_CsrNew();
    ASSERT_NE(csr, NULL);

    // set csr info
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME, dnName1, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME, dnName2, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_SET_PUBKEY, pkey, 0), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CsrSign(mdId, pkey, &algParam, csr), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CsrGenBuff(BSL_FORMAT_PEM, csr, &encode), 0);
    BSL_SAL_FREE(encode.data);
    ASSERT_EQ(HITLS_X509_CsrGenFile(BSL_FORMAT_PEM, csr, path), 0);

    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    // set cert info
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, pkey, 0), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_GET_SUBJECT_DN, &subject, sizeof(BslList *)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, subject, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, subject, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(SetCertExtkid(cert, akid, akid), 0);

    // sign cert
    ASSERT_EQ(HITLS_X509_CertSign(mdId, pkey, &algParam, cert), HITLS_PKI_SUCCESS);

    // generate cert file
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_PEM, cert, path1), HITLS_PKI_SUCCESS);
    // generate cert buff
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_PEM, cert, &encode), 0);
    BSL_SAL_FREE(encode.data);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CsrFree(csr);
    HITLS_X509_DnListFree(dnList);
    remove(path);
#else
    (void)algId;
    (void)paraId;
    (void)mdId;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_GEN_CSR_MIDCERT_TC001(int algId, int paraId, int mdId)
{
#if defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_CRYPTO_CODECSKEY) && defined(HITLS_BSL_SAL_FILE) && \
    defined(HITLS_PKI_X509_CSR)
    if (PkiSkipTestByParaId(algId, paraId, BSL_FORMAT_PEM)) {
        SKIP_TEST();
    }
    SDV_HITLS_GEN_CSR_CERT_TC001(algId, paraId, mdId);
    char *path = "tmpmid.csr";
    char *pathmidkey = "tmpmidkey.pem";
    char *pathmid = "tmpmid.cert";
    HITLS_X509_Csr *csr = NULL;
    BSL_Buffer encode = {0};
    HITLS_X509_DN dnName1[1] = {{BSL_CID_AT_COMMONNAME, (uint8_t *)"MID", 2}};
    HITLS_X509_DN dnName2[1] = {{BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2}};
    HITLS_X509_Attrs *attrs = NULL;
    HITLS_X509_SignAlgParam algParam = {0};
    HITLS_X509_Cert *cert = NULL;
    uint32_t version = 2; // v3 cert
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x55};
    BSL_TIME beforeTime = {2025, 1, 1, 0, 0, 0, 0, 0};
    BSL_TIME afterTime = {2035, 1, 1, 0, 0, 0, 0, 0};
    uint8_t akid[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    uint8_t skid[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x99};
    BslList *dnList = NULL;
    BslList *subject = NULL;
    BslList *issuer = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *capkey = NULL;
    HITLS_X509_Cert *cacert = NULL;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    pkey = GenKey(algId, paraId);
    ASSERT_NE(pkey, NULL);
    ASSERT_EQ(CRYPT_EAL_EncodeFileKey(pkey, NULL, BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pathmidkey), CRYPT_SUCCESS);

    csr = HITLS_X509_CsrNew();
    ASSERT_NE(csr, NULL);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "tmpca1.cert", &cacert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, "tmpcakey.pem", NULL, 0, &capkey), CRYPT_SUCCESS);

    // set csr info
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME, dnName1, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME, dnName2, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_CSR_GET_ATTRIBUTES, &attrs, sizeof(HITLS_X509_Attrs *)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_SET_PUBKEY, pkey, 0), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CsrSign(mdId, pkey, &algParam, csr), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CsrGenBuff(BSL_FORMAT_PEM, csr, &encode), 0);
    BSL_SAL_FREE(encode.data);
    ASSERT_EQ(HITLS_X509_CsrGenFile(BSL_FORMAT_PEM, csr, path), 0);

    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    // set cert info
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, pkey, 0), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_GET_SUBJECT_DN, &subject, sizeof(BslList *)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, subject, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cacert, HITLS_X509_GET_SUBJECT_DN, &issuer, sizeof(BslList *)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, issuer, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(SetCertExtkid(cert, akid, skid), 0);

    // sign cert
    ASSERT_EQ(HITLS_X509_CertSign(mdId, capkey, &algParam, cert), HITLS_PKI_SUCCESS);

    // generate cert file
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_PEM, cert, pathmid), HITLS_PKI_SUCCESS);
    // generate cert buff
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_PEM, cert, &encode), 0);
    BSL_SAL_FREE(encode.data);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(capkey);
    HITLS_X509_CertFree(cacert);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CsrFree(csr);
    HITLS_X509_DnListFree(dnList);
    remove(path);
#else
    (void)algId;
    (void)paraId;
    (void)mdId;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_GEN_CSR_EECERT_TC001(int algId, int paraId, int mdId)
{
#if defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_CRYPTO_CODECSKEY) && defined(HITLS_BSL_SAL_FILE) && \
    defined(HITLS_PKI_X509_CSR)
    if (PkiSkipTestByParaId(algId, paraId, BSL_FORMAT_PEM)) {
        SKIP_TEST();
    }
    SDV_HITLS_GEN_CSR_MIDCERT_TC001(algId, paraId, mdId);
    char *path = "tmpee.csr";
    char *pathmidkey = "tmpeekey.pem";
    char *pathmid = "tmpee.cert";
    HITLS_X509_Csr *csr = NULL;
    BSL_Buffer encode = {0};
    HITLS_X509_DN dnName1[1] = {{BSL_CID_AT_COMMONNAME, (uint8_t *)"EE", 2}};
    HITLS_X509_DN dnName2[1] = {{BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2}};
    HITLS_X509_SignAlgParam algParam = {0};
    HITLS_X509_Cert *cert = NULL;
    uint32_t version = 2; // v3 cert
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x66};
    BSL_TIME beforeTime = {2025, 1, 1, 0, 0, 0, 0, 0};
    BSL_TIME afterTime = {2035, 1, 1, 0, 0, 0, 0, 0};
    uint8_t akid[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x99};
    uint8_t skid[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00};
    BslList *dnList = NULL;
    BslList *subject = NULL;
    BslList *issuer = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *capkey = NULL;
    HITLS_X509_Cert *cacert = NULL;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    pkey = GenKey(algId, paraId);
    ASSERT_NE(pkey, NULL);
    ASSERT_EQ(CRYPT_EAL_EncodeFileKey(pkey, NULL, BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pathmidkey), CRYPT_SUCCESS);

    csr = HITLS_X509_CsrNew();
    ASSERT_NE(csr, NULL);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, "tmpmid.cert", &cacert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT, "tmpmidkey.pem", NULL, 0, &capkey), CRYPT_SUCCESS);

    // set csr info
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME, dnName1, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME, dnName2, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_SET_PUBKEY, pkey, 0), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CsrSign(mdId, pkey, &algParam, csr), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CsrGenBuff(BSL_FORMAT_PEM, csr, &encode), 0);
    BSL_SAL_FREE(encode.data);
    ASSERT_EQ(HITLS_X509_CsrGenFile(BSL_FORMAT_PEM, csr, path), 0);

    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    // set cert info
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, pkey, 0), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_GET_SUBJECT_DN, &subject, sizeof(BslList *)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, subject, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cacert, HITLS_X509_GET_SUBJECT_DN, &issuer, sizeof(BslList *)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, issuer, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(SetCertExtkid(cert, akid, skid), 0);

    // sign cert
    ASSERT_EQ(HITLS_X509_CertSign(mdId, capkey, &algParam, cert), HITLS_PKI_SUCCESS);

    // generate cert file
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_PEM, cert, pathmid), HITLS_PKI_SUCCESS);
    // generate cert buff
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_PEM, cert, &encode), 0);
    BSL_SAL_FREE(encode.data);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(capkey);
    HITLS_X509_CertFree(cacert);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CsrFree(csr);
    HITLS_X509_DnListFree(dnList);
    remove(path);
    remove(pathmidkey);
    remove("tmpcakey.pem");
    remove("tmpmidkey.pem");
#else
    (void)algId;
    (void)paraId;
    (void)mdId;
    SKIP_TEST();
#endif
}
/* END_CASE */

#if defined(HITLS_PKI_X509_CRT_PARSE) && (defined(HITLS_PKI_X509_VFY_DEFAULT) || defined(HITLS_PKI_X509_VFY_CB)) && \
    defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_CRYPTO_CODECSKEY) && defined(HITLS_BSL_SAL_FILE) &&            \
    defined(HITLS_PKI_X509_CSR)
static int32_t HITLS_AddCertToStoreTest(char *path, HITLS_X509_StoreCtx *store, HITLS_X509_Cert **cert)
{
    int32_t ret = HITLS_X509_CertParseFile(BSL_FORMAT_PEM, path, cert);
    if (ret != HITLS_PKI_SUCCESS){
        return ret;
    }
    return HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, *cert, 0);
}
#endif

/* BEGIN_CASE */
void SDV_HITLS_CERT_CHAIN_FUNC_TC001(int algId, int paraId, int mdId)
{
#if defined(HITLS_PKI_X509_CRT_PARSE) && (defined(HITLS_PKI_X509_VFY_DEFAULT) || defined(HITLS_PKI_X509_VFY_CB)) && \
    defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_CRYPTO_CODECSKEY) && defined(HITLS_BSL_SAL_FILE) &&            \
    defined(HITLS_PKI_X509_CSR)
    if (PkiSkipTestByParaId(algId, paraId, BSL_FORMAT_PEM)) {
        SKIP_TEST();
    }
    SDV_HITLS_GEN_CSR_EECERT_TC001(algId, paraId, mdId);
    HITLS_X509_StoreCtx *store = HITLS_X509_StoreCtxNew();
    ASSERT_NE(store, NULL);
    HITLS_X509_Cert *entity = NULL;
    int32_t ret = HITLS_AddCertToStoreTest("tmpee.cert", store, &entity);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *midcert = NULL;
    ret = HITLS_AddCertToStoreTest("tmpmid.cert", store, &midcert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    HITLS_X509_Cert *cacert = NULL;
    ret = HITLS_AddCertToStoreTest("tmpca1.cert", store, &cacert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    HITLS_X509_List *chain = NULL;
    ret = HITLS_X509_CertChainBuild(store, true, entity, &chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CertVerify(store, chain);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CertFree(entity);
    HITLS_X509_CertFree(midcert);
    HITLS_X509_CertFree(cacert);
    HITLS_X509_StoreCtxFree(store);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    remove("tmpee.cert");
    remove("tmpca1.cert");
    remove("tmpmid.cert");
#else
    (void)algId;
    (void)paraId;
    (void)mdId;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_MLDSA_PQCCert_TC009(int key_format)
{
#if defined(HITLS_CRYPTO_KEY_ENCODE) && defined(HITLS_CRYPTO_KEY_DECODE)
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    BSL_Buffer encodeAsn1 = {0};
    uint32_t outputFormats[] = {(uint32_t)key_format};
    BSL_Param encodeParam[] = {
        {CRYPT_PARAM_ENCODE_OUTPUT_FORMATS, BSL_PARAM_TYPE_UINT32_PTR, outputFormats, sizeof(outputFormats), 0},
        BSL_PARAM_END
    };
    CRYPT_EAL_PkeyCtx *pkeyout = NULL;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    ASSERT_NE(pkey, NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, CRYPT_MLDSA_TYPE_MLDSA_44), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_EncodeBuffKeyEx(pkey, encodeParam, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encodeAsn1), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    switch (key_format)
    {
        case CRYPT_ALGO_MLDSA_PRIV_FORMAT_SEED_ONLY:
            encodeAsn1.data[20] = 0x81;  //seed_only  修改第20位为tag
            ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encodeAsn1, NULL, 0, &pkeyout), BSL_ASN1_ERR_TAG_EXPECTED);
            break;
        case CRYPT_ALGO_MLDSA_PRIV_FORMAT_PRIV_ONLY:
            encodeAsn1.data[24] = 0x05;  //priv_only  修改第24位为tag
            ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encodeAsn1, NULL, 0, &pkeyout), BSL_ASN1_ERR_TAG_EXPECTED);
            break;
        case CRYPT_ALGO_MLDSA_PRIV_FORMAT_BOTH:
            encodeAsn1.data[28] = 0x31;  //both  修改第28位为第一个tag
            ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encodeAsn1, NULL, 0, &pkeyout), BSL_ASN1_ERR_TAG_EXPECTED);
            encodeAsn1.data[28] = 0x04;  //both  修改第28位为第一个tag
            encodeAsn1.data[62] = 0x80;  //both  修改第62位为第二个tag
            ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encodeAsn1, NULL, 0, &pkeyout), BSL_ASN1_ERR_TAG_EXPECTED);
            encodeAsn1.data[62] = 0x04;  //both  修改第62位为第二个tag
            break;
        default:
            break;
    }
EXIT:
    BSL_SAL_FREE(encodeAsn1.data);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkeyout);
#else
    SKIP_TEST();
    (void)key_format;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_HITLS_MLDSA_PQCCert_TC010()
{
#if defined(HITLS_CRYPTO_KEY_ENCODE) && defined(HITLS_CRYPTO_KEY_DECODE)
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    BSL_Buffer encodeAsn1 = {0};
    uint32_t outputFormats[] = { CRYPT_ALGO_MLDSA_PRIV_FORMAT_BOTH};
    BSL_Param encodeParam[] = {
        {CRYPT_PARAM_ENCODE_OUTPUT_FORMATS, BSL_PARAM_TYPE_UINT32_PTR, outputFormats, sizeof(outputFormats), 0},
        BSL_PARAM_END
    };
    CRYPT_EAL_PkeyCtx *pkeyout = NULL;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_DSA);
    ASSERT_NE(pkey, NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, CRYPT_MLDSA_TYPE_MLDSA_44), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKeyEx(pkey, encodeParam, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encodeAsn1), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    encodeAsn1.data[40]++;
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encodeAsn1, NULL, 0, &pkeyout), CRYPT_MLDSA_PRVKEY_SEED_INCONSISTENT);
EXIT:
    BSL_SAL_FREE(encodeAsn1.data);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkeyout);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * Test SLH-DSA certificate encode/decode consistency
 * Parse certificate from file, re-encode it, and compare with original file
 */
/* BEGIN_CASE */
void SDV_HITLS_SLHDSA_PQCCert_TC001(int format, char *path)
{
#if defined(HITLS_PKI_X509_CRT_PARSE) && defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_BSL_SAL_FILE)
    HITLS_X509_Cert *cert = NULL;
    BSL_Buffer buff = {0};

    TestMemInit();
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    BSL_SAL_ReadFile(path, &data, &dataLen);
    ASSERT_EQ(HITLS_X509_CertParseFile(format, path, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertGenBuff(format, cert, &buff), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("cert", buff.data, buff.dataLen, data, dataLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(buff.data);
    BSL_SAL_Free(data);
    HITLS_X509_CertFree(cert);
#else
    (void)format;
    (void)path;
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * Test extracting SAN extension from certificate buffer
 */
/* BEGIN_CASE */
void SDV_PKI_GET_SAN_FROM_CERT_BUFF_TC001(int algId, int format, Hex *encode)
{
#ifdef HITLS_PKI_X509_CRT_PARSE
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_ExtSan san = {0};
    HITLS_X509_GeneralName *gn = NULL;
    TestMemInit();
    ASSERT_EQ(HITLS_X509_CertParseBuff(format, (BSL_Buffer *)encode, &cert), HITLS_PKI_SUCCESS);
    ASSERT_NE(cert, NULL);
    BSL_Buffer cn = {0};

    // Check whether the certificate contains SAN extension
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SAN, &san, sizeof(HITLS_X509_ExtSan)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(san.names), 11); // 11 is the number of SAN extensions in the certificate.
    gn = BSL_LIST_GET_FIRST(san.names);

    while (gn != NULL) {
        ASSERT_NE(gn->value.data, NULL);
        gn = BSL_LIST_GET_NEXT(san.names);
    }

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SUBJECT_CN_STR, &cn, sizeof(BSL_Buffer)), 0);
    ASSERT_NE(cn.data, NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CertFree(cert);
    BSL_LIST_FREE(san.names, NULL);
    BSL_SAL_Free(cn.data);
#else
    UnusedParam2(algId, format, encode);
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_PKI_GEN_ENCKEY_STUB_TC001
 * title 1. Test the pkey prv encode with stub malloc fail
 *
 */
/* BEGIN_CASE */
void SDV_PKI_GEN_ENCKEY_STUB_TC001(int algId, int curveId, int symId, Hex *pwd)
{
#if defined(HITLS_CRYPTO_KEY_ENCODE) && defined(HITLS_CRYPTO_KEY_EPKI)
    if (PkiSkipTest(algId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }
    CRYPT_Pbkdf2Param param = {.pbesId = BSL_CID_PBES2, .pbkdfId = BSL_CID_PBKDF2, .hmacId = CRYPT_MAC_HMAC_SHA256,
                              .symId = symId,           .pwd = pwd->x,             .pwdLen = pwd->len,
                              .saltLen = 16,            .itCnt = 2000};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EncodeParam paramEx = {CRYPT_DERIVE_PBKDF2, &param};
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BSL_Buffer encode = {0};
    uint32_t totalMallocCount = 0;

    pkey = GenKey(algId, curveId);
    ASSERT_NE(pkey, NULL);

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    /* Phase 1: Probe - count malloc calls during successful execution */
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkey, &paramEx, BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_ENCRYPT, &encode), 0);
    totalMallocCount = STUB_GetMallocCallCount();
    BSL_SAL_Free(encode.data);
    encode.data = NULL;
    encode.dataLen = 0;

    /* Phase 2: Test - iteratively fail each malloc */
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ASSERT_NE(CRYPT_EAL_EncodeBuffKey(pkey, &paramEx, BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_ENCRYPT, &encode), 0);
    }
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    STUB_RESTORE(BSL_SAL_Malloc);
#else
    (void)algId;
    (void)curveId;
    (void)symId;
    (void)pwd;
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_PKI_GEN_ENCKEY_STUB_TC002
 * title 1. Test the pkey pub encode with stub malloc fail
 *
 */
/* BEGIN_CASE */
void SDV_PKI_GEN_ENCKEY_STUB_TC002(int algId, int curveId, int symId, Hex *pwd, Hex *sm2Pub)
{
#if defined(HITLS_CRYPTO_KEY_ENCODE) && defined(HITLS_CRYPTO_KEY_EPKI)
    if (PkiSkipTest(algId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }
    CRYPT_Pbkdf2Param param = {.pbesId = BSL_CID_PBES2, .pbkdfId = BSL_CID_PBKDF2, .hmacId = CRYPT_MAC_HMAC_SHA256,
        .symId = symId,           .pwd = pwd->x,             .pwdLen = pwd->len,
        .saltLen = 16,            .itCnt = 2000};
    CRYPT_EAL_PkeyPub pub = {.id = CRYPT_PKEY_SM2, .key.eccPub = {.data = sm2Pub->x, .len = sm2Pub->len}};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EncodeParam paramEx = {CRYPT_DERIVE_PBKDF2, &param};
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BSL_Buffer encode = {0};
    uint32_t totalMallocCount = 0;

    if (algId == CRYPT_PKEY_SM2) {
        ASSERT_NE(pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2), NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_SUCCESS);
    } else {
        pkey = GenKey(algId, curveId);
        ASSERT_NE(pkey, NULL);
    }

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    /* Phase 1: Probe - count malloc calls during successful execution */
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkey, &paramEx, BSL_FORMAT_PEM, CRYPT_PUBKEY_SUBKEY, &encode), CRYPT_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    BSL_SAL_Free(encode.data);
    encode.data = NULL;
    encode.dataLen = 0;

    /* Phase 2: Test - iteratively fail each malloc */
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ASSERT_NE(CRYPT_EAL_EncodeBuffKey(pkey, &paramEx, BSL_FORMAT_PEM, CRYPT_PUBKEY_SUBKEY, &encode), CRYPT_SUCCESS);
    }
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    STUB_RESTORE(BSL_SAL_Malloc);
#else
    (void)algId;
    (void)curveId;
    (void)symId;
    (void)pwd;
    (void)sm2Pub;
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_PKI_GEN_CERT_STUB_TC001
 * title 1. Test the cert encode with stub malloc fail
 *
 */
/* BEGIN_CASE */
void SDV_PKI_GEN_CERT_STUB_TC001(int algId, int hashId, int curveId)
{
#ifdef HITLS_PKI_X509_CRT_GEN
    if (PkiSkipTest(algId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }

    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *testCert = NULL;
    uint32_t version = 2; // v3 cert
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};
    BSL_TIME beforeTime = {2025, 1, 1, 0, 0, 0, 0, 0};
    BSL_TIME afterTime = {2035, 1, 1, 0, 0, 0, 0, 0};
    BslList *dnList = NULL;
    BslList *testDnList = NULL;

    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    BSL_Buffer encode = {0};
    uint32_t totalMallocCount = 0;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    testCert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_NE(testCert, NULL);

    // set cert info
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(testCert, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(testCert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(testCert, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(testCert, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, key, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(testCert, HITLS_X509_SET_PUBKEY, key, 0), HITLS_PKI_SUCCESS);
    dnList = GenDNList();
    testDnList = GenDNList();
    ASSERT_NE(testDnList, NULL);
    ASSERT_NE(dnList, NULL);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, dnList, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, dnList, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(testCert, HITLS_X509_SET_ISSUER_DN, testDnList, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(testCert, HITLS_X509_SET_SUBJECT_DN, testDnList, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(SetCertExt(cert), 0);
    ASSERT_EQ(SetCertExt(testCert), 0);

    // sign cert
    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, NULL, cert), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, NULL, testCert), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, &algParam, cert), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, &algParam, testCert), HITLS_PKI_SUCCESS);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    /* Phase 1: Probe - count malloc calls during successful execution */
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &encode), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    BSL_SAL_Free(encode.data);
    encode.data = NULL;
    encode.dataLen = 0;

    /* Phase 2: Test - iteratively fail each malloc */
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount - 1; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ASSERT_NE(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, testCert, &encode), HITLS_PKI_SUCCESS);
    }
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(testCert);
    HITLS_X509_DnListFree(dnList);
    HITLS_X509_DnListFree(testDnList);
    STUB_RESTORE(BSL_SAL_Malloc);
#else
    UnusedParam1(algId, hashId, curveId);
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test SDV_PKI_GEN_CSR_STUB_TC001
 * title 1. Test the csr encode with stub malloc fail
 *
 */
/* BEGIN_CASE */
void SDV_PKI_GEN_CSR_STUB_TC001(int algId, int hashId, int curveId)
{
#ifdef HITLS_PKI_X509_CSR_GEN
    if (PkiSkipTest(algId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }
    HITLS_X509_Csr *csr = NULL;
    HITLS_X509_Csr *testCsr = NULL;
    BSL_Buffer encode = {0};
    HITLS_X509_DN dnName1[1] = {{BSL_CID_AT_COMMONNAME, (uint8_t *)"OH", 2}};
    HITLS_X509_DN dnName2[1] = {{BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2}};
    HITLS_X509_Attrs *attrs = NULL;
    HITLS_X509_Attrs *testAttrs = NULL;
    HITLS_X509_Ext *ext = NULL;
    HITLS_X509_Ext *testExt = NULL;
    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    uint32_t totalMallocCount = 0;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    csr = HITLS_X509_CsrNew();
    testCsr = HITLS_X509_CsrNew();
    ASSERT_NE(csr, NULL);
    ASSERT_NE(testCsr, NULL);
    ext = HITLS_X509_ExtNew(HITLS_X509_EXT_TYPE_CSR);
    testExt = HITLS_X509_ExtNew(HITLS_X509_EXT_TYPE_CSR);
    ASSERT_NE(ext, NULL);
    ASSERT_NE(testExt, NULL);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_SET_PUBKEY, key, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(testCsr, HITLS_X509_SET_PUBKEY, key, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME, dnName1, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(testCsr, HITLS_X509_ADD_SUBJECT_NAME, dnName1, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME, dnName2, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(testCsr, HITLS_X509_ADD_SUBJECT_NAME, dnName2, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_CSR_GET_ATTRIBUTES, &attrs, sizeof(HITLS_X509_Attrs *)), 0);
    ASSERT_EQ(HITLS_X509_CsrCtrl(testCsr, HITLS_X509_CSR_GET_ATTRIBUTES, &testAttrs, sizeof(HITLS_X509_Attrs *)), 0);
    ASSERT_EQ(FillExt(ext), 0);
    ASSERT_EQ(FillExt(testExt), 0);
    ASSERT_EQ(HITLS_X509_AttrCtrl(attrs, HITLS_X509_ATTR_SET_REQUESTED_EXTENSIONS, ext, 0), 0);
    ASSERT_EQ(HITLS_X509_AttrCtrl(testAttrs, HITLS_X509_ATTR_SET_REQUESTED_EXTENSIONS, testExt, 0), 0);
    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CsrSign(hashId, key, NULL, csr), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_X509_CsrSign(hashId, key, NULL, testCsr), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CsrSign(hashId, key, &algParam, csr), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_X509_CsrSign(hashId, key, &algParam, testCsr), HITLS_PKI_SUCCESS);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    /* Phase 1: Probe - count malloc calls during successful execution */
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_X509_CsrGenBuff(BSL_FORMAT_ASN1, csr, &encode), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    BSL_SAL_Free(encode.data);
    encode.data = NULL;
    encode.dataLen = 0;

    /* Phase 2: Test - iteratively fail each malloc */
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount - 1; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ASSERT_NE(HITLS_X509_CsrGenBuff(BSL_FORMAT_ASN1, testCsr, &encode), HITLS_PKI_SUCCESS);
    }
EXIT:
    TestRandDeInit();
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CsrFree(csr);
    HITLS_X509_CsrFree(testCsr);
    HITLS_X509_ExtFree(ext);
    HITLS_X509_ExtFree(testExt);
#else
    UnusedParam1(algId, hashId, curveId);
    SKIP_TEST();
#endif
}
/* END_CASE */

#if (defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_SLH_DSA) || \
    defined(HITLS_CRYPTO_COMPOSITE)) && \
    (defined(HITLS_PKI_X509_CSR_GEN) && defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_PKI_X509_CRL_GEN))
static int32_t GenKeyAndSelfCert(int32_t algId, int paraId, int mdId, CRYPT_EAL_PkeyCtx **key, HITLS_X509_Cert **cert)
{
    HITLS_X509_Cert *tmpCert = NULL;
    CRYPT_EAL_PkeyCtx *privKey = NULL;
    uint8_t serialNum[] = {0x01, 0x02, 0x03, 0x04};
    BSL_TIME beforeTime = {2024, 1, 1, 0, 0, 0, 1, 0};
    BSL_TIME afterTime = {2050, 12, 31, 23, 59, 59, 1, 0};
    uint8_t kid[20] = {0}; // SHA-1 hash for SKI
    HITLS_X509_ExtSki ski = {false, {kid, sizeof(kid)}};
    HITLS_X509_ExtBCons bCons = {true, true, -1}; // CA=true, maxPathLen=-1 (no limit)
    HITLS_X509_ExtKeyUsage ku = {true, HITLS_X509_EXT_KU_DIGITAL_SIGN | HITLS_X509_EXT_KU_KEY_CERT_SIGN};

    // Create private key context for the requested PQ/composite algorithm
    privKey = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_NE(privKey, NULL);

    // Set algorithm parameters
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(privKey, paraId), CRYPT_SUCCESS);

    // Generate key pair
    ASSERT_EQ(CRYPT_EAL_PkeyGen(privKey), CRYPT_SUCCESS);

    // Create new certificate
    tmpCert = HITLS_X509_CertNew();
    ASSERT_NE(tmpCert, NULL);

    // Set version (v3)
    int32_t version = HITLS_X509_VERSION_3;
    ASSERT_EQ(HITLS_X509_CertCtrl(tmpCert, HITLS_X509_SET_VERSION, &version, sizeof(int32_t)), HITLS_PKI_SUCCESS);

    // Set serial number
    ASSERT_EQ(HITLS_X509_CertCtrl(tmpCert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);

    // Set validity time
    ASSERT_EQ(HITLS_X509_CertCtrl(tmpCert, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(tmpCert, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)),
        HITLS_PKI_SUCCESS);

    // Set public key
    ASSERT_EQ(HITLS_X509_CertCtrl(tmpCert, HITLS_X509_SET_PUBKEY, privKey, 0), HITLS_PKI_SUCCESS);

    // Create and set subject DN: C=CN, O=Test, CN=test pqc root
    BslList *subjectDN = HITLS_X509_DnListNew();
    ASSERT_NE(subjectDN, NULL);
    HITLS_X509_DN dnCountry = {BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2};
    HITLS_X509_DN dnOrg = {BSL_CID_AT_ORGANIZATIONNAME, (uint8_t *)"Test", 4};
    HITLS_X509_DN dnCN = {BSL_CID_AT_COMMONNAME, (uint8_t *)"test pqc root", 14};
    ASSERT_EQ(HITLS_X509_AddDnName(subjectDN, &dnCountry, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(subjectDN, &dnOrg, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(subjectDN, &dnCN, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(tmpCert, HITLS_X509_SET_SUBJECT_DN, subjectDN, sizeof(BslList)), HITLS_PKI_SUCCESS);

    // Set issuer DN (same as subject for self-signed certificate)
    ASSERT_EQ(HITLS_X509_CertCtrl(tmpCert, HITLS_X509_SET_ISSUER_DN, subjectDN, sizeof(BslList)), HITLS_PKI_SUCCESS);

    // Generate SKI from public key (simplified - using a hash of public key)
    // In real implementation, this should use SHA-1 or SHA-256 hash of the public key
    // For now, we'll use a placeholder
    ASSERT_EQ(HITLS_X509_CertCtrl(tmpCert, HITLS_X509_EXT_SET_SKI, &ski, sizeof(HITLS_X509_ExtSki)), HITLS_PKI_SUCCESS);

    // Set Basic Constraints
    ASSERT_EQ(HITLS_X509_CertCtrl(tmpCert, HITLS_X509_EXT_SET_BCONS, &bCons, sizeof(HITLS_X509_ExtBCons)),
        HITLS_PKI_SUCCESS);

    // Set Key Usage
    ASSERT_EQ(HITLS_X509_CertCtrl(tmpCert, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage)),
        HITLS_PKI_SUCCESS);

    // Sign certificate (self-signed, using private key)
    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, NULL, tmpCert), HITLS_PKI_SUCCESS);
    HITLS_X509_DnListFree(subjectDN);
    *cert = tmpCert;
    *key = privKey;
    return 0;
EXIT:
    HITLS_X509_DnListFree(subjectDN);
    HITLS_X509_CertFree(tmpCert);
    CRYPT_EAL_PkeyFreeCtx(privKey);
    return -1;
}

static int32_t GenCrl(CRYPT_EAL_PkeyCtx *privKey, HITLS_X509_Cert *cert, int mdId, HITLS_X509_Crl **crl)
{
    HITLS_X509_Crl *tmpCrl = NULL;
    BslList *issuerDN = NULL;
    uint8_t serialNum[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t crlNumber[] = {0x01};
    BSL_TIME revokeTime = {2024, 6, 1, 0, 0, 0, 1, 0};
    BSL_TIME beforeTime = {2024, 1, 1, 0, 0, 0, 1, 0};
    BSL_TIME afterTime = {2050, 12, 31, 23, 59, 59, 1, 0};
    int32_t version = HITLS_X509_VERSION_2;
    HITLS_X509_RevokeExtReason reason = {true, HITLS_X509_REVOKED_REASON_KEY_COMPROMISE};
    HITLS_X509_ExtCrlNumber crlNumberExt = {false, {crlNumber, 1}};

    // Create new CRL
    tmpCrl = HITLS_X509_CrlNew();
    ASSERT_NE(tmpCrl, NULL);

    // Get issuer DN from certificate
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN, &issuerDN, sizeof(BslList *)), HITLS_PKI_SUCCESS);

    // Set CRL fields
    ASSERT_EQ(HITLS_X509_CrlCtrl(tmpCrl, HITLS_X509_SET_ISSUER_DN, issuerDN, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(tmpCrl, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(tmpCrl, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(tmpCrl, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);

    // Add a revoked certificate entry
    HITLS_X509_CrlEntry *entry = HITLS_X509_CrlEntryNew();
    ASSERT_NE(entry, NULL);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_SERIALNUM, serialNum, sizeof(serialNum)), 0);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME, &revokeTime, sizeof(BSL_TIME)), 0);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REASON, &reason,
        sizeof(HITLS_X509_RevokeExtReason)), 0);
    ASSERT_EQ(HITLS_X509_CrlCtrl(tmpCrl, HITLS_X509_CRL_ADD_REVOKED_CERT, entry, 0), 0);

    // Set CRL number extension
    ASSERT_EQ(HITLS_X509_CrlCtrl(tmpCrl, HITLS_X509_EXT_SET_CRLNUMBER, &crlNumberExt, sizeof(HITLS_X509_ExtCrlNumber)), 0);

    // Sign CRL
    ASSERT_EQ(HITLS_X509_CrlSign(mdId, privKey, NULL, tmpCrl), HITLS_PKI_SUCCESS);

    HITLS_X509_CrlEntryFree(entry);
    *crl = tmpCrl;
    return 0;
EXIT:
    HITLS_X509_CrlEntryFree(entry);
    HITLS_X509_CrlFree(tmpCrl);
    return -1;
}

static int32_t GenCsr(CRYPT_EAL_PkeyCtx *privKey, int mdId, HITLS_X509_Csr **csr)
{
    HITLS_X509_Csr *tmpCsr = NULL;

    // Create new CSR
    tmpCsr = HITLS_X509_CsrNew();
    ASSERT_NE(tmpCsr, NULL);

    // Set public key
    ASSERT_EQ(HITLS_X509_CsrCtrl(tmpCsr, HITLS_X509_SET_PUBKEY, privKey, 0), HITLS_PKI_SUCCESS);

    // Create and set subject DN: C=CN, O=Test, CN=test pqc end
    HITLS_X509_DN dnCountry = {BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2};
    HITLS_X509_DN dnOrg = {BSL_CID_AT_ORGANIZATIONNAME, (uint8_t *)"Test", 4};
    HITLS_X509_DN dnCN = {BSL_CID_AT_COMMONNAME, (uint8_t *)"test pqc end", 12};

    ASSERT_EQ(HITLS_X509_CsrCtrl(tmpCsr, HITLS_X509_ADD_SUBJECT_NAME, &dnCountry, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(tmpCsr, HITLS_X509_ADD_SUBJECT_NAME, &dnOrg, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(tmpCsr, HITLS_X509_ADD_SUBJECT_NAME, &dnCN, 1), HITLS_PKI_SUCCESS);

    // Sign CSR
    ASSERT_EQ(HITLS_X509_CsrSign(mdId, privKey, NULL, tmpCsr), HITLS_PKI_SUCCESS);

    *csr = tmpCsr;
    return 0;
EXIT:
    HITLS_X509_CsrFree(tmpCsr);
    return -1;
}
#endif

/* @
 * @test SDV_CRYPT_EAL_COMPOSITE_CERT_ROUNDTRIP_TC001
 * @spec -
 * @title Test Composite BC certificate samples support parse/encode/parse roundtrip.
 * @precon BC Composite root/leaf certificate samples are available in PEM.
 * @brief
 * 1.Parse BC Composite root and leaf certificates.
 * 2.Check Composite key/signature algorithm fields and key usage expectations.
 * 3.Verify root self-signature and leaf issuer signature.
 * 4.Re-encode PEM, compare with the original BC files, and parse again.
 * 5.Repeat the field and signature checks on the reparsed certificates.
 * @expect
 * 1.Root/leaf certificate parse and PEM roundtrip succeed.
 * 2.Composite paraId/signature algorithm/key usage remain unchanged.
 * 3.Signature verification succeeds before and after roundtrip.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_COMPOSITE_CERT_ROUNDTRIP_TC001(char *sampleDir, int expectParaId,
    int expectRootKeyUsage, int expectLeafKeyUsage)
{
#if !defined(HITLS_BSL_PEM) || !defined(HITLS_BSL_SAL_FILE) || \
    !defined(HITLS_PKI_X509_CRT_PARSE) || !defined(HITLS_PKI_X509_CRT_GEN)
    (void)sampleDir;
    (void)expectParaId;
    (void)expectRootKeyUsage;
    (void)expectLeafKeyUsage;
    SKIP_TEST();
#else
    if (PkiSkipTestByParaId(CRYPT_PKEY_COMPOSITE, expectParaId, BSL_FORMAT_PEM)) {
        SKIP_TEST();
    }

    char rootPath[COMPOSITE_SAMPLE_PATH_MAX] = {0};
    char leafPath[COMPOSITE_SAMPLE_PATH_MAX] = {0};
    BSL_Buffer rootFile = {0};
    BSL_Buffer leafFile = {0};
    BSL_Buffer rootEncode = {0};
    BSL_Buffer leafEncode = {0};
    HITLS_X509_Cert *rootCert = NULL;
    HITLS_X509_Cert *leafCert = NULL;
    HITLS_X509_Cert *rootParsed = NULL;
    HITLS_X509_Cert *leafParsed = NULL;

    TestMemInit();
    BSL_GLOBAL_Init();

    ASSERT_EQ(ReadCompositeSampleFile(sampleDir, "root_cert.pem", &rootFile, rootPath, sizeof(rootPath)), BSL_SUCCESS);
    ASSERT_EQ(ReadCompositeSampleFile(sampleDir, "leaf_cert.pem", &leafFile, leafPath, sizeof(leafPath)), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, rootPath, &rootCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, leafPath, &leafCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CheckCompositeCertFields(rootCert, expectParaId, expectRootKeyUsage), CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositeCertFields(leafCert, expectParaId, expectLeafKeyUsage), CRYPT_SUCCESS);
    ASSERT_EQ(HITLS_X509_CheckSignature(rootCert->tbs.ealPubKey, rootCert->tbs.tbsRawData,
        rootCert->tbs.tbsRawDataLen, &rootCert->signAlgId, &rootCert->signature), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CheckSignature(rootCert->tbs.ealPubKey, leafCert->tbs.tbsRawData,
        leafCert->tbs.tbsRawDataLen, &leafCert->signAlgId, &leafCert->signature), HITLS_PKI_SUCCESS);

    ASSERT_EQ(CheckParsedCompositeCertRoundTrip(rootCert, &rootFile, &rootEncode), CRYPT_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_PEM, &rootEncode, &rootParsed), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CheckCompositeCertFields(rootParsed, expectParaId, expectRootKeyUsage), CRYPT_SUCCESS);
    ASSERT_EQ(HITLS_X509_CheckSignature(rootParsed->tbs.ealPubKey, rootParsed->tbs.tbsRawData,
        rootParsed->tbs.tbsRawDataLen, &rootParsed->signAlgId, &rootParsed->signature), HITLS_PKI_SUCCESS);

    ASSERT_EQ(CheckParsedCompositeCertRoundTrip(leafCert, &leafFile, &leafEncode), CRYPT_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_PEM, &leafEncode, &leafParsed), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CheckCompositeCertFields(leafParsed, expectParaId, expectLeafKeyUsage), CRYPT_SUCCESS);
    ASSERT_EQ(HITLS_X509_CheckSignature(rootParsed->tbs.ealPubKey, leafParsed->tbs.tbsRawData,
        leafParsed->tbs.tbsRawDataLen, &leafParsed->signAlgId, &leafParsed->signature), HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_CertFree(leafParsed);
    HITLS_X509_CertFree(rootParsed);
    HITLS_X509_CertFree(leafCert);
    HITLS_X509_CertFree(rootCert);
    BSL_SAL_FREE(leafEncode.data);
    BSL_SAL_FREE(rootEncode.data);
    BSL_SAL_FREE(leafFile.data);
    BSL_SAL_FREE(rootFile.data);
    BSL_GLOBAL_DeInit();
#endif
}
/* END_CASE */

/* @
 * @test SDV_CRYPT_EAL_COMPOSITE_CSR_CRL_ROUNDTRIP_TC001
 * @spec -
 * @title Test Composite BC CSR and CRL samples support parse/encode/parse roundtrip.
 * @precon BC Composite root certificate, CSR, and CRL PEM samples are available.
 * @brief
 * 1.Parse the issuer root certificate, leaf CSR, and issuer CRL.
 * 2.Check Composite key/signature algorithm fields on CSR and CRL.
 * 3.Verify the CSR signature with its embedded public key and the CRL signature with the issuer public key.
 * 4.Re-encode CSR/CRL PEM, compare with the original BC files, and parse again.
 * 5.Repeat the field and signature checks on the reparsed CSR/CRL.
 * @expect
 * 1.CSR/CRL parse and PEM roundtrip succeed.
 * 2.Composite paraId/signature algorithm remain unchanged.
 * 3.Signature verification succeeds before and after roundtrip.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_COMPOSITE_CSR_CRL_ROUNDTRIP_TC001(char *sampleDir, int expectParaId)
{
#if !defined(HITLS_BSL_PEM) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_PKI_X509_CRT_PARSE) || \
    !defined(HITLS_PKI_X509_CSR_PARSE) || !defined(HITLS_PKI_X509_CSR_GEN) || \
    !defined(HITLS_PKI_X509_CRL_PARSE) || !defined(HITLS_PKI_X509_CRL_GEN)
    (void)sampleDir;
    (void)expectParaId;
    SKIP_TEST();
#else
    if (PkiSkipTestByParaId(CRYPT_PKEY_COMPOSITE, expectParaId, BSL_FORMAT_PEM)) {
        SKIP_TEST();
    }

    char rootPath[COMPOSITE_SAMPLE_PATH_MAX] = {0};
    char csrPath[COMPOSITE_SAMPLE_PATH_MAX] = {0};
    char crlPath[COMPOSITE_SAMPLE_PATH_MAX] = {0};
    BSL_Buffer csrFile = {0};
    BSL_Buffer crlFile = {0};
    BSL_Buffer csrEncode = {0};
    BSL_Buffer crlEncode = {0};
    HITLS_X509_Cert *rootCert = NULL;
    HITLS_X509_Csr *csr = NULL;
    HITLS_X509_Csr *csrParsed = NULL;
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Crl *crlParsed = NULL;

    TestMemInit();
    BSL_GLOBAL_Init();

    ASSERT_EQ(JoinCompositeSamplePath(rootPath, sizeof(rootPath), sampleDir, "root_cert.pem"), CRYPT_SUCCESS);
    ASSERT_EQ(ReadCompositeSampleFile(sampleDir, "leaf.csr.pem", &csrFile, csrPath, sizeof(csrPath)), BSL_SUCCESS);
    ASSERT_EQ(ReadCompositeSampleFile(sampleDir, "issuer.crl.pem", &crlFile, crlPath, sizeof(crlPath)), BSL_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, rootPath, &rootCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CheckCompositeDecodedKey(rootCert->tbs.ealPubKey, expectParaId), CRYPT_SUCCESS);

    ASSERT_EQ(HITLS_X509_CsrParseFile(BSL_FORMAT_PEM, csrPath, &csr), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CheckCompositeCsrFields(csr, expectParaId), CRYPT_SUCCESS);
    ASSERT_EQ(HITLS_X509_CheckSignature(csr->reqInfo.ealPubKey, csr->reqInfo.reqInfoRawData,
        csr->reqInfo.reqInfoRawDataLen, &csr->signAlgId, &csr->signature), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrVerify(csr), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CheckParsedCompositeCsrRoundTrip(csr, &csrFile, &csrEncode), CRYPT_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrParseBuff(BSL_FORMAT_PEM, &csrEncode, &csrParsed), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CheckCompositeCsrFields(csrParsed, expectParaId), CRYPT_SUCCESS);
    ASSERT_EQ(HITLS_X509_CheckSignature(csrParsed->reqInfo.ealPubKey, csrParsed->reqInfo.reqInfoRawData,
        csrParsed->reqInfo.reqInfoRawDataLen, &csrParsed->signAlgId, &csrParsed->signature), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrVerify(csrParsed), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, crlPath, &crl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CheckCompositeCrlFields(crl, expectParaId), CRYPT_SUCCESS);
    ASSERT_EQ(HITLS_X509_CheckSignature(rootCert->tbs.ealPubKey, crl->tbs.tbsRawData,
        crl->tbs.tbsRawDataLen, &crl->signAlgId, &crl->signature), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlVerify(rootCert->tbs.ealPubKey, crl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CheckParsedCompositeCrlRoundTrip(crl, &crlFile, &crlEncode), CRYPT_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlParseBuff(BSL_FORMAT_PEM, &crlEncode, &crlParsed), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CheckCompositeCrlFields(crlParsed, expectParaId), CRYPT_SUCCESS);
    ASSERT_EQ(HITLS_X509_CheckSignature(rootCert->tbs.ealPubKey, crlParsed->tbs.tbsRawData,
        crlParsed->tbs.tbsRawDataLen, &crlParsed->signAlgId, &crlParsed->signature), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlVerify(rootCert->tbs.ealPubKey, crlParsed), HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_CrlFree(crlParsed);
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CsrFree(csrParsed);
    HITLS_X509_CsrFree(csr);
    HITLS_X509_CertFree(rootCert);
    BSL_SAL_FREE(crlEncode.data);
    BSL_SAL_FREE(csrEncode.data);
    BSL_SAL_FREE(crlFile.data);
    BSL_SAL_FREE(csrFile.data);
    BSL_GLOBAL_DeInit();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_PQ_CERT_GEN_PKI_TC001(int algId, int paraId, int mdId, char *root, char *crl, char *csr)
{
#if (defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_SLH_DSA) || \
    defined(HITLS_CRYPTO_COMPOSITE)) && \
    (defined(HITLS_PKI_X509_CSR_GEN) && defined(HITLS_PKI_X509_CRT_GEN) && defined(HITLS_PKI_X509_CRL_GEN))
    if (PkiSkipTestByParaId(algId, paraId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    BSL_GLOBAL_Init();

    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *privKey = NULL;
    HITLS_X509_Crl *crlObj = NULL;
    HITLS_X509_Csr *csrObj = NULL;
    HITLS_X509_Cert *pcert = NULL;
    HITLS_X509_Crl *pcrl = NULL;
    HITLS_X509_Csr *pcsr = NULL;

    // 1. Generate key and self-signed certificate
    ASSERT_EQ(GenKeyAndSelfCert(algId, paraId, mdId, &privKey, &cert), 0);

    // 2. Generate CRL using the key and self-signed certificate
    ASSERT_EQ(GenCrl(privKey, cert, mdId, &crlObj), 0);

    // 3. Generate CSR with subject name: C=CN, O=Test, CN=test pqc end
    ASSERT_EQ(GenCsr(privKey, mdId, &csrObj), 0);

    // 4. Encode and output self-signed certificate to file
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, root), HITLS_PKI_SUCCESS);

    // 5. Encode and output CSR to file
    ASSERT_EQ(HITLS_X509_CsrGenFile(BSL_FORMAT_ASN1, csrObj, csr), HITLS_PKI_SUCCESS);

    // 6. Encode and output CRL to file
    ASSERT_EQ(HITLS_X509_CrlGenFile(BSL_FORMAT_ASN1, crlObj, crl), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, root, &pcert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrParseFile(BSL_FORMAT_ASN1, csr, &pcsr), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, crl, &pcrl), HITLS_PKI_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pcert->tbs.ealPubKey, mdId, pcert->tbs.tbsRawData, pcert->tbs.tbsRawDataLen,
        pcert->signature.buff, pcert->signature.len), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pcert->tbs.ealPubKey, mdId, pcsr->reqInfo.reqInfoRawData,
        pcsr->reqInfo.reqInfoRawDataLen, pcsr->signature.buff, pcsr->signature.len), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pcert->tbs.ealPubKey, mdId, pcrl->tbs.tbsRawData, pcrl->tbs.tbsRawDataLen,
        pcrl->signature.buff, pcrl->signature.len), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertVerifyByPubKey(pcert, pcert->tbs.ealPubKey), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlVerify(pcert->tbs.ealPubKey, pcrl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrVerify(pcsr), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CheckSignature(pcert->tbs.ealPubKey, pcert->tbs.tbsRawData, pcert->tbs.tbsRawDataLen,
        &(pcert->signAlgId), &(pcert->signature)), HITLS_PKI_SUCCESS);
    remove(root);
    remove(crl);
    remove(csr);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
    CRYPT_EAL_PkeyFreeCtx(privKey);
    HITLS_X509_CrlFree(crlObj);
    HITLS_X509_CsrFree(csrObj);
    HITLS_X509_CertFree(pcert);
    HITLS_X509_CrlFree(pcrl);
    HITLS_X509_CsrFree(pcsr);
    BSL_GLOBAL_DeInit();
    TestRandDeInit();
#else
    (void)algId;
    (void)paraId;
    (void)mdId;
    (void)root;
    (void)crl;
    (void)csr;
    SKIP_TEST();
#endif
}
/* END_CASE */

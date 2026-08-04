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
#include <string.h>
#include "bsl_sal.h"
#include "sal_file.h"
#include "bsl_err.h"
#include "bsl_init.h"
#include "crypt_errno.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"
#include "crypt_util_rand.h"
#include "bsl_params.h"
#include "composite_local.h"
#include "eal_pkey_local.h"
#include "crypt_eal_codecs.h"
#include "crypt_codecskey.h"
#include "crypt_params_key.h"
#include "bsl_pem_internal.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_csr.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_types.h"
#include "hitls_cert_local.h"
#include "hitls_csr_local.h"
#include "hitls_crl_local.h"
#include "hitls_x509_local.h"
#include "stub_utils.h"
/* END_HEADER */

STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);

#define COMPOSITE_SAMPLE_PATH_MAX 512U
#define COMPOSITE_SHA256_LEN 32U

static uint32_t g_compositeDetRandState = 0;

static void CompositeDetRandReset(void)
{
    g_compositeDetRandState = 0x6A09E667u;
}

static int32_t CompositeDetRandFill(uint8_t *randNum, uint32_t randLen)
{
    if (randNum == NULL) {
        return CRYPT_NULL_INPUT;
    }

    for (uint32_t i = 0; i < randLen; i++) {
        g_compositeDetRandState ^= g_compositeDetRandState << 13;
        g_compositeDetRandState ^= g_compositeDetRandState >> 17;
        g_compositeDetRandState ^= g_compositeDetRandState << 5;
        randNum[i] = (uint8_t)(g_compositeDetRandState >> 24);
    }

    return CRYPT_SUCCESS;
}

static int32_t CompositeDetRand(uint8_t *randNum, uint32_t randLen)
{
    return CompositeDetRandFill(randNum, randLen);
}

static int32_t CompositeDetRandEx(void *libCtx, uint8_t *randNum, uint32_t randLen)
{
    (void)libCtx;
    return CompositeDetRandFill(randNum, randLen);
}

static CRYPT_MD_AlgId GetCompositeHashAlgId(int type)
{
    switch (type) {
        case CRYPT_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256:
        case CRYPT_COMPOSITE_MLDSA44_RSA2048_PKCS15_SHA256:
        case CRYPT_COMPOSITE_MLDSA44_ECDSA_P256_SHA256:
            return CRYPT_MD_SHA256;
        case CRYPT_COMPOSITE_MLDSA44_ED25519_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_RSA3072_PSS_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_RSA3072_PKCS15_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_RSA4096_PSS_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_RSA4096_PKCS15_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_ECDSA_P256_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_ECDSA_P384_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_ECDSA_BRAINPOOLP256R1_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_ED25519_SHA512:
        case CRYPT_COMPOSITE_MLDSA87_ECDSA_P384_SHA512:
        case CRYPT_COMPOSITE_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512:
        case CRYPT_COMPOSITE_MLDSA87_RSA3072_PSS_SHA512:
        case CRYPT_COMPOSITE_MLDSA87_RSA4096_PSS_SHA512:
        case CRYPT_COMPOSITE_MLDSA87_ECDSA_P521_SHA512:
            return CRYPT_MD_SHA512;
        default:
            return CRYPT_MD_MAX;
    }
}

static uint32_t GetCompositeExpectedSecBits(int type)
{
    switch (type) {
        case CRYPT_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256:
        case CRYPT_COMPOSITE_MLDSA44_RSA2048_PKCS15_SHA256:
            return 112;
        case CRYPT_COMPOSITE_MLDSA44_ED25519_SHA512:
        case CRYPT_COMPOSITE_MLDSA44_ECDSA_P256_SHA256:
            return 128;
        case CRYPT_COMPOSITE_MLDSA65_RSA3072_PSS_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_RSA3072_PKCS15_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_RSA4096_PSS_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_RSA4096_PKCS15_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_ECDSA_P256_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_ECDSA_BRAINPOOLP256R1_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_ED25519_SHA512:
        case CRYPT_COMPOSITE_MLDSA87_RSA3072_PSS_SHA512:
        case CRYPT_COMPOSITE_MLDSA87_RSA4096_PSS_SHA512:
            return 128;
        case CRYPT_COMPOSITE_MLDSA65_ECDSA_P384_SHA512:
        case CRYPT_COMPOSITE_MLDSA87_ECDSA_P384_SHA512:
        case CRYPT_COMPOSITE_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512:
            return 192;
        case CRYPT_COMPOSITE_MLDSA87_ECDSA_P521_SHA512:
            return 256;
        default:
            return 0;
    }
}

static int32_t ExportCompositePubKey(CRYPT_EAL_PkeyCtx *ctx, CRYPT_EAL_PkeyPub *pub)
{
    int32_t ret;

    pub->id = CRYPT_PKEY_COMPOSITE;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &pub->key.compositePub.len,
        sizeof(pub->key.compositePub.len));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    pub->key.compositePub.data = BSL_SAL_Malloc(pub->key.compositePub.len);
    if (pub->key.compositePub.data == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeyGetPub(ctx, pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(pub->key.compositePub.data);
        pub->key.compositePub.data = NULL;
    }
    return ret;
}

static int32_t ExportCompositePrvKey(CRYPT_EAL_PkeyCtx *ctx, CRYPT_EAL_PkeyPrv *prv)
{
    int32_t ret;

    prv->id = CRYPT_PKEY_COMPOSITE;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &prv->key.compositePrv.len,
        sizeof(prv->key.compositePrv.len));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    prv->key.compositePrv.data = BSL_SAL_Malloc(prv->key.compositePrv.len);
    if (prv->key.compositePrv.data == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeyGetPrv(ctx, prv);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(prv->key.compositePrv.data);
        prv->key.compositePrv.data = NULL;
    }
    return ret;
}

static int32_t BuildCompositePubKeyWithEmptyRsaN(const CRYPT_EAL_PkeyCtx *ctx,
    const CRYPT_EAL_PkeyPub *srcPub, CRYPT_EAL_PkeyPub *badPub)
{
    static const uint8_t badRsaPub[] = {
        0x30, 0x07,
        0x02, 0x00,
        0x02, 0x03, 0x01, 0x00, 0x01
    };
    const CRYPT_CompositeCtx *composite = NULL;
    uint32_t pqcPubkeyLen;

    composite = (const CRYPT_CompositeCtx *)ctx->key;
    pqcPubkeyLen = composite->info->pqcPubkeyLen;
    badPub->id = CRYPT_PKEY_COMPOSITE;
    badPub->key.compositePub.len = pqcPubkeyLen + sizeof(badRsaPub);
    badPub->key.compositePub.data = BSL_SAL_Malloc(badPub->key.compositePub.len);
    if (badPub->key.compositePub.data == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    (void)memcpy(badPub->key.compositePub.data, srcPub->key.compositePub.data, pqcPubkeyLen);
    (void)memcpy(badPub->key.compositePub.data + pqcPubkeyLen, badRsaPub, sizeof(badRsaPub));
    return CRYPT_SUCCESS;
}

static int32_t CloneCompositePubKey(const CRYPT_EAL_PkeyPub *srcPub, CRYPT_EAL_PkeyPub *dstPub)
{
    dstPub->id = CRYPT_PKEY_COMPOSITE;
    dstPub->key.compositePub.len = srcPub->key.compositePub.len;
    dstPub->key.compositePub.data = BSL_SAL_Malloc(dstPub->key.compositePub.len);
    if (dstPub->key.compositePub.data == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memcpy(dstPub->key.compositePub.data, srcPub->key.compositePub.data, dstPub->key.compositePub.len);
    return CRYPT_SUCCESS;
}

#if defined(HITLS_CRYPTO_CODECSKEY) && defined(HITLS_BSL_SAL_FILE) && \
    defined(HITLS_CRYPTO_KEY_DECODE) && defined(HITLS_CRYPTO_KEY_ENCODE)
static uint32_t DecodeCompositeDerLen(const uint8_t *data, uint32_t *offset)
{
    uint8_t first;
    uint32_t lenBytes;
    uint32_t value = 0;

    first = data[(*offset)++];
    if ((first & 0x80U) == 0U) {
        return first;
    }

    lenBytes = first & 0x7FU;
    for (uint32_t i = 0; i < lenBytes; i++) {
        value = (value << 8) | data[(*offset)++];
    }
    return value;
}

static uint8_t GetCompositeDerTradPointTag(const BSL_Buffer *der, uint32_t pqcPubkeyLen)
{
    uint32_t offset = 1;

    (void)DecodeCompositeDerLen(der->data, &offset); /* Skip outer SubjectPublicKeyInfo SEQUENCE length. */
    offset++;
    offset += DecodeCompositeDerLen(der->data, &offset); /* Skip AlgorithmIdentifier SEQUENCE length. */
    offset++;
    (void)DecodeCompositeDerLen(der->data, &offset); /* Skip subjectPublicKey BIT STRING length. */
    offset++;
    return der->data[offset + pqcPubkeyLen];
}
#endif

static int32_t CloneCompositePrvKey(const CRYPT_EAL_PkeyPrv *srcPrv, CRYPT_EAL_PkeyPrv *dstPrv)
{
    dstPrv->id = CRYPT_PKEY_COMPOSITE;
    dstPrv->key.compositePrv.len = srcPrv->key.compositePrv.len;
    dstPrv->key.compositePrv.data = BSL_SAL_Malloc(dstPrv->key.compositePrv.len);
    if (dstPrv->key.compositePrv.data == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memcpy(dstPrv->key.compositePrv.data, srcPrv->key.compositePrv.data, dstPrv->key.compositePrv.len);
    return CRYPT_SUCCESS;
}

#ifdef HITLS_BSL_PARAMS
static int32_t InitCompositeOctetsParam(BSL_Param *params, int32_t key, uint8_t *data, uint32_t dataLen)
{
    int32_t ret = BSL_PARAM_InitValue(&params[0], key, BSL_PARAM_TYPE_OCTETS, data, dataLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    params[1] = (BSL_Param)BSL_PARAM_END;
    return CRYPT_SUCCESS;
}
#endif

#if (defined(HITLS_CRYPTO_CODECSKEY) && defined(HITLS_BSL_SAL_FILE) && defined(HITLS_CRYPTO_KEY_DECODE)) || \
    (defined(HITLS_BSL_PEM) && defined(HITLS_BSL_SAL_FILE) && defined(HITLS_PKI_X509))
static int32_t CheckCompositeDecodedKey(CRYPT_EAL_PkeyCtx *key, int32_t expectParaId)
{
    ASSERT_EQ(CRYPT_EAL_PkeyGetId(key), CRYPT_PKEY_COMPOSITE);
    ASSERT_EQ(CRYPT_EAL_PkeyGetParaId(key), expectParaId);
    return CRYPT_SUCCESS;
EXIT:
    return -1;
}
#endif

#if (defined(HITLS_CRYPTO_CODECSKEY) && defined(HITLS_BSL_SAL_FILE) && defined(HITLS_CRYPTO_KEY_DECODE)) || \
    (defined(HITLS_BSL_PEM) && defined(HITLS_BSL_SAL_FILE) && defined(HITLS_PKI_X509))
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
#endif

#if defined(HITLS_CRYPTO_CODECSKEY) && defined(HITLS_BSL_SAL_FILE) && \
    defined(HITLS_CRYPTO_KEY_DECODE) && defined(HITLS_CRYPTO_KEY_ENCODE)
static int32_t CheckSha256Hex(const char *log, const uint8_t *data, uint32_t dataLen, Hex *expectDigest)
{
    uint8_t digest[COMPOSITE_SHA256_LEN] = {0};
    uint32_t digestLen = sizeof(digest);

    ASSERT_EQ(expectDigest->len, COMPOSITE_SHA256_LEN);
    ASSERT_EQ(CRYPT_EAL_Md(CRYPT_MD_SHA256, data, dataLen, digest, &digestLen), CRYPT_SUCCESS);
    ASSERT_EQ(digestLen, COMPOSITE_SHA256_LEN);
    ASSERT_COMPARE(log, digest, digestLen, expectDigest->x, expectDigest->len);
    return CRYPT_SUCCESS;
EXIT:
    return -1;
}

static int32_t CheckCompositePubRawSha256(CRYPT_EAL_PkeyCtx *key, Hex *expectDigest)
{
    CRYPT_EAL_PkeyPub pub = {0};

    ASSERT_EQ(ExportCompositePubKey(key, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CheckSha256Hex("composite pub raw sha256", pub.key.compositePub.data,
        pub.key.compositePub.len, expectDigest), CRYPT_SUCCESS);
    BSL_SAL_Free(pub.key.compositePub.data);
    return CRYPT_SUCCESS;
EXIT:
    BSL_SAL_Free(pub.key.compositePub.data);
    return -1;
}

static int32_t CheckCompositePrvRawSha256(CRYPT_EAL_PkeyCtx *key, Hex *expectDigest)
{
    CRYPT_EAL_PkeyPrv prv = {0};

    ASSERT_EQ(ExportCompositePrvKey(key, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CheckSha256Hex("composite prv raw sha256", prv.key.compositePrv.data,
        prv.key.compositePrv.len, expectDigest), CRYPT_SUCCESS);
    BSL_SAL_ClearFree(prv.key.compositePrv.data, prv.key.compositePrv.len);
    return CRYPT_SUCCESS;
EXIT:
    BSL_SAL_ClearFree(prv.key.compositePrv.data, prv.key.compositePrv.len);
    return -1;
}
#endif

#if defined(HITLS_BSL_PEM) && defined(HITLS_BSL_SAL_FILE) && defined(HITLS_PKI_X509)
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

static int32_t CheckCompositeCrlFields(HITLS_X509_Crl *crl, int32_t expectParaId)
{
    ASSERT_EQ(crl->signAlgId.algId, expectParaId);
    ASSERT_EQ(crl->tbs.signAlgId.algId, expectParaId);
    return CRYPT_SUCCESS;
EXIT:
    return -1;
}
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

static bool PkiSkipCompositeParaTest(int32_t paraId)
{
#ifndef HITLS_CRYPTO_COMPOSITE
    (void)paraId;
    return true;
#else
    switch (paraId) {
#if defined(HITLS_CRYPTO_RSA) && defined(HITLS_CRYPTO_RSA_EMSA_PSS)
        case CRYPT_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256:
        case CRYPT_COMPOSITE_MLDSA65_RSA3072_PSS_SHA512:
        case CRYPT_COMPOSITE_MLDSA65_RSA4096_PSS_SHA512:
        case CRYPT_COMPOSITE_MLDSA87_RSA3072_PSS_SHA512:
        case CRYPT_COMPOSITE_MLDSA87_RSA4096_PSS_SHA512:
            return false;
#endif
#if defined(HITLS_CRYPTO_RSA) && defined(HITLS_CRYPTO_RSA_EMSA_PKCSV15)
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

/* @
 * @test SDV_CRYPTO_COMPOSITE_API_TC001
 * @spec -
 * @title Test Composite ML-DSA API: context, key generation, and key I/O.
 * @precon nan
 * @brief
 * 1.Create two contexts (ctxA, ctxB).
 * 2.Set parameters by ID, including error test.
 * 3.Generate keys for ctxA.
 * 4.Export keys from ctxA (GetPub/GetPrv).
 * 5.Import keys into ctxB (SetPub/SetPrv).
 * @expect
 * 1.Contexts and key operations succeed.
 * 2.Key I/O is successful.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_API_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctxA = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    CRYPT_EAL_PkeyCtx *ctxB = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    int32_t val = CRYPT_PKEY_PARAID_MAX;
    ASSERT_TRUE(ctxA != NULL);
    ASSERT_TRUE(ctxB != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxA, val), CRYPT_INVALID_ARG);
    val = (int32_t)type;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxA, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxB, val), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctxA), CRYPT_SUCCESS);

    uint32_t pubKeyLen = 0;
    uint32_t prvKeyLen = 0;
    uint32_t secBits = GetCompositeExpectedSecBits(type);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen)),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctxA, CRYPT_CTRL_GET_PRVKEY_LEN, &prvKeyLen, sizeof(prvKeyLen)),
        CRYPT_SUCCESS);
    ASSERT_TRUE(secBits != 0);
    ASSERT_EQ(CRYPT_EAL_PkeyGetSecurityBits(ctxA), secBits);

    CRYPT_EAL_PkeyPub pk = { 0 };
    pk.id = CRYPT_PKEY_COMPOSITE;
    pk.key.compositePub.len = pubKeyLen;
    pk.key.compositePub.data = BSL_SAL_Malloc(pubKeyLen);
    ASSERT_TRUE(pk.key.compositePub.data != NULL);
    
    CRYPT_EAL_PkeyPrv sk = { 0 };
    sk.id = CRYPT_PKEY_COMPOSITE;
    sk.key.compositePrv.len = prvKeyLen;
    sk.key.compositePrv.data = BSL_SAL_Malloc(prvKeyLen);
    ASSERT_TRUE(sk.key.compositePrv.data != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctxA, &pk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctxA, &sk), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctxB, &pk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctxB, &sk), CRYPT_SUCCESS);
EXIT:

    BSL_SAL_Free(pk.key.compositePub.data);
    BSL_SAL_Free(sk.key.compositePrv.data);
    CRYPT_EAL_PkeyFreeCtx(ctxA);
    CRYPT_EAL_PkeyFreeCtx(ctxB);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_GENKEY_ATOMIC_TC001
 * @spec -
 * @title Test Composite GenKey failure under deterministic malloc injection.
 * @precon nan
 * @brief
 * 1.Register a deterministic random stream, then create sign and verify contexts and set parameters.
 * 2.Run one successful GenKey to collect the total malloc count for one generation attempt.
 * 3.Create a fresh Composite context for each malloc-failure injection and call GenKey once.
 * 4.Discard the failed context directly instead of reusing it.
 * @expect
 * 1.Every injected malloc failure makes the current GenKey attempt fail.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_GENKEY_ATOMIC_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    CRYPT_RandRegist(CompositeDetRand);
    CRYPT_RandRegistEx(CompositeDetRandEx);
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    uint32_t totalMallocCount = 0;

    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    /* This successful run is only used to measure the malloc footprint of one GenKey attempt. */
    CompositeDetRandReset();
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    ASSERT_TRUE(totalMallocCount > 0);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    ctx = NULL;

    for (uint32_t i = 0; i < totalMallocCount; i++) {
        ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
        ASSERT_TRUE(ctx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);

        CompositeDetRandReset();
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        STUB_EnableMallocFail(true);
        ASSERT_NE(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
        STUB_EnableMallocFail(false);
        CRYPT_EAL_PkeyFreeCtx(ctx);
        ctx = NULL;
    }
EXIT:
    STUB_EnableMallocFail(false);
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_SIGN_ATOMIC_TC001
 * @spec -
 * @title Test Composite sign failure keeps caller output unchanged with deterministic randomness.
 * @precon nan
 * @brief
 * 1.Register a deterministic random stream, then create a context, set parameters, and generate a keypair.
 * 2.Pre-hash a message and prepare a caller-owned signature buffer.
 * 3.Reset the deterministic stream and verify a too-short output buffer fails without changing the buffer or signLen.
 * 4.Run one successful warm-up SignData to initialize reusable signing state such as RSA blinding.
 * 5.Reset the deterministic stream for one successful SignData to collect total malloc count on the warmed context.
 * 6.Reset the deterministic stream before each malloc-failure injection of SignData.
 * 7.Verify every failed sign leaves the caller buffer and signLen unchanged.
 * 8.Verify the context still signs and verifies successfully afterwards.
 * @expect
 * 1.SignData failure never leaks partial signature bytes into the caller buffer.
 * 2.signLen remains unchanged on failure.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_SIGN_ATOMIC_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    CRYPT_RandRegist(CompositeDetRand);
    CRYPT_RandRegistEx(CompositeDetRandEx);
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    uint8_t *sign = NULL;
    uint8_t *baseline = NULL;
    uint8_t msg[] = "composite sign atomicity";
    uint8_t digest[64] = {0};
    uint32_t digestLen = sizeof(digest);
    uint32_t signLen = 0;
    uint32_t totalMallocCount = 0;

    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    CompositeDetRandReset();
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);

    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);
    ASSERT_EQ(CRYPT_EAL_Md(mdId, msg, sizeof(msg) - 1, digest, &digestLen), CRYPT_SUCCESS);

    signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_TRUE(signLen > 1);
    sign = BSL_SAL_Malloc(signLen);
    baseline = BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(sign != NULL);
    ASSERT_TRUE(baseline != NULL);
    (void)memset(sign, 0xA5, signLen);
    (void)memset(baseline, 0xA5, signLen);

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);

    uint32_t shortSignLen = signLen - 1;
    CompositeDetRandReset();
    ASSERT_NE(CRYPT_EAL_PkeySignData(ctx, digest, digestLen, sign, &shortSignLen), CRYPT_SUCCESS);
    ASSERT_EQ(shortSignLen, signLen - 1);
    ASSERT_COMPARE("sign unchanged after short buffer fail", sign, signLen, baseline, signLen);

    /* Warm up lazy state such as RSA blinding so counted mallocs match repeated signing on the same ctx. */
    uint32_t warmupSignLen = signLen;
    CompositeDetRandReset();
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ctx, digest, digestLen, sign, &warmupSignLen), CRYPT_SUCCESS);

    STUB_ResetMallocCount();
    uint32_t curSignLen = signLen;
    CompositeDetRandReset();
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ctx, digest, digestLen, sign, &curSignLen), CRYPT_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    ASSERT_TRUE(totalMallocCount > 0);

    for (uint32_t i = 0; i < totalMallocCount; i++) {
        (void)memset(sign, 0xA5, signLen);
        curSignLen = signLen;

        CompositeDetRandReset();
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        STUB_EnableMallocFail(true);
        ASSERT_NE(CRYPT_EAL_PkeySignData(ctx, digest, digestLen, sign, &curSignLen), CRYPT_SUCCESS);
        STUB_EnableMallocFail(false);

        ASSERT_EQ(curSignLen, signLen);
        ASSERT_COMPARE("sign unchanged after sign fail", sign, signLen, baseline, signLen);
    }

    curSignLen = signLen;
    CompositeDetRandReset();
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ctx, digest, digestLen, sign, &curSignLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(ctx, digest, digestLen, sign, curSignLen), CRYPT_SUCCESS);

EXIT:
    STUB_EnableMallocFail(false);
    STUB_RESTORE(BSL_SAL_Malloc);
    BSL_SAL_Free(baseline);
    BSL_SAL_Free(sign);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_SET_CTX_INFO_ATOMIC_TC001
 * @spec -
 * @title Test Composite SetCtxInfo failure keeps the previous context unchanged.
 * @precon nan
 * @brief
 * 1.Create sign and verify contexts, set parameters, generate a keypair, and import the public key.
 * 2.Set the same initial ctxInfo on both contexts and generate one signature.
 * 3.Inject malloc failure into verifyCtx SetCtxInfo when updating to a different ctxInfo.
 * 4.Verify the old signature still succeeds after the failed update.
 * 5.Apply the new ctxInfo successfully and verify the old signature no longer matches.
 * @expect
 * 1.Failed SetCtxInfo keeps the previous ctxInfo unchanged.
 * 2.Successful SetCtxInfo replaces the previous ctxInfo.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_SET_CTX_INFO_ATOMIC_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    static const uint8_t oldCtxInfo[] = "ctx-old";
    static const uint8_t newCtxInfo[] = "ctx-new";
    static const uint8_t msg[] = "composite ctx info atomicity";
    CRYPT_EAL_PkeyCtx *signCtx = NULL;
    CRYPT_EAL_PkeyCtx *verifyCtx = NULL;
    CRYPT_EAL_PkeyPub pubKey = {0};
    uint8_t *sign = NULL;
    uint32_t signLen = 0;
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);

    TestMemInit();
    TestRandInit();

    signCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    verifyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(signCtx != NULL);
    ASSERT_TRUE(verifyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(signCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(verifyCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(signCtx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(signCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubKey.key.compositePub.len,
        sizeof(pubKey.key.compositePub.len)), CRYPT_SUCCESS);
    pubKey.id = CRYPT_PKEY_COMPOSITE;
    pubKey.key.compositePub.data = BSL_SAL_Malloc(pubKey.key.compositePub.len);
    ASSERT_TRUE(pubKey.key.compositePub.data != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(signCtx, &pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(verifyCtx, &pubKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(signCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)oldCtxInfo,
        (uint32_t)(sizeof(oldCtxInfo) - 1)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)oldCtxInfo,
        (uint32_t)(sizeof(oldCtxInfo) - 1)), CRYPT_SUCCESS);

    signLen = CRYPT_EAL_PkeyGetSignLen(signCtx);
    ASSERT_TRUE(signLen > 0);
    sign = BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(sign != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(signCtx, mdId, msg, sizeof(msg) - 1, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(verifyCtx, mdId, msg, sizeof(msg) - 1, sign, signLen), CRYPT_SUCCESS);

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_ResetMallocCount();
    STUB_SetMallocFailIndex(0);
    STUB_EnableMallocFail(true);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)newCtxInfo,
        (uint32_t)(sizeof(newCtxInfo) - 1)), CRYPT_MEM_ALLOC_FAIL);
    STUB_EnableMallocFail(false);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(verifyCtx, mdId, msg, sizeof(msg) - 1, sign, signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)newCtxInfo,
        (uint32_t)(sizeof(newCtxInfo) - 1)), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeyVerify(verifyCtx, mdId, msg, sizeof(msg) - 1, sign, signLen), CRYPT_SUCCESS);

EXIT:
    STUB_EnableMallocFail(false);
    STUB_RESTORE(BSL_SAL_Malloc);
    BSL_SAL_Free(sign);
    BSL_SAL_Free(pubKey.key.compositePub.data);
    CRYPT_EAL_PkeyFreeCtx(verifyCtx);
    CRYPT_EAL_PkeyFreeCtx(signCtx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_SIGN_TC001
 * @spec -
 * @title Test Composite ML-DSA signature and verification.
 * @precon Private and public key data is available.
 * @brief
 * 1.Create context and set parameters.
 * 2.Set the private key.
 * 3.Call the signature interface.
 * 4.Set the public key.
 * 5.Call the verification interface.
 * @expect
 * 1.Signature operation succeeds.
 * 2.Verification operation succeeds.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_SIGN_TC001(int type, Hex *ctxText, Hex *testPrvKey, Hex *testPubKey, Hex *msg)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);
    CRYPT_MD_AlgId wrongMdId = (mdId == CRYPT_MD_SHA256) ? CRYPT_MD_SHA512 : CRYPT_MD_SHA256;
    uint8_t *out = NULL;
    uint8_t *outWithCtx = NULL;
    uint8_t *outFromHash = NULL;
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);

    uint32_t val = (uint32_t)type;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv prvKey = { 0 };
    prvKey.id = CRYPT_PKEY_COMPOSITE;
    prvKey.key.compositePrv.data = testPrvKey->x;
    prvKey.key.compositePrv.len = testPrvKey->len;
    ret = CRYPT_EAL_PkeySetPrv(ctx, &prvKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t outLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    out = BSL_SAL_Malloc(outLen);
    ASSERT_TRUE(out != NULL);

    ret = CRYPT_EAL_PkeySign(ctx, mdId, msg->x, msg->len, out, &outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    
    CRYPT_EAL_PkeyPub pubKey = { 0 };
    pubKey.id = CRYPT_PKEY_COMPOSITE;
    pubKey.key.compositePub.data = testPubKey->x;
    pubKey.key.compositePub.len = testPubKey->len;
    ret = CRYPT_EAL_PkeySetPub(ctx, &pubKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(ctx, mdId, msg->x, msg->len, out, outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    uint32_t wrongOutLen = outLen;
    ret = CRYPT_EAL_PkeySign(ctx, wrongMdId, msg->x, msg->len, out, &wrongOutLen);
    ASSERT_EQ(ret, CRYPT_INVALID_ARG);
    ret = CRYPT_EAL_PkeyVerify(ctx, wrongMdId, msg->x, msg->len, out, outLen);
    ASSERT_EQ(ret, CRYPT_INVALID_ARG);

    uint32_t outLenWithCtx = CRYPT_EAL_PkeyGetSignLen(ctx);
    outWithCtx = BSL_SAL_Malloc(outLenWithCtx);
    ASSERT_TRUE(outWithCtx != NULL);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_CTX_INFO, ctxText->x, ctxText->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeySign(ctx, mdId, msg->x, msg->len, outWithCtx, &outLenWithCtx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(ctx, mdId, msg->x, msg->len, outWithCtx, outLenWithCtx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    uint8_t digest[64] = {0};
    uint32_t digestLen = sizeof(digest);
    ASSERT_EQ(CRYPT_EAL_Md(mdId, msg->x, msg->len, digest, &digestLen), CRYPT_SUCCESS);

    uint32_t outFromHashLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    outFromHash = BSL_SAL_Malloc(outFromHashLen);
    ASSERT_TRUE(outFromHash != NULL);
    ret = CRYPT_EAL_PkeySignData(ctx, digest, digestLen, outFromHash, &outFromHashLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerifyData(ctx, digest, digestLen, outFromHash, outFromHashLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(out);
    BSL_SAL_Free(outWithCtx);
    BSL_SAL_Free(outFromHash);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_VERIFY_TC001
 * @spec -
 * @title Test Composite ML-DSA signature verification with pre-generated signature.
 * @precon Public key, message, and signature data is available.
 * @brief
 * 1.Create context and set parameters.
 * 2.Set the public key.
 * 3.Call the verification interface with message and signature.
 * @expect
 * 1.Verification operation succeeds.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_VERIFY_TC001(int type, Hex *ctxText, Hex *testPubKey, Hex *msg, Hex *sign, Hex *signWithCtx)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);

    uint32_t val = (uint32_t)type;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pubKey = { 0 };
    pubKey.id = CRYPT_PKEY_COMPOSITE;
    pubKey.key.compositePub.data = testPubKey->x;
    pubKey.key.compositePub.len = testPubKey->len;
    ret = CRYPT_EAL_PkeySetPub(ctx, &pubKey);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(ctx, mdId, msg->x, msg->len, sign->x, sign->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_CTX_INFO, ctxText->x, ctxText->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(ctx, mdId, msg->x, msg->len, signWithCtx->x, signWithCtx->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_IMPORT_ASN1_NEGATIVE_TC001
 * @spec -
 * @title Test Composite ASN.1 key decode negative samples reject invalid public/private inputs.
 * @precon nan
 * @brief
 * 1.Decode one prebuilt Composite DER public-key sample and one private-key sample.
 * 2.Verify the public/private decode paths reject the negative samples with the expected return codes.
 * @expect
 * 1.Public/private key decode return the configured expected error codes.
 * 2.No usable key context is produced on failure.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_IMPORT_ASN1_NEGATIVE_TC001(int type, char *pubKeyPath, char *prvKeyPath,
    int expectedPubRet, int expectedPrvRet)
{
#if !defined(HITLS_CRYPTO_CODECSKEY) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_KEY_DECODE)
    (void)type;
    (void)pubKeyPath;
    (void)prvKeyPath;
    (void)expectedPubRet;
    (void)expectedPrvRet;
    SKIP_TEST();
#else
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    (void)type;

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, pubKeyPath, NULL, 0, &pubCtx),
        expectedPubRet);
    ASSERT_EQ(pubCtx, NULL);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, prvKeyPath, NULL, 0, &prvCtx),
        expectedPrvRet);
    ASSERT_EQ(prvCtx, NULL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
#endif
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_IMPORT_ASN1_NON_F4_TC001
 * @spec -
 * @title Test Composite ASN.1 key decode accepts RSA public/private keys whose exponent is not 65537.
 * @precon nan
 * @brief
 * 1.Decode one prebuilt Composite DER public key and one private key whose inner RSA exponent is 65539.
 * 2.Sign with the decoded private key and verify with the decoded public key.
 * @expect
 * 1.Public/private key decode succeeds.
 * 2.Sign and verify succeed with the imported key pair.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_IMPORT_ASN1_NON_F4_TC001(int type, char *pubKeyPath, char *prvKeyPath)
{
#if !defined(HITLS_CRYPTO_CODECSKEY) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_KEY_DECODE)
    (void)type;
    (void)pubKeyPath;
    (void)prvKeyPath;
    SKIP_TEST();
#else
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);
    uint8_t msg[] = "composite asn1 import rsa non-f4";
    uint8_t *sign = NULL;
    uint32_t signLen = 0;
    TestMemInit();
    TestRandInit();
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, pubKeyPath, NULL, 0, &pubCtx),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, prvKeyPath, NULL, 0, &prvCtx),
        CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositeDecodedKey(pubCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositeDecodedKey(prvCtx, type), CRYPT_SUCCESS);

    signLen = CRYPT_EAL_PkeyGetSignLen(prvCtx);
    ASSERT_TRUE(signLen > 0);
    sign = BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(sign != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(prvCtx, mdId, msg, sizeof(msg) - 1, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pubCtx, mdId, msg, sizeof(msg) - 1, sign, signLen), CRYPT_SUCCESS);
EXIT:
    BSL_SAL_Free(sign);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    TestRandDeInit();
#endif
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_IMPORT_RSA_BITS_TC001
 * @spec -
 * @title Test RSA Composite import checks the real RSA modulus bit length from encoded key data.
 * @precon nan
 * @brief
 * 1.Generate one RSA4096 Composite key pair and one matching RSA3072 Composite key pair.
 * 2.Export their Composite public/private keys.
 * 3.Import the real RSA4096 keys into RSA4096 Composite contexts.
 * 4.Import the RSA3072 keys into RSA4096 Composite contexts.
 * @expect
 * 1.RSA4096 imports succeed.
 * 2.RSA3072 imports are rejected with CRYPT_COMPOSITE_ERR_BITS_MISMATCH.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_IMPORT_RSA_BITS_TC001(int type4096, int type3072)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx4096Src = NULL;
    CRYPT_EAL_PkeyCtx *ctx4096Dst = NULL;
    CRYPT_EAL_PkeyCtx *ctx3072Src = NULL;
    CRYPT_EAL_PkeyCtx *ctx4096BadPub = NULL;
    CRYPT_EAL_PkeyCtx *ctx4096BadPrv = NULL;
    CRYPT_EAL_PkeyPub goodPub = {0};
    CRYPT_EAL_PkeyPub badPub = {0};
    CRYPT_EAL_PkeyPrv goodPrv = {0};
    CRYPT_EAL_PkeyPrv badPrv = {0};

    ctx4096Src = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ctx4096Dst = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ctx3072Src = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ctx4096BadPub = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ctx4096BadPrv = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx4096Src != NULL);
    ASSERT_TRUE(ctx4096Dst != NULL);
    ASSERT_TRUE(ctx3072Src != NULL);
    ASSERT_TRUE(ctx4096BadPub != NULL);
    ASSERT_TRUE(ctx4096BadPrv != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx4096Src, type4096), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx4096Dst, type4096), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx3072Src, type3072), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx4096BadPub, type4096), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx4096BadPrv, type4096), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx4096Src), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx3072Src), CRYPT_SUCCESS);

    ASSERT_EQ(ExportCompositePubKey(ctx4096Src, &goodPub), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePrvKey(ctx4096Src, &goodPrv), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePubKey(ctx3072Src, &badPub), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePrvKey(ctx3072Src, &badPrv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx4096Dst, &goodPub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx4096Dst, &goodPrv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx4096BadPub, &badPub), CRYPT_COMPOSITE_ERR_BITS_MISMATCH);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx4096BadPrv, &badPrv), CRYPT_COMPOSITE_ERR_BITS_MISMATCH);

EXIT:
    BSL_SAL_Free(badPrv.key.compositePrv.data);
    BSL_SAL_Free(badPub.key.compositePub.data);
    BSL_SAL_Free(goodPrv.key.compositePrv.data);
    BSL_SAL_Free(goodPub.key.compositePub.data);
    CRYPT_EAL_PkeyFreeCtx(ctx4096BadPrv);
    CRYPT_EAL_PkeyFreeCtx(ctx4096BadPub);
    CRYPT_EAL_PkeyFreeCtx(ctx3072Src);
    CRYPT_EAL_PkeyFreeCtx(ctx4096Dst);
    CRYPT_EAL_PkeyFreeCtx(ctx4096Src);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_IMPORT_RSA_EMPTY_N_TC001
 * @spec -
 * @title Test RSA Composite public-key import rejects an empty INTEGER modulus.
 * @precon nan
 * @brief
 * 1.Generate one valid RSA4096 Composite key pair and export its Composite public key.
 * 2.Build a malformed Composite public key by keeping the PQC prefix and replacing the RSA public key with
 *   a DER blob whose modulus is encoded as empty INTEGER.
 * 3.Import the valid and malformed Composite public keys into RSA4096 Composite contexts.
 * @expect
 * 1.Valid Composite public key import succeeds.
 * 2.Malformed Composite public key import returns CRYPT_COMPOSITE_ERR_BITS_MISMATCH.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_IMPORT_RSA_EMPTY_N_TC001(int type)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctxSrc = NULL;
    CRYPT_EAL_PkeyCtx *ctxGood = NULL;
    CRYPT_EAL_PkeyCtx *ctxBad = NULL;
    CRYPT_EAL_PkeyPub goodPub = {0};
    CRYPT_EAL_PkeyPub badPub = {0};

    ctxSrc = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ctxGood = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ctxBad = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctxSrc != NULL);
    ASSERT_TRUE(ctxGood != NULL);
    ASSERT_TRUE(ctxBad != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxSrc, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxGood, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxBad, type), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctxSrc), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePubKey(ctxSrc, &goodPub), CRYPT_SUCCESS);
    ASSERT_EQ(BuildCompositePubKeyWithEmptyRsaN(ctxSrc, &goodPub, &badPub), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctxGood, &goodPub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctxBad, &badPub), CRYPT_COMPOSITE_ERR_BITS_MISMATCH);

EXIT:
    BSL_SAL_Free(badPub.key.compositePub.data);
    BSL_SAL_Free(goodPub.key.compositePub.data);
    CRYPT_EAL_PkeyFreeCtx(ctxBad);
    CRYPT_EAL_PkeyFreeCtx(ctxGood);
    CRYPT_EAL_PkeyFreeCtx(ctxSrc);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_CHECK_KEYPAIR_TC001
 * @spec -
 * @title Test Composite ML-DSA keypair/private-key check APIs.
 * @precon Composite keypair/private-key check is enabled (HITLS_CRYPTO_COMPOSITE_CHECK defined).
 * @brief
 * 1. Create contexts (ctx, pubCtx, prvCtx).
 * 2. Test keypair/private-key check before parameters are set (expect failure).
 * 3. Set parameters on all contexts and test private-key check before any private key is present (expect failure).
 * 4. Generate a keypair in ctx and verify both keypair/private-key checks succeed there.
 * 5. Extract public key (pk) and private key (sk) from ctx.
 * 6. Set private key in prvCtx and public key in pubCtx.
 * 7. Test private-key check on prvCtx (expect success) and on pubCtx (expect failure, no private key).
 * 8. Test keypair check with mismatched public/private contexts (expect failure).
 * 9. Test keypair check with a public key context as the private key context (expect failure, no private key).
 * 10. Test keypair check with public key context as the public key context and private key context as the private
 *     key context (expect success).
 * @expect
 * 1. Keypair check succeeds only when both public and private keys are present and match.
 * 2. Private-key check succeeds only when a valid private key is present.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_CHECK_KEYPAIR_TC001(int type)
{
#if !defined(HITLS_CRYPTO_COMPOSITE_CHECK)
    (void)type;
    SKIP_TEST();
#else
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx =
        CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_COMPOSITE, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    pubCtx =
        CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_COMPOSITE, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    prvCtx =
        CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_COMPOSITE, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    pubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    prvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
#endif
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(pubCtx != NULL);
    ASSERT_TRUE(prvCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(ctx, ctx), CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(ctx), CRYPT_COMPOSITE_KEYINFO_NOT_SET);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(prvCtx), CRYPT_MLDSA_INVALID_PRVKEY);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(ctx, ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(ctx), CRYPT_SUCCESS);

    uint32_t pubKeyLen = 0;
    uint32_t prvKeyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen)),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &prvKeyLen, sizeof(prvKeyLen)),
        CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pk = { 0 };
    pk.id = CRYPT_PKEY_COMPOSITE;
    pk.key.compositePub.len = pubKeyLen;
    pk.key.compositePub.data = BSL_SAL_Malloc(pubKeyLen);
    ASSERT_TRUE(pk.key.compositePub.data != NULL);
 
    CRYPT_EAL_PkeyPrv sk = { 0 };
    sk.id = CRYPT_PKEY_COMPOSITE;
    sk.key.compositePrv.len = prvKeyLen;
    sk.key.compositePrv.data = BSL_SAL_Malloc(prvKeyLen);
    ASSERT_TRUE(sk.key.compositePrv.data != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &sk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &sk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &pk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(prvCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pubCtx), CRYPT_MLDSA_INVALID_PRVKEY);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(prvCtx, pubCtx), CRYPT_MLDSA_INVALID_PRVKEY); // pub prv mismatch
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, pubCtx), CRYPT_MLDSA_INVALID_PRVKEY); // no prv
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    BSL_SAL_Free(sk.key.compositePrv.data);
    BSL_SAL_Free(pk.key.compositePub.data);
    TestRandDeInit();
#endif
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_ED448_REJECT_TC001
 * @spec -
 * @title Test Composite rejects unsupported Ed448 paraId during SetParaById.
 * @precon nan
 * @brief
 * 1.Create one Composite context.
 * 2.Call SetParaById with MLDSA87_ED448_SHAKE256.
 * @expect
 * 1.SetParaById returns CRYPT_INVALID_ARG.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_ED448_REJECT_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    int32_t type = CRYPT_COMPOSITE_MLDSA87_ED448_SHAKE256;

    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_INVALID_ARG);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_CTRL_REPEATED_TC001
 * @spec -
 * @title Test Composite rejects repeated SetParaById and keeps the first paraId.
 * @precon nan
 * @brief
 * 1.Create one Composite context.
 * 2.Set one valid paraId successfully.
 * 3.Call SetParaById again with the same or a different Composite type.
 * 4.Query GET_PARAID after the failure.
 * @expect
 * 1.The second SetParaById returns CRYPT_COMPOSITE_CTRL_INIT_REPEATED.
 * 2.The stored paraId remains the first one.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_CTRL_REPEATED_TC001(int firstType, int secondType)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    int32_t paraId = 0;

    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, firstType), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, secondType), CRYPT_COMPOSITE_CTRL_INIT_REPEATED);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PARAID, &paraId, sizeof(paraId)), CRYPT_SUCCESS);
    ASSERT_EQ(paraId, firstType);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_KEY_STATE_TC001
 * @spec -
 * @title Test Composite key-absent state and repeated key import checks.
 * @precon nan
 * @brief
 * 1.Create one empty Composite context and three helper contexts with the same paraId.
 * 2.Generate one valid key pair in the source context and export public/private keys.
 * 3.Verify key-dependent APIs fail before emptyCtx imports any key.
 * 4.Import the public key once and twice into pubCtx.
 * 5.Import the private key once and twice into prvCtx.
 * @expect
 * 1.Empty key state rejects key export, sign, and verify.
 * 2.The second SetPub and SetPrv return CRYPT_COMPOSITE_KEY_REPEATED_SET.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_KEY_STATE_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    static const uint8_t msg[] = "composite key state";
    CRYPT_EAL_PkeyCtx *emptyCtx = NULL;
    CRYPT_EAL_PkeyCtx *srcCtx = NULL;
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyPub goodPub = {0};
    CRYPT_EAL_PkeyPub checkPub = {0};
    CRYPT_EAL_PkeyPrv goodPrv = {0};
    CRYPT_EAL_PkeyPrv checkPrv = {0};
    CRYPT_EAL_PkeyPub emptyPub = {0};
    CRYPT_EAL_PkeyPrv emptyPrv = {0};
    uint8_t dummyPub[1] = {0};
    uint8_t dummyPrv[1] = {0};
    uint8_t *sign = NULL;
    uint32_t pubKeyLen = 0;
    uint32_t prvKeyLen = 0;
    uint32_t signLen = 0;
    uint32_t curSignLen = 0;
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);

    TestMemInit();
    TestRandInit();
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);

    emptyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    srcCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    pubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    prvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(emptyCtx != NULL);
    ASSERT_TRUE(srcCtx != NULL);
    ASSERT_TRUE(pubCtx != NULL);
    ASSERT_TRUE(prvCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(emptyCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(srcCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(srcCtx), CRYPT_SUCCESS);

    ASSERT_EQ(ExportCompositePubKey(srcCtx, &goodPub), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePrvKey(srcCtx, &goodPrv), CRYPT_SUCCESS);

    emptyPub.id = CRYPT_PKEY_COMPOSITE;
    emptyPub.key.compositePub.data = dummyPub;
    emptyPub.key.compositePub.len = sizeof(dummyPub);
    emptyPrv.id = CRYPT_PKEY_COMPOSITE;
    emptyPrv.key.compositePrv.data = dummyPrv;
    emptyPrv.key.compositePrv.len = sizeof(dummyPrv);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(emptyCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen)),
        CRYPT_COMPOSITE_KEY_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(emptyCtx, CRYPT_CTRL_GET_PRVKEY_LEN, &prvKeyLen, sizeof(prvKeyLen)),
        CRYPT_COMPOSITE_KEY_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(emptyCtx, &emptyPub), CRYPT_COMPOSITE_KEY_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(emptyCtx, &emptyPrv), CRYPT_COMPOSITE_KEY_NOT_SET);

#if defined(HITLS_CRYPTO_COMPOSITE_CHECK)
    ASSERT_NE(CRYPT_EAL_PkeyPairCheck(emptyCtx, emptyCtx), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeyPrvCheck(emptyCtx), CRYPT_SUCCESS);
#endif

    signLen = CRYPT_EAL_PkeyGetSignLen(srcCtx);
    ASSERT_TRUE(signLen > 0);
    sign = BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(sign != NULL);
    (void)memset(sign, 0, signLen);

    curSignLen = signLen;
    ASSERT_NE(CRYPT_EAL_PkeySign(emptyCtx, mdId, msg, sizeof(msg) - 1, sign, &curSignLen), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeyVerify(emptyCtx, mdId, msg, sizeof(msg) - 1, sign, signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &goodPub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &goodPub), CRYPT_COMPOSITE_KEY_REPEATED_SET);
    ASSERT_EQ(ExportCompositePubKey(pubCtx, &checkPub), CRYPT_SUCCESS);
    ASSERT_COMPARE("repeated setpub keeps first pub", checkPub.key.compositePub.data, checkPub.key.compositePub.len,
        goodPub.key.compositePub.data, goodPub.key.compositePub.len);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &goodPrv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &goodPrv), CRYPT_COMPOSITE_KEY_REPEATED_SET);
    ASSERT_EQ(ExportCompositePrvKey(prvCtx, &checkPrv), CRYPT_SUCCESS);
    ASSERT_COMPARE("repeated setprv keeps first prv", checkPrv.key.compositePrv.data, checkPrv.key.compositePrv.len,
        goodPrv.key.compositePrv.data, goodPrv.key.compositePrv.len);

EXIT:
    BSL_SAL_Free(sign);
    BSL_SAL_ClearFree(checkPrv.key.compositePrv.data, checkPrv.key.compositePrv.len);
    BSL_SAL_ClearFree(goodPrv.key.compositePrv.data, goodPrv.key.compositePrv.len);
    BSL_SAL_FREE(checkPub.key.compositePub.data);
    BSL_SAL_FREE(goodPub.key.compositePub.data);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(srcCtx);
    CRYPT_EAL_PkeyFreeCtx(emptyCtx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_EXPORT_BOUNDARY_TC001
 * @spec -
 * @title Test Composite GetPubEx/GetPrvEx short-buffer handling and useLen write-back.
 * @precon nan
 * @brief
 * 1.Generate one valid Composite key pair and export the baseline public/private key.
 * 2.Call GetPubEx and GetPrvEx with output buffers shorter than the real key length.
 * 3.Call GetPubEx and GetPrvEx again with exact-length buffers.
 * 4.Compare exact-length Ex output with normal GetPub/GetPrv output.
 * @expect
 * 1.Short-buffer exports return CRYPT_COMPOSITE_LEN_NOT_ENOUGH.
 * 2.Exact-length exports succeed and write back the used length.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_EXPORT_BOUNDARY_TC001(int type)
{
#ifndef HITLS_BSL_PARAMS
    (void)type;
    SKIP_TEST();
#else
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPub basePub = {0};
    CRYPT_EAL_PkeyPrv basePrv = {0};
    uint8_t *shortPub = NULL;
    uint8_t *shortPrv = NULL;
    uint8_t *exactPub = NULL;
    uint8_t *exactPrv = NULL;
    BSL_Param pubShortParam[2] = {0};
    BSL_Param prvShortParam[2] = {0};
    BSL_Param pubExactParam[2] = {0};
    BSL_Param prvExactParam[2] = {0};

    TestMemInit();
    TestRandInit();

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(ExportCompositePubKey(ctx, &basePub), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePrvKey(ctx, &basePrv), CRYPT_SUCCESS);
    ASSERT_TRUE(basePub.key.compositePub.len > 1);
    ASSERT_TRUE(basePrv.key.compositePrv.len > 1);

    shortPub = BSL_SAL_Malloc(basePub.key.compositePub.len - 1);
    shortPrv = BSL_SAL_Malloc(basePrv.key.compositePrv.len - 1);
    exactPub = BSL_SAL_Malloc(basePub.key.compositePub.len);
    exactPrv = BSL_SAL_Malloc(basePrv.key.compositePrv.len);
    ASSERT_TRUE(shortPub != NULL);
    ASSERT_TRUE(shortPrv != NULL);
    ASSERT_TRUE(exactPub != NULL);
    ASSERT_TRUE(exactPrv != NULL);

    ASSERT_EQ(InitCompositeOctetsParam(pubShortParam, CRYPT_PARAM_COMPOSITE_PUBKEY, shortPub,
        basePub.key.compositePub.len - 1), CRYPT_SUCCESS);
    ASSERT_EQ(InitCompositeOctetsParam(prvShortParam, CRYPT_PARAM_COMPOSITE_PRVKEY, shortPrv,
        basePrv.key.compositePrv.len - 1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, pubShortParam), CRYPT_COMPOSITE_LEN_NOT_ENOUGH);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(ctx, prvShortParam), CRYPT_COMPOSITE_LEN_NOT_ENOUGH);

    ASSERT_EQ(InitCompositeOctetsParam(pubExactParam, CRYPT_PARAM_COMPOSITE_PUBKEY, exactPub,
        basePub.key.compositePub.len), CRYPT_SUCCESS);
    ASSERT_EQ(InitCompositeOctetsParam(prvExactParam, CRYPT_PARAM_COMPOSITE_PRVKEY, exactPrv,
        basePrv.key.compositePrv.len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, pubExactParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(ctx, prvExactParam), CRYPT_SUCCESS);
    ASSERT_EQ(pubExactParam[0].useLen, basePub.key.compositePub.len);
    ASSERT_EQ(prvExactParam[0].useLen, basePrv.key.compositePrv.len);
    ASSERT_COMPARE("pub ex matches normal export", exactPub, pubExactParam[0].useLen,
        basePub.key.compositePub.data, basePub.key.compositePub.len);
    ASSERT_COMPARE("prv ex matches normal export", exactPrv, prvExactParam[0].useLen,
        basePrv.key.compositePrv.data, basePrv.key.compositePrv.len);

EXIT:
    BSL_SAL_Free(exactPrv);
    BSL_SAL_Free(exactPub);
    BSL_SAL_Free(shortPrv);
    BSL_SAL_Free(shortPub);
    BSL_SAL_ClearFree(basePrv.key.compositePrv.data, basePrv.key.compositePrv.len);
    BSL_SAL_FREE(basePub.key.compositePub.data);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
#endif
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_VERIFY_NEGATIVE_TC001
 * @spec -
 * @title Test Composite verify rejects wrong message, wrong ctxInfo, wrong public key, and wrong paraId.
 * @precon nan
 * @brief
 * 1.Generate one sign context, one same-type verification context, one same-type wrong-key context,
 *   and one different-paraId verification context.
 * 2.Generate the signing key pair and one additional same-type key pair for the wrong-key case.
 * 3.Export the signing public key into the same-type verification context and try to import it into the
 *   different-paraId context.
 * 4.Sign one message with ctxInfo A.
 * 5.Verify with the correct input, then retry with wrong message, wrong ctxInfo, wrong public key,
 *   and wrong paraId when the different-paraId context accepts the public key.
 * @expect
 * 1.The correct input verifies successfully.
 * 2.All mismatch cases fail verification.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_VERIFY_NEGATIVE_TC001(int type, int altType, int expectAltSetPubFail)
{
    if (PkiSkipCompositeParaTest(type) || PkiSkipCompositeParaTest(altType)) {
        SKIP_TEST();
    }
    static const uint8_t ctxInfoA[] = "ctx-A";
    static const uint8_t ctxInfoB[] = "ctx-B";
    static const uint8_t msg[] = "composite verify negative";
    CRYPT_EAL_PkeyCtx *signCtx = NULL;
    CRYPT_EAL_PkeyCtx *verifyCtx = NULL;
    CRYPT_EAL_PkeyCtx *otherCtx = NULL;
    CRYPT_EAL_PkeyCtx *altCtx = NULL;
    CRYPT_EAL_PkeyPub signPub = {0};
    uint8_t *sign = NULL;
    uint8_t wrongMsg[sizeof(msg)] = {0};
    uint32_t signLen = 0;
    int32_t ret;
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);

    TestMemInit();
    TestRandInit();
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);

    signCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    verifyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    otherCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    altCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(signCtx != NULL);
    ASSERT_TRUE(verifyCtx != NULL);
    ASSERT_TRUE(otherCtx != NULL);
    ASSERT_TRUE(altCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(signCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(verifyCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(otherCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(altCtx, altType), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(signCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(otherCtx), CRYPT_SUCCESS);

    ASSERT_EQ(ExportCompositePubKey(signCtx, &signPub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(verifyCtx, &signPub), CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeySetPub(altCtx, &signPub);
    if (expectAltSetPubFail != 0) {
        ASSERT_NE(ret, CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    }

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(signCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctxInfoA,
        (uint32_t)(sizeof(ctxInfoA) - 1)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctxInfoA,
        (uint32_t)(sizeof(ctxInfoA) - 1)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(otherCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctxInfoA,
        (uint32_t)(sizeof(ctxInfoA) - 1)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(altCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctxInfoA,
        (uint32_t)(sizeof(ctxInfoA) - 1)), CRYPT_SUCCESS);

    signLen = CRYPT_EAL_PkeyGetSignLen(signCtx);
    ASSERT_TRUE(signLen > 0);
    sign = BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(sign != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(signCtx, mdId, msg, sizeof(msg) - 1, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(verifyCtx, mdId, msg, sizeof(msg) - 1, sign, signLen), CRYPT_SUCCESS);

    (void)memcpy(wrongMsg, msg, sizeof(msg));
    wrongMsg[0] ^= 0x01U;
    ASSERT_NE(CRYPT_EAL_PkeyVerify(verifyCtx, mdId, wrongMsg, sizeof(wrongMsg) - 1, sign, signLen),
        CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctxInfoB,
        (uint32_t)(sizeof(ctxInfoB) - 1)), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeyVerify(verifyCtx, mdId, msg, sizeof(msg) - 1, sign, signLen), CRYPT_SUCCESS);

    ASSERT_NE(CRYPT_EAL_PkeyVerify(otherCtx, mdId, msg, sizeof(msg) - 1, sign, signLen), CRYPT_SUCCESS);
    if (expectAltSetPubFail == 0) {
        ASSERT_NE(CRYPT_EAL_PkeyVerify(altCtx, mdId, msg, sizeof(msg) - 1, sign, signLen), CRYPT_SUCCESS);
    }

EXIT:
    BSL_SAL_Free(sign);
    BSL_SAL_FREE(signPub.key.compositePub.data);
    CRYPT_EAL_PkeyFreeCtx(altCtx);
    CRYPT_EAL_PkeyFreeCtx(otherCtx);
    CRYPT_EAL_PkeyFreeCtx(verifyCtx);
    CRYPT_EAL_PkeyFreeCtx(signCtx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_SIGNATURE_FORMAT_TC001
 * @spec -
 * @title Test Composite verify rejects malformed signature layout variants.
 * @precon nan
 * @brief
 * 1.Generate one valid Composite signature and import its public key into a verify context.
 * 2.Verify the baseline signature.
 * 3.Verify one signature truncated before the PQC part ends.
 * 4.Verify one signature truncated inside the traditional part.
 * 5.Verify one signature with one byte flipped in the PQC part.
 * 6.Verify one signature with one byte flipped in the traditional part.
 * 7.Verify one signature with one extra trailing byte.
 * @expect
 * 1.The baseline signature succeeds.
 * 2.All malformed signature variants are rejected.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_SIGNATURE_FORMAT_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    static const uint8_t msg[] = "composite signature format";
    CRYPT_EAL_PkeyCtx *signCtx = NULL;
    CRYPT_EAL_PkeyCtx *verifyCtx = NULL;
    CRYPT_EAL_PkeyPub pubKey = {0};
    uint8_t *sign = NULL;
    uint8_t *pqcTampered = NULL;
    uint8_t *tradTampered = NULL;
    uint8_t *extendedSign = NULL;
    uint32_t signLen = 0;
    uint32_t pqcSigLen = 0;
    uint32_t midTruncLen = 0;
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);

    TestMemInit();
    TestRandInit();
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);

    signCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    verifyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(signCtx != NULL);
    ASSERT_TRUE(verifyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(signCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(verifyCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(signCtx), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePubKey(signCtx, &pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(verifyCtx, &pubKey), CRYPT_SUCCESS);

    signLen = CRYPT_EAL_PkeyGetSignLen(signCtx);
    pqcSigLen = ((const CRYPT_CompositeCtx *)signCtx->key)->info->pqcSigLen;
    ASSERT_TRUE(signLen > pqcSigLen);
    ASSERT_TRUE(pqcSigLen > 0);

    sign = BSL_SAL_Malloc(signLen);
    pqcTampered = BSL_SAL_Malloc(signLen);
    tradTampered = BSL_SAL_Malloc(signLen);
    extendedSign = BSL_SAL_Malloc(signLen + 1);
    ASSERT_TRUE(sign != NULL);
    ASSERT_TRUE(pqcTampered != NULL);
    ASSERT_TRUE(tradTampered != NULL);
    ASSERT_TRUE(extendedSign != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(signCtx, mdId, msg, sizeof(msg) - 1, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(verifyCtx, mdId, msg, sizeof(msg) - 1, sign, signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(verifyCtx, mdId, msg, sizeof(msg) - 1, sign, pqcSigLen - 1),
        CRYPT_COMPOSITE_INVALID_SIG_LEN);

    ASSERT_TRUE(signLen > pqcSigLen + 1);
    midTruncLen = pqcSigLen + 1;
    ASSERT_NE(CRYPT_EAL_PkeyVerify(verifyCtx, mdId, msg, sizeof(msg) - 1, sign, midTruncLen),
        CRYPT_SUCCESS);

    (void)memcpy(pqcTampered, sign, signLen);
    pqcTampered[0] ^= 0x01U;
    ASSERT_NE(CRYPT_EAL_PkeyVerify(verifyCtx, mdId, msg, sizeof(msg) - 1, pqcTampered, signLen),
        CRYPT_SUCCESS);

    (void)memcpy(tradTampered, sign, signLen);
    tradTampered[pqcSigLen] ^= 0x01U;
    ASSERT_NE(CRYPT_EAL_PkeyVerify(verifyCtx, mdId, msg, sizeof(msg) - 1, tradTampered, signLen),
        CRYPT_SUCCESS);

    (void)memcpy(extendedSign, sign, signLen);
    extendedSign[signLen] = 0xA5U;
    ASSERT_NE(CRYPT_EAL_PkeyVerify(verifyCtx, mdId, msg, sizeof(msg) - 1, extendedSign, signLen + 1),
        CRYPT_SUCCESS);

EXIT:
    BSL_SAL_Free(extendedSign);
    BSL_SAL_Free(tradTampered);
    BSL_SAL_Free(pqcTampered);
    BSL_SAL_Free(sign);
    BSL_SAL_FREE(pubKey.key.compositePub.data);
    CRYPT_EAL_PkeyFreeCtx(verifyCtx);
    CRYPT_EAL_PkeyFreeCtx(signCtx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_SIGNDATA_BOUNDARY_TC001
 * @spec -
 * @title Test Composite SignData/VerifyData digest-length and output-buffer boundaries.
 * @precon nan
 * @brief
 * 1.Generate one valid Composite key pair.
 * 2.Prepare one exact digest, one short digest, and one long digest.
 * 3.Call SignData with wrong digest lengths and a short signature buffer.
 * 4.Call SignData with the exact digest and exact output length.
 * 5.Call VerifyData with the exact digest and wrong digest lengths.
 * @expect
 * 1.Wrong digest lengths return CRYPT_INVALID_ARG.
 * 2.Short signature buffer returns CRYPT_COMPOSITE_INVALID_SIG_LEN.
 * 3.Exact digest and exact output length succeed.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_SIGNDATA_BOUNDARY_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_MD_AlgId mdId = CRYPT_MD_MAX;
    uint8_t digest[65] = {0};
    uint8_t *sign = NULL;
    uint32_t digestLen = 0;
    uint32_t signLen = 0;
    uint32_t shortSignLen = 0;
    uint32_t curSignLen = 0;

    TestMemInit();
    TestRandInit();

    mdId = GetCompositeHashAlgId(type);
    if (mdId != CRYPT_MD_MAX) {
        digestLen = CRYPT_EAL_MdGetDigestSize(mdId);
    }
    ASSERT_TRUE(digestLen > 1);
    ASSERT_TRUE(digestLen + 1 <= sizeof(digest));
    (void)memset(digest, 0x3C, sizeof(digest));

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);

    signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_TRUE(signLen > 1);
    sign = BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(sign != NULL);

    curSignLen = signLen;
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ctx, digest, digestLen - 1, sign, &curSignLen), CRYPT_INVALID_ARG);
    curSignLen = signLen;
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ctx, digest, digestLen + 1, sign, &curSignLen), CRYPT_INVALID_ARG);

    shortSignLen = signLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ctx, digest, digestLen, sign, &shortSignLen), CRYPT_COMPOSITE_INVALID_SIG_LEN);
    ASSERT_EQ(shortSignLen, signLen - 1);

    curSignLen = signLen;
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ctx, digest, digestLen, sign, &curSignLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(ctx, digest, digestLen, sign, curSignLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(ctx, digest, digestLen - 1, sign, curSignLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(ctx, digest, digestLen + 1, sign, curSignLen), CRYPT_INVALID_ARG);

EXIT:
    BSL_SAL_Free(sign);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_IMPORT_RAW_NEGATIVE_TC001
 * @spec -
 * @title Test Composite raw-key import rejects malformed lengths.
 * @precon nan
 * @brief
 * 1.Generate one valid Composite key pair and export raw public/private keys.
 * 2.Build truncated and extra-byte variants for the raw public/private key.
 * 3.Import malformed raw public/private keys into fresh contexts and expect failure.
 * 4.Import one valid private key first, then verify malformed public-key import still fails.
 * 5.Import one valid public key first, then verify malformed private-key import still fails.
 * @expect
 * 1.Malformed raw imports fail.
 * 2.A context that hits such a failure is released directly instead of being reused.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_IMPORT_RAW_NEGATIVE_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *srcCtx = NULL;
    CRYPT_EAL_PkeyCtx *truncPubCtx = NULL;
    CRYPT_EAL_PkeyCtx *extraPubCtx = NULL;
    CRYPT_EAL_PkeyCtx *truncPrvCtx = NULL;
    CRYPT_EAL_PkeyCtx *extraPrvCtx = NULL;
    CRYPT_EAL_PkeyCtx *keepPrvCtx = NULL;
    CRYPT_EAL_PkeyCtx *keepPubCtx = NULL;
    CRYPT_EAL_PkeyPub goodPub = {0};
    CRYPT_EAL_PkeyPub truncPub = {0};
    CRYPT_EAL_PkeyPub extraPub = {0};
    CRYPT_EAL_PkeyPrv goodPrv = {0};
    CRYPT_EAL_PkeyPrv truncPrv = {0};
    CRYPT_EAL_PkeyPrv extraPrv = {0};
    const CRYPT_CompositeCtx *compositeKey = NULL;
    uint32_t maxPubKeyLen = 0;
    uint32_t maxPrvKeyLen = 0;
    uint32_t isRsa = 0;

    TestMemInit();
    TestRandInit();

    srcCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    truncPubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    extraPubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    truncPrvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    extraPrvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    keepPrvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    keepPubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(srcCtx != NULL);
    ASSERT_TRUE(truncPubCtx != NULL);
    ASSERT_TRUE(extraPubCtx != NULL);
    ASSERT_TRUE(truncPrvCtx != NULL);
    ASSERT_TRUE(extraPrvCtx != NULL);
    ASSERT_TRUE(keepPrvCtx != NULL);
    ASSERT_TRUE(keepPubCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(srcCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(truncPubCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(extraPubCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(truncPrvCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(extraPrvCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(keepPrvCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(keepPubCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(srcCtx), CRYPT_SUCCESS);
    compositeKey = (const CRYPT_CompositeCtx *)srcCtx->key;
    ASSERT_TRUE(compositeKey != NULL);
    isRsa = (uint32_t)(compositeKey->info->tradAlg == CRYPT_PKEY_RSA);

    ASSERT_EQ(ExportCompositePubKey(srcCtx, &goodPub), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePrvKey(srcCtx, &goodPrv), CRYPT_SUCCESS);

    ASSERT_EQ(CloneCompositePubKey(&goodPub, &truncPub), CRYPT_SUCCESS);
    ASSERT_TRUE(truncPub.key.compositePub.len > ((const CRYPT_CompositeCtx *)srcCtx->key)->info->pqcPubkeyLen);
    truncPub.key.compositePub.len--;
    ASSERT_EQ(CloneCompositePrvKey(&goodPrv, &truncPrv), CRYPT_SUCCESS);
    ASSERT_TRUE(truncPrv.key.compositePrv.len > ((const CRYPT_CompositeCtx *)srcCtx->key)->info->pqcPrvkeyLen);
    truncPrv.key.compositePrv.len--;
    if (isRsa == 0) {
        maxPubKeyLen = compositeKey->info->pubKeyLen;
        maxPrvKeyLen = compositeKey->info->prvKeyLen;
        ASSERT_TRUE(maxPubKeyLen >= goodPub.key.compositePub.len);
        ASSERT_TRUE(maxPrvKeyLen >= goodPrv.key.compositePrv.len);
    }

    extraPub.id = CRYPT_PKEY_COMPOSITE;
    extraPub.key.compositePub.len = (isRsa != 0) ? (goodPub.key.compositePub.len + 1) : (maxPubKeyLen + 1);
    extraPub.key.compositePub.data = BSL_SAL_Malloc(extraPub.key.compositePub.len);
    ASSERT_TRUE(extraPub.key.compositePub.data != NULL);
    (void)memcpy(extraPub.key.compositePub.data, goodPub.key.compositePub.data, goodPub.key.compositePub.len);
    (void)memset(extraPub.key.compositePub.data + goodPub.key.compositePub.len, 0xA5,
        extraPub.key.compositePub.len - goodPub.key.compositePub.len);

    extraPrv.id = CRYPT_PKEY_COMPOSITE;
    extraPrv.key.compositePrv.len = (isRsa != 0) ? (goodPrv.key.compositePrv.len + 1) : (maxPrvKeyLen + 1);
    extraPrv.key.compositePrv.data = BSL_SAL_Malloc(extraPrv.key.compositePrv.len);
    ASSERT_TRUE(extraPrv.key.compositePrv.data != NULL);
    (void)memcpy(extraPrv.key.compositePrv.data, goodPrv.key.compositePrv.data, goodPrv.key.compositePrv.len);
    (void)memset(extraPrv.key.compositePrv.data + goodPrv.key.compositePrv.len, 0xA5,
        extraPrv.key.compositePrv.len - goodPrv.key.compositePrv.len);

    ASSERT_NE(CRYPT_EAL_PkeySetPub(truncPubCtx, &truncPub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(extraPubCtx, &extraPub), CRYPT_COMPOSITE_KEYLEN_ERROR);

    ASSERT_NE(CRYPT_EAL_PkeySetPrv(truncPrvCtx, &truncPrv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(extraPrvCtx, &extraPrv), CRYPT_COMPOSITE_KEYLEN_ERROR);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(keepPrvCtx, &goodPrv), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeySetPub(keepPrvCtx, &truncPub), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(keepPubCtx, &goodPub), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeySetPrv(keepPubCtx, &truncPrv), CRYPT_SUCCESS);

EXIT:
    truncPrv.key.compositePrv.len = goodPrv.key.compositePrv.len;
    BSL_SAL_ClearFree(extraPrv.key.compositePrv.data, extraPrv.key.compositePrv.len);
    BSL_SAL_ClearFree(truncPrv.key.compositePrv.data, truncPrv.key.compositePrv.len);
    BSL_SAL_ClearFree(goodPrv.key.compositePrv.data, goodPrv.key.compositePrv.len);
    BSL_SAL_FREE(extraPub.key.compositePub.data);
    BSL_SAL_FREE(truncPub.key.compositePub.data);
    BSL_SAL_FREE(goodPub.key.compositePub.data);
    CRYPT_EAL_PkeyFreeCtx(keepPubCtx);
    CRYPT_EAL_PkeyFreeCtx(keepPrvCtx);
    CRYPT_EAL_PkeyFreeCtx(extraPrvCtx);
    CRYPT_EAL_PkeyFreeCtx(truncPrvCtx);
    CRYPT_EAL_PkeyFreeCtx(extraPubCtx);
    CRYPT_EAL_PkeyFreeCtx(truncPubCtx);
    CRYPT_EAL_PkeyFreeCtx(srcCtx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_IMPORT_TRAD_PROFILE_TC001
 * @spec -
 * @title Test Composite import rejects malformed ECDSA traditional key components.
 * @precon nan
 * @brief
 * 1.Generate one valid Composite key pair and export raw public/private keys.
 * 2.Corrupt the ECDSA traditional public/private component encoding in the exported raw key.
 * 3.Import the malformed raw public/private key into fresh contexts.
 * @expect
 * 1.Malformed ECDSA traditional components are rejected during SetPub/SetPrv.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_IMPORT_TRAD_PROFILE_TC001(int type)
{
    CRYPT_EAL_PkeyCtx *srcCtx = NULL;
    CRYPT_EAL_PkeyCtx *badPubCtx = NULL;
    CRYPT_EAL_PkeyCtx *badPrvCtx = NULL;
    CRYPT_EAL_PkeyPub goodPub = {0};
    CRYPT_EAL_PkeyPub badPub = {0};
    CRYPT_EAL_PkeyPrv goodPrv = {0};
    CRYPT_EAL_PkeyPrv badPrv = {0};
    uint32_t pqcPubLen = 0;
    uint32_t pqcPrvLen = 0;

    TestMemInit();
    TestRandInit();

    srcCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    badPubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    badPrvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(srcCtx != NULL);
    ASSERT_TRUE(badPubCtx != NULL);
    ASSERT_TRUE(badPrvCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(srcCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(badPubCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(badPrvCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(srcCtx), CRYPT_SUCCESS);

    ASSERT_EQ(ExportCompositePubKey(srcCtx, &goodPub), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePrvKey(srcCtx, &goodPrv), CRYPT_SUCCESS);
    ASSERT_EQ(CloneCompositePubKey(&goodPub, &badPub), CRYPT_SUCCESS);
    ASSERT_EQ(CloneCompositePrvKey(&goodPrv, &badPrv), CRYPT_SUCCESS);

    pqcPubLen = ((const CRYPT_CompositeCtx *)srcCtx->key)->info->pqcPubkeyLen;
    pqcPrvLen = ((const CRYPT_CompositeCtx *)srcCtx->key)->info->pqcPrvkeyLen;
    badPub.key.compositePub.data[pqcPubLen] = 0x05U;
    badPrv.key.compositePrv.data[pqcPrvLen] = 0x31U;
    ASSERT_NE(CRYPT_EAL_PkeySetPub(badPubCtx, &badPub), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeySetPrv(badPrvCtx, &badPrv), CRYPT_SUCCESS);

EXIT:
    BSL_SAL_ClearFree(badPrv.key.compositePrv.data, badPrv.key.compositePrv.len);
    BSL_SAL_ClearFree(goodPrv.key.compositePrv.data, goodPrv.key.compositePrv.len);
    BSL_SAL_FREE(badPub.key.compositePub.data);
    BSL_SAL_FREE(goodPub.key.compositePub.data);
    CRYPT_EAL_PkeyFreeCtx(badPrvCtx);
    CRYPT_EAL_PkeyFreeCtx(badPubCtx);
    CRYPT_EAL_PkeyFreeCtx(srcCtx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_IMPORT_COMPRESSED_TRAD_PUB_TC001
 * @spec -
 * @title Test Composite compressed ECDSA public-key sample imports successfully and re-encodes to uncompressed format.
 * @precon A Composite DER public key sample whose ECDSA traditional component uses compressed point format is available.
 * @brief
 * 1.Read and decode one prebuilt Composite DER public key sample with compressed ECDSA point format.
 * 2.Check the imported sample encodes the traditional ECDSA point in compressed form.
 * 3.Re-encode the imported Composite public key to DER.
 * 4.Check the exported DER encodes the traditional ECDSA point in uncompressed form.
 * @expect
 * 1.Compressed ECDSA point format is accepted during Composite DER public-key import.
 * 2.Composite DER public-key export normalizes the ECDSA point to uncompressed format.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_IMPORT_COMPRESSED_TRAD_PUB_TC001(int type, char *pubKeyPath)
{
#if !defined(HITLS_CRYPTO_CODECSKEY) || !defined(HITLS_BSL_SAL_FILE) || \
    !defined(HITLS_CRYPTO_KEY_DECODE) || !defined(HITLS_CRYPTO_KEY_ENCODE)
    (void)type;
    (void)pubKeyPath;
    SKIP_TEST();
#else
    BSL_Buffer pubFile = {0};
    BSL_Buffer pubEncode = {0};
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    uint32_t pqcPubLen = 0;

    TestMemInit();

    ASSERT_EQ(BSL_SAL_ReadFile(pubKeyPath, &pubFile.data, &pubFile.dataLen), BSL_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, pubKeyPath, NULL, 0, &pubCtx),
        CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositeDecodedKey(pubCtx, type), CRYPT_SUCCESS);

    pqcPubLen = ((const CRYPT_CompositeCtx *)pubCtx->key)->info->pqcPubkeyLen;
    ASSERT_EQ(GetCompositeDerTradPointTag(&pubFile, pqcPubLen), 0x03U);

    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pubCtx, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &pubEncode),
        CRYPT_SUCCESS);
    ASSERT_EQ(GetCompositeDerTradPointTag(&pubEncode, pqcPubLen), 0x04U);

EXIT:
    BSL_SAL_FREE(pubEncode.data);
    BSL_SAL_FREE(pubFile.data);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
#endif
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_DUPCTX_TC001
 * @spec -
 * @title Test Composite DupCtx keeps keys equivalent and ctxInfo isolated.
 * @precon nan
 * @brief
 * 1.Generate one Composite key pair and set ctxInfo A.
 * 2.Duplicate the context with PkeyDupCtx.
 * 3.Compare exported keys from the original and duplicate contexts.
 * 4.Cross-verify signatures between the two contexts with the same ctxInfo.
 * 5.Change ctxInfo on the duplicate only and verify the old signature no longer matches there.
 * 6.Release the original context and verify the duplicate still signs and verifies independently.
 * @expect
 * 1.DupCtx preserves the key material.
 * 2.Subsequent ctxInfo changes stay isolated to the modified context.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_DUPCTX_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    static const uint8_t ctxInfoA[] = "dup-ctx-A";
    static const uint8_t ctxInfoB[] = "dup-ctx-B";
    static const uint8_t msg[] = "composite dupctx";
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *dupCtx = NULL;
    CRYPT_EAL_PkeyPub pubA = {0};
    CRYPT_EAL_PkeyPub pubB = {0};
    CRYPT_EAL_PkeyPrv prvA = {0};
    CRYPT_EAL_PkeyPrv prvB = {0};
    uint8_t *signA = NULL;
    uint8_t *signB = NULL;
    uint8_t *signDup = NULL;
    uint32_t signLen = 0;
    uint32_t signBLen = 0;
    uint32_t signDupLen = 0;
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);

    TestMemInit();
    TestRandInit();
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctxInfoA,
        (uint32_t)(sizeof(ctxInfoA) - 1)), CRYPT_SUCCESS);

    dupCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(dupCtx != NULL);

    ASSERT_EQ(ExportCompositePubKey(ctx, &pubA), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePubKey(dupCtx, &pubB), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePrvKey(ctx, &prvA), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePrvKey(dupCtx, &prvB), CRYPT_SUCCESS);
    ASSERT_COMPARE("dupctx pub export", pubA.key.compositePub.data, pubA.key.compositePub.len,
        pubB.key.compositePub.data, pubB.key.compositePub.len);
    ASSERT_COMPARE("dupctx prv export", prvA.key.compositePrv.data, prvA.key.compositePrv.len,
        prvB.key.compositePrv.data, prvB.key.compositePrv.len);

    signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    signBLen = CRYPT_EAL_PkeyGetSignLen(dupCtx);
    ASSERT_TRUE(signLen > 0);
    ASSERT_TRUE(signBLen > 0);
    signA = BSL_SAL_Malloc(signLen);
    signB = BSL_SAL_Malloc(signBLen);
    ASSERT_TRUE(signA != NULL);
    ASSERT_TRUE(signB != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, msg, sizeof(msg) - 1, signA, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(dupCtx, mdId, msg, sizeof(msg) - 1, signA, signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(dupCtx, mdId, msg, sizeof(msg) - 1, signB, &signBLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, msg, sizeof(msg) - 1, signB, signBLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(dupCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctxInfoB,
        (uint32_t)(sizeof(ctxInfoB) - 1)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, msg, sizeof(msg) - 1, signA, signLen), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeyVerify(dupCtx, mdId, msg, sizeof(msg) - 1, signA, signLen), CRYPT_SUCCESS);

    signDupLen = CRYPT_EAL_PkeyGetSignLen(dupCtx);
    ASSERT_TRUE(signDupLen > 0);
    signDup = BSL_SAL_Malloc(signDupLen);
    ASSERT_TRUE(signDup != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(dupCtx, mdId, msg, sizeof(msg) - 1, signDup, &signDupLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(dupCtx, mdId, msg, sizeof(msg) - 1, signDup, signDupLen), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeyVerify(ctx, mdId, msg, sizeof(msg) - 1, signDup, signDupLen), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyFreeCtx(ctx);
    ctx = NULL;
    signDupLen = CRYPT_EAL_PkeyGetSignLen(dupCtx);
    ASSERT_EQ(CRYPT_EAL_PkeySign(dupCtx, mdId, msg, sizeof(msg) - 1, signDup, &signDupLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(dupCtx, mdId, msg, sizeof(msg) - 1, signDup, signDupLen), CRYPT_SUCCESS);

EXIT:
    BSL_SAL_Free(signDup);
    BSL_SAL_Free(signB);
    BSL_SAL_Free(signA);
    BSL_SAL_ClearFree(prvB.key.compositePrv.data, prvB.key.compositePrv.len);
    BSL_SAL_ClearFree(prvA.key.compositePrv.data, prvA.key.compositePrv.len);
    BSL_SAL_FREE(pubB.key.compositePub.data);
    BSL_SAL_FREE(pubA.key.compositePub.data);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPT_EAL_COMPOSITE_KEY_ROUNDTRIP_TC001
 * @spec -
 * @title Test Composite BC key samples support decode/encode/decode roundtrip.
 * @precon BC Composite public/private key samples are available.
 * @brief
 * 1.Decode BC Composite public/private key files.
 * 2.Check decoded key type, paraId, and raw key SHA-256 expectations.
 * 3.Re-encode the decoded keys and compare them with the original BC files.
 * 4.Decode the re-encoded keys and repeat the checks.
 * @expect
 * 1.Public/private key decode and re-encode succeed.
 * 2.Re-encoded bytes match the BC source files.
 * 3.Decoded roundtrip keys preserve the expected Composite paraId and raw-key digests.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_COMPOSITE_KEY_ROUNDTRIP_TC001(char *sampleDir, int expectParaId,
    Hex *expectPubRawSha256, Hex *expectPrvRawSha256)
{
#if !defined(HITLS_CRYPTO_CODECSKEY) || !defined(HITLS_BSL_SAL_FILE) || \
    !defined(HITLS_CRYPTO_KEY_DECODE) || !defined(HITLS_CRYPTO_KEY_ENCODE)
    (void)sampleDir;
    (void)expectParaId;
    (void)expectPubRawSha256;
    (void)expectPrvRawSha256;
    SKIP_TEST();
#else
    char pubPath[COMPOSITE_SAMPLE_PATH_MAX] = {0};
    char prvPath[COMPOSITE_SAMPLE_PATH_MAX] = {0};
    BSL_Buffer pubFile = {0};
    BSL_Buffer prvFile = {0};
    BSL_Buffer pubEncode = {0};
    BSL_Buffer prvEncode = {0};
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyCtx *pubRoundtrip = NULL;
    CRYPT_EAL_PkeyCtx *prvRoundtrip = NULL;

    TestMemInit();

    ASSERT_EQ(ReadCompositeSampleFile(sampleDir, "publickey.der", &pubFile, pubPath, sizeof(pubPath)), BSL_SUCCESS);
    ASSERT_EQ(ReadCompositeSampleFile(sampleDir, "privatekey.der", &prvFile, prvPath, sizeof(prvPath)), BSL_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, pubPath, NULL, 0, &pubCtx),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, prvPath, NULL, 0, &prvCtx),
        CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositeDecodedKey(pubCtx, expectParaId), CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositeDecodedKey(prvCtx, expectParaId), CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositePubRawSha256(pubCtx, expectPubRawSha256), CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositePrvRawSha256(prvCtx, expectPrvRawSha256), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pubCtx, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &pubEncode),
        CRYPT_SUCCESS);
    ASSERT_COMPARE("bc composite publickey roundtrip", pubEncode.data, pubEncode.dataLen, pubFile.data, pubFile.dataLen);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &pubEncode, NULL, 0, &pubRoundtrip),
        CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositeDecodedKey(pubRoundtrip, expectParaId), CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositePubRawSha256(pubRoundtrip, expectPubRawSha256), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(prvCtx, NULL, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &prvEncode),
        CRYPT_SUCCESS);
    ASSERT_COMPARE("bc composite privatekey roundtrip", prvEncode.data, prvEncode.dataLen, prvFile.data, prvFile.dataLen);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &prvEncode, NULL, 0,
        &prvRoundtrip), CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositeDecodedKey(prvRoundtrip, expectParaId), CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositePrvRawSha256(prvRoundtrip, expectPrvRawSha256), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(prvRoundtrip);
    CRYPT_EAL_PkeyFreeCtx(pubRoundtrip);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    BSL_SAL_ClearFree(prvEncode.data, prvEncode.dataLen);
    BSL_SAL_FREE(pubEncode.data);
    BSL_SAL_ClearFree(prvFile.data, prvFile.dataLen);
    BSL_SAL_FREE(pubFile.data);
#endif
}
/* END_CASE */

/* @
 * @test SDV_CRYPT_EAL_COMPOSITE_SIGN_VERIFY_ROUNDTRIP_TC001
 * @spec -
 * @title Test Composite BC sign/verify samples support positive cross verification.
 * @precon BC Composite key files, message, and signature samples are available.
 * @brief
 * 1.Decode BC Composite public/private key files.
 * 2.Verify the BC signature with the BC public key in openHiTLS.
 * 3.Sign the same message with the BC private key in openHiTLS.
 * 4.Verify the generated signature with the BC public key.
 * @expect
 * 1.BC signature verification succeeds.
 * 2.openHiTLS signature generation succeeds.
 * 3.Generated signature verification succeeds.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_COMPOSITE_SIGN_VERIFY_ROUNDTRIP_TC001(char *sampleDir, int expectParaId, Hex *msg,
    Hex *bcSignature)
{
#if !defined(HITLS_CRYPTO_CODECSKEY) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_KEY_DECODE)
    (void)sampleDir;
    (void)expectParaId;
    (void)msg;
    (void)bcSignature;
    SKIP_TEST();
#else
    char pubPath[COMPOSITE_SAMPLE_PATH_MAX] = {0};
    char prvPath[COMPOSITE_SAMPLE_PATH_MAX] = {0};
    BSL_Buffer pubFile = {0};
    BSL_Buffer prvFile = {0};
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    uint8_t *generatedSignature = NULL;
    uint32_t generatedSignatureLen = 0;
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(expectParaId);

    TestMemInit();
    TestRandInit();
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);

    ASSERT_EQ(ReadCompositeSampleFile(sampleDir, "publickey.der", &pubFile, pubPath, sizeof(pubPath)), BSL_SUCCESS);
    ASSERT_EQ(ReadCompositeSampleFile(sampleDir, "privatekey.der", &prvFile, prvPath, sizeof(prvPath)), BSL_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, pubPath, NULL, 0, &pubCtx),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, prvPath, NULL, 0, &prvCtx),
        CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositeDecodedKey(pubCtx, expectParaId), CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositeDecodedKey(prvCtx, expectParaId), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pubCtx, mdId, msg->x, msg->len, bcSignature->x, bcSignature->len),
        CRYPT_SUCCESS);

    generatedSignatureLen = CRYPT_EAL_PkeyGetSignLen(prvCtx);
    ASSERT_TRUE(generatedSignatureLen > 0);
    generatedSignature = BSL_SAL_Malloc(generatedSignatureLen);
    ASSERT_TRUE(generatedSignature != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(prvCtx, mdId, msg->x, msg->len,
        generatedSignature, &generatedSignatureLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pubCtx, mdId, msg->x, msg->len,
        generatedSignature, generatedSignatureLen), CRYPT_SUCCESS);

EXIT:
    BSL_SAL_Free(generatedSignature);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    BSL_SAL_ClearFree(prvFile.data, prvFile.dataLen);
    BSL_SAL_FREE(pubFile.data);
    TestRandDeInit();
#endif
}
/* END_CASE */

/* @
 * @test SDV_CRYPT_EAL_COMPOSITE_SIGN_COMPARE_BC_DETRAND_TC001
 * @spec -
 * @title Test Composite deterministic signatures match BC bytes with and without ctxInfo.
 * @precon BC Composite key files, message, ctxInfo, and signature samples are available.
 * @brief
 * 1.Decode BC Composite public/private key files.
 * 2.Register deterministic random callbacks for Composite signing.
 * 3.Verify the BC no-context signature with the BC public key in openHiTLS.
 * 4.Reset deterministic randomness, sign the same message without ctxInfo, and compare bytes with the BC signature.
 * 5.Set the same ctxInfo on both verify/sign contexts.
 * 6.Verify the BC with-context signature, reset deterministic randomness, sign again, and compare bytes with the BC signature.
 * @expect
 * 1.Both BC signatures verify successfully.
 * 2.openHiTLS deterministic no-context and with-context signatures match the BC bytes exactly.
 * 3.Generated signatures verify successfully.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_COMPOSITE_SIGN_COMPARE_BC_DETRAND_TC001(char *sampleDir, int expectParaId, Hex *ctxText,
    Hex *msg, Hex *expectSignature, Hex *expectSignatureWithCtx)
{
#if !defined(HITLS_CRYPTO_CODECSKEY) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_KEY_DECODE)
    (void)sampleDir;
    (void)expectParaId;
    (void)ctxText;
    (void)msg;
    (void)expectSignature;
    (void)expectSignatureWithCtx;
    SKIP_TEST();
#else
    char pubPath[COMPOSITE_SAMPLE_PATH_MAX] = {0};
    char prvPath[COMPOSITE_SAMPLE_PATH_MAX] = {0};
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    uint8_t *generatedSignature = NULL;
    uint32_t generatedSignatureBufLen = 0;
    uint32_t generatedSignatureLen = 0;
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(expectParaId);

    TestMemInit();
    TestRandInit();
    CRYPT_RandRegist(CompositeDetRand);
    CRYPT_RandRegistEx(CompositeDetRandEx);
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);

    ASSERT_EQ(JoinCompositeSamplePath(pubPath, sizeof(pubPath), sampleDir, "publickey.der"), CRYPT_SUCCESS);
    ASSERT_EQ(JoinCompositeSamplePath(prvPath, sizeof(prvPath), sampleDir, "privatekey.der"), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, pubPath, NULL, 0, &pubCtx),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, prvPath, NULL, 0, &prvCtx),
        CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositeDecodedKey(pubCtx, expectParaId), CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositeDecodedKey(prvCtx, expectParaId), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pubCtx, mdId, msg->x, msg->len, expectSignature->x, expectSignature->len),
        CRYPT_SUCCESS);

    generatedSignatureBufLen = CRYPT_EAL_PkeyGetSignLen(prvCtx);
    ASSERT_TRUE(generatedSignatureBufLen > 0);
    generatedSignature = BSL_SAL_Malloc(generatedSignatureBufLen);
    ASSERT_TRUE(generatedSignature != NULL);

    CompositeDetRandReset();
    generatedSignatureLen = generatedSignatureBufLen;
    ASSERT_EQ(CRYPT_EAL_PkeySign(prvCtx, mdId, msg->x, msg->len, generatedSignature, &generatedSignatureLen),
        CRYPT_SUCCESS);
    ASSERT_EQ(generatedSignatureLen, expectSignature->len);
    ASSERT_COMPARE("composite detrand sign without ctx", generatedSignature, generatedSignatureLen,
        expectSignature->x, expectSignature->len);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pubCtx, mdId, msg->x, msg->len, generatedSignature, generatedSignatureLen),
        CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pubCtx, CRYPT_CTRL_SET_CTX_INFO, ctxText->x, ctxText->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(prvCtx, CRYPT_CTRL_SET_CTX_INFO, ctxText->x, ctxText->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pubCtx, mdId, msg->x, msg->len,
        expectSignatureWithCtx->x, expectSignatureWithCtx->len), CRYPT_SUCCESS);

    CompositeDetRandReset();
    generatedSignatureLen = generatedSignatureBufLen;
    ASSERT_EQ(CRYPT_EAL_PkeySign(prvCtx, mdId, msg->x, msg->len, generatedSignature, &generatedSignatureLen),
        CRYPT_SUCCESS);
    ASSERT_EQ(generatedSignatureLen, expectSignatureWithCtx->len);
    ASSERT_COMPARE("composite detrand sign with ctx", generatedSignature, generatedSignatureLen,
        expectSignatureWithCtx->x, expectSignatureWithCtx->len);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pubCtx, mdId, msg->x, msg->len, generatedSignature, generatedSignatureLen),
        CRYPT_SUCCESS);

EXIT:
    BSL_SAL_Free(generatedSignature);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    TestRandDeInit();
#endif
}
/* END_CASE */

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
#if !defined(HITLS_BSL_PEM) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_PKI_X509)
    (void)sampleDir;
    (void)expectParaId;
    (void)expectRootKeyUsage;
    (void)expectLeafKeyUsage;
    SKIP_TEST();
#else
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
#if !defined(HITLS_BSL_PEM) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_PKI_X509)
    (void)sampleDir;
    (void)expectParaId;
    SKIP_TEST();
#else
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

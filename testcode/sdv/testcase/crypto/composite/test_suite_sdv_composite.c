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
#include "bsl_bytes.h"
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
#include "stub_utils.h"
/* END_HEADER */

STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);
STUB_DEFINE_RET1(int32_t, CRYPT_EAL_MdInit, CRYPT_EAL_MdCtx *);
STUB_DEFINE_RET3(int32_t, CRYPT_EAL_MdUpdate, CRYPT_EAL_MdCtx *, const uint8_t *, uint32_t);
STUB_DEFINE_RET3(int32_t, CRYPT_EAL_MdFinal, CRYPT_EAL_MdCtx *, uint8_t *, uint32_t *);

static int32_t CompositeKemFailMdInit(CRYPT_EAL_MdCtx *ctx)
{
    return CRYPT_EAL_MdGetId(ctx) == CRYPT_MD_SHA3_256 ? CRYPT_INVALID_ARG : get_real_CRYPT_EAL_MdInit()(ctx);
}

static int32_t CompositeKemFailMdUpdate(CRYPT_EAL_MdCtx *ctx, const uint8_t *data, uint32_t len)
{
    return CRYPT_EAL_MdGetId(ctx) == CRYPT_MD_SHA3_256 ? CRYPT_INVALID_ARG :
                                                         get_real_CRYPT_EAL_MdUpdate()(ctx, data, len);
}

static int32_t CompositeKemFailMdFinal(CRYPT_EAL_MdCtx *ctx, uint8_t *out, uint32_t *len)
{
    return CRYPT_EAL_MdGetId(ctx) == CRYPT_MD_SHA3_256 ? CRYPT_INVALID_ARG :
                                                         get_real_CRYPT_EAL_MdFinal()(ctx, out, len);
}

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

static bool CompositeKemDisabled(int type);

static bool PkiSkipCompositeParaTest(int32_t paraId)
{
    if (paraId >= CRYPT_COMPOSITE_MLKEM768_RSA2048_SHA3_256 &&
        paraId <= CRYPT_COMPOSITE_MLKEM1024_ECDH_P521_SHA3_256) {
        return CompositeKemDisabled(paraId);
    }
#ifndef HITLS_CRYPTO_COMPOSITE_SIGN
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
 * @test SDV_CRYPTO_COMPOSITE_EMPTY_MESSAGE_TC001
 * @title Test Composite empty, boundary, binary-pattern and large messages.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_EMPTY_MESSAGE_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    static const uint8_t emptyMessage = 0;
    static const uint8_t oneByteMessage[] = {0x00};
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t *sign = NULL;
    /* 64-byte pattern messages, a 65-byte boundary message and a 4 KiB large message. */
    uint8_t allZeroMessage[64] = {0};
    uint8_t allFfMessage[64] = {0};
    uint8_t leadingZeroMessage[64] = {0};
    uint8_t trailingZeroMessage[64] = {0};
    uint8_t boundaryMessage[65] = {0};
    uint8_t largeMessage[4096] = {0};
    /* Nine cases: NULL, empty, one byte, four patterns, boundary and large input. */
    const uint8_t *messages[9] = {NULL, &emptyMessage, oneByteMessage, allZeroMessage,
        allFfMessage, leadingZeroMessage, trailingZeroMessage, boundaryMessage, largeMessage};
    const uint32_t messageLens[9] = {0, 0, 1, 64, 64, 64, 64, 65, 4096};
    uint32_t signLen = 0;
    uint32_t i;
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);

    TestMemInit();
    TestRandInit();
    /* 0xFF, 0xA5, 0x5A and 0x3C are distinct binary-pattern test values. */
    (void)memset(allFfMessage, 0xFF, sizeof(allFfMessage));
    (void)memset(leadingZeroMessage, 0xA5, sizeof(leadingZeroMessage));
    (void)memset(trailingZeroMessage, 0xA5, sizeof(trailingZeroMessage));
    (void)memset(boundaryMessage, 0x5A, sizeof(boundaryMessage));
    (void)memset(largeMessage, 0x3C, sizeof(largeMessage));
    leadingZeroMessage[0] = 0;
    trailingZeroMessage[sizeof(trailingZeroMessage) - 1] = 0;
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_TRUE(signLen > 0);
    sign = BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(sign != NULL);

    for (i = 0; i < sizeof(messages) / sizeof(messages[0]); i++) {
        signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
        ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, messages[i], messageLens[i], sign, &signLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, messages[i], messageLens[i], sign, signLen), CRYPT_SUCCESS);
    }

EXIT:
    BSL_SAL_Free(sign);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_REFCOUNT_TC001
 * @title Test Composite EAL context reference increments and release ordering.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_REFCOUNT_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    static const uint8_t message[] = "composite reference count";
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *aliasA = NULL;
    CRYPT_EAL_PkeyCtx *aliasB = NULL;
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);
    uint8_t *sign = NULL;
    uint32_t signLen = 0;

    TestMemInit();
    TestRandInit();
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(ctx->references.count, 1);
    aliasA = ctx;
    aliasB = ctx;
    ASSERT_EQ(CRYPT_EAL_PkeyUpRef(aliasA), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyUpRef(aliasB), CRYPT_SUCCESS);
    /* Three references: the original context plus two EAL up-references. */
    ASSERT_EQ(ctx->references.count, 3);

    CRYPT_EAL_PkeyFreeCtx(aliasA);
    aliasA = NULL;
    /* One alias was released, leaving the original and one alias. */
    ASSERT_EQ(ctx->references.count, 2);
    CRYPT_EAL_PkeyFreeCtx(aliasB);
    aliasB = NULL;
    ASSERT_EQ(ctx->references.count, 1);
    signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    sign = BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(sign != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, message, sizeof(message) - 1, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, message, sizeof(message) - 1, sign, signLen), CRYPT_SUCCESS);

EXIT:
    BSL_SAL_Free(sign);
    CRYPT_EAL_PkeyFreeCtx(aliasA);
    CRYPT_EAL_PkeyFreeCtx(aliasB);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_API_NULL_TC001
 * @title Test null-pointer handling across Composite public EAL APIs.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_API_NULL_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    static const uint8_t message[] = "null-api";
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPara para = {0};
    /* 64-byte buffers are intentionally oversized scratch buffers for NULL checks. */
    uint8_t sign[64] = {0};
    uint8_t digest[64] = {0};
    uint32_t signLen = sizeof(sign);
    uint32_t digestLen = sizeof(digest);
    int32_t value = 0;

    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(NULL, type), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(NULL, &para), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(NULL, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(NULL, CRYPT_CTRL_GET_PUBKEY_LEN, &value, sizeof(value)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(NULL, &pub), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(NULL, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(NULL, &prv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(NULL, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(NULL, &pub), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(NULL, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(NULL, &prv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(NULL, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(NULL, CRYPT_MD_SHA256, message, sizeof(message) - 1,
        sign, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(NULL, CRYPT_MD_SHA256, message, sizeof(message) - 1,
        sign, signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySignData(NULL, digest, digestLen, sign, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(NULL, digest, digestLen, sign, signLen), CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyDupCtx(NULL) == NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyUpRef(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetKeyLen(NULL), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyGetKeyBits(NULL), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyGetSecurityBits(NULL), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyGetSignLen(NULL), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyGetParaId(NULL), CRYPT_PKEY_PARAID_MAX);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPara(NULL, &para), CRYPT_NULL_INPUT);
    CRYPT_EAL_PkeyFreeCtx(NULL);

EXIT:
    return;
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_PARAM_COMBO_TC001
 * @title Test Composite API parameter combinations and invalid algorithm values.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_PARAM_COMBO_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    static const uint8_t message[] = {0x00};
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *invalidCtx = NULL;
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);
    uint8_t *sign = NULL;
    /* 64 bytes provide a fixed digest scratch buffer for invalid-length calls. */
    uint8_t digest[64] = {0};
    uint32_t signLen = 0;
    uint32_t value = 0;
    int32_t invalidType = CRYPT_PKEY_PARAID_MAX;

    TestMemInit();
    TestRandInit();
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    invalidCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(invalidCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(invalidCtx, invalidType), CRYPT_INVALID_ARG);
    signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    sign = BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(sign != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, message, sizeof(message), sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, message, sizeof(message), sign, signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, NULL, sizeof(message), sign, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, message, sizeof(message), sign, &signLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, message, sizeof(message), NULL, &signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, message, sizeof(message), sign, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, NULL, sizeof(message), sign, signLen), CRYPT_NULL_INPUT);
    ASSERT_NE(CRYPT_EAL_PkeyVerify(ctx, mdId, message, 0, sign, signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message, sizeof(message), sign, signLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, message, sizeof(message), NULL, signLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, message, sizeof(message), sign, 0),
        CRYPT_COMPOSITE_INVALID_SIG_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ctx, NULL, 1, sign, &signLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ctx, digest, 0, sign, &signLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(ctx, NULL, 1, sign, signLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(ctx, digest, 0, sign, signLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, NULL, 0), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &value, 1), CRYPT_INVALID_ARG);

EXIT:
    BSL_SAL_Free(sign);
    CRYPT_EAL_PkeyFreeCtx(invalidCtx);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_TRIM_MATRIX_TC001
 * @title Test that every registered Composite parameter can be selected and queried.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_TRIM_MATRIX_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    int32_t paraId = 0;
    int32_t invalidType = CRYPT_PKEY_PARAID_MAX;

    TestMemInit();
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetParaId(ctx), type);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PARAID, &paraId, sizeof(paraId)), CRYPT_SUCCESS);
    ASSERT_EQ(paraId, type);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, invalidType), CRYPT_COMPOSITE_CTRL_INIT_REPEATED);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_ALGID_TC001
 * @title Test Composite Sign/Verify binds the configured hash algorithm.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_ALGID_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    static const uint8_t message[] = "composite algid binding";
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);
    CRYPT_MD_AlgId wrongMdId = CRYPT_MD_SHA256;
    uint8_t *sign = NULL;
    uint32_t signLen = 0;

    TestMemInit();
    TestRandInit();
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);
    if (mdId == CRYPT_MD_SHA256) {
        wrongMdId = CRYPT_MD_SHA512;
    }
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_TRUE(signLen > 0);
    sign = BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(sign != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, message, sizeof(message) - 1, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, message, sizeof(message) - 1, sign, signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, wrongMdId, message, sizeof(message) - 1, sign, &signLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, wrongMdId, message, sizeof(message) - 1, sign, signLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_MAX, message, sizeof(message) - 1, sign, &signLen), CRYPT_INVALID_ARG);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_MAX, message, sizeof(message) - 1, sign, signLen), CRYPT_INVALID_ARG);

EXIT:
    BSL_SAL_Free(sign);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_GENKEY_REPLACE_TC001
 * @title Test repeated GenKey replaces the key pair without cross-key acceptance.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_GENKEY_REPLACE_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    static const uint8_t oldMessage[] = "composite old key";
    static const uint8_t newMessage[] = "composite new key";
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *oldVerify = NULL;
    CRYPT_EAL_PkeyCtx *newVerify = NULL;
    CRYPT_EAL_PkeyPub oldPub = {0};
    CRYPT_EAL_PkeyPub newPub = {0};
    CRYPT_EAL_PkeyPrv oldPrv = {0};
    CRYPT_EAL_PkeyPrv newPrv = {0};
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);
    uint8_t *oldSign = NULL;
    uint8_t *newSign = NULL;
    uint32_t oldSignLen = 0;
    uint32_t newSignLen = 0;

    TestMemInit();
    TestRandInit();
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    oldVerify = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    newVerify = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(oldVerify != NULL);
    ASSERT_TRUE(newVerify != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(oldVerify, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(newVerify, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePubKey(ctx, &oldPub), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePrvKey(ctx, &oldPrv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(oldVerify, &oldPub), CRYPT_SUCCESS);
    oldSignLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    oldSign = BSL_SAL_Malloc(oldSignLen);
    ASSERT_TRUE(oldSign != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, oldMessage, sizeof(oldMessage) - 1, oldSign, &oldSignLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePubKey(ctx, &newPub), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePrvKey(ctx, &newPrv), CRYPT_SUCCESS);
    ASSERT_TRUE(oldPub.key.compositePub.len != newPub.key.compositePub.len ||
        memcmp(oldPub.key.compositePub.data, newPub.key.compositePub.data, oldPub.key.compositePub.len) != 0);
    ASSERT_TRUE(oldPrv.key.compositePrv.len != newPrv.key.compositePrv.len ||
        memcmp(oldPrv.key.compositePrv.data, newPrv.key.compositePrv.data, oldPrv.key.compositePrv.len) != 0);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(newVerify, &newPub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(oldVerify, mdId, oldMessage, sizeof(oldMessage) - 1, oldSign, oldSignLen),
        CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeyVerify(ctx, mdId, oldMessage, sizeof(oldMessage) - 1, oldSign, oldSignLen), CRYPT_SUCCESS);
    newSignLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    newSign = BSL_SAL_Malloc(newSignLen);
    ASSERT_TRUE(newSign != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, newMessage, sizeof(newMessage) - 1, newSign, &newSignLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(newVerify, mdId, newMessage, sizeof(newMessage) - 1, newSign, newSignLen), 0);

EXIT:
    BSL_SAL_Free(oldSign);
    BSL_SAL_Free(newSign);
    BSL_SAL_Free(oldPub.key.compositePub.data);
    BSL_SAL_Free(newPub.key.compositePub.data);
    BSL_SAL_ClearFree(oldPrv.key.compositePrv.data, oldPrv.key.compositePrv.len);
    BSL_SAL_ClearFree(newPrv.key.compositePrv.data, newPrv.key.compositePrv.len);
    CRYPT_EAL_PkeyFreeCtx(oldVerify);
    CRYPT_EAL_PkeyFreeCtx(newVerify);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_SIGN_VERIFY_MUTATION_TC001
 * @title Test Composite message, component and signature-length mutation matrix.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_SIGN_VERIFY_MUTATION_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    static const uint8_t emptyMessage = 0;
    static const uint8_t oneByteMessage[] = {0x00};
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *otherCtx = NULL;
    CRYPT_CompositeCtx *composite = NULL;
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);
    /* Five cases: NULL, empty, one byte, a valid message and a one-byte mutation. */
    const uint8_t *messages[5] = {NULL, &emptyMessage, oneByteMessage,
        (const uint8_t *)"composite mutation message", (const uint8_t *)"composite mutation messagf"};
    /* The two string messages are 27 bytes long, excluding their terminators. */
    const uint32_t messageLens[5] = {0, 0, 1, 27, 27};
    uint8_t *sign = NULL;
    uint8_t *mutated = NULL;
    uint32_t signLen = 0;
    uint32_t pqcSigLen = 0;
    uint32_t i;
    /* Four mutation offsets: first PQC byte, PQC boundary, first traditional byte and last byte. */
    uint32_t offsets[4] = {0};

    TestMemInit();
    TestRandInit();
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    otherCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL && otherCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(otherCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(otherCtx), CRYPT_SUCCESS);
    signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_TRUE(signLen > 1);
    composite = (CRYPT_CompositeCtx *)ctx->key;
    ASSERT_TRUE(composite != NULL);
    ASSERT_TRUE(composite->info != NULL);
    pqcSigLen = composite->info->alg.sign.pqcSigLen;
    ASSERT_TRUE(pqcSigLen > 1);
    ASSERT_TRUE(pqcSigLen < signLen);
    sign = BSL_SAL_Malloc(signLen);
    mutated = BSL_SAL_Malloc(signLen + 1);
    ASSERT_TRUE(sign != NULL && mutated != NULL);

    signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, messages[3], messageLens[3], sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, messages[3], messageLens[3], sign, signLen), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeyVerify(otherCtx, mdId, messages[3], messageLens[3], sign, signLen), CRYPT_SUCCESS);
    for (i = 0; i < sizeof(messages) / sizeof(messages[0]); i++) {
        signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
        ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, messages[i], messageLens[i], sign, &signLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, messages[i], messageLens[i], sign, signLen), CRYPT_SUCCESS);
    }

    signLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, messages[3], messageLens[3], sign, &signLen), CRYPT_SUCCESS);
    offsets[0] = 0;
    offsets[1] = pqcSigLen - 1;
    offsets[2] = pqcSigLen;
    offsets[3] = signLen - 1;
    for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        (void)memcpy(mutated, sign, signLen);
        mutated[offsets[i]] ^= 0x01;
        ASSERT_NE(CRYPT_EAL_PkeyVerify(ctx, mdId, messages[3], messageLens[3], mutated, signLen), CRYPT_SUCCESS);
    }
    (void)memset(mutated, 0, signLen);
    ASSERT_NE(CRYPT_EAL_PkeyVerify(ctx, mdId, messages[3], messageLens[3], mutated, signLen), CRYPT_SUCCESS);
    (void)memset(mutated, 0xFF, signLen);
    ASSERT_NE(CRYPT_EAL_PkeyVerify(ctx, mdId, messages[3], messageLens[3], mutated, signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, messages[3], messageLens[3], sign, 0),
        CRYPT_COMPOSITE_INVALID_SIG_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, messages[3], messageLens[3], sign, pqcSigLen - 1),
        CRYPT_COMPOSITE_INVALID_SIG_LEN);
    ASSERT_NE(CRYPT_EAL_PkeyVerify(ctx, mdId, messages[3], messageLens[3], sign, pqcSigLen), CRYPT_SUCCESS);
    (void)memcpy(mutated, sign, signLen);
    ASSERT_NE(CRYPT_EAL_PkeyVerify(ctx, mdId, messages[3], messageLens[3], mutated, signLen + 1), CRYPT_SUCCESS);

EXIT:
    BSL_SAL_Free(sign);
    BSL_SAL_Free(mutated);
    CRYPT_EAL_PkeyFreeCtx(otherCtx);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_RAW_PREHASH_MATRIX_TC001
 * @title Test raw-message and pre-hashed-message paths with binary message patterns.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_RAW_PREHASH_MATRIX_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_MD_AlgId mdId = CRYPT_MD_MAX;
    const uint8_t *messages[4] = {NULL};
    uint32_t messageLens[4] = {0};
    uint8_t zeroMessage[32] = {0};
    uint8_t ffMessage[32] = {0};
    uint8_t leadingMessage[32] = {0};
    uint8_t trailingMessage[32] = {0};
    uint8_t digest[64] = {0};
    uint8_t *rawSign = NULL;
    uint8_t *prehashSign = NULL;
    uint32_t requiredSignLen = 0;
    uint32_t rawSignLen = 0;
    uint32_t prehashSignLen = 0;
    uint32_t digestLen = 0;
    uint32_t i;

    TestMemInit();
    TestRandInit();
    mdId = GetCompositeHashAlgId(type);
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);
    for (i = 0; i < sizeof(leadingMessage); i++) {
        leadingMessage[i] = (uint8_t)(i + 1);
        trailingMessage[i] = (uint8_t)(i + 1);
        ffMessage[i] = 0xFF;
    }
    leadingMessage[0] = 0x00;
    trailingMessage[sizeof(trailingMessage) - 1] = 0x00;
    messages[0] = zeroMessage;
    messages[1] = ffMessage;
    messages[2] = leadingMessage;
    messages[3] = trailingMessage;
    for (i = 0; i < sizeof(messageLens) / sizeof(messageLens[0]); i++) {
        messageLens[i] = sizeof(zeroMessage);
    }

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    requiredSignLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_TRUE(requiredSignLen > 0);
    rawSign = BSL_SAL_Malloc(requiredSignLen);
    prehashSign = BSL_SAL_Malloc(requiredSignLen);
    ASSERT_TRUE(rawSign != NULL);
    ASSERT_TRUE(prehashSign != NULL);

    for (i = 0; i < sizeof(messages) / sizeof(messages[0]); i++) {
        rawSignLen = requiredSignLen;
        ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, messages[i], messageLens[i], rawSign, &rawSignLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, messages[i], messageLens[i], rawSign, rawSignLen), CRYPT_SUCCESS);
        digestLen = sizeof(digest);
        ASSERT_EQ(CRYPT_EAL_Md(mdId, messages[i], messageLens[i], digest, &digestLen), CRYPT_SUCCESS);
        prehashSignLen = requiredSignLen;
        ASSERT_EQ(CRYPT_EAL_PkeySignData(ctx, digest, digestLen, prehashSign, &prehashSignLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(ctx, digest, digestLen, prehashSign, prehashSignLen), CRYPT_SUCCESS);
    }

EXIT:
    BSL_SAL_Free(rawSign);
    BSL_SAL_Free(prehashSign);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_CTX_MATRIX_TC001
 * @spec -
 * @title Test Composite context length and binary-content matrix.
 * @precon nan
 * @brief Set context values of length 0, 1, 254, 255 and 256, then sign and verify.
 * @expect Supported lengths preserve binary bytes and cross-context verification succeeds;
 *         length 256 is rejected without changing the previous context.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_CTX_MATRIX_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    static const uint8_t message[] = "composite context matrix";
    CRYPT_EAL_PkeyCtx *signCtx = NULL;
    CRYPT_EAL_PkeyCtx *verifyCtx = NULL;
    CRYPT_EAL_PkeyPub pub = {0};
    /* Context capacity is 255 bytes; 256 is the deliberately rejected boundary. */
    uint8_t context[256] = {0};
    uint8_t *sign = NULL;
    uint32_t signLen = 0;
    /* Exercise empty, one-byte, below-limit, limit and above-limit context lengths. */
    uint32_t contextLens[5] = {0, 1, 254, 255, 256};
    uint32_t i;
    int32_t ret;
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
    ASSERT_EQ(ExportCompositePubKey(signCtx, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(verifyCtx, &pub), CRYPT_SUCCESS);
    signLen = CRYPT_EAL_PkeyGetSignLen(signCtx);
    ASSERT_TRUE(signLen > 0);
    sign = BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(sign != NULL);
    (void)memset(context, 0, sizeof(context));
    for (i = 0; i < sizeof(contextLens) / sizeof(contextLens[0]); i++) {
        uint32_t contextLen = contextLens[i];
        (void)memset(context, (int)(i + 1), sizeof(context));
        ret = CRYPT_EAL_PkeyCtrl(signCtx, CRYPT_CTRL_SET_CTX_INFO,
            contextLen == 0 ? NULL : context, contextLen);
        if (contextLen == 256) {
            ASSERT_EQ(ret, CRYPT_COMPOSITE_KEYLEN_ERROR);
            signLen = CRYPT_EAL_PkeyGetSignLen(signCtx);
            ASSERT_EQ(CRYPT_EAL_PkeySign(signCtx, mdId, message, sizeof(message) - 1, sign, &signLen), CRYPT_SUCCESS);
            ASSERT_EQ(CRYPT_EAL_PkeyVerify(verifyCtx, mdId, message, sizeof(message) - 1, sign, signLen),
                CRYPT_SUCCESS);
            continue;
        }
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(verifyCtx, CRYPT_CTRL_SET_CTX_INFO, contextLen == 0 ? NULL : context, contextLen),
            CRYPT_SUCCESS);
        signLen = CRYPT_EAL_PkeyGetSignLen(signCtx);
        ASSERT_EQ(CRYPT_EAL_PkeySign(signCtx, mdId, message, sizeof(message) - 1, sign, &signLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(verifyCtx, mdId, message, sizeof(message) - 1, sign, signLen), CRYPT_SUCCESS);
    }

EXIT:
    BSL_SAL_Free(sign);
    BSL_SAL_FREE(pub.key.compositePub.data);
    CRYPT_EAL_PkeyFreeCtx(verifyCtx);
    CRYPT_EAL_PkeyFreeCtx(signCtx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_OUTPUT_BOUNDARY_TC001
 * @spec -
 * @title Test Composite signature output boundary and trailing sentinel handling.
 * @precon nan
 * @brief Exercise L-1, L and L+1 output capacities with a prefilled caller buffer.
 * @expect L-1 fails without changing output; L and L+1 succeed and bytes after the
 *         actual signature remain unchanged.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_OUTPUT_BOUNDARY_TC001(int type)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
    static const uint8_t message[] = "composite output boundary";
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t *sign = NULL;
    uint8_t *baseline = NULL;
    uint32_t requiredLen = 0;
    uint32_t signLen = 0;
    uint32_t i;
    uint32_t j;
    CRYPT_MD_AlgId mdId = GetCompositeHashAlgId(type);

    TestMemInit();
    TestRandInit();
    ASSERT_TRUE(mdId != CRYPT_MD_MAX);
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    requiredLen = CRYPT_EAL_PkeyGetSignLen(ctx);
    ASSERT_TRUE(requiredLen > 1);
    sign = BSL_SAL_Malloc(requiredLen + 1);
    baseline = BSL_SAL_Malloc(requiredLen + 1);
    ASSERT_TRUE(sign != NULL);
    ASSERT_TRUE(baseline != NULL);
    /* 0xA5 is the trailing sentinel used to detect writes beyond the signature. */
    (void)memset(sign, 0xA5, requiredLen + 1);
    (void)memcpy(baseline, sign, requiredLen + 1);
    signLen = requiredLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, message, sizeof(message) - 1, sign, &signLen),
        CRYPT_COMPOSITE_INVALID_SIG_LEN);
    ASSERT_EQ(signLen, requiredLen - 1);
    ASSERT_COMPARE("short output unchanged", sign, requiredLen + 1, baseline, requiredLen + 1);

    for (i = requiredLen; i <= requiredLen + 1; i++) {
        /* Refill the signature buffer and sentinel before each L/L+1 attempt. */
        (void)memset(sign, 0xA5, requiredLen + 1);
        signLen = i;
        ASSERT_EQ(CRYPT_EAL_PkeySign(ctx, mdId, message, sizeof(message) - 1, sign, &signLen), CRYPT_SUCCESS);
        ASSERT_TRUE(signLen > 0);
        ASSERT_TRUE(signLen <= requiredLen);
        for (j = signLen; j < requiredLen + 1; j++) {
            ASSERT_EQ(sign[j], 0xA5);
        }
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, mdId, message, sizeof(message) - 1, sign, signLen), CRYPT_SUCCESS);
    }

EXIT:
    BSL_SAL_Free(baseline);
    BSL_SAL_Free(sign);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
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
 * 2.Failed generation clears both component contexts, parameter information, and key lengths.
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
        const CRYPT_CompositeCtx *inner = ctx->key;
        ASSERT_TRUE(inner->pqcCtx == NULL && inner->tradCtx == NULL && inner->info == NULL);
        ASSERT_EQ(inner->pubLen, 0);
        ASSERT_EQ(inner->prvLen, 0);
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
    ASSERT_EQ(CRYPT_EAL_PkeySignData(ctx, digest, digestLen, sign, &shortSignLen),
        CRYPT_COMPOSITE_INVALID_SIG_LEN);
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
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
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
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
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
 * 5.Check RSA private-key versions 2 and -1 are rejected while version 1 is accepted.
 * @expect
 * 1.RSA4096 imports succeed.
 * 2.RSA3072 imports are rejected with CRYPT_COMPOSITE_ERR_BITS_MISMATCH.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_IMPORT_RSA_BITS_TC001(int type4096, int type3072)
{
    if (PkiSkipCompositeParaTest(type4096) || PkiSkipCompositeParaTest(type3072)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx4096Src = NULL;
    CRYPT_EAL_PkeyCtx *ctx4096Dst = NULL;
    CRYPT_EAL_PkeyCtx *ctxGoodPrv = NULL;
    CRYPT_EAL_PkeyCtx *ctx3072Src = NULL;
    CRYPT_EAL_PkeyCtx *ctx4096BadPub = NULL;
    CRYPT_EAL_PkeyCtx *ctx4096BadPrv = NULL;
    CRYPT_EAL_PkeyPub goodPub = {0};
    CRYPT_EAL_PkeyPub badPub = {0};
    CRYPT_EAL_PkeyPrv goodPrv = {0};
    CRYPT_EAL_PkeyPrv badPrv = {0};

    ctx4096Src = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ctx4096Dst = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ctxGoodPrv = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ctx3072Src = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ctx4096BadPub = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ctx4096BadPrv = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx4096Src != NULL);
    ASSERT_TRUE(ctx4096Dst != NULL);
    ASSERT_TRUE(ctxGoodPrv != NULL);
    ASSERT_TRUE(ctx3072Src != NULL);
    ASSERT_TRUE(ctx4096BadPub != NULL);
    ASSERT_TRUE(ctx4096BadPrv != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx4096Src, type4096), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx4096Dst, type4096), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctxGoodPrv, type4096), CRYPT_SUCCESS);
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
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctxGoodPrv, &goodPrv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx4096BadPub, &badPub), CRYPT_COMPOSITE_ERR_BITS_MISMATCH);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx4096BadPrv, &badPrv), CRYPT_COMPOSITE_ERR_BITS_MISMATCH);

    uint32_t pqcLen = ((const CRYPT_CompositeCtx *)ctx4096Src->key)->info->pqcPrvkeyLen;
    uint8_t *rsa = goodPrv.key.compositePrv.data + pqcLen;
    uint32_t versionOffset = 2 + ((rsa[1] & 0x80U) != 0 ? (rsa[1] & 0x7fU) : 0);
    ASSERT_TRUE(goodPrv.key.compositePrv.len > pqcLen + versionOffset + 2);
    ASSERT_EQ(rsa[versionOffset], 0x02);
    ASSERT_EQ(rsa[versionOffset + 1], 1);
    uint8_t invalidVersions[] = {2, 0xff};
    int32_t versionErrors[] = {CRYPT_DECODE_ASN1_BUFF_FAILED, BSL_ASN1_ERR_DECODE_INT};
    for (uint32_t i = 0; i < sizeof(invalidVersions); i++) {
        rsa[versionOffset + 2] = invalidVersions[i];
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx4096BadPrv, type4096), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx4096BadPrv, &goodPrv), versionErrors[i]);
    }
    rsa[versionOffset + 2] = 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx4096BadPrv, type4096), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx4096BadPrv, &goodPrv), CRYPT_SUCCESS);
    rsa[versionOffset + 2] = 0;

EXIT:
    BSL_SAL_Free(badPrv.key.compositePrv.data);
    BSL_SAL_Free(badPub.key.compositePub.data);
    BSL_SAL_Free(goodPrv.key.compositePrv.data);
    BSL_SAL_Free(goodPub.key.compositePub.data);
    CRYPT_EAL_PkeyFreeCtx(ctx4096BadPrv);
    CRYPT_EAL_PkeyFreeCtx(ctx4096BadPub);
    CRYPT_EAL_PkeyFreeCtx(ctx3072Src);
    CRYPT_EAL_PkeyFreeCtx(ctx4096Dst);
    CRYPT_EAL_PkeyFreeCtx(ctxGoodPrv);
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
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
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
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
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
 * @test SDV_CRYPTO_COMPOSITE_UNSUPPORTED_PARAM_TC001
 * @spec -
 * @title Test Composite rejects unsupported parameter IDs during SetParaById.
 * @precon nan
 * @brief
 * 1.Create direct and Provider Composite contexts.
 * 2.Call SetParaById with an unsupported parameter ID.
 * @expect
 * 1.SetParaById returns the expected error without installing parameters or component contexts.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_UNSUPPORTED_PARAM_TC001(int type, int expected)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    BslOidString *oid = BSL_OBJ_GetOID(type);
    ASSERT_TRUE(oid != NULL);
    ASSERT_EQ(BSL_OBJ_GetCID(oid), type);
    if (type == CRYPT_COMPOSITE_MLKEM1024_X448_SHA3_256) {
        const uint8_t expectedOid[] = {0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x41};
        ASSERT_COMPARE("X448 OID", oid->octs, oid->octetLen, expectedOid, sizeof(expectedOid));
    }
    for (int provider = 0; provider < 2; provider++) {
#ifdef HITLS_CRYPTO_PROVIDER
        ctx = provider ? CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_COMPOSITE,
            CRYPT_EAL_PKEY_UNKNOWN_OPERATE, NULL) : CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
#else
        if (provider != 0) {
            break;
        }
        ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
#endif
        ASSERT_TRUE(ctx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), expected);
        const CRYPT_CompositeCtx *inner = ctx->key;
        ASSERT_TRUE(inner->info == NULL && inner->pqcCtx == NULL && inner->tradCtx == NULL);
        CRYPT_EAL_PkeyFreeCtx(ctx);
        ctx = NULL;
    }

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
    if (PkiSkipCompositeParaTest(firstType) || PkiSkipCompositeParaTest(secondType)) {
        SKIP_TEST();
    }
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
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
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
    pqcSigLen = ((const CRYPT_CompositeCtx *)signCtx->key)->info->alg.sign.pqcSigLen;
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
 * @title Test Composite import rejects malformed EC components without duplicate Composite error entries.
 * @precon nan
 * @brief
 * 1.Generate one valid Composite key pair and export raw public/private keys.
 * 2.Corrupt the EC traditional public/private component encoding in the exported raw key.
 * 3.Import malformed keys through direct or Provider contexts, with the opposite SIGN key already set.
 * 4.Check failed imports clear both components and parameters, then reset parameters and retry valid keys.
 * 5.Reject trailing data after an ECPrivateKey that fits within the outer key-length bound.
 * @expect
 * 1.Malformed EC components return the expected errors during SetPub/SetPrv.
 * 2.The public-key error has two entries from ECC/EAL; the ASN.1 error has one necessary Composite entry.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_IMPORT_TRAD_PROFILE_TC001(int type, int provider)
{
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
#ifndef HITLS_CRYPTO_PROVIDER
    if (provider != 0) {
        SKIP_TEST();
    }
#endif
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

#ifdef HITLS_CRYPTO_PROVIDER
    if (provider != 0) {
        srcCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_COMPOSITE, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, NULL);
        badPubCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_COMPOSITE, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, NULL);
        badPrvCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_COMPOSITE, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, NULL);
    } else
#endif
    {
        srcCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
        badPubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
        badPrvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    }
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

    if (((const CRYPT_CompositeCtx *)srcCtx->key)->info->kind == CRYPT_COMPOSITE_KIND_SIGN) {
        ASSERT_EQ(CRYPT_EAL_PkeySetPrv(badPubCtx, &goodPrv), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeySetPub(badPrvCtx, &goodPub), CRYPT_SUCCESS);
    }
    pqcPubLen = ((const CRYPT_CompositeCtx *)srcCtx->key)->info->pqcPubkeyLen;
    pqcPrvLen = ((const CRYPT_CompositeCtx *)srcCtx->key)->info->pqcPrvkeyLen;
    badPub.key.compositePub.data[pqcPubLen] = 0x05U;
    badPrv.key.compositePrv.data[pqcPrvLen] = 0x31U;
    BSL_ERR_ClearError();
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(badPubCtx, &badPub), CRYPT_ECC_ERR_POINT_CODE);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ECC_ERR_POINT_CODE);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_ECC_ERR_POINT_CODE);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
    BSL_ERR_ClearError();
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(badPrvCtx, &badPrv), BSL_ASN1_ERR_TAG_EXPECTED);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_ASN1_ERR_TAG_EXPECTED);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);

    /* Omit optional curve parameters so the trailing byte passes the outer key-length bound. */
    uint8_t *ec = badPrv.key.compositePrv.data + pqcPrvLen;
    ASSERT_TRUE(goodPrv.key.compositePrv.len >= pqcPrvLen + 51);
    ASSERT_EQ(ec[1], 49);
    ASSERT_EQ(ec[39], 0xa0);
    ec[0] = 0x30;
    ec[1] = 37;
    ec[39] = 0;
    badPrv.key.compositePrv.len = pqcPrvLen + 40;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(badPrvCtx, type), CRYPT_SUCCESS);
    BSL_ERR_ClearError();
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(badPrvCtx, &badPrv), CRYPT_COMPOSITE_KEYLEN_ERROR);
    ASSERT_EQ(BSL_ERR_GetLastError(), CRYPT_COMPOSITE_KEYLEN_ERROR);
    ASSERT_EQ(BSL_ERR_GetLastError(), BSL_SUCCESS);
    badPrv.key.compositePrv.len = goodPrv.key.compositePrv.len;

    CRYPT_EAL_PkeyCtx *failedCtxs[] = {badPubCtx, badPrvCtx};
    for (uint32_t i = 0; i < sizeof(failedCtxs) / sizeof(failedCtxs[0]); i++) {
        const CRYPT_CompositeCtx *inner = failedCtxs[i]->key;
        ASSERT_EQ(inner->pqcCtx, NULL);
        ASSERT_EQ(inner->tradCtx, NULL);
        ASSERT_EQ(inner->info, NULL);
        ASSERT_EQ(inner->pubLen, 0);
        ASSERT_EQ(inner->prvLen, 0);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(failedCtxs[i], type), CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(badPubCtx, &goodPub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(badPrvCtx, &goodPrv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(badPubCtx, &badPub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(badPrvCtx, &badPrv), CRYPT_SUCCESS);
    ASSERT_COMPARE("recovered public key", badPub.key.compositePub.data, badPub.key.compositePub.len,
                   goodPub.key.compositePub.data, goodPub.key.compositePub.len);
    ASSERT_COMPARE("recovered private key", badPrv.key.compositePrv.data, badPrv.key.compositePrv.len,
                   goodPrv.key.compositePrv.data, goodPrv.key.compositePrv.len);

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
    if (PkiSkipCompositeParaTest(type)) {
        SKIP_TEST();
    }
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
 * @title Test Composite key samples support decode/encode/decode roundtrip.
 * @precon Composite public/private key samples are available.
 * @brief
 * 1.Decode Composite public/private key files.
 * 2.Check decoded key type, paraId, and raw key SHA-256 expectations.
 * 3.Re-encode the decoded keys and compare them with the original files.
 * 4.Decode the re-encoded keys and repeat the checks.
 * @expect
 * 1.Public/private key decode and re-encode succeed.
 * 2.Re-encoded bytes match the source files.
 * 3.Decoded roundtrip keys preserve the expected Composite paraId and raw-key digests.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_COMPOSITE_KEY_ROUNDTRIP_TC001(char *sampleDir, int expectParaId,
    Hex *expectPubRawSha256, Hex *expectPrvRawSha256)
{
    if (PkiSkipCompositeParaTest(expectParaId)) {
        SKIP_TEST();
    }
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
    TestRandInit();

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
    ASSERT_COMPARE("composite publickey roundtrip", pubEncode.data, pubEncode.dataLen, pubFile.data, pubFile.dataLen);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &pubEncode, NULL, 0, &pubRoundtrip),
        CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositeDecodedKey(pubRoundtrip, expectParaId), CRYPT_SUCCESS);
    ASSERT_EQ(CheckCompositePubRawSha256(pubRoundtrip, expectPubRawSha256), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(prvCtx, NULL, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &prvEncode),
        CRYPT_SUCCESS);
    ASSERT_COMPARE("composite privatekey roundtrip", prvEncode.data, prvEncode.dataLen, prvFile.data, prvFile.dataLen);
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
    TestRandDeInit();
#endif
}
/* END_CASE */

/* @
 * @test SDV_CRYPT_EAL_COMPOSITE_SIGN_VERIFY_ROUNDTRIP_TC001
 * @spec -
 * @title Test Composite sign/verify samples support positive cross verification.
 * @precon Composite key files, message, and signature samples are available.
 * @brief
 * 1.Decode Composite public/private key files.
 * 2.Verify the signature with the public key in openHiTLS.
 * 3.Sign the same message with the private key in openHiTLS.
 * 4.Verify the generated signature with the public key.
 * @expect
 * 1.Signature verification succeeds.
 * 2.openHiTLS signature generation succeeds.
 * 3.Generated signature verification succeeds.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_COMPOSITE_SIGN_VERIFY_ROUNDTRIP_TC001(char *sampleDir, int expectParaId, Hex *msg,
    Hex *sampleSignature)
{
    if (PkiSkipCompositeParaTest(expectParaId)) {
        SKIP_TEST();
    }
#if !defined(HITLS_CRYPTO_CODECSKEY) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_KEY_DECODE)
    (void)sampleDir;
    (void)expectParaId;
    (void)msg;
    (void)sampleSignature;
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

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pubCtx, mdId, msg->x, msg->len, sampleSignature->x, sampleSignature->len),
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
 * @test SDV_CRYPT_EAL_COMPOSITE_SIGN_COMPARE_VECTOR_DETRAND_TC001
 * @spec -
 * @title Test Composite deterministic signatures match reference bytes with and without ctxInfo.
 * @precon Composite key files, message, ctxInfo, and signature samples are available.
 * @brief
 * 1.Decode Composite public/private key files.
 * 2.Register deterministic random callbacks for Composite signing.
 * 3.Verify the no-context signature with the public key in openHiTLS.
 * 4.Reset deterministic randomness, sign the same message without ctxInfo, and compare bytes with the signature.
 * 5.Set the same ctxInfo on both verify/sign contexts.
 * 6.Verify the with-context signature, reset deterministic randomness, sign again, and compare bytes with the signature.
 * @expect
 * 1.Both signatures verify successfully.
 * 2.openHiTLS deterministic no-context and with-context signatures match the reference bytes exactly.
 * 3.Generated signatures verify successfully.
 * @prior nan
 * @auto FALSE
 @ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_COMPOSITE_SIGN_COMPARE_VECTOR_DETRAND_TC001(char *sampleDir, int expectParaId, Hex *ctxText,
                                                               Hex *msg, Hex *expectSignature,
                                                               Hex *expectSignatureWithCtx)
{
    if (PkiSkipCompositeParaTest(expectParaId)) {
        SKIP_TEST();
    }
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

static CRYPT_EAL_PkeyCtx *CompositeKemNewCtx(int provider)
{
    return provider ? CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_COMPOSITE, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, NULL) :
                      CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
}

static uint32_t CompositeKemCipherLen(int type)
{
    switch (type) {
        case CRYPT_COMPOSITE_MLKEM768_RSA2048_SHA3_256:
            return 1344;
        case CRYPT_COMPOSITE_MLKEM768_RSA3072_SHA3_256:
            return 1472;
        case CRYPT_COMPOSITE_MLKEM768_RSA4096_SHA3_256:
            return 1600;
        case CRYPT_COMPOSITE_MLKEM768_X25519_SHA3_256:
            return 1120;
        case CRYPT_COMPOSITE_MLKEM768_ECDH_P256_SHA3_256:
        case CRYPT_COMPOSITE_MLKEM768_ECDH_BRAINPOOLP256R1_SHA3_256:
            return 1153;
        case CRYPT_COMPOSITE_MLKEM768_ECDH_P384_SHA3_256:
            return 1185;
        case CRYPT_COMPOSITE_MLKEM1024_RSA3072_SHA3_256:
            return 1952;
        case CRYPT_COMPOSITE_MLKEM1024_ECDH_P384_SHA3_256:
        case CRYPT_COMPOSITE_MLKEM1024_ECDH_BRAINPOOLP384R1_SHA3_256:
            return 1665;
        case CRYPT_COMPOSITE_MLKEM1024_ECDH_P521_SHA3_256:
            return 1701;
        default:
            return 0;
    }
}

static bool CompositeKemDisabled(int type)
{
    (void)type;
#if !defined(HITLS_CRYPTO_COMPOSITE_KEM) || !defined(HITLS_CRYPTO_MLKEM) || !defined(HITLS_CRYPTO_SHA3)
    return true;
#else
    switch (type) {
#if defined(HITLS_CRYPTO_RSA) && defined(HITLS_CRYPTO_RSAES_OAEP) && defined(HITLS_CRYPTO_SHA256)
        case CRYPT_COMPOSITE_MLKEM768_RSA2048_SHA3_256:
        case CRYPT_COMPOSITE_MLKEM768_RSA3072_SHA3_256:
        case CRYPT_COMPOSITE_MLKEM768_RSA4096_SHA3_256:
        case CRYPT_COMPOSITE_MLKEM1024_RSA3072_SHA3_256:
            return false;
#endif
#ifdef HITLS_CRYPTO_X25519
        case CRYPT_COMPOSITE_MLKEM768_X25519_SHA3_256:
            return false;
#endif
#ifdef HITLS_CRYPTO_ECDH
#ifdef HITLS_CRYPTO_CURVE_NISTP256
        case CRYPT_COMPOSITE_MLKEM768_ECDH_P256_SHA3_256:
            return false;
#endif
#ifdef HITLS_CRYPTO_CURVE_NISTP384
        case CRYPT_COMPOSITE_MLKEM768_ECDH_P384_SHA3_256:
        case CRYPT_COMPOSITE_MLKEM1024_ECDH_P384_SHA3_256:
            return false;
#endif
#ifdef HITLS_CRYPTO_CURVE_BP256R1
        case CRYPT_COMPOSITE_MLKEM768_ECDH_BRAINPOOLP256R1_SHA3_256:
            return false;
#endif
#ifdef HITLS_CRYPTO_CURVE_BP384R1
        case CRYPT_COMPOSITE_MLKEM1024_ECDH_BRAINPOOLP384R1_SHA3_256:
            return false;
#endif
#ifdef HITLS_CRYPTO_CURVE_NISTP521
        case CRYPT_COMPOSITE_MLKEM1024_ECDH_P521_SHA3_256:
            return false;
#endif
#endif
        default:
            return true;
    }
#endif
}

#ifdef HITLS_CRYPTO_COMPOSITE_KEM
static bool CompositeKemCapabilities(CRYPT_EAL_PkeyCtx *src, CRYPT_EAL_PkeyCtx *pubCtx)
{
    bool success = false;
    uint8_t sig[64];
    uint32_t sigLen = sizeof(sig);
    uint8_t pubBuf[1] = {0};
#ifdef HITLS_CRYPTO_COMPOSITE_SIGN
    int32_t signRet = CRYPT_NOT_SUPPORT;
#else
    int32_t signRet = CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
    ASSERT_EQ(CRYPT_EAL_PkeySign(src, CRYPT_MD_SHA256, pubBuf, 1, sig, &sigLen), signRet);
    ASSERT_EQ(CRYPT_EAL_PkeySignData(src, pubBuf, 32, sig, &sigLen), signRet);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(src, CRYPT_MD_SHA256, pubBuf, 1, sig, sizeof(sig)), signRet);
    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(src, pubBuf, 32, sig, sizeof(sig)), signRet);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(src, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecapsInit(src, NULL), CRYPT_SUCCESS);
    sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(src, pubBuf, 1, sig, &sigLen), CRYPT_EAL_ALG_NOT_SUPPORT);
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(src, pubBuf, 1, sig, &sigLen), CRYPT_EAL_ALG_NOT_SUPPORT);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(src, pubCtx, sig, &sigLen), CRYPT_EAL_ALG_NOT_SUPPORT);
    success = true;
EXIT:
    return success;
}

static bool CompositeKemReplaceKeys(CRYPT_EAL_PkeyCtx *src, CRYPT_EAL_PkeyCtx *pubCtx,
    CRYPT_EAL_PkeyCtx *prvCtx, const CRYPT_EAL_PkeyPub *pub, const CRYPT_EAL_PkeyPrv *prv, int type, int provider)
{
    bool success = false;
    uint8_t exportBuf[3000];
    CRYPT_EAL_PkeyCtx *mixed = NULL;
#ifndef HITLS_CRYPTO_COMPOSITE_CHECK
    (void)prvCtx;
#endif
    ASSERT_EQ(CRYPT_EAL_PkeyGen(src), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyPub replaced = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePub = {exportBuf, sizeof(exportBuf)}};
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(src, &replaced), CRYPT_SUCCESS);
    ASSERT_TRUE(replaced.key.compositePub.len != pub->key.compositePub.len ||
                ConstTimeMemcmp(exportBuf, pub->key.compositePub.data, replaced.key.compositePub.len) != UINT32_MAX);
#ifdef HITLS_CRYPTO_COMPOSITE_CHECK
    ASSERT_NE(CRYPT_EAL_PkeyPairCheck(src, prvCtx), CRYPT_SUCCESS);
#endif
    CRYPT_EAL_PkeyPrv replacedPrv = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePrv = {exportBuf, sizeof(exportBuf)}};
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(src, &replacedPrv), CRYPT_SUCCESS);
    memcpy(exportBuf, prv->key.compositePrv.data, 64); /* Replace only the traditional private key. */
    mixed = CompositeKemNewCtx(provider);
    ASSERT_TRUE(mixed != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(mixed, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(mixed, &replacedPrv), CRYPT_SUCCESS);
    uint8_t cipher[1952];
    uint8_t secret[32];
    uint8_t recovered[32];
    uint32_t cipherLen = sizeof(cipher);
    uint32_t secretLen = sizeof(secret);
    uint32_t recoveredLen = sizeof(recovered);
    TestErrClear();
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(pubCtx, cipher, &cipherLen, secret, &secretLen), CRYPT_SUCCESS);
    int32_t wrongKeyRet = CRYPT_EAL_PkeyDecaps(src, cipher, cipherLen, recovered, &recoveredLen);
    ASSERT_TRUE(wrongKeyRet != CRYPT_SUCCESS || ConstTimeMemcmp(secret, recovered, sizeof(secret)) != UINT32_MAX);
    recoveredLen = sizeof(recovered);
    wrongKeyRet = CRYPT_EAL_PkeyDecaps(mixed, cipher, cipherLen, recovered, &recoveredLen);
    ASSERT_TRUE(wrongKeyRet != CRYPT_SUCCESS || ConstTimeMemcmp(secret, recovered, sizeof(secret)) != UINT32_MAX);
    success = true;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(mixed);
    BSL_SAL_CleanseData(exportBuf, sizeof(exportBuf));
    return success;
}

static bool CompositeKemImportedTradKey(CRYPT_EAL_PkeyCtx *src, CRYPT_EAL_PkeyCtx *pubCtx,
    CRYPT_EAL_PkeyCtx *prvCtx, CRYPT_EAL_PkeyCtx *dup)
{
    bool success = false;
    uint8_t exportBuf[3000];
    const CRYPT_CompositeCtx *inner = src->key;
    BSL_Buffer tradPub = {0};
    BSL_Buffer importedTradPub = {0};
    int32_t ret = CRYPT_CompositeGetTradPubKey(src->key, &tradPub);
    if (ret == CRYPT_SUCCESS) {
        ret = CRYPT_CompositeGetTradPubKey(prvCtx->key, &importedTradPub);
    }
    bool pubEqual = ret == CRYPT_SUCCESS && tradPub.dataLen == importedTradPub.dataLen &&
                    memcmp(tradPub.data, importedTradPub.data, tradPub.dataLen) == 0;
    BSL_SAL_Free(tradPub.data);
    BSL_SAL_Free(importedTradPub.data);
    ASSERT_TRUE(pubEqual);
    if (inner->info->tradAlg == CRYPT_PKEY_RSA) {
        int32_t padding = 0;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(((CRYPT_CompositeCtx *)dup->key)->tradCtx, CRYPT_CTRL_GET_RSA_PADDING, &padding,
                                     sizeof(padding)),
                  CRYPT_SUCCESS);
        ASSERT_EQ(padding, CRYPT_RSAES_OAEP);
        uint8_t plaintext[32] = {0};
        uint8_t ciphertext[512];
        uint32_t cipherLen = sizeof(ciphertext);
        uint32_t plainLen = sizeof(exportBuf);
        ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(((CRYPT_CompositeCtx *)pubCtx->key)->tradCtx, plaintext, sizeof(plaintext),
                                        ciphertext, &cipherLen),
                  CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(((CRYPT_CompositeCtx *)dup->key)->tradCtx, ciphertext, cipherLen, exportBuf,
                                        &plainLen),
                  CRYPT_SUCCESS);
        ASSERT_EQ(plainLen, sizeof(plaintext));
        ASSERT_EQ(ConstTimeMemcmp(plaintext, exportBuf, plainLen), UINT32_MAX);
    }
    success = true;
EXIT:
    BSL_SAL_CleanseData(exportBuf, sizeof(exportBuf));
    return success;
}

static bool CheckCompositeKemExchange(CRYPT_EAL_PkeyCtx *pubCtx, CRYPT_EAL_PkeyCtx *prvCtx)
{
    bool success = false;
    uint8_t cipher[1952];
    uint8_t secret[32];
    uint8_t recovered[32];
    uint32_t cipherLen = sizeof(cipher);
    uint32_t secretLen = sizeof(secret);
    uint32_t recoveredLen = sizeof(recovered);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(pubCtx, cipher, &cipherLen, secret, &secretLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(prvCtx, cipher, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
    ASSERT_EQ(secretLen, sizeof(secret));
    ASSERT_EQ(recoveredLen, secretLen);
    ASSERT_COMPARE("shared secret", recovered, recoveredLen, secret, secretLen);
    success = true;
EXIT:
    BSL_SAL_CleanseData(secret, sizeof(secret));
    BSL_SAL_CleanseData(recovered, sizeof(recovered));
    return success;
}

static bool CompositeKemLifecycle(CRYPT_EAL_PkeyCtx *src, CRYPT_EAL_PkeyCtx *pubCtx,
    CRYPT_EAL_PkeyCtx *prvCtx, const CRYPT_EAL_PkeyPrv *prv)
{
    bool success = false;
    CRYPT_EAL_PkeyCtx *dup = NULL;
    uint8_t exportBuf[3000];
    uint8_t cipher[1952];
    uint8_t secret[32];
    uint8_t recovered[32];
    uint32_t cipherLen = sizeof(cipher);
    uint32_t secretLen = sizeof(secret);
    uint32_t recoveredLen = sizeof(recovered);
    dup = CRYPT_EAL_PkeyDupCtx(prvCtx);
    ASSERT_TRUE(dup != NULL);
    ASSERT_TRUE(((CRYPT_CompositeCtx *)dup->key)->tradCtx != ((CRYPT_CompositeCtx *)prvCtx->key)->tradCtx);
    CRYPT_EAL_PkeyCtx *pubDup = CRYPT_EAL_PkeyDupCtx(pubCtx);
    ASSERT_TRUE(pubDup != NULL);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    pubCtx = pubDup;
    BSL_Param exportParams[] = {{CRYPT_PARAM_COMPOSITE_PRVKEY, BSL_PARAM_TYPE_OCTETS, exportBuf, sizeof(exportBuf), 0},
                                BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(dup, exportParams), CRYPT_SUCCESS);
    ASSERT_EQ(exportParams[0].useLen, prv->key.compositePrv.len);
    ASSERT_EQ(ConstTimeMemcmp(exportBuf, prv->key.compositePrv.data, exportParams[0].useLen), UINT32_MAX);
    ASSERT_TRUE(CheckCompositeKemExchange(src, src));
    cipherLen = sizeof(cipher);
    secretLen = sizeof(secret);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(pubCtx, cipher, &cipherLen, secret, &secretLen), CRYPT_SUCCESS);
    recoveredLen = sizeof(recovered);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(prvCtx, cipher, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
    ASSERT_EQ(ConstTimeMemcmp(secret, recovered, sizeof(secret)), UINT32_MAX);
    recoveredLen = sizeof(recovered);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(dup, cipher, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
    ASSERT_EQ(ConstTimeMemcmp(secret, recovered, sizeof(secret)), UINT32_MAX);
    ASSERT_EQ(CRYPT_EAL_PkeyUpRef(prvCtx), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    recoveredLen = sizeof(recovered);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(prvCtx, cipher, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
    ASSERT_EQ(ConstTimeMemcmp(secret, recovered, sizeof(secret)), UINT32_MAX);
    ASSERT_TRUE(CheckCompositeKemExchange(prvCtx, dup));
    recoveredLen = sizeof(recovered);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(pubCtx, cipher, sizeof(cipher), recovered, &recoveredLen),
        CRYPT_COMPOSITE_KEY_NOT_SET);
    cipherLen = sizeof(cipher);
    secretLen = sizeof(secret);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(pubCtx, cipher, &cipherLen, secret, &secretLen), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyFreeCtx(src);
    src = NULL;
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    prvCtx = NULL;
    TestErrClear();
    recoveredLen = sizeof(recovered);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(dup, cipher, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
    ASSERT_EQ(ConstTimeMemcmp(secret, recovered, sizeof(secret)), UINT32_MAX);
    uint8_t previous[1952];
    memcpy(previous, cipher, cipherLen);
    cipherLen = sizeof(cipher);
    secretLen = sizeof(secret);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(dup, cipher, &cipherLen, secret, &secretLen), CRYPT_SUCCESS);
    ASSERT_NE(ConstTimeMemcmp(previous, cipher, cipherLen), UINT32_MAX);
    recoveredLen = sizeof(recovered);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(dup, cipher, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
    ASSERT_EQ(ConstTimeMemcmp(secret, recovered, sizeof(secret)), UINT32_MAX);
    ASSERT_TRUE(TestIsErrStackEmpty());
    success = true;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(dup);
    CRYPT_EAL_PkeyFreeCtx(src);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    BSL_SAL_CleanseData(exportBuf, sizeof(exportBuf));
    BSL_SAL_CleanseData(secret, sizeof(secret));
    BSL_SAL_CleanseData(recovered, sizeof(recovered));
    return success;
}
#endif

/* @
 * @test SDV_CRYPTO_COMPOSITE_KEM_KEYMGMT_TC001
 * @brief Generate and independently import KEM keys through direct and Provider contexts,
 *        check pairing, canonical exports, duplication, and rejected mixed imports/signing.
 * @expect Private-key imports recover the Composite public key and support both encapsulation and decapsulation.
 * @precon nan
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_KEM_KEYMGMT_TC001(int type, int provider, int useEx)
{
#ifndef HITLS_CRYPTO_COMPOSITE_KEM
    (void)type;
    (void)provider;
    (void)useEx;
    SKIP_TEST();
#else
    if (CompositeKemDisabled(type)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *src = NULL;
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    uint8_t pubBuf[2300];
    uint8_t prvBuf[3000];
    uint32_t length = 0;
    CRYPT_EAL_PkeyPub pub = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePub = {pubBuf, sizeof(pubBuf)}};
    CRYPT_EAL_PkeyPrv prv = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePrv = {prvBuf, sizeof(prvBuf)}};
    src = CompositeKemNewCtx(provider);
    pubCtx = CompositeKemNewCtx(provider);
    prvCtx = CompositeKemNewCtx(!provider);
    ASSERT_TRUE(src != NULL && pubCtx != NULL && prvCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(src, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvCtx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &length, sizeof(length)), CRYPT_SUCCESS);
    const CRYPT_CompositeCtx *inner = src->key;
    ASSERT_EQ(inner->info->kind, CRYPT_COMPOSITE_KIND_KEM);
    ASSERT_EQ(length, CompositeKemCipherLen(type));
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, CRYPT_CTRL_GET_SHARED_KEY_LEN, &length, sizeof(length)), CRYPT_SUCCESS);
    ASSERT_EQ(length, 32);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, CRYPT_CTRL_SET_CTX_INFO, NULL, 0), CRYPT_NOT_SUPPORT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, CRYPT_CTRL_GET_SIGNLEN, &length, sizeof(length)), CRYPT_NOT_SUPPORT);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(src), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(src, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(src, &prv), CRYPT_SUCCESS);
    BSL_Param pubParams[] = {{CRYPT_PARAM_COMPOSITE_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubBuf, pub.key.compositePub.len, 0},
                             BSL_PARAM_END};
    BSL_Param prvParams[] = {{CRYPT_PARAM_COMPOSITE_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvBuf, prv.key.compositePrv.len, 0},
                             BSL_PARAM_END};
    ASSERT_EQ(useEx ? CRYPT_EAL_PkeySetPubEx(pubCtx, pubParams) : CRYPT_EAL_PkeySetPub(pubCtx, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(useEx ? CRYPT_EAL_PkeySetPrvEx(prvCtx, prvParams) : CRYPT_EAL_PkeySetPrv(prvCtx, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pubCtx, &prv), CRYPT_COMPOSITE_KEY_REPEATED_SET);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(prvCtx, &pub), CRYPT_COMPOSITE_KEY_REPEATED_SET);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(pubCtx, pubParams), CRYPT_COMPOSITE_KEY_REPEATED_SET);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(prvCtx, prvParams), CRYPT_COMPOSITE_KEY_REPEATED_SET);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(src, &pub), CRYPT_COMPOSITE_KEY_REPEATED_SET);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(src, &prv), CRYPT_COMPOSITE_KEY_REPEATED_SET);
    uint8_t importedPub[2300];
    CRYPT_EAL_PkeyPub derived = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePub = {importedPub, sizeof(importedPub)}};
    BSL_Param derivedParams[] = {{CRYPT_PARAM_COMPOSITE_PUBKEY, BSL_PARAM_TYPE_OCTETS,
                                  importedPub, sizeof(importedPub), 0}, BSL_PARAM_END};
    ASSERT_EQ(useEx ? CRYPT_EAL_PkeyGetPubEx(prvCtx, derivedParams) : CRYPT_EAL_PkeyGetPub(prvCtx, &derived),
              CRYPT_SUCCESS);
    ASSERT_COMPARE("recovered public key", importedPub,
        useEx ? derivedParams[0].useLen : derived.key.compositePub.len, pubBuf, pub.key.compositePub.len);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(prvCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &length, sizeof(length)), CRYPT_SUCCESS);
    ASSERT_EQ(length, pub.key.compositePub.len);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pubCtx, &prv), CRYPT_COMPOSITE_KEY_NOT_SET);
#ifdef HITLS_CRYPTO_COMPOSITE_CHECK
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), CRYPT_SUCCESS);
#endif
    ASSERT_TRUE(CompositeKemImportedTradKey(src, pubCtx, prvCtx, prvCtx));
    ASSERT_TRUE(CompositeKemCapabilities(src, pubCtx));
    ASSERT_TRUE(CompositeKemReplaceKeys(src, pubCtx, prvCtx, &pub, &prv, type, provider));
    bool lifecycleOk = CompositeKemLifecycle(src, pubCtx, prvCtx, &prv);
    src = NULL;
    pubCtx = NULL;
    prvCtx = NULL;
    ASSERT_TRUE(lifecycleOk);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(src);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    BSL_SAL_CleanseData(prvBuf, sizeof(prvBuf));
    TestRandDeInit();
#endif
}
/* END_CASE */

static bool CompositeKemExportBoundary(CRYPT_EAL_PkeyCtx *ctx, bool privateKey)
{
    bool success = false;
    uint8_t baseline[3000];
    uint8_t guarded[3002];
    CRYPT_EAL_PkeyPub pub = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePub = {baseline, sizeof(baseline)}};
    CRYPT_EAL_PkeyPrv prv = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePrv = {baseline, sizeof(baseline)}};
    ASSERT_EQ(privateKey ? CRYPT_EAL_PkeyGetPrv(ctx, &prv) : CRYPT_EAL_PkeyGetPub(ctx, &pub), CRYPT_SUCCESS);
    uint32_t length = privateKey ? prv.key.compositePrv.len : pub.key.compositePub.len;
    uint32_t capacities[] = {0, length - 1, length, length + 1};
    for (int useEx = 0; useEx < 2; useEx++) {
        for (uint32_t i = 0; i < 4; i++) {
            memset(guarded, 0xa5, sizeof(guarded));
            pub.key.compositePub = (CRYPT_CompositePub){guarded + 1, capacities[i]};
            prv.key.compositePrv = (CRYPT_CompositePrv){guarded + 1, capacities[i]};
            BSL_Param params[] = {{privateKey ? CRYPT_PARAM_COMPOSITE_PRVKEY : CRYPT_PARAM_COMPOSITE_PUBKEY,
                                   BSL_PARAM_TYPE_OCTETS, guarded + 1, capacities[i], 0},
                                  BSL_PARAM_END};
            int32_t ret = privateKey ? (useEx ? CRYPT_EAL_PkeyGetPrvEx(ctx, params) : CRYPT_EAL_PkeyGetPrv(ctx, &prv)) :
                                       (useEx ? CRYPT_EAL_PkeyGetPubEx(ctx, params) : CRYPT_EAL_PkeyGetPub(ctx, &pub));
            ASSERT_EQ(ret, i < 2 ? CRYPT_COMPOSITE_LEN_NOT_ENOUGH : CRYPT_SUCCESS);
            ASSERT_EQ(guarded[0], 0xa5);
            ASSERT_EQ(guarded[length + 1], 0xa5);
            if (i >= 2) {
                ASSERT_EQ(useEx ? params[0].useLen : (privateKey ? prv.key.compositePrv.len : pub.key.compositePub.len),
                          length);
                ASSERT_EQ(ConstTimeMemcmp(guarded + 1, baseline, length), UINT32_MAX);
            } else {
                for (uint32_t j = 0; j < sizeof(guarded); j++) {
                    ASSERT_EQ(guarded[j], 0xa5);
                }
            }
        }
    }
    success = true;
EXIT:
    BSL_SAL_CleanseData(baseline, sizeof(baseline));
    BSL_SAL_CleanseData(guarded, sizeof(guarded));
    return success;
}

#ifdef HITLS_CRYPTO_COMPOSITE_KEM
static bool CompositeKemManagementArgs(CRYPT_EAL_PkeyCtx *ctx, int type)
{
    bool success = false;
    CRYPT_EAL_PkeyCtx *copy = NULL;
    uint32_t length = 0;
    uint8_t scratch[3000];
    CRYPT_EAL_PkeyPub pub = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePub = {scratch, sizeof(scratch)}};
    CRYPT_EAL_PkeyPrv prv = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePrv = {scratch, sizeof(scratch)}};
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    copy = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(copy != NULL);
    CRYPT_EAL_PkeyFreeCtx(copy);
    copy = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetParaId(ctx), type);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pub), CRYPT_COMPOSITE_KEY_NOT_SET);
    uint8_t expectedOid[] = {0x2b, 0x06, 0x01, 0x05,
                             0x05, 0x07, 0x06, (uint8_t)(55 + type - CRYPT_COMPOSITE_MLKEM768_RSA2048_SHA3_256)};
    BslOidString *oid = BSL_OBJ_GetOID(type);
    ASSERT_TRUE(oid != NULL);
    ASSERT_COMPARE("KEM OID", oid->octs, oid->octetLen, expectedOid, sizeof(expectedOid));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prv), CRYPT_COMPOSITE_KEY_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_COMPOSITE_CTRL_INIT_REPEATED);
    copy = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(copy != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGetParaId(copy), type);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(copy, &pub), CRYPT_COMPOSITE_KEY_NOT_SET);
    CRYPT_EAL_PkeyFreeCtx(copy);
    copy = NULL;
    int controls[] = {CRYPT_CTRL_GET_PARAID, CRYPT_CTRL_GET_CIPHERTEXT_LEN, CRYPT_CTRL_GET_SHARED_KEY_LEN};
    for (uint32_t i = 0; i < 3; i++) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, controls[i], NULL, sizeof(length)), CRYPT_INVALID_ARG);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, controls[i], &length, 0), CRYPT_INVALID_ARG);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, controls[i], &length, sizeof(length) - 1), CRYPT_INVALID_ARG);
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, controls[i], &length, sizeof(length) + 1), CRYPT_INVALID_ARG);
    }
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(NULL, &pub), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(NULL, &prv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(NULL, &pub), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(NULL, &prv), CRYPT_NULL_INPUT);
    BSL_Param nullData[] = {{CRYPT_PARAM_COMPOSITE_PUBKEY, BSL_PARAM_TYPE_OCTETS, NULL, sizeof(scratch), 0},
                            BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, nullData), CRYPT_NULL_INPUT);
    nullData[0].key = CRYPT_PARAM_COMPOSITE_PRVKEY;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(ctx, nullData), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(NULL, nullData), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(NULL, nullData), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(NULL, nullData), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(NULL, nullData), CRYPT_NULL_INPUT);
    BSL_Param empty[] = {BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, empty), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(ctx, empty), CRYPT_NULL_INPUT);
    success = true;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(copy);
    return success;
}

static bool CompositeKemDecapsBounds(CRYPT_EAL_PkeyCtx *ctx, int type, uint8_t *cipher,
    uint32_t cipherLen, const uint8_t *secret)
{
    bool success = false;
    uint8_t recovered[34];
    uint8_t output[34];
    uint32_t outputLen = 0;
    uint32_t expected = CompositeKemCipherLen(type);
    uint32_t secretCaps[] = {0, 31, 32, 33};
    for (uint32_t r = 0; r < 4; r++) {
        memset(recovered, 0xa5, sizeof(recovered));
        uint32_t recoveredLen = secretCaps[r];
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, cipher + 1, cipherLen, recovered + 1, &recoveredLen),
                  r < 2 ? CRYPT_COMPOSITE_LEN_NOT_ENOUGH : CRYPT_SUCCESS);
        ASSERT_EQ(recoveredLen, r < 2 ? secretCaps[r] : 32);
        ASSERT_EQ(recovered[0], 0xa5);
        ASSERT_EQ(recovered[33], 0xa5);
        if (r >= 2) {
            ASSERT_EQ(ConstTimeMemcmp(secret + 1, recovered + 1, 32), UINT32_MAX);
        } else {
            for (uint32_t j = 0; j < sizeof(recovered); j++) {
                ASSERT_EQ(recovered[j], 0xa5);
            }
        }
    }
    for (int i = 0; i < 4; i++) {
        outputLen = sizeof(output);
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(i == 0 ? NULL : ctx, i == 1 ? NULL : cipher + 1, expected,
                                       i == 2 ? NULL : output, i == 3 ? NULL : &outputLen),
                  CRYPT_NULL_INPUT);
        ASSERT_EQ(outputLen, sizeof(output));
    }
    uint32_t pqcLength = type >= CRYPT_COMPOSITE_MLKEM1024_RSA3072_SHA3_256 ? 1568 : 1088;
    uint32_t badLengths[] = {0, pqcLength - 1, pqcLength, pqcLength + 1, expected - 1, expected + 1};
    for (uint32_t i = 0; i < sizeof(badLengths) / sizeof(badLengths[0]); i++) {
        outputLen = sizeof(output);
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, cipher + 1, badLengths[i], output, &outputLen),
                  CRYPT_COMPOSITE_KEYLEN_ERROR);
        ASSERT_EQ(outputLen, sizeof(output));
    }
    success = true;
EXIT:
    BSL_SAL_CleanseData(recovered, sizeof(recovered));
    BSL_SAL_CleanseData(output, sizeof(output));
    return success;
}

static bool CompositeKemOperationBounds(CRYPT_EAL_PkeyCtx *ctx, int type)
{
    bool success = false;
    uint8_t cipher[1954];
    uint8_t secret[34];
    uint32_t cipherLen = 0;
    uint32_t secretLen = 0;
    for (int i = 0; i < 5; i++) {
        cipherLen = sizeof(cipher);
        secretLen = sizeof(secret);
        ASSERT_EQ(CRYPT_EAL_PkeyEncaps(i == 0 ? NULL : ctx, i == 1 ? NULL : cipher, i == 2 ? NULL : &cipherLen,
                                       i == 3 ? NULL : secret, i == 4 ? NULL : &secretLen),
                  CRYPT_NULL_INPUT);
        ASSERT_EQ(cipherLen, sizeof(cipher));
        ASSERT_EQ(secretLen, sizeof(secret));
    }
    uint32_t expected = CompositeKemCipherLen(type);
    uint32_t cipherCaps[] = {0, expected - 1, expected, expected + 1};
    uint32_t secretCaps[] = {0, 31, 32, 33};
    for (uint32_t c = 0; c < 4; c++) {
        for (uint32_t s = 0; s < 4; s++) {
            memset(cipher, 0xa5, sizeof(cipher));
            memset(secret, 0xa5, sizeof(secret));
            cipherLen = cipherCaps[c];
            secretLen = secretCaps[s];
            int32_t ret = CRYPT_EAL_PkeyEncaps(ctx, cipher + 1, &cipherLen, secret + 1, &secretLen);
            ASSERT_EQ(ret, c < 2 || s < 2 ? CRYPT_COMPOSITE_LEN_NOT_ENOUGH : CRYPT_SUCCESS);
            ASSERT_EQ(cipherLen, ret == CRYPT_SUCCESS ? expected : cipherCaps[c]);
            ASSERT_EQ(secretLen, ret == CRYPT_SUCCESS ? 32 : secretCaps[s]);
            ASSERT_EQ(cipher[0], 0xa5);
            ASSERT_EQ(cipher[expected + 1], 0xa5);
            ASSERT_EQ(secret[0], 0xa5);
            ASSERT_EQ(secret[33], 0xa5);
            if (ret != CRYPT_SUCCESS) {
                for (uint32_t j = 0; j < sizeof(cipher); j++) {
                    ASSERT_EQ(cipher[j], 0xa5);
                }
                for (uint32_t j = 0; j < sizeof(secret); j++) {
                    ASSERT_EQ(secret[j], 0xa5);
                }
                continue;
            }
        }
    }
    ASSERT_TRUE(CompositeKemDecapsBounds(ctx, type, cipher, cipherLen, secret));
    success = true;
EXIT:
    BSL_SAL_CleanseData(secret, sizeof(secret));
    return success;
}
#endif

/* @
 * @test SDV_CRYPTO_COMPOSITE_KEM_API_TC001
 * @brief Check KEM management and operation pointers, states and exact output boundaries.
 * @expect Invalid calls preserve buffers; valid calls fill only the specified output region.
 * @precon nan
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_KEM_API_TC001(int type, int provider)
{
#ifndef HITLS_CRYPTO_COMPOSITE_KEM
    (void)type;
    (void)provider;
    SKIP_TEST();
#else
    if (CompositeKemDisabled(type)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = CompositeKemNewCtx(provider);
    uint8_t cipher[1954];
    uint8_t secret[34];
    uint32_t cipherLen = sizeof(cipher) - 2;
    uint32_t secretLen = 32;
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, cipher, &cipherLen, secret, &secretLen), CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    ASSERT_EQ(cipherLen, sizeof(cipher) - 2);
    ASSERT_EQ(secretLen, 32);
    ASSERT_TRUE(CompositeKemManagementArgs(ctx, type));
    cipherLen = sizeof(cipher);
    secretLen = sizeof(secret);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, cipher, &cipherLen, secret, &secretLen), CRYPT_COMPOSITE_KEY_NOT_SET);
    ASSERT_EQ(cipherLen, sizeof(cipher));
    ASSERT_EQ(secretLen, sizeof(secret));
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_TRUE(CompositeKemExportBoundary(ctx, false));
    ASSERT_TRUE(CompositeKemExportBoundary(ctx, true));
    BSL_Param empty[] = {BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, empty), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(ctx, empty), CRYPT_NULL_INPUT);
    ASSERT_TRUE(CompositeKemOperationBounds(ctx, type));

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_CleanseData(secret, sizeof(secret));
    TestRandDeInit();
#endif
}
/* END_CASE */

#ifdef HITLS_CRYPTO_COMPOSITE_KEM
static bool CheckCompositeKemInvalidImport(CRYPT_EAL_PkeyCtx *src, const CRYPT_EAL_PkeyPub *pub,
    const CRYPT_EAL_PkeyPrv *prv, int provider, bool privateKey)
{
    bool success = false;
    CRYPT_EAL_PkeyCtx *target = NULL;
    const CRYPT_CompositeCtx *inner = src->key;
    const uint8_t *good = privateKey ? prv->key.compositePrv.data : pub->key.compositePub.data;
    uint32_t goodLen = privateKey ? prv->key.compositePrv.len : pub->key.compositePub.len;
    uint32_t pqcLen = privateKey ? 64 : inner->info->pqcPubkeyLen;
    uint8_t bad[3000];
    uint32_t lengths[] = {0, pqcLen, goodLen - 1, sizeof(bad)};
    uint32_t scenarios = privateKey ? 5 : 6;
    for (uint32_t scenario = 0; scenario < scenarios; scenario++) {
        if (scenario == 4 && inner->info->tradAlg == CRYPT_PKEY_X25519) {
            continue;
        }
        target = CompositeKemNewCtx(provider);
        ASSERT_TRUE(target != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(target, inner->info->paramId), CRYPT_SUCCESS);
        memset(bad, 0, sizeof(bad));
        memcpy(bad, good, goodLen);
        uint32_t badLen = scenario < 4 ? lengths[scenario] : goodLen;
        if (scenario == 4) {
            bad[pqcLen] = privateKey || inner->info->tradAlg == CRYPT_PKEY_RSA ? 0xff : 0x02;
        } else if (scenario == 5) {
            memset(bad, 0xff, pqcLen);
        }
        BSL_Param params[] = {{privateKey ? CRYPT_PARAM_COMPOSITE_PRVKEY : CRYPT_PARAM_COMPOSITE_PUBKEY,
                               BSL_PARAM_TYPE_OCTETS, bad, badLen, 0}, BSL_PARAM_END};
        ASSERT_NE(privateKey ? CRYPT_EAL_PkeySetPrvEx(target, params) : CRYPT_EAL_PkeySetPubEx(target, params),
                  CRYPT_SUCCESS);
        ASSERT_EQ(((CRYPT_CompositeCtx *)target->key)->pubLen, 0);
        ASSERT_EQ(((CRYPT_CompositeCtx *)target->key)->prvLen, 0);
        if (((CRYPT_CompositeCtx *)target->key)->info == NULL) {
            ASSERT_EQ(((CRYPT_CompositeCtx *)target->key)->pqcCtx, NULL);
            ASSERT_EQ(((CRYPT_CompositeCtx *)target->key)->tradCtx, NULL);
            ASSERT_EQ(CRYPT_EAL_PkeySetParaById(target, inner->info->paramId), CRYPT_SUCCESS);
        }
        params[0].value = (uint8_t *)(uintptr_t)good;
        params[0].valueLen = goodLen;
        ASSERT_EQ(privateKey ? CRYPT_EAL_PkeySetPrvEx(target, params) : CRYPT_EAL_PkeySetPubEx(target, params),
                  CRYPT_SUCCESS);
        TestErrClear();
        ASSERT_TRUE(CheckCompositeKemExchange(privateKey ? src : target, privateKey ? target : src));
        ASSERT_TRUE(TestIsErrStackEmpty());
        CRYPT_EAL_PkeyFreeCtx(target);
        target = NULL;
    }
    success = true;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(target);
    BSL_SAL_CleanseData(bad, sizeof(bad));
    return success;
}

static bool CheckCompositeKemEcPointImport(CRYPT_EAL_PkeyCtx *src, const CRYPT_EAL_PkeyPub *pub, int provider)
{
    bool success = false;
    CRYPT_EAL_PkeyCtx *target = NULL;
    const CRYPT_CompositeCtx *inner = src->key;
    uint32_t pqcLen = inner->info->pqcPubkeyLen;
    uint32_t goodLen = pub->key.compositePub.len;
    uint8_t point[3000];
    uint8_t prefixes[] = {0x02, 0x06};
    for (uint32_t i = 0; i < sizeof(prefixes); i++) {
        target = CompositeKemNewCtx(provider);
        ASSERT_TRUE(target != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(target, inner->info->paramId), CRYPT_SUCCESS);
        memcpy(point, pub->key.compositePub.data, goodLen);
        point[pqcLen] = prefixes[i] | (point[goodLen - 1] & 1);
        uint32_t pointLen = i == 0 ? pqcLen + 1 + (goodLen - pqcLen - 1) / 2 : goodLen;
        BSL_Param params[] = {{CRYPT_PARAM_COMPOSITE_PUBKEY, BSL_PARAM_TYPE_OCTETS, point, pointLen, 0}, BSL_PARAM_END};
        ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(target, params), CRYPT_SUCCESS);
        CRYPT_EAL_PkeyPub normalized = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePub = {point, sizeof(point)}};
        ASSERT_EQ(CRYPT_EAL_PkeyGetPub(target, &normalized), CRYPT_SUCCESS);
        ASSERT_COMPARE("normalized public key", point, normalized.key.compositePub.len,
            pub->key.compositePub.data, goodLen);
        TestErrClear();
        ASSERT_TRUE(CheckCompositeKemExchange(target, src));
        ASSERT_TRUE(TestIsErrStackEmpty());
        CRYPT_EAL_PkeyFreeCtx(target);
        target = NULL;
    }
    success = true;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(target);
    return success;
}
#endif

/* @
 * @test SDV_CRYPTO_COMPOSITE_KEM_IMPORT_NEGATIVE_TC001
 * @brief Reject malformed raw component keys, reset failed contexts and retry valid imports in the same objects.
 * @expect Invalid imports publish no key; compatible RSA exponents and EC point encodings retain working KEM.
 * @precon nan
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_KEM_IMPORT_NEGATIVE_TC001(int type, int provider)
{
#ifndef HITLS_CRYPTO_COMPOSITE_KEM
    (void)type;
    (void)provider;
    SKIP_TEST();
#else
    if (CompositeKemDisabled(type)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *src = CompositeKemNewCtx(provider);
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    ASSERT_TRUE(src != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(src, type), CRYPT_SUCCESS);
    CRYPT_CompositeCtx *inner = src->key;
    if (inner->info->tradAlg == CRYPT_PKEY_RSA) {
        uint8_t e[] = {1, 0, 3};
        CRYPT_EAL_PkeyPara para = {.id = CRYPT_PKEY_RSA, .para.rsaPara = {e, sizeof(e), inner->info->bits}};
        ASSERT_EQ(CRYPT_EAL_PkeySetPara(inner->tradCtx, &para), CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_PkeyGen(src), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePubKey(src, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(ExportCompositePrvKey(src, &prv), CRYPT_SUCCESS);
    ASSERT_TRUE(CheckCompositeKemInvalidImport(src, &pub, &prv, provider, false));
    ASSERT_TRUE(CheckCompositeKemInvalidImport(src, &pub, &prv, provider, true));
    if (inner->info->tradAlg == CRYPT_PKEY_ECDH) {
        ASSERT_TRUE(CheckCompositeKemEcPointImport(src, &pub, provider));
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(src);
    BSL_SAL_Free(pub.key.compositePub.data);
    BSL_SAL_ClearFree(prv.key.compositePrv.data, prv.key.compositePrv.len);
    TestRandDeInit();
#endif
}
/* END_CASE */

static int32_t CompositeKemKeyFailCall(CRYPT_EAL_PkeyCtx *src, int type, int provider, int operation,
                                       CRYPT_EAL_PkeyPub *pub, CRYPT_EAL_PkeyPrv *prv, BSL_Buffer *encoded)
{
    CRYPT_EAL_PkeyCtx *target = NULL;
    uint8_t bytes[3000];
    BSL_Buffer output = {0};
    int32_t ret = CRYPT_SUCCESS;
    if (operation <= 3) {
        target = operation == 1 ? CRYPT_EAL_PkeyDupCtx(src) : CompositeKemNewCtx(provider);
        if (target == NULL) {
            return CRYPT_MEM_ALLOC_FAIL;
        }
        if (operation != 1) {
            ret = CRYPT_EAL_PkeySetParaById(target, type);
        }
        if (ret == CRYPT_SUCCESS && operation == 2) {
            ret = CRYPT_EAL_PkeySetPub(target, pub);
        } else if (ret == CRYPT_SUCCESS && operation == 3) {
            ret = CRYPT_EAL_PkeySetPrv(target, prv);
        }
    } else if (operation == 4) {
        CRYPT_EAL_PkeyPub key = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePub = {bytes, sizeof(bytes)}};
        ret = CRYPT_EAL_PkeyGetPub(src, &key);
    } else if (operation == 5) {
        CRYPT_EAL_PkeyPrv key = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePrv = {bytes, sizeof(bytes)}};
        ret = CRYPT_EAL_PkeyGetPrv(src, &key);
    } else if (operation == 6) {
        ret = CRYPT_EAL_EncodeBuffKey(src, NULL, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &output);
    } else {
        ret = provider ?
                  CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN, "ASN1", "PRIKEY_PKCS8_UNENCRYPT",
                                                  encoded, NULL, &target) :
                  CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, encoded, NULL, 0, &target);
        if (ret != CRYPT_SUCCESS && target != NULL) {
            ret = CRYPT_SUCCESS;
        }
    }
    if (operation == 3 && target != NULL && ret != CRYPT_SUCCESS) {
        CRYPT_CompositeCtx *inner = target->key;
        if (inner->pubLen != 0 || inner->prvLen != 0) {
            ret = CRYPT_SUCCESS;
        }
    }
    CRYPT_EAL_PkeyFreeCtx(target);
    BSL_SAL_ClearFree(output.data, output.dataLen);
    BSL_SAL_CleanseData(bytes, sizeof(bytes));
    return ret;
}

/* @
 * @test SDV_CRYPTO_COMPOSITE_KEM_KEYFAIL_TC001
 * @brief Inject allocations into management and codecs, then exercise the original long-term key.
 * @expect Failed temporary objects are released and the source key remains usable and unchanged.
 * @precon nan
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_KEM_KEYFAIL_TC001(int type, int provider)
{
#ifndef HITLS_CRYPTO_COMPOSITE_KEM
    (void)type;
    (void)provider;
    SKIP_TEST();
#else
    if (CompositeKemDisabled(type)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *src = CompositeKemNewCtx(provider);
    BSL_Buffer encoded = {0};
    uint8_t pubBytes[2400];
    uint8_t prvBytes[3000];
    uint8_t exported[3000];
    CRYPT_EAL_PkeyPub pub = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePub = {pubBytes, sizeof(pubBytes)}};
    CRYPT_EAL_PkeyPrv prv = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePrv = {prvBytes, sizeof(prvBytes)}};
    ASSERT_TRUE(src != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(src, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(src), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(src, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(src, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(src, NULL, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encoded),
              CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    for (int operation = 0; operation < 8; operation++) {
        STUB_EnableMallocFail(false);
        STUB_ResetMallocCount();
        ASSERT_EQ(CompositeKemKeyFailCall(src, type, provider, operation, &pub, &prv, &encoded), CRYPT_SUCCESS);
        uint32_t total = STUB_GetMallocCallCount();
        ASSERT_TRUE(total > 0);
        for (uint32_t i = 0; i < total; i++) {
            STUB_ResetMallocCount();
            STUB_SetMallocFailIndex(i);
            STUB_EnableMallocFail(true);
            int32_t ret = CompositeKemKeyFailCall(src, type, provider, operation, &pub, &prv, &encoded);
            STUB_EnableMallocFail(false);
            ASSERT_NE(ret, CRYPT_SUCCESS);
        }
        TestErrClear();
        ASSERT_EQ(CompositeKemKeyFailCall(src, type, provider, operation, &pub, &prv, &encoded), CRYPT_SUCCESS);
        CRYPT_EAL_PkeyPrv check = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePrv = {exported, sizeof(exported)}};
        ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(src, &check), CRYPT_SUCCESS);
        ASSERT_EQ(check.key.compositePrv.len, prv.key.compositePrv.len);
        ASSERT_EQ(ConstTimeMemcmp(exported, prvBytes, check.key.compositePrv.len), UINT32_MAX);
    }
    uint8_t cipher[1952];
    uint8_t secret[32];
    uint8_t recovered[32];
    uint32_t cipherLen = sizeof(cipher);
    uint32_t secretLen = sizeof(secret);
    uint32_t recoveredLen = sizeof(recovered);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(src, cipher, &cipherLen, secret, &secretLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(src, cipher, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
    ASSERT_EQ(ConstTimeMemcmp(secret, recovered, sizeof(secret)), UINT32_MAX);
    BSL_SAL_CleanseData(secret, sizeof(secret));
    BSL_SAL_CleanseData(recovered, sizeof(recovered));
EXIT:
    STUB_EnableMallocFail(false);
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_PkeyFreeCtx(src);
    BSL_SAL_ClearFree(encoded.data, encoded.dataLen);
    BSL_SAL_CleanseData(prvBytes, sizeof(prvBytes));
    BSL_SAL_CleanseData(exported, sizeof(exported));
    TestRandDeInit();
#endif
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_KEM_GENFAIL_TC001
 * @brief Inject each allocation failure into initial and repeated KEM generation, then check
 *        that both component contexts, parameters, and key lengths have been cleared.
 * @expect Failed generation preserves its error and leaves an object safe to destroy.
 * @precon nan
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_KEM_GENFAIL_TC001(int type, int regenerate)
{
    if (CompositeKemDisabled(type)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    CRYPT_RandRegist(CompositeDetRand);
    CRYPT_RandRegistEx(CompositeDetRandEx);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    uint32_t total = 0;
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(STUB_GetMallocCallCount() > 0);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    if (regenerate) {
        CompositeDetRandReset();
        ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    }
    STUB_ResetMallocCount();
    CompositeDetRandReset();
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    total = STUB_GetMallocCallCount();
    if (total == 0) {
        /* Some implementations generate keys without allocating heap memory. */
        SkipTest(__FILE__);
        goto EXIT;
    }
    CRYPT_EAL_PkeyFreeCtx(ctx);
    ctx = NULL;
    for (uint32_t i = 0; i < total; i++) {
        ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
        ASSERT_TRUE(ctx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
        if (regenerate) {
            CompositeDetRandReset();
            ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
        }
        CompositeDetRandReset();
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        STUB_EnableMallocFail(true);
        int32_t ret = CRYPT_EAL_PkeyGen(ctx);
        STUB_EnableMallocFail(false);
        ASSERT_NE(ret, CRYPT_SUCCESS);
        CRYPT_CompositeCtx *inner = ctx->key;
        ASSERT_TRUE(inner->pqcCtx == NULL && inner->tradCtx == NULL && inner->info == NULL);
        ASSERT_EQ(inner->pubLen, 0);
        ASSERT_EQ(inner->prvLen, 0);
        ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_COMPOSITE_KEYINFO_NOT_SET);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
        CompositeDetRandReset();
        ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
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

static int32_t g_compositeKemRandCall;
static int32_t g_compositeKemRandFail;

static int32_t CompositeKemFailRand(uint8_t *out, uint32_t len)
{
    if (g_compositeKemRandCall++ == g_compositeKemRandFail) {
        return CRYPT_INVALID_ARG;
    }
    return CompositeDetRandFill(out, len);
}

static int32_t CompositeKemFailRandEx(void *libCtx, uint8_t *out, uint32_t len)
{
    (void)libCtx;
    return CompositeKemFailRand(out, len);
}

/* @
 * @test SDV_CRYPTO_COMPOSITE_KEM_RANDFAIL_TC001
 * @brief Fail the random source in either component, including replacement of an existing key.
 * @expect The original component error is returned and all generated key state is destroyed.
 * @precon nan
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_KEM_RANDFAIL_TC001(int type, int component, int regenerate)
{
    if (CompositeKemDisabled(type)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    CRYPT_RandRegist(CompositeKemFailRand);
    CRYPT_RandRegistEx(CompositeKemFailRandEx);
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    g_compositeKemRandFail = -1;
    g_compositeKemRandCall = 0;
    CompositeDetRandReset();
    if (regenerate) {
        ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    }
    g_compositeKemRandFail = component;
    g_compositeKemRandCall = 0;
    int32_t expected =
        component == 1 && type != CRYPT_COMPOSITE_MLKEM768_X25519_SHA3_256 ? CRYPT_BN_RAND_GEN_FAIL : CRYPT_INVALID_ARG;
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), expected);
    CRYPT_CompositeCtx *inner = ctx->key;
    ASSERT_TRUE(inner->info == NULL && inner->pqcCtx == NULL && inner->tradCtx == NULL);
    ASSERT_EQ(inner->pubLen, 0);
    ASSERT_EQ(inner->prvLen, 0);
EXIT:
    g_compositeKemRandFail = -1;
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
}
/* END_CASE */

/* @
 * @test SDV_CRYPTO_COMPOSITE_CTRL_TC001
 * @brief Reject KEM controls on signature objects while preserving the pre-parameter
 *        signature context behavior; KEM rejects signature context controls.
 * @expect Existing signatures retain their contexts; KEM parameters reject signing context controls.
 * @precon nan
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_CTRL_TC001(void)
{
    if (PkiSkipCompositeParaTest(CRYPT_COMPOSITE_MLDSA44_ED25519_SHA512) ||
        CompositeKemDisabled(CRYPT_COMPOSITE_MLKEM768_X25519_SHA3_256)) {
        SKIP_TEST();
    }
    TestMemInit();
    CRYPT_EAL_PkeyCtx *sign = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    CRYPT_EAL_PkeyCtx *kem = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    uint32_t length = 0;
    uint8_t context[] = {1, 2, 3};
    ASSERT_TRUE(sign != NULL && kem != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(sign, CRYPT_CTRL_SET_CTX_INFO, context, sizeof(context)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(kem, CRYPT_CTRL_SET_CTX_INFO, context, sizeof(context)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(sign, CRYPT_COMPOSITE_MLDSA44_ED25519_SHA512), CRYPT_SUCCESS);
    ASSERT_EQ(((CRYPT_CompositeCtx *)sign->key)->info->kind, CRYPT_COMPOSITE_KIND_SIGN);
    ASSERT_EQ(((CRYPT_CompositeCtx *)sign->key)->ctxLen, sizeof(context));
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(sign, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &length, sizeof(length)), CRYPT_NOT_SUPPORT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(sign, CRYPT_CTRL_GET_SHARED_KEY_LEN, &length, sizeof(length)), CRYPT_NOT_SUPPORT);
#ifdef HITLS_CRYPTO_COMPOSITE_KEM
    uint8_t cipher[1120];
    uint8_t secret[32];
    uint32_t cipherLen = sizeof(cipher);
    uint32_t secretLen = sizeof(secret);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(sign, cipher, &cipherLen, secret, &secretLen), CRYPT_NOT_SUPPORT);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(sign, cipher, sizeof(cipher), secret, &secretLen), CRYPT_NOT_SUPPORT);
#endif
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(kem, CRYPT_COMPOSITE_MLKEM768_X25519_SHA3_256), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(kem, CRYPT_CTRL_SET_CTX_INFO, context, sizeof(context)), CRYPT_NOT_SUPPORT);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(sign);
    CRYPT_EAL_PkeyFreeCtx(kem);
}
/* END_CASE */

#if defined(HITLS_CRYPTO_COMPOSITE_KEM) && defined(HITLS_CRYPTO_KEY_ENCODE) && defined(HITLS_CRYPTO_KEY_DECODE)
static bool CompositeKemRejectDer(BSL_Buffer *encoded, int provider, int *types, const char **typeNames)
{
    bool success = false;
    CRYPT_EAL_PkeyCtx *invalidKey = NULL;
    uint8_t invalid[3100];
    BSL_Buffer bad = {0};
    for (uint32_t i = 0; i < 3; i++) {
        uint32_t algorithm = 0;
        while (algorithm < 24 && !(encoded[i].data[algorithm] == 0x30 && encoded[i].data[algorithm + 1] == 10 &&
                                   encoded[i].data[algorithm + 2] == 0x06)) {
            algorithm++;
        }
        ASSERT_TRUE(algorithm < 24);
        uint32_t insert = algorithm + 12;
        memcpy(invalid, encoded[i].data, insert);
        invalid[algorithm + 1] += 2;
        invalid[insert] = 0x05;
        invalid[insert + 1] = 0;
        memcpy(invalid + insert + 2, encoded[i].data + insert, encoded[i].dataLen - insert);
        if (i != 1) {
            if (invalid[1] == 0x82) {
                uint32_t length = ((uint32_t)invalid[2] << 8) + invalid[3] + 2;
                invalid[2] = (uint8_t)(length >> 8);
                invalid[3] = (uint8_t)length;
            } else if (invalid[1] == 0x81) {
                invalid[2] += 2;
            } else {
                invalid[1] += 2;
            }
        }
        bad = (BSL_Buffer){invalid, encoded[i].dataLen + 2};
        uint8_t parameterTags[] = {0x05, 0x06, 0x30};
        for (uint32_t parameter = 0; parameter < sizeof(parameterTags); parameter++) {
            invalid[insert] = parameterTags[parameter];
            ASSERT_NE(provider ? CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN, "ASN1", typeNames[i],
                                                                 &bad, NULL, &invalidKey) :
                                 CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, types[i], &bad, NULL, 0, &invalidKey),
                      CRYPT_SUCCESS);
            ASSERT_TRUE(invalidKey == NULL);
        }
        uint8_t badOids[] = {65, 127, 37}; /* Reserved KEM, unknown, and Composite SIGN OIDs. */
        for (uint32_t oid = 0; oid < sizeof(badOids); oid++) {
            memcpy(invalid, encoded[i].data, encoded[i].dataLen);
            invalid[algorithm + 11] = badOids[oid];
            bad = (BSL_Buffer){invalid, encoded[i].dataLen};
            ASSERT_NE(provider ? CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN, "ASN1", typeNames[i],
                                                                 &bad, NULL, &invalidKey) :
                                 CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, types[i], &bad, NULL, 0, &invalidKey),
                      CRYPT_SUCCESS);
            ASSERT_TRUE(invalidKey == NULL);
        }
        for (uint32_t truncation = 0; truncation < 3; truncation++) {
            bad = (BSL_Buffer){encoded[i].data, truncation == 0 ? 0 :
                                                truncation == 1 ? encoded[i].dataLen / 2 :
                                                                  encoded[i].dataLen - 1};
            ASSERT_NE(provider ? CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN, "ASN1", typeNames[i],
                                                                 &bad, NULL, &invalidKey) :
                                 CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, types[i], &bad, NULL, 0, &invalidKey),
                      CRYPT_SUCCESS);
            ASSERT_TRUE(invalidKey == NULL);
        }
    }
    success = true;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(invalidKey);
    return success;
}

static bool CompositeKemRejectPem(const BSL_Buffer *encoded, int provider)
{
    bool success = false;
    CRYPT_EAL_PkeyCtx *invalidKey = NULL;
    uint8_t invalid[3100];
    BSL_Buffer bad = {0};
    for (uint32_t mutation = 0; mutation < 3; mutation++) {
        ASSERT_TRUE(encoded[0].dataLen <= sizeof(invalid));
        memcpy(invalid, encoded[0].data, encoded[0].dataLen);
        bad = (BSL_Buffer){invalid, mutation == 2 ? 0 : encoded[0].dataLen};
        if (mutation == 0) {
            invalid[11] = 'X'; /* Invalid PUBLIC KEY label. */
        } else if (mutation == 1) {
            uint32_t start = 0;
            while (start < bad.dataLen && invalid[start] != '\n') {
                start++;
            }
            ASSERT_TRUE(start + 1 < bad.dataLen);
            invalid[start + 1] = '!'; /* Invalid Base64 character. */
        }
        ASSERT_NE(provider ? CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN, "PEM", "PUBKEY_SUBKEY", &bad,
                                                             NULL, &invalidKey) :
                             CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, CRYPT_PUBKEY_SUBKEY, &bad, NULL, 0, &invalidKey),
                  CRYPT_SUCCESS);
        ASSERT_TRUE(invalidKey == NULL);
    }

    success = true;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(invalidKey);
    return success;
}

static bool CompositeKemCodecRoundtrip(int type, int provider, int bufferFormat, int keyType, const char *typeName,
    BSL_Buffer *encoded, CRYPT_EAL_PkeyCtx **decoded)
{
    bool success = false;
    CRYPT_EAL_PkeyCtx *cross = NULL;
    BSL_Buffer reencoded = {0};
    if (provider) {
        ASSERT_EQ(CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN,
            bufferFormat == BSL_FORMAT_ASN1 ? "ASN1" : "PEM", typeName, encoded, NULL, decoded),
            CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(bufferFormat, keyType, encoded, NULL, 0, decoded),
            CRYPT_SUCCESS);
    }
    int32_t paraId = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetId(*decoded), CRYPT_PKEY_COMPOSITE);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(*decoded, CRYPT_CTRL_GET_PARAID, &paraId, sizeof(paraId)), CRYPT_SUCCESS);
    ASSERT_EQ(paraId, type);
    ASSERT_EQ(provider ? CRYPT_EAL_DecodeBuffKey(bufferFormat, keyType, encoded, NULL, 0, &cross) :
                         CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN,
                                                         bufferFormat == BSL_FORMAT_ASN1 ? "ASN1" : "PEM",
                                                         typeName, encoded, NULL, &cross),
              CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetParaId(cross), type);
    CRYPT_EAL_PkeyFreeCtx(*decoded);
    *decoded = cross;
    cross = NULL;
    ASSERT_EQ(keyType == CRYPT_PUBKEY_SUBKEY_WITHOUT_SEQ ? CRYPT_EAL_EncodePubKeyBuffInternal(*decoded, bufferFormat, CRYPT_PUBKEY_SUBKEY,
        false, &reencoded) :
        CRYPT_EAL_EncodeBuffKey(*decoded, NULL, bufferFormat, keyType, &reencoded), CRYPT_SUCCESS);
    ASSERT_EQ(reencoded.dataLen, encoded->dataLen);
    ASSERT_EQ(ConstTimeMemcmp(reencoded.data, encoded->data, encoded->dataLen), UINT32_MAX);
    BSL_SAL_ClearFree(reencoded.data, reencoded.dataLen);
    reencoded = (BSL_Buffer){0};
    success = true;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(cross);
    BSL_SAL_ClearFree(reencoded.data, reencoded.dataLen);
    return success;
}
#endif

/* @
 * @test SDV_CRYPTO_COMPOSITE_KEM_CODECS_TC001
 * @brief Round-trip KEM SPKI, SPKI without SEQUENCE and PKCS8 through existing codecs.
 * @expect Decoded public/private objects execute KEM and preserve canonical encodings.
 * @precon nan
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_KEM_CODECS_TC001(int type, int provider, int format)
{
    if (CompositeKemDisabled(type)) {
        SKIP_TEST();
    }
#if !defined(HITLS_CRYPTO_KEY_ENCODE) || !defined(HITLS_CRYPTO_KEY_DECODE) || !defined(HITLS_CRYPTO_COMPOSITE_KEM)
    (void)provider;
    (void)format;
    SKIP_TEST();
#else
#ifndef HITLS_CRYPTO_KEY_DECODE_CHAIN
    if (provider) {
        SKIP_TEST();
    }
#endif
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *key = NULL;
    CRYPT_EAL_PkeyCtx *decoded[3] = {0};
    BSL_Buffer encoded[3] = {0};
    int types[] = {CRYPT_PUBKEY_SUBKEY, CRYPT_PUBKEY_SUBKEY_WITHOUT_SEQ, CRYPT_PRIKEY_PKCS8_UNENCRYPT};
    const char *typeNames[] = {"PUBKEY_SUBKEY", "PUBKEY_SUBKEY_WITHOUT_SEQ", "PRIKEY_PKCS8_UNENCRYPT"};
    uint8_t cipher[1952];
    uint8_t secret[32];
    uint8_t recovered[32];
    key = provider ? CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_COMPOSITE, CRYPT_EAL_PKEY_KEM_OPERATE, NULL) :
        CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    ASSERT_TRUE(key != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(key, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(key), CRYPT_SUCCESS);
    for (uint32_t i = 0; i < 3; i++) {
        int bufferFormat = i == 1 ? BSL_FORMAT_ASN1 : format;
        ASSERT_EQ(i == 1 ? CRYPT_EAL_EncodePubKeyBuffInternal(key, bufferFormat, CRYPT_PUBKEY_SUBKEY,
            false, &encoded[i]) :
            CRYPT_EAL_EncodeBuffKey(key, NULL, bufferFormat, types[i], &encoded[i]), CRYPT_SUCCESS);
        ASSERT_TRUE(CompositeKemCodecRoundtrip(type, provider, bufferFormat, types[i], typeNames[i],
            &encoded[i], &decoded[i]));
    }
    for (uint32_t i = 0; i < 2; i++) {
        uint32_t cipherLen = sizeof(cipher);
        uint32_t secretLen = sizeof(secret);
        uint32_t recoveredLen = sizeof(recovered);
        ASSERT_EQ(CRYPT_EAL_PkeyEncaps(decoded[i], cipher, &cipherLen, secret, &secretLen), CRYPT_SUCCESS);
        uint32_t expectedLen = 0;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(key, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &expectedLen, sizeof(expectedLen)),
            CRYPT_SUCCESS);
        ASSERT_EQ(cipherLen, expectedLen);
        ASSERT_EQ(secretLen, sizeof(secret));
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(decoded[2], cipher, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
        ASSERT_EQ(recoveredLen, sizeof(recovered));
        ASSERT_EQ(ConstTimeMemcmp(secret, recovered, sizeof(secret)), UINT32_MAX);
    }
    ASSERT_TRUE(format == BSL_FORMAT_ASN1 ? CompositeKemRejectDer(encoded, provider, types, typeNames) :
                CompositeKemRejectPem(encoded, provider));

EXIT:
    CRYPT_EAL_PkeyFreeCtx(key);
    for (uint32_t i = 0; i < 3; i++) {
        CRYPT_EAL_PkeyFreeCtx(decoded[i]);
        BSL_SAL_ClearFree(encoded[i].data, encoded[i].dataLen);
    }
    TestRandDeInit();
#endif
}
/* END_CASE */

#ifdef HITLS_CRYPTO_COMPOSITE_KEM
static bool CompositeKemLeadingZero(CRYPT_EAL_PkeyCtx *ctx, int type, Hex *cipher)
{
    CRYPT_CompositeCtx *inner = ctx->key;
    if (inner->info->tradAlg != CRYPT_PKEY_ECDH) {
        return true;
    }
    bool success = false;
    CRYPT_EAL_PkeyCtx *peer = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    uint8_t modified[1952];
    uint8_t combined[400];
    uint8_t publicKey[133];
    uint8_t expected[32];
    uint8_t recovered[32];
    uint32_t pqcLen = type >= CRYPT_COMPOSITE_MLKEM1024_RSA3072_SHA3_256 ? 1568 : 1088;
    uint32_t tradLen =
        type == CRYPT_COMPOSITE_MLKEM1024_ECDH_P521_SHA3_256 ? 66 :
        (type == CRYPT_COMPOSITE_MLKEM768_ECDH_P384_SHA3_256 || type == CRYPT_COMPOSITE_MLKEM1024_ECDH_P384_SHA3_256 ||
         type == CRYPT_COMPOSITE_MLKEM1024_ECDH_BRAINPOOLP384R1_SHA3_256) ?
                                                               48 :
                                                               32;
    ASSERT_TRUE(peer != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(peer, inner->info->tradParam), CRYPT_SUCCESS);
    CompositeDetRandReset();
    CRYPT_RandRegist(CompositeDetRand);
    CRYPT_RandRegistEx(CompositeDetRandEx);
    uint32_t secretLen = 0;
    bool found = false;
    for (uint32_t i = 0; i < 1024; i++) {
        ASSERT_EQ(CRYPT_EAL_PkeyGen(peer), CRYPT_SUCCESS);
        secretLen = 66;
        ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(inner->tradCtx, peer, combined + 32, &secretLen), CRYPT_SUCCESS);
        ASSERT_EQ(secretLen, tradLen);
        if (combined[32] == 0) {
            found = true;
            break;
        }
    }
    ASSERT_TRUE(found);
    memcpy(modified, cipher->x, cipher->len);
    BSL_Param pub[] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, modified + pqcLen, sizeof(modified) - pqcLen, 0},
                       BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(peer, pub), CRYPT_SUCCESS);
    secretLen = 32;
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(inner->pqcCtx, modified, pqcLen, combined, &secretLen), CRYPT_SUCCESS);
    uint32_t pointLen = pub[0].useLen;
    memcpy(combined + 32 + tradLen, modified + pqcLen, pointLen);
    pub[0].value = publicKey;
    pub[0].valueLen = sizeof(publicKey);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(inner->tradCtx, pub), CRYPT_SUCCESS);
    memcpy(combined + 32 + tradLen + pointLen, publicKey, pub[0].useLen);
    const char *label = type == CRYPT_COMPOSITE_MLKEM768_ECDH_P256_SHA3_256             ? "MLKEM768-P256" :
                        type == CRYPT_COMPOSITE_MLKEM768_ECDH_P384_SHA3_256             ? "MLKEM768-P384" :
                        type == CRYPT_COMPOSITE_MLKEM768_ECDH_BRAINPOOLP256R1_SHA3_256  ? "MLKEM768-BP256" :
                        type == CRYPT_COMPOSITE_MLKEM1024_ECDH_P384_SHA3_256            ? "MLKEM1024-P384" :
                        type == CRYPT_COMPOSITE_MLKEM1024_ECDH_BRAINPOOLP384R1_SHA3_256 ? "MLKEM1024-BP384" :
                                                                                          "MLKEM1024-P521";
    uint32_t combinedLen = 32 + tradLen + pointLen + pub[0].useLen;
    memcpy(combined + combinedLen, label, strlen(label));
    uint32_t expectedLen = sizeof(expected);
    ASSERT_EQ(CRYPT_EAL_Md(CRYPT_MD_SHA3_256, combined, combinedLen + strlen(label), expected, &expectedLen),
              CRYPT_SUCCESS);
    secretLen = sizeof(recovered);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, modified, cipher->len, recovered, &secretLen), CRYPT_SUCCESS);
    ASSERT_EQ(secretLen, sizeof(recovered));
    ASSERT_EQ(ConstTimeMemcmp(expected, recovered, sizeof(expected)), UINT32_MAX);
    success = true;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(peer);
    BSL_SAL_CleanseData(combined, sizeof(combined));
    BSL_SAL_CleanseData(expected, sizeof(expected));
    BSL_SAL_CleanseData(recovered, sizeof(recovered));
    return success;
}
#endif

#if defined(HITLS_CRYPTO_COMPOSITE_KEM)
static bool CompositeKemVectorSeeds(CRYPT_EAL_PkeyCtx *ctx, int type, Hex *prv, Hex *cipher, Hex *secret)
{
    bool success = false;
    CRYPT_EAL_PkeyCtx *seedCtx = NULL;
    uint8_t changedSeed[3000];
    uint8_t changedCipher[1952];
    uint8_t recovered[32];
    uint8_t rejected[32];
    uint32_t recoveredLen = 0;
    ASSERT_TRUE(prv->len <= sizeof(changedSeed));
    for (uint32_t mutation = 0; mutation < 3; mutation++) {
        memcpy(changedSeed, prv->x, prv->len);
        if (mutation < 2) {
            changedSeed[mutation * 32] ^= 1;
        } else {
            memcpy(changedSeed, prv->x + 32, 32);
            memcpy(changedSeed + 32, prv->x, 32);
        }
        seedCtx = CompositeKemNewCtx(0);
        ASSERT_TRUE(seedCtx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(seedCtx, type), CRYPT_SUCCESS);
        CRYPT_EAL_PkeyPrv changed = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePrv = {changedSeed, prv->len}};
        ASSERT_EQ(CRYPT_EAL_PkeySetPrv(seedCtx, &changed), CRYPT_SUCCESS);
        recoveredLen = sizeof(recovered);
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(seedCtx, cipher->x, cipher->len, recovered, &recoveredLen),
                  CRYPT_SUCCESS);
        if (mutation == 1) {
            /* z is used only by implicit rejection, not by valid ciphertext decapsulation. */
            ASSERT_EQ(ConstTimeMemcmp(recovered, secret->x, secret->len), UINT32_MAX);
            ASSERT_TRUE(cipher->len <= sizeof(changedCipher));
            memcpy(changedCipher, cipher->x, cipher->len);
            changedCipher[0] ^= 1;
            recoveredLen = sizeof(rejected);
            ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, changedCipher, cipher->len, rejected, &recoveredLen),
                      CRYPT_SUCCESS);
            recoveredLen = sizeof(recovered);
            ASSERT_EQ(CRYPT_EAL_PkeyDecaps(seedCtx, changedCipher, cipher->len, recovered, &recoveredLen),
                      CRYPT_SUCCESS);
            ASSERT_NE(ConstTimeMemcmp(recovered, rejected, sizeof(recovered)), UINT32_MAX);
        } else {
            ASSERT_NE(ConstTimeMemcmp(recovered, secret->x, secret->len), UINT32_MAX);
        }
        CRYPT_EAL_PkeyFreeCtx(seedCtx);
        seedCtx = NULL;
    }
    success = true;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(seedCtx);
    BSL_SAL_CleanseData(changedSeed, sizeof(changedSeed));
    BSL_SAL_CleanseData(recovered, sizeof(recovered));
    BSL_SAL_CleanseData(rejected, sizeof(rejected));
    return success;
}
#endif

#if defined(HITLS_CRYPTO_COMPOSITE_KEM)
static bool CompositeKemVectorCurve(int type, Hex *prv, Hex *cipher, Hex *secret)
{
    bool success = false;
    CRYPT_EAL_PkeyCtx *seedCtx = NULL;
    uint8_t recovered[32];
    uint32_t recoveredLen = 0;
    CRYPT_EAL_PkeyPrv key = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePrv = {prv->x, prv->len}};
    int otherCurve = type == CRYPT_COMPOSITE_MLKEM768_ECDH_P256_SHA3_256 ?
                         CRYPT_COMPOSITE_MLKEM768_ECDH_BRAINPOOLP256R1_SHA3_256 :
                     type == CRYPT_COMPOSITE_MLKEM768_ECDH_BRAINPOOLP256R1_SHA3_256 ?
                         CRYPT_COMPOSITE_MLKEM768_ECDH_P256_SHA3_256 :
                     type == CRYPT_COMPOSITE_MLKEM1024_ECDH_P384_SHA3_256 ?
                         CRYPT_COMPOSITE_MLKEM1024_ECDH_BRAINPOOLP384R1_SHA3_256 :
                     type == CRYPT_COMPOSITE_MLKEM1024_ECDH_BRAINPOOLP384R1_SHA3_256 ?
                         CRYPT_COMPOSITE_MLKEM1024_ECDH_P384_SHA3_256 :
                         0;
    if (otherCurve != 0 && !CompositeKemDisabled(otherCurve)) {
        seedCtx = CompositeKemNewCtx(0);
        ASSERT_TRUE(seedCtx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(seedCtx, otherCurve), CRYPT_SUCCESS);
        int32_t ret = CRYPT_EAL_PkeySetPrv(seedCtx, &key);
        if (ret == CRYPT_SUCCESS) {
            recoveredLen = sizeof(recovered);
            ret = CRYPT_EAL_PkeyDecaps(seedCtx, cipher->x, cipher->len, recovered, &recoveredLen);
            ASSERT_TRUE(ret != CRYPT_SUCCESS ||
                        ConstTimeMemcmp(recovered, secret->x, secret->len) != UINT32_MAX);
        } else {
            /* The longer brainpool private-key encoding exceeds the NIST parameter's limit. */
            ASSERT_EQ(ret, CRYPT_COMPOSITE_KEYLEN_ERROR);
        }
        CRYPT_EAL_PkeyFreeCtx(seedCtx);
        seedCtx = NULL;
    }
    success = true;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(seedCtx);
    BSL_SAL_CleanseData(recovered, sizeof(recovered));
    return success;
}
#endif

/* @
 * @test SDV_CRYPTO_COMPOSITE_KEM_VECTOR_TC001
 * @brief Decapsulate independently specified draft Appendix G vectors.
 * @expect Direct and Provider objects produce the independently specified shared secret.
 * @precon nan
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_KEM_VECTOR_TC001(int type, Hex *prv, Hex *cipher, Hex *secret)
{
#ifndef HITLS_CRYPTO_COMPOSITE_KEM
    (void)type;
    (void)prv;
    (void)cipher;
    (void)secret;
    SKIP_TEST();
#else
    if (CompositeKemDisabled(type)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t recovered[32];
    uint8_t modified[146] = {0};
    CRYPT_EAL_PkeyPrv key = {.id = CRYPT_PKEY_COMPOSITE, .key.compositePrv = {prv->x, prv->len}};
    for (int path = 0; path < 4; path++) {
        int provider = path / 2;
        ctx = provider ? CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_COMPOSITE, CRYPT_EAL_PKEY_KEM_OPERATE, NULL) :
            CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
        ASSERT_TRUE(ctx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
        BSL_Param params[] = {{CRYPT_PARAM_COMPOSITE_PRVKEY, BSL_PARAM_TYPE_OCTETS, prv->x, prv->len, 0},
                              BSL_PARAM_END};
        ASSERT_EQ(path % 2 ? CRYPT_EAL_PkeySetPrvEx(ctx, params) : CRYPT_EAL_PkeySetPrv(ctx, &key), CRYPT_SUCCESS);
        uint32_t recoveredLen = sizeof(recovered);
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, cipher->x, cipher->len, recovered, &recoveredLen), CRYPT_SUCCESS);
        ASSERT_EQ(recoveredLen, secret->len);
        ASSERT_EQ(ConstTimeMemcmp(recovered, secret->x, secret->len), UINT32_MAX);
        if (path == 0) {
            ASSERT_TRUE(CompositeKemLeadingZero(ctx, type, cipher));
            ASSERT_TRUE(CompositeKemVectorSeeds(ctx, type, prv, cipher, secret));
            ASSERT_TRUE(CompositeKemVectorCurve(type, prv, cipher, secret));
        }
        CRYPT_EAL_PkeyFreeCtx(ctx);
        ctx = NULL;
    }
    if (type >= CRYPT_COMPOSITE_MLKEM768_ECDH_P256_SHA3_256 &&
        type != CRYPT_COMPOSITE_MLKEM1024_RSA3072_SHA3_256) {
        ASSERT_TRUE(prv->len <= sizeof(modified));
        memcpy(modified, prv->x, prv->len);
        modified[prv->len - 1] ^= 1; /* Existing EC import ignores the inner curve OID. */
        key.key.compositePrv.data = modified;
        ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
        ASSERT_TRUE(ctx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &key), CRYPT_SUCCESS);
        uint32_t recoveredLen = sizeof(recovered);
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, cipher->x, cipher->len, recovered, &recoveredLen), CRYPT_SUCCESS);
        ASSERT_EQ(ConstTimeMemcmp(recovered, secret->x, secret->len), UINT32_MAX);
    }
EXIT:
    BSL_SAL_CleanseData(modified, sizeof(modified));
    BSL_SAL_CleanseData(recovered, sizeof(recovered));
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
#endif
}
/* END_CASE */

#if defined(HITLS_CRYPTO_COMPOSITE_KEM) && defined(HITLS_CRYPTO_KEY_DECODE) && defined(HITLS_CRYPTO_KEY_ENCODE) && \
    defined(HITLS_BSL_SAL_FILE)
static int32_t CompositeKemSampleDecode(BSL_Buffer *buff, int provider, int format, int privateKey, CRYPT_EAL_PkeyCtx **key)
{
    return provider ?
               CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN, format == BSL_FORMAT_ASN1 ? "ASN1" : "PEM",
                                               privateKey ? "PRIKEY_PKCS8_UNENCRYPT" : "PUBKEY_SUBKEY", buff, NULL,
                                               key) :
               CRYPT_EAL_DecodeBuffKey(format, privateKey ? CRYPT_PRIKEY_PKCS8_UNENCRYPT : CRYPT_PUBKEY_SUBKEY, buff,
                                       NULL, 0, key);
}

static bool CompositeKemSampleSecrets(const char *sampleDir, int type, CRYPT_EAL_PkeyCtx *key)
{
    char path[COMPOSITE_SAMPLE_PATH_MAX];
    BSL_Buffer cipher = {0};
    BSL_Buffer secret = {0};
    uint8_t recovered[32];
    bool success = false;
    for (int i = 0; i < 2; i++) {
        ASSERT_EQ(ReadCompositeSampleFile(sampleDir, i == 0 ? "ciphertext0.bin" : "ciphertext-rejected.bin",
            &cipher, path, sizeof(path)), BSL_SUCCESS);
        ASSERT_EQ(ReadCompositeSampleFile(sampleDir, i == 0 ? "secret0.bin" : "secret-rejected.bin",
            &secret, path, sizeof(path)), BSL_SUCCESS);
        ASSERT_EQ(cipher.dataLen, CompositeKemCipherLen(type));
        ASSERT_EQ(secret.dataLen, sizeof(recovered));
        uint32_t recoveredLen = sizeof(recovered);
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(key, cipher.data, cipher.dataLen, recovered, &recoveredLen), CRYPT_SUCCESS);
        ASSERT_EQ(recoveredLen, secret.dataLen);
        ASSERT_EQ(ConstTimeMemcmp(recovered, secret.data, secret.dataLen), UINT32_MAX);
        BSL_SAL_FREE(cipher.data);
        BSL_SAL_ClearFree(secret.data, secret.dataLen);
        secret = (BSL_Buffer){0};
    }
    success = true;
EXIT:
    BSL_SAL_FREE(cipher.data);
    BSL_SAL_ClearFree(secret.data, secret.dataLen);
    BSL_SAL_CleanseData(recovered, sizeof(recovered));
    return success;
}
#endif

/* @
 * @test SDV_CRYPTO_COMPOSITE_KEM_SAMPLE_TC001
 * @brief Decode saved sample keys, compare canonical DER, consume sample ciphertexts and rejection secrets.
 * @expect All supported combinations interoperate; explicit NULL parameters and X448 are rejected.
 * @precon Composite KEM static fixtures are present.
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_KEM_SAMPLE_TC001(char *sampleDir, int type, int provider, int format, int supported)
{
#if !defined(HITLS_CRYPTO_COMPOSITE_KEM) || !defined(HITLS_CRYPTO_KEY_DECODE) || !defined(HITLS_CRYPTO_KEY_ENCODE) || \
    !defined(HITLS_BSL_SAL_FILE)
    (void)sampleDir;
    (void)type;
    (void)provider;
    (void)format;
    (void)supported;
    SKIP_TEST();
#else
    if (supported && CompositeKemDisabled(type)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *keys[2] = {NULL, NULL};
    CRYPT_EAL_PkeyCtx *roundtrip = NULL;
    BSL_Buffer input = {0};
    BSL_Buffer original = {0};
    BSL_Buffer encoded = {0};
    char name[48];
    char path[COMPOSITE_SAMPLE_PATH_MAX];
    uint8_t cipher[1952];
    uint8_t secret[32];
    uint8_t recovered[32];
    for (int i = 0; i < 2; i++) {
        ASSERT_TRUE(snprintf(name, sizeof(name), "%skey.%s", i ? "private" : "public",
                             format == BSL_FORMAT_ASN1 ? "der" : "pem") > 0);
        ASSERT_EQ(ReadCompositeSampleFile(sampleDir, name, &input, path, sizeof(path)), BSL_SUCCESS);
        int32_t ret = CompositeKemSampleDecode(&input, provider, format, i, &keys[i]);
        if (!supported) {
            ASSERT_NE(ret, CRYPT_SUCCESS);
            ASSERT_EQ(keys[i], NULL);
        } else {
            ASSERT_EQ(ret, CRYPT_SUCCESS);
            ASSERT_EQ(CheckCompositeDecodedKey(keys[i], type), CRYPT_SUCCESS);
            ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(keys[i], NULL, BSL_FORMAT_ASN1,
                                              i ? CRYPT_PRIKEY_PKCS8_UNENCRYPT : CRYPT_PUBKEY_SUBKEY, &encoded),
                      CRYPT_SUCCESS);
            ASSERT_TRUE(snprintf(name, sizeof(name), "%skey.der", i ? "private" : "public") > 0);
            ASSERT_EQ(ReadCompositeSampleFile(sampleDir, name, &original, path, sizeof(path)), BSL_SUCCESS);
            ASSERT_EQ(encoded.dataLen, original.dataLen);
            ASSERT_EQ(ConstTimeMemcmp(encoded.data, original.data, original.dataLen), UINT32_MAX);
            ASSERT_EQ(CompositeKemSampleDecode(&encoded, !provider, BSL_FORMAT_ASN1, i, &roundtrip), CRYPT_SUCCESS);
            CRYPT_EAL_PkeyFreeCtx(keys[i]);
            keys[i] = roundtrip;
            roundtrip = NULL;
        }
        BSL_SAL_ClearFree(input.data, input.dataLen);
        input = (BSL_Buffer){0};
        BSL_SAL_ClearFree(original.data, original.dataLen);
        original = (BSL_Buffer){0};
        BSL_SAL_ClearFree(encoded.data, encoded.dataLen);
        encoded = (BSL_Buffer){0};
    }
    if (!supported) {
        goto EXIT;
    }
    ASSERT_TRUE(CompositeKemSampleSecrets(sampleDir, type, keys[1]));
    uint32_t cipherLen = sizeof(cipher);
    uint32_t secretLen = sizeof(secret);
    uint32_t recoveredLen = sizeof(recovered);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(keys[0], cipher, &cipherLen, secret, &secretLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(keys[1], cipher, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
    ASSERT_EQ(secretLen, sizeof(secret));
    ASSERT_EQ(recoveredLen, secretLen);
    ASSERT_EQ(ConstTimeMemcmp(secret, recovered, secretLen), UINT32_MAX);
    for (int i = 0; i < 2; i++) {
        ASSERT_TRUE(snprintf(name, sizeof(name), "%skey-null.der", i ? "private" : "public") > 0);
        ASSERT_EQ(ReadCompositeSampleFile(sampleDir, name, &input, path, sizeof(path)), BSL_SUCCESS);
        ASSERT_NE(CompositeKemSampleDecode(&input, provider, BSL_FORMAT_ASN1, i, &roundtrip), CRYPT_SUCCESS);
        ASSERT_EQ(roundtrip, NULL);
        BSL_SAL_ClearFree(input.data, input.dataLen);
        input = (BSL_Buffer){0};
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(keys[0]);
    CRYPT_EAL_PkeyFreeCtx(keys[1]);
    CRYPT_EAL_PkeyFreeCtx(roundtrip);
    BSL_SAL_ClearFree(input.data, input.dataLen);
    BSL_SAL_ClearFree(original.data, original.dataLen);
    BSL_SAL_ClearFree(encoded.data, encoded.dataLen);
    BSL_SAL_CleanseData(secret, sizeof(secret));
    BSL_SAL_CleanseData(recovered, sizeof(recovered));
    TestRandDeInit();
#endif
}
/* END_CASE */

#ifdef HITLS_CRYPTO_COMPOSITE_KEM
static bool CompositeKemRejectRsaCipher(CRYPT_EAL_PkeyCtx *ctx, const uint8_t *cipher, uint32_t cipherLen)
{
    bool success = false;
    uint8_t output[1952];
    uint8_t recovered[32];
    uint8_t sentinel[32];
    uint32_t recoveredLen = sizeof(recovered);
    memset(sentinel, 0xa5, sizeof(sentinel));
    CRYPT_CompositeCtx *inner = ctx->key;
    uint8_t plain[33] = {0};
    for (uint32_t len = 31; len <= 33; len += 2) {
        memcpy(output, cipher, cipherLen);
        uint32_t rsaLen = inner->info->alg.kem.tradCipherLen;
        ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(inner->tradCtx, plain, len,
            output + inner->info->alg.kem.pqcCipherLen, &rsaLen), CRYPT_SUCCESS);
        memcpy(recovered, sentinel, sizeof(recovered));
        recoveredLen = sizeof(recovered);
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, output, cipherLen, recovered, &recoveredLen),
            CRYPT_COMPOSITE_KEYLEN_ERROR);
        ASSERT_EQ(recoveredLen, sizeof(recovered));
        ASSERT_EQ(ConstTimeMemcmp(recovered, sentinel, sizeof(recovered)), UINT32_MAX);
    }
    for (int parameter = 0; parameter < 3; parameter++) {
        CRYPT_MD_AlgId mdId = CRYPT_MD_SHA256;
        CRYPT_MD_AlgId mgfId = CRYPT_MD_SHA256;
#ifdef HITLS_CRYPTO_SHA512
        mdId = parameter == 0 ? CRYPT_MD_SHA512 : mdId;
        mgfId = parameter == 1 ? CRYPT_MD_SHA512 : mgfId;
#else
        if (parameter != 2) {
            continue;
        }
#endif
        BSL_Param params[] = {{CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
            {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mgfId, sizeof(mgfId), 0}, BSL_PARAM_END};
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(inner->tradCtx, CRYPT_CTRL_SET_RSA_RSAES_OAEP, params, 0), CRYPT_SUCCESS);
        if (parameter == 2) {
            ASSERT_EQ(CRYPT_EAL_PkeyCtrl(inner->tradCtx, CRYPT_CTRL_SET_RSA_OAEP_LABEL, plain, 1), CRYPT_SUCCESS);
        }
        memcpy(output, cipher, cipherLen);
        uint32_t rsaLen = inner->info->alg.kem.tradCipherLen;
        ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(inner->tradCtx, plain, 32,
            output + inner->info->alg.kem.pqcCipherLen, &rsaLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_CompositeSetRsaPadding(inner), CRYPT_SUCCESS);
        memcpy(recovered, sentinel, sizeof(recovered));
        recoveredLen = sizeof(recovered);
        ASSERT_NE(CRYPT_EAL_PkeyDecaps(ctx, output, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
        ASSERT_EQ(recoveredLen, sizeof(recovered));
        ASSERT_EQ(ConstTimeMemcmp(recovered, sentinel, sizeof(recovered)), UINT32_MAX);
    }

    success = true;
EXIT:
    BSL_SAL_CleanseData(recovered, sizeof(recovered));
    return success;
}

static bool CheckCompositeKemImplicitRejection(CRYPT_EAL_PkeyCtx *ctx, uint32_t pqcLength,
    uint8_t *cipher, uint32_t cipherLen, const uint8_t *secret)
{
    bool success = false;
    uint8_t recovered[32];
    uint8_t checked[32];
    uint32_t recoveredLen = sizeof(recovered);
    uint32_t positions[] = {0, pqcLength / 2, pqcLength - 1};
    for (uint32_t i = 0; i < 3; i++) {
        cipher[positions[i]] ^= 1;
        recoveredLen = sizeof(recovered);
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, cipher, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
        ASSERT_EQ(recoveredLen, sizeof(recovered));
        ASSERT_NE(ConstTimeMemcmp(secret, recovered, 32), UINT32_MAX);
        uint32_t checkedLen = sizeof(checked);
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, cipher, cipherLen, checked, &checkedLen), CRYPT_SUCCESS);
        ASSERT_EQ(ConstTimeMemcmp(checked, recovered, sizeof(checked)), UINT32_MAX);
        cipher[positions[i]] ^= 1;
    }
    success = true;
EXIT:
    BSL_SAL_CleanseData(recovered, sizeof(recovered));
    BSL_SAL_CleanseData(checked, sizeof(checked));
    return success;
}

static bool CompositeKemRejectCipher(CRYPT_EAL_PkeyCtx *ctx, int type, uint8_t *cipher, uint32_t cipherLen,
    const uint8_t *secret)
{
    bool success = false;
    uint8_t output[1952];
    uint8_t recovered[32];
    uint8_t sentinel[32];
    uint32_t recoveredLen = sizeof(recovered);
    memset(sentinel, 0xa5, sizeof(sentinel));
    uint32_t pqcLength = type >= CRYPT_COMPOSITE_MLKEM1024_RSA3072_SHA3_256 ? 1568 : 1088;
    ASSERT_TRUE(CheckCompositeKemImplicitRejection(ctx, pqcLength, cipher, cipherLen, secret));
    memcpy(output, cipher, cipherLen);
    CRYPT_CompositeCtx *inner = ctx->key;
    memset(output + inner->info->alg.kem.pqcCipherLen, 0, inner->info->alg.kem.tradCipherLen);
    recoveredLen = sizeof(recovered);
    if (inner->info->tradAlg == CRYPT_PKEY_RSA) {
        ASSERT_NE(CRYPT_EAL_PkeyDecaps(ctx, output, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, output, cipherLen, recovered, &recoveredLen),
            inner->info->tradAlg == CRYPT_PKEY_X25519 ?
            CRYPT_CURVE25519_KEY_COMPUTE_FAILED : CRYPT_COMPOSITE_KEYLEN_ERROR);
    }
    ASSERT_EQ(recoveredLen, sizeof(recovered));
    if (inner->info->tradAlg == CRYPT_PKEY_ECDH) {
        output[inner->info->alg.kem.pqcCipherLen] = 0x04;
        recoveredLen = sizeof(recovered);
        ASSERT_NE(CRYPT_EAL_PkeyDecaps(ctx, output, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
        ASSERT_EQ(recoveredLen, sizeof(recovered));
        memcpy(output, cipher, cipherLen);
        uint8_t prefixes[] = {0x02, 0x03, 0x06, 0x07, 0xff};
        for (uint32_t i = 0; i < sizeof(prefixes); i++) {
            output[inner->info->alg.kem.pqcCipherLen] = prefixes[i];
            recoveredLen = sizeof(recovered);
            ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, output, cipherLen, recovered, &recoveredLen),
                      CRYPT_COMPOSITE_KEYLEN_ERROR);
            ASSERT_EQ(recoveredLen, sizeof(recovered));
        }
        memset(output + pqcLength, 0xff, cipherLen - pqcLength);
        output[pqcLength] = 0x04;
        recoveredLen = sizeof(recovered);
        ASSERT_NE(CRYPT_EAL_PkeyDecaps(ctx, output, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
        ASSERT_EQ(recoveredLen, sizeof(recovered));
    } else if (inner->info->tradAlg == CRYPT_PKEY_X25519) {
        output[pqcLength] = 1; /* The encoded u = 1 point has low order. */
        recoveredLen = sizeof(recovered);
        memcpy(recovered, sentinel, sizeof(recovered));
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, output, cipherLen, recovered, &recoveredLen),
                  CRYPT_CURVE25519_KEY_COMPUTE_FAILED);
        ASSERT_EQ(recoveredLen, sizeof(recovered));
        ASSERT_EQ(ConstTimeMemcmp(recovered, sentinel, sizeof(recovered)), UINT32_MAX);
    }
    memcpy(output, cipher, cipherLen);
    output[0] ^= 1;
    memset(output + pqcLength, 0, cipherLen - pqcLength);
    recoveredLen = sizeof(recovered);
    memcpy(recovered, sentinel, sizeof(recovered));
    ASSERT_NE(CRYPT_EAL_PkeyDecaps(ctx, output, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
    ASSERT_EQ(recoveredLen, sizeof(recovered));
    ASSERT_EQ(ConstTimeMemcmp(recovered, sentinel, sizeof(recovered)), UINT32_MAX);
    if (inner->info->tradAlg == CRYPT_PKEY_RSA) {
        ASSERT_TRUE(CompositeKemRejectRsaCipher(ctx, cipher, cipherLen));
    }
    success = true;
EXIT:
    BSL_SAL_CleanseData(recovered, sizeof(recovered));
    return success;
}

static bool CompositeKemAllocFailure(CRYPT_EAL_PkeyCtx *ctx, int decaps, const uint8_t *cipher,
    uint32_t cipherLen, const uint8_t *secret)
{
    bool success = false;
    uint8_t output[1952];
    uint8_t recovered[32];
    uint8_t sentinel[32];
    uint8_t checked[32];
    uint32_t recoveredLen = sizeof(recovered);
    memset(sentinel, 0xa5, sizeof(sentinel));
    uint32_t outputLen = sizeof(output);
    CRYPT_CompositeCtx *inner = ctx->key;
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    outputLen = sizeof(output);
    recoveredLen = sizeof(recovered);
    ASSERT_EQ(decaps ? CRYPT_EAL_PkeyDecaps(ctx, cipher, cipherLen, recovered, &recoveredLen) :
        CRYPT_EAL_PkeyEncaps(ctx, output, &outputLen, recovered, &recoveredLen), CRYPT_SUCCESS);
    uint32_t total = STUB_GetMallocCallCount();
    ASSERT_TRUE(total > 0);
    for (uint32_t i = 0; i < total; i++) {
        memcpy(recovered, sentinel, sizeof(recovered));
        memset(output, 0xa5, sizeof(output));
        outputLen = sizeof(output);
        recoveredLen = sizeof(recovered);
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        STUB_EnableMallocFail(true);
        int32_t ret = decaps ? CRYPT_EAL_PkeyDecaps(ctx, cipher, cipherLen, recovered, &recoveredLen) :
            CRYPT_EAL_PkeyEncaps(ctx, output, &outputLen, recovered, &recoveredLen);
        STUB_EnableMallocFail(false);
        if (ret == CRYPT_SUCCESS && inner->info->tradAlg != CRYPT_PKEY_X25519) {
            ASSERT_EQ(recoveredLen, sizeof(recovered));
            if (!decaps) {
                uint32_t checkedLen = sizeof(checked);
                ASSERT_EQ(outputLen, cipherLen);
                ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, output, outputLen, checked, &checkedLen), CRYPT_SUCCESS);
                ASSERT_EQ(ConstTimeMemcmp(recovered, checked, sizeof(checked)), UINT32_MAX);
            } else {
                ASSERT_EQ(ConstTimeMemcmp(recovered, secret, 32), UINT32_MAX);
            }
            continue;
        }
        ASSERT_NE(ret, CRYPT_SUCCESS);
        ASSERT_EQ(recoveredLen, sizeof(recovered));
        ASSERT_COMPARE("failure preserves output", recovered, sizeof(recovered), sentinel, sizeof(sentinel));
        if (!decaps) {
            ASSERT_EQ(outputLen, sizeof(output));
            for (uint32_t j = 0; j < sizeof(output); j++) {
                ASSERT_EQ(output[j], 0xa5);
            }
        }
    }
    STUB_RESTORE(BSL_SAL_Malloc);
    success = true;
EXIT:
    STUB_EnableMallocFail(false);
    STUB_RESTORE(BSL_SAL_Malloc);
    return success;
}

static bool CompositeKemPrimitiveFailure(CRYPT_EAL_PkeyCtx *ctx, int decaps, const uint8_t *cipher, uint32_t cipherLen)
{
    bool success = false;
    uint8_t output[1952];
    uint8_t recovered[32];
    uint8_t sentinel[32];
    uint32_t recoveredLen = sizeof(recovered);
    memset(sentinel, 0xa5, sizeof(sentinel));
    uint32_t outputLen = sizeof(output);
    CRYPT_CompositeCtx *inner = ctx->key;
    for (int component = 0; !decaps && component < (inner->info->tradAlg == CRYPT_PKEY_RSA ? 3 : 2); component++) {
        g_compositeKemRandCall = 0;
        g_compositeKemRandFail = component;
        outputLen = sizeof(output);
        recoveredLen = sizeof(recovered);
        memset(output, 0xa5, sizeof(output));
        memcpy(recovered, sentinel, sizeof(recovered));
        ASSERT_NE(CRYPT_EAL_PkeyEncaps(ctx, output, &outputLen, recovered, &recoveredLen), CRYPT_SUCCESS);
        ASSERT_EQ(outputLen, sizeof(output));
        ASSERT_EQ(recoveredLen, sizeof(recovered));
        ASSERT_EQ(ConstTimeMemcmp(recovered, sentinel, sizeof(recovered)), UINT32_MAX);
        for (uint32_t j = 0; j < sizeof(output); j++) {
            ASSERT_EQ(output[j], 0xa5);
        }
    }
    g_compositeKemRandFail = -1;
    for (int phase = 0; phase < 3; phase++) {
        if (phase == 0) {
            STUB_REPLACE(CRYPT_EAL_MdInit, CompositeKemFailMdInit);
        } else if (phase == 1) {
            STUB_REPLACE(CRYPT_EAL_MdUpdate, CompositeKemFailMdUpdate);
        } else {
            STUB_REPLACE(CRYPT_EAL_MdFinal, CompositeKemFailMdFinal);
        }
        outputLen = sizeof(output);
        recoveredLen = sizeof(recovered);
        memset(output, 0xa5, sizeof(output));
        memcpy(recovered, sentinel, sizeof(recovered));
        ASSERT_EQ(decaps ? CRYPT_EAL_PkeyDecaps(ctx, cipher, cipherLen, recovered, &recoveredLen) :
                           CRYPT_EAL_PkeyEncaps(ctx, output, &outputLen, recovered, &recoveredLen),
                  CRYPT_INVALID_ARG);
        STUB_RESTORE(CRYPT_EAL_MdInit);
        STUB_RESTORE(CRYPT_EAL_MdUpdate);
        STUB_RESTORE(CRYPT_EAL_MdFinal);
        ASSERT_EQ(recoveredLen, sizeof(recovered));
        ASSERT_EQ(ConstTimeMemcmp(recovered, sentinel, sizeof(recovered)), UINT32_MAX);
        if (!decaps) {
            ASSERT_EQ(outputLen, sizeof(output));
            for (uint32_t j = 0; j < sizeof(output); j++) {
                ASSERT_EQ(output[j], 0xa5);
            }
        }
    }
    success = true;
EXIT:
    g_compositeKemRandFail = -1;
    STUB_RESTORE(CRYPT_EAL_MdInit);
    STUB_RESTORE(CRYPT_EAL_MdUpdate);
    STUB_RESTORE(CRYPT_EAL_MdFinal);
    return success;
}
#endif

/* @
 * @test SDV_CRYPTO_COMPOSITE_KEM_OPFAIL_TC001
 * @brief Check operation boundaries, rejection semantics and allocation/random failures.
 * @expect Failures preserve input lengths, output buffers and long-term keys, and permit reuse.
 * @precon nan
 @ */
/* BEGIN_CASE */
void SDV_CRYPTO_COMPOSITE_KEM_OPFAIL_TC001(int type, int decaps)
{
#ifndef HITLS_CRYPTO_COMPOSITE_KEM
    (void)type;
    (void)decaps;
    SKIP_TEST();
#else
    if (CompositeKemDisabled(type)) {
        SKIP_TEST();
    }
    TestMemInit();
    TestRandInit();
    CRYPT_RandRegist(CompositeKemFailRand);
    CRYPT_RandRegistEx(CompositeKemFailRandEx);
    g_compositeKemRandFail = -1;
    CompositeDetRandReset();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_COMPOSITE);
    uint8_t cipher[1952];
    uint8_t secret[32];
    uint8_t recovered[32];
    uint32_t cipherLen = sizeof(cipher);
    uint32_t secretLen = sizeof(secret);
    uint32_t recoveredLen = sizeof(recovered);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, type), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, cipher, &cipherLen, secret, &secretLen), CRYPT_SUCCESS);
    if (!decaps) {
        ASSERT_TRUE(CompositeKemRejectCipher(ctx, type, cipher, cipherLen, secret));
    }
    ASSERT_TRUE(CompositeKemAllocFailure(ctx, decaps, cipher, cipherLen, secret));
    ASSERT_TRUE(CompositeKemPrimitiveFailure(ctx, decaps, cipher, cipherLen));
    recoveredLen = sizeof(recovered);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, cipher, cipherLen, recovered, &recoveredLen), CRYPT_SUCCESS);
    ASSERT_EQ(ConstTimeMemcmp(secret, recovered, sizeof(secret)), UINT32_MAX);
EXIT:
    STUB_EnableMallocFail(false);
    STUB_RESTORE(BSL_SAL_Malloc);
    g_compositeKemRandFail = -1;
    STUB_RESTORE(CRYPT_EAL_MdInit);
    STUB_RESTORE(CRYPT_EAL_MdUpdate);
    STUB_RESTORE(CRYPT_EAL_MdFinal);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
#endif
}
/* END_CASE */

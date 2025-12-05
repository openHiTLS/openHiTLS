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
#include "crypt_errno.h"
#include "eal_md_local.h"
#include "eal_pkey_local.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
#include "crypt_dsa.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_pkey.h"
#include "eal_cipher_local.h"
#include "modes_local.h"
#include "eal_common.h"

static bool IsMacAlgIdValid(int id)
{
    int algList[] = {
        CRYPT_MAC_HMAC_MD5,
        CRYPT_MAC_HMAC_SHA1,
        CRYPT_MAC_HMAC_SHA224,
        CRYPT_MAC_HMAC_SHA256,
        CRYPT_MAC_HMAC_SHA384,
        CRYPT_MAC_HMAC_SHA512,
        CRYPT_MAC_HMAC_SHA3_224,
        CRYPT_MAC_HMAC_SHA3_256,
        CRYPT_MAC_HMAC_SHA3_384,
        CRYPT_MAC_HMAC_SHA3_512,
        CRYPT_MAC_HMAC_SM3,
        CRYPT_MAC_CMAC_AES128,
        CRYPT_MAC_CMAC_AES192,
        CRYPT_MAC_CMAC_AES256,
        CRYPT_MAC_GMAC_AES128,
        CRYPT_MAC_GMAC_AES192,
        CRYPT_MAC_GMAC_AES256,
        CRYPT_MAC_SIPHASH64,
        CRYPT_MAC_SIPHASH128
    };
    int algIdCnt = sizeof(algList) / sizeof(int);
    for (int i = 0; i < algIdCnt; i++) {
        if (id == algList[i]) {
            return true;
        }
    }
    return false;
}

static bool IsCipherAlgIdValid(int id)
{
    int algList[] = {
        CRYPT_CIPHER_AES128_CBC,
        CRYPT_CIPHER_AES192_CBC,
        CRYPT_CIPHER_AES256_CBC,
        CRYPT_CIPHER_AES128_CTR,
        CRYPT_CIPHER_AES192_CTR,
        CRYPT_CIPHER_AES256_CTR,
        CRYPT_CIPHER_AES128_ECB,
        CRYPT_CIPHER_AES192_ECB,
        CRYPT_CIPHER_AES256_ECB,
        CRYPT_CIPHER_AES128_XTS,
        CRYPT_CIPHER_AES256_XTS,
        CRYPT_CIPHER_AES128_CCM,
        CRYPT_CIPHER_AES192_CCM,
        CRYPT_CIPHER_AES256_CCM,
        CRYPT_CIPHER_AES128_GCM,
        CRYPT_CIPHER_AES192_GCM,
        CRYPT_CIPHER_AES256_GCM,
        CRYPT_CIPHER_AES128_CFB,
        CRYPT_CIPHER_AES192_CFB,
        CRYPT_CIPHER_AES256_CFB,
        CRYPT_CIPHER_AES128_OFB,
        CRYPT_CIPHER_AES192_OFB,
        CRYPT_CIPHER_AES256_OFB,
        CRYPT_CIPHER_CHACHA20_POLY1305,
        CRYPT_CIPHER_SM4_XTS,
        CRYPT_CIPHER_SM4_CBC,
        CRYPT_CIPHER_SM4_ECB,
        CRYPT_CIPHER_SM4_CTR,
        CRYPT_CIPHER_SM4_GCM,
        CRYPT_CIPHER_SM4_CFB,
        CRYPT_CIPHER_SM4_OFB,
        CRYPT_CIPHER_SM4_HCTR
    };
    int algIdCnt = sizeof(algList) / sizeof(int);
    for (int i = 0; i < algIdCnt; i++) {
        if (id == algList[i]) {
            return true;
        }
    }
    return false;
}

static bool IsPkeyAlgIdValid(int id)
{
    int algList[] = {
        CRYPT_PKEY_DSA,
        CRYPT_PKEY_ED25519,
        CRYPT_PKEY_X25519,
        CRYPT_PKEY_RSA,
        CRYPT_PKEY_DH,
        CRYPT_PKEY_ECDSA,
        CRYPT_PKEY_ECDH,
        CRYPT_PKEY_SM2
    };
    int algIdCnt = sizeof(algList) / sizeof(int);
    for (int i = 0; i < algIdCnt; i++) {
        if (id == algList[i]) {
            return true;
        }
    }
    return false;
}

#define MD_OUTPUT_MAXSIZE 128

static int32_t MdTest(CRYPT_EAL_MdCTX *ctx, Hex *msg, Hex *hash)
{
    (void)msg;
    (void)hash;
    uint8_t output[MD_OUTPUT_MAXSIZE];
    uint32_t outLen = MD_OUTPUT_MAXSIZE;

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, msg->x, msg->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outLen), CRYPT_SUCCESS);
    if (ctx->id != CRYPT_MD_SHAKE128 && ctx->id != CRYPT_MD_SHAKE256) {
        ASSERT_TRUE(outLen == hash->len);
    }
    ASSERT_EQ(memcmp(output, hash->x, hash->len), 0);
    return 0;
EXIT:
    return -1;
}
/* END_HEADER */

/**
 * @test   SDV_CRYPTO_MAC_ALG_CHECK_TC001
 * @title  Check the validity of the mac algorithm ID.
 * @precon nan
 * @brief
 *    1. Call the CRYPT_EAL_MacIsValidAlgId method, compare the returned value with 'isValid', expected result 1
 * @expect
 *    1. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_MAC_ALG_CHECK_TC001(int algId)
{
    int isValid = IsMacAlgIdValid(algId);
    ASSERT_TRUE(CRYPT_EAL_MacIsValidAlgId(algId) == isValid);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_CIPHER_ALG_CHECK_TC001
 * @title  Check the validity of the symmetric algorithm ID.
 * @precon nan
 * @brief
 *    1. Call the CRYPT_EAL_CipherIsValidAlgId method, compare the returned value with 'isValid', expected result 1
 * @expect
 *    1. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CIPHER_ALG_CHECK_TC001(int algId)
{
    int isValid = IsCipherAlgIdValid(algId);
    ASSERT_TRUE(CRYPT_EAL_CipherIsValidAlgId(algId) == isValid);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_MD_COPY_FUNC_TC001
 * @title  CRYPT_EAL_MdCopyCtx function test.
 * @precon nan
 * @brief
 *    1. Create the context ctx of md algorithm, expected result 1
 *    2. Calculate the hash of msg, and compare the calculated result with hash vector, expected result 2
 *    3. Call to CRYPT_EAL_MdCopyCtx method to copy ctx, expected result 3
 *    4. Calculate the hash of msg, and compare the calculated result with hash vector, expected result 4
 * @expect
 *    1. Success, the context is not null.
 *    2. Success, the hashs are the same.
 *    3. CRYPT_SUCCESS
 *    4. Success, the hashs are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_MD_COPY_FUNC_TC001(int id, Hex *msg, Hex *hash)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *cpyCtx = NULL;
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(MdTest(ctx, msg, hash), 0);

    cpyCtx = CRYPT_EAL_MdNewCtx(id);
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdCopyCtx(cpyCtx, ctx), CRYPT_SUCCESS);
    ASSERT_EQ(MdTest(cpyCtx, msg, hash), 0);

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
    CRYPT_EAL_MdFreeCtx(cpyCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_PKEY_NEW_CTX_API_TC001
 * @title  CRYPT_EAL_PkeyNewCtx test.
 * @precon nan
 * @brief
 *    1. Call the CRYPT_EAL_PkeyNewCtx method, algId is CRYPT_PKEY_MAX, expected result 1
 * @expect
 *    1. Return null.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_PKEY_NEW_CTX_API_TC001(void)
{
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MAX);
    ASSERT_TRUE(pkey == NULL);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_PKEY_FREE_CTX_API_TC001
 * @title  CRYPT_EAL_PkeyFreeCtx test.
 * @precon nan
 * @brief
 *    1. Call the CRYPT_EAL_PkeyFreeCtx method, ctx is null, expected result 1
 * @expect
 *    1. No memory leakage occurs.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_PKEY_FREE_CTX_API_TC001(void)
{
    CRYPT_EAL_PkeyFreeCtx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_PKEY_SET_PARA_API_TC001
 * @title  Check the validity of the asymmetric algorithm ID.
 * @precon nan
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPara method:
 *       (1) pkey = NULL, expected result 1
 *       (2) para = NULL, expected result 1
 *       (3) pkey.id != para.id, expected result 2
 * @expect
 *    1. CRYPT_NULL_INPUT.
 *    2. CRYPT_EAL_ERR_ALGID.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_PKEY_SET_PARA_API_TC001(void)
{
    CRYPT_EAL_PkeyPara para = {0};

    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_DSA);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(NULL, &para) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, NULL) == CRYPT_NULL_INPUT);

    para.id = CRYPT_PKEY_RSA;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_ALGID);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_PKEY_ALG_CHECK_TC001
 * @title  Check the validity of the asymmetric algorithm ID.
 * @precon nan
 * @brief
 *    1. Call the CRYPT_EAL_PkeyIsValidAlgId method, compare the returned value with 'isValid', expected result 1
 * @expect
 *    1. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_PKEY_ALG_CHECK_TC001(int algId)
{
    int isValid = IsPkeyAlgIdValid(algId);
    ASSERT_TRUE(CRYPT_EAL_PkeyIsValidAlgId(algId) == isValid);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_PKEY_SET_PRV_API_TC001
 * @title  CRYPT_EAL_PkeySetPrv bad arguments.
 * @precon nan
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPrv:
 *       (1) pkey=NULL, expected result 1
 *       (2) prv=NULL, expected result 1
 *       (3) pkey.id != prv.id, expected result 2
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_EAL_ERR_ALGID
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_PKEY_SET_PRV_API_TC001(void)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPrv prv = {0};

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(NULL, &prv), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, NULL), CRYPT_NULL_INPUT);

    prv.id = CRYPT_PKEY_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prv), CRYPT_EAL_ERR_ALGID);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_PKEY_SET_PUB_API_TC001
 * @title  CRYPT_EAL_PkeySetPub bad arguments.
 * @precon nan
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPub:
 *       (1) pkey=NULL, expected result 1
 *       (2) prv=NULL, expected result 1
 *       (3) pkey.id != prv.id, expected result 2
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_EAL_ERR_ALGID
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_PKEY_SET_PUB_API_TC001(void)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPub pub = {0};

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(NULL, &pub), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, NULL), CRYPT_NULL_INPUT);

    pub.id = CRYPT_PKEY_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_EAL_ERR_ALGID);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_PKEY_GEN_API_TC001
 * @title  CRYPT_EAL_PkeyGen bad arguments.
 * @precon nan
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPub: peky = NULL, expected result 1
 * @expect
 *    1. CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_PKEY_GEN_API_TC001(void)
{
    ASSERT_EQ(CRYPT_EAL_PkeyGen(NULL), CRYPT_NULL_INPUT);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_PKEY_CMP_TC001
 * @title  CRYPT_EAL_PkeyCmp Test.
 * @precon nan
 * @brief
 *    1. Call the CRYPT_EAL_PkeyCmp, ctx1=NULL, ctx2=NULL, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCmp, ctx1=NULL, ctx2!=NULL or ctx1=NULL, ctx2!=NULL, expected result 2
 *    3. Call the CRYPT_EAL_PkeyCmp, ctx1!=NULL, ctx2!=NULL, the content in ctx1 and ctx2 is empty, expected result 2
 *    4. Call the CRYPT_EAL_PkeyCmp, ctx1!=NULL, ctx2!=NULL, ctx1.id!=ctx2.id, expected result 3
 *    5. Call the CRYPT_EAL_PkeyCmp, ctx1->pkey=NULL, expected result 2
 * @expect
 *    1. CRYPT_SUCCESS
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_EAL_PKEY_CMP_DIFF_KEY_TYPE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_PKEY_CMP_TC001(void)
{
    CRYPT_EAL_PkeyCtx ctx1 = {0};
    CRYPT_EAL_PkeyCtx ctx2 = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(NULL, &ctx2), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(&ctx1, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(&ctx1, &ctx2), CRYPT_EAL_ALG_NOT_SUPPORT);

    ctx1.id = CRYPT_PKEY_DH;
    ctx2.id = CRYPT_PKEY_DSA;
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(&ctx1, &ctx2), CRYPT_EAL_PKEY_CMP_DIFF_KEY_TYPE);

    ctx2.id = CRYPT_PKEY_DH;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_DH);
    ASSERT_TRUE(pkey != NULL);
    ctx1.method = pkey->method;
    ctx2.method = pkey->method;
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(&ctx1, &ctx2), CRYPT_NULL_INPUT);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_PKEY_GET_ID_API_TC001
 * @title  CRYPT_EAL_PkeyGetId Test.
 * @precon nan
 * @brief
 *    1. Create the context(ctx) of pkeyId, expected result 1
 *    2. Call the CRYPT_EAL_PkeyGetId to get id of ctx, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetId to get id of NULL, expected result 3
 * @expect
 *    1. Success, and context is not NULL.
 *    2. The getted id and pkeyId are the same.
 *    3. Get id: CRYPT_PKEY_MAX
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_PKEY_GET_ID_API_TC001(void)
{
    int pkeyId = CRYPT_PKEY_DSA;

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(pkeyId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGetId(ctx), pkeyId);
    ASSERT_EQ(CRYPT_EAL_PkeyGetId(NULL), CRYPT_PKEY_MAX);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_PKEY_EXT_DATA_API_TC001
 * @title  CRYPT_EAL_PkeySetExtData/CRYPT_EAL_PkeyGetExtData Test.
 * @precon nan
 * @brief
 *    1. Create the context(ctx) of pkeyId, expected result 1
 *    2. Call the CRYPT_EAL_PkeySetExtData to set ext data, ctx is null, expected result 2
 *    3. Call the CRYPT_EAL_PkeySetExtData to set ext data, all parameters are valid, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGetExtData to get ext data, ctx is null, expected result 4
 *    5. Call the CRYPT_EAL_PkeyGetExtData to get ext data, all parameters are valid, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_SUCCESS
 *    4. Return null.
 *    5. The returned value is not null and the value is correct.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_PKEY_EXT_DATA_API_TC001(void)
{
    int pkeyId = CRYPT_PKEY_DSA;
    int data = 1;
    void *ptr = NULL;

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(pkeyId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetExtData(NULL, &data), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeySetExtData(ctx, &data), CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetExtData(NULL) == NULL);
    ptr = CRYPT_EAL_PkeyGetExtData(ctx);
    ASSERT_TRUE(ptr != NULL);
    ASSERT_EQ(*(int *)ptr, data);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_REINIT_TC001
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_REINIT_TC001(int id)
{
    uint8_t key[16] = {0};
    uint32_t keyLen = 16;
    uint8_t iv[16] = {0};
    uint32_t ivLen = 16;
    uint8_t in[15] = {0};
    uint32_t inLen = 15;
    uint8_t out[64] = {0};
    uint32_t outLen = 64;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx((CRYPT_CIPHER_AlgId)id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    (void)CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv, ivLen), CRYPT_SUCCESS);
    struct ModesCipherCtx *ciphCtx = ((struct CRYPT_EAL_CipherCtxLocal *)ctx)->ctx;
    ASSERT_TRUE(ciphCtx != NULL);
    // Check data dataLen
    ASSERT_EQ(ciphCtx->dataLen, 0);
    for (uint32_t i = 0; i < EAL_MAX_BLOCK_LENGTH; i++) {
        ASSERT_EQ(ciphCtx->data[i], 0);
    }
EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_REINIT_TC002
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_REINIT_TC002(int id)
{
    uint8_t key[32] = {0};
    uint32_t keyLen = 32;
    uint8_t iv[12] = {0};
    uint32_t ivLen = 12;
    uint8_t in[15] = {0};
    uint32_t inLen = 15;
    uint8_t out[64] = {0};
    uint32_t outLen = 64;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx((CRYPT_CIPHER_AlgId)id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv, ivLen), CRYPT_SUCCESS);
    struct ModesChaChaCtx *ciphCtx = ((struct CRYPT_EAL_CipherCtxLocal *)ctx)->ctx;
    ASSERT_TRUE(ciphCtx != NULL);
    // Check data dataLen
    ASSERT_EQ(ciphCtx->chachaCtx.polyCtx.lastLen, 0);
    uint32_t lastSize = (uint32_t)sizeof(ciphCtx->chachaCtx.polyCtx.last);
    for (uint32_t i = 0; i < lastSize; i++) {
        ASSERT_EQ(ciphCtx->chachaCtx.polyCtx.last[i], 0);
    }
    // Check aadLen cipherTextLen
    ASSERT_EQ(ciphCtx->chachaCtx.aadLen, 0);
    ASSERT_EQ(ciphCtx->chachaCtx.cipherTextLen, 0);
EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_REINIT_TC003
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_REINIT_TC003(int id)
{
    uint8_t key[16] = {0};
    uint32_t keyLen = 16;
    uint8_t iv[12] = {0};
    uint32_t ivLen = 12;
    uint8_t in[15] = {0};
    uint32_t inLen = 15;
    uint8_t out[64] = {0};
    uint32_t outLen = 64;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx((CRYPT_CIPHER_AlgId)id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv, ivLen), CRYPT_SUCCESS);
    struct ModesGcmCtx *ciphCtx = ((struct CRYPT_EAL_CipherCtxLocal *)ctx)->ctx;
    ASSERT_TRUE(ciphCtx != NULL);
    // Check data dataLen
    ASSERT_EQ(ciphCtx->gcmCtx.aadLen, 0);
    ASSERT_EQ(ciphCtx->gcmCtx.lastLen, 0);
    ASSERT_EQ(ciphCtx->gcmCtx.plaintextLen, 0);
    for (uint32_t i = 0; i < GCM_BLOCKSIZE; i++) {
        ASSERT_EQ(ciphCtx->gcmCtx.ghash[i], 0);
    }
EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_GET_KEY_LEN_TC001
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_GET_KEY_LEN_TC001(int algid, int paramId, int pubLen, int prvLen, int sharedLen)
{
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(algid);
    ASSERT_TRUE(ctx != NULL);
    int32_t ret;
    if (paramId != 0) {
        ret = CRYPT_EAL_PkeySetParaById(ctx, paramId);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    }

    uint32_t val = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(val, pubLen);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(val, prvLen);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(val, sharedLen);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_GET_KEY_LEN_TC002
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_GET_KEY_LEN_TC002(int algid, int paramId, int pubLen, int prvLen)
{
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(algid);
    ASSERT_TRUE(ctx != NULL);
    int32_t ret;
    if (paramId != 0) {
        ret = CRYPT_EAL_PkeySetParaById(ctx, paramId);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    }

    uint32_t val = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(val, pubLen);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(val, prvLen);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_GET_KEY_LEN_TC003_1
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_GET_KEY_LEN_TC003_1(int algid, int rsaBits, Hex *p, Hex *q, Hex *g)
{
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(algid);
    ASSERT_TRUE(ctx != NULL);
    int32_t ret;
    CRYPT_EAL_PkeyPara para = {0};
    uint8_t e[3] = {1, 0, 1};
    if (algid == CRYPT_PKEY_RSA) {
        para.id = CRYPT_PKEY_RSA;
        para.para.rsaPara.e = e;
        para.para.rsaPara.eLen = 3;
        para.para.rsaPara.bits = rsaBits;
    } else {
        para.id = algid;  // DH or DSA
        para.para.dhPara.p = p->x;
        para.para.dhPara.q = q->x;
        para.para.dhPara.g = g->x;
        para.para.dhPara.pLen = p->len;
        para.para.dhPara.qLen = q->len;
        para.para.dhPara.gLen = g->len;
    }
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(ctx, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);

    uint32_t val = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    if (algid == CRYPT_PKEY_DH) {
        ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &val, sizeof(val));
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_GET_KEY_LEN_TC003_2
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_GET_KEY_LEN_TC003_2(int algid, int rsaBits, Hex *p, Hex *q, Hex *g)
{
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(algid);
    ASSERT_TRUE(ctx != NULL);
    int32_t ret;
    CRYPT_EAL_PkeyPara para = {0};
    uint8_t e[3] = {1, 0, 1};
    if (algid == CRYPT_PKEY_RSA) {
        para.id = CRYPT_PKEY_RSA;
        para.para.rsaPara.e = e;
        para.para.rsaPara.eLen = 3;
        para.para.rsaPara.bits = rsaBits;
    } else {
        para.id = algid;  // DH or DSA
        para.para.dhPara.p = p->x;
        para.para.dhPara.q = q->x;
        para.para.dhPara.g = g->x;
        para.para.dhPara.pLen = p->len;
        para.para.dhPara.qLen = q->len;
        para.para.dhPara.gLen = g->len;
    }
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(ctx, &para), CRYPT_SUCCESS);
    uint32_t flag = CRYPT_ENABLE_SP800_KEYGEN_FLAG;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_GEN_FLAG, &flag, sizeof(flag));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    flag = CRYPT_DISABLE_SP800_KEYGEN_FLAG;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_GEN_FLAG, &flag, sizeof(flag));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_GET_KEY_LEN_TC003_3
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_GET_KEY_LEN_TC003_3(int algid, int rsaBits, Hex *p, Hex *q, Hex *g)
{
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(algid);
    ASSERT_TRUE(ctx != NULL);
    int32_t ret;
    CRYPT_EAL_PkeyPara para = {0};
    uint8_t e[3] = {1, 0, 1};
    if (algid == CRYPT_PKEY_RSA) {
        para.id = CRYPT_PKEY_RSA;
        para.para.rsaPara.e = e;
        para.para.rsaPara.eLen = 3;
        para.para.rsaPara.bits = rsaBits;
    } else {
        para.id = algid;  // DH or DSA
        para.para.dhPara.p = p->x;
        para.para.dhPara.q = q->x;
        para.para.dhPara.g = g->x;
        para.para.dhPara.pLen = p->len;
        para.para.dhPara.qLen = q->len;
        para.para.dhPara.gLen = g->len;
    }
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(ctx, &para), CRYPT_SUCCESS);
    uint32_t flag = CRYPT_ENABLE_SP800_KEYGEN_FLAG;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_GEN_FLAG, &flag, sizeof(flag));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

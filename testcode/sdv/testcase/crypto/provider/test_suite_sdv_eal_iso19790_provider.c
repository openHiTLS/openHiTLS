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
#include <stdlib.h>
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_eal_provider.h"
#include "crypt_provider_local.h"
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#include "crypt_eal_mac.h"
#include "eal_mac_local.h"
#include "crypt_eal_kdf.h"
#include "eal_kdf_local.h"
#include "crypt_eal_md.h"
#include "eal_md_local.h"
#include "crypt_eal_pkey.h"
#include "eal_pkey_local.h"
#include "test.h"
#include "crypt_eal_cmvp.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_errno.h"
#include "crypt_eal_md.h"
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"
#include "crypt_eal_entropy.h"
#include "crypt_util_rand.h"
#include "crypt_params_key.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
/* END_HEADER */

#ifdef HITLS_CRYPTO_CMVP_ISO19790_PURE_C
#define HITLS_CRYPTO_CMVP_ISO19790
#define HITLS_ISO_PROVIDER_PATH "../../output/CMVP/C/lib"
#endif

#ifdef HITLS_CRYPTO_CMVP_ISO19790_ARMV8_LE
#define HITLS_CRYPTO_CMVP_ISO19790
#define HITLS_ISO_PROVIDER_PATH "../../output/CMVP/armv8_le/lib"
#endif

#ifdef HITLS_CRYPTO_CMVP_ISO19790_X86_64
#define HITLS_CRYPTO_CMVP_ISO19790
#define HITLS_ISO_PROVIDER_PATH "../../output/CMVP/x86_64/lib"
#endif

#ifdef HITLS_CRYPTO_CMVP_ISO19790
#define ISO19790_LOG_FILE "iso19790_audit.log"
#ifndef HITLS_PROVIDER_LIB_NAME
#error "HITLS_PROVIDER_LIB_NAME must be defined by build system"
#endif
#define HITLS_ISO_PROVIDER_ATTR "provider=iso"

static FILE* g_logFile = NULL;

static int32_t InitLogFile(void)
{
    if (g_logFile == NULL) {
        g_logFile = fopen(ISO19790_LOG_FILE, "a");
        if (g_logFile == NULL) {
            return CRYPT_NULL_INPUT;
        }
    }
    return CRYPT_SUCCESS;
}

static void CloseLogFile(void)
{
    if (g_logFile != NULL) {
        fclose(g_logFile);
        g_logFile = NULL;
    }
}

static void ISO19790_RunLogCb(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err)
{
    char timeStr[72] = {0};
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);

    if (InitLogFile() != CRYPT_SUCCESS) {
        return;
    }

    sprintf(timeStr, "%d-%d-%d %d:%d:%d",
            tm_info->tm_year + 1900,
            tm_info->tm_mon + 1,
            tm_info->tm_mday,
            tm_info->tm_hour,
            tm_info->tm_min,
            tm_info->tm_sec);

    if (oper == CRYPT_EVENT_INTEGRITY_TEST) {
        if (err == CRYPT_SUCCESS) {
            fprintf(g_logFile, "[%s] [open hitls] [INFO] Integrity test begin.\n", timeStr);
        } else {
            fprintf(g_logFile, "[%s] [open hitls] [ERR] Integrity test failed, errcode: 0x%x\n", timeStr, err);
        }
        fflush(g_logFile);
        CloseLogFile();
        return;
    }

    // ISO/IEC 19790:2012 AS09.33
    // The module shall provide an output status indication when zeroing is complete
    if (oper == CRYPT_EVENT_ZERO && err == CRYPT_SUCCESS) {
        fprintf(g_logFile, "[%s] [open hitls] [INFO] SSP already zeroisation - algorithm type: %d, id: %d\n",
                timeStr, type, id);
        fflush(g_logFile);
    }

    /*
        ISO/IEC 19790:2012 AS06.26
        The following events of the cryptographic module should be recorded by the OS audit mechanism:
        ● Attempted to provide invalid input for the cryptographic officer function;
    */
    if (err != CRYPT_SUCCESS) {
        fprintf(g_logFile, "[%s] [open hitls] [ERR]  Occur error - algorithm type: %d, id: %d, operate: %d, errcode: 0x%x\n",
                timeStr, type, id, oper, err);
        fflush(g_logFile);
    }
    /*
        ISO/IEC 19790:2012 AS06.26
        The following events of the cryptographic module should be recorded by the OS audit mechanism:
        ● Modify, access, delete, and add encrypted data and SSPs；
        ● Use security-related encryption features
        ISO/IEC 19790:2012 AS02.24
        When a service uses approved encryption algorithms, security functions or processes,
        and specified services or processes in an approved manner,
        the service shall provide corresponding status indications.
    */
    fprintf(g_logFile, "[%s] [open hitls] [INFO] Excute - algorithm type: %d, id: %d, operate: %d\n",
            timeStr, type, id, oper);
    fflush(g_logFile);
    CloseLogFile();
}


static int32_t GetEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    return CRYPT_EAL_SeedPoolGetEntropy((CRYPT_EAL_SeedPoolCtx *)ctx, entropy, strength, lenRange);
}

static void CleanEntropy(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    BSL_SAL_ClearFree(entropy->data, entropy->len);
}

static int32_t GetNonce(void *ctx, CRYPT_Data *nonce, uint32_t strength, CRYPT_Range *lenRange)
{
    return GetEntropy(ctx, nonce, strength, lenRange);
}

static void CleanNonce(void *ctx, CRYPT_Data *nonce)
{
    CleanEntropy(ctx, nonce);
}

static int32_t GetEntropy_Stub(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)ctx;
    (void)strength;
    entropy->data = BSL_SAL_Malloc(lenRange->min);
    if (entropy->data == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    entropy->len = lenRange->min;
    for (uint32_t i = 0; i < entropy->len; i++) {
        entropy->data[i] = rand() % 256;
    }
    return CRYPT_SUCCESS;
}

static void CleanEntropy_Stub(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    BSL_SAL_ClearFree(entropy->data, entropy->len);
    entropy->data = NULL;
    entropy->len = 0;
}

static int32_t GetNonce_Stub(void *ctx, CRYPT_Data *nonce, uint32_t strength, CRYPT_Range *lenRange)
{
    return GetEntropy_Stub(ctx, nonce, strength, lenRange);
}

static void CleanNonce_Stub(void *ctx, CRYPT_Data *nonce)
{
    CleanEntropy_Stub(ctx, nonce);
}

static void EntropyRunLogCb(int32_t ret)
{
    char timeStr[72] = {0};
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);

    if (InitLogFile() != CRYPT_SUCCESS) {
        return;
    }

    sprintf(timeStr, "%d-%d-%d %d:%d:%d",
            tm_info->tm_year + 1900,
            tm_info->tm_mon + 1,
            tm_info->tm_mday,
            tm_info->tm_hour,
            tm_info->tm_min,
            tm_info->tm_sec);

    fprintf(g_logFile, "[%s] [open hitls] [INFO] Excute entropy health test - ret: %d\n",
            timeStr, ret);
    fflush(g_logFile);
    CloseLogFile();
}

typedef struct {
    CRYPT_EAL_LibCtx *libCtx;
} Iso19790_ProviderLoadCtx;

static int32_t Iso19790_ProviderLoad(Iso19790_ProviderLoadCtx *ctx)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;

    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);

    CRYPT_EAL_RegEventReport(ISO19790_RunLogCb);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, HITLS_ISO_PROVIDER_PATH), CRYPT_SUCCESS);

    int index = 0;
    BSL_Param param[7] = {{0}, {0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_CMVP_LOG_FUNC, BSL_PARAM_TYPE_FUNC_PTR, ISO19790_RunLogCb, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR, GetEntropy_Stub, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR, CleanEntropy_Stub, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR, GetNonce_Stub, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR, CleanNonce_Stub, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, NULL, 0);

    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, 0, HITLS_PROVIDER_LIB_NAME, param, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(libCtx, CRYPT_RAND_SHA256, HITLS_ISO_PROVIDER_ATTR, NULL, 0, NULL), CRYPT_SUCCESS);

    ctx->libCtx = libCtx;
    return CRYPT_SUCCESS;

EXIT:
    CRYPT_EAL_LibCtxFree(libCtx);
    return CRYPT_MEM_ALLOC_FAIL;
}

static void Iso19790_ProviderUnload(Iso19790_ProviderLoadCtx *ctx)
{
    CRYPT_EAL_RandDeinitEx(ctx->libCtx);
    CRYPT_EAL_LibCtxFree(ctx->libCtx);
    (void)memset_s(ctx, sizeof(Iso19790_ProviderLoadCtx), 0, sizeof(Iso19790_ProviderLoadCtx));
}
#endif

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_PKEY_SIGN_VERIFY_TEST_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_PkeyCtx *keyCtx = NULL;
    uint8_t signature[128] = {0};
    uint32_t signatureLen = sizeof(signature);
    uint8_t testData[] = "Test data for signing and verification with ECDSA";
    uint32_t testDataLen = sizeof(testData) - 1;
    
    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    keyCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_SM2, 0, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(keyCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(keyCtx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(keyCtx, CRYPT_MD_SM3, testData, testDataLen, signature, &signatureLen), 0);
    ASSERT_TRUE(signatureLen > 0);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(keyCtx, CRYPT_MD_SM3, testData, testDataLen, signature, signatureLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(keyCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

#ifdef HITLS_CRYPTO_CMVP_ISO19790
static void SetRsaPara(CRYPT_EAL_PkeyPara *para, uint8_t *e, uint32_t eLen, uint32_t bits)
{
    para->id = CRYPT_PKEY_RSA;
    para->para.rsaPara.e = e;
    para->para.rsaPara.eLen = eLen;
    para->para.rsaPara.bits = bits;
}
#endif

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_PKEY_SIGN_VERIFY_TEST_TC002()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    uint8_t e[] = {1, 0, 1};
    CRYPT_EAL_PkeyPara para = {0};
    int32_t mdId = CRYPT_MD_SHA256;
    int32_t pkcsv15 = mdId;
    uint8_t signature[256] = {0};
    uint32_t signatureLen = sizeof(signature);
    uint8_t testData[] = "Test data for signing and verification with ECDSA";
    uint32_t testDataLen = sizeof(testData) - 1;

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_RSA, 0, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(pkeyCtx != NULL);
    SetRsaPara(&para, e, 3, 2048);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkeyCtx, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, testData, testDataLen, signature, &signatureLen), 0);
    ASSERT_TRUE(signatureLen > 0);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkeyCtx, mdId, testData, testDataLen, signature, signatureLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO_PROVIDER_PKEY_ENCRYPT_DECRYPT_TEST_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    uint8_t e[] = {1, 0, 1};
    CRYPT_EAL_PkeyPara para = {0};
    int32_t mdId = CRYPT_MD_SHA256;
    uint8_t plaintext[256] = {0};
    uint32_t plaintextLen = sizeof(plaintext);
    uint8_t ciphertext[256] = {0};
    uint32_t ciphertextLen = sizeof(ciphertext);
    uint8_t testData[] = "Test data for encrypt and decrypt with RSA.";
    uint32_t testDataLen = sizeof(testData) - 1;

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    BSL_Param oaep[3] = {{CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END
    };

    pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_RSA, 0, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(pkeyCtx != NULL);
    SetRsaPara(&para, e, 3, 2048);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkeyCtx, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaep, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(pkeyCtx, testData, testDataLen, ciphertext, &ciphertextLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(pkeyCtx, ciphertext, ciphertextLen, plaintext, &plaintextLen), CRYPT_SUCCESS);
    ASSERT_EQ(testDataLen, plaintextLen);
    ASSERT_EQ(memcmp(testData, plaintext, plaintextLen), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_DRBG_TEST_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    CRYPT_EAL_Es *es = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = NULL;
    CRYPT_EAL_RndCtx *randCtx1 = NULL;
    CRYPT_EAL_RndCtx *randCtx2 = NULL;
    CRYPT_EAL_LibCtx *libCtx = NULL;
    int32_t ret = CRYPT_SUCCESS;

    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);

    CRYPT_EAL_RegEventReport(ISO19790_RunLogCb);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, HITLS_ISO_PROVIDER_PATH), CRYPT_SUCCESS);

    BSL_Param param[2] = {{0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_CMVP_LOG_FUNC, BSL_PARAM_TYPE_FUNC_PTR, ISO19790_RunLogCb, 0);
    for (int32_t i = 0; i < 3; i++) {
        ret = CRYPT_EAL_ProviderLoad(libCtx, 0, HITLS_PROVIDER_LIB_NAME, param, NULL);
        if (ret == CRYPT_SUCCESS) {
            break;
        }
    }
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    bool healthTest = true;
    uint32_t seedPoolSize = 4096;
    es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);

    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, "sha256_df", (uint32_t)strlen("sha256_df")), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, "timestamp", (uint32_t)strlen("timestamp")), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_LOG_CALLBACK, EntropyRunLogCb, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(healthTest)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, &seedPoolSize, sizeof(seedPoolSize)), CRYPT_SUCCESS);
    for (int32_t i = 0; i < 3; i++) {
        ret = CRYPT_EAL_EsInit(es);
        if (ret == CRYPT_SUCCESS) {
            break;
        }
    }
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    pool = CRYPT_EAL_SeedPoolNew(true);
    ASSERT_TRUE(pool != NULL);

    CRYPT_EAL_EsPara para = {
        false,
        8,
        es,
        (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet,
    };

    ASSERT_EQ(CRYPT_EAL_SeedPoolAddEs(pool, &para), CRYPT_SUCCESS);

    int index = 0;
    BSL_Param randParam[6] = {0};
    ASSERT_EQ(BSL_PARAM_InitValue(&randParam[index++], CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR, GetEntropy, 0), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&randParam[index++], CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR, CleanEntropy, 0), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&randParam[index++], CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR, GetNonce, 0), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&randParam[index++], CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR, CleanNonce, 0), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&randParam[index++], CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, pool, 0), CRYPT_SUCCESS);

    randCtx1 = CRYPT_EAL_ProviderDrbgNewCtx(libCtx, CRYPT_RAND_SHA256, NULL, randParam);
    randCtx2 = CRYPT_EAL_ProviderDrbgNewCtx(libCtx, CRYPT_RAND_SHA256, NULL, NULL);
    ASSERT_TRUE(randCtx1 != NULL && randCtx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_DrbgInstantiate(randCtx1, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DrbgInstantiate(randCtx2, NULL, 0), CRYPT_SUCCESS);

    unsigned char data[16] = {0};
    uint32_t dataLen = sizeof(data);
    ASSERT_EQ(CRYPT_EAL_Drbgbytes(randCtx1, data, dataLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Drbgbytes(randCtx2, data, dataLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DrbgSeed(randCtx1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DrbgSeed(randCtx2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Drbgbytes(randCtx1, data, dataLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Drbgbytes(randCtx2, data, dataLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_DrbgDeinit(randCtx1);
    CRYPT_EAL_DrbgDeinit(randCtx2);
    CRYPT_EAL_SeedPoolFree(pool);
    CRYPT_EAL_EsFree(es);
    CRYPT_EAL_LibCtxFree(libCtx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_MD_TEST_TC001(int algId)
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    (void)algId;
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_MdCTX *mdCtx = NULL;
    uint8_t plaintext[128] = {0};
    uint32_t plaintextLen = sizeof(plaintext);
    uint8_t md[128] = {0};
    uint32_t mdLen = sizeof(md);

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(ctx.libCtx, algId, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(mdCtx != NULL);
    int32_t ret = CRYPT_EAL_MdInit(mdCtx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_MdUpdate(mdCtx, plaintext, plaintextLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_MdFinal(mdCtx, md, &mdLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MdFreeCtx(mdCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_MAC_TEST_TC001(int algId, int keyLen)
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    (void)algId;
    (void)keyLen;
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_MacCtx *macCtx = NULL;
    uint8_t macKey[32] = {0};
    uint32_t macKeyLen = keyLen;
    uint8_t plaintext[128] = {0};
    uint32_t plaintextLen = sizeof(plaintext);
    uint8_t iv[16] = {0};
    uint32_t ivLen = sizeof(iv);
    int32_t tagLen = 16;
    uint8_t mac[128] = {0};
    uint32_t macLen = sizeof(mac);

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    macCtx = CRYPT_EAL_ProviderMacNewCtx(ctx.libCtx, algId, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(macCtx != NULL);
    int32_t ret = CRYPT_EAL_MacInit(macCtx, macKey, macKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    if (algId == CRYPT_MAC_GMAC_AES128 || algId == CRYPT_MAC_GMAC_AES192 || algId == CRYPT_MAC_GMAC_AES256) {
        ret = CRYPT_EAL_MacCtrl(macCtx, CRYPT_CTRL_SET_IV, iv, ivLen);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ret = CRYPT_EAL_MacCtrl(macCtx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen));
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    }

    ret = CRYPT_EAL_MacUpdate(macCtx, plaintext, plaintextLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    if (algId == CRYPT_MAC_GMAC_AES128 || algId == CRYPT_MAC_GMAC_AES192 || algId == CRYPT_MAC_GMAC_AES256) {
        macLen = tagLen;
    }
    ret = CRYPT_EAL_MacFinal(macCtx, mac, &macLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MacFreeCtx(macCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_KDF_TEST_TC001(int macId, int iter, int saltLen)
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    (void)macId;
    (void)iter;
    (void)saltLen;
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_KdfCTX *kdfCtx = NULL;
    uint8_t password[32] = {0};
    uint32_t passwordLen = sizeof(password);
    uint8_t salt[32] = {0};
    uint8_t derivedKey[32] = {0};
    uint32_t derivedKeyLen = sizeof(derivedKey);

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(ctx.libCtx, CRYPT_KDF_PBKDF2, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(kdfCtx != NULL);

    BSL_Param param[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};

    (void)BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &macId, sizeof(macId));
    (void)BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, password, passwordLen);
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen);
    (void)BSL_PARAM_InitValue(&param[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &iter, sizeof(iter));

    int32_t ret = CRYPT_EAL_KdfSetParam(kdfCtx, param);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_KdfDerive(kdfCtx, derivedKey, derivedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_KDF_TEST_TC002(int algId, Hex *key, Hex *salt, Hex *info)
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    (void)algId;
    (void)key;
    (void)salt;
    (void)info;
    SKIP_TEST();
#else
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_KdfCTX *kdfCtx = NULL;
    uint32_t outLen = 32;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);
    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(ctx.libCtx, CRYPT_KDF_HKDF, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(kdfCtx != NULL);

    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
        &mode, sizeof(mode)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        info->x, info->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(kdfCtx, out, outLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    if (out != NULL) {
        free(out);
    }
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_KDF_TEST_TC003(int algId, Hex *key, Hex *label, Hex *seed, Hex *result)
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    (void)algId;
    (void)key;
    (void)label;
    (void)seed;
    (void)result;
    SKIP_TEST();
#else
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_KdfCTX *kdfCtx = NULL;

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(ctx.libCtx, CRYPT_KDF_KDFTLS12, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(kdfCtx != NULL);

    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_LABEL, BSL_PARAM_TYPE_OCTETS,
        label->x, label->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SEED, BSL_PARAM_TYPE_OCTETS,
        seed->x, seed->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(kdfCtx, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    if (out != NULL) {
        free(out);
    }
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */


/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_Get_Status_Test_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_ProvMgrCtx *providerMgr = NULL;

    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, HITLS_ISO_PROVIDER_PATH), CRYPT_SUCCESS);
    
    bool isLoaded = false;
    int32_t ret = CRYPT_EAL_ProviderIsLoaded(libCtx, 0, HITLS_PROVIDER_LIB_NAME, &isLoaded);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(isLoaded == false);

    int index = 0;
    BSL_Param param[7] = {{0}, {0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_CMVP_LOG_FUNC, BSL_PARAM_TYPE_FUNC_PTR, ISO19790_RunLogCb, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR, GetEntropy_Stub, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR, CleanEntropy_Stub, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR, GetNonce_Stub, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR, CleanNonce_Stub, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, NULL, 0);

    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, 0, HITLS_PROVIDER_LIB_NAME, param, &providerMgr), CRYPT_SUCCESS);
    ASSERT_TRUE(providerMgr != NULL);

    ret = CRYPT_EAL_ProviderIsLoaded(libCtx, 0, HITLS_PROVIDER_LIB_NAME, &isLoaded);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(isLoaded);

    providerMgr = NULL;
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, 0, HITLS_PROVIDER_LIB_NAME, param, &providerMgr), CRYPT_SUCCESS);
    ASSERT_TRUE(providerMgr != NULL);

    ret = CRYPT_EAL_ProviderUnload(libCtx, 0, HITLS_PROVIDER_LIB_NAME);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_ProviderIsLoaded(libCtx, 0, HITLS_PROVIDER_LIB_NAME, &isLoaded);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(isLoaded);

    ret = CRYPT_EAL_ProviderUnload(libCtx, 0, HITLS_PROVIDER_LIB_NAME);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_ProviderIsLoaded(libCtx, 0, HITLS_PROVIDER_LIB_NAME, &isLoaded);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(isLoaded == false);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_ProviderUnload(libCtx, 0, HITLS_PROVIDER_LIB_NAME);
    CRYPT_EAL_LibCtxFree(libCtx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_CMVP_SELFTEST_Test_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_SelftestCtx *selftestCtx = NULL;

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    selftestCtx = CRYPT_CMVP_SelftestNewCtx(ctx.libCtx, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(selftestCtx != NULL);

    const char *version = CRYPT_CMVP_GetVersion(selftestCtx);
    ASSERT_TRUE(version != NULL);

    BSL_Param params[2] = {{0}, BSL_PARAM_END};
    int32_t type = CRYPT_CMVP_KAT_TEST;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_CMVP_SELFTEST_TYPE, BSL_PARAM_TYPE_INT32,
        &type, sizeof(type)), CRYPT_SUCCESS);
    int32_t ret = CRYPT_CMVP_Selftest(selftestCtx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    type = CRYPT_CMVP_INTEGRITY_TEST;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_CMVP_SELFTEST_TYPE, BSL_PARAM_TYPE_INT32,
        &type, sizeof(type)), CRYPT_SUCCESS);
    ret = CRYPT_CMVP_Selftest(selftestCtx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_CMVP_SelftestFreeCtx(selftestCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */


/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_CIPHPER_TEST_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_CipherCtx *cipherCtx = NULL;

    uint8_t key[32] = {0};
    uint32_t keyLen = 16;
    uint8_t iv[32] = {0};
    uint32_t ivLen = 16;
    uint8_t plain[] = "Test data for signing and verification with ECDSA";
    uint32_t plainLen = sizeof(plainLen) - 1;
    uint8_t cipher[128] = {0};
    uint32_t cipherLen = sizeof(cipher);
    
    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    cipherCtx = CRYPT_EAL_ProviderCipherNewCtx(ctx.libCtx, CRYPT_CIPHER_AES128_CBC, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(cipherCtx != NULL);

    int32_t ret = CRYPT_EAL_CipherInit(cipherCtx, key, keyLen, iv, ivLen, true);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    
    ret = CRYPT_EAL_CipherSetPadding(cipherCtx, CRYPT_PADDING_PKCS7);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    
    uint32_t tmpLen = cipherLen;
    ret = CRYPT_EAL_CipherUpdate(cipherCtx, plain, plainLen, cipher, &tmpLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    cipherLen = tmpLen;
    tmpLen = sizeof(cipher) - cipherLen;
    ret = CRYPT_EAL_CipherFinal(cipherCtx, cipher + cipherLen, &tmpLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    cipherLen += tmpLen;
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherFreeCtx(cipherCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */


#ifdef HITLS_CRYPTO_CMVP_ISO19790
static void SetDsaPara(CRYPT_EAL_PkeyPara *para, uint8_t *p, uint32_t pLen, uint8_t *q, uint32_t qLen, uint8_t *g, uint32_t gLen)
{
    para->id = CRYPT_PKEY_DSA;
    para->para.dsaPara.p = p;
    para->para.dsaPara.pLen = pLen;
    para->para.dsaPara.q = q;
    para->para.dsaPara.qLen = qLen;
    para->para.dsaPara.g = g;
    para->para.dsaPara.gLen = gLen;
}
#endif

/*
    SDV_ISO19790_PROVIDER_PKEY_TEST_TC001
    测试DSA set para
*/
/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_PKEY_TEST_TC001(int hashId, Hex *p, Hex *q, Hex *g)
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    (void)hashId;
    (void)p;
    (void)q;
    (void)g;
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;

    CRYPT_EAL_PkeyPara para = {0};
    uint8_t signature[128] = {0};
    uint32_t signatureLen = sizeof(signature);
    uint8_t testData[] = "Test data for signing and verification with ECDSA";
    uint32_t testDataLen = sizeof(testData) - 1;
    
    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_DSA, 0, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(pkeyCtx != NULL);
    SetDsaPara(&para, p->x, p->len, q->x, q->len, g->x, g->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkeyCtx, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, hashId, testData, testDataLen, signature, &signatureLen), 0);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkeyCtx, hashId, testData, testDataLen, signature, signatureLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_MAC_PARAM_CHECK_TC001(int algId, int keyLen)
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    (void)algId;
    (void)keyLen;
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_MacCtx *macCtx = NULL;
    uint8_t macKey[32] = {0};
    uint32_t macKeyLen = 13;

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    macCtx = CRYPT_EAL_ProviderMacNewCtx(ctx.libCtx, algId, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(macCtx != NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());
    
    int32_t ret = CRYPT_EAL_MacInit(macCtx, macKey, macKeyLen);
    ASSERT_EQ(ret, CRYPT_CMVP_ERR_PARAM_CHECK);

    macKeyLen = keyLen;
    ret = CRYPT_EAL_MacInit(macCtx, macKey, macKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MacFreeCtx(macCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_KDF_PARAM_CHECK_TC001(Hex *key, Hex *label, Hex *seed)
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    (void)key;
    (void)label;
    (void)seed;
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_KdfCTX *kdfCtx = NULL;

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(ctx.libCtx, CRYPT_KDF_KDFTLS12, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(kdfCtx != NULL);

    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, 14), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_LABEL, BSL_PARAM_TYPE_OCTETS,
        label->x, label->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SEED, BSL_PARAM_TYPE_OCTETS,
        seed->x, seed->len), CRYPT_SUCCESS);

    int32_t macId = CRYPT_MAC_HMAC_SHA224;

    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macId, sizeof(macId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, params), CRYPT_CMVP_ERR_PARAM_CHECK);

    macId = CRYPT_MAC_HMAC_SHA256;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macId, sizeof(macId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, params), CRYPT_SUCCESS);

    // key len < 112 / 8
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, 13), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, params), CRYPT_CMVP_ERR_PARAM_CHECK);

EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_KDF_PARAM_CHECK_TC002(Hex *key, Hex *salt, Hex *info)
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    (void)key;
    (void)salt;
    (void)info;
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_KdfCTX *kdfCtx = NULL;
    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(ctx.libCtx, CRYPT_KDF_HKDF, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(kdfCtx != NULL);

    int32_t macId = CRYPT_MAC_HMAC_SHA256;
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macId, sizeof(macId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
        &mode, sizeof(mode)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        info->x, info->len), CRYPT_SUCCESS);

    macId = CRYPT_MAC_HMAC_SM3;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, params), CRYPT_CMVP_ERR_PARAM_CHECK);

    macId = CRYPT_MAC_HMAC_SHA256;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, params), CRYPT_SUCCESS);

    // key len < 112 / 8
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, 13), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, params), CRYPT_CMVP_ERR_PARAM_CHECK);
    TestErrClear();

    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, 14), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, params), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_KDF_PARAM_CHECK_TC003()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_KdfCTX *kdfCtx = NULL;
    uint8_t password[32] = {0};
    uint32_t passwordLen = sizeof(password);
    uint8_t salt[32] = {0};
    uint8_t derivedKey[32] = {0};

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(ctx.libCtx, CRYPT_KDF_PBKDF2, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(kdfCtx != NULL);

    int32_t iter = 1024;
    int32_t saltLen = 16;
    int32_t macId = CRYPT_MAC_SIPHASH64;

    BSL_Param param[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &macId, sizeof(macId));
    (void)BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, password, passwordLen);
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen);
    (void)BSL_PARAM_InitValue(&param[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &iter, sizeof(iter));

    int32_t ret = CRYPT_EAL_KdfSetParam(kdfCtx, param);
    ASSERT_EQ(ret, CRYPT_CMVP_ERR_PARAM_CHECK);

    macId = CRYPT_MAC_HMAC_SHA1;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, param), CRYPT_SUCCESS);

    iter = 999;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, param), CRYPT_CMVP_ERR_PARAM_CHECK);

    iter = 1000;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, param), CRYPT_SUCCESS);

    saltLen = 15;
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, param), CRYPT_CMVP_ERR_PARAM_CHECK);

    saltLen = 16;
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(kdfCtx, param), CRYPT_SUCCESS);

    uint32_t derivedKeyLen = 13;
    ret = CRYPT_EAL_KdfDerive(kdfCtx, derivedKey, derivedKeyLen);
    ASSERT_EQ(ret, CRYPT_CMVP_ERR_PARAM_CHECK);

    derivedKeyLen = 14;
    ret = CRYPT_EAL_KdfDerive(kdfCtx, derivedKey, derivedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_DSA_PARAM_CHECK_TC001(Hex *p, Hex *q, Hex *g)
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    (void)p;
    (void)q;
    (void)g;
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;

    CRYPT_EAL_PkeyPara para = {0};

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_DSA, 0, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(pkeyCtx != NULL);

    SetDsaPara(&para, p->x, 256, q->x, 27, g->x, 256);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkeyCtx, &para), CRYPT_CMVP_ERR_PARAM_CHECK);

    SetDsaPara(&para, p->x, 256, q->x, 31, g->x, 256);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkeyCtx, &para), CRYPT_CMVP_ERR_PARAM_CHECK);

    SetDsaPara(&para, p->x, 384, q->x, 31, g->x, 384);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkeyCtx, &para), CRYPT_CMVP_ERR_PARAM_CHECK);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_RSA_PARAM_CHECK_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    uint8_t e[] = {1, 0, 1};
    CRYPT_EAL_PkeyPara para = {0};

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_RSA, 0, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(pkeyCtx != NULL);
    SetRsaPara(&para, e, 3, 1024);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkeyCtx, &para), CRYPT_CMVP_ERR_PARAM_CHECK);

    SetRsaPara(&para, e, 3, 2048);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkeyCtx, &para), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/*
    Check the padding mode of the RSA.
*/
/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_RSA_PARAM_CHECK_TC002()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    uint8_t e[] = {1, 0, 1};
    CRYPT_EAL_PkeyPara para = {0};
    int32_t mdId = CRYPT_MD_SHA256;

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_RSA, 0, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(pkeyCtx != NULL);
    SetRsaPara(&para, e, 3, 2048);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkeyCtx, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkeyCtx), CRYPT_SUCCESS);

    int32_t pkcsv15 = mdId;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &pkcsv15, sizeof(pkcsv15)),
        CRYPT_CMVP_ERR_PARAM_CHECK);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15_TLS, &pkcsv15, sizeof(pkcsv15)),
        CRYPT_CMVP_ERR_PARAM_CHECK);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_NO_PADDING, NULL, 0), CRYPT_CMVP_ERR_PARAM_CHECK);

    int32_t pad = CRYPT_EMSA_PKCSV15;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(pad)), CRYPT_SUCCESS);
    pad = CRYPT_EMSA_PSS;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(pad)), CRYPT_SUCCESS);
    pad = CRYPT_RSAES_OAEP;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(pad)), CRYPT_SUCCESS);
    pad = CRYPT_RSAES_PKCSV15;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(pad)), CRYPT_CMVP_ERR_PARAM_CHECK);
    pad = CRYPT_RSA_NO_PAD;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(pad)), CRYPT_CMVP_ERR_PARAM_CHECK);
    pad = CRYPT_RSAES_PKCSV15_TLS;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(pad)), CRYPT_CMVP_ERR_PARAM_CHECK);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);

    BSL_Param pssParam[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END};

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);

    BSL_Param oaep[3] = {{CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaep, 0), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_ECDH_SM2_TEST_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx1 = NULL;
    CRYPT_EAL_PkeyCtx *pkeyCtx2 = NULL;

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    pkeyCtx1 = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_ECDH, 0, HITLS_ISO_PROVIDER_ATTR);
    pkeyCtx2 = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_ECDH, 0, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(pkeyCtx1 != NULL && pkeyCtx2 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkeyCtx1, CRYPT_ECC_SM2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkeyCtx2, CRYPT_ECC_SM2), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkeyCtx1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkeyCtx2), CRYPT_SUCCESS);

    uint8_t sharedKey1[32] = {0};
    uint32_t sharedKeyLen1 = sizeof(sharedKey1);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(pkeyCtx1, pkeyCtx2, sharedKey1, &sharedKeyLen1), CRYPT_SUCCESS);
    ASSERT_EQ(sharedKeyLen1, 32);

    uint8_t sharedKey2[32] = {0};
    uint32_t sharedKeyLen2 = sizeof(sharedKey2);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(pkeyCtx2, pkeyCtx1, sharedKey2, &sharedKeyLen2), CRYPT_SUCCESS);
    ASSERT_EQ(sharedKeyLen2, 32);

    ASSERT_EQ(memcmp(sharedKey1, sharedKey2, sharedKeyLen1), 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx1);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx2);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/*
    Test event report log.
*/
/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_RUN_LOG_TEST_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_RegEventReport(ISO19790_RunLogCb);

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, BSL_CID_UNKNOWN, 0, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(pkeyCtx == NULL);
EXIT:
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_DH_CHECK_TEST_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;

    ASSERT_EQ(Iso19790_ProviderLoad(&ctx), CRYPT_SUCCESS);

    pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_DH, 0, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(pkeyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkeyCtx, CRYPT_DH_RFC7919_2048), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkeyCtx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pkeyCtx, pkeyCtx), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    Iso19790_ProviderUnload(&ctx);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_MD_USE_DEFAULT_LIBCTX_TEST_TC001(int algId)
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    (void)algId;
    SKIP_TEST();
#else
    int32_t ret = CRYPT_SUCCESS;
    CRYPT_EAL_MdCTX *mdCtx = NULL;
    uint8_t plaintext[128] = {0};
    uint32_t plaintextLen = sizeof(plaintext);
    uint8_t md[128] = {0};
    uint32_t mdLen = sizeof(md);
    int index = 0;
    BSL_Param param[7] = {{0}, {0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_CMVP_LOG_FUNC, BSL_PARAM_TYPE_FUNC_PTR, ISO19790_RunLogCb, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR, GetEntropy_Stub, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR, CleanEntropy_Stub, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR, GetNonce_Stub, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR, CleanNonce_Stub, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, NULL, 0);

    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(NULL, HITLS_ISO_PROVIDER_PATH), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_ProviderLoad(NULL, 0, HITLS_PROVIDER_LIB_NAME, param, NULL), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, HITLS_ISO_PROVIDER_ATTR, NULL, 0, NULL), CRYPT_SUCCESS);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(NULL, algId, HITLS_ISO_PROVIDER_ATTR);
    ASSERT_TRUE(mdCtx != NULL);
    ret = CRYPT_EAL_MdInit(mdCtx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_MdUpdate(mdCtx, plaintext, plaintextLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_MdFinal(mdCtx, md, &mdLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MdFreeCtx(mdCtx);
    CRYPT_EAL_RandDeinitEx(NULL);
    CRYPT_EAL_ProviderUnload(NULL, 0, HITLS_PROVIDER_LIB_NAME);
#endif
}
/* END_CASE */

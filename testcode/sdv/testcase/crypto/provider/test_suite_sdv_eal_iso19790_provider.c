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
#include "crypt_iso_19790.h"
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
#include <stdio.h>
#include <time.h>
#include <string.h>
/* END_HEADER */

#ifdef HITLS_CRYPTO_CMVP_ISO19790
#define ISO19790_LOG_FILE "iso19790_audit.log"

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

static const char *GetAlgoTypeStr(CRYPT_ALGO_TYPE type)
{
    switch (type) {
        case CRYPT_ALGO_CIPHER:
            return "CRYPT_ALGO_CIPHER";
        case CRYPT_ALGO_PKEY:
            return "CRYPT_ALGO_PKEY";
        case CRYPT_ALGO_MD:
            return "CRYPT_ALGO_MD";
        case CRYPT_ALGO_MAC:
            return "CRYPT_ALGO_MAC";
        case CRYPT_ALGO_KDF:
            return "CRYPT_ALGO_KDF";
        case CRYPT_ALGO_RAND:
            return "CRYPT_ALGO_RAND";
        default:
            return "UNKNOWN";
    }
}

static const char *GetEventStr(CRYPT_EVENT_TYPE oper)
{
    switch (oper) {
        case CRYPT_EVENT_ENC:          /**< Encryption. */
            return "CRYPT_EVENT_ENC";
        case CRYPT_EVENT_DEC:          /**< Decryption. */
            return "CRYPT_EVENT_DEC";
        case CRYPT_EVENT_GEN:          /**< Generate the key. */
            return "CRYPT_EVENT_GEN";
        case CRYPT_EVENT_SIGN:         /**< Signature. */
            return "CRYPT_EVENT_SIGN";
        case CRYPT_EVENT_VERIFY:       /**< Verify the signature. */
            return "CRYPT_EVENT_VERIFY";
        case CRYPT_EVENT_MD:           /**< Hash. */
            return "CRYPT_EVENT_MD";
        case CRYPT_EVENT_MAC:          /**< MAC. */
            return "CRYPT_EVENT_MAC";
        case CRYPT_EVENT_KDF:          /**< KDF. */
            return "CRYPT_EVENT_KDF";
        case CRYPT_EVENT_KEYAGGREMENT: /**< Key negotiation. */
            return "CRYPT_EVENT_KEYAGGREMENT";
        case CRYPT_EVENT_RANDGEN:      /**< Generating a random number. */
            return "CRYPT_EVENT_RANDGEN";
        case CRYPT_EVENT_ZERO:         /**< sensitive information to zero. */
            return "CRYPT_EVENT_ZERO";
        case CRYPT_EVENT_ERR:          /**< An error occurred. */
            return "CRYPT_EVENT_ERR";
        case CRYPT_EVENT_SETSSP:       /**< Adding and Modifying Password Data and SSP. */
            return "CRYPT_EVENT_SETSSP";
        case CRYPT_EVENT_GETSSP:       /**< Access password data and SSP. */
            return "CRYPT_EVENT_GETSSP";
        case CRYPT_EVENT_ENCAPS:       /**< Key encapsulation. */
            return "CRYPT_EVENT_ENCAPS";
        case CRYPT_EVENT_DECAPS:       /**< Key decapsulation. */
            return "CRYPT_EVENT_DECAPS";
        case CRYPT_EVENT_BLIND:        /**< Message blinding. */
            return "CRYPT_EVENT_BLIND";
        case CRYPT_EVENT_UNBLIND:      /**< Signature unblinding. */
            return "CRYPT_EVENT_UNBLIND";
        case CRYPT_EVENT_PARAM_CHECK:
            return "CRYPT_EVENT_PARAM_CHECK";
        case CRYPT_EVENT_PCT_TEST:
            return "CRYPT_EVENT_PCT_TEST";
        case CRYPT_EVENT_KAT_TEST:
            return "CRYPT_EVENT_KAT_TEST";
        case CRYPT_EVENT_ES_HEALTH_TEST:
            return "CRYPT_EVENT_ES_HEALTH_TEST";
        case CRYPT_EVENT_INTEGRITY_TEST:
            return "CRYPT_EVENT_INTEGRITY_TEST";
        default:
            return "UNKNOWN";
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
        fprintf(g_logFile, "[%s] [open hitls] [INFO] SSP already zeroisation - algorithm type: %s, id: %d\n", 
                timeStr, GetAlgoTypeStr(type), id);
        fflush(g_logFile);
    }

    /*
        ISO/IEC 19790:2012 AS06.26
        The following events of the cryptographic module should be recorded by the OS audit mechanism:
        ● Attempted to provide invalid input for the cryptographic officer function;
    */
    if (err != CRYPT_SUCCESS) {
        fprintf(g_logFile, "[%s] [open hitls] [ERR]  Occur error - algorithm type: %s, id: %d, operate: %s, errcode: 0x%x\n",
                timeStr, GetAlgoTypeStr(type), id, GetEventStr(oper), err);
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
    fprintf(g_logFile, "[%s] [open hitls] [INFO] Excute - algorithm type: %s, id: %d, operate: %s\n", 
            timeStr, GetAlgoTypeStr(type), id, GetEventStr(oper));
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

static void GetSeedPool(void **seedPool, void **es)
{
    CRYPT_EAL_Es *esTemp = NULL;
    CRYPT_EAL_SeedPoolCtx *poolTemp = NULL;
    int32_t ret = 0;
    esTemp = CRYPT_EAL_EsNew();
    ASSERT_TRUE(esTemp != NULL);

    ret = CRYPT_EAL_EsCtrl(esTemp, CRYPT_ENTROPY_SET_CF, "sha256_df", (uint32_t)strlen("sha256_df"));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_EsCtrl(esTemp, CRYPT_ENTROPY_REMOVE_NS, "timestamp", (uint32_t)strlen("timestamp"));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_EsCtrl(esTemp, CRYPT_ENTROPY_SET_LOG_CALLBACK, EntropyRunLogCb, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    bool healthTest = true;
    ret = CRYPT_EAL_EsCtrl(esTemp, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(healthTest));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t size = 4096;
    ret = CRYPT_EAL_EsCtrl(esTemp, CRYPT_ENTROPY_SET_POOL_SIZE, &size, sizeof(size));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_EsInit(esTemp);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    poolTemp = CRYPT_EAL_SeedPoolNew(true);
    ASSERT_TRUE(poolTemp != NULL);

    CRYPT_EAL_EsPara para = {
        false,
        8,
        esTemp,
        (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet,
    };

    ret = CRYPT_EAL_SeedPoolAddEs(poolTemp, &para);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    *seedPool = poolTemp;
    *es = esTemp;
    return;

EXIT:
    CRYPT_EAL_SeedPoolFree(poolTemp);
    CRYPT_EAL_EsFree(esTemp);
    return;
}

typedef struct {
    CRYPT_EAL_LibCtx *libCtx;
    CRYPT_EAL_Es *es;
    CRYPT_EAL_SeedPoolCtx *pool;
} Iso19790_ProviderLoadCtx;

static void Iso19790_ProviderLoad(Iso19790_ProviderLoadCtx *ctx)
{
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_Es *es = NULL;
    CRYPT_EAL_SeedPoolCtx *pool = NULL;
    
    libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, "../script/build"), CRYPT_SUCCESS);

    BSL_Param param[2] = {{0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_RUN_LOG_CB, BSL_PARAM_TYPE_FUNC_PTR, ISO19790_RunLogCb, 0);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, 0, "libopenhitls.so", param, NULL), CRYPT_SUCCESS);

    GetSeedPool((void **)&pool, (void **)&es);
    ASSERT_TRUE(pool != NULL && es != NULL);

    BSL_Param randParam[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&randParam[0], CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR, GetEntropy, 0);
    (void)BSL_PARAM_InitValue(&randParam[1], CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR, CleanEntropy, 0);
    (void)BSL_PARAM_InitValue(&randParam[2], CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR, GetNonce, 0);
    (void)BSL_PARAM_InitValue(&randParam[3], CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR, CleanNonce, 0);
    (void)BSL_PARAM_InitValue(&randParam[4], CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, pool, 0);

    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(libCtx, CRYPT_RAND_SHA256, "provider=iso19790_provider", NULL, 0, randParam), 0);

    ctx->libCtx = libCtx;
    ctx->es = es;
    ctx->pool = pool;
    return;

EXIT:
    CRYPT_EAL_LibCtxFree(libCtx);
    CRYPT_EAL_SeedPoolFree(pool);
    CRYPT_EAL_EsFree(es);
    return;
}

static void Iso19790_ProviderUnload(Iso19790_ProviderLoadCtx *ctx)
{
    CRYPT_EAL_RandDeinitEx(ctx->libCtx);
    CRYPT_EAL_LibCtxFree(ctx->libCtx);
    CRYPT_EAL_SeedPoolFree(ctx->pool);
    CRYPT_EAL_EsFree(ctx->es);
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
    
    Iso19790_ProviderLoad(&ctx);
    ASSERT_TRUE(ctx.libCtx != NULL && ctx.es != NULL && ctx.pool != NULL);

    keyCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_SM2, 0, "provider=iso19790_provider");
    ASSERT_TRUE(keyCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(keyCtx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(keyCtx, CRYPT_MD_SM3, testData, testDataLen, signature, &signatureLen), 0);
    ASSERT_TRUE(signatureLen > 0);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(keyCtx, CRYPT_MD_SM3, testData, testDataLen, signature, signatureLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(keyCtx);
    Iso19790_ProviderUnload(&ctx);
    return;
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

    Iso19790_ProviderLoad(&ctx);
    ASSERT_TRUE(ctx.libCtx != NULL && ctx.es != NULL && ctx.pool != NULL);

    pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_RSA, 0, "provider=iso19790_provider");
    ASSERT_TRUE(pkeyCtx != NULL);
    SetRsaPara(&para, e, 3, 2048);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkeyCtx, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, testData, testDataLen, signature, &signatureLen), 0);
    ASSERT_TRUE(signatureLen > 0);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkeyCtx, mdId, testData, testDataLen, signature, signatureLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    Iso19790_ProviderUnload(&ctx);
    return;
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
    CRYPT_EAL_RndCtx *randCtx = NULL;
    Iso19790_ProviderLoadCtx ctx = {0};
    Iso19790_ProviderLoad(&ctx);
    ASSERT_TRUE(ctx.libCtx != NULL && ctx.es != NULL && ctx.pool != NULL);

    es = CRYPT_EAL_EsNew();
    ASSERT_TRUE(es != NULL);

    int32_t ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, "sha256_df", (uint32_t)strlen("sha256_df"));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_REMOVE_NS, "timestamp", (uint32_t)strlen("timestamp"));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_LOG_CALLBACK, EntropyRunLogCb, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    bool healthTest = true;
    ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(healthTest));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t size = 4096;
    ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, &size, sizeof(size));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_EsInit(es);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    pool = CRYPT_EAL_SeedPoolNew(true);
    ASSERT_TRUE(pool != NULL);

    CRYPT_EAL_EsPara para = {
        false,
        8,
        es,
        (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet,
    };

    ret = CRYPT_EAL_SeedPoolAddEs(pool, &para);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_Param param[6] = {0};
    ASSERT_EQ(BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR, GetEntropy, 0), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR, CleanEntropy, 0), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR, GetNonce, 0), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[3], CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR, CleanNonce, 0), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[4], CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, pool, 0), CRYPT_SUCCESS);

    randCtx = CRYPT_EAL_ProviderDrbgNewCtx(ctx.libCtx, CRYPT_RAND_SHA256, NULL, param);
    ASSERT_TRUE(randCtx != NULL);

    ret = CRYPT_EAL_DrbgInstantiate(randCtx, NULL, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    unsigned char data[16] = {0};
    uint32_t dataLen = sizeof(data);

    ret = CRYPT_EAL_Drbgbytes(randCtx, data, dataLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_DrbgSeed(randCtx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_Drbgbytes(randCtx, data, dataLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_DrbgDeinit(randCtx);
    CRYPT_EAL_SeedPoolFree(pool);
    CRYPT_EAL_EsFree(es);
    Iso19790_ProviderUnload(&ctx);
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

    Iso19790_ProviderLoad(&ctx);
    ASSERT_TRUE(ctx.libCtx != NULL && ctx.es != NULL && ctx.pool != NULL);

    mdCtx = CRYPT_EAL_ProviderMdNewCtx(ctx.libCtx, algId, "provider=iso19790_provider");
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
    return;
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

    Iso19790_ProviderLoad(&ctx);
    ASSERT_TRUE(ctx.libCtx != NULL && ctx.es != NULL && ctx.pool != NULL);

    macCtx = CRYPT_EAL_ProviderMacNewCtx(ctx.libCtx, algId, "provider=iso19790_provider");
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

EXIT:
    CRYPT_EAL_MacFreeCtx(macCtx);
    Iso19790_ProviderUnload(&ctx);
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_KDF_TEST_TC001(int algId, int macId, int iter, int saltLen)
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    (void)algId;
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

    Iso19790_ProviderLoad(&ctx);
    ASSERT_TRUE(ctx.libCtx != NULL && ctx.es != NULL && ctx.pool != NULL);

    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(ctx.libCtx, algId, "provider=iso19790_provider");
    ASSERT_TRUE(kdfCtx != NULL);

    BSL_Param param[4] = {{0}, {0}, {0}, BSL_PARAM_END};

    (void)BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &macId, sizeof(macId));
    (void)BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, password, passwordLen);
    (void)BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen);
    (void)BSL_PARAM_InitValue(&param[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &iter, sizeof(iter));

    int32_t ret = CRYPT_EAL_KdfSetParam(kdfCtx, param);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_KdfDerive(kdfCtx, derivedKey, derivedKeyLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_KdfFreeCtx(kdfCtx);
    Iso19790_ProviderUnload(&ctx);
    return;
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
    Iso19790_ProviderLoad(&ctx);
    ASSERT_TRUE(ctx.libCtx != NULL && ctx.es != NULL && ctx.pool != NULL);

    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(ctx.libCtx, CRYPT_KDF_HKDF, "provider=iso19790_provider");
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
void SDV_ISO19790_PROVIDER_KDF_TEST_TC003(int algId, Hex *key, Hex *label, Hex *seed)
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    (void)algId;
    (void)key;
    (void)label;
    (void)seed;
    SKIP_TEST();
#else
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t outLen = 32;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_KdfCTX *kdfCtx = NULL;

    Iso19790_ProviderLoad(&ctx);
    ASSERT_TRUE(ctx.libCtx != NULL && ctx.es != NULL && ctx.pool != NULL);

    kdfCtx = CRYPT_EAL_ProviderKdfNewCtx(ctx.libCtx, CRYPT_KDF_KDFTLS12, "provider=iso19790_provider");
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
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, "../script/build"), CRYPT_SUCCESS);
    
    bool isLoaded = false;
    int32_t ret = CRYPT_EAL_ProviderIsLoad(libCtx, 0, "libopenhitls.so", &isLoaded);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(isLoaded == false);

    BSL_Param providerParam[2] = {{0}, BSL_PARAM_END};
    (void)BSL_PARAM_InitValue(&providerParam[0], CRYPT_PARAM_RUN_LOG_CB, BSL_PARAM_TYPE_FUNC_PTR, ISO19790_RunLogCb, 0);

    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, 0, "libopenhitls.so", providerParam, &providerMgr), CRYPT_SUCCESS);
    ASSERT_TRUE(providerMgr != NULL);


    ret = CRYPT_EAL_ProviderIsLoad(libCtx, 0, "libopenhitls.so", &isLoaded);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(isLoaded);

    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, 0, "libopenhitls.so", providerParam, &providerMgr), CRYPT_SUCCESS);
    ASSERT_TRUE(providerMgr != NULL);

    ret = CRYPT_EAL_ProviderUnload(libCtx, 0, "libopenhitls.so");
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_ProviderIsLoad(libCtx, 0, "libopenhitls.so", &isLoaded);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(isLoaded);

    ret = CRYPT_EAL_ProviderUnload(libCtx, 0, "libopenhitls.so");
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_ProviderIsLoad(libCtx, 0, "libopenhitls.so", &isLoaded);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(isLoaded == false);

EXIT:
    CRYPT_EAL_ProviderUnload(libCtx, 0, "libopenhitls.so");
    CRYPT_EAL_LibCtxFree(libCtx);
    return;
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

    Iso19790_ProviderLoad(&ctx);
    ASSERT_TRUE(ctx.libCtx != NULL && ctx.es != NULL && ctx.pool != NULL);

    selftestCtx = CRYPT_CMVP_SelftestNewCtx(ctx.libCtx, "provider=iso19790_provider");
    ASSERT_TRUE(selftestCtx != NULL);

    const char *version = CRYPT_CMVP_GetVersion(selftestCtx);
    ASSERT_TRUE(version != NULL);
    printf("Provider Version: %s\n", version);

    int32_t ret = CRYPT_CMVP_Selftest(selftestCtx, CRYPT_CMVP_KAT_TEST);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_CMVP_Selftest(selftestCtx, CRYPT_CMVP_INTEGRITY_TEST);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_CMVP_SelftestFreeCtx(selftestCtx);
    Iso19790_ProviderUnload(&ctx);
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_ML_DSA_TEST_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    // uint8_t e[] = {1, 0, 1};
    // CRYPT_EAL_PkeyPara para = {0};
    int32_t mdId = CRYPT_MD_SHAKE128;
    // int32_t pkcsv15 = mdId;
    uint8_t signature[4627] = {0}; // 4627
    uint32_t signatureLen = sizeof(signature);
    uint8_t testData[] = "Test data for signing and verification with ECDSA";
    uint32_t testDataLen = sizeof(testData) - 1;
    
    Iso19790_ProviderLoad(&ctx);
    ASSERT_TRUE(ctx.libCtx != NULL && ctx.es != NULL && ctx.pool != NULL);

    pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_ML_DSA, 0, "provider=iso19790_provider");
    ASSERT_TRUE(pkeyCtx != NULL);

    uint32_t val = CRYPT_MLDSA_TYPE_MLDSA_44;
    int32_t ret = CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkeyCtx), CRYPT_SUCCESS);
    // ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, testData, testDataLen, signature, &signatureLen), 0);
    ASSERT_TRUE(signatureLen > 0);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkeyCtx, mdId, testData, testDataLen, signature, signatureLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    Iso19790_ProviderUnload(&ctx);
    return;
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_ISO19790_PROVIDER_ML_KEM_TEST_TC001()
{
#ifndef HITLS_CRYPTO_CMVP_ISO19790
    SKIP_TEST();
#else
    Iso19790_ProviderLoadCtx ctx = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;

    uint32_t cipherLen = 0;
    uint8_t *ciphertext = NULL;
    uint32_t sharedLen = 32;
    uint8_t *sharedKey = NULL;

    Iso19790_ProviderLoad(&ctx);
    ASSERT_TRUE(ctx.libCtx != NULL && ctx.es != NULL && ctx.pool != NULL);

    pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_ML_KEM, 0, "provider=iso19790_provider");
    ASSERT_TRUE(pkeyCtx != NULL);

    uint32_t val = CRYPT_KEM_TYPE_MLKEM_512;
    int32_t ret = CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkeyCtx), CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ciphertext = BSL_SAL_Malloc(cipherLen);
    ASSERT_TRUE(ciphertext != NULL);

    sharedKey = BSL_SAL_Malloc(sharedLen);
    ASSERT_TRUE(sharedKey != NULL);

    ret = CRYPT_EAL_PkeyEncaps(pkeyCtx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKey);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    Iso19790_ProviderUnload(&ctx);
    return;
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
    
    Iso19790_ProviderLoad(&ctx);
    ASSERT_TRUE(ctx.libCtx != NULL && ctx.es != NULL && ctx.pool != NULL);

    cipherCtx = CRYPT_EAL_ProviderCipherNewCtx(ctx.libCtx, CRYPT_CIPHER_AES128_CBC, "provider=iso19790_provider");
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

EXIT:
    CRYPT_EAL_CipherFreeCtx(cipherCtx);
    Iso19790_ProviderUnload(&ctx);
    return;
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
    
    Iso19790_ProviderLoad(&ctx);
    ASSERT_TRUE(ctx.libCtx != NULL && ctx.es != NULL && ctx.pool != NULL);

    pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(ctx.libCtx, CRYPT_PKEY_DSA, 0, "provider=iso19790_provider");
    ASSERT_TRUE(pkeyCtx != NULL);
    SetDsaPara(&para, p->x, p->len, q->x, q->len, g->x, g->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkeyCtx, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, hashId, testData, testDataLen, signature, &signatureLen), 0);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkeyCtx, hashId, testData, testDataLen, signature, signatureLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    Iso19790_ProviderUnload(&ctx);
    return;
#endif
}
/* END_CASE */

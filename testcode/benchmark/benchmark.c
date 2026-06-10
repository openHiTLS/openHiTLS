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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_eal_rand.h"
#include "crypt_util_rand.h"
#include "benchmark.h"
#include "benchmark_registry.h"

enum {
    BENCHMARK_COUNT =
#define COUNT_BENCH(name) +1
        0 BENCHMARK_LIST(COUNT_BENCH)
#undef COUNT_BENCH
};

static const BenchCtx *g_benchs[BENCHMARK_COUNT];

static void InitBenchRegistry(void)
{
    static int inited = 0;
    size_t index = 0;

    if (inited != 0) {
        return;
    }

#define REGISTER_BENCH(name) g_benchs[index++] = BenchmarkGet##name();
    BENCHMARK_LIST(REGISTER_BENCH)
#undef REGISTER_BENCH

    inited = 1;
}

typedef struct {
    const char *s;
    int32_t id;
} StrIdMap;

static BenchSharedData g_benchSharedData = {
    .lens = {16, 64, 256, 1024, 8192, 16384},
    .key = {1},
};

BenchSharedData *BenchGetSharedData(void)
{
    return &g_benchSharedData;
}

#if defined(HITLS_CRYPTO_PROVIDER)
/*
 * Provider rand state lives on libctx->drbg. Some benchmarked algorithms still
 * obtain randomness through the legacy CRYPT_Rand bridge, so benchmark startup
 * installs a process-default callback that forwards to the global provider ctx.
 */
static int32_t BenchmarkProviderRand(uint8_t *rand, uint32_t randLen)
{
    return CRYPT_EAL_RandbytesEx(NULL, rand, randLen);
}

static int32_t BenchmarkProviderRandEx(void *libCtx, uint8_t *rand, uint32_t randLen)
{
    return CRYPT_EAL_RandbytesEx((CRYPT_EAL_LibCtx *)libCtx, rand, randLen);
}
#endif

static StrIdMap g_strIdMap[] = {
    {"md5", CRYPT_MD_MD5},
    {"sha1", CRYPT_MD_SHA1},
    {"sha224", CRYPT_MD_SHA224},
    {"sha256", CRYPT_MD_SHA256},
    {"sha384", CRYPT_MD_SHA384},
    {"sha512", CRYPT_MD_SHA512},
    {"sha3-224", CRYPT_MD_SHA3_224},
    {"sha3-256", CRYPT_MD_SHA3_256},
    {"sha3-384", CRYPT_MD_SHA3_384},
    {"sha3-512", CRYPT_MD_SHA3_512},
    {"shake128", CRYPT_MD_SHAKE128},
    {"shake256", CRYPT_MD_SHAKE256},
    {"sm3", CRYPT_MD_SM3},
    {"SLH-DSA-SHA2-128S", CRYPT_SLH_DSA_SHA2_128S},
    {"SLH-DSA-SHAKE-128S", CRYPT_SLH_DSA_SHAKE_128S},
    {"SLH-DSA-SHA2-128F", CRYPT_SLH_DSA_SHA2_128F},
    {"SLH-DSA-SHAKE-128F", CRYPT_SLH_DSA_SHAKE_128F},
    {"SLH-DSA-SHA2-192S", CRYPT_SLH_DSA_SHA2_192S},
    {"SLH-DSA-SHAKE-192S", CRYPT_SLH_DSA_SHAKE_192S},
    {"SLH-DSA-SHA2-192F", CRYPT_SLH_DSA_SHA2_192F},
    {"SLH-DSA-SHAKE-192F", CRYPT_SLH_DSA_SHAKE_192F},
    {"SLH-DSA-SHA2-256S", CRYPT_SLH_DSA_SHA2_256S},
    {"SLH-DSA-SHAKE-256S", CRYPT_SLH_DSA_SHAKE_256S},
    {"SLH-DSA-SHA2-256F", CRYPT_SLH_DSA_SHA2_256F},
    {"SLH-DSA-SHAKE-256F", CRYPT_SLH_DSA_SHAKE_256F},
    {"nistp192", CRYPT_ECC_NISTP192},
    {"nistp224", CRYPT_ECC_NISTP224},
    {"nistp256", CRYPT_ECC_NISTP256},
    {"nistp384", CRYPT_ECC_NISTP384},
    {"nistp521", CRYPT_ECC_NISTP521},
    {"brainpoolP256r1", CRYPT_ECC_BRAINPOOLP256R1},
    {"brainpoolP384r1", CRYPT_ECC_BRAINPOOLP384R1},
    {"brainpoolP512r1", CRYPT_ECC_BRAINPOOLP512R1},
    {"aes128-cbc", CRYPT_CIPHER_AES128_CBC},
    {"aes128-ctr", CRYPT_CIPHER_AES128_CTR},
    {"aes128-ecb", CRYPT_CIPHER_AES128_ECB},
    {"aes128-xts", CRYPT_CIPHER_AES128_XTS},
    {"aes128-ccm", CRYPT_CIPHER_AES128_CCM},
    {"aes128-gcm", CRYPT_CIPHER_AES128_GCM},
    {"aes128-cfb", CRYPT_CIPHER_AES128_CFB},
    {"aes128-ofb", CRYPT_CIPHER_AES128_OFB},
    {"aes192-cbc", CRYPT_CIPHER_AES192_CBC},
    {"aes192-ctr", CRYPT_CIPHER_AES192_CTR},
    {"aes192-ecb", CRYPT_CIPHER_AES192_ECB},
    {"aes192-ccm", CRYPT_CIPHER_AES192_CCM},
    {"aes192-gcm", CRYPT_CIPHER_AES192_GCM},
    {"aes192-cfb", CRYPT_CIPHER_AES192_CFB},
    {"aes192-ofb", CRYPT_CIPHER_AES192_OFB},
    {"aes256-cbc", CRYPT_CIPHER_AES256_CBC},
    {"aes256-ctr", CRYPT_CIPHER_AES256_CTR},
    {"aes256-ecb", CRYPT_CIPHER_AES256_ECB},
    {"aes256-xts", CRYPT_CIPHER_AES256_XTS},
    {"aes256-ccm", CRYPT_CIPHER_AES256_CCM},
    {"aes256-gcm", CRYPT_CIPHER_AES256_GCM},
    {"aes256-cfb", CRYPT_CIPHER_AES256_CFB},
    {"aes256-ofb", CRYPT_CIPHER_AES256_OFB},
    {"sm4-cbc", CRYPT_CIPHER_SM4_CBC},
    {"sm4-ecb", CRYPT_CIPHER_SM4_ECB},
    {"sm4-ctr", CRYPT_CIPHER_SM4_CTR},
    {"sm4-gcm", CRYPT_CIPHER_SM4_GCM},
    {"sm4-cfb", CRYPT_CIPHER_SM4_CFB},
    {"sm4-ofb", CRYPT_CIPHER_SM4_OFB},
    {"sm4-xts", CRYPT_CIPHER_SM4_XTS},
    {"chacha20-poly1305", CRYPT_CIPHER_CHACHA20_POLY1305},
    {"hmac-md5", CRYPT_MAC_HMAC_MD5},
    {"hmac-sha1", CRYPT_MAC_HMAC_SHA1},
    {"hmac-sha224", CRYPT_MAC_HMAC_SHA224},
    {"hmac-sha256", CRYPT_MAC_HMAC_SHA256},
    {"hmac-sha384", CRYPT_MAC_HMAC_SHA384},
    {"hmac-sha512", CRYPT_MAC_HMAC_SHA512},
    {"hmac-sha3-224", CRYPT_MAC_HMAC_SHA3_224},
    {"hmac-sha3-256", CRYPT_MAC_HMAC_SHA3_256},
    {"hmac-sha3-384", CRYPT_MAC_HMAC_SHA3_384},
    {"hmac-sha3-512", CRYPT_MAC_HMAC_SHA3_512},
    {"hmac-sha3-224", CRYPT_MAC_HMAC_SHA3_224},
    {"hmac-sha3-256", CRYPT_MAC_HMAC_SHA3_256},
    {"hmac-sm3", CRYPT_MAC_HMAC_SM3},
    {"cmac-aes128", CRYPT_MAC_CMAC_AES128},
    {"cmac-aes192", CRYPT_MAC_CMAC_AES192},
    {"cmac-aes256", CRYPT_MAC_CMAC_AES256},
    {"cmac-sm4", CRYPT_MAC_CMAC_SM4},
    {"cbc-mac-sm4", CRYPT_MAC_CBC_MAC_SM4},
    {"gmac-aes128", CRYPT_MAC_GMAC_AES128},
    {"gmac-aes192", CRYPT_MAC_GMAC_AES192},
    {"gmac-aes256", CRYPT_MAC_GMAC_AES256},
    {"siphash64", CRYPT_MAC_SIPHASH64},
    {"siphash128", CRYPT_MAC_SIPHASH128},
    {"dh-rfc2409-768", CRYPT_DH_RFC2409_768},
    {"dh-rfc2409-1024", CRYPT_DH_RFC2409_1024},
    {"dh-rfc3526-1536", CRYPT_DH_RFC3526_1536},
    {"dh-rfc3526-2048", CRYPT_DH_RFC3526_2048},
    {"dh-rfc3526-3072", CRYPT_DH_RFC3526_3072},
    {"dh-rfc3526-4096", CRYPT_DH_RFC3526_4096},
    {"dh-rfc3526-6144", CRYPT_DH_RFC3526_6144},
    {"dh-rfc3526-8192", CRYPT_DH_RFC3526_8192},
    {"dh-rfc7919-2048", CRYPT_DH_RFC7919_2048},
    {"dh-rfc7919-3072", CRYPT_DH_RFC7919_3072},
    {"dh-rfc7919-4096", CRYPT_DH_RFC7919_4096},
    {"dh-rfc7919-6144", CRYPT_DH_RFC7919_6144},
    {"dh-rfc7919-8192", CRYPT_DH_RFC7919_8192},
    {"rsa-2048", 2048},
    {"rsa-3072", 3072},
    {"rsa-4096", 4096},
    {"mlkem-512", CRYPT_KEM_TYPE_MLKEM_512},
    {"mlkem-768", CRYPT_KEM_TYPE_MLKEM_768},
    {"mlkem-1024", CRYPT_KEM_TYPE_MLKEM_1024},
    {"xmss-sha2-10-256", CRYPT_XMSS_SHA2_10_256},
    {"xmssmt-sha2-20/2-256", CRYPT_XMSSMT_SHA2_20_2_256},
    {"xmssmt-sha2-20/4-256", CRYPT_XMSSMT_SHA2_20_4_256},
};

static uint32_t g_benchFailureCount = 0;

static int32_t AlgStr2Id(const char *str)
{
    for (size_t i = 0; i < SIZEOF(g_strIdMap); i++) {
        if (strncasecmp(g_strIdMap[i].s, str, strlen(g_strIdMap[i].s)) == 0) {
            return g_strIdMap[i].id;
        }
    }
    return -1;
}

const char *GetAlgName(int32_t algId)
{
    for (size_t i = 0; i < SIZEOF(g_strIdMap); i++) {
        if (g_strIdMap[i].id == algId) {
            return g_strIdMap[i].s;
        }
    }
    return "";
}

static void PrintUsage(void)
{
    printf("Usage: openhitls_benchmark [options]\n");
    printf("Options:\n");
    printf("  -a <algorithm>      Specify algorithm to benchmark (e.g., sm2*, sm2-KeyGen, *KeyGen)\n");
    printf("  -t <times>          Number of times to run each benchmark\n");
    printf("  -s <seconds>        Number of seconds to run each benchmark\n");
    printf("  -l <len>            Length of the payload to benchmark\n");
    printf("  -d <digest id>      Digest algorithm id before sign\n");
    printf("  -p <para id>        Parameter id to benchmark\n");
    printf("  -h                  Show this help message\n");
}

static int32_t ParseNamedIdOrExit(const char *value, const char *optName)
{
    int32_t id = AlgStr2Id(value);
    if (id == -1) {
        printf("Unknown %s: %s\n", optName, value);
        exit(1);
    }
    return id;
}

static void ParseOptions(int argc, char **argv, BenchOptions *opts)
{
    int c;

    while ((c = getopt(argc, argv, "a:t:s:l:d:p:h")) != -1) {
        switch (c) {
            case 'a':
                opts->algorithm = optarg;
                break;
            case 't':
                opts->times = (uint32_t)atoi(optarg);
                break;
            case 's':
                opts->seconds = (uint32_t)atoi(optarg);
                break;
            case 'l':
                opts->len = (uint32_t)atoi(optarg);
                break;
            case 'd':
                opts->hashId = ParseNamedIdOrExit(optarg, "digest id");
                break;
            case 'p':
                opts->paraId = ParseNamedIdOrExit(optarg, "parameter id");
                break;
            case 'h':
                PrintUsage();
                exit(0);
            default:
                PrintUsage();
                exit(1);
        }
    }
}

bool MatchAlgorithm(const char *pattern, const char *name)
{
    if (pattern == NULL) {
        return true;
    }

    // it's operation benchmark
    if (strncmp(pattern, "*-", 2) == 0) {
        return true;
    }

    size_t patternLen = strlen(pattern);
    size_t nameLen = strlen(name);

    const char *asterisk = strchr(pattern, '*');
    if (asterisk != NULL) {
        // Process prefix wildcard "*XXX"
        if (pattern[0] == '*') {
            // Check if pattern is "*XXX"
            return (nameLen >= patternLen - 1) && (strcasecmp(name + nameLen - (patternLen - 1), pattern + 1) == 0);
        }

        // Process suffix wildcard "XXX*"
        if (pattern[patternLen - 1] == '*') {
            return strncasecmp(name, pattern, patternLen - 1) == 0;
        }
        return false;
    }

    return strncasecmp(pattern, name, strlen(name)) == 0;
}

static uint32_t MatchOperation(const char *pattern, const BenchCtx *bench)
{
    uint32_t re = 0;
    const CtxOps *ctxOps = bench->ctxOps;

    for (int32_t i = 0; i < ctxOps->opsNum; i++) {
        const Operation *op = &ctxOps->ops[i];
        const char *hyphen = strchr(pattern, '-');
        if (hyphen != NULL) {
            size_t algoLen = strlen(bench->name);
            const char *operation = hyphen + 1;

            // Match algorithm part before hyphen
            if (strncasecmp(operation, op->name + algoLen, strlen(operation)) == 0) {
                re |= op->id;
            }
        } else {
            // not match a operation, config default supported operation
            re |= op->id;
        }
    }

    return re;
}

static int32_t InstantOperation(const Operation *op, void *ctx, const BenchExecOptions *opts)
{
    return op->oper(ctx, opts);
}

static BenchExecOptions ResolveExecOptions(const CtxOps *ctxOps, const BenchOptions *reqOpts, int32_t paraId, int32_t len)
{
    BenchExecOptions execOpts = {
        .times = reqOpts->times,
        .seconds = reqOpts->seconds,
        .len = len,
        .paraId = paraId,
        .hashId = (reqOpts->hashId == -1) ? ctxOps->hashId : reqOpts->hashId,
    };
    return execOpts;
}

static bool IsFixedLenOperation(const Operation *op)
{
    return (op->id & (KEY_GEN_ID | KEY_DERIVE_ID)) != 0;
}

static bool IsRequestedLenMatch(const BenchOptions *reqOpts, int32_t len)
{
    return reqOpts->len == (uint32_t)-1 || reqOpts->len == (uint32_t)len;
}

static void RunBenchCase(const CtxOps *ctxOps, const Operation *op, const BenchExecOptions *execOpts)
{
    void *ctx = NULL;
    int32_t ret = ctxOps->setUp(&ctx, op, ctxOps->algId, execOpts->paraId);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to setup benchmark testcase: %08x\n", ret);
        g_benchFailureCount++;
        return;
    }
    ret = InstantOperation(op, ctx, execOpts);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to %s, ret = %08x\n", op->name, ret);
        g_benchFailureCount++;
    }
    ctxOps->tearDown(ctx);
}

static void ResetOptions(BenchOptions *opts, const BenchCtx *benchCtx)
{
    if (opts->seconds == 0) {
        opts->seconds = benchCtx->seconds;
    }
    if (opts->times == 0) {
        opts->times = benchCtx->times;
    }
}

static void DoBenchTest(const BenchCtx *benchs, const CtxOps *ctxOps, const Operation *op, BenchOptions *algOpts)
{
    const int32_t *lens = (benchs->lens != NULL) ? benchs->lens : BenchGetSharedData()->lens;
    if (IsFixedLenOperation(op)) {
        BenchExecOptions execOpts = ResolveExecOptions(ctxOps, algOpts, algOpts->paraId, -1);
        RunBenchCase(ctxOps, op, &execOpts);
        return;
    }

    bool isMatch = false;
    for (uint32_t i = 0; i < benchs->lensNum; i++) {
        if (!IsRequestedLenMatch(algOpts, lens[i])) {
            continue;
        }
        BenchExecOptions execOpts = ResolveExecOptions(ctxOps, algOpts, algOpts->paraId, lens[i]);
        RunBenchCase(ctxOps, op, &execOpts);
        isMatch = true;
    }

    if (algOpts->len != (uint32_t)-1 && !isMatch) {
        BenchExecOptions execOpts = ResolveExecOptions(ctxOps, algOpts, algOpts->paraId, (int32_t)algOpts->len);
        RunBenchCase(ctxOps, op, &execOpts);
    }
}

static int32_t BenchmarkRandInit(void)
{
#if defined(HITLS_CRYPTO_PROVIDER)
    int32_t ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SHA256, "provider=default", NULL, 0, NULL);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_RandRegist(BenchmarkProviderRand);
    CRYPT_RandRegistEx(BenchmarkProviderRandEx);
    return CRYPT_SUCCESS;
#else
    return CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
#endif
}

static void BenchmarkRandCleanup(void)
{
#if defined(HITLS_CRYPTO_PROVIDER)
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
#endif
    CRYPT_EAL_RandDeinitEx(NULL);
}

int main(int argc, char **argv)
{
    int32_t ret;
    bool hasMatch = false;
    BenchOptions opts = {0};

    // default options
    opts.algorithm = "*"; // all algorithms
    opts.filteredOps = 0x3F; // all operations
    opts.paraId = -1; // fake hash id
    opts.hashId = -1; // fake hash id
    opts.len = -1; // fake len
    ParseOptions(argc, argv, &opts);

    ret = BenchmarkRandInit();
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to initialize random number generator: %08x\n", ret);
        return -1;
    }

    InitBenchRegistry();
    printf("%-35s, %10s, %15s, %15s, %20s\n", "algorithm operation", "len", "run times", "time elapsed(ms)", "ops/s");

    for (size_t i = 0; i < SIZEOF(g_benchs); i++) {
        const CtxOps *ctxOps = g_benchs[i]->ctxOps;
        BenchOptions algOpts = opts;
        ResetOptions(&algOpts, g_benchs[i]);

        // filtering benchmark test
        if (!MatchAlgorithm(opts.algorithm, g_benchs[i]->name)) {
            continue;
        }
        hasMatch = true;
        opts.filteredOps = MatchOperation(opts.algorithm, g_benchs[i]);

        for (int32_t j = 0; j < ctxOps->opsNum; j++) {
            const Operation *op = &ctxOps->ops[j];
            if ((uint32_t)(op->id & opts.filteredOps) == 0U) {
                continue;
            }
            BenchOptions tmpOpts = algOpts;
            if (tmpOpts.paraId != -1 || g_benchs[i]->paraIdsNum == 0) {
                DoBenchTest(g_benchs[i], ctxOps, op, &tmpOpts);
            } else {
                for (uint32_t k = 0; k < g_benchs[i]->paraIdsNum; k++) {
                    tmpOpts.paraId = g_benchs[i]->paraIds[k];
                    DoBenchTest(g_benchs[i], ctxOps, op, &tmpOpts);
                }
            }
        }
    }

    BenchmarkRandCleanup();
    if (!hasMatch) {
        printf("No benchmark matched algorithm pattern: %s\n", opts.algorithm);
        return 1;
    }
    if (g_benchFailureCount != 0) {
        return 1;
    }
    return 0;
}

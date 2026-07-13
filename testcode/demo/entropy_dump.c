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

/*
 * Dump conditioned entropy-source or AES-256 CTR_DRBG output for external
 * assessment tools. Configured built-in sources run with startup health
 * testing enabled.
 *
 * Usage: entropy_dump <outfile> <mbytes> [cf] [conditioned|drbg]
 *   cf: pool conditioning function name (default sha3_256_df).
 */

#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bsl_sal.h"
#include "crypt_eal_entropy.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "hitls_build.h"

#define ES_POOL_SIZE 4096
#define OUTPUT_CHUNK_SIZE 4096
#define ES_INIT_ATTEMPTS 50
#define ES_FULL_ENTROPY_PER_BYTE 8

#if defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER) && defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP)
#define ES_SOURCE_NAMES "CPU-Jitter + Hash-Loop"
#elif defined(HITLS_CRYPTO_ENTROPY_NS_CPUJITTER)
#define ES_SOURCE_NAMES "CPU-Jitter"
#elif defined(HITLS_CRYPTO_ENTROPY_NS_HASHLOOP)
#define ES_SOURCE_NAMES "Hash-Loop"
#else
#define ES_SOURCE_NAMES "no built-in source"
#endif

static CRYPT_EAL_Es *EsInitOnce(const char *cf)
{
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    if (es == NULL) {
        return NULL;
    }

    int32_t ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, (void *)(intptr_t)cf, strlen(cf));
    if (ret == CRYPT_SUCCESS) {
        bool healthTest = true;
        ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(healthTest));
    }
    if (ret == CRYPT_SUCCESS) {
        uint32_t size = ES_POOL_SIZE;
        ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_POOL_SIZE, &size, sizeof(size));
    }
    if (ret == CRYPT_SUCCESS) {
        ret = CRYPT_EAL_EsInit(es);
    }
    if (ret == CRYPT_SUCCESS) {
        return es;
    }
    CRYPT_EAL_EsFree(es);
    return NULL;
}

static CRYPT_EAL_Es *EsInitWithRetry(const char *cf, uint32_t *attempts)
{
    CRYPT_EAL_Es *es = NULL;
    for (uint32_t attempt = 0; attempt < ES_INIT_ATTEMPTS && es == NULL; attempt++) {
        (*attempts)++;
        es = EsInitOnce(cf);
    }
    return es;
}

static int32_t SeedGetEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    return CRYPT_EAL_SeedPoolGetEntropy((CRYPT_EAL_SeedPoolCtx *)ctx, entropy, strength, lenRange);
}

static void SeedCleanEntropy(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    if (entropy == NULL) {
        return;
    }
    BSL_SAL_CleanseData(entropy->data, entropy->len);
    BSL_SAL_Free(entropy->data);
    entropy->data = NULL;
    entropy->len = 0;
}

static int32_t SeedGetNonce(void *ctx, CRYPT_Data *nonce, uint32_t strength, CRYPT_Range *lenRange)
{
    return SeedGetEntropy(ctx, nonce, strength, lenRange);
}

static void SeedCleanNonce(void *ctx, CRYPT_Data *nonce)
{
    SeedCleanEntropy(ctx, nonce);
}

static int WriteConditioned(FILE *fp, CRYPT_EAL_Es *es, uint64_t total, uint32_t initAttempts)
{
    uint64_t done = 0;
    uint8_t buf[OUTPUT_CHUNK_SIZE];
    while (done < total) {
        uint32_t want = (uint32_t)((total - done > sizeof(buf)) ? sizeof(buf) : (total - done));
        uint32_t got = CRYPT_EAL_EsEntropyGet(es, buf, want);
        if (got == 0) {
            fprintf(stderr, "entropy source read failed at %llu bytes\n", (unsigned long long)done);
            return 1;
        }
        if (fwrite(buf, 1, got, fp) != got) {
            perror("fwrite");
            return 1;
        }
        done += got;
        if ((done & ((1U << 20) - 1)) == 0) {
            fprintf(stderr, "\r%llu MiB", (unsigned long long)(done >> 20));
        }
    }
    fprintf(stderr, "\ndone: %llu bytes (init attempts %u)\n",
        (unsigned long long)done, initAttempts);
    return 0;
}

static int WriteDrbg(FILE *fp, CRYPT_EAL_Es *es, uint64_t total)
{
    int status = 1;
    CRYPT_EAL_SeedPoolCtx *pool = CRYPT_EAL_SeedPoolNew(true);
    CRYPT_EAL_RndCtx *drbg = NULL;
    if (pool == NULL) {
        fprintf(stderr, "CRYPT_EAL_SeedPoolNew failed\n");
        return 1;
    }

    CRYPT_EAL_EsPara para = {false, ES_FULL_ENTROPY_PER_BYTE, es,
        (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    int32_t ret = CRYPT_EAL_SeedPoolAddEs(pool, &para);
    if (ret != CRYPT_SUCCESS) {
        fprintf(stderr, "CRYPT_EAL_SeedPoolAddEs failed: 0x%x\n", (uint32_t)ret);
        goto EXIT;
    }

    CRYPT_RandSeedMethod seedMethod = {SeedGetEntropy, SeedCleanEntropy, SeedGetNonce, SeedCleanNonce};
    drbg = CRYPT_EAL_DrbgNew(CRYPT_RAND_AES256_CTR, &seedMethod, pool);
    if (drbg == NULL) {
        fprintf(stderr, "CRYPT_EAL_DrbgNew failed\n");
        goto EXIT;
    }
    ret = CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        fprintf(stderr, "CRYPT_EAL_DrbgInstantiate failed: 0x%x\n", (uint32_t)ret);
        goto EXIT;
    }

    uint64_t done = 0;
    uint8_t buf[OUTPUT_CHUNK_SIZE];
    while (done < total) {
        uint32_t want = (uint32_t)((total - done > sizeof(buf)) ? sizeof(buf) : (total - done));
        ret = CRYPT_EAL_Drbgbytes(drbg, buf, want);
        if (ret != CRYPT_SUCCESS) {
            fprintf(stderr, "CRYPT_EAL_Drbgbytes failed at %llu bytes: 0x%x\n",
                (unsigned long long)done, (uint32_t)ret);
            goto EXIT;
        }
        if (fwrite(buf, 1, want, fp) != want) {
            perror("fwrite");
            goto EXIT;
        }
        done += want;
        if ((done & ((1U << 20) - 1)) == 0) {
            fprintf(stderr, "\r%llu MiB", (unsigned long long)(done >> 20));
        }
    }
    fprintf(stderr, "\ndone: %llu bytes\n", (unsigned long long)done);
    status = 0;

EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    CRYPT_EAL_SeedPoolFree(pool);
    return status;
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "usage: %s <outfile> <mbytes> [cf] [conditioned|drbg]\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    char *end = NULL;
    errno = 0;
    unsigned long long mb = strtoull(argv[2], &end, 10);
    /* strtoull wraps a leading minus into the unsigned range; reject it and any
       non-numeric, overflowing, zero or oversized size so the tool never emits a
       silent empty evidence file. */
    if (argv[2][0] == '-' || errno != 0 || end == argv[2] || *end != '\0' || mb == 0 || mb > UINT32_MAX) {
        fprintf(stderr, "invalid mbytes: %s\n", argv[2]);
        return 1;
    }
    uint32_t mbytes = (uint32_t)mb;
    const char *cf = (argc > 3) ? argv[3] : "sha3_256_df";
    const char *output = (argc > 4) ? argv[4] : "conditioned";
    bool drbgOutput = strcmp(output, "drbg") == 0;
    if (!drbgOutput && strcmp(output, "conditioned") != 0) {
        fprintf(stderr, "unknown output: %s\n", output);
        return 1;
    }

    fprintf(stderr, "sources: %s; cf: %s\n", ES_SOURCE_NAMES, cf);
    fprintf(stderr, "output: %s\n", drbgOutput ? "CTR_DRBG(AES-256) without DF" : "conditioned entropy");

    uint32_t initAttempts = 0;
    CRYPT_EAL_Es *es = EsInitWithRetry(cf, &initAttempts);
    if (es == NULL) {
        fprintf(stderr, "EsInit never succeeded (%u attempts)\n", initAttempts);
        return 1;
    }

    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        perror("fopen");
        CRYPT_EAL_EsFree(es);
        return 1;
    }

    uint64_t total = (uint64_t)mbytes * 1024 * 1024;
    int status = drbgOutput ? WriteDrbg(fp, es, total)
                            : WriteConditioned(fp, es, total, initAttempts);
    if (fclose(fp) != 0) {
        perror("fclose");
        status = 1;
    }
    CRYPT_EAL_EsFree(es);
    return status;
}

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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "hitls_config.h"
#include "hitls_error.h"
#include "app_opt.h"
#include "app_print.h"
#include "app_errno.h"
#include "bsl_errno.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "app_list.h"
#include "bsl_sal.h"
#include "stub_utils.h"
#include "cipher_suite.h"

#define LIST_OUTPUT_BUFFER_SIZE 32768

STUB_DEFINE_RET4(int32_t, HITLS_CFG_GetCipherSuites, HITLS_Config *, uint16_t *, uint32_t, uint32_t *);
STUB_DEFINE_RET1(const HITLS_Cipher *, HITLS_CFG_GetCipherByID, uint16_t);
STUB_DEFINE_RET4(int32_t, BSL_UIO_Write, BSL_UIO *, const void *, uint32_t, uint32_t *);
STUB_DEFINE_RET1(int32_t, CRYPT_EAL_Init, uint64_t);

/* END_HEADER */

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_list.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c */

static int32_t CaptureList(int argc, char **argv, char *output, size_t size)
{
    FILE *capture = tmpfile();
    int saved = dup(STDOUT_FILENO);
    int32_t ret = -1;
    if (capture == NULL || saved < 0) {
        goto EXIT;
    }
    fflush(stdout);
    if (dup2(fileno(capture), STDOUT_FILENO) < 0) {
        goto EXIT;
    }
    ret = HITLS_ListMain(argc, argv);
    fflush(stdout);
    if (dup2(saved, STDOUT_FILENO) < 0) {
        ret = -1;
        goto EXIT;
    }
    clearerr(stdout);
    rewind(capture);
    size_t len = fread(output, 1, size - 1, capture);
    output[len] = '\0';
    if (ferror(capture) || fgetc(capture) != EOF) {
        ret = -1;
    }
EXIT:
    if (saved >= 0) {
        close(saved);
    }
    if (capture != NULL) {
        fclose(capture);
    }
    return ret;
}

static const HITLS_Cipher *g_selectedCipher;

static const HITLS_Cipher *StubSelectedCipher(uint16_t id)
{
    (void)id;
    return g_selectedCipher;
}

static int32_t StubSingleCipherSuite(HITLS_Config *config, uint16_t *ids, uint32_t capacity, uint32_t *count)
{
    (void)config;
    if (capacity == 0) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }
    ids[0] = HITLS_RSA_WITH_AES_128_CBC_SHA;
    *count = 1;
    return HITLS_SUCCESS;
}

static int32_t StubCipherSuitesWithUnknown(HITLS_Config *config, uint16_t *ids, uint32_t capacity, uint32_t *count)
{
    (void)config;
    if (capacity < 2) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }
    ids[0] = UINT16_MAX;
    ids[1] = HITLS_RSA_WITH_AES_128_CBC_SHA;
    *count = 2;
    return HITLS_SUCCESS;
}

static const HITLS_Cipher *StubCipherWithUnknown(uint16_t id)
{
    return id == UINT16_MAX ? NULL : g_selectedCipher;
}

static int32_t StubCipherSuiteFailure(HITLS_Config *config, uint16_t *ids, uint32_t capacity, uint32_t *count)
{
    (void)config;
    (void)ids;
    (void)capacity;
    (void)count;
    return HITLS_CONFIG_INVALID_LENGTH;
}

static int32_t StubEalInitFailure(uint64_t opts)
{
    (void)opts;
    return CRYPT_EAL_ERR_ALGID;
}

static uint32_t g_writeCallCount = 0;

static int32_t StubWriteFailure(BSL_UIO *uio, const void *data, uint32_t len, uint32_t *writeLen)
{
    (void)uio;
    (void)data;
    (void)len;
    (void)writeLen;
    g_writeCallCount++;
    return BSL_UIO_FAIL;
}

static int32_t CaptureCipherDetails(const HITLS_Cipher *cipher, char *output, size_t size)
{
    char *argv[] = {"list", "-ciphersuites"};
    g_selectedCipher = cipher;
    STUB_REPLACE(HITLS_CFG_GetCipherSuites, StubSingleCipherSuite);
    STUB_REPLACE(HITLS_CFG_GetCipherByID, StubSelectedCipher);
    int32_t ret = CaptureList(2, argv, output, size);
    STUB_RESTORE(HITLS_CFG_GetCipherSuites);
    STUB_RESTORE(HITLS_CFG_GetCipherByID);
    g_selectedCipher = NULL;
    return ret;
}

/* Valid list inputs. */
/* BEGIN_CASE */
void UT_HITLS_APP_LIST_TC001(void)
{
    char *argv[][20] = {
        {"list", "-all-algorithms"},
        {"list", "-digest-algorithms"},
        {"list", "-cipher-algorithms"},
        {"list", "-asym-algorithms"},
        {"list", "-mac-algorithms"},
        {"list", "-rand-algorithms"},
        {"list", "-kdf-algorithms"},
        {"list", "-all-curves"},
        {"list", "-ciphersuites"},
        {"list", "-ciphersuites", "-names-only"},
        {"list", "-help"},
    };

    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_SUCCESS},
        {2, argv[1], HITLS_APP_SUCCESS},
        {2, argv[2], HITLS_APP_SUCCESS},
        {2, argv[3], HITLS_APP_SUCCESS},
        {2, argv[4], HITLS_APP_SUCCESS},
        {2, argv[5], HITLS_APP_SUCCESS},
        {2, argv[6], HITLS_APP_SUCCESS},
        {2, argv[7], HITLS_APP_SUCCESS},
        {2, argv[8], HITLS_APP_SUCCESS},
        {3, argv[9], HITLS_APP_SUCCESS},
        {2, argv[10], HITLS_APP_HELP},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_ListMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/* Invalid list inputs. */
/* BEGIN_CASE */
void UT_HITLS_APP_LIST_TC002(void)
{
    char *argv[][20] = {
        {"list"},
        {"list", "-ttt"},
        {"list", "-ciphersuites", "unexpected"},
        {"list", "-names-only"},
    };

    OptTestData testData[] = {
        {1, argv[0], HITLS_APP_OPT_UNKOWN},
        {2, argv[1], HITLS_APP_OPT_UNKOWN},
        {3, argv[2], HITLS_APP_OPT_UNKOWN},
        {2, argv[3], HITLS_APP_OPT_UNKOWN},
    };

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_ListMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/* List failures return application errors and stop later queries. */
/* BEGIN_CASE */
void UT_HITLS_APP_LIST_PRINT_FAILURE(void)
{
    char *output = BSL_SAL_Malloc(LIST_OUTPUT_BUFFER_SIZE);
    char *suiteArgv[] = {"list", "-ciphersuites", "-digest-algorithms"};
    char *digestArgv[] = {"list", "-digest-algorithms", "-cipher-algorithms"};
    ASSERT_TRUE(output != NULL);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    STUB_REPLACE(HITLS_CFG_GetCipherSuites, StubCipherSuiteFailure);
    ASSERT_EQ(CaptureList(3, suiteArgv, output, LIST_OUTPUT_BUFFER_SIZE), HITLS_APP_INTERNAL_EXCEPTION);
    ASSERT_TRUE(strstr(output, "List Digest Algorithms:\n") == NULL);
    STUB_RESTORE(HITLS_CFG_GetCipherSuites);

    STUB_REPLACE(CRYPT_EAL_Init, StubEalInitFailure);
    ASSERT_EQ(CaptureList(3, suiteArgv, output, LIST_OUTPUT_BUFFER_SIZE), HITLS_APP_CRYPTO_FAIL);
    STUB_RESTORE(CRYPT_EAL_Init);

    g_writeCallCount = 0;
    STUB_REPLACE(BSL_UIO_Write, StubWriteFailure);
    ASSERT_EQ(CaptureList(3, digestArgv, output, LIST_OUTPUT_BUFFER_SIZE), HITLS_APP_UIO_FAIL);
    ASSERT_EQ(g_writeCallCount, 2);
EXIT:
    STUB_RESTORE(HITLS_CFG_GetCipherSuites);
    STUB_RESTORE(CRYPT_EAL_Init);
    STUB_RESTORE(BSL_UIO_Write);
    BSL_SAL_FREE(output);
    AppPrintErrorUioUnInit();
}
/* END_CASE */

/* KDF name-to-CID mapping. */
/* BEGIN_CASE */
void UT_HITLS_APP_LIST_TC003(void)
{
    ASSERT_EQ(HITLS_APP_GetCidByName("hkdf", HITLS_APP_LIST_OPT_KDF_ALG), CRYPT_KDF_HKDF);
    ASSERT_EQ(HITLS_APP_GetCidByName("pbkdf2", HITLS_APP_LIST_OPT_KDF_ALG), CRYPT_KDF_PBKDF2);
    ASSERT_EQ(HITLS_APP_GetCidByName("kdftls12", HITLS_APP_LIST_OPT_KDF_ALG), CRYPT_KDF_KDFTLS12);
    ASSERT_EQ(HITLS_APP_GetCidByName("scrypt", HITLS_APP_LIST_OPT_KDF_ALG), CRYPT_KDF_SCRYPT);
    ASSERT_EQ(HITLS_APP_GetCidByName("hmac_sha256", HITLS_APP_LIST_OPT_KDF_ALG), BSL_CID_UNKNOWN);

EXIT:
    return;
}
/* END_CASE */

/* Default names match the library list in order. */
/* BEGIN_CASE */
void UT_HITLS_APP_LIST_CIPHERSUITES_TC001(void)
{
    char *names = BSL_SAL_Malloc(LIST_OUTPUT_BUFFER_SIZE);
    HITLS_Config *config = NULL;
    char *argv[] = {"list", "-ciphersuites", "-names-only"};
    ASSERT_TRUE(names != NULL);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(CaptureList(3, argv, names, LIST_OUTPUT_BUFFER_SIZE), HITLS_APP_SUCCESS);

    config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(config != NULL);
    uint16_t ids[HITLS_CFG_MAX_SIZE];
    uint32_t count = 0;
    ASSERT_EQ(HITLS_CFG_GetCipherSuites(config, ids, sizeof(ids) / sizeof(ids[0]), &count), HITLS_SUCCESS);

    char *next = NULL;
    char *name = strtok_r(names, ":\n", &next);
    for (uint32_t i = 0; i < count; i++) {
        const char *expected = (const char *)HITLS_CFG_GetCipherSuiteStdName(HITLS_CFG_GetCipherByID(ids[i]));
        ASSERT_TRUE(name != NULL);
        ASSERT_TRUE(strcmp(name, expected) == 0);
        name = strtok_r(NULL, ":\n", &next);
    }
    ASSERT_TRUE(name == NULL);
EXIT:
    BSL_SAL_FREE(names);
    HITLS_CFG_FreeConfig(config);
    AppPrintErrorUioUnInit();
}
/* END_CASE */

/* Suite fields, including non-default suites. */
/* BEGIN_CASE */
void UT_HITLS_APP_LIST_CIPHERSUITES_TC002(char *name, char *version, char *kx, char *auth,
    char *enc, char *hash, char *mac)
{
    const HITLS_Cipher *cipher = HITLS_CFG_GetCipherSuiteByStdName((const uint8_t *)name);
    if (cipher == NULL) {
        SKIP_TEST();
    }
    char *output = BSL_SAL_Malloc(1024);
    const char *expected[] = {name, version, kx, auth, enc, hash, mac};
    const char *prefixes[] = {"", "", "Kx=", "Au=", "Enc=", "Hash=", "Mac="};
    ASSERT_TRUE(output != NULL);
    ASSERT_EQ(CaptureCipherDetails(cipher, output, 1024), HITLS_APP_SUCCESS);
    char *line = strchr(output, '\n');
    ASSERT_TRUE(line != NULL);
    char *next = NULL;
    char *token = strtok_r(line + 1, " \n", &next);
    for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        ASSERT_TRUE(token != NULL);
        ASSERT_TRUE(strncmp(token, prefixes[i], strlen(prefixes[i])) == 0);
        ASSERT_TRUE(strcmp(token + strlen(prefixes[i]), expected[i]) == 0);
        token = strtok_r(NULL, " \n", &next);
    }
    ASSERT_TRUE(token == NULL);
EXIT:
    BSL_SAL_FREE(output);
}
/* END_CASE */

/* Colon-separated standard names and repeated options. */
/* BEGIN_CASE */
void UT_HITLS_APP_LIST_CIPHERSUITES_TC004(void)
{
    char *output = BSL_SAL_Calloc(1, LIST_OUTPUT_BUFFER_SIZE);
    char *repeated = BSL_SAL_Calloc(1, LIST_OUTPUT_BUFFER_SIZE);
    char *argv[] = {"list", "-ciphersuites", "-names-only"};
    char *reverse[] = {"list", "-names-only", "-ciphersuites", "-ciphersuites", "-names-only"};
    ASSERT_TRUE(output != NULL && repeated != NULL);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(CaptureList(3, argv, output, LIST_OUTPUT_BUFFER_SIZE), HITLS_APP_SUCCESS);
    ASSERT_EQ(CaptureList(5, reverse, repeated, LIST_OUTPUT_BUFFER_SIZE), HITLS_APP_SUCCESS);
    ASSERT_TRUE(strcmp(output, repeated) == 0);
    size_t len = strlen(output);
    ASSERT_TRUE(len > 1 && output[len - 1] == '\n' && output[len - 2] != ':');
    ASSERT_TRUE(strstr(output, "List Cipher Suites:\n") == NULL);
    ASSERT_TRUE(strchr(output, ' ') == NULL && strchr(output, '=') == NULL);
    ASSERT_TRUE(strstr(output, "::") == NULL && output[0] != ':');
EXIT:
    BSL_SAL_FREE(output);
    BSL_SAL_FREE(repeated);
    AppPrintErrorUioUnInit();
}
/* END_CASE */

/* Unknown algorithm identifiers display unknown. */
/* BEGIN_CASE */
void UT_HITLS_APP_LIST_CIPHERSUITES_TC009(void)
{
    const HITLS_Cipher *cipher = HITLS_CFG_GetCipherByID(HITLS_RSA_WITH_AES_128_CBC_SHA);
    if (cipher == NULL) {
        SKIP_TEST();
    }
    char *captured = BSL_SAL_Malloc(1024);
    ASSERT_TRUE(captured != NULL);
    CipherSuiteInfo invalid = *(const CipherSuiteInfo *)cipher;
    invalid.cipherAlg = (HITLS_CipherAlgo)BSL_CID_UNKNOWN;
    invalid.hashAlg = (HITLS_HashAlgo)BSL_CID_UNKNOWN;
    invalid.macAlg = (HITLS_MacAlgo)BSL_CID_UNKNOWN;
    ASSERT_EQ(CaptureCipherDetails((const HITLS_Cipher *)&invalid, captured, 1024), HITLS_APP_SUCCESS);
    ASSERT_TRUE(strstr(captured, "Enc=unknown ") != NULL);
    ASSERT_TRUE(strstr(captured, "Hash=unknown ") != NULL);
    ASSERT_TRUE(strstr(captured, "Mac=unknown ") != NULL || strstr(captured, "Mac=unknown\n") != NULL);
EXIT:
    BSL_SAL_FREE(captured);
}
/* END_CASE */

/* Unknown suite identifiers are omitted from both output modes. */
/* BEGIN_CASE */
void UT_HITLS_APP_LIST_CIPHERSUITES_UNKNOWN_ID(void)
{
    g_selectedCipher = HITLS_CFG_GetCipherByID(HITLS_RSA_WITH_AES_128_CBC_SHA);
    if (g_selectedCipher == NULL) {
        SKIP_TEST();
    }
    char *names = BSL_SAL_Calloc(1, LIST_OUTPUT_BUFFER_SIZE);
    char *details = BSL_SAL_Calloc(1, LIST_OUTPUT_BUFFER_SIZE);
    char *namesArgv[] = {"list", "-ciphersuites", "-names-only"};
    char *detailsArgv[] = {"list", "-ciphersuites"};
    const char *expected = (const char *)HITLS_CFG_GetCipherSuiteStdName(g_selectedCipher);
    ASSERT_TRUE(names != NULL && details != NULL && expected != NULL);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    STUB_REPLACE(HITLS_CFG_GetCipherSuites, StubCipherSuitesWithUnknown);
    STUB_REPLACE(HITLS_CFG_GetCipherByID, StubCipherWithUnknown);

    ASSERT_EQ(CaptureList(3, namesArgv, names, LIST_OUTPUT_BUFFER_SIZE), HITLS_APP_SUCCESS);
    ASSERT_TRUE(strncmp(names, expected, strlen(expected)) == 0);
    ASSERT_TRUE(names[strlen(expected)] == '\n');
    ASSERT_TRUE(strstr(names, "(NONE)") == NULL && names[0] != ':');

    ASSERT_EQ(CaptureList(2, detailsArgv, details, LIST_OUTPUT_BUFFER_SIZE), HITLS_APP_SUCCESS);
    ASSERT_TRUE(strstr(details, expected) != NULL);
    ASSERT_TRUE(strstr(details, "(NONE)") == NULL);
EXIT:
    STUB_RESTORE(HITLS_CFG_GetCipherSuites);
    STUB_RESTORE(HITLS_CFG_GetCipherByID);
    g_selectedCipher = NULL;
    BSL_SAL_FREE(names);
    BSL_SAL_FREE(details);
    AppPrintErrorUioUnInit();
}
/* END_CASE */

/* Single-list names match the NAME column, separated by colons. */
/* BEGIN_CASE */
void UT_HITLS_APP_LIST_NAMES_ONLY(char *query)
{
    char *details = BSL_SAL_Malloc(LIST_OUTPUT_BUFFER_SIZE);
    char *output = BSL_SAL_Malloc(LIST_OUTPUT_BUFFER_SIZE);
    char *plain[] = {"list", query};
    char *compact[] = {"list", query, "-names-only"};
    ASSERT_TRUE(details != NULL && output != NULL);
    ASSERT_EQ(CaptureList(2, plain, details, LIST_OUTPUT_BUFFER_SIZE), HITLS_APP_SUCCESS);
    ASSERT_EQ(CaptureList(3, compact, output, LIST_OUTPUT_BUFFER_SIZE), HITLS_APP_SUCCESS);
    char *next = NULL;
    (void)strtok_r(details, "\n", &next); /* Skip title. */
    (void)strtok_r(NULL, "\n", &next); /* Skip NAME/CID header. */
    char *name = output;
    for (char *line = strtok_r(NULL, "\n", &next); line != NULL; line = strtok_r(NULL, "\n", &next)) {
        if (name != output) {
            ASSERT_EQ(*name, ':');
            name++;
        }
        size_t len = strcspn(line, " \t");
        ASSERT_TRUE(strncmp(name, line, len) == 0);
        name += len;
    }
    ASSERT_TRUE(strcmp(name, "\n") == 0);
EXIT:
    BSL_SAL_FREE(details);
    BSL_SAL_FREE(output);
}
/* END_CASE */

/* Combined name lists retain titles and follow query order. */
/* BEGIN_CASE */
void UT_HITLS_APP_LIST_NAMES_ONLY_COMBINED(void)
{
    char *output = BSL_SAL_Malloc(LIST_OUTPUT_BUFFER_SIZE);
    char *argv[] = {"list", "-ciphersuites", "-digest-algorithms", "-names-only"};
    ASSERT_TRUE(output != NULL);
    ASSERT_EQ(CaptureList(4, argv, output, LIST_OUTPUT_BUFFER_SIZE), HITLS_APP_SUCCESS);
    ASSERT_TRUE(strstr(output, "List Cipher Suites:\n") == output);
    char *digest = strstr(output, "List Digest Algorithms:\n");
    ASSERT_TRUE(digest != NULL);
EXIT:
    BSL_SAL_FREE(output);
}
/* END_CASE */

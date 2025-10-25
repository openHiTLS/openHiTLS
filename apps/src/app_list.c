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
#include <string.h>
#include <stddef.h>
#include <securec.h>
#include "hitls_error.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_opt.h"
#include "crypt_algid.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_md.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_kdf.h"
#include "app_list.h"

const HITLS_CmdOption g_listOpts[] = {
    {"help", HITLS_APP_OPT_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"all-algorithms", HITLS_APP_LIST_OPT_ALL_ALG, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "List supported all algorthms"},
    {"digest-algorithms", HITLS_APP_LIST_OPT_DGST_ALG, HITLS_APP_OPT_VALUETYPE_NO_VALUE,
     "List supported digest algorthms"},
    {"cipher-algorithms", HITLS_APP_LIST_OPT_CIPHER_ALG, HITLS_APP_OPT_VALUETYPE_NO_VALUE,
     "List supported cipher algorthms"},
    {"asym-algorithms", HITLS_APP_LIST_OPT_ASYM_ALG, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "List supported asym algorthms"},
    {"mac-algorithms", HITLS_APP_LIST_OPT_MAC_ALG, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "List supported mac algorthms"},
    {"rand-algorithms", HITLS_APP_LIST_OPT_RAND_ALG, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "List supported rand algorthms"},
    {"kdf-algorithms", HITLS_APP_LIST_OPT_KDF_ALG, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "List supported kdf algorthms"},
    {"all-curves", HITLS_APP_LIST_OPT_CURVES, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "List supported curves"},
    {NULL, 0, 0, NULL}};

typedef struct {
    int32_t cid;
    const char *name;
} CidInfo;

static const CidInfo g_allCipherAlgInfo [] = {
    {CRYPT_CIPHER_AES128_CBC, "aes128-cbc"},
    {CRYPT_CIPHER_AES128_CCM, "aes128-ccm"},
    {CRYPT_CIPHER_AES128_CFB, "aes128-cfb"},
    {CRYPT_CIPHER_AES128_CTR, "aes128-ctr"},
    {CRYPT_CIPHER_AES128_ECB, "aes128-ecb"},
    {CRYPT_CIPHER_AES128_GCM, "aes128-gcm"},
    {CRYPT_CIPHER_AES128_OFB, "aes128-ofb"},
    {CRYPT_CIPHER_AES128_XTS, "aes128-xts"},
    {CRYPT_CIPHER_AES192_CBC, "aes192-cbc"},
    {CRYPT_CIPHER_AES192_CCM, "aes192-ccm"},
    {CRYPT_CIPHER_AES192_CFB, "aes192-cfb"},
    {CRYPT_CIPHER_AES192_CTR, "aes192-ctr"},
    {CRYPT_CIPHER_AES192_ECB, "aes192-ecb"},
    {CRYPT_CIPHER_AES192_GCM, "aes192-gcm"},
    {CRYPT_CIPHER_AES192_OFB, "aes192-ofb"},
    {CRYPT_CIPHER_AES256_CBC, "aes256-cbc"},
    {CRYPT_CIPHER_AES256_CCM, "aes256-ccm"},
    {CRYPT_CIPHER_AES256_CFB, "aes256-cfb"},
    {CRYPT_CIPHER_AES256_CTR, "aes256-ctr"},
    {CRYPT_CIPHER_AES256_ECB, "aes256-ecb"},
    {CRYPT_CIPHER_AES256_GCM, "aes256-gcm"},
    {CRYPT_CIPHER_AES256_OFB, "aes256-ofb"},
    {CRYPT_CIPHER_AES256_XTS, "aes256-xts"},
    {CRYPT_CIPHER_CHACHA20_POLY1305, "chacha20-poly1305"},
    {CRYPT_CIPHER_SM4_CBC, "sm4-cbc"},
    {CRYPT_CIPHER_SM4_CFB, "sm4-cfb"},
    {CRYPT_CIPHER_SM4_CTR, "sm4-ctr"},
    {CRYPT_CIPHER_SM4_ECB, "sm4-ecb"},
    {CRYPT_CIPHER_SM4_GCM, "sm4-gcm"},
    {CRYPT_CIPHER_SM4_OFB, "sm4-ofb"},
    {CRYPT_CIPHER_SM4_XTS, "sm4-xts"},
};

#define CIPHER_ALG_CNT (sizeof(g_allCipherAlgInfo) / sizeof(CidInfo))

static const CidInfo g_allMdAlgInfo[] = {
    {CRYPT_MD_MD5, "md5"},
    {CRYPT_MD_SHA1, "sha1"},
    {CRYPT_MD_SHA224, "sha224"},
    {CRYPT_MD_SHA256, "sha256"},
    {CRYPT_MD_SHA384, "sha384"},
    {CRYPT_MD_SHA512, "sha512"},
    {CRYPT_MD_SHA3_224, "sha3-224"},
    {CRYPT_MD_SHA3_256, "sha3-256"},
    {CRYPT_MD_SHA3_384, "sha3-384"},
    {CRYPT_MD_SHA3_512, "sha3-512"},
    {CRYPT_MD_SHAKE128, "shake128"},
    {CRYPT_MD_SHAKE256, "shake256"},
    {CRYPT_MD_SM3, "sm3"},
};

#define MD_ALG_CNT (sizeof(g_allMdAlgInfo) / sizeof(CidInfo))

static const CidInfo g_allPkeyAlgInfo[] = {
    {CRYPT_PKEY_ECDH, "ecdh"},
    {CRYPT_PKEY_ECDSA, "ecdsa"},
    {CRYPT_PKEY_ED25519, "ed25519"},
    {CRYPT_PKEY_DH, "dh"},
    {CRYPT_PKEY_DSA, "dsa"},
    {CRYPT_PKEY_RSA, "rsa"},
    {CRYPT_PKEY_SM2, "sm2"},
    {CRYPT_PKEY_X25519, "x25519"},
};

#define PKEY_ALG_CNT (sizeof(g_allPkeyAlgInfo) / sizeof(CidInfo))

static const CidInfo g_allMacAlgInfo[] = {
    {CRYPT_MAC_HMAC_MD5, "hmac-md5"},
    {CRYPT_MAC_HMAC_SHA1, "hmac-sha1"},
    {CRYPT_MAC_HMAC_SHA224, "hmac-sha224"},
    {CRYPT_MAC_HMAC_SHA256, "hmac-sha256"},
    {CRYPT_MAC_HMAC_SHA384, "hmac-sha384"},
    {CRYPT_MAC_HMAC_SHA512, "hmac-sha512"},
    {CRYPT_MAC_HMAC_SHA3_224, "hmac-sha3-224"},
    {CRYPT_MAC_HMAC_SHA3_256, "hmac-sha3-256"},
    {CRYPT_MAC_HMAC_SHA3_384, "hmac-sha3-384"},
    {CRYPT_MAC_HMAC_SHA3_512, "hmac-sha3-512"},
    {CRYPT_MAC_HMAC_SM3, "hmac-sm3"},
    {CRYPT_MAC_CMAC_AES128, "cmac-aes128"},
    {CRYPT_MAC_CMAC_AES192, "cmac-aes192"},
    {CRYPT_MAC_CMAC_AES256, "cmac-aes256"},
    {CRYPT_MAC_GMAC_AES128, "gmac-aes128"},
    {CRYPT_MAC_GMAC_AES192, "gmac-aes192"},
    {CRYPT_MAC_GMAC_AES256, "gmac-aes256"},
    {CRYPT_MAC_SIPHASH64, "siphash64"},
    {CRYPT_MAC_SIPHASH128, "siphash128"},
    {CRYPT_MAC_CBC_MAC_SM4, "sm4-cbc-mac"},
};

#define MAC_ALG_CNT (sizeof(g_allMacAlgInfo) / sizeof(CidInfo))

static const CidInfo g_allRandAlgInfo[] = {
    {CRYPT_RAND_SHA1, "sha1"},
    {CRYPT_RAND_SHA224, "sha224"},
    {CRYPT_RAND_SHA256, "sha256"},
    {CRYPT_RAND_SHA384, "sha384"},
    {CRYPT_RAND_SHA512, "sha512"},
    {CRYPT_RAND_SM3, "sm3"},
    {CRYPT_RAND_HMAC_SHA1, "hmac-sha1"},
    {CRYPT_RAND_HMAC_SHA224, "hmac-sha224"},
    {CRYPT_RAND_HMAC_SHA256, "hmac-sha256"},
    {CRYPT_RAND_HMAC_SHA384, "hmac-sha384"},
    {CRYPT_RAND_HMAC_SHA512, "hmac-sha512"},
    {CRYPT_RAND_AES128_CTR, "aes128-ctr"},
    {CRYPT_RAND_AES192_CTR, "aes192-ctr"},
    {CRYPT_RAND_AES256_CTR, "aes256-ctr"},
    {CRYPT_RAND_AES128_CTR_DF, "aes128-ctr-df"},
    {CRYPT_RAND_AES192_CTR_DF, "aes192-ctr-df"},
    {CRYPT_RAND_AES256_CTR_DF, "aes256-ctr-df"},
    {CRYPT_RAND_SM4_CTR_DF, "sm4-ctr-df"},
};

#define RAND_ALG_CNT (sizeof(g_allRandAlgInfo) / sizeof(CidInfo))

static const CidInfo g_allKdfAlgInfo[] = {
    {CRYPT_MAC_HMAC_MD5, "hmac-md5"},
    {CRYPT_MAC_HMAC_SHA1, "hmac-sha1"},
    {CRYPT_MAC_HMAC_SHA224, "hmac-sha224"},
    {CRYPT_MAC_HMAC_SHA256, "hmac-sha256"},
    {CRYPT_MAC_HMAC_SHA384, "hmac-sha384"},
    {CRYPT_MAC_HMAC_SHA512, "hmac-sha512"},
    {CRYPT_MAC_HMAC_SHA3_224, "hmac-sha3-224"},
    {CRYPT_MAC_HMAC_SHA3_256, "hmac-sha3-256"},
    {CRYPT_MAC_HMAC_SHA3_384, "hmac-sha3-384"},
    {CRYPT_MAC_HMAC_SHA3_512, "hmac-sha3-512"},
    {CRYPT_MAC_HMAC_SM3, "hmac-sm3"},
    {CRYPT_KDF_PBKDF2, "pbkdf2"},
};

#define KDF_ALG_CNT (sizeof(g_allKdfAlgInfo) / sizeof(CidInfo))

static CidInfo g_allCurves[] = {
    {CRYPT_ECC_NISTP224, "P-224"},
    {CRYPT_ECC_NISTP256, "P-256"},
    {CRYPT_ECC_NISTP384, "P-384"},
    {CRYPT_ECC_NISTP521, "P-521"},
    {CRYPT_ECC_NISTP224, "prime224v1"},
    {CRYPT_ECC_NISTP256, "prime256v1"},
    {CRYPT_ECC_NISTP384, "secp384r1"},
    {CRYPT_ECC_NISTP521, "secp521r1"},
    {CRYPT_ECC_BRAINPOOLP256R1, "brainpoolp256r1"},
    {CRYPT_ECC_BRAINPOOLP384R1, "brainpoolp384r1"},
    {CRYPT_ECC_BRAINPOOLP512R1, "brainpoolp512r1"},
    {CRYPT_ECC_SM2, "sm2"},
};

#define CURVES_SPLIT_LINE 6
#define CURVES_CNT (sizeof(g_allCurves) / sizeof(CidInfo))

typedef void (*PrintAlgFunc)(void);
PrintAlgFunc g_printAlgFuncList[] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
#define PRINT_ALG_FUNC_LIST_CNT (sizeof(g_printAlgFuncList) / sizeof(PrintAlgFunc))

static void AppPushPrintFunc(PrintAlgFunc func)
{
    for (size_t i = 0; i < PRINT_ALG_FUNC_LIST_CNT; ++i) {
        if ((g_printAlgFuncList[i] == NULL) || (g_printAlgFuncList[i] == func)) {
            g_printAlgFuncList[i] = func;
            return;
        }
    }
}

static void AppPrintList(void)
{
    for (size_t i = 0; i < PRINT_ALG_FUNC_LIST_CNT; ++i) {
        if ((g_printAlgFuncList[i] != NULL)) {
            g_printAlgFuncList[i]();
        }
    }
}

static void ResetPrintAlgFuncList(void)
{
    for (size_t i = 0; i < PRINT_ALG_FUNC_LIST_CNT; ++i) {
        g_printAlgFuncList[i] = NULL;
    }
}

static BSL_UIO *g_stdout = NULL;

static int32_t AppPrintStdoutUioInit(void)
{
    g_stdout = BSL_UIO_New(BSL_UIO_FileMethod());
    if (BSL_UIO_Ctrl(g_stdout, BSL_UIO_FILE_PTR, 0, (void *)stdout) != BSL_SUCCESS) {
        AppPrintError("Failed to set stdout mode.\n");
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static void AppPrintStdoutUioUnInit(void)
{
    BSL_UIO_Free(g_stdout);
}

static void PrintCipherAlg(void)
{
    AppPrint(g_stdout, "List Cipher Algorithms:\n");
    AppPrint(g_stdout, "%-20s\t%s\n", "NAME", "CID");

    for (size_t i = 0; i < CIPHER_ALG_CNT; ++i) {
        if (!CRYPT_EAL_CipherIsValidAlgId(g_allCipherAlgInfo[i].cid)) {
            continue;
        }
        AppPrint(g_stdout, "%-20s\t%3zu\n", g_allCipherAlgInfo[i].name, g_allCipherAlgInfo[i].cid);
    }
}

static void PrintMdAlg(void)
{
    AppPrint(g_stdout, "List Digest Algorithms:\n");
    AppPrint(g_stdout, "%-20s\t%s\n", "NAME", "CID");
    for (size_t i = 0; i < MD_ALG_CNT; ++i) {
        if (!CRYPT_EAL_MdIsValidAlgId(g_allMdAlgInfo[i].cid)) {
            continue;
        }
        AppPrint(g_stdout, "%-20s\t%3zu\n", g_allMdAlgInfo[i].name, g_allMdAlgInfo[i].cid);
    }
}

static void PrintPkeyAlg(void)
{
    AppPrint(g_stdout, "List Asym Algorithms:\n");
    AppPrint(g_stdout, "%-20s\t%s\n", "NAME", "CID");
    for (size_t i = 0; i < PKEY_ALG_CNT; ++i) {
        if (!CRYPT_EAL_PkeyIsValidAlgId(g_allPkeyAlgInfo[i].cid)) {
            continue;
        }
        AppPrint(g_stdout, "%-20s\t%3zu\n", g_allPkeyAlgInfo[i].name, g_allPkeyAlgInfo[i].cid);
    }
}

static void PrintMacAlg(void)
{
    AppPrint(g_stdout, "List Mac Algorithms:\n");
    AppPrint(g_stdout, "%-20s\t%s\n", "NAME", "CID");
    for (size_t i = 0; i < MAC_ALG_CNT; ++i) {
        if (!CRYPT_EAL_MacIsValidAlgId(g_allMacAlgInfo[i].cid)) {
            continue;
        }
        AppPrint(g_stdout, "%-20s\t%3zu\n", g_allMacAlgInfo[i].name, g_allMacAlgInfo[i].cid);
    }
}

static void PrintRandAlg(void)
{
    AppPrint(g_stdout, "List Rand Algorithms:\n");
    AppPrint(g_stdout, "%-20s\t%s\n", "NAME", "CID");
    for (size_t i = 0; i < RAND_ALG_CNT; ++i) {
        if (!CRYPT_EAL_RandIsValidAlgId(g_allRandAlgInfo[i].cid)) {
            continue;
        }
        AppPrint(g_stdout, "%-20s\t%3zu\n", g_allRandAlgInfo[i].name, g_allRandAlgInfo[i].cid);
    }
}

static void PrintHkdfAlg(void)
{
    AppPrint(g_stdout, "List  Hkdf  Algorithms:\n");
    AppPrint(g_stdout, "%-20s\t%s\n", "NAME", "CID");
    for (size_t i = 0; i < KDF_ALG_CNT; ++i) {
        if (!CRYPT_EAL_KdfIsValidAlgId(g_allKdfAlgInfo[i].cid)) {
            continue;
        }
        AppPrint(g_stdout, "%-20s\t%3zu\n", g_allKdfAlgInfo[i].name, g_allKdfAlgInfo[i].cid);
    }
}

static void PrintPbkdf2Alg(void)
{
    AppPrint(g_stdout, "List  Pbkdf2  Algorithms:\n");
    AppPrint(g_stdout, "%-20s\t%s\n", "NAME", "CID");
    for (size_t i = 0; i < KDF_ALG_CNT; ++i) {
        if (!CRYPT_EAL_KdfIsValidAlgId(g_allKdfAlgInfo[i].cid)) {
            continue;
        }
        AppPrint(g_stdout, "%-20s\t%3zu\n", g_allKdfAlgInfo[i].name, g_allKdfAlgInfo[i].cid);
    }
}

static void PrintKdftls12Alg(void)
{
    AppPrint(g_stdout, "List  Kdftls12  Algorithms:\n");
    AppPrint(g_stdout, "%-20s\t%s\n", "NAME", "CID");
    for (size_t i = 0; i < KDF_ALG_CNT; ++i) {
        if (!CRYPT_EAL_KdfIsValidAlgId(g_allKdfAlgInfo[i].cid)) {
            continue;
        }
        AppPrint(g_stdout, "%-20s\t%3zu\n", g_allKdfAlgInfo[i].name, g_allKdfAlgInfo[i].cid);
    }
}

static void PrintKdfAlg(void)
{
    PrintHkdfAlg();
    AppPrint(g_stdout, "\n");
    PrintPbkdf2Alg();
    AppPrint(g_stdout, "\n");
    PrintKdftls12Alg();
}

static void PrintAllAlg(void)
{
    PrintCipherAlg();
    AppPrint(g_stdout, "\n");
    PrintMdAlg();
    AppPrint(g_stdout, "\n");
    PrintPkeyAlg();
    AppPrint(g_stdout, "\n");
    PrintMacAlg();
    AppPrint(g_stdout, "\n");
    PrintRandAlg();
    AppPrint(g_stdout, "\n");
    PrintKdfAlg();
}

static void PrintCurves(void)
{
    AppPrint(g_stdout, "List  Curves:\n");
    AppPrint(g_stdout, "%-20s\t%s\n", "NAME", "CID");
    for (size_t i = 0; i < CURVES_CNT; ++i) {
        AppPrint(g_stdout, "%-20s\t%3zu\n", g_allCurves[i].name, g_allCurves[i].cid);
    }
}

static int32_t ParseListOpt(void)
{
    bool isEmptyOpt = true;
    int optType = HITLS_APP_OPT_ERR;
    while ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF) {
        isEmptyOpt = false;
        switch (optType) {
            case HITLS_APP_OPT_HELP:
                HITLS_APP_OptHelpPrint(g_listOpts);
                return HITLS_APP_HELP;
            case HITLS_APP_OPT_ERR:
                AppPrintError("list: Use -help for summary.\n");
                return HITLS_APP_OPT_UNKOWN;
            case HITLS_APP_LIST_OPT_ALL_ALG:
                AppPushPrintFunc(PrintAllAlg);
                break;
            case HITLS_APP_LIST_OPT_DGST_ALG:
                AppPushPrintFunc(PrintMdAlg);
                break;
            case HITLS_APP_LIST_OPT_CIPHER_ALG:
                AppPushPrintFunc(PrintCipherAlg);
                break;
            case HITLS_APP_LIST_OPT_ASYM_ALG:
                AppPushPrintFunc(PrintPkeyAlg);
                break;
            case HITLS_APP_LIST_OPT_MAC_ALG:
                AppPushPrintFunc(PrintMacAlg);
                break;
            case HITLS_APP_LIST_OPT_RAND_ALG:
                AppPushPrintFunc(PrintRandAlg);
                break;
            case HITLS_APP_LIST_OPT_KDF_ALG:
                AppPushPrintFunc(PrintKdfAlg);
                break;
            case HITLS_APP_LIST_OPT_CURVES:
                AppPushPrintFunc(PrintCurves);
                break;
            default:
                break;
        }
    }
    // Get the number of parameters that cannot be parsed in the current version
    // and print the error information and help list.
    if ((HITLS_APP_GetRestOptNum() != 0) || isEmptyOpt) {
        AppPrintError("Extra arguments given.\n");
        AppPrintError("list: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    return HITLS_APP_SUCCESS;
}

// List main function
int32_t HITLS_ListMain(int argc, char *argv[])
{
    ResetPrintAlgFuncList();
    int32_t ret = HITLS_APP_SUCCESS;
    do {
        ret = AppPrintStdoutUioInit();
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        ret = HITLS_APP_OptBegin(argc, argv, g_listOpts);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("error in opt begin.\n");
            break;
        }
        ret = ParseListOpt();
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        AppPrintList();
    } while (false);
    HITLS_APP_OptEnd();
    AppPrintStdoutUioUnInit();
    return ret;
}

static int32_t GetInfoByType(int32_t type, const CidInfo **cidInfos, uint32_t *cnt, char **typeName)
{
    switch (type) {
        case HITLS_APP_LIST_OPT_DGST_ALG:
            *cidInfos = g_allMdAlgInfo;
            *cnt = MD_ALG_CNT;
            *typeName = "dgst";
            return HITLS_APP_SUCCESS;
        case HITLS_APP_LIST_OPT_CIPHER_ALG:
            *cidInfos = g_allCipherAlgInfo;
            *cnt = CIPHER_ALG_CNT;
            *typeName = "cipher";
            return HITLS_APP_SUCCESS;
        case HITLS_APP_LIST_OPT_ASYM_ALG:
            *cidInfos = g_allPkeyAlgInfo;
            *cnt = PKEY_ALG_CNT;
            *typeName = "asym";
            return HITLS_APP_SUCCESS;
        case HITLS_APP_LIST_OPT_MAC_ALG:
            *cidInfos = g_allMacAlgInfo;
            *cnt = MAC_ALG_CNT;
            *typeName = "mac";
            return HITLS_APP_SUCCESS;
        case HITLS_APP_LIST_OPT_RAND_ALG:
            *cidInfos = g_allRandAlgInfo;
            *cnt = RAND_ALG_CNT;
            *typeName = "rand";
            return HITLS_APP_SUCCESS;
        case HITLS_APP_LIST_OPT_KDF_ALG:
            *cidInfos = g_allKdfAlgInfo;
            *cnt = KDF_ALG_CNT;
            *typeName = "kdf";
            return HITLS_APP_SUCCESS;
        case HITLS_APP_LIST_OPT_CURVES:
            *cidInfos = g_allCurves;
            *cnt = CURVES_CNT;
            *typeName = "curves";
            return HITLS_APP_SUCCESS;
        default:
            return HITLS_APP_INVALID_ARG;
    }
}

int32_t HITLS_APP_GetCidByName(const char *name, int32_t type)
{
    if (name == NULL) {
        return BSL_CID_UNKNOWN;
    }
    const CidInfo *cidInfos = NULL;
    uint32_t cnt = 0;
    char *typeName;
    int32_t ret = GetInfoByType(type, &cidInfos, &cnt, &typeName);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Get cid info by name failed, name: %s\n", name);
        return BSL_CID_UNKNOWN;
    }
    for (size_t i = 0; i < cnt; ++i) {
        if (strcmp(name, cidInfos[i].name) == 0) {
            return (BslCid)cidInfos[i].cid;
        }
    }
    AppPrintError("Unsupport %s: %s\n", typeName, name);
    return BSL_CID_UNKNOWN;
}

const char *HITLS_APP_GetNameByCid(int32_t cid, int32_t type)
{
    const CidInfo *cidInfos = NULL;
    uint32_t cnt = 0;
    char *typeName;
    int32_t ret = GetInfoByType(type, &cidInfos, &cnt, &typeName);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Get cid info by cid failed, cid: %d\n", cid);
        return NULL;
    }
    for (size_t i = 0; i < cnt; ++i) {
        if (cid == cidInfos[i].cid) {
            return cidInfos[i].name;
        }
    }
    AppPrintError("Unsupport %s: %d\n", typeName, cid);
    return NULL;
}

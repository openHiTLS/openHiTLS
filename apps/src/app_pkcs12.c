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

#include "app_pkcs12.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <securec.h>
#include <limits.h>
#include "app_errno.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_utils.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "bsl_err.h"
#include "bsl_uio.h"
#include "bsl_ui.h"
#include "bsl_obj.h"
#include "bsl_errno.h"
#include "crypt_eal_rand.h"
#include "hitls_cert_local.h"
#include "hitls_pkcs12_local.h"
#include "hitls_pki_errno.h"


#define CA_NAME_NUM (APP_FILE_MAX_SIZE_KB / 1) // Calculated based on the average value of 1K for each certificate.

typedef enum {
    HITLS_APP_OPT_IN_FILE = 2,
    HITLS_APP_OPT_OUT_FILE,
    HITLS_APP_OPT_PASS_IN,
    HITLS_APP_OPT_PASS_OUT,
    HITLS_APP_OPT_IN_KEY,
    HITLS_APP_OPT_EXPORT,
    HITLS_APP_OPT_CLCERTS,
    HITLS_APP_OPT_KEY_PBE,
    HITLS_APP_OPT_CERT_PBE,
    HITLS_APP_OPT_MAC_ALG,
    HITLS_APP_OPT_CHAIN,
    HITLS_APP_OPT_CANAME,
    HITLS_APP_OPT_NAME,
    HITLS_APP_OPT_CA_FILE,
    HITLS_APP_OPT_CIPHER_ALG,
} HITLSOptType;

typedef struct {
    char *inFile;
    char *outFile;
    char *passInArg;
    char *passOutArg;
} GeneralOptions;

typedef struct {
    bool clcerts;
    const char *cipherAlgName;
} ImportOptions;

typedef struct {
    char *inKey;
    char *name;
    char *caName[CA_NAME_NUM];
    uint32_t caNameSize;
    char *caFile;
    char *macAlgArg;
    char *certPbeArg;
    char *keyPbeArg;
    bool chain;
    bool export;
} OutputOptions;

typedef struct {
    GeneralOptions genOpt;
    ImportOptions importOpt;
    OutputOptions outPutOpt;
    CRYPT_EAL_PkeyCtx *pkey;
    char *passin;
    char *passout;
    int32_t cipherAlgCid;
    int32_t macAlg;
    int32_t certPbe;
    int32_t keyPbe;
    HITLS_PKCS12 *p12;
    HITLS_X509_StoreCtx *store;
    HITLS_X509_StoreCtx *dupStore;
    HITLS_X509_List *certList;
    HITLS_X509_List *caCertList;
    HITLS_X509_List *outCertChainList;
    HITLS_X509_Cert *userCert;
    BSL_UIO *wUio;
} Pkcs12OptCtx;

typedef struct {
    const uint32_t id;
    const char *name;
} AlgList;

typedef int32_t (*OptHandleFunc)(Pkcs12OptCtx *);

typedef struct {
    int optType;
    OptHandleFunc func;
} OptHandleTable;

#define MIN_NAME_LEN 1U
#define MAX_NAME_LEN 1024U

static const HITLS_CmdOption OPTS[] = {
    {"help", HITLS_APP_OPT_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"in", HITLS_APP_OPT_IN_FILE, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Input file"},
    {"out", HITLS_APP_OPT_OUT_FILE, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output file"},
    {"passin", HITLS_APP_OPT_PASS_IN, HITLS_APP_OPT_VALUETYPE_STRING, "Input file pass phrase source"},
    {"passout", HITLS_APP_OPT_PASS_OUT, HITLS_APP_OPT_VALUETYPE_STRING, "Output file pass phrase source"},
    {"inkey", HITLS_APP_OPT_IN_KEY, HITLS_APP_OPT_VALUETYPE_STRING, "Private key if not infile"},
    {"export", HITLS_APP_OPT_EXPORT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Output PKCS12 file"},
    {"clcerts",  HITLS_APP_OPT_CLCERTS, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "output client certs"},
    {"keypbe", HITLS_APP_OPT_KEY_PBE, HITLS_APP_OPT_VALUETYPE_STRING, "Private key PBE algorithm (default PBES2)"},
    {"certpbe", HITLS_APP_OPT_CERT_PBE, HITLS_APP_OPT_VALUETYPE_STRING, "Certificate PBE algorithm (default PBES2)"},
    {"macalg", HITLS_APP_OPT_MAC_ALG, HITLS_APP_OPT_VALUETYPE_STRING, "Digest algorithm used in MAC (default SHA256)"},
    {"chain", HITLS_APP_OPT_CHAIN, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Add certificate chain"},
    {"caname",  HITLS_APP_OPT_CANAME, HITLS_APP_OPT_VALUETYPE_STRING, "Input friendly ca name"},
    {"name", HITLS_APP_OPT_NAME, HITLS_APP_OPT_VALUETYPE_STRING, "Use name as friendly name"},
    {"CAfile", HITLS_APP_OPT_CA_FILE, HITLS_APP_OPT_VALUETYPE_STRING, "PEM-format file of CA's"},
    {"", HITLS_APP_OPT_CIPHER_ALG, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Any supported cipher"},
    {NULL, 0, 0, NULL}
};

static const AlgList MAC_ALG_LIST[] = {
    {CRYPT_MD_SHA224, "sha224"},
    {CRYPT_MD_SHA256, "sha256"},
    {CRYPT_MD_SHA384, "sha384"},
    {CRYPT_MD_SHA512, "sha512"}
};

static const AlgList CERT_PBE_LIST[] = {
    {BSL_CID_PBES2,   "PBES2"}
};

static const AlgList KEY_PBE_LIST[] = {
    {BSL_CID_PBES2,   "PBES2"}
};

static int32_t DisplayHelp(Pkcs12OptCtx *opt)
{
    (void)opt;
    HITLS_APP_OptHelpPrint(OPTS);
    return HITLS_APP_HELP;
}

static int32_t HandleOptErr(Pkcs12OptCtx *opt)
{
    (void)opt;
    AppPrintError("pkcs12: Use -help for summary.\n");
    return HITLS_APP_OPT_UNKOWN;
}

static int32_t ParseInFile(Pkcs12OptCtx *opt)
{
    opt->genOpt.inFile = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t ParseOutFile(Pkcs12OptCtx *opt)
{
    opt->genOpt.outFile = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t ParsePassIn(Pkcs12OptCtx *opt)
{
    opt->genOpt.passInArg = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t ParsePassOut(Pkcs12OptCtx *opt)
{
    opt->genOpt.passOutArg = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t ParseInKey(Pkcs12OptCtx *opt)
{
    opt->outPutOpt.inKey = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t ParseExport(Pkcs12OptCtx *opt)
{
    opt->outPutOpt.export = true;
    return HITLS_APP_SUCCESS;
}

static int32_t ParseClcerts(Pkcs12OptCtx *opt)
{
    opt->importOpt.clcerts = true;
    return HITLS_APP_SUCCESS;
}

static int32_t ParseKeyPbe(Pkcs12OptCtx *opt)
{
    opt->outPutOpt.keyPbeArg = HITLS_APP_OptGetValueStr();
    bool find = false;
    for (size_t i = 0; i < sizeof(KEY_PBE_LIST) / sizeof(KEY_PBE_LIST[0]); i++) {
        if (strcmp(KEY_PBE_LIST[i].name, opt->outPutOpt.keyPbeArg) == 0) {
            find = true;
            opt->keyPbe = KEY_PBE_LIST[i].id;
            break;
        }
    }

    // If the supported algorithm list is not found, print the supported algorithm list and return an error.
    if (!find) {
        AppPrintError("pkcs12: The current private key PBE algorithm supports only the following algorithms:\n");
        for (size_t i = 0; i < sizeof(KEY_PBE_LIST) / sizeof(KEY_PBE_LIST[0]); i++) {
            AppPrintError("%-19s", KEY_PBE_LIST[i].name);
            // 4 algorithm names are displayed in each row.
            if ((i + 1) % 4 == 0 && i != ((sizeof(KEY_PBE_LIST) / sizeof(KEY_PBE_LIST[0])) - 1)) {
                AppPrintError("\n");
            }
        }
        AppPrintError("\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t ParseCertPbe(Pkcs12OptCtx *opt)
{
    opt->outPutOpt.certPbeArg = HITLS_APP_OptGetValueStr();
    bool find = false;
    for (size_t i = 0; i < sizeof(CERT_PBE_LIST) / sizeof(CERT_PBE_LIST[0]); i++) {
        if (strcmp(CERT_PBE_LIST[i].name, opt->outPutOpt.certPbeArg) == 0) {
            find = true;
            opt->certPbe = CERT_PBE_LIST[i].id;
            break;
        }
    }

    // If the supported algorithm list is not found, print the supported algorithm list and return an error.
    if (!find) {
        AppPrintError("pkcs12: The current certificate PBE algorithm supports only the following algorithms:\n");
        for (size_t i = 0; i < sizeof(CERT_PBE_LIST) / sizeof(CERT_PBE_LIST[0]); i++) {
            AppPrintError("%-19s", CERT_PBE_LIST[i].name);
            // 4 algorithm names are displayed in each row.
            if ((i + 1) % 4 == 0 && i != ((sizeof(CERT_PBE_LIST) / sizeof(CERT_PBE_LIST[0])) - 1)) {
                AppPrintError("\n");
            }
        }
        AppPrintError("\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t ParseMacAlg(Pkcs12OptCtx *opt)
{
    opt->outPutOpt.macAlgArg = HITLS_APP_OptGetValueStr();
    bool find = false;
    for (size_t i = 0; i < sizeof(MAC_ALG_LIST) / sizeof(MAC_ALG_LIST[0]); i++) {
        if (strcmp(MAC_ALG_LIST[i].name, opt->outPutOpt.macAlgArg) == 0) {
            find = true;
            opt->macAlg = MAC_ALG_LIST[i].id;
            break;
        }
    }

    // If the supported algorithm list is not found, print the supported algorithm list and return an error.
    if (!find) {
        AppPrintError("pkcs12: The current digest algorithm supports only the following algorithms:\n");
        for (size_t i = 0; i < sizeof(MAC_ALG_LIST) / sizeof(MAC_ALG_LIST[0]); i++) {
            AppPrintError("%-19s", MAC_ALG_LIST[i].name);
            // 4 algorithm names are displayed in each row.
            if ((i + 1) % 4 == 0 && i != ((sizeof(MAC_ALG_LIST) / sizeof(MAC_ALG_LIST[0])) - 1)) {
                AppPrintError("\n");
            }
        }
        AppPrintError("\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t ParseChain(Pkcs12OptCtx *opt)
{
    opt->outPutOpt.chain = true;
    return HITLS_APP_SUCCESS;
}

static int32_t ParseName(Pkcs12OptCtx *opt)
{
    opt->outPutOpt.name = HITLS_APP_OptGetValueStr();
    if (strlen(opt->outPutOpt.name) > MAX_NAME_LEN) {
        AppPrintError("pkcs12: The name length is incorrect. It should be in the range of %u to %u.\n", MIN_NAME_LEN,
            MAX_NAME_LEN);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t ParseCaName(Pkcs12OptCtx *opt)
{
    char *caName = HITLS_APP_OptGetValueStr();
    if (strlen(caName) > MAX_NAME_LEN) {
        AppPrintError("pkcs12: The name length is incorrect. It should be in the range of %u to %u.\n", MIN_NAME_LEN,
            MAX_NAME_LEN);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    uint32_t index = opt->outPutOpt.caNameSize;
    if (index >= CA_NAME_NUM) {
        AppPrintError("pkcs12: The maximum number of canames is %u.\n", CA_NAME_NUM);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    opt->outPutOpt.caName[index] = caName;
    ++(opt->outPutOpt.caNameSize);
    return HITLS_APP_SUCCESS;
}

static int32_t ParseCaFile(Pkcs12OptCtx *opt)
{
    opt->outPutOpt.caFile = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t ParseCipher(Pkcs12OptCtx *opt)
{
    opt->importOpt.cipherAlgName = HITLS_APP_OptGetUnKownOptName();
    return HITLS_APP_GetAndCheckCipherOpt(opt->importOpt.cipherAlgName, &opt->cipherAlgCid);
}

static const OptHandleTable OPT_HANDLE_TABLE[] = {
    {HITLS_APP_OPT_ERR,        HandleOptErr},
    {HITLS_APP_OPT_HELP,       DisplayHelp},
    {HITLS_APP_OPT_IN_FILE,    ParseInFile},
    {HITLS_APP_OPT_OUT_FILE,   ParseOutFile},
    {HITLS_APP_OPT_PASS_IN,    ParsePassIn},
    {HITLS_APP_OPT_PASS_OUT,   ParsePassOut},
    {HITLS_APP_OPT_IN_KEY,     ParseInKey},
    {HITLS_APP_OPT_EXPORT,     ParseExport},
    {HITLS_APP_OPT_CLCERTS,    ParseClcerts},
    {HITLS_APP_OPT_KEY_PBE,    ParseKeyPbe},
    {HITLS_APP_OPT_CERT_PBE,   ParseCertPbe},
    {HITLS_APP_OPT_MAC_ALG,    ParseMacAlg},
    {HITLS_APP_OPT_CHAIN,      ParseChain},
    {HITLS_APP_OPT_CANAME,     ParseCaName},
    {HITLS_APP_OPT_NAME,       ParseName},
    {HITLS_APP_OPT_CA_FILE,    ParseCaFile},
    {HITLS_APP_OPT_CIPHER_ALG, ParseCipher}
};

static int32_t ParseOpt(int argc, char *argv[], Pkcs12OptCtx *opt)
{
    int32_t ret = HITLS_APP_OptBegin(argc, argv, OPTS);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("pkcs12: error in opt begin.\n");
        return ret;
    }

    int optType = HITLS_APP_OPT_ERR;
    while ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF) {
        for (size_t i = 0; i < (sizeof(OPT_HANDLE_TABLE) / sizeof(OPT_HANDLE_TABLE[0])); i++) {
            if (optType != OPT_HANDLE_TABLE[i].optType) {
                continue;
            }

            ret = OPT_HANDLE_TABLE[i].func(opt);
            if (ret != HITLS_APP_SUCCESS) { // If any option fails to be parsed, an error is returned.
                return ret;
            }
            break; // If the parsing is successful, exit the current loop and parse the next option.
        }
    }

    // Obtain the number of parameters that cannot be parsed in the current version,
    // and print the error information and help list.
    if (HITLS_APP_GetRestOptNum() != 0) {
        AppPrintError("pkcs12: Extra arguments given.\n");
        AppPrintError("pkcs12: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    return ret;
}

static int32_t CheckInFile(const char *inFile, const char *fileType)
{
    if (inFile == NULL) {
        AppPrintError("pkcs12: The %s is not specified.\n", fileType);
        return HITLS_APP_OPT_UNKOWN;
    }
    if ((strnlen(inFile, PATH_MAX + 1) >= PATH_MAX) || (strlen(inFile) == 0)) {
        AppPrintError("pkcs12: The length of %s error, range is (0, %d).\n", fileType, PATH_MAX);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    size_t fileLen = 0;
    int32_t ret = BSL_SAL_FileLength(inFile, &fileLen);
    if (ret != BSL_SUCCESS) {
        AppPrintError("pkcs12: Failed to get file size: %s, errCode = 0x%x.\n", fileType, ret);
        return HITLS_APP_BSL_FAIL;
    }
    if (fileLen > APP_FILE_MAX_SIZE) {
        AppPrintError("pkcs12: File size exceed limit %zukb: %s.\n", APP_FILE_MAX_SIZE_KB, fileType);
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CheckOutFile(const char *outFile)
{
    // If outfile is transferred, the length cannot exceed PATH_MAX.
    if ((outFile != NULL) && ((strnlen(outFile, PATH_MAX + 1) >= PATH_MAX) || (strlen(outFile) == 0))) {
        AppPrintError("pkcs12: The length of out file error, range is (0, %d).\n", PATH_MAX);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t LoadCertList(const char *certFile, HITLS_X509_List **outCertList)
{
    HITLS_X509_List *certlist = NULL;
    int32_t ret = HITLS_X509_CertParseBundleFile(BSL_FORMAT_PEM, certFile, &certlist);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkcs12: Failed to read cert from %s. errCode = 0x%x.\n", certFile, ret);
        return HITLS_APP_X509_FAIL;
    }
    *outCertList = certlist;
    return HITLS_APP_SUCCESS;
}

static int32_t CheckCertListWithPriKey(HITLS_X509_List *certList, CRYPT_EAL_PkeyCtx *prvKey, HITLS_X509_Cert **userCert)
{
    HITLS_X509_Cert *pstCert = BSL_LIST_GET_FIRST(certList);
    while (pstCert != NULL) {
        CRYPT_EAL_PkeyCtx *pubKey = NULL;
        int32_t ret = HITLS_X509_CertCtrl(pstCert, HITLS_X509_GET_PUBKEY, &pubKey, 0);
        if (ret != HITLS_PKI_SUCCESS) {
            AppPrintError("pkcs12: Get pubKey from certificate failed, errCode = 0x%x.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
        ret = CRYPT_EAL_PkeyCmp(pubKey, prvKey);
        CRYPT_EAL_PkeyFreeCtx(pubKey);
        if (ret == CRYPT_SUCCESS) {
            // If an error occurs, the memory applied here will be uniformly freed through the release of caList
            *userCert = HITLS_X509_CertDup(pstCert);
            if (*userCert == NULL) {
                AppPrintError("pkcs12: Failed to duplicate the certificate.\n");
                return HITLS_APP_X509_FAIL;
            }
            BSL_LIST_DeleteCurrent(certList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
            return HITLS_APP_SUCCESS;
        }
        pstCert = BSL_LIST_GET_NEXT(certList);
    }
    AppPrintError("pkcs12: No certificate matches private key.\n");
    return HITLS_APP_X509_FAIL;
}

static int32_t AddCertToList(HITLS_X509_Cert *cert, HITLS_X509_List *certList)
{
    HITLS_X509_Cert *tmpCert = HITLS_X509_CertDup(cert);
    if (tmpCert == NULL) {
        AppPrintError("pkcs12: Failed to duplicate the certificate.\n");
        return HITLS_APP_X509_FAIL;
    }
    int32_t ret = BSL_LIST_AddElement(certList, tmpCert, BSL_LIST_POS_AFTER);
    if (ret != BSL_SUCCESS) {
        AppPrintError("pkcs12: Failed to add cert list, errCode = 0x%x.\n", ret);
        HITLS_X509_CertFree(tmpCert);
        return HITLS_APP_BSL_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t AddCertChain(Pkcs12OptCtx *opt)
{
    // if the issuer certificate for input certificate is not found in the trust store, then only input
    // certificate will be considered in the output chain.
    if (BSL_LIST_COUNT(opt->outCertChainList) <= 1) {
        AppPrintError("pkcs12: Failed to get local issuer certificate.\n");
        return HITLS_APP_X509_FAIL;
    }

    // Mark duplicate CA certificate
    opt->dupStore = HITLS_X509_StoreCtxNew();
    if (opt->dupStore == NULL) {
        AppPrintError("pkcs12: Failed to create the dup store context.\n");
        return HITLS_APP_X509_FAIL;
    }
    HITLS_X509_Cert *cert = BSL_LIST_GET_FIRST(opt->certList);
    while (cert != NULL) {
        (void)HITLS_X509_StoreCtxCtrl(opt->dupStore, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, cert,
            sizeof(HITLS_X509_Cert));
        cert = BSL_LIST_GET_NEXT(opt->certList);
    }

    // The first element in the output certificate chain is the input certificate, skip it.
    HITLS_X509_Cert *pstCert = BSL_LIST_GET_FIRST(opt->outCertChainList);
    pstCert = BSL_LIST_GET_NEXT(opt->outCertChainList);
    while (pstCert != NULL) {
        if (HITLS_X509_StoreCtxCtrl(opt->dupStore, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, pstCert,
            sizeof(HITLS_X509_Cert)) == HITLS_X509_ERR_CERT_EXIST) {
            pstCert = BSL_LIST_GET_NEXT(opt->outCertChainList);
            continue;
        }
        int32_t ret = AddCertToList(pstCert, opt->certList);
        if (ret != HITLS_APP_SUCCESS) {
            return ret;
        }
        pstCert = BSL_LIST_GET_NEXT(opt->outCertChainList);
    }
    return HITLS_APP_SUCCESS;
}

static int32_t ParseAndAddCertChain(Pkcs12OptCtx *opt)
{
    // If the user certificate is a root certificate, no action is required.
    bool selfSigned = false;
    int32_t ret = HITLS_X509_CheckIssued(opt->userCert, opt->userCert, &selfSigned);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkcs12: Failed to check cert issued, errCode = 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    opt->store = HITLS_X509_StoreCtxNew();
    if (opt->store == NULL) {
        AppPrintError("pkcs12: Failed to create the store context.\n");
        return HITLS_APP_X509_FAIL;
    }

    ret = HITLS_X509_CertParseBundleFile(BSL_FORMAT_PEM, opt->outPutOpt.caFile, &opt->caCertList);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkcs12: Failed to parse certificate %s, errCode = 0x%x.\n", opt->outPutOpt.caFile, ret);
        return HITLS_APP_X509_FAIL;
    }

    HITLS_X509_Cert *cert = BSL_LIST_GET_FIRST(opt->caCertList);
    while (cert != NULL) {
        ret = HITLS_X509_StoreCtxCtrl(opt->store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, cert, sizeof(HITLS_X509_Cert));
        if (ret == HITLS_X509_ERR_CERT_EXIST) {
            cert = BSL_LIST_GET_NEXT(opt->caCertList);
            continue;
        }
        if (ret != HITLS_PKI_SUCCESS) {
            AppPrintError("pkcs12: Failed to add the certificate %s to the trust store, errCode = 0x%0x.\n",
                opt->outPutOpt.caFile, ret);
            return HITLS_APP_X509_FAIL;
        }
        cert = BSL_LIST_GET_NEXT(opt->caCertList);
    }

    ret = HITLS_X509_CertChainBuild(opt->store, true, opt->userCert, &opt->outCertChainList);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkcs12: Failed get cert chain by cert, errCode = 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    return AddCertChain(opt);
}

static int32_t AddKeyBagToP12(char *name, CRYPT_EAL_PkeyCtx *pkey, HITLS_PKCS12 *p12)
{
    // new a key Bag
    HITLS_PKCS12_Bag *pkeyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, 0, pkey);
    if (pkeyBag == NULL) {
        AppPrintError("pkcs12: Failed to create the private key bag.\n");
        return HITLS_APP_X509_FAIL;
    }
    if (name != NULL) {
        BSL_Buffer attribute = { (uint8_t *)name, strlen(name) };
        int32_t ret = HITLS_PKCS12_BagAddAttr(pkeyBag, BSL_CID_FRIENDLYNAME, &attribute);
        if (ret != HITLS_PKI_SUCCESS) {
            AppPrintError("pkcs12: Failed to add the private key friendlyname, errCode = 0x%x.\n", ret);
            HITLS_PKCS12_BagFree(pkeyBag);
            return HITLS_APP_X509_FAIL;
        }
    }
    // Set entity-key to p12
    int32_t ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_KEYBAG, pkeyBag, 0);
    HITLS_PKCS12_BagFree(pkeyBag);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkcs12: Failed to set the private key bag, errCode = 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t AddUserCertBagToP12(char *name, HITLS_X509_Cert *cert, HITLS_PKCS12 *p12)
{
    // new a cert Bag
    HITLS_PKCS12_Bag *certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, cert);
    if (certBag == NULL) {
        AppPrintError("pkcs12: Failed to create the user cert bag.\n");
        return HITLS_APP_X509_FAIL;
    }
    if (name != NULL) {
        BSL_Buffer attribute = { (uint8_t *)name, strlen(name) };
        int32_t ret = HITLS_PKCS12_BagAddAttr(certBag, BSL_CID_FRIENDLYNAME, &attribute);
        if (ret != HITLS_PKI_SUCCESS) {
            AppPrintError("pkcs12: Failed to add the user cert friendlyname, errCode = 0x%x.\n", ret);
            HITLS_PKCS12_BagFree(certBag);
            return HITLS_APP_X509_FAIL;
        }
    }
    // Set entity-cert to p12
    int32_t ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_CERTBAG, certBag, 0);
    HITLS_PKCS12_BagFree(certBag);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkcs12: Failed to set the user cert bag, errCode = 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t AddOtherCertListBagToP12(char **caName, uint32_t caNameSize, HITLS_X509_List *certList,
    HITLS_PKCS12 *p12)
{
    int32_t ret = HITLS_APP_SUCCESS;
    HITLS_X509_Cert *pstCert = BSL_LIST_GET_FIRST(certList);
    uint32_t index = 0;
    while (pstCert != NULL) {
        HITLS_PKCS12_Bag *otherCertBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, pstCert);
        if (otherCertBag == NULL) {
            AppPrintError("pkcs12: Failed to create the other cert bag.\n");
            return HITLS_APP_X509_FAIL;
        }

        if ((index < caNameSize) && (caName[index] != NULL)) {
            BSL_Buffer caAttribute = { (uint8_t *)caName[index], strlen(caName[index]) };
            ret = HITLS_PKCS12_BagAddAttr(otherCertBag, BSL_CID_FRIENDLYNAME, &caAttribute);
            if (ret != HITLS_PKI_SUCCESS) {
                AppPrintError("pkcs12: Failed to add the other cert friendlyname, errCode = 0x%x.\n", ret);
                HITLS_PKCS12_BagFree(otherCertBag);
                return HITLS_APP_X509_FAIL;
            }
            ++index;
        }
        ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_CERTBAG, otherCertBag, 0);
        HITLS_PKCS12_BagFree(otherCertBag);
        if (ret != HITLS_PKI_SUCCESS) {
            AppPrintError("pkcs12: Failed to add the other cert bag, errCode = 0x%x.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
        pstCert = BSL_LIST_GET_NEXT(certList);
    }

    if (index < caNameSize) {
        AppPrintError("pkcs12: Warning: Redundant %zu -caname options.\n", caNameSize - index);
    }
    return HITLS_APP_SUCCESS;
}

static int32_t PrintPkcs12(Pkcs12OptCtx *opt)
{
    int32_t ret = HITLS_APP_SUCCESS;
    uint8_t *passOutBuf = NULL;
    uint32_t passOutBufLen = 0;
    BSL_UI_ReadPwdParam passParam = { "Export passwd", opt->genOpt.outFile, true };
    if (HITLS_APP_GetPasswd(&passParam, &opt->passout, &passOutBuf, &passOutBufLen) != HITLS_APP_SUCCESS) {
        return HITLS_APP_PASSWD_FAIL;
    }
    HITLS_PKCS12_EncodeParam encodeParam = { 0 };
    CRYPT_Pbkdf2Param certPbParam = { 0 };
    certPbParam.pbesId = opt->certPbe;
    certPbParam.pbkdfId = BSL_CID_PBKDF2;
    certPbParam.hmacId = CRYPT_MAC_HMAC_SHA256;
    certPbParam.symId = CRYPT_CIPHER_AES256_CBC;
    certPbParam.saltLen = DEFAULT_SALTLEN;
    certPbParam.pwd = passOutBuf;
    certPbParam.pwdLen = passOutBufLen;
    certPbParam.itCnt = DEFAULT_ITCNT;
    CRYPT_EncodeParam certEncParam = { CRYPT_DERIVE_PBKDF2, &certPbParam };

    HITLS_PKCS12_KdfParam  hmacParam  = { 0 };
    hmacParam.macId = opt->macAlg;
    hmacParam.saltLen = DEFAULT_SALTLEN;
    hmacParam.pwd = passOutBuf;
    hmacParam.pwdLen = passOutBufLen;
    hmacParam.itCnt = DEFAULT_ITCNT;
    HITLS_PKCS12_MacParam macParam = { .para = &hmacParam, .algId = BSL_CID_PKCS12KDF };
    encodeParam.macParam = macParam;
    encodeParam.encParam = certEncParam;

    BSL_Buffer p12Buff = { 0 };
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, opt->p12, &encodeParam, true, &p12Buff);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkcs12: Failed to generate pkcs12, errCode = 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    ret = HITLS_APP_OptWriteUio(opt->wUio, p12Buff.data, p12Buff.dataLen, HITLS_APP_FORMAT_ASN1);
    BSL_SAL_FREE(p12Buff.data);
    return ret;
}

static int32_t MakePfxAndOutput(Pkcs12OptCtx *opt)
{
    // Create pkcs12 info
    opt->p12 = HITLS_PKCS12_New();
    if (opt->p12 == NULL) {
        AppPrintError("pkcs12: Failed to create pkcs12 info.\n");
        return HITLS_APP_X509_FAIL;
    }

    // add key to p12
    int32_t ret = AddKeyBagToP12(opt->outPutOpt.name, opt->pkey, opt->p12);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    // add user cert to p12
    ret = AddUserCertBagToP12(opt->outPutOpt.name, opt->userCert, opt->p12);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    // add other cert to p12
    ret = AddOtherCertListBagToP12(opt->outPutOpt.caName, opt->outPutOpt.caNameSize, opt->certList, opt->p12);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    //  Cal localKeyId to p12
    int32_t mdId = CRYPT_MD_SHA1;
    ret = HITLS_PKCS12_Ctrl(opt->p12, HITLS_PKCS12_GEN_LOCALKEYID, &mdId, sizeof(CRYPT_MD_AlgId));
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkcs12: Failed to set the local keyid, errCode = 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    return PrintPkcs12(opt);
}

static int32_t CreatePkcs12File(Pkcs12OptCtx *opt)
{
    int32_t ret = LoadCertList(opt->genOpt.inFile, &opt->certList);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("pkcs12: Failed to load cert list.\n");
        return ret;
    }

    opt->pkey = HITLS_APP_LoadPrvKey(opt->outPutOpt.inKey, BSL_FORMAT_PEM, &opt->passin);
    if (opt->pkey == NULL) {
        AppPrintError("pkcs12: Load key failed.\n");
        return HITLS_APP_LOAD_KEY_FAIL;
    }

    ret = CheckCertListWithPriKey(opt->certList, opt->pkey, &opt->userCert);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    if (opt->outPutOpt.chain) {
        ret = ParseAndAddCertChain(opt);
        if (ret != HITLS_APP_SUCCESS) {
            return ret;
        }
    }

    return MakePfxAndOutput(opt);
}

static int32_t OutPutCert(const char *certType, BSL_UIO *wUio, HITLS_X509_Cert *cert)
{
    BSL_Buffer encodeCert = {};
    int32_t ret = HITLS_X509_CertGenBuff(BSL_FORMAT_PEM, cert, &encodeCert);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkcs12: encode %s failed, errCode = 0x%0x.\n", certType, ret);
        return HITLS_APP_X509_FAIL;
    }
    ret = HITLS_APP_OptWriteUio(wUio, encodeCert.data, encodeCert.dataLen, HITLS_APP_FORMAT_PEM);
    BSL_SAL_Free(encodeCert.data);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("pkcs12: Failed to print the cert\n");
        return ret;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t OutPutCerts(Pkcs12OptCtx *opt)
{
    // Output the user cert.
    int32_t ret = HITLS_PKCS12_Ctrl(opt->p12, HITLS_PKCS12_GET_ENTITY_CERT, &opt->userCert, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkcs12: Failed to get user cert, errCode = 0x%0x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    ret = OutPutCert("user cert", opt->wUio, opt->userCert);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    // only output user cert
    if (opt->importOpt.clcerts) {
        return HITLS_APP_SUCCESS;
    }

    // Output other cert and cert chain
    HITLS_PKCS12_Bag *pstCertBag = BSL_LIST_GET_FIRST(opt->p12->certList);
    while (pstCertBag != NULL) {
        ret = OutPutCert("cert chain", opt->wUio, pstCertBag->value.cert);
        if (ret != HITLS_APP_SUCCESS) {
            return ret;
        }
        pstCertBag = BSL_LIST_GET_NEXT(opt->p12->certList);
    }

    return HITLS_APP_SUCCESS;
}

static int32_t OutPutKey(Pkcs12OptCtx *opt)
{
    // Output private key
    int32_t ret = HITLS_PKCS12_Ctrl(opt->p12, HITLS_PKCS12_GET_ENTITY_KEY, &opt->pkey, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkcs12: Failed to get private key, errCode = 0x%0x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    AppKeyPrintParam param = { opt->genOpt.outFile, BSL_FORMAT_PEM, opt->cipherAlgCid, false, false};
    return HITLS_APP_PrintPrvKeyByUio(opt->wUio, opt->pkey, &param, &opt->passout);
}

static int32_t OutPutCertsAndKey(Pkcs12OptCtx *opt)
{
    int32_t ret = OutPutCerts(opt);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    return OutPutKey(opt);
}

static int32_t ParsePkcs12File(Pkcs12OptCtx *opt)
{
    BSL_UI_ReadPwdParam passParam = { "Import passwd", NULL, false };
    BSL_Buffer encPwd = { (uint8_t *)"", 0 };
    if (HITLS_APP_GetPasswd(&passParam, &opt->passin, &encPwd.data, &encPwd.dataLen) != HITLS_APP_SUCCESS) {
        return HITLS_APP_PASSWD_FAIL;
    }
    HITLS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &encPwd,
    };
    int32_t ret = HITLS_PKCS12_ParseFile(BSL_FORMAT_ASN1, opt->genOpt.inFile, &param, &opt->p12, true);
    (void)memset_s(encPwd.data, encPwd.dataLen, 0, encPwd.dataLen);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("pkcs12: Failed to parse the %s pkcs12 file, errCode = 0x%x.\n", opt->genOpt.inFile, ret);
        return HITLS_APP_X509_FAIL;
    }

    return OutPutCertsAndKey(opt);
}

static int32_t CheckParam(Pkcs12OptCtx *opt)
{
    // In all cases, the infile must exist.
    int32_t ret = CheckInFile(opt->genOpt.inFile, "in file");
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    if (opt->outPutOpt.export) {
        // In the export cases, the private key must be available.
        ret = CheckInFile(opt->outPutOpt.inKey, "private key");
        if (ret != HITLS_APP_SUCCESS) {
            return ret;
        }
        if (opt->importOpt.clcerts) {
            AppPrintError("pkcs12: Warning: -clcerts option ignored with -export\n");
        }
        if (opt->importOpt.cipherAlgName != NULL) {
            AppPrintError("pkcs12: Warning: output encryption option -%s ignored with -export\n",
                opt->importOpt.cipherAlgName);
        }
        // When adding a certificate chain, caFile must be exist.
        if (opt->outPutOpt.chain) {
            ret = CheckInFile(opt->outPutOpt.caFile, "ca file");
            if (ret != HITLS_APP_SUCCESS) {
                return ret;
            }
        } else if (opt->outPutOpt.caFile != NULL) {
            AppPrintError("pkcs12: Warning: ignoring -CAfile since -chain is not given\n");
        }
    } else {
        if (opt->outPutOpt.chain) {
            AppPrintError("pkcs12: Warning: ignoring -chain since -export is not given\n");
        }
        if (opt->outPutOpt.caFile != NULL) {
            AppPrintError("pkcs12: Warning: ignoring -CAfile since -export is not given\n");
        }
        if (opt->outPutOpt.keyPbeArg != NULL) {
            AppPrintError("pkcs12: Warning: ignoring -keypbe since -export is not given\n");
        }
        if (opt->outPutOpt.certPbeArg != NULL) {
            AppPrintError("pkcs12: Warning: ignoring -certpbe since -export is not given\n");
        }
        if (opt->outPutOpt.macAlgArg != NULL) {
            AppPrintError("pkcs12: Warning: ignoring -macalg since -export is not given\n");
        }
        if (opt->outPutOpt.name != NULL) {
            AppPrintError("pkcs12: Warning: ignoring -name since -export is not given\n");
        }
        if (opt->outPutOpt.caNameSize != 0) {
            AppPrintError("pkcs12: Warning: ignoring -caname since -export is not given\n");
        }
    }

    return CheckOutFile(opt->genOpt.outFile);
}

static void InitPkcs12OptCtx(Pkcs12OptCtx *optCtx)
{
    optCtx->pkey = NULL;
    optCtx->passin = NULL;
    optCtx->passout = NULL;
    optCtx->cipherAlgCid = CRYPT_CIPHER_AES256_CBC;
    optCtx->macAlg = BSL_CID_SHA256;
    optCtx->certPbe = BSL_CID_PBES2;
    optCtx->keyPbe = BSL_CID_PBES2;

    optCtx->p12 = NULL;
    optCtx->store = NULL;
    optCtx->certList = NULL;
    optCtx->caCertList = NULL;
    optCtx->outCertChainList = NULL;
    optCtx->userCert = NULL;
    optCtx->wUio = NULL;

    optCtx->genOpt.inFile = NULL;
    optCtx->genOpt.outFile = NULL;
    optCtx->genOpt.passInArg = NULL;
    optCtx->genOpt.passOutArg = NULL;

    optCtx->importOpt.clcerts = false;
    optCtx->importOpt.cipherAlgName = NULL;

    optCtx->outPutOpt.inKey = NULL;
    optCtx->outPutOpt.name = NULL;
    optCtx->outPutOpt.caNameSize = 0;
    optCtx->outPutOpt.caFile = NULL;
    optCtx->outPutOpt.macAlgArg = NULL;
    optCtx->outPutOpt.certPbeArg = NULL;
    optCtx->outPutOpt.keyPbeArg = NULL;
    optCtx->outPutOpt.chain = false;
    optCtx->outPutOpt.export = false;
}

static void UnInitPkcs12OptCtx(Pkcs12OptCtx *optCtx)
{
    CRYPT_EAL_PkeyFreeCtx(optCtx->pkey);
    optCtx->pkey = NULL;
    if (optCtx->passin != NULL) {
        BSL_SAL_ClearFree(optCtx->passin, strlen(optCtx->passin));
    }
    if (optCtx->passout != NULL) {
        BSL_SAL_ClearFree(optCtx->passout, strlen(optCtx->passout));
    }
    HITLS_PKCS12_Free(optCtx->p12);
    optCtx->p12 = NULL;
    HITLS_X509_StoreCtxFree(optCtx->store);
    optCtx->store = NULL;
    HITLS_X509_StoreCtxFree(optCtx->dupStore);
    optCtx->dupStore = NULL;
    BSL_LIST_FREE(optCtx->caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(optCtx->outCertChainList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_LIST_FREE(optCtx->certList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_X509_CertFree(optCtx->userCert);
    optCtx->userCert = NULL;
    BSL_UIO_Free(optCtx->wUio);
    optCtx->wUio = NULL;
    BSL_SAL_FREE(optCtx);
}

static int32_t HandlePKCS12Opt(Pkcs12OptCtx *opt)
{
    // 1.Read and Parse pass arg
    if ((HITLS_APP_ParsePasswd(opt->genOpt.passInArg, &opt->passin) != HITLS_APP_SUCCESS) ||
        (HITLS_APP_ParsePasswd(opt->genOpt.passOutArg, &opt->passout) != HITLS_APP_SUCCESS)) {
        return HITLS_APP_PASSWD_FAIL;
    }

    // 2.Create output uio
    opt->wUio = HITLS_APP_UioOpen(opt->genOpt.outFile, 'w', 0);
    if (opt->wUio == NULL) {
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(opt->wUio, true);

    return opt->outPutOpt.export ? CreatePkcs12File(opt) : ParsePkcs12File(opt);
}

// pkcs12 main function
int32_t HITLS_PKCS12Main(int argc, char *argv[])
{
    Pkcs12OptCtx *opt = BSL_SAL_Calloc(1, sizeof(Pkcs12OptCtx));
    if (opt == NULL) {
        AppPrintError("pkcs12: Failed to create pkcs12 ctx.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }

    InitPkcs12OptCtx(opt);
    int32_t ret = HITLS_APP_SUCCESS;
    do {
        ret = ParseOpt(argc, argv, opt);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        ret = CheckParam(opt);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_AES128_CTR, "provider=default", NULL, 0, NULL);
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("pkcs12: Failed to initialize the random number, errCode = 0x%x.\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        ret = HandlePKCS12Opt(opt);
    } while (false);

    UnInitPkcs12OptCtx(opt);
    CRYPT_EAL_RandDeinitEx(NULL);
    return ret;
}
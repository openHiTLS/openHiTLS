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
#include "app_verify.h"
#include <stddef.h>
#include <stdbool.h>
#include <limits.h>
#include "string.h"
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "app_function.h"
#include "bsl_list.h"
#include "app_errno.h"
#include "app_opt.h"
#include "app_print.h"
#include "app_conf.h"
#include "app_utils.h"
#include "crypt_eal_rand.h"
#include "hitls_pki_errno.h"

typedef enum OptionChoice {
    HITLS_APP_OPT_VERIFY_ERR = -1,
    HITLS_APP_OPT_VERIFY_EOF = 0,
    HITLS_APP_OPT_VERIFY_CERTS = HITLS_APP_OPT_VERIFY_EOF,
    HITLS_APP_OPT_VERIFY_HELP = 1,
    HITLS_APP_OPT_VERIFY_CAFILE,
    HITLS_APP_OPT_VERIFY_VERBOSE,
    HITLS_APP_OPT_VERIFY_NOKEYUSAGE
} HITLSOptType;

const HITLS_CmdOption g_verifyOpts[] = {
    {"help", HITLS_APP_OPT_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"nokeyusage", HITLS_APP_OPT_VERIFY_NOKEYUSAGE, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Set not to verify keyUsage"},
    {"CAfile", HITLS_APP_OPT_VERIFY_CAFILE, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Input ca file"},
    {"verbose", HITLS_APP_OPT_VERIFY_VERBOSE, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Print extra information"},
    {"certs", HITLS_APP_OPT_VERIFY_CERTS, HITLS_APP_OPT_VALUETYPE_PARAMTERS, "Input certs"},
    {NULL, 0, 0, NULL}
};

static bool g_verbose = false;
static bool g_noVerifyKeyUsage = false;

void PrintCertErr(HITLS_X509_Cert *cert)
{
    if (!g_verbose) {
        return;
    }
    BSL_Buffer subjectName = { NULL, 0 };
    if (HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SUBJECT_DN_STR, &subjectName, sizeof(BSL_Buffer)) ==
        HITLS_PKI_SUCCESS) {
        (void)AppPrintError("%s\n", subjectName.data);
        BSL_SAL_FREE(subjectName.data);
    }
}

bool CheckCertKeyUsage(HITLS_X509_Cert *cert, const char *certfile, uint32_t usage)
{
    if (g_noVerifyKeyUsage) {
        return true;
    }

    uint32_t keyUsage = 0;
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_KUSAGE, &keyUsage, sizeof(keyUsage));
    if (ret != HITLS_PKI_SUCCESS) {
        (void)AppPrintError("Failed to get the key usage of file %s, errCode = %d.\n", certfile, ret);
        return false;
    }

    // Check only if the keyusage extension is present.
    if (keyUsage == HITLS_X509_EXT_KU_NONE) {
        return true;
    }
    if ((keyUsage & usage) == 0) {
        PrintCertErr(cert);
        (void)AppPrintError("Failed to check the key usage of file %s.\n", certfile);
        return false;
    }
    return true;
}

int32_t InitVerify(HITLS_X509_StoreCtx *store, const char *cafile)
{
    int32_t depth = 20; // HITLS_X509_STORECTX_SET_PARAM_DEPTH can be set to a maximum of 20
    int32_t ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_DEPTH, &depth, sizeof(int32_t));
    if (ret != HITLS_PKI_SUCCESS) {
        (void)AppPrintError("Failed to set the maximum depth of the certificate chain, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    int64_t timeval = BSL_SAL_CurrentSysTimeGet();
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &timeval, sizeof(timeval));
    if (ret != HITLS_PKI_SUCCESS) {
        (void)AppPrintError("Failed to set time of the certificate chain, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    HITLS_X509_List *certlist = NULL;
    ret = HITLS_X509_CertParseBundleFile(BSL_FORMAT_PEM, cafile, &certlist);
    if (ret != HITLS_PKI_SUCCESS) {
        (void)AppPrintError("Failed to parse certificate <%s>, errCode = %d.\n", cafile, ret);
        return HITLS_APP_X509_FAIL;
    }
    HITLS_X509_Cert **cert = BSL_LIST_First(certlist);
    while (cert != NULL) {
        if (!CheckCertKeyUsage(*cert, cafile, HITLS_X509_EXT_KU_KEY_CERT_SIGN)) {
            ret = HITLS_APP_X509_FAIL;
            break;
        }
        ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, *cert, sizeof(HITLS_X509_Cert *));
        if (ret != HITLS_PKI_SUCCESS) {
            PrintCertErr(*cert);
            ret = HITLS_APP_X509_FAIL;
            (void)AppPrintError("Failed to add the certificate <%s> to the trust store, errCode = %d.\n", cafile, ret);
            break;
        }
        cert = BSL_LIST_Next(certlist);
    }

    BSL_LIST_FREE(certlist, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return ret;
}

static int32_t AddCertToChain(HITLS_X509_List *chain, HITLS_X509_Cert *cert)
{
    int ref;
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_LIST_AddElement(chain, cert, BSL_LIST_POS_END);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    return ret;
}

static int32_t VerifyCert(HITLS_X509_StoreCtx *storeCtx, const char *fileName)
{
    HITLS_X509_Cert *cert = HITLS_APP_LoadCert(fileName, BSL_FORMAT_PEM);
    if (cert == NULL) {
        return HITLS_APP_X509_FAIL;
    }
    const char *errStr = fileName == NULL ? "stdin" : fileName;
    if (!CheckCertKeyUsage(cert, errStr, HITLS_X509_EXT_KU_KEY_ENCIPHERMENT)) {
        HITLS_X509_CertFree(cert);
        return HITLS_APP_X509_FAIL;
    }
    HITLS_X509_List *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (chain == NULL) {
        AppPrintError("Failed to create the certificate chain from %s.\n", errStr);
        HITLS_X509_CertFree(cert);
        return HITLS_APP_X509_FAIL;
    }
    int32_t ret = AddCertToChain(chain, cert);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to add the chain from %s, errCode = %d.\n", errStr, ret);
        HITLS_X509_CertFree(cert);
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        return HITLS_APP_X509_FAIL;
    }
    ret = HITLS_X509_CertVerify(storeCtx, chain);
    if (ret != HITLS_PKI_SUCCESS) {
        PrintCertErr(cert);
        HITLS_X509_CertFree(cert);
        BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        (void)AppPrintError("error %s: verification failed, errCode = %d.\n", errStr, ret);
        return HITLS_APP_X509_FAIL;
    }
    HITLS_X509_CertFree(cert);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    (void)AppPrintError("%s: OK\n", errStr);
    return HITLS_APP_SUCCESS;
}

static int32_t VerifyCerts(HITLS_X509_StoreCtx *storeCtx, int argc, char **argv)
{
    int32_t ret = HITLS_APP_SUCCESS;
    if (argc == 0) {
        return VerifyCert(storeCtx, NULL);
    } else {
        for (int i = 0; i < argc; ++i) {
            ret = VerifyCert(storeCtx, argv[i]);
            if (ret != HITLS_APP_SUCCESS) {
                return HITLS_APP_X509_FAIL;
            }
        }
    }
    return ret;
}

static int32_t OptParse(char **cafile)
{
    HITLSOptType optType;
    int ret = HITLS_APP_SUCCESS;
    while ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_VERIFY_EOF) {
        switch (optType) {
            case HITLS_APP_OPT_VERIFY_EOF:
            case HITLS_APP_OPT_VERIFY_ERR:
                ret = HITLS_APP_OPT_UNKOWN;
                (void)AppPrintError("verify: Use -help for summary.\n");
                return ret;
            case HITLS_APP_OPT_VERIFY_HELP:
                ret = HITLS_APP_HELP;
                (void)HITLS_APP_OptHelpPrint(g_verifyOpts);
                return ret;
            case HITLS_APP_OPT_VERIFY_CAFILE:
                *cafile = HITLS_APP_OptGetValueStr();
                if (*cafile == NULL || strlen(*cafile) >= PATH_MAX) {
                    AppPrintError("The length of CA file error, range is (0, 4096).\n");
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_VERIFY_VERBOSE:
                g_verbose = true;
                break;
            case HITLS_APP_OPT_VERIFY_NOKEYUSAGE:
                g_noVerifyKeyUsage = true;
                break;
            default:
                return HITLS_APP_OPT_UNKOWN;
        }
    }
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_VerifyMain(int argc, char *argv[])
{
    HITLS_X509_StoreCtx *store = NULL;
    char *cafile = NULL;
    int32_t mainRet = HITLS_APP_SUCCESS;
    if (CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_AES128_CTR,
        "provider=default", NULL, 0, NULL) != CRYPT_SUCCESS) {
        mainRet = HITLS_APP_CRYPTO_FAIL;
        goto end;
    }
    mainRet = HITLS_APP_OptBegin(argc, argv, g_verifyOpts);
    if (mainRet != HITLS_APP_SUCCESS) {
        (void)AppPrintError("error in opt begin.\n");
        goto end;
    }
    mainRet = OptParse(&cafile);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }

    if (cafile == NULL) {
        mainRet = HITLS_APP_OPT_UNKOWN;
        (void)AppPrintError("Failed to complete the verification because the CAfile file is not obtained\n");
        goto end;
    }

    store = HITLS_X509_StoreCtxNew();
    if (store == NULL) {
        mainRet = HITLS_APP_X509_FAIL;
        (void)AppPrintError("Failed to create the store context.\n");
        goto end;
    }

    mainRet = InitVerify(store, cafile);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }

    int unParseParamNum = HITLS_APP_GetRestOptNum();
    char **unParseParam = HITLS_APP_GetRestOpt();

    mainRet = VerifyCerts(store, unParseParamNum, unParseParam);
end:
    HITLS_X509_StoreCtxFree(store);
    HITLS_APP_OptEnd();
    CRYPT_EAL_RandDeinitEx(NULL);
    return mainRet;
}
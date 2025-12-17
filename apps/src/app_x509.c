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

#include "app_x509.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <securec.h>
#include <limits.h>
#include "bsl_list.h"
#include "bsl_print.h"
#include "bsl_conf_def.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"
#include "crypt_codecskey.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_md.h"
#include "hitls_pki_errno.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_conf.h"
#include "app_opt.h"
#include "app_utils.h"
#include "app_list.h"

#define X509_DEFAULT_CERT_DAYS 30
#define X509_DEFAULT_SERIAL_SIZE 20
#define X509_DAY_SECONDS (24 * 60 * 60)
#define X509_SET_SERIAL_PREFIX "0x"
#define X509_MAX_MD_LEN 64

typedef enum {
    HITLS_APP_OPT_IN = 2,
    HITLS_APP_OPT_INFORM,
    HITLS_APP_OPT_REQ,
    HITLS_APP_OPT_OUT,
    HITLS_APP_OPT_OUTFORM,
    HITLS_APP_OPT_NOOUT,
    HITLS_APP_OPT_TEXT,
    HITLS_APP_OPT_ISSUER,
    HITLS_APP_OPT_SUBJECT,
    HITLS_APP_OPT_NAMEOPT,
    HITLS_APP_OPT_SUBJECT_HASH,
    HITLS_APP_OPT_FINGERPRINT,
    HITLS_APP_OPT_PUBKEY,
    HITLS_APP_OPT_DAYS,
    HITLS_APP_OPT_SET_SERIAL,
    HITLS_APP_OPT_EXT_FILE,
    HITLS_APP_OPT_EXT_SECTION,
    HITLS_APP_OPT_MD_ALG,
    HITLS_APP_OPT_SIGN_KEY,
    HITLS_APP_OPT_PASSIN,
    HITLS_APP_OPT_CA,
    HITLS_APP_OPT_CA_KEY,
    HITLS_APP_OPT_USERID,
} HITLSOptType;

static const HITLS_CmdOption g_x509Opts[] = {
    {"help", HITLS_APP_OPT_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    /* General opts */
    {"in", HITLS_APP_OPT_IN, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Input file"},
    {"inform", HITLS_APP_OPT_INFORM, HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, "Input format"},
    {"req", HITLS_APP_OPT_REQ, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Input is a csr, sign and output"},
    {"out", HITLS_APP_OPT_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output file"},
    {"outform", HITLS_APP_OPT_OUTFORM, HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, "Output format"},
    {"noout", HITLS_APP_OPT_NOOUT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "No Cert output "},
    /* Print opts */
    {"nameopt", HITLS_APP_OPT_NAMEOPT, HITLS_APP_OPT_VALUETYPE_STRING,
        "Cert name options: oneline|multiline|rfc2253 - def oneline"},
    {"issuer", HITLS_APP_OPT_ISSUER, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Print issuer DN"},
    {"subject", HITLS_APP_OPT_SUBJECT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Print subject DN"},
    {"hash", HITLS_APP_OPT_SUBJECT_HASH, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Print subject DN hash"},
    {"fingerprint", HITLS_APP_OPT_FINGERPRINT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Print fingerprint"},
    {"pubkey", HITLS_APP_OPT_PUBKEY, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Output the pubkey"},
    {"text", HITLS_APP_OPT_TEXT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Print x509 cert in text"},
    /* Certificate output opts */
    {"days", HITLS_APP_OPT_DAYS, HITLS_APP_OPT_VALUETYPE_POSITIVE_INT,
        "How long before the certificate expires - def 30 days"},
    {"set_serial", HITLS_APP_OPT_SET_SERIAL, HITLS_APP_OPT_VALUETYPE_STRING, "Cer serial number"},
    {"extfile", HITLS_APP_OPT_EXT_FILE, HITLS_APP_OPT_VALUETYPE_IN_FILE, "File with x509v3 extension to add"},
    {"extensions", HITLS_APP_OPT_EXT_SECTION, HITLS_APP_OPT_VALUETYPE_STRING, "Section from config file to use"},
    {"md", HITLS_APP_OPT_MD_ALG, HITLS_APP_OPT_VALUETYPE_STRING, "Any supported digest algorithm."},
    {"signkey", HITLS_APP_OPT_SIGN_KEY, HITLS_APP_OPT_VALUETYPE_IN_FILE,
        "Privkey file for self sign cert, must be PEM format"},
    {"passin", HITLS_APP_OPT_PASSIN, HITLS_APP_OPT_VALUETYPE_STRING, "Private key and cert file pass-phrase source"},
    {"CA", HITLS_APP_OPT_CA, HITLS_APP_OPT_VALUETYPE_IN_FILE, "CA certificate, must be PEM format"},
    {"CAkey", HITLS_APP_OPT_CA_KEY, HITLS_APP_OPT_VALUETYPE_IN_FILE, "CA key, must be PEM format"},
    {"userId", HITLS_APP_OPT_USERID, HITLS_APP_OPT_VALUETYPE_STRING, "sm2 userId, default is null"},
    {NULL, 0, 0, NULL},
};

typedef struct {
    bool req;
    char *inPath;
    BSL_ParseFormat inForm;
    char *outPath;
    BSL_ParseFormat outForm;
    bool noout;
    char *passInArg;
} X509GeneralOpts;

typedef struct {
    int32_t nameOpt;
    bool issuer;
    bool subject;
    bool subjectHash;
    bool text;
    int32_t mdId;
    bool fingerprint;
    bool pubKey;
} X509PrintOpts;

typedef struct {
    int32_t mdId;
    int64_t days;     // default to 30.
    uint8_t *serial;  // If this parameter is not specified, the value is generated randomly.
    uint32_t serialLen;
    char *extFile;
    char *extSection;
    char *signKeyPath;
    char *caPath;
    char *caKeyPath;
} X509CertOpts;

typedef struct {
    X509GeneralOpts generalOpts;
    X509PrintOpts printOpts;
    X509CertOpts certOpts;

    BSL_UIO *outUio;
    BSL_CONF *conf;
    HITLS_X509_Cert *cert;
    HITLS_X509_Cert *ca;
    HITLS_X509_Csr *csr;
    HITLS_X509_Ext *certExt;
    CRYPT_EAL_PkeyCtx *privKey;
    char *passin; // pass of privkey
    BSL_Buffer encodeCert;
    char *userId;
} X509OptCtx;

typedef int32_t (*X509OptHandleFunc)(X509OptCtx *);

typedef struct {
    int optType;
    X509OptHandleFunc func;
} X509OptHandleFuncMap;

typedef int32_t (*ExtConfHandleFunc)(char *cnfValue, X509OptCtx *optCtx);

typedef struct {
    char *extName;
    ExtConfHandleFunc func;
} X509ExtHandleFuncMap;

typedef struct {
    const char *nameopt;
    int32_t printFlag;
} X509NamePrintFlag;

typedef int32_t (*PrintX509Func)(const X509OptCtx *);

/**
 * 6 types of data printing:
 *    1. issuer
 *    2. subject
 *    3. hash
 *    4. fingerprint
 *    5. pubKey
 *    6. cert
 */
PrintX509Func g_printX509FuncList[] = {NULL, NULL, NULL, NULL, NULL, NULL};

#define PRINT_X509_FUNC_LIST_CNT (sizeof(g_printX509FuncList) / sizeof(PrintX509Func))

static void AppPushPrintX509Func(PrintX509Func func)
{
    for (size_t i = 0; i < PRINT_X509_FUNC_LIST_CNT; ++i) {
        if ((g_printX509FuncList[i] == NULL) || (g_printX509FuncList[i] == func)) {
            g_printX509FuncList[i] = func;
            return;
        }
    }
}

static int32_t AppPrintX509(const X509OptCtx *optCtx)
{
    int32_t ret = HITLS_APP_SUCCESS;
    for (size_t i = 0; i < PRINT_X509_FUNC_LIST_CNT; ++i) {
        if ((g_printX509FuncList[i] != NULL)) {
            ret = g_printX509FuncList[i](optCtx);
            if (ret != HITLS_APP_SUCCESS) {
                return ret;
            }
        }
    }
    return ret;
}

static void ResetPrintX509FuncList(void)
{
    for (size_t i = 0; i < PRINT_X509_FUNC_LIST_CNT; ++i) {
        g_printX509FuncList[i] = NULL;
    }
}

static int32_t PrintIssuer(const X509OptCtx *optCtx)
{
    BslList *issuer = NULL;
    int32_t ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_GET_ISSUER_DN, &issuer, sizeof(BslList *));
    if (ret != 0) {
        AppPrintError("x509: Get issuer name failed, errCode=%d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    ret = BSL_PRINT_Fmt(0, optCtx->outUio,
                        optCtx->printOpts.nameOpt == HITLS_PKI_PRINT_DN_MULTILINE ? "Issuer=\n" : "Issuer=");
    if (ret != 0) {
        AppPrintError("x509: Print issuer name failed, errCode=%d.\n", ret);
        return HITLS_APP_BSL_FAIL;
    }
    ret = HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_DNNAME, issuer, sizeof(BslList), optCtx->outUio);
    if (ret != 0) {
        AppPrintError("x509: Print issuer failed, errCode=%d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t PrintSubject(const X509OptCtx *optCtx)
{
    BslList *subject = NULL;
    int32_t ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_GET_SUBJECT_DN, &subject, sizeof(BslList *));
    if (ret != 0) {
        AppPrintError("x509: Get subject name failed, errCode=%d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    ret = BSL_PRINT_Fmt(0, optCtx->outUio,
                        optCtx->printOpts.nameOpt == HITLS_PKI_PRINT_DN_MULTILINE ? "Subject=\n" : "Subject=");
    if (ret != 0) {
        AppPrintError("x509: Print subject name failed, errCode=%d.\n", ret);
        return HITLS_APP_BSL_FAIL;
    }
    ret = HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_DNNAME, subject, sizeof(BslList), optCtx->outUio);
    if (ret != 0) {
        AppPrintError("x509: Print subject failed, errCode=%d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t PrintSubjectHash(const X509OptCtx *optCtx)
{
    BslList *subject = NULL;
    int32_t ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_GET_SUBJECT_DN, &subject, sizeof(BslList *));
    if (ret != 0) {
        AppPrintError("x509: Get subject name for hash failed, errCode=%d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    ret = HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_DNNAME_HASH, subject, sizeof(BslList), optCtx->outUio);
    if (ret != 0) {
        AppPrintError("x509: Print subject hash failed, errCode=%d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t PrintFingerPrint(const X509OptCtx *optCtx)
{
    uint8_t md[X509_MAX_MD_LEN] = {0};
    uint32_t mdLen = X509_MAX_MD_LEN;
    if (optCtx->printOpts.mdId == CRYPT_MD_SHAKE128) {
        mdLen = HITLS_APP_SHAKE128_SIZE;
    } else if (optCtx->printOpts.mdId == CRYPT_MD_SHAKE256) {
        mdLen = HITLS_APP_SHAKE256_SIZE;
    }
    int32_t ret = HITLS_X509_CertDigest(optCtx->cert, optCtx->printOpts.mdId, md, &mdLen);
    if (ret != 0) {
        AppPrintError("x509: Get cert digest failed, errCode=%d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    ret = BSL_PRINT_Fmt(0, optCtx->outUio, "%s Fingerprint=",
                        HITLS_APP_GetNameByCid(optCtx->printOpts.mdId, HITLS_APP_LIST_OPT_DGST_ALG));
    if (ret != 0) {
        AppPrintError("x509: Print fingerprint failed, errCode=%d.\n", ret);
        return HITLS_APP_BSL_FAIL;
    }
    ret = BSL_PRINT_Hex(0, true, md, mdLen, optCtx->outUio);
    if (ret != 0) {
        AppPrintError("x509: Print fingerprint failed, errCode=%d.\n", ret);
        return HITLS_APP_BSL_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t PrintCert(const X509OptCtx *optCtx)
{
    int32_t ret = HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_CERT, optCtx->cert, sizeof(HITLS_X509_Cert *), optCtx->outUio);
    if (ret != 0) {
        AppPrintError("x509: Print cert failed, errCode=%d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptErr(X509OptCtx *optCtx)
{
    (void)optCtx;
    AppPrintError("x509: Use -help for summary.\n");
    return HITLS_APP_OPT_UNKOWN;
}

static int32_t X509OptHelp(X509OptCtx *optCtx)
{
    (void)optCtx;
    HITLS_APP_OptHelpPrint(g_x509Opts);
    return HITLS_APP_HELP;
}

static int32_t X509OptIn(X509OptCtx *optCtx)
{
    optCtx->generalOpts.inPath = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptOut(X509OptCtx *optCtx)
{
    optCtx->generalOpts.outPath = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptInForm(X509OptCtx *optCtx)
{
    char *str = HITLS_APP_OptGetValueStr();
    int32_t ret =
        HITLS_APP_OptGetFormatType(str, HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, (uint32_t *)&optCtx->generalOpts.inForm);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("x509: Invalid format \"%s\" for -inform.\nx509: Use -help for summary.\n", str);
    }
    return ret;
}

static int32_t X509OptOutForm(X509OptCtx *optCtx)
{
    char *str = HITLS_APP_OptGetValueStr();
    int32_t ret =
        HITLS_APP_OptGetFormatType(str, HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, (uint32_t *)&optCtx->generalOpts.outForm);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("x509: Invalid format \"%s\" for -outform.\nx509: Use -help for summary.\n", str);
    }
    return ret;
}

static int32_t X509OptReq(X509OptCtx *optCtx)
{
    optCtx->generalOpts.req = true;
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptNoout(X509OptCtx *optCtx)
{
    optCtx->generalOpts.noout = true;
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptIssuer(X509OptCtx *optCtx)
{
    optCtx->printOpts.issuer = true;
    AppPushPrintX509Func(PrintIssuer);
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptSubject(X509OptCtx *optCtx)
{
    optCtx->printOpts.subject = true;
    AppPushPrintX509Func(PrintSubject);
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptNameOpt(X509OptCtx *optCtx)
{
    static const X509NamePrintFlag printFlags[] = {
        {"oneline", HITLS_PKI_PRINT_DN_ONELINE},
        {"multiline", HITLS_PKI_PRINT_DN_MULTILINE},
        {"rfc2253", HITLS_PKI_PRINT_DN_RFC2253},
    };
    char *str = HITLS_APP_OptGetValueStr();
    for (size_t i = 0; i < (sizeof(printFlags) / sizeof(X509NamePrintFlag)); ++i) {
        if (strcmp(printFlags[i].nameopt, str) == 0) {
            optCtx->printOpts.nameOpt = printFlags[i].printFlag;
            return HITLS_APP_SUCCESS;
        }
    }
    AppPrintError("x509: Invalid nameopt %s.\nx509: Use -help for summary.\n", str);
    return HITLS_APP_OPT_VALUE_INVALID;
}

static int32_t X509OptSubjectHash(X509OptCtx *optCtx)
{
    (void)optCtx;
    AppPushPrintX509Func(PrintSubjectHash);
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptFingerprint(X509OptCtx *optCtx)
{
    (void)optCtx;
    AppPushPrintX509Func(PrintFingerPrint);
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptText(X509OptCtx *optCtx)
{
    optCtx->printOpts.text = true;
    AppPushPrintX509Func(PrintCert);
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptPubkey(X509OptCtx *optCtx)
{
    (void)optCtx;
    optCtx->printOpts.pubKey = true;
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptMdId(X509OptCtx *optCtx)
{
    optCtx->certOpts.mdId = HITLS_APP_GetCidByName(HITLS_APP_OptGetValueStr(), HITLS_APP_LIST_OPT_DGST_ALG);
    optCtx->printOpts.mdId = optCtx->certOpts.mdId;
    return optCtx->certOpts.mdId == BSL_CID_UNKNOWN ? HITLS_APP_OPT_VALUE_INVALID : HITLS_APP_SUCCESS;
}

static int32_t X509OptDays(X509OptCtx *optCtx)
{
    int32_t ret = HITLS_APP_OptGetUint32(HITLS_APP_OptGetValueStr(), (uint32_t *)&optCtx->certOpts.days);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("x509: Invalid days.\nx509: Use -help for summary.\n");
    }
    return ret;
}

static int32_t X509OptSetSerial(X509OptCtx *optCtx)
{
    char *str = HITLS_APP_OptGetValueStr();

    int32_t ret = HITLS_APP_HexToByte(str, 1, &optCtx->certOpts.serial, &optCtx->certOpts.serialLen);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("x509: Invalid serial: %s.\n", str);
    }
    return ret;
}

static int32_t X509OptExtFile(X509OptCtx *optCtx)
{
    optCtx->certOpts.extFile = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptExtSection(X509OptCtx *optCtx)
{
    optCtx->certOpts.extSection = HITLS_APP_OptGetValueStr();
    if (strlen(optCtx->certOpts.extSection) > BSL_CONF_SEC_SIZE) {
        AppPrintError("x509: Invalid extensions, size should less than %d.\n", BSL_CONF_SEC_SIZE);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptSignKey(X509OptCtx *optCtx)
{
    optCtx->certOpts.signKeyPath = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptPassin(X509OptCtx *optCtx)
{
    optCtx->generalOpts.passInArg = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptCa(X509OptCtx *optCtx)
{
    optCtx->certOpts.caPath = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t X509OptCaKey(X509OptCtx *optCtx)
{
    optCtx->certOpts.caKeyPath = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t X509UserId(X509OptCtx *optCtx)
{
    optCtx->userId = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static const X509OptHandleFuncMap g_x509OptHandleFuncMap[] = {
    {HITLS_APP_OPT_ERR, X509OptErr},
    {HITLS_APP_OPT_HELP, X509OptHelp},
    {HITLS_APP_OPT_IN, X509OptIn},
    {HITLS_APP_OPT_INFORM, X509OptInForm},
    {HITLS_APP_OPT_REQ, X509OptReq},
    {HITLS_APP_OPT_OUT, X509OptOut},
    {HITLS_APP_OPT_OUTFORM, X509OptOutForm},
    {HITLS_APP_OPT_NOOUT, X509OptNoout},
    {HITLS_APP_OPT_ISSUER, X509OptIssuer},
    {HITLS_APP_OPT_SUBJECT, X509OptSubject},
    {HITLS_APP_OPT_NAMEOPT, X509OptNameOpt},
    {HITLS_APP_OPT_SUBJECT_HASH, X509OptSubjectHash},
    {HITLS_APP_OPT_FINGERPRINT, X509OptFingerprint},
    {HITLS_APP_OPT_PUBKEY, X509OptPubkey},
    {HITLS_APP_OPT_TEXT, X509OptText},
    {HITLS_APP_OPT_MD_ALG, X509OptMdId},
    {HITLS_APP_OPT_DAYS, X509OptDays},
    {HITLS_APP_OPT_SET_SERIAL, X509OptSetSerial},
    {HITLS_APP_OPT_EXT_FILE, X509OptExtFile},
    {HITLS_APP_OPT_EXT_SECTION, X509OptExtSection},
    {HITLS_APP_OPT_SIGN_KEY, X509OptSignKey},
    {HITLS_APP_OPT_PASSIN, X509OptPassin},
    {HITLS_APP_OPT_CA, X509OptCa},
    {HITLS_APP_OPT_CA_KEY, X509OptCaKey},
    {HITLS_APP_OPT_USERID, X509UserId},
};

static int32_t ParseX509Opt(int argc, char *argv[], X509OptCtx *optCtx)
{
    int32_t ret = HITLS_APP_OptBegin(argc, argv, g_x509Opts);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_APP_OptEnd();
        AppPrintError("error in opt begin.\n");
        return ret;
    }

    int optType = HITLS_APP_OPT_ERR;
    while ((ret == HITLS_APP_SUCCESS) && ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF)) {
        for (size_t i = 0; i < (sizeof(g_x509OptHandleFuncMap) / sizeof(g_x509OptHandleFuncMap[0])); ++i) {
            if (optType == g_x509OptHandleFuncMap[i].optType) {
                ret = g_x509OptHandleFuncMap[i].func(optCtx);
                break;
            }
        }
    }
    // Obtain the number of parameters that cannot be parsed in the current version,
    // and print the error information and help list.
    if ((ret == HITLS_APP_SUCCESS) && (HITLS_APP_GetRestOptNum() != 0)) {
        AppPrintError("x509: Extra arguments given.\nx509: Use -help for summary.\n");
        ret = HITLS_APP_OPT_UNKOWN;
    }
    HITLS_APP_OptEnd();
    return ret;
}

static int32_t GetCertPubkeyEncodeBuff(
    HITLS_X509_Cert *cert, BSL_ParseFormat format, bool isComplete, BSL_Buffer *encode)
{
    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &pubKey, 0);
    if (ret != 0) {
        AppPrintError("x509: Get pubKey from cert failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    ret = CRYPT_EAL_EncodePubKeyBuffInternal(pubKey, format, CRYPT_PUBKEY_SUBKEY, isComplete, encode);
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("x509: Encode pubKey failed, errCode = %d.\n", ret);
        return HITLS_APP_ENCODE_KEY_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

/**
 * RFC 5280:
 * section 4.1
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *    algorithm AlgorithmIdentifier,
 *    subjectPublicKey BIT STRING
 * }
 * AlgorithmIdentifier ::= SEQUENCE { ... }
 *
 * section 4.2.1.2
 * (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the value of the
 *     BIT STRING subjectPublicKey (excluding the tag, length, and number of unused bits).
 */
static int32_t GetCertKid(HITLS_X509_Cert *cert, BSL_ParseFormat format, BSL_Buffer *buff)
{
    // 1. Get the encode value of algotithm and subjectPublicKey.
    BSL_Buffer info = {0};
    int32_t ret = GetCertPubkeyEncodeBuff(cert, format, false, &info);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    // 2. Skip the algorithm
    uint8_t *enc = info.data;
    uint32_t encLen = info.dataLen;
    uint32_t vLen = 0;
    ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, &enc, &encLen, &vLen);
    if (ret != 0) {
        AppPrintError("x509: Decode pubKey failed, errCode = %d.\n", ret);
        ret = HITLS_APP_DECODE_FAIL;
        goto EXIT;
    }
    enc += vLen;
    encLen -= vLen;

    // 3. Skip the tag, length and unusedBits of bitstring
    ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_BITSTRING, &enc, &encLen, &vLen);
    if (ret != 0) {
        AppPrintError("x509: Decode pubKey failed, errCode = %d.\n", ret);
        ret = HITLS_APP_DECODE_FAIL;
        goto EXIT;
    }
    enc += 1;  // 1: skip the unusedBits of bitstring
    encLen -= 1;

    // 4. sha1
    buff->data = BSL_SAL_Malloc(20);  // 20: CRYPT_SHA1_DIGESTSIZE
    if (buff->data == NULL) {
        AppPrintError("x509: Allocate memory for kid failed.\n");
        ret = HITLS_APP_MEM_ALLOC_FAIL;
        goto EXIT;
    }
    buff->dataLen = 20;  // 20: CRYPT_SHA1_DIGESTSIZE
    ret = CRYPT_EAL_Md(CRYPT_MD_SHA1, enc, encLen, buff->data, &buff->dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(buff->data);
        buff->dataLen = 0;
        AppPrintError("x509: Failed to calculate the kid, errCode = %d.\n", ret);
        ret = HITLS_APP_CRYPTO_FAIL;
        goto EXIT;
    }
    ret = HITLS_APP_SUCCESS;
EXIT:
    BSL_SAL_Free(info.data);
    return ret;
}

static int32_t LoadConf(X509OptCtx *optCtx)
{
    if (optCtx->certOpts.extFile == NULL || optCtx->certOpts.extSection == NULL) {
        return HITLS_APP_SUCCESS;
    }
    optCtx->conf = BSL_CONF_New(BSL_CONF_DefaultMethod());
    if (optCtx->conf == NULL) {
        AppPrintError("x509: New conf failed.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    int32_t ret = BSL_CONF_Load(optCtx->conf, optCtx->certOpts.extFile);
    if (ret != 0) {
        BSL_CONF_Free(optCtx->conf);
        optCtx->conf = NULL;
        AppPrintError("x509: Load extfile %s failed, errCode = %d.\n", optCtx->certOpts.extFile, ret);
        return HITLS_APP_CONF_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t LoadRelatedFiles(X509OptCtx *optCtx)
{
    // Load and verify csr
    optCtx->csr = HITLS_APP_LoadCsr(optCtx->generalOpts.inPath, optCtx->generalOpts.inForm);
    if (optCtx->csr == NULL) {
        AppPrintError("x509: Load csr failed\n");
        return HITLS_APP_LOAD_CSR_FAIL;
    }
    int32_t ret;
    if (optCtx->userId != NULL) {
        ret = HITLS_X509_CsrCtrl(optCtx->csr, HITLS_X509_SET_VFY_SM2_USER_ID, optCtx->userId, strlen(optCtx->userId));
        if (ret != 0) {
            AppPrintError("x509: set userId failed, errCode = %d.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
    }

    ret = HITLS_X509_CsrVerify(optCtx->csr);
    if (ret != 0) {
        AppPrintError("x509: Verify csr failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    if (HITLS_APP_ParsePasswd(optCtx->generalOpts.passInArg, &optCtx->passin) != HITLS_APP_SUCCESS) {
        return HITLS_APP_PASSWD_FAIL;
    }

    // Load private key
    if (optCtx->certOpts.signKeyPath != NULL) {
        optCtx->privKey = HITLS_APP_LoadPrvKey(optCtx->certOpts.signKeyPath, BSL_FORMAT_PEM, &optCtx->passin);
    } else if (optCtx->certOpts.caKeyPath != NULL) {
        optCtx->privKey = HITLS_APP_LoadPrvKey(optCtx->certOpts.caKeyPath, BSL_FORMAT_PEM, &optCtx->passin);
    }
    if (optCtx->privKey == NULL) {
        AppPrintError("x509: Load signkey or cakey failed.\n");
        return HITLS_APP_LOAD_KEY_FAIL;
    }
    if (optCtx->userId != NULL) {
        ret = CRYPT_EAL_PkeyCtrl(optCtx->privKey, CRYPT_CTRL_SET_SM2_USER_ID, optCtx->userId, strlen(optCtx->userId));
        if (ret != 0) {
            AppPrintError("x509: set userId failed, errCode = %d.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
    }
    // Load ca
    if (optCtx->certOpts.caPath != NULL) {
        optCtx->ca = HITLS_APP_LoadCert(optCtx->certOpts.caPath, BSL_FORMAT_PEM);
        if (optCtx->ca == NULL) {
            AppPrintError("x509: Load ca failed\n");
            return HITLS_APP_LOAD_CERT_FAIL;
        }
        CRYPT_EAL_PkeyCtx *pubKey = NULL;
        ret = HITLS_X509_CertCtrl(optCtx->ca, HITLS_X509_GET_PUBKEY, &pubKey, 0);
        if (ret != 0) {
            AppPrintError("x509: Get pubKey from ca failed, errCode = %d.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
        ret = CRYPT_EAL_PkeyPairCheck(pubKey, optCtx->privKey);
        CRYPT_EAL_PkeyFreeCtx(pubKey);
        if (ret != 0) {
            AppPrintError("x509: CA public key and CA private key do not match, errCode = %d.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
    }

    return LoadConf(optCtx);
}

static int32_t SetSerial(X509OptCtx *optCtx)
{
    int32_t ret;
    if (optCtx->certOpts.serial == NULL) {
        optCtx->certOpts.serial = BSL_SAL_Malloc(X509_DEFAULT_SERIAL_SIZE);
        if (optCtx->certOpts.serial == NULL) {
            AppPrintError("x509: Allocate serial memory failed.\n");
            return HITLS_APP_MEM_ALLOC_FAIL;
        }
        optCtx->certOpts.serialLen = X509_DEFAULT_SERIAL_SIZE;
        if ((ret = CRYPT_EAL_RandbytesEx(NULL, optCtx->certOpts.serial, optCtx->certOpts.serialLen)) != 0) {
            BSL_SAL_FREE(optCtx->certOpts.serial);
            AppPrintError("x509: Generate serial number failed, errCode = %d.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
    }
    ret = HITLS_X509_CertCtrl(
        optCtx->cert, HITLS_X509_SET_SERIALNUM, optCtx->certOpts.serial, optCtx->certOpts.serialLen);
    if (ret != 0) {
        AppPrintError("x509: Set serial number failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t SetValidity(X509OptCtx *optCtx)
{
    int64_t startTime = BSL_SAL_CurrentSysTimeGet();
    if (startTime == 0) {
        AppPrintError("x509: Get system time failed.\n");
        return HITLS_APP_SAL_FAIL;
    }
    if (optCtx->certOpts.days > (INT64_MAX - startTime) / X509_DAY_SECONDS) {
        AppPrintError("x509: The sum of the current time and -days %lld outside integer range.\n", optCtx->certOpts.days);
        return HITLS_APP_SAL_FAIL;
    }
    int64_t endTime = startTime + optCtx->certOpts.days * X509_DAY_SECONDS;
    if (endTime >= 253402272000) {  // 253402272000: utctime of 10000-01-01 00:00:00
        AppPrintError("x509: The end time of cert is greatter than 9999 years.\n");
        return HITLS_APP_INVALID_ARG;
    }

    BSL_TIME start = {0};
    BSL_TIME end = {0};
    if (BSL_SAL_UtcTimeToDateConvert(startTime, &start) != 0 || BSL_SAL_UtcTimeToDateConvert(endTime, &end) != 0) {
        AppPrintError("x509: Time convert failed.\n");
        return HITLS_APP_SAL_FAIL;
    }

    int32_t ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_SET_BEFORE_TIME, &start, sizeof(BSL_TIME));
    if (ret != 0) {
        AppPrintError("x509: Set start time failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_SET_AFTER_TIME, &end, sizeof(BSL_TIME));
    if (ret != 0) {
        AppPrintError("x509: Set end time failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t SetCertDn(X509OptCtx *optCtx)
{
    BslList *subject = NULL;
    int32_t ret = HITLS_X509_CsrCtrl(optCtx->csr, HITLS_X509_GET_SUBJECT_DN, &subject, sizeof(BslList *));
    if (ret != 0) {
        AppPrintError("x509: Get subject from csr failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_SET_SUBJECT_DN, subject, sizeof(BslList));
    if (ret != 0) {
        AppPrintError("x509: Set subject failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    BslList *issuer = subject;
    if (optCtx->ca != NULL) {
        ret = HITLS_X509_CertCtrl(optCtx->ca, HITLS_X509_GET_SUBJECT_DN, &issuer, sizeof(BslList *));
        if (ret != 0) {
            AppPrintError("x509: Get subject from ca failed, errCode = %d.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
    }
    ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_SET_ISSUER_DN, issuer, sizeof(BslList));
    if (ret != 0) {
        AppPrintError("x509: Set issuer failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CopyExtensionsFromCsr(X509OptCtx *optCtx)
{
    int32_t ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_SET_CSR_EXT, optCtx->csr, 0);
    if (ret == HITLS_X509_ERR_ATTR_NOT_FOUND) {
        return HITLS_APP_SUCCESS;
    }
    if (ret != 0) {
        AppPrintError("x509: Copy csr extensions failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    int32_t version = HITLS_X509_VERSION_3;
    ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_SET_VERSION, &version, sizeof(version));
    if (ret != 0) {
        AppPrintError("x509: Set cert version failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t X509SetBasicConstraints(HITLS_X509_ExtBCons *bCons, X509OptCtx *optCtx)
{
    int32_t ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_EXT_SET_BCONS, bCons, sizeof(HITLS_X509_ExtBCons));
    if (ret != 0) {
        AppPrintError("x509: Set basicConstraints failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t X509SetKeyUsage(HITLS_X509_ExtKeyUsage *ku, X509OptCtx *optCtx)
{
    int32_t ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_EXT_SET_KUSAGE, ku, sizeof(HITLS_X509_ExtKeyUsage));
    if (ret != 0) {
        AppPrintError("x509: Set keyUsage failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t X509SetExtendKeyUsage(HITLS_X509_ExtExKeyUsage *exku, X509OptCtx *optCtx)
{
    int32_t ret =
        HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_EXT_SET_EXKUSAGE, exku, sizeof(HITLS_X509_ExtExKeyUsage));
    if (ret != 0) {
        AppPrintError("x509: Set extendKeyUsage failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t X509SetSubjectAltName(HITLS_X509_ExtSan *san, X509OptCtx *optCtx)
{
    int32_t ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_EXT_SET_SAN, san, sizeof(HITLS_X509_ExtSan));
    if (ret != 0) {
        AppPrintError("x509: Set subjectAltName failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t X509SetSubjectKeyIdentifier(HITLS_X509_ExtSki *ski, HITLS_X509_Cert *cert, bool needFree)
{
    int32_t ret = GetCertKid(cert, BSL_FORMAT_ASN1, &ski->kid);
    if (ret != 0) {
        return ret;
    }

    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SKI, ski, sizeof(HITLS_X509_ExtSki));
    if (needFree) {
        BSL_SAL_FREE(ski->kid.data);
    }
    if (ret != 0) {
        AppPrintError("x509: Set subjectKeyIdentifier failed, errCode = %d.\n", ret);
        BSL_SAL_FREE(ski->kid.data);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t SetSelfSignedCertAki(HITLS_CFG_ExtAki *cfgAki, HITLS_X509_Cert *cert)
{
    // [keyid] set ski, kid is from csr or self-generated
    // [keyid:always] set ski and aki, aki = ski
    bool isSkiExist;
    HITLS_X509_ExtAki aki = cfgAki->aki;
    HITLS_X509_ExtSki ski = {0};

    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_CHECK_SKI, &isSkiExist, sizeof(bool));
    if (ret != 0) {
        AppPrintError("x509: Check cert subjectKeyIdentifier failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    if (isSkiExist && (cfgAki->flag & HITLS_CFG_X509_EXT_AKI_KID_ALWAYS) == 0) {
        // Ski has been set and the cnf does not contain 'always'.
        return HITLS_APP_SUCCESS;
    }

    if (isSkiExist) {
        // get ski from cert
        ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SKI, &ski, sizeof(HITLS_X509_ExtSki));
        if (ret != 0) {
            AppPrintError("x509: Get cert subjectKeyIdentifier failed, errCode = %d.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
    } else {
        // generate ski and set ski
        ret = X509SetSubjectKeyIdentifier(&ski, cert, false);
        if (ret != 0) {
            return ret;
        }
        if ((cfgAki->flag & HITLS_CFG_X509_EXT_AKI_KID_ALWAYS) == 0) {
            BSL_SAL_Free(ski.kid.data);
            return ret;
        }
    }

    aki.kid = ski.kid;
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_AKI, &aki, sizeof(HITLS_X509_ExtAki));
    if (!isSkiExist) {
        BSL_SAL_Free(ski.kid.data);
    }
    if (ret != 0) {
        AppPrintError("x509: Set cert authorityKeyIdentifier failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t SetNonSelfSignedCertAki(HITLS_CFG_ExtAki *cfgAki, X509OptCtx *optCtx)
{
    // [keyid] set ski and aki, aki.kid is from issuer cert
    HITLS_X509_ExtSki caSki = {0};
    HITLS_X509_ExtAki aki = cfgAki->aki;
    bool isSkiExist;
    int32_t ret = HITLS_X509_CertCtrl(optCtx->ca, HITLS_X509_EXT_GET_SKI, &caSki, sizeof(HITLS_X509_ExtSki));
    if (ret != 0) {
        AppPrintError("x509: Get issuer keyId failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    aki.kid = caSki.kid;
    ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_EXT_SET_AKI, &aki, sizeof(HITLS_X509_ExtAki));
    if (ret != 0) {
        AppPrintError("x509: Set non-self-signed cert authorityKeyIdentifier failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_EXT_CHECK_SKI, &isSkiExist, sizeof(bool));
    if (ret != 0) {
        AppPrintError("x509: Check cert subjectKeyIdentifier failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    if (isSkiExist) {
        return HITLS_APP_SUCCESS;
    }

    return X509SetSubjectKeyIdentifier(&caSki, optCtx->cert, true);
}

static int32_t X509SetAuthKeyIdentifier(HITLS_CFG_ExtAki *cfgAki, X509OptCtx *optCtx)
{
    if (optCtx->ca == NULL) {
        return SetSelfSignedCertAki(cfgAki, optCtx->cert);
    } else {
        return SetNonSelfSignedCertAki(cfgAki, optCtx);
    }
}

static int32_t X509ProcExt(BslCid cid, void *val, X509OptCtx *optCtx)
{
    if (val == NULL) {
        return HITLS_APP_INTERNAL_EXCEPTION;
    }
    switch (cid) {
        case BSL_CID_CE_BASICCONSTRAINTS:
            return X509SetBasicConstraints(val, optCtx);
        case BSL_CID_CE_KEYUSAGE:
            return X509SetKeyUsage(val, optCtx);
        case BSL_CID_CE_EXTKEYUSAGE:
            return X509SetExtendKeyUsage(val, optCtx);
        case BSL_CID_CE_AUTHORITYKEYIDENTIFIER:
            return X509SetAuthKeyIdentifier(val, optCtx);
        case BSL_CID_CE_SUBJECTKEYIDENTIFIER:
            return X509SetSubjectKeyIdentifier(val, optCtx->cert, true);
        case BSL_CID_CE_SUBJECTALTNAME:
            return X509SetSubjectAltName(val, optCtx);
        default:
            AppPrintError("x509: Unsupported extension: %d.\n", (int32_t)cid);
            return HITLS_APP_X509_FAIL;
    }
}

static int32_t SetCertExtensionsByConf(X509OptCtx *optCtx)
{
    if (optCtx->conf == NULL) {
        return HITLS_APP_SUCCESS;
    }
    int32_t ret =
        HITLS_APP_CONF_ProcExt(optCtx->conf, optCtx->certOpts.extSection, (ProcExtCallBack)X509ProcExt, optCtx);
    if (ret != HITLS_APP_SUCCESS && ret != HITLS_APP_NO_EXT) {
        return ret;
    }
    if (ret == HITLS_APP_NO_EXT) {
        return HITLS_APP_SUCCESS;
    }
    int32_t version = HITLS_X509_VERSION_3;
    ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_SET_VERSION, &version, sizeof(version));
    if (ret != 0) {
        AppPrintError("x509: Set cert version failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t SetPubKey(X509OptCtx *optCtx)
{
    int32_t ret;
    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    if (optCtx->ca == NULL) {
        // self-signed cert
        pubKey = optCtx->privKey;
    } else {
        // non self-signed cert
        ret = HITLS_X509_CsrCtrl(optCtx->csr, HITLS_X509_GET_PUBKEY, &pubKey, 0);
        if (ret != 0) {
            AppPrintError("x509: Get pubKey from csr failed, errCode = %d.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
    }
    ret = HITLS_X509_CertCtrl(optCtx->cert, HITLS_X509_SET_PUBKEY, pubKey, 0);
    if (optCtx->ca != NULL) {
        CRYPT_EAL_PkeyFreeCtx(pubKey);
    }
    if (ret != 0) {
        AppPrintError("x509: Set public key failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t SetCertCont(X509OptCtx *optCtx)
{
    // Pubkey must be set first, which will be used in set extensions
    int32_t ret = SetPubKey(optCtx);
    if (ret != 0) {
        return ret;
    }

    ret = CopyExtensionsFromCsr(optCtx);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    ret = SetCertExtensionsByConf(optCtx);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    ret = SetSerial(optCtx);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    ret = SetValidity(optCtx);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    return SetCertDn(optCtx);
}

static int32_t GenCert(X509OptCtx *optCtx)
{
    int32_t ret = LoadRelatedFiles(optCtx);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    optCtx->cert = HITLS_X509_CertNew();
    if (optCtx->cert == NULL) {
        AppPrintError("x509: Failed to new a cert.\n");
        return HITLS_APP_X509_FAIL;
    }

    ret = SetCertCont(optCtx);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    ret = HITLS_X509_CertSign(optCtx->certOpts.mdId, optCtx->privKey, NULL, optCtx->cert);
    if (ret != 0) {
        AppPrintError("x509: sign cert failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    ret = HITLS_X509_CertGenBuff(optCtx->generalOpts.outForm, optCtx->cert, &optCtx->encodeCert);
    if (ret != 0) {
        AppPrintError("x509: encode cert failed, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    return HITLS_APP_SUCCESS;
}

static int32_t LoadCert(X509OptCtx *optCtx)
{
    optCtx->cert = HITLS_APP_LoadCert(optCtx->generalOpts.inPath, optCtx->generalOpts.inForm);
    if (optCtx->cert == NULL) {
        return HITLS_APP_LOAD_CERT_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t OutputPubkey(X509OptCtx *optCtx)
{
    if (!optCtx->printOpts.pubKey) {
        return HITLS_APP_SUCCESS;
    }
    BSL_Buffer encodePubkey = {0};
    int32_t ret = GetCertPubkeyEncodeBuff(optCtx->cert, BSL_FORMAT_PEM, true, &encodePubkey);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    uint32_t writeLen = 0;
    ret = BSL_UIO_Write(optCtx->outUio, encodePubkey.data, encodePubkey.dataLen, &writeLen);
    BSL_SAL_Free(encodePubkey.data);
    if (ret != 0 || writeLen != encodePubkey.dataLen) {
        AppPrintError("x509: write pubKey failed, errCode = %d, writeLen = %u.\n", ret, writeLen);
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t X509Output(X509OptCtx *optCtx)
{
    int32_t ret;
    optCtx->outUio = HITLS_APP_UioOpen(optCtx->generalOpts.outPath, 'w', 0);
    if (optCtx->outUio == NULL) {
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(optCtx->outUio, true);
    // Output cert info
    if (optCtx->printOpts.issuer || optCtx->printOpts.subject || optCtx->printOpts.text) {
        ret = HITLS_PKI_PrintCtrl(HITLS_PKI_SET_PRINT_FLAG, (void *)&optCtx->printOpts.nameOpt, sizeof(int32_t), NULL);
        if (ret != 0) {
            AppPrintError("x509: Set DN print flag failed, errCode = %d.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
    }
    ret = AppPrintX509(optCtx);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    // Output pubKey
    ret = OutputPubkey(optCtx);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    // Output cert der/pem
    if (optCtx->generalOpts.noout) {
        return HITLS_APP_SUCCESS;
    }
    if (optCtx->encodeCert.data == NULL) {
        ret = HITLS_X509_CertGenBuff(optCtx->generalOpts.outForm, optCtx->cert, &optCtx->encodeCert);
        if (ret != 0) {
            AppPrintError("x509: encode cert failed, errCode = %d.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
    }
    uint32_t writeLen = 0;
    ret = BSL_UIO_Write(optCtx->outUio, optCtx->encodeCert.data, optCtx->encodeCert.dataLen, &writeLen);
    if (ret != 0 || writeLen != optCtx->encodeCert.dataLen) {
        AppPrintError("x509: write cert failed, errCode = %d, writeLen = %u.\n", ret, writeLen);
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static bool CheckGenCertOpt(X509OptCtx *optCtx)
{
    if (optCtx->certOpts.caPath != NULL) {
        if (optCtx->certOpts.signKeyPath != NULL) {
            AppPrintError("x509: Cannot use both -signkey and -CA.\n");
            return false;
        }
    } else {
        if (optCtx->certOpts.caKeyPath != NULL) {
            if (optCtx->certOpts.signKeyPath != NULL) {
                AppPrintError("x509: Cannot use both -CAkey and -signkey.\n");
                return false;
            } else {
                AppPrintError("x509: Should use both -CA and -CAkey.\n");
                return false;
            }
        }
    }
    if (optCtx->certOpts.signKeyPath == NULL && optCtx->certOpts.caKeyPath == NULL) {
        AppPrintError("x509: We need a private key to genetate cert, use -signkey or -CAkey.\n");
        return false;
    }
    if (optCtx->certOpts.extFile != NULL && optCtx->certOpts.extSection == NULL) {
        AppPrintError("x509: Warning: ignoring -extFile since -extensions is not given.\n");
        optCtx->certOpts.extFile = NULL;
    }
    if (optCtx->certOpts.extFile == NULL && optCtx->certOpts.extSection != NULL) {
        AppPrintError("x509: Warning: ignoring -extensions since -extFile is not given.\n");
        optCtx->certOpts.extSection = NULL;
    }
    return true;
}

static bool CheckOpt(X509OptCtx *optCtx)
{
    if (optCtx->generalOpts.req) {  // new cert
        return CheckGenCertOpt(optCtx);
    } else {
        if (optCtx->certOpts.signKeyPath != NULL || optCtx->certOpts.caKeyPath != NULL ||
            optCtx->certOpts.caPath != NULL) {
            AppPrintError("x509: Warning: ignoring -signkey, -CA, -CAkey since -req is not given.\n");
            optCtx->certOpts.caKeyPath = NULL;
            optCtx->certOpts.signKeyPath = NULL;
            optCtx->certOpts.caPath = NULL;
        }
        if (optCtx->certOpts.serialLen != 0) {
            AppPrintError("x509: Warning: ignoring -set_serial since -req is not given.\n");
            BSL_SAL_FREE(optCtx->certOpts.serial);
            optCtx->certOpts.serialLen = 0;
        }
        if (optCtx->certOpts.extFile != NULL || optCtx->certOpts.extSection != NULL) {
            AppPrintError("x509: Warning: ignoring -extfile or -extensions since -req is not given.\n");
            optCtx->certOpts.extFile = NULL;
            optCtx->certOpts.extSection = NULL;
        }
    }
    return true;
}

int32_t HandleX509Opt(int argc, char *argv[], X509OptCtx *optCtx)
{
    int32_t ret = ParseX509Opt(argc, argv, optCtx);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (!CheckOpt(optCtx)) {
        return HITLS_APP_OPT_TYPE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static void InitX509OptCtx(X509OptCtx *optCtx)
{
    optCtx->generalOpts.inForm = BSL_FORMAT_PEM;
    optCtx->generalOpts.outForm = BSL_FORMAT_PEM;
    optCtx->generalOpts.req = false;
    optCtx->generalOpts.noout = false;
    optCtx->printOpts.nameOpt = HITLS_PKI_PRINT_DN_ONELINE;
    optCtx->certOpts.days = X509_DEFAULT_CERT_DAYS;
    optCtx->certOpts.mdId = CRYPT_MD_SHA256;
    optCtx->printOpts.mdId = CRYPT_MD_SHA1;
}

static void UnInitX509OptCtx(X509OptCtx *optCtx)
{
    BSL_UIO_Free(optCtx->outUio);
    optCtx->outUio = NULL;
    BSL_CONF_Free(optCtx->conf);
    optCtx->conf = NULL;
    HITLS_X509_CertFree(optCtx->cert);
    optCtx->cert = NULL;
    HITLS_X509_CertFree(optCtx->ca);
    optCtx->ca = NULL;
    HITLS_X509_CsrFree(optCtx->csr);
    optCtx->csr = NULL;
    CRYPT_EAL_PkeyFreeCtx(optCtx->privKey);
    optCtx->privKey = NULL;
    BSL_SAL_FREE(optCtx->certOpts.serial);
    BSL_SAL_FREE(optCtx->encodeCert.data);
    if (optCtx->passin != NULL) {
        BSL_SAL_ClearFree(optCtx->passin, strlen(optCtx->passin));
    }
}

// x509 main function
int32_t HITLS_X509Main(int argc, char *argv[])
{
    ResetPrintX509FuncList();
    X509OptCtx optCtx = {0};
    InitX509OptCtx(&optCtx);
    int32_t ret = HITLS_APP_SUCCESS;
    do {
        // Init rand: Generate a serial number or signature certificate.
        ret = HandleX509Opt(argc, argv, &optCtx);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }

        if (optCtx.generalOpts.req) {
            if (CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_AES128_CTR,
                "provider=default", NULL, 0, NULL) != CRYPT_SUCCESS) {
                ret = HITLS_APP_CRYPTO_FAIL;
                break;
            }
            ret = GenCert(&optCtx);
        } else {
            ret = LoadCert(&optCtx);
        }
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }

        ret = X509Output(&optCtx);
    } while (false);
    UnInitX509OptCtx(&optCtx);
    CRYPT_EAL_RandDeinitEx(NULL);
    return ret;
}

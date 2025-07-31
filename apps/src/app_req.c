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

#include "app_req.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <securec.h>
#include <linux/limits.h>
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_list.h"
#include "bsl_ui.h"
#include "app_utils.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "crypt_errno.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_rand.h"
#include "hitls_csr_local.h"
#include "hitls_pki_errno.h"

#define HITLS_APP_REQ_SECTION "req"
#define HITLS_APP_REQ_EXTENSION_SECTION "req_extensions"

typedef enum {
    HITLS_REQ_APP_OPT_NEW = 2,
    HITLS_REQ_APP_OPT_VERIFY,
    HITLS_REQ_APP_OPT_MDALG,
    HITLS_REQ_APP_OPT_SUBJ,
    HITLS_REQ_APP_OPT_KEY,
    HITLS_REQ_APP_OPT_KEYFORM,
    HITLS_REQ_APP_OPT_PASSIN,
    HITLS_REQ_APP_OPT_PASSOUT,
    HITLS_REQ_APP_OPT_NOOUT,
    HITLS_REQ_APP_OPT_TEXT,
    HITLS_REQ_APP_OPT_CONFIG,
    HITLS_REQ_APP_OPT_IN,
    HITLS_REQ_APP_OPT_INFORM,
    HITLS_REQ_APP_OPT_OUT,
    HITLS_REQ_APP_OPT_OUTFORM,
} HITLSOptType;

const HITLS_CmdOption g_reqOpts[] = {
    {"help", HITLS_APP_OPT_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"new", HITLS_REQ_APP_OPT_NEW, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "New request"},
    {"verify", HITLS_REQ_APP_OPT_VERIFY, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Verify self-signature on the request"},
    {"mdalg", HITLS_REQ_APP_OPT_MDALG, HITLS_APP_OPT_VALUETYPE_STRING, "Any supported digest"},
    {"subj", HITLS_REQ_APP_OPT_SUBJ, HITLS_APP_OPT_VALUETYPE_STRING, "Set or modify subject of request or cert"},
    {"key", HITLS_REQ_APP_OPT_KEY, HITLS_APP_OPT_VALUETYPE_STRING, "Key for signing, and to include unless -in given"},
    {"keyform", HITLS_REQ_APP_OPT_KEYFORM, HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, "Input format - DER or PEM"},
    {"passin", HITLS_REQ_APP_OPT_PASSIN, HITLS_APP_OPT_VALUETYPE_STRING, "Private key and certificate password source"},
    {"passout", HITLS_REQ_APP_OPT_PASSOUT, HITLS_APP_OPT_VALUETYPE_STRING, "Output file pass phrase source"},
    {"noout", HITLS_REQ_APP_OPT_NOOUT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Do not output REQ"},
    {"text", HITLS_REQ_APP_OPT_TEXT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Text form of request"},
    {"config", HITLS_REQ_APP_OPT_CONFIG, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Request template file"},
    {"in", HITLS_REQ_APP_OPT_IN, HITLS_APP_OPT_VALUETYPE_IN_FILE, "X.509 request input file (default stdin)"},
    {"inform", HITLS_REQ_APP_OPT_INFORM, HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, "Input format - DER or PEM"},
    {"out", HITLS_REQ_APP_OPT_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output file"},
    {"outform", HITLS_REQ_APP_OPT_OUTFORM, HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, "Output format - DER or PEM"},
    {NULL},
};

typedef struct {
    char *inFilePath;
    BSL_ParseFormat inFormat;
    bool verify;
} ReqGeneralOptions;

typedef struct {
    bool new;
    char *configFilePath;
    bool text;
    char *subj;
} ReqCertOptions;

typedef struct {
    char *keyFilePath;
    BSL_ParseFormat keyFormat;
    char *passInArg;
    char *passOutArg;
    int32_t mdalgId;
} ReqKeysAndSignOptions;

typedef struct {
    char *outFilePath;
    BSL_ParseFormat outFormat;
    bool noout;
} ReqOutputOptions;

typedef struct {
    ReqGeneralOptions genOpt;
    ReqCertOptions certOpt;
    ReqKeysAndSignOptions keyAndSignOpt;
    ReqOutputOptions outPutOpt;
    char *passin;
    char *passout;
    HITLS_X509_Csr *csr;
    CRYPT_EAL_PkeyCtx *pkey;
    BSL_UIO *wUio;
    BSL_Buffer encode;
    HITLS_X509_Ext *ext;
    BSL_CONF *conf;
} ReqOptCtx;

typedef int32_t (*ReqOptHandleFunc)(ReqOptCtx *);

typedef struct {
    int optType;
    ReqOptHandleFunc func;
} ReqOptHandleTable;

static int32_t ReqOptErr(ReqOptCtx *optCtx)
{
    (void)optCtx;
    AppPrintError("req: Use -help for summary.\n");
    return HITLS_APP_OPT_UNKOWN;
}

static int32_t ReqOptHelp(ReqOptCtx *optCtx)
{
    (void)optCtx;
    HITLS_APP_OptHelpPrint(g_reqOpts);
    return HITLS_APP_HELP;
}

static int32_t ReqOptNew(ReqOptCtx *optCtx)
{
    optCtx->certOpt.new = true;
    return HITLS_APP_SUCCESS;
}

static int32_t ReqOptVerify(ReqOptCtx *optCtx)
{
    optCtx->genOpt.verify = true;
    return HITLS_APP_SUCCESS;
}

static int32_t ReqOptMdAlg(ReqOptCtx *optCtx)
{
    return HITLS_APP_GetAndCheckHashOpt(HITLS_APP_OptGetValueStr(), &optCtx->keyAndSignOpt.mdalgId);
}

static int32_t ReqOptSubj(ReqOptCtx *optCtx)
{
    optCtx->certOpt.subj = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t ReqOptKey(ReqOptCtx *optCtx)
{
    optCtx->keyAndSignOpt.keyFilePath = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t ReqOptKeyFormat(ReqOptCtx *optCtx)
{
    return HITLS_APP_OptGetFormatType(HITLS_APP_OptGetValueStr(), HITLS_APP_OPT_VALUETYPE_FMT_ANY,
        &optCtx->keyAndSignOpt.keyFormat);
}

static int32_t ReqOptPassin(ReqOptCtx *optCtx)
{
    optCtx->keyAndSignOpt.passInArg = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t ReqOptPassout(ReqOptCtx *optCtx)
{
    optCtx->keyAndSignOpt.passOutArg = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t ReqOptNoout(ReqOptCtx *optCtx)
{
    optCtx->outPutOpt.noout = true;
    return HITLS_APP_SUCCESS;
}

static int32_t ReqOptText(ReqOptCtx *optCtx)
{
    optCtx->certOpt.text = true;
    return HITLS_APP_SUCCESS;
}

static int32_t ReqOptConfig(ReqOptCtx *optCtx)
{
    optCtx->certOpt.configFilePath = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t ReqOptIn(ReqOptCtx *optCtx)
{
    optCtx->genOpt.inFilePath = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t ReqOptInFormat(ReqOptCtx *optCtx)
{
    return HITLS_APP_OptGetFormatType(HITLS_APP_OptGetValueStr(), HITLS_APP_OPT_VALUETYPE_FMT_PEMDER,
        &optCtx->genOpt.inFormat);
}

static int32_t ReqOptOut(ReqOptCtx *optCtx)
{
    optCtx->outPutOpt.outFilePath = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t ReqOptOutFormat(ReqOptCtx *optCtx)
{
    return HITLS_APP_OptGetFormatType(HITLS_APP_OptGetValueStr(), HITLS_APP_OPT_VALUETYPE_FMT_PEMDER,
        &optCtx->outPutOpt.outFormat);
}

static const ReqOptHandleTable g_reqOptHandleTable[] = {
    {HITLS_APP_OPT_ERR, ReqOptErr},
    {HITLS_APP_OPT_HELP, ReqOptHelp},
    {HITLS_REQ_APP_OPT_NEW, ReqOptNew},
    {HITLS_REQ_APP_OPT_VERIFY, ReqOptVerify},
    {HITLS_REQ_APP_OPT_MDALG, ReqOptMdAlg},
    {HITLS_REQ_APP_OPT_SUBJ, ReqOptSubj},
    {HITLS_REQ_APP_OPT_KEY, ReqOptKey},
    {HITLS_REQ_APP_OPT_KEYFORM, ReqOptKeyFormat},
    {HITLS_REQ_APP_OPT_PASSIN, ReqOptPassin},
    {HITLS_REQ_APP_OPT_PASSOUT, ReqOptPassout},
    {HITLS_REQ_APP_OPT_NOOUT, ReqOptNoout},
    {HITLS_REQ_APP_OPT_TEXT, ReqOptText},
    {HITLS_REQ_APP_OPT_CONFIG, ReqOptConfig},
    {HITLS_REQ_APP_OPT_IN, ReqOptIn},
    {HITLS_REQ_APP_OPT_INFORM, ReqOptInFormat},
    {HITLS_REQ_APP_OPT_OUT, ReqOptOut},
    {HITLS_REQ_APP_OPT_OUTFORM, ReqOptOutFormat},
};

static int32_t ParseReqOpt(ReqOptCtx *optCtx)
{
    int32_t ret = HITLS_APP_SUCCESS;
    int optType = HITLS_APP_OPT_ERR;
    while ((ret == HITLS_APP_SUCCESS) && ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF)) {
        for (size_t i = 0; i < (sizeof(g_reqOptHandleTable) / sizeof(g_reqOptHandleTable[0])); ++i) {
            if (optType == g_reqOptHandleTable[i].optType) {
                ret = g_reqOptHandleTable[i].func(optCtx);
                break;
            }
        }
    }
    // Obtain the number of parameters that cannot be parsed in the current version,
    // and print the error inFormation and help list.
    if ((ret == HITLS_APP_SUCCESS) && (HITLS_APP_GetRestOptNum() != 0)) {
        AppPrintError("Extra arguments given.\n");
        AppPrintError("req: Use -help for summary.\n");
        ret = HITLS_APP_OPT_UNKOWN;
    }

    if ((HITLS_APP_ParsePasswd(optCtx->keyAndSignOpt.passInArg, &optCtx->passin) != HITLS_APP_SUCCESS) ||
        (HITLS_APP_ParsePasswd(optCtx->keyAndSignOpt.passOutArg, &optCtx->passout) != HITLS_APP_SUCCESS)) {
        return HITLS_APP_PASSWD_FAIL;
    }
    return ret;
}

static int32_t ReqLoadPrvKey(ReqOptCtx *optCtx)
{
    if (optCtx->keyAndSignOpt.keyFilePath == NULL) {
        optCtx->pkey = HITLS_APP_GenRsaPkeyCtx(2048);  // default 2048
        if (optCtx->pkey == NULL) {
            return HITLS_APP_CRYPTO_FAIL;
        }
        // default write to private.pem
        int32_t ret = HITLS_APP_PrintPrvKey(
            optCtx->pkey, "private.pem", BSL_FORMAT_PEM, CRYPT_CIPHER_AES256_CBC, &optCtx->passout);
        return ret;
    }

    optCtx->pkey =
        HITLS_APP_LoadPrvKey(optCtx->keyAndSignOpt.keyFilePath, optCtx->keyAndSignOpt.keyFormat, &optCtx->passin);
    if (optCtx->pkey == NULL) {
        return HITLS_APP_LOAD_KEY_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t SetRequestedExt(ReqOptCtx *optCtx)
{
    if (optCtx->ext == NULL) {
        return HITLS_APP_SUCCESS;
    }
    BslList *attrList = NULL;
    int32_t ret = HITLS_X509_CsrCtrl(optCtx->csr, HITLS_X509_CSR_GET_ATTRIBUTES, &attrList, sizeof(BslList *));
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("req: Failed to get attr the csr, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    HITLS_X509_Attrs *attrs = NULL;
    ret = HITLS_X509_CsrCtrl(optCtx->csr, HITLS_X509_CSR_GET_ATTRIBUTES, &attrs, sizeof(HITLS_X509_Attrs *));
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("req: Failed to get attrs from the csr, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    ret = HITLS_X509_AttrCtrl(attrs, HITLS_X509_ATTR_SET_REQUESTED_EXTENSIONS, optCtx->ext, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("req: Failed to set attr the csr, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t GetSignMdId(ReqOptCtx *optCtx)
{
    CRYPT_PKEY_AlgId id = CRYPT_EAL_PkeyGetId(optCtx->pkey);
    int32_t mdalgId = optCtx->keyAndSignOpt.mdalgId;
    if (mdalgId == CRYPT_MD_MAX) {
        if (id == CRYPT_PKEY_ED25519) {
            mdalgId = CRYPT_MD_SHA512;
        } else if ((id == CRYPT_PKEY_SM2)) {
            mdalgId = CRYPT_MD_SM3;
        } else {
            mdalgId = CRYPT_MD_SHA256;
        }
    }
    return mdalgId;
}

static int32_t ProcSanExt(BslCid cid, void *val, void *ctx)
{
    HITLS_X509_Ext *ext = ctx;
    switch (cid) {
        case BSL_CID_CE_SUBJECTALTNAME:
            return HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_SAN, val, sizeof(HITLS_X509_ExtSan));
        default:
            return HITLS_APP_CONF_FAIL;
    }
}

static int32_t ParseConf(ReqOptCtx *optCtx)
{
    if (!optCtx->certOpt.new || (optCtx->certOpt.configFilePath == NULL)) {
        return HITLS_APP_SUCCESS;
    }
    optCtx->ext = HITLS_X509_ExtNew(HITLS_X509_EXT_TYPE_CSR);
    if (optCtx->ext == NULL) {
        (void)AppPrintError("req: Failed to create the ext context.\n");
        return HITLS_APP_X509_FAIL;
    }
    optCtx->conf = BSL_CONF_New(BSL_CONF_DefaultMethod());
    if (optCtx->conf == NULL) {
        (void)AppPrintError("req: Failed to create profile context.\n");
        return HITLS_APP_CONF_FAIL;
    }
    char extSectionStr[BSL_CONF_SEC_SIZE + 1] = {0};
    uint32_t extSectionStrLen = sizeof(extSectionStr);
    int32_t ret = BSL_CONF_Load(optCtx->conf, optCtx->certOpt.configFilePath);
    if (ret != BSL_SUCCESS) {
        (void)AppPrintError("req: Failed to load the config file %s.\n", optCtx->certOpt.configFilePath);
        return HITLS_APP_CONF_FAIL;
    }
    ret = BSL_CONF_GetString(optCtx->conf, HITLS_APP_REQ_SECTION, HITLS_APP_REQ_EXTENSION_SECTION,
        extSectionStr, &extSectionStrLen);
    if (ret == BSL_CONF_VALUE_NOT_FOUND) {
        return HITLS_APP_SUCCESS;
    } else if (ret != BSL_SUCCESS) {
        (void)AppPrintError("req: Failed to get req_extensions, config file %s.\n", optCtx->certOpt.configFilePath);
        return HITLS_APP_CONF_FAIL;
    }
    ret = HITLS_APP_CONF_ProcExt(optCtx->conf, extSectionStr, ProcSanExt, optCtx->ext);
    if (ret == HITLS_APP_NO_EXT) {
        return HITLS_APP_SUCCESS;
    } else if (ret != BSL_SUCCESS) {
        (void)AppPrintError("req: Failed to parse SAN from config file %s.\n", optCtx->certOpt.configFilePath);
        return HITLS_APP_CONF_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t ReqGen(ReqOptCtx *optCtx)
{
    if (optCtx->certOpt.subj == NULL) {
        AppPrintError("req: -subj must be included when -new is used.\n");
        return HITLS_APP_INVALID_ARG;
    }
    if (optCtx->genOpt.inFilePath != NULL) {
        AppPrintError("req: ignore -in option when generating csr.\n");
    }

    int32_t ret = ReqLoadPrvKey(optCtx);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    optCtx->csr = HITLS_X509_CsrNew();
    if (optCtx->csr == NULL) {
        (void)AppPrintError("req: Failed to create the csr context.\n");
        return HITLS_APP_X509_FAIL;
    }

    ret = HITLS_X509_CsrCtrl(optCtx->csr, HITLS_X509_SET_PUBKEY, optCtx->pkey, sizeof(CRYPT_EAL_PkeyCtx *));
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("req: Failed to set public the csr, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    if (ParseConf(optCtx) != HITLS_APP_SUCCESS) {
        return HITLS_APP_CONF_FAIL;
    }

    ret = HITLS_APP_CFG_ProcDnName(optCtx->certOpt.subj, HiTLS_AddSubjDnNameToCsr, optCtx->csr);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("req: Failed to set subject name the csr, errCode = %d.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    ret = SetRequestedExt(optCtx);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = HITLS_X509_CsrSign(GetSignMdId(optCtx), optCtx->pkey, NULL, optCtx->csr);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("req: Failed to sign the csr, errCode = %x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    ret = HITLS_X509_CsrGenBuff(optCtx->outPutOpt.outFormat, optCtx->csr, &optCtx->encode);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("req: Failed to generate the csr, errCode = %x.\n", ret);
    }

    return ret;
}

static int32_t ReqLoad(ReqOptCtx *optCtx)
{
    optCtx->csr = HITLS_APP_LoadCsr(optCtx->genOpt.inFilePath, optCtx->genOpt.inFormat);
    if (optCtx->csr == NULL) {
        return HITLS_APP_X509_FAIL;
    }

    return HITLS_APP_SUCCESS;
}

static void ReqVerify(ReqOptCtx *optCtx)
{
    int32_t ret = HITLS_X509_CsrVerify(optCtx->csr);
    if (ret == HITLS_PKI_SUCCESS) {
        (void)AppPrintError("req: verify ok.\n");
    } else {
        (void)AppPrintError("req: verify failure, errCode = %d.\n", ret);
    }
}

static int32_t ReqOutput(ReqOptCtx *optCtx)
{
    if (optCtx->outPutOpt.noout && !optCtx->certOpt.text) {
        return HITLS_APP_SUCCESS;
    }

    optCtx->wUio = HITLS_APP_UioOpen(optCtx->outPutOpt.outFilePath, 'w', 0);
    if (optCtx->wUio == NULL) {
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(optCtx->wUio, true);

    int32_t ret;
    if (optCtx->certOpt.text) {
        ret = HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_CSR, optCtx->csr, sizeof(HITLS_X509_Csr *), optCtx->wUio);
        if (ret != HITLS_PKI_SUCCESS) {
            AppPrintError("x509: print csr failed, errCode = %d.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
    }

    if (optCtx->outPutOpt.noout) {
        return HITLS_APP_SUCCESS;
    }
    if (optCtx->encode.data == NULL) {
        ret = HITLS_X509_CsrGenBuff(optCtx->outPutOpt.outFormat, optCtx->csr, &optCtx->encode);
        if (ret != 0) {
            AppPrintError("x509: encode csr failed, errCode = %d.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
    }
    uint32_t writeLen = 0;
    ret = BSL_UIO_Write(optCtx->wUio, optCtx->encode.data, optCtx->encode.dataLen, &writeLen);
    if (ret != 0 || writeLen != optCtx->encode.dataLen) {
        AppPrintError("req: write csr failed, errCode = %d, writeLen = %ld.\n", ret, writeLen);
        return HITLS_APP_UIO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static void InitReqOptCtx(ReqOptCtx *optCtx)
{
    optCtx->genOpt.inFormat = BSL_FORMAT_PEM;
    optCtx->keyAndSignOpt.keyFormat = BSL_FORMAT_UNKNOWN;
    optCtx->outPutOpt.outFormat = BSL_FORMAT_PEM;
}

static void UnInitReqOptCtx(ReqOptCtx *optCtx)
{
    if (optCtx->passin != NULL) {
         BSL_SAL_ClearFree(optCtx->passin, strlen(optCtx->passin));
    }
    if (optCtx->passout != NULL) {
        BSL_SAL_ClearFree(optCtx->passout, strlen(optCtx->passout));
    }
    HITLS_X509_CsrFree(optCtx->csr);
    CRYPT_EAL_PkeyFreeCtx(optCtx->pkey);
    BSL_UIO_Free(optCtx->wUio);
    BSL_SAL_FREE(optCtx->encode.data);
    HITLS_X509_ExtFree(optCtx->ext);
    BSL_CONF_Free(optCtx->conf);
}

// req main function
int32_t HITLS_ReqMain(int argc, char *argv[])
{
    ReqOptCtx optCtx = {0};
    InitReqOptCtx(&optCtx);
    int32_t ret = HITLS_APP_SUCCESS;
    do {
        ret = HITLS_APP_OptBegin(argc, argv, g_reqOpts);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("req: error in opt begin.\n");
            break;
        }
        if (CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_AES128_CTR,
            "provider=default", NULL, 0, NULL) != CRYPT_SUCCESS) {
            AppPrintError("req: failed to init rand.\n");
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }

        ret = ParseReqOpt(&optCtx);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }

        if (optCtx.certOpt.new) {
            ret = ReqGen(&optCtx);
        } else {
            ret = ReqLoad(&optCtx);
        }

        if (ret != HITLS_APP_SUCCESS) {
            break;
        }

        if (optCtx.genOpt.verify) {
            ReqVerify(&optCtx);
        }

        ret = ReqOutput(&optCtx);
    } while (false);
    CRYPT_EAL_RandDeinitEx(NULL);
    UnInitReqOptCtx(&optCtx);
    HITLS_APP_OptEnd();
    return ret;
}

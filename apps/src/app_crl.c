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

#include "app_crl.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <linux/limits.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_types.h"
#include "hitls_pki_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "app_opt.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_conf.h"
#include "app_utils.h"

#define MAX_CRLFILE_SIZE (256 * 1024)
#define DEFAULT_CERT_SIZE 1024U
typedef enum OptionChoice {
    HITLS_APP_OPT_CRL_ERR = -1,
    HITLS_APP_OPT_CRL_EOF = 0,
    // The first opt of each option is help and is equal to 1. The following opt can be customized.
    HITLS_APP_OPT_CRL_HELP = 1,
    HITLS_APP_OPT_CRL_IN,
    HITLS_APP_OPT_CRL_NOOUT,
    HITLS_APP_OPT_CRL_OUT,
    HITLS_APP_OPT_CRL_NEXTUPDATE,
    HITLS_APP_OPT_CRL_CAFILE,
    HITLS_APP_OPT_CRL_INFORM,
    HITLS_APP_OPT_CRL_OUTFORM,
} HITLSOptType;

const HITLS_CmdOption g_crlOpts[] = {
    {"help", HITLS_APP_OPT_CRL_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"in", HITLS_APP_OPT_CRL_IN, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Input file"},
    {"noout", HITLS_APP_OPT_CRL_NOOUT, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "No CRL output "},
    {"out", HITLS_APP_OPT_CRL_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE, "Output file"},
    {"nextupdate", HITLS_APP_OPT_CRL_NEXTUPDATE, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Print CRL nextupdate"},
    {"CAfile", HITLS_APP_OPT_CRL_CAFILE, HITLS_APP_OPT_VALUETYPE_IN_FILE, "Verify CRL using CAFile"},
    {"inform", HITLS_APP_OPT_CRL_INFORM, HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, "Input crl file format"},
    {"outform", HITLS_APP_OPT_CRL_OUTFORM, HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, "Output crl file format"},
    {NULL}
};

typedef struct {
    BSL_ParseFormat inform;
    BSL_ParseFormat outform;
    char *infile;
    char *cafile;
    char *outfile;
    bool noout;
    bool nextupdate;
    BSL_UIO *uio;
} CrlInfo;

static int32_t DecodeCertFile(uint8_t *infileBuf, uint64_t infileBufLen, HITLS_X509_Cert **tmp)
{
    // The input parameter inBufLen is uint64_t, and PEM_decode requires bufLen of uint32_t. Check whether the
    // conversion precision is lost.
    uint32_t bufLen = (uint32_t)infileBufLen;
    if ((uint64_t)bufLen != infileBufLen) {
        return HITLS_APP_DECODE_FAIL;
    }

    BSL_Buffer encode = {infileBuf, bufLen};
    return HITLS_X509_CertParseBuff(BSL_FORMAT_UNKNOWN, &encode, tmp);
}

static int32_t VerifyCrlFile(const char *caFile, const HITLS_X509_Crl *crl)
{
    BSL_UIO *readUio = HITLS_APP_UioOpen(caFile, 'r', 0);
    if (readUio == NULL) {
        AppPrintError("Failed to open the file <%s>, No such file or directory\n", caFile);
        return HITLS_APP_UIO_FAIL;
    }
    uint8_t *caFileBuf = NULL;
    uint64_t caFileBufLen = 0;
    int32_t ret = HITLS_APP_OptReadUio(readUio, &caFileBuf, &caFileBufLen, MAX_CRLFILE_SIZE);
    BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
    BSL_UIO_Free(readUio);
    if (ret != HITLS_APP_SUCCESS || caFileBuf == NULL || caFileBufLen == 0) {
        BSL_SAL_FREE(caFileBuf);
        AppPrintError("Failed to read CAfile from <%s>\n", caFile);
        return HITLS_APP_UIO_FAIL;
    }
    HITLS_X509_Cert *cert = NULL;
    ret = DecodeCertFile(caFileBuf, caFileBufLen, &cert);  // Decode the CAfile content.
    BSL_SAL_FREE(caFileBuf);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_X509_CertFree(cert);
        AppPrintError("Failed to decode the CAfile <%s>\n", caFile);
        return HITLS_APP_DECODE_FAIL;
    }

    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    // Obtaining the Public Key of the CA Certificate
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &pubKey, sizeof(CRYPT_EAL_PkeyCtx *));
    HITLS_X509_CertFree(cert);
    if (pubKey == NULL) {
        AppPrintError("Failed to getting CRL issuer certificate\n");
        return HITLS_APP_X509_FAIL;
    }
    ret = HITLS_X509_CrlVerify(pubKey, crl);
    CRYPT_EAL_PkeyFreeCtx((CRYPT_EAL_PkeyCtx *)pubKey);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("The verification result: failed\n");
        return HITLS_APP_CERT_VERIFY_FAIL;
    }
    AppPrintError("The verification result: OK\n");
    return HITLS_APP_SUCCESS;
}


static int32_t GetCrlInfoByStd(uint8_t **infileBuf, uint64_t *infileBufLen)
{
    (void)AppPrintError("Please enter the key content\n");
    size_t crlDataCapacity = DEFAULT_CERT_SIZE;
    void *crlData = BSL_SAL_Calloc(crlDataCapacity, sizeof(uint8_t));
    if (crlData == NULL) { return HITLS_APP_MEM_ALLOC_FAIL; }
    size_t crlDataSize = 0;
    bool isMatchCrlData = false;
    while (true) {
        char *buf = NULL;
        size_t bufLen = 0;
        ssize_t readLen = getline(&buf, &bufLen, stdin);
        if (readLen <= 0) {
            BSL_SAL_FREE(buf);
            (void)AppPrintError("Failed to obtain the standard input.\n");
            break;
        }
        if ((crlDataSize + readLen) > MAX_CRLFILE_SIZE) {
            BSL_SAL_FREE(buf);
            BSL_SAL_FREE(crlData);
            AppPrintError("The stdin supports a maximum of %zu bytes.\n", MAX_CRLFILE_SIZE);
            return HITLS_APP_STDIN_FAIL;
        }
        if ((crlDataSize + readLen) > crlDataCapacity) {
            // If the space is insufficient, expand the capacity by twice.
            size_t newCrlDataCapacity = crlDataCapacity << 1;
            /* If the space is insufficient for two times of capacity expansion,
            expand the capacity based on the actual length. */
            if ((crlDataSize + readLen) > newCrlDataCapacity) {
                newCrlDataCapacity = crlDataSize + readLen;
            }
            crlData = ExpandingMem(crlData, newCrlDataCapacity, crlDataCapacity);
            crlDataCapacity = newCrlDataCapacity;
        }
        if (memcpy_s(crlData + crlDataSize, crlDataCapacity - crlDataSize, buf, readLen) != 0) {
            BSL_SAL_FREE(buf);
            BSL_SAL_FREE(crlData);
            return HITLS_APP_SECUREC_FAIL;
        }
        crlDataSize += readLen;
        if (strcmp(buf, "-----BEGIN X509 CRL-----\n") == 0) {
            isMatchCrlData = true;
        }
        if (isMatchCrlData && (strcmp(buf, "-----END X509 CRL-----\n") == 0)) {
            BSL_SAL_FREE(buf);
            break;
        }
        BSL_SAL_FREE(buf);
    }
    *infileBuf = crlData;
    *infileBufLen = crlDataSize;
    return (crlDataSize > 0) ? HITLS_APP_SUCCESS : HITLS_APP_STDIN_FAIL;
}

static int32_t GetCrlInfoByFile(char *infile, uint8_t **infileBuf, uint64_t *infileBufLen)
{
    int32_t readRet = HITLS_APP_SUCCESS;
    BSL_UIO *uio = HITLS_APP_UioOpen(infile, 'r', 0);
    if (uio == NULL) {
        AppPrintError("Failed to open the CRL from <%s>, No such file or directory\n", infile);
        return HITLS_APP_UIO_FAIL;
    }
    readRet = HITLS_APP_OptReadUio(uio, infileBuf, infileBufLen, MAX_CRLFILE_SIZE);
    BSL_UIO_SetIsUnderlyingClosedByUio(uio, true);
    BSL_UIO_Free(uio);
    if (readRet != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to read the CRL from <%s>\n", infile);
        return readRet;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t GetCrlInfo(char *infile, uint8_t **infileBuf, uint64_t *infileBufLen)
{
    int32_t getRet = HITLS_APP_SUCCESS;
    if (infile == NULL) {
        getRet = GetCrlInfoByStd(infileBuf, infileBufLen);
    } else {
        getRet = GetCrlInfoByFile(infile, infileBuf, infileBufLen);
    }
    return getRet;
}

static int32_t GetAndDecCRL(CrlInfo *outInfo, uint8_t **infileBuf, uint64_t *infileBufLen, HITLS_X509_Crl **crl)
{
    int32_t ret = GetCrlInfo(outInfo->infile, infileBuf, infileBufLen);  // Obtaining the CRL File Content
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to obtain the content of the CRL file.\n");
        return ret;
    }
    BSL_Buffer buff = {*infileBuf, *infileBufLen};
    ret = HITLS_X509_CrlParseBuff(outInfo->inform, &buff, crl);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("Failed to decode the CRL file.\n");
        return HITLS_APP_DECODE_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t OutCrlFileInfo(BSL_UIO *uio, HITLS_X509_Crl *crl, uint32_t format)
{
    BSL_Buffer encode = {0};
    int32_t ret = HITLS_X509_CrlGenBuff(format, crl, &encode);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("Failed to convert the CRL.\n");
        return HITLS_APP_ENCODE_FAIL;
    }

    ret = HITLS_APP_OptWriteUio(uio, encode.data, encode.dataLen, HITLS_APP_FORMAT_PEM);
    BSL_SAL_FREE(encode.data);
    if (ret != HITLS_APP_SUCCESS) {
        (void)AppPrintError("Failed to print the CRL content\n");
    }
    return ret;
}

static int32_t PrintNextUpdate(BSL_UIO *uio, HITLS_X509_Crl *crl)
{
    BSL_TIME time = {0};
    int32_t ret = HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_AFTER_TIME, &time, sizeof(BSL_TIME));
    if (ret != HITLS_PKI_SUCCESS && ret != HITLS_X509_ERR_CRL_NEXTUPDATE_UNEXIST) {
        (void)AppPrintError("Failed to get character string\n");
        return HITLS_APP_X509_FAIL;
    }

    ret = HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_NEXTUPDATE, &time, sizeof(BSL_TIME), uio);
    if (ret != HITLS_PKI_SUCCESS) {
        (void)AppPrintError("Failed to get print string\n");
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t OptParse(CrlInfo *outInfo)
{
    HITLSOptType optType;
    int ret = HITLS_APP_SUCCESS;

    while ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_CRL_EOF) {
        switch (optType) {
            case HITLS_APP_OPT_CRL_EOF:
            case HITLS_APP_OPT_CRL_ERR:
                ret = HITLS_APP_OPT_UNKOWN;
                (void)AppPrintError("crl: Use -help for summary.\n");
                return ret;
            case HITLS_APP_OPT_CRL_HELP:
                ret = HITLS_APP_HELP;
                (void)HITLS_APP_OptHelpPrint(g_crlOpts);
                return ret;
            case HITLS_APP_OPT_CRL_OUT:
                outInfo->outfile = HITLS_APP_OptGetValueStr();
                if (outInfo->outfile == NULL || strlen(outInfo->outfile) >= PATH_MAX) {
                    AppPrintError("The length of outfile error, range is (0, 4096).\n");
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_CRL_NOOUT:
                outInfo->noout = true;
                break;
            case HITLS_APP_OPT_CRL_IN:
                outInfo->infile = HITLS_APP_OptGetValueStr();
                if (outInfo->infile == NULL || strlen(outInfo->infile) >= PATH_MAX) {
                    AppPrintError("The length of input file error, range is (0, 4096).\n");
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_CRL_CAFILE:
                outInfo->cafile = HITLS_APP_OptGetValueStr();
                if (outInfo->cafile == NULL || strlen(outInfo->cafile) >= PATH_MAX) {
                    AppPrintError("The length of CA file error, range is (0, 4096).\n");
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_CRL_NEXTUPDATE:
                outInfo->nextupdate = true;
                break;
            case HITLS_APP_OPT_CRL_INFORM:
                if (HITLS_APP_OptGetFormatType(HITLS_APP_OptGetValueStr(), HITLS_APP_OPT_VALUETYPE_FMT_PEMDER,
                    &outInfo->inform) != HITLS_APP_SUCCESS) {
                    AppPrintError("The informat of crl file error.\n");
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_CRL_OUTFORM:
                if (HITLS_APP_OptGetFormatType(HITLS_APP_OptGetValueStr(), HITLS_APP_OPT_VALUETYPE_FMT_PEMDER,
                    &outInfo->outform) != HITLS_APP_SUCCESS) {
                    AppPrintError("The format of crl file error.\n");
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            default:
                return HITLS_APP_OPT_UNKOWN;
        }
    }
    return HITLS_APP_SUCCESS;
}

int32_t  HITLS_CrlMain(int argc, char *argv[])
{
    CrlInfo crlInfo = {0, BSL_FORMAT_PEM, NULL, NULL, NULL, false, false, NULL};
    HITLS_X509_Crl *crl = NULL;
    uint8_t *infileBuf = NULL;
    uint64_t infileBufLen = 0;
    int32_t mainRet = HITLS_APP_OptBegin(argc, argv, g_crlOpts);
    if (mainRet != HITLS_APP_SUCCESS) {
        (void)AppPrintError("error in opt begin.\n");
        goto end;
    }
    mainRet = OptParse(&crlInfo);
    if (mainRet != HITLS_APP_SUCCESS) {
        goto end;
    }
    int unParseParamNum = HITLS_APP_GetRestOptNum();
    if (unParseParamNum != 0) {  // The input parameters are not completely parsed.
        (void)AppPrintError("Extra arguments given.\n");
        (void)AppPrintError("crl: Use -help for summary.\n");
        mainRet = HITLS_APP_OPT_UNKOWN;
        goto end;
    }
    mainRet = GetAndDecCRL(&crlInfo, &infileBuf, &infileBufLen, &crl);
    if (mainRet != HITLS_APP_SUCCESS) {
        HITLS_X509_CrlFree(crl);
        goto end;
    }
    crlInfo.uio = HITLS_APP_UioOpen(crlInfo.outfile, 'w', 0);
    if (crlInfo.uio == NULL) {
        (void)AppPrintError("Failed to open the standard output.");
        mainRet = HITLS_APP_UIO_FAIL;
        goto end;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(crlInfo.uio, !(crlInfo.outfile == NULL));

    if (crlInfo.nextupdate == true) {
        mainRet = PrintNextUpdate(crlInfo.uio, crl);
        if (mainRet != HITLS_APP_SUCCESS) {
            goto end;
        }
    }
    if (crlInfo.cafile != NULL) {
        mainRet = VerifyCrlFile(crlInfo.cafile, crl);
        if (mainRet != HITLS_APP_SUCCESS) {
            goto end;
        }
    }
    if (crlInfo.noout == false) {
        mainRet = OutCrlFileInfo(crlInfo.uio, crl, crlInfo.outform);
    }

end:
    HITLS_X509_CrlFree(crl);
    BSL_SAL_FREE(infileBuf);
    BSL_UIO_Free(crlInfo.uio);
    HITLS_APP_OptEnd();
    return mainRet;
}

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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "app_opt.h"
#include "app_print.h"
#include "bsl_uio.h"
#include "uio_abstraction.h"
#include "app_errno.h"
#include "crypt_errno.h"
#include "app_req.h"
#include "app_function.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "sal_file.h"
#include "hitls_pki_csr.h"
#include "hitls_pki_errno.h"
#include "hitls_csr_local.h"

/* END_HEADER */

static void RestoreStdoutByFd(int savedStdoutFd)
{
    if (savedStdoutFd < 0) {
        return;
    }
    /*
     * req may print directly to process stdout when no output file is given.
     * Restore stdout between iterations so later command cases and test logs do
     * not reuse redirected state, and keep the recovery independent of /dev/tty.
     */
    fflush(stdout);
    (void)dup2(savedStdoutFd, STDOUT_FILENO);
    clearerr(stdout);
}

static void SplitArgs(char *str, char **result, int *count) {
    char *token;
    token = strtok(str, " ");
    while (token != NULL) {
        result[*count] = token;
        (*count)++;
        token = strtok(NULL, " ");
    }
}

/**
 * @test UT_HITLS_APP_REQ_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_REQ_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_REQ_TC001(char *arg, int expect)
{
    int savedStdoutFd = dup(STDOUT_FILENO);
    char *argv[20] = {};
    int argc = 0;
    SplitArgs(arg, argv, &argc);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    int ret = HITLS_ReqMain(argc, argv);
    RestoreStdoutByFd(savedStdoutFd);
    ASSERT_EQ(ret, expect);
EXIT:
    if (savedStdoutFd >= 0) {
        close(savedStdoutFd);
    }
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_REQ_DN_CONF_TC001
 * @spec  -
 * @title Test generating a CSR subject from distinguished_name in config
 */
/* BEGIN_CASE */
void UT_HITLS_APP_REQ_DN_CONF_TC001(char *arg, char *outFile, Hex *expectSubject)
{
    int savedStdoutFd = dup(STDOUT_FILENO);
    char *argv[20] = {};
    int argc = 0;
    HITLS_X509_Csr *csr = NULL;
    BslList *subject = NULL;
    BSL_ASN1_Buffer name = {0};
    BSL_Buffer encodedName = {0};
    SplitArgs(arg, argv, &argc);

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_ReqMain(argc, argv), HITLS_APP_SUCCESS);
    RestoreStdoutByFd(savedStdoutFd);
    ASSERT_EQ(HITLS_X509_CsrParseFile(BSL_FORMAT_PEM, outFile, &csr), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_GET_SUBJECT_DN, &subject, sizeof(BslList *)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_EncodeNameList(subject, &name), HITLS_PKI_SUCCESS);
    BSL_ASN1_TemplateItem item = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0};
    BSL_ASN1_Template templ = {&item, 1};
    ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, &name, 1, &encodedName.data, &encodedName.dataLen),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(encodedName.dataLen, expectSubject->len);
    ASSERT_EQ(memcmp(encodedName.data, expectSubject->x, expectSubject->len), 0);

EXIT:
    RestoreStdoutByFd(savedStdoutFd);
    if (savedStdoutFd >= 0) {
        close(savedStdoutFd);
    }
    AppPrintErrorUioUnInit();
    BSL_SAL_FREE(encodedName.data);
    BSL_SAL_FREE(name.buff);
    HITLS_X509_CsrFree(csr);
    (void)remove(outFile);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_REQ_DEFAULT_KEY_OVERWRITE_TC001
 * @spec  -
 * @title A configuration error does not overwrite an existing default private key
 */
/* BEGIN_CASE */
void UT_HITLS_APP_REQ_DEFAULT_KEY_OVERWRITE_TC001(char *arg, int expect)
{
    static const uint8_t originalKey[] = "existing private key";
    int savedStdoutFd = dup(STDOUT_FILENO);
    char *argv[20] = {};
    int argc = 0;
    uint8_t *fileData = NULL;
    uint32_t fileDataLen = 0;

    (void)remove("private.pem");
    ASSERT_EQ(BSL_SAL_WriteFile("private.pem", originalKey, sizeof(originalKey) - 1), BSL_SUCCESS);
    ASSERT_EQ(chmod("private.pem", S_IRUSR | S_IWUSR), 0);
    SplitArgs(arg, argv, &argc);

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_ReqMain(argc, argv), expect);
    RestoreStdoutByFd(savedStdoutFd);
    ASSERT_EQ(BSL_SAL_ReadFile("private.pem", &fileData, &fileDataLen), BSL_SUCCESS);
    ASSERT_EQ(fileDataLen, sizeof(originalKey) - 1);
    ASSERT_COMPARE("Compare private key data", fileData, fileDataLen, originalKey, sizeof(originalKey) - 1);

EXIT:
    RestoreStdoutByFd(savedStdoutFd);
    if (savedStdoutFd >= 0) {
        close(savedStdoutFd);
    }
    AppPrintErrorUioUnInit();
    BSL_SAL_FREE(fileData);
    (void)remove("private.pem");
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_REQ_NO_EXT_CONF_TC001
 * @spec  -
 * @title A DN-only configuration does not add an extensionRequest attribute
 */
/* BEGIN_CASE */
void UT_HITLS_APP_REQ_NO_EXT_CONF_TC001(char *arg, char *outFile)
{
    int savedStdoutFd = dup(STDOUT_FILENO);
    char *argv[20] = {};
    int argc = 0;
    HITLS_X509_Csr *csr = NULL;
    HITLS_X509_Attrs *attrs = NULL;
    HITLS_X509_Ext *ext = NULL;

    (void)remove(outFile);
    SplitArgs(arg, argv, &argc);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_ReqMain(argc, argv), HITLS_APP_SUCCESS);
    RestoreStdoutByFd(savedStdoutFd);
    ASSERT_EQ(HITLS_X509_CsrParseFile(BSL_FORMAT_PEM, outFile, &csr), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_CSR_GET_ATTRIBUTES, &attrs, sizeof(attrs)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AttrCtrl(attrs, HITLS_X509_ATTR_GET_REQUESTED_EXTENSIONS, &ext, sizeof(ext)),
        HITLS_X509_ERR_ATTR_NOT_FOUND);
    ASSERT_EQ(ext, NULL);

EXIT:
    RestoreStdoutByFd(savedStdoutFd);
    if (savedStdoutFd >= 0) {
        close(savedStdoutFd);
    }
    AppPrintErrorUioUnInit();
    HITLS_X509_ExtFree(ext);
    HITLS_X509_CsrFree(csr);
    (void)remove(outFile);
    return;
}
/* END_CASE */

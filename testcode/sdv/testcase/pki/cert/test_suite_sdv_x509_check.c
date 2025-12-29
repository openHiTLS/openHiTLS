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
#include <stdbool.h>
#include "securec.h"
#include "sal_file.h"
#include "sal_time.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_obj.h"
#include "bsl_types.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_params_key.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_rand.h"
#include "crypt_util_rand.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_csr.h"
#include "hitls_pki_x509.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_types.h"
#include "hitls_pki_utils.h"
#include "hitls_cert_local.h"
#include "hitls_x509_verify.h"
#include "hitls_x509_local.h"
/* END_HEADER */

#define MAX_BUFF_SIZE 4096
#define PATH_MAX_LEN 4096
#define PWD_MAX_LEN 4096

static uint32_t g_version = 2; // v3 cert
static uint8_t g_serialNum[4] = {0x11, 0x22, 0x33, 0x44};
static BSL_TIME g_beforeTime = {2025, 1, 1, 0, 0, 0, 0, 0};
static BSL_TIME g_afterTime = {2035, 1, 1, 0, 0, 0, 0, 0};

static int32_t SetRsaPara(CRYPT_EAL_PkeyCtx *pkey)
{
    uint8_t e[] = {1, 0, 1};  // RSA public exponent
    CRYPT_EAL_PkeyPara para = {0};
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.e = e;
    para.para.rsaPara.eLen = 3; // public exponent length = 3
    para.para.rsaPara.bits = 2048; // Bits of para is 2048
    return CRYPT_EAL_PkeySetPara(pkey, &para);
}

static int32_t SetRsaPssPara(CRYPT_EAL_PkeyCtx *pkey)
{
    int32_t mdId = CRYPT_MD_SHA256;
    int32_t saltLen = 20; // 20 bytes salt
    BSL_Param pssParam[4] = {
    {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
    {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
    {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
    BSL_PARAM_END};
    return CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0);
}

// if alg is ecc, algParam specifies curveId; if pqc, algParam specifies paramSet
static CRYPT_EAL_PkeyCtx *GenKey(int32_t algId, int32_t algParam)
{
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(algId == BSL_CID_RSASSAPSS ? BSL_CID_RSA : algId);
    ASSERT_NE(pkey, NULL);

    if (algId == CRYPT_PKEY_ECDSA) {
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algParam), CRYPT_SUCCESS);
    }

    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(SetRsaPara(pkey), CRYPT_SUCCESS);
    }
    if (algId == BSL_CID_RSASSAPSS) {
        ASSERT_EQ(SetRsaPara(pkey), CRYPT_SUCCESS);
        ASSERT_EQ(SetRsaPssPara(pkey), CRYPT_SUCCESS);
    }
    if (algId == CRYPT_PKEY_ML_DSA) {
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, algParam), CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    return pkey;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return NULL;
}

static BslList* GenDNList(void)
{
    HITLS_X509_DN dnName1[1] = {{BSL_CID_AT_COMMONNAME, (uint8_t *)"OH", 2}};
    HITLS_X509_DN dnName2[1] = {{BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2}};

    BslList *dirNames = HITLS_X509_DnListNew();
    ASSERT_NE(dirNames, NULL);

    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName1, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName2, 1), HITLS_PKI_SUCCESS);
    return dirNames;

EXIT:
    HITLS_X509_DnListFree(dirNames);
    return NULL;
}

static BslList* GenGeneralNameList(void)
{
    char *str = "test";
    char *emailstr = "Wllill@163.com";
    HITLS_X509_GeneralName *email = NULL;
    HITLS_X509_GeneralName *dns = NULL;
    HITLS_X509_GeneralName *dname = NULL;
    HITLS_X509_GeneralName *uri = NULL;
    HITLS_X509_GeneralName *ip = NULL;

    BslList *names = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
    ASSERT_NE(names, NULL);

    email = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    dns = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    dname = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    uri = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    ip = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    ASSERT_TRUE(email != NULL && dns != NULL && dname != NULL && uri != NULL && ip != NULL);

    email->type = HITLS_X509_GN_EMAIL;
    dns->type = HITLS_X509_GN_DNS;
    uri->type = HITLS_X509_GN_URI;
    dname->type = HITLS_X509_GN_DNNAME;
    ip->type = HITLS_X509_GN_IP;
    email->value.dataLen = strlen(emailstr);
    dns->value.dataLen = strlen(str);
    uri->value.dataLen = strlen(str);
    dname->value.dataLen = sizeof(BslList *);
    ip->value.dataLen = strlen(str);
    email->value.data = BSL_SAL_Dump(emailstr, strlen(emailstr));
    dns->value.data = BSL_SAL_Dump(str, strlen(str));
    uri->value.data = BSL_SAL_Dump(str, strlen(str));
    dname->value.data = (uint8_t *)GenDNList();
    ip->value.data = BSL_SAL_Dump(str, strlen(str));
    ASSERT_TRUE(email->value.data != NULL && dns->value.data != NULL
        && uri->value.data != NULL && dname->value.data != NULL && ip->value.data != NULL);

    ASSERT_EQ(BSL_LIST_AddElement(names, email, BSL_LIST_POS_END), 0);
    ASSERT_EQ(BSL_LIST_AddElement(names, dns, BSL_LIST_POS_END), 0);
    ASSERT_EQ(BSL_LIST_AddElement(names, uri, BSL_LIST_POS_END), 0);
    ASSERT_EQ(BSL_LIST_AddElement(names, dname, BSL_LIST_POS_END), 0);
    ASSERT_EQ(BSL_LIST_AddElement(names, ip, BSL_LIST_POS_END), 0);

    return names;
EXIT:
    HITLS_X509_FreeGeneralName(email);
    HITLS_X509_FreeGeneralName(dns);
    HITLS_X509_FreeGeneralName(dname);
    HITLS_X509_FreeGeneralName(uri);
    HITLS_X509_FreeGeneralName(ip);
    BSL_LIST_FREE(names, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
    return NULL;
}

static void FreeListData(void *data)
{
    (void)data;
    return;
}

static int32_t SetCertExt(HITLS_X509_Cert *cert)
{
    int32_t ret = 1;
    uint8_t kid[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    HITLS_X509_ExtBCons bCons = {true, true, 1};
    HITLS_X509_ExtKeyUsage ku = {true, HITLS_X509_EXT_KU_DIGITAL_SIGN | HITLS_X509_EXT_KU_NON_REPUDIATION};
    HITLS_X509_ExtAki aki = {true, {kid, sizeof(kid)}, NULL, {0}};
    HITLS_X509_ExtSki ski = {true, {kid, sizeof(kid)}};
    HITLS_X509_ExtExKeyUsage exku = {true, NULL};
    HITLS_X509_ExtSan san = {true, NULL};
    BSL_Buffer oidBuff = {0};
    BslOidString *oid = NULL;

    BslList *oidList = BSL_LIST_New(sizeof(BSL_Buffer));
    ASSERT_TRUE(oidList != NULL);
    oid = BSL_OBJ_GetOID(BSL_CID_KP_SERVERAUTH);
    ASSERT_NE(oid, NULL);
    oidBuff.data = (uint8_t *)oid->octs;
    oidBuff.dataLen = oid->octetLen;
    ASSERT_EQ(BSL_LIST_AddElement(oidList, &oidBuff, BSL_LIST_POS_END), 0);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_BCONS, &bCons, sizeof(HITLS_X509_ExtBCons)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SKI, &ski, sizeof(HITLS_X509_ExtSki)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_AKI, &aki, sizeof(HITLS_X509_ExtAki)), 0);

    exku.oidList = oidList;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_EXKUSAGE, &exku, sizeof(HITLS_X509_ExtExKeyUsage)), 0);

    san.names = GenGeneralNameList();
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SAN, &san, sizeof(HITLS_X509_ExtSan)), 0);

    ret = 0;
EXIT:
    BSL_LIST_FREE(oidList, (BSL_LIST_PFUNC_FREE)FreeListData);
    BSL_LIST_FREE(san.names, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
    return ret;
}

static BslList* GenAllDNList(void)
{
    HITLS_X509_DN dnName1[1] = {{BSL_CID_AT_COMMONNAME, (uint8_t *)"OH", 2}};
    HITLS_X509_DN dnName2[1] = {{BSL_CID_AT_SURNAME, (uint8_t *)"证书", 6}};
    HITLS_X509_DN dnName3[1] = {{BSL_CID_AT_SERIALNUMBER, (uint8_t *)"11223344", 8}};
    HITLS_X509_DN dnName4[1] = {{BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2}};
    HITLS_X509_DN dnName5[1] = {{BSL_CID_AT_LOCALITYNAME, (uint8_t *)"这里", 6}};
    HITLS_X509_DN dnName6[1] = {{BSL_CID_AT_STATEORPROVINCENAME, (uint8_t *)"陕西", 6}};
    HITLS_X509_DN dnName7[1] = {{BSL_CID_AT_STREETADDRESS, (uint8_t *)"天谷二路", 12}};
    HITLS_X509_DN dnName8[1] = {{BSL_CID_AT_ORGANIZATIONNAME, (uint8_t *)"TEST", 4}};
    HITLS_X509_DN dnName9[1] = {{BSL_CID_AT_ORGANIZATIONALUNITNAME, (uint8_t *)"UT", 2}};
    HITLS_X509_DN dnName10[1] = {{BSL_CID_AT_TITLE, (uint8_t *)"TEST", 4}};
    HITLS_X509_DN dnName11[1] = {{BSL_CID_AT_GIVENNAME, (uint8_t *)"证书", 6}};
    HITLS_X509_DN dnName12[1] = {{BSL_CID_AT_INITIALS, (uint8_t *)"测试", 6}};
    HITLS_X509_DN dnName13[1] = {{BSL_CID_AT_GENERATIONQUALIFIER, (uint8_t *)"CN", 2}};
    HITLS_X509_DN dnName14[1] = {{BSL_CID_AT_DNQUALIFIER, (uint8_t *)"1", 1}};
    HITLS_X509_DN dnName15[1] = {{BSL_CID_AT_PSEUDONYM, (uint8_t *)"TEST", 4}};
    HITLS_X509_DN dnName16[1] = {{BSL_CID_DOMAINCOMPONENT, (uint8_t *)"TEST", 4}};
    HITLS_X509_DN dnName17[1] = {{BSL_CID_AT_USERID, (uint8_t *)"TEST", 4}};

    BslList *dirNames = HITLS_X509_DnListNew();
    ASSERT_NE(dirNames, NULL);

    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName1, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName2, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName3, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName4, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName5, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName6, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName7, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName8, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName9, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName10, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName11, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName12, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName13, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName14, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName15, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName16, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName17, 1), HITLS_PKI_SUCCESS);
    return dirNames;

EXIT:
    HITLS_X509_DnListFree(dirNames);
    return NULL;
}

static int32_t ReadFile(const char *filePath, uint8_t *buff, uint32_t buffLen, uint32_t *outLen)
{
    FILE *fp = NULL;
    int32_t ret = -1;

    fp = fopen(filePath, "rb");
    if (fp == NULL) {
        return ret;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        goto EXIT;
    }
    long fileSize = ftell(fp);
    if (fileSize < 0 || (uint32_t)fileSize > buffLen) {
        goto EXIT;
    }
    rewind(fp);
    size_t readSize = fread(buff, 1, fileSize, fp);
    if (readSize != (size_t)fileSize) {
        goto EXIT;
    }
    *outLen = (uint32_t)fileSize;
    ret = 0;

EXIT:
    (void)fclose(fp);
    return ret;
}

static int32_t PrintBuffTest(int cmd, BSL_Buffer *data, char *log, Hex *expect, bool isExpectFile)
{
    int32_t ret = -1;
    uint8_t printBuf[MAX_BUFF_SIZE] = {};
    uint32_t printBufLen = sizeof(printBuf);
    uint8_t expectBuf[MAX_BUFF_SIZE] = {};
    uint32_t expectBufLen = sizeof(expectBuf);
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_MemMethod());
    ASSERT_NE(uio, NULL);
    ASSERT_EQ(HITLS_PKI_PrintCtrl(cmd, data->data, data->dataLen, uio), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_UIO_Read(uio, printBuf, MAX_BUFF_SIZE, &printBufLen), 0);
    if (isExpectFile) {
        ASSERT_EQ(ReadFile((char *)expect->x, expectBuf, MAX_BUFF_SIZE, &expectBufLen), 0);
        ASSERT_COMPARE(log, expectBuf, expectBufLen, printBuf, printBufLen - 1); // Ignore line break differences
    } else {
        ASSERT_COMPARE(log, expect->x, expect->len, printBuf, printBufLen - 1); // Ignore line break differences
    }
    ret = 0;
EXIT:
    BSL_UIO_Free(uio);
    return ret;
}

static int32_t WriteFile(const char *filePath, const uint8_t *buff, uint32_t buffLen)
{
    FILE *fp = NULL;
    int32_t ret = -1;

    fp = fopen(filePath, "wb");
    if (fp == NULL) {
        return ret;
    }

    size_t writeSize = fwrite(buff, 1, buffLen, fp);
    if (writeSize != buffLen) {
        goto EXIT;
    }
    ret = 0;

EXIT:
    (void)fclose(fp);
    return ret;
}

static int32_t GetPrintBuff(BSL_Buffer *data, char *expectedPath)
{
    int32_t ret = -1;
    uint8_t dataBuf[MAX_BUFF_SIZE] = {};
    uint32_t dataBufLen = sizeof(dataBuf);
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_MemMethod());
    ASSERT_NE(uio, NULL);
    ASSERT_EQ(HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_CERT, data->data, data->dataLen, uio),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_UIO_Read(uio, dataBuf, MAX_BUFF_SIZE, &dataBufLen), 0);
    ASSERT_EQ(WriteFile(expectedPath, dataBuf, dataBufLen - 1), HITLS_PKI_SUCCESS); // ignore line break differences
    ret = 0;
EXIT:
    BSL_UIO_Free(uio);
    return ret;
}

static int32_t SetCertBasic(HITLS_X509_Cert *cert, uint32_t version, uint8_t *serialNum, uint32_t serialNumLen,
    BSL_TIME *beforeTime, BSL_TIME *afterTime, BslList *subject, BslList *issuer, CRYPT_EAL_PkeyCtx *pkey)
{
    int32_t ret = 1;
    if (version <= 3) { // version can be 1,2,3
        ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    }
    
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, serialNumLen), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    if (pkey != NULL) {
        ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, pkey, 0), HITLS_PKI_SUCCESS);
    }
    if (subject != NULL) {
        ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, subject, sizeof(BslList)), HITLS_PKI_SUCCESS);
    }
    if (issuer != NULL) {
        ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, issuer, sizeof(BslList)), HITLS_PKI_SUCCESS);
    }
    ret = 0;
EXIT:
    return ret;
}

static int32_t CompareDNLists(BslList *extList1, BslList *extList2)
{
    int32_t ret = -1;
    ret = BSL_LIST_COUNT(extList1);
    ret = BSL_LIST_COUNT(extList2);
    ASSERT_EQ(BSL_LIST_COUNT(extList1), BSL_LIST_COUNT(extList2));
    HITLS_X509_NameNode **nameNode1 = BSL_LIST_First(extList1);
    HITLS_X509_NameNode **nameNode2 = BSL_LIST_First(extList2);
    ASSERT_NE(*nameNode1, NULL);
    ASSERT_NE(*nameNode2, NULL);

    for (int i = 0; i < BSL_LIST_COUNT(extList1); i += 2) { // every DNname has 2 layers
        ASSERT_NE((*nameNode1), NULL);
        ASSERT_EQ((*nameNode1)->layer, 1);
        ASSERT_EQ((*nameNode1)->nameType.tag, 0);
        ASSERT_EQ((*nameNode1)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode1)->nameType.len, 0);
        ASSERT_EQ((*nameNode1)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode1)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode1)->nameValue.len, 0);

        ASSERT_NE((*nameNode2), NULL);
        ASSERT_EQ((*nameNode2)->layer, 1);
        ASSERT_EQ((*nameNode2)->nameType.tag, 0);
        ASSERT_EQ((*nameNode2)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode2)->nameType.len, 0);
        ASSERT_EQ((*nameNode2)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode2)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode2)->nameValue.len, 0);

        nameNode1 = BSL_LIST_Next(extList1);
        nameNode2 = BSL_LIST_Next(extList2);
        ASSERT_NE((*nameNode1), NULL);
        ASSERT_EQ((*nameNode1)->layer, 2); // layer 2
        ASSERT_NE((*nameNode2), NULL);
        ASSERT_EQ((*nameNode2)->layer, 2); // layer 2
        ASSERT_EQ((*nameNode1)->nameType.tag, (*nameNode2)->nameType.tag);
        ASSERT_COMPARE("nameType", (*nameNode1)->nameType.buff, (*nameNode1)->nameType.len,
            (*nameNode2)->nameType.buff, (*nameNode2)->nameType.len);

        ASSERT_EQ((*nameNode1)->nameValue.tag, (*nameNode2)->nameValue.tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode1)->nameValue.buff, (*nameNode1)->nameValue.len,
            (*nameNode2)->nameValue.buff, (*nameNode2)->nameValue.len);
        nameNode1 = BSL_LIST_Next(extList1);
        nameNode2 = BSL_LIST_Next(extList2);
    }
    ret = 0;

EXIT:
    return ret;
}

static int32_t parsedBasicFieldsCheck(HITLS_X509_Cert *parsedCert, uint32_t version, uint8_t *serialNum,
    uint32_t serialNumLen, BSL_TIME *beforeTime, BSL_TIME *afterTime, BslList *subject, BslList *issuer, int isEdited)
{
    int32_t ret = -1;
    ASSERT_EQ(parsedCert->tbs.version, version);
    ASSERT_EQ(parsedCert->tbs.serialNum.len, serialNumLen);
    ASSERT_COMPARE("serial", parsedCert->tbs.serialNum.buff, serialNumLen, serialNum, serialNumLen);
    ASSERT_EQ(BSL_SAL_DateTimeCompare(&parsedCert->tbs.validTime.start, beforeTime, NULL), BSL_TIME_CMP_EQUAL);
    ASSERT_EQ(BSL_SAL_DateTimeCompare(&parsedCert->tbs.validTime.end, afterTime, NULL), BSL_TIME_CMP_EQUAL);
    ASSERT_EQ(CompareDNLists(parsedCert->tbs.issuerName, issuer), 0);
    ASSERT_EQ(CompareDNLists(parsedCert->tbs.subjectName, subject), 0);
    if (!isEdited) {
        ASSERT_EQ(HITLS_X509_CheckSignature(parsedCert->tbs.ealPubKey, parsedCert->tbs.tbsRawData,
            parsedCert->tbs.tbsRawDataLen, &parsedCert->signAlgId, &parsedCert->signature), HITLS_PKI_SUCCESS);
    }
    ret = 0;

EXIT:
    return ret;
}

static char g_sm2DefaultUserid[] = "1234567812345678";

static void SetSignParam(int32_t algId, int32_t mdId, HITLS_X509_SignAlgParam *algParam, CRYPT_RSA_PssPara *pssParam)
{
    if (algId == BSL_CID_RSASSAPSS) {
        algParam->algId = BSL_CID_RSASSAPSS;
        pssParam->mdId = mdId;
        pssParam->mgfId = mdId;
        pssParam->saltLen = 20; // 20 bytes salt
        algParam->rsaPss = *pssParam;
    }
    if (algId == BSL_CID_SM2DSA) {
        algParam->algId = BSL_CID_SM2DSAWITHSM3;
        algParam->sm2UserId.data = (uint8_t *)g_sm2DefaultUserid;
        algParam->sm2UserId.dataLen = (uint32_t)strlen(g_sm2DefaultUserid);
    }
    
}

/**
 * Test the generation and parsing with and without extensions when the version is not set or set to 0, 1, 2
 */
/* BEGIN_CASE */
void SDV_X509_CERT_VERSIONCHECK_TC001(int version, int extflag, int result, char *expectpath, char *expectbuf)
{
    char *path = "tmpca.cert";
    BSL_Buffer data = {0};
    HITLS_X509_SignAlgParam algParam = {0};

    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *certcheck = NULL;
    HITLS_X509_Cert *parsecert = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BslList *subject = GenDNList();

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    
    pkey = GenKey(CRYPT_PKEY_ECDSA, CRYPT_ECC_NISTP256);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    ASSERT_EQ(SetCertBasic(cert, version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, subject, subject, pkey), 0);
    if (extflag) {
        ASSERT_EQ(SetCertExt(cert), 0);
    }
    if (version == 4) { // version = 4 means not set version
        version = 0; // default version = 0
    }
    
    // sign cert
    ASSERT_EQ(HITLS_X509_CertSign(CRYPT_MD_SHA256, pkey, &algParam, cert), result);
    if (result == HITLS_PKI_SUCCESS) {
        // generate cert file
        ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsecert), HITLS_PKI_SUCCESS);
        parsedBasicFieldsCheck(parsecert, version, g_serialNum, sizeof(g_serialNum),
            &g_beforeTime, &g_afterTime, subject, subject, 0);
        ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, expectpath, &certcheck), HITLS_PKI_SUCCESS);
        data.data = (uint8_t *)certcheck;
        data.dataLen = sizeof(HITLS_X509_Cert *);
        GetPrintBuff(&data, expectbuf);
        Hex expect = {(uint8_t *)expectbuf, 0};
        ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);
    }

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(certcheck);
    HITLS_X509_CertFree(parsecert);
    HITLS_X509_DnListFree(subject);
    remove(path);
}
/* END_CASE */

/**
 * Test the parsing when the version is set to 3
 */
/* BEGIN_CASE */
void SDV_X509_CERT_VERSIONCHECK_TC002()
{
    HITLS_X509_Cert *cert = NULL;
    uint32_t version = 3;

    TestMemInit();
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version,
        sizeof(version)), HITLS_X509_ERR_INVALID_PARAM);

EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/**
 * Testing for parse of various abnormal scenarios for certificate basic fields
 */
/* BEGIN_CASE */
void SDV_X509_CERT_VERSIONCHECK_TC003(char *path, int result, char *expectbuf)
{
    HITLS_X509_Cert *cert = NULL;
    BSL_Buffer data = {0};
    TestMemInit();
    if (result == CRYPT_DECODE_ERR_NO_USABLE_DECODER) {
    #ifndef HITLS_CRYPTO_KEY_DECODE_CHAIN
        result = CRYPT_DECODE_UNKNOWN_OID;
    #endif
    }

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), result);
    if (result == HITLS_PKI_SUCCESS) {
        data.data = (uint8_t *)cert;
        data.dataLen = sizeof(HITLS_X509_Cert *);
        GetPrintBuff(&data, expectbuf);
        Hex expect = {(uint8_t *)expectbuf, 0};
        ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);
    }

EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/**
 * Test the generation and parsing of certificates when serialnum is 0xFF, 0, a 20-digit array, and a 21-digit array.
 */
/* BEGIN_CASE */
void SDV_X509_CERT_SERIALNUMCHECK_TC001(int extflag, int result, Hex *serialNum, char *expectpath, char *expectbuf)
{
    char *path = "tmpca.cert";
    BSL_Buffer data = {0};
    HITLS_X509_SignAlgParam algParam = {0};

    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *certcheck = NULL;
    HITLS_X509_Cert *parsecert = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BslList *subject = GenDNList();

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    
    pkey = GenKey(CRYPT_PKEY_ECDSA, CRYPT_ECC_NISTP256);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_EQ(SetCertBasic(cert, g_version, (uint8_t *)serialNum->x, serialNum->len,
        &g_beforeTime, &g_afterTime, subject, subject, pkey), 0);
    if (extflag) {
        ASSERT_EQ(SetCertExt(cert), 0);
    }
    
    // sign cert
    ASSERT_EQ(HITLS_X509_CertSign(CRYPT_MD_SHA256, pkey, &algParam, cert), result);
    if (result == HITLS_PKI_SUCCESS) {
        ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsecert), HITLS_PKI_SUCCESS);
        parsedBasicFieldsCheck(parsecert, g_version, (uint8_t *)serialNum->x, serialNum->len,
            &g_beforeTime, &g_afterTime, subject, subject, 0);
        ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, expectpath, &certcheck), HITLS_PKI_SUCCESS);
        data.data = (uint8_t *)certcheck;
        data.dataLen = sizeof(HITLS_X509_Cert *);
        GetPrintBuff(&data, expectbuf);
        Hex expect = {(uint8_t *)expectbuf, 0};
        ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);
    }

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(certcheck);
    HITLS_X509_CertFree(parsecert);
    HITLS_X509_DnListFree(subject);
    remove(path);
}
/* END_CASE */

/**
 * Testing the certificate generation function when the key is not set or when the key uses an unsupported algorithm
 */
/* BEGIN_CASE */
void SDV_X509_CERT_KEYCHECK_TC001(int keyflag, int result)
{
    HITLS_X509_SignAlgParam algParam = {0};
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BslList *subject = GenDNList();

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    
    pkey = GenKey(CRYPT_PKEY_X25519, CRYPT_ECC_NISTP256);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    if (keyflag) {
        ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
            &g_beforeTime, &g_afterTime, subject, subject, pkey), 0);
    } else {
        ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
            &g_beforeTime, &g_afterTime, subject, subject, NULL), 0);
    }
    
    ASSERT_EQ(SetCertExt(cert), 0);
    
    // sign cert
    ASSERT_EQ(HITLS_X509_CertSign(CRYPT_MD_SHA256, pkey, &algParam, cert), result);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
    HITLS_X509_DnListFree(subject);
}
/* END_CASE */

/**
 * Without setting the issuer, certificate generation fails.
 */
/* BEGIN_CASE */
void SDV_X509_CERT_ISSUERCHECK_TC001()
{
    HITLS_X509_SignAlgParam algParam = {0};
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BslList *subject = GenDNList();

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    pkey = GenKey(CRYPT_PKEY_X25519, CRYPT_ECC_NISTP256);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, subject, NULL, pkey), 0);
    ASSERT_EQ(SetCertExt(cert), 0);
    
    // sign cert
    ASSERT_EQ(HITLS_X509_CertSign(CRYPT_MD_SHA256, pkey, &algParam, cert), HITLS_X509_ERR_CERT_INVALID_DN);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
    HITLS_X509_DnListFree(subject);
}
/* END_CASE */

/**
 * When generating the issuer field, if the DN is empty, or if the type in the DN is an invalid OID,
 * or if the value in the DN is empty, the certificate generation will fail.
 */
/* BEGIN_CASE */
void SDV_X509_CERT_ISSUERCHECK_TC002()
{
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BslList *subject = GenDNList();
    BslList *issuer = HITLS_X509_DnListNew();
    ASSERT_NE(issuer, NULL);
    HITLS_X509_DN dnName1[1] = {{BSL_CID_UNKNOWN, (uint8_t *)"OH", 2}};
    HITLS_X509_DN dnName2[1] = {{BSL_CID_AT_COMMONNAME, NULL, 0}};
    BslList *dirNames = HITLS_X509_DnListNew();
    ASSERT_NE(dirNames, NULL);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName1, 1), HITLS_X509_ERR_SET_DNNAME_UNKNOWN);
    BslList *issuer1 = HITLS_X509_DnListNew();
    ASSERT_EQ(HITLS_X509_AddDnName(issuer1, dnName2, 1), HITLS_X509_ERR_INVALID_PARAM);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    
    pkey = GenKey(CRYPT_PKEY_X25519, CRYPT_ECC_NISTP256);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, subject, NULL, pkey), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, issuer,
        sizeof(BslList)), HITLS_X509_ERR_SET_NAME_LIST);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, dirNames,
        sizeof(BslList)), HITLS_X509_ERR_SET_NAME_LIST);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, issuer1,
        sizeof(BslList)), HITLS_X509_ERR_SET_NAME_LIST);
    ASSERT_EQ(SetCertExt(cert), 0);
    
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
    HITLS_X509_DnListFree(subject);
    HITLS_X509_DnListFree(issuer);
    HITLS_X509_DnListFree(issuer1);
    HITLS_X509_DnListFree(dirNames);
}
/* END_CASE */

/**
 * Set the subject as non-empty, but there are no DN attributes inside, the certificate generation failed.
 */
/* BEGIN_CASE */
void SDV_X509_CERT_SUBJECTCHECK_TC002(int extflag)
{
    HITLS_X509_SignAlgParam algParam = {0};
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BslList *issuer = GenDNList();
    BslList *subject = HITLS_X509_DnListNew();

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    
    pkey = GenKey(CRYPT_PKEY_X25519, CRYPT_ECC_NISTP256);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, NULL, issuer, pkey), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, subject,
        sizeof(BslList)), HITLS_X509_ERR_SET_NAME_LIST);
    if (extflag) {
        ASSERT_EQ(SetCertExt(cert), 0);
    }
    
    // sign cert
    ASSERT_EQ(HITLS_X509_CertSign(CRYPT_MD_SHA256, pkey, &algParam, cert), HITLS_X509_ERR_CERT_INVALID_DN);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
    HITLS_X509_DnListFree(subject);
    HITLS_X509_DnListFree(issuer);
}
/* END_CASE */

/**
 * If the subject is not set and SAN is set as critical, or if the subject is not set and there is no SAN,
 * or if the subject is set and contains the email attribute, certificate generation will fail.
 */
/* BEGIN_CASE */
void SDV_X509_CERT_SUBJECTCHECK_TC001(int extflag, int emailflag)
{
    HITLS_X509_SignAlgParam algParam = {0};
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BslList *subject = GenDNList();
    HITLS_X509_DN dnName1[1] = {{BSL_CID_AT_COMMONNAME, (uint8_t *)"OH", 2}};
    HITLS_X509_DN dnName2[1] = {{BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2}};
    HITLS_X509_DN dnName3[1] = {{BSL_CID_EMAILADDRESS, (uint8_t *)"Wllill@163.com", 14}};

    BslList *dirNames = HITLS_X509_DnListNew();
    ASSERT_NE(dirNames, NULL);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    
    pkey = GenKey(CRYPT_PKEY_X25519, CRYPT_ECC_NISTP256);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, NULL, subject, pkey), 0);
    if (extflag) {
        ASSERT_EQ(SetCertExt(cert), 0);
    }
    if (emailflag) {
        ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName1, 1), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName2, 1), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName3, 1), HITLS_X509_ERR_SET_DNNAME_UNKNOWN);
    }
    
    // sign cert
    ASSERT_EQ(HITLS_X509_CertSign(CRYPT_MD_SHA256, pkey, &algParam, cert), HITLS_X509_ERR_CERT_INVALID_DN);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
    HITLS_X509_DnListFree(subject);
    HITLS_X509_DnListFree(dirNames);
}
/* END_CASE */

/**
 * Set all currently supported attributes in the subject, set SAN or do not set SAN,
 * certificate generate and parsing success.
 */
/* BEGIN_CASE */
void SDV_X509_CERT_SUBJECTCHECK_TC003(int extflag, char *expectpath, char *expectbuf)
{
    char *path = "tmpca.cert";
    BSL_Buffer data = {0};
    HITLS_X509_SignAlgParam algParam = {0};

    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *certcheck = NULL;
    HITLS_X509_Cert *parsecert = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BslList *subject = GenAllDNList();

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    
    pkey = GenKey(CRYPT_PKEY_ECDSA, CRYPT_ECC_NISTP256);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_EQ(SetCertBasic(cert, g_version, (uint8_t *)g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, subject, subject, pkey), 0);
    if (extflag) {
        ASSERT_EQ(SetCertExt(cert), 0);
    }
    
    // sign cert
    ASSERT_EQ(HITLS_X509_CertSign(CRYPT_MD_SHA256, pkey, &algParam, cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsecert), HITLS_PKI_SUCCESS);
    parsedBasicFieldsCheck(parsecert, g_version, (uint8_t *)g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, subject, subject, 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, expectpath, &certcheck), HITLS_PKI_SUCCESS);
    data.data = (uint8_t *)certcheck;
    data.dataLen = sizeof(HITLS_X509_Cert *);
    GetPrintBuff(&data, expectbuf);
    Hex expect = {(uint8_t *)expectbuf, 0};
    ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(certcheck);
    HITLS_X509_CertFree(parsecert);
    HITLS_X509_DnListFree(subject);
    remove(path);
}
/* END_CASE */

/**
 * Rsapss certificate, modify the OID of the signature algorithm in tbs or modify its parameters,
 * and verify the certificate's parsing capability. Parsing fails when the OID is inconsistent,
 * and parsing can succeed when the parameters are inconsistent but OID is consistent.
 */
/* BEGIN_CASE */
void SDV_X509_CERT_OIDCHECK_TC001(char *path, int result, char *expectbuf)
{
    HITLS_X509_Cert *cert = NULL;
    BSL_Buffer data = {0};
    TestMemInit();
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), result);
    if (result == HITLS_PKI_SUCCESS) {
        ASSERT_EQ(cert->signAlgId.algId, cert->tbs.signAlgId.algId);
        data.data = (uint8_t *)cert;
        data.dataLen = sizeof(HITLS_X509_Cert *);
        GetPrintBuff(&data, expectbuf);
        Hex expect = {(uint8_t *)expectbuf, 0};
        ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);
    }
    if (strstr(path, (const char *)"oidparamdiff") != NULL) {
        ASSERT_TRUE(cert->signAlgId.rsaPssParam.mdId != cert->tbs.signAlgId.rsaPssParam.mdId);
    }

EXIT:
    TestRandDeInit();
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/**
 * When the ISSUER and Subject in the CA contain the old encoding format TeletexString,
 * parsing is successful, the certificate is issued successfully using this CA,
 * and the issued certificate inherits the TeletexString encoding format.
 */
/* BEGIN_CASE */
void SDV_X509_CERT_TELETEXSTRING_PARSEGEN_TC001(char *path, char *expectbuf)
{
    char *path1 = "tmpcaissuer.cert";
    BSL_Buffer data = {0};
    HITLS_X509_SignAlgParam algParam = {0};

    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *cacert = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    BslList *issuer = NULL;
    BslList *subject = NULL;
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    
    pkey = GenKey(CRYPT_PKEY_ECDSA, CRYPT_ECC_NISTP256);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cacert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cacert, HITLS_X509_GET_SUBJECT_DN, &subject, sizeof(BslList *)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cacert, HITLS_X509_GET_ISSUER_DN, &issuer, sizeof(BslList *)), HITLS_PKI_SUCCESS);

    ASSERT_EQ(SetCertBasic(cert, g_version, (uint8_t *)g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, subject, issuer, pkey), 0);
    ASSERT_EQ(SetCertExt(cert), 0);

    // sign cert
    ASSERT_EQ(HITLS_X509_CertSign(CRYPT_MD_SHA256, pkey, &algParam, cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path1), HITLS_PKI_SUCCESS);
    data.data = (uint8_t *)cacert;
    data.dataLen = sizeof(HITLS_X509_Cert *);
    GetPrintBuff(&data, expectbuf);
    Hex expect = {(uint8_t *)expectbuf, 0};
    ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(cacert);
    remove(path1);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_AKISKI_GEN_TEST_TC001(int isCritical, Hex *kid, int algId,
    int hashId, int curveId, int hasAki, int hasSki)
{
    char *path = "tmp.cert";
    char *expectPath = "exp.cert";
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *parsedCert = NULL;
    HITLS_X509_ExtAki parsedAki = {0};
    HITLS_X509_ExtSki parsedSki = {0};
    BslList *dnList = NULL;
    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    BSL_Buffer data = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    dnList = GenDNList();
    ASSERT_NE(dnList, NULL);

    // set authority key identifier, subject key identifier extension
    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, key), 0);
    HITLS_X509_Ext *ext = &cert->tbs.ext;
    if (hasAki) {
        HITLS_X509_ExtAki aki = {isCritical, {kid->x, kid->len}, NULL, {0}};
        ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_AKI, &aki,
            sizeof(HITLS_X509_ExtAki)), HITLS_PKI_SUCCESS);
    }
    if (hasSki) {
        HITLS_X509_ExtSki ski = {isCritical, {kid->x, kid->len}};
        ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SKI, &ski,
            sizeof(HITLS_X509_ExtSki)), HITLS_PKI_SUCCESS);
    }
    ASSERT_NE(ext->flag & HITLS_X509_EXT_FLAG_GEN, 0);

    // sign the cert
    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, NULL, cert), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, &algParam, cert), HITLS_PKI_SUCCESS);
    }
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path), HITLS_PKI_SUCCESS);

    // cert print compare
    data.data = (uint8_t *)cert;
    data.dataLen = sizeof(HITLS_X509_Cert *);
    ASSERT_EQ(GetPrintBuff(&data, expectPath), 0);
    Hex expect = {(uint8_t *)expectPath, 0};
    ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);

    // cert parsed fields compare
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, 0), 0);
    if (hasAki) {
        ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_AKI,
            &parsedAki, sizeof(HITLS_X509_ExtAki)), HITLS_PKI_SUCCESS);
        ASSERT_EQ(parsedAki.critical, isCritical);
        ASSERT_COMPARE("Get parsedAki", parsedAki.kid.data, parsedAki.kid.dataLen, kid->x, kid->len);
    }
    if (hasSki) {
        ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_SKI,
            &parsedSki, sizeof(HITLS_X509_ExtSki)), HITLS_PKI_SUCCESS);
        ASSERT_EQ(parsedSki.critical, isCritical);
        ASSERT_COMPARE("Get parsedSki", parsedSki.kid.data, parsedSki.kid.dataLen, kid->x, kid->len);
    }

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    remove(path);
    remove(expectPath);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_ILLEGAL_AKISKI_GEN_TEST_TC001(int isCritical, Hex *kid, int algId,
    int curveId, int hasAki, int hasSki)
{
    HITLS_X509_Cert *cert = NULL;
    BslList *dnList = NULL;

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    dnList = GenDNList();
    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, key), 0);

    if (hasAki) {
        HITLS_X509_ExtAki aki = {isCritical, {kid->x, kid->len}, NULL, {0}};
        ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_AKI, &aki,
            sizeof(HITLS_X509_ExtAki)), HITLS_X509_ERR_EXT_KID);
    }
    if (hasSki) {
        HITLS_X509_ExtSki ski = {isCritical, {kid->x, kid->len}};
        ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SKI, &ski,
            sizeof(HITLS_X509_ExtSki)), HITLS_X509_ERR_EXT_KID);
    }

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_DnListFree(dnList);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_EXTAKI_PARSE_TEST_TC001(char *certPath, int isCritical, Hex *kid, int isEdited)
{
    HITLS_X509_Cert *parsedCert = NULL;
    HITLS_X509_ExtAki parsedAki = {0};

    BslList *dnList = GenDNList();
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, isEdited), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_AKI,
        &parsedAki, sizeof(HITLS_X509_ExtAki)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedAki.critical, isCritical);
    ASSERT_COMPARE("Get aki", parsedAki.kid.data, parsedAki.kid.dataLen, kid->x, kid->len);

EXIT:
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_EXTSKI_PARSE_TEST_TC001(char *certPath, int isCritical, Hex *kid, int isEdited)
{
    HITLS_X509_Cert *parsedCert = NULL;
    HITLS_X509_ExtSki parsedSki = {0};
    BslList *dnList = GenDNList();
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, isEdited), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_SKI,
        &parsedSki, sizeof(HITLS_X509_ExtSki)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedSki.critical, isCritical);
    ASSERT_COMPARE("Get parsedSki", parsedSki.kid.data, parsedSki.kid.dataLen, kid->x, kid->len);

EXIT:
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_KUSAGE_GEN_TEST_TC001(int isCritical, int algId, int hashId, int curveId,
    int expKuDigitailSign, int expKuNonRepudiation, int expKuKeyEncipherment, int expKuDataEncipherment,
    int expKuAgreement, int expKuCertSign, int expKuCrlSign, int expKuEncipherOnly, int expKuDecipherOnly)
{
    char *path = "tmp.cert";
    char *expectPath = "exp.cert";
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *parsedCert = NULL;
    BslList *dnList = NULL;
    uint32_t keyUsage = 0;
    if (expKuDigitailSign) {
        keyUsage |= HITLS_X509_EXT_KU_DIGITAL_SIGN;
    }
    if (expKuNonRepudiation) {
        keyUsage |= HITLS_X509_EXT_KU_NON_REPUDIATION;
    }
    if (expKuKeyEncipherment) {
        keyUsage |= HITLS_X509_EXT_KU_KEY_ENCIPHERMENT;
    }
    if (expKuDataEncipherment) {
        keyUsage |= HITLS_X509_EXT_KU_DATA_ENCIPHERMENT;
    }
    if (expKuAgreement) {
        keyUsage |= HITLS_X509_EXT_KU_KEY_AGREEMENT;
    }
    if (expKuCertSign) {
        keyUsage |= HITLS_X509_EXT_KU_KEY_CERT_SIGN;
    }
    if (expKuCrlSign) {
        keyUsage |= HITLS_X509_EXT_KU_CRL_SIGN;
    }
    if (expKuEncipherOnly) {
        keyUsage |= HITLS_X509_EXT_KU_ENCIPHER_ONLY;
    }
    if (expKuDecipherOnly) {
        keyUsage |= HITLS_X509_EXT_KU_DECIPHER_ONLY;
    }
    uint32_t parsedKeyUsage = 0;
    HITLS_X509_ExtKeyUsage ku = {isCritical, keyUsage};
    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    BSL_Buffer data = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    dnList = GenDNList();
    
    // set keyUsage extension
    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, key), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage)), 0);

    // sign the cert
    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, NULL, cert), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, &algParam, cert), HITLS_PKI_SUCCESS);
    }
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path), HITLS_PKI_SUCCESS);

    // cert print compare
    data.data = (uint8_t *)cert;
    data.dataLen = sizeof(HITLS_X509_Cert *);
    ASSERT_EQ(GetPrintBuff(&data, expectPath), 0);
    Hex expect = {(uint8_t *)expectPath, 0};
    ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);

    // cert parsed fields compare
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, 0), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_KUSAGE,
        &parsedKeyUsage, sizeof(parsedKeyUsage)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedKeyUsage, keyUsage);
    if (keyUsage != HITLS_X509_EXT_KU_NONE) {
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_DIGITAL_SIGN) != 0, expKuDigitailSign);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_NON_REPUDIATION) != 0, expKuNonRepudiation);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_KEY_ENCIPHERMENT) != 0, expKuKeyEncipherment);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_DATA_ENCIPHERMENT) != 0, expKuDataEncipherment);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_KEY_AGREEMENT) != 0, expKuAgreement);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_KEY_CERT_SIGN) != 0, expKuCertSign);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_CRL_SIGN) != 0, expKuCrlSign);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_ENCIPHER_ONLY) != 0, expKuEncipherOnly);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_DECIPHER_ONLY) != 0, expKuDecipherOnly);
    }

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    remove(path);
    remove(expectPath);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_ILLEGAL_KUSAGE_GEN_TEST_TC001(int isCritical, int keyUsage, int algId, int curveId)
{
    HITLS_X509_Cert *cert = NULL;
    BslList *dnList = NULL;
    HITLS_X509_ExtKeyUsage ku = {isCritical, keyUsage};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    dnList = GenDNList();
    
    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, key), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE,
        &ku, sizeof(HITLS_X509_ExtKeyUsage)), HITLS_X509_ERR_EXT_KU);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_DnListFree(dnList);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_KUSAGE_PARSE_TEST_TC001(char *certPath, int isEdited, int expKuDigitailSign,
    int expKuNonRepudiation, int expKuKeyEncipherment, int expKuDataEncipherment, int expKuAgreement,
    int expKuCertSign, int expKuCrlSign, int expKuEncipherOnly, int expKuDecipherOnly)
{
    HITLS_X509_Cert *parsedCert = NULL;
    uint32_t parsedKeyUsage = 0;
    uint32_t expkeyUsage = 0;
    if (expKuDigitailSign) {
        expkeyUsage |= HITLS_X509_EXT_KU_DIGITAL_SIGN;
    }
    if (expKuNonRepudiation) {
        expkeyUsage |= HITLS_X509_EXT_KU_NON_REPUDIATION;
    }
    if (expKuKeyEncipherment) {
        expkeyUsage |= HITLS_X509_EXT_KU_KEY_ENCIPHERMENT;
    }
    if (expKuDataEncipherment) {
        expkeyUsage |= HITLS_X509_EXT_KU_DATA_ENCIPHERMENT;
    }
    if (expKuAgreement) {
        expkeyUsage |= HITLS_X509_EXT_KU_KEY_AGREEMENT;
    }
    if (expKuCertSign) {
        expkeyUsage |= HITLS_X509_EXT_KU_KEY_CERT_SIGN;
    }
    if (expKuCrlSign) {
        expkeyUsage |= HITLS_X509_EXT_KU_CRL_SIGN;
    }
    if (expKuEncipherOnly) {
        expkeyUsage |= HITLS_X509_EXT_KU_ENCIPHER_ONLY;
    }
    if (expKuDecipherOnly) {
        expkeyUsage |= HITLS_X509_EXT_KU_DECIPHER_ONLY;
    }
    BslList *dnList = GenDNList();
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, isEdited), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_KUSAGE,
        &parsedKeyUsage, sizeof(parsedKeyUsage)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedKeyUsage, expkeyUsage);
    if (expkeyUsage != HITLS_X509_EXT_KU_NONE) {
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_DIGITAL_SIGN) != 0, expKuDigitailSign);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_NON_REPUDIATION) != 0, expKuNonRepudiation);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_KEY_ENCIPHERMENT) != 0, expKuKeyEncipherment);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_DATA_ENCIPHERMENT) != 0, expKuDataEncipherment);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_KEY_AGREEMENT) != 0, expKuAgreement);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_KEY_CERT_SIGN) != 0, expKuCertSign);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_CRL_SIGN) != 0, expKuCrlSign);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_ENCIPHER_ONLY) != 0, expKuEncipherOnly);
        ASSERT_EQ((parsedKeyUsage & HITLS_X509_EXT_KU_DECIPHER_ONLY) != 0, expKuDecipherOnly);
    }

EXIT:
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_SAN_GEN_TEST_TC001(int isCritical, int algId, int hashId,
    int curveId, char *nameValue, int nameType)
{
    char *path = "tmp.cert";
    char *expectPath = "exp.cert";
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *parsedCert = NULL;
    BslList *dnList = NULL;
    BslList *list = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
    HITLS_X509_ExtSan san = {0};
    HITLS_X509_ExtSan parsedSan = {0};
    HITLS_X509_GeneralName *gn = NULL;
    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    BSL_Buffer data = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    // set subjetc alternative name extension
    dnList = GenDNList();
    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, key), 0);
    san.critical = isCritical;
    san.names = list;
    HITLS_X509_GeneralName generalName = {nameType, {(uint8_t *)nameValue, strlen(nameValue)}};
    ASSERT_EQ(BSL_LIST_AddElement(list, &generalName, BSL_LIST_POS_END), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SAN, &san, sizeof(HITLS_X509_ExtSan)), HITLS_PKI_SUCCESS);

    // sign the cert
    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, NULL, cert), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, &algParam, cert), HITLS_PKI_SUCCESS);
    }
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path), HITLS_PKI_SUCCESS);

    // cert print compare
    data.data = (uint8_t *)cert;
    data.dataLen = sizeof(HITLS_X509_Cert *);
    ASSERT_EQ(GetPrintBuff(&data, expectPath), 0);
    Hex expect = {(uint8_t *)expectPath, 0};
    ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);

    // cert parsed fields compare
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum,
        sizeof(g_serialNum), &g_beforeTime, &g_afterTime, dnList, dnList, 0), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_SAN,
        &parsedSan, sizeof(HITLS_X509_ExtSan)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedSan.critical, isCritical);
    ASSERT_EQ(BSL_LIST_COUNT(parsedSan.names), 1);
    gn = BSL_LIST_GET_FIRST(parsedSan.names);
    ASSERT_EQ(gn->type, nameType);
    ASSERT_EQ(gn->value.dataLen, generalName.value.dataLen);
    ASSERT_EQ(memcmp(gn->value.data, generalName.value.data, gn->value.dataLen), 0);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    HITLS_X509_ClearSubjectAltName(&parsedSan);
    BSL_LIST_FREE(list, FreeListData);
    remove(path);
    remove(expectPath);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_SAN_ALL_GEN_TEST_TC001(int isCritical, int algId, int hashId, int curveId)
{
    char *path = "tmp.cert";
    char *expectPath = "exp.cert";
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *parsedCert = NULL;
    BslList *dnList = NULL;
    HITLS_X509_ExtSan san = {0};
    HITLS_X509_ExtSan parsedSan = {0};
    HITLS_X509_GeneralName *gn = NULL;
    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    BSL_Buffer data = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    dnList = GenDNList();
    // set all options of subject anternative name
    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, key), 0);
    san.critical = isCritical;
    san.names = GenGeneralNameList();
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SAN, &san, sizeof(HITLS_X509_ExtSan)), HITLS_PKI_SUCCESS);

    // sign the cert
    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, NULL, cert), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, &algParam, cert), HITLS_PKI_SUCCESS);
    }
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path), HITLS_PKI_SUCCESS);

    // cert print compare
    data.data = (uint8_t *)cert;
    data.dataLen = sizeof(HITLS_X509_Cert *);
    ASSERT_EQ(GetPrintBuff(&data, expectPath), 0);
    Hex expect = {(uint8_t *)expectPath, 0};
    ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);

    // cert parsed fields compare
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, 0), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_SAN,
        &parsedSan, sizeof(HITLS_X509_ExtSan)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedSan.critical, isCritical);
    int nameNum = 5;
    ASSERT_EQ(BSL_LIST_COUNT(san.names), nameNum);
    gn = BSL_LIST_GET_FIRST(parsedSan.names);
    char *str = "test";
    char *emailstr = "Wllill@163.com";
    while (gn != NULL) {
        if (gn->type == HITLS_X509_GN_DNNAME) {
            ASSERT_EQ(CompareDNLists((BslList *)gn->value.data, dnList), 0);
            gn = BSL_LIST_GET_NEXT(parsedSan.names);
            continue;
        }
        if (gn->type == HITLS_X509_GN_EMAIL) {
            ASSERT_COMPARE("email", gn->value.data, gn->value.dataLen, emailstr, strlen(emailstr));
            gn = BSL_LIST_GET_NEXT(parsedSan.names);
            continue;
        }
        ASSERT_COMPARE("generalName", gn->value.data, gn->value.dataLen, str, strlen(str));
        gn = BSL_LIST_GET_NEXT(parsedSan.names);
    }

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    BSL_LIST_FREE(san.names, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
    HITLS_X509_ClearSubjectAltName(&parsedSan);
    remove(path);
    remove(expectPath);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_ILLEGAL_SAN_GEN_TEST_TC001(int isCritical, int algId, int curveId)
{
    HITLS_X509_Cert *cert = NULL;
    BslList *dnList = NULL;
    BslList *list = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
    HITLS_X509_ExtSan san = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    dnList = GenDNList();

    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, key), 0);
    san.critical = isCritical;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SAN, &san,
        sizeof(HITLS_X509_ExtSan)), HITLS_X509_ERR_EXT_SAN); // list is null
    san.names = list;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SAN, &san,
        sizeof(HITLS_X509_ExtSan)), HITLS_X509_ERR_EXT_SAN); // list is empty
    char *email = "test@openhitls.com";
    HITLS_X509_GeneralName generalName = {HITLS_X509_GN_MAX, {(uint8_t *)email, (uint32_t)strlen(email)}};
    ASSERT_EQ(BSL_LIST_AddElement(list, &generalName, BSL_LIST_POS_END), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SAN, &san,
        sizeof(HITLS_X509_ExtSan)), HITLS_X509_ERR_EXT_GN_UNSUPPORT); // generalName with wrong type

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_DnListFree(dnList);
    BSL_LIST_FREE(list, FreeListData);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_SAN_PARSE_TEST_TC001(int isCritical, char *certPath,
    int isEdited, char *nameValue, int nameType)
{
    HITLS_X509_Cert *parsedCert = NULL;
    HITLS_X509_ExtSan parsedSan = {0};
    HITLS_X509_GeneralName *gn = NULL;
    BslList *dnList = GenDNList();
    uint32_t nameValueLen = (uint32_t)strlen(nameValue);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, isEdited), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_SAN,
        &parsedSan, sizeof(HITLS_X509_ExtSan)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedSan.critical, isCritical);
    ASSERT_EQ(BSL_LIST_COUNT(parsedSan.names), 1);
    gn = BSL_LIST_GET_FIRST(parsedSan.names);
    ASSERT_EQ(gn->type, nameType);
    ASSERT_EQ(gn->value.dataLen, nameValueLen);
    ASSERT_COMPARE("subject Alternative Name", gn->value.data, gn->value.dataLen, nameValue, nameValueLen);

EXIT:
    TestRandDeInit();
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    HITLS_X509_ClearSubjectAltName(&parsedSan);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_SAN_ALL_PARSE_TC001(int isCritical, char *certPath, int isEdited)
{
    HITLS_X509_Cert *parsedCert = NULL;
    HITLS_X509_ExtSan parsedSan = {0};
    HITLS_X509_GeneralName *gn = NULL;
    BslList *dnList = GenDNList();
    int nameNum = 5;

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, isEdited), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_SAN,
        &parsedSan, sizeof(HITLS_X509_ExtSan)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedSan.critical, isCritical);
    ASSERT_EQ(BSL_LIST_COUNT(parsedSan.names), nameNum);
    gn = BSL_LIST_GET_FIRST(parsedSan.names);
    while (gn != NULL) {
        if (gn->type == HITLS_X509_GN_EMAIL) {
            char *email = "test@openhitls.com";
            ASSERT_COMPARE("generalName email", gn->value.data, gn->value.dataLen,
                email, strlen(email));
        } else if (gn->type == HITLS_X509_GN_DNS) {
            char *dns = "test.openhitls.com";
            ASSERT_COMPARE("generalName dns", gn->value.data, gn->value.dataLen, dns, strlen(dns));
        } else if (gn->type == HITLS_X509_GN_DNNAME) {
            ASSERT_EQ(CompareDNLists((BslList *)gn->value.data, dnList), 0);
        } else if (gn->type == HITLS_X509_GN_URI) {
            char *uri = "https://test.openhitls.com";
            ASSERT_COMPARE("generalName uri", gn->value.data, gn->value.dataLen, uri, strlen(uri));
        } else {
            char *ip = "test";
            ASSERT_COMPARE("generalName ip", gn->value.data, gn->value.dataLen, ip, strlen(ip));
        }
        gn = BSL_LIST_GET_NEXT(parsedSan.names);
    }

EXIT:
    TestRandDeInit();
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    HITLS_X509_ClearSubjectAltName(&parsedSan);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_ILLEGAL_SAN_PARSE_TEST_TC001(int isCritical, char *certPath, int isEdited)
{
    HITLS_X509_Cert *parsedCert = NULL;
    HITLS_X509_ExtSan parsedSan = {0};
    HITLS_X509_GeneralName *gn = NULL;
    BslList *dnList = GenDNList();
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, isEdited), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_SAN,
        &parsedSan, sizeof(HITLS_X509_ExtSan)), HITLS_PKI_SUCCESS); // list is empty
    ASSERT_EQ(parsedSan.critical, isCritical);
    ASSERT_EQ(BSL_LIST_COUNT(parsedSan.names), 0);
    gn = BSL_LIST_GET_FIRST(parsedSan.names);
    ASSERT_EQ(gn, NULL);

EXIT:
    TestRandDeInit();
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    HITLS_X509_ClearSubjectAltName(&parsedSan);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_BCON_GEN_TEST_TC001(int isCritical, int isCa, int maxPathLen,
    int algId, int hashId, int curveId)
{
    char *path = "tmp.cert";
    char *expectPath = "exp.cert";
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *parsedCert = NULL;
    BslList *dnList = NULL;
    HITLS_X509_ExtBCons bCons = {isCritical, isCa, maxPathLen};
    HITLS_X509_ExtBCons parsedBCons = {0};
    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    BSL_Buffer data = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    dnList = GenDNList();

    // set basic constrains extension
    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, key), 0);
    HITLS_X509_Ext *ext = &cert->tbs.ext;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_BCONS,
        &bCons, sizeof(HITLS_X509_ExtBCons)), HITLS_PKI_SUCCESS);
    ASSERT_NE(ext->flag & HITLS_X509_EXT_FLAG_GEN, 0);

    // sign the cert
    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, NULL, cert), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, &algParam, cert), HITLS_PKI_SUCCESS);
    }
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path), HITLS_PKI_SUCCESS);

    // cert print compare
    data.data = (uint8_t *)cert;
    data.dataLen = sizeof(HITLS_X509_Cert *);
    ASSERT_EQ(GetPrintBuff(&data, expectPath), 0);
    Hex expect = {(uint8_t *)expectPath, 0};
    ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);

    // cert parsed fields compare
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, 0), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_BCONS,
        &parsedBCons, sizeof(HITLS_X509_ExtBCons)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBCons.critical, isCritical);
    ASSERT_EQ(parsedBCons.isCa, isCa);
    ASSERT_EQ(parsedBCons.maxPathLen, maxPathLen);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    remove(path);
    remove(expectPath);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_BCON_PARSE_TEST_TC001(int isCritical, int isCa, int maxPathLen, char *path, int isEdited)
{
    HITLS_X509_Cert *parsedCert = NULL;
    BslList *dnList = GenDNList();
    HITLS_X509_ExtBCons parsedBCons = {0};
    
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, isEdited), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_BCONS,
        &parsedBCons, sizeof(HITLS_X509_ExtBCons)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBCons.critical, isCritical);
    ASSERT_EQ(parsedBCons.isCa, isCa);
    ASSERT_EQ(parsedBCons.maxPathLen, maxPathLen);

EXIT:
    TestRandDeInit();
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_ILLEGAL_BCON_PARSE_TEST_TC001(char *path)
{
    HITLS_X509_Cert *parsedCert = NULL; // maxPathLen = -1
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_X509_ERR_PARSE_EXT_BUF);

EXIT:
    HITLS_X509_CertFree(parsedCert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_EXTKU_GEN_TEST_TC001(int isCritical, int oidNum, int algId, int hashId, int curveId)
{
    char *path = "tmp.cert";
    char *expectPath = "exp.cert";
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *parsedCert = NULL;
    BslList *dnList = NULL;
    HITLS_X509_ExtExKeyUsage exku = {0};
    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    BSL_Buffer data = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    BslList *oidList = BSL_LIST_New(sizeof(BSL_Buffer));
    ASSERT_NE(oidList, NULL);
    dnList = GenDNList();

    // set extended keyUsage extension
    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, key), 0);
    HITLS_X509_Ext *ext = &cert->tbs.ext;
    exku.critical = isCritical;
    exku.oidList = oidList;
    int cur = 0;
    BslOidString *oid[6];
    BSL_Buffer oidBuff[6];
    oid[cur++] = BSL_OBJ_GetOID(BSL_CID_KP_SERVERAUTH);
    oid[cur++] = BSL_OBJ_GetOID(BSL_CID_KP_CLIENTAUTH);
    oid[cur++] = BSL_OBJ_GetOID(BSL_CID_KP_CODESIGNING);
    oid[cur++] = BSL_OBJ_GetOID(BSL_CID_KP_EMAILPROTECTION);
    oid[cur++] = BSL_OBJ_GetOID(BSL_CID_KP_TIMESTAMPING);
    oid[cur++] = BSL_OBJ_GetOID(BSL_CID_KP_OCSPSIGNING);
    for (int i = 0; i < oidNum; i++) {
        ASSERT_NE(oid[i], NULL);
        oidBuff[i].data = (uint8_t *)oid[i]->octs;
        oidBuff[i].dataLen = (uint32_t)oid[i]->octetLen;
        ASSERT_EQ(BSL_LIST_AddElement(oidList, &oidBuff[i], BSL_LIST_POS_END), 0);
    }
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_EXKUSAGE,
        &exku, sizeof(HITLS_X509_ExtExKeyUsage)), HITLS_PKI_SUCCESS);
    ASSERT_NE(ext->flag & HITLS_X509_EXT_FLAG_GEN, 0);

    // sign the cert
    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, NULL, cert), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, &algParam, cert), HITLS_PKI_SUCCESS);
    }
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path), HITLS_PKI_SUCCESS);

    // cert print compare
    data.data = (uint8_t *)cert;
    data.dataLen = sizeof(HITLS_X509_Cert *);
    ASSERT_EQ(GetPrintBuff(&data, expectPath), 0);
    Hex expect = {(uint8_t *)expectPath, 0};
    ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);

    // cert parsed fields compare
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, 0), 0);
    HITLS_X509_CertExt *parsedExt = (HITLS_X509_CertExt *)parsedCert->tbs.ext.extData;
    ASSERT_EQ(parsedExt->exKeyUsage.critical, isCritical);
    ASSERT_EQ(BSL_LIST_COUNT(parsedExt->exKeyUsage.oidList), oidNum);
    uint32_t idx = 0;
    for (BSL_Buffer *dataOid = BSL_LIST_GET_FIRST(parsedExt->exKeyUsage.oidList); dataOid != NULL;
        dataOid = BSL_LIST_GET_NEXT(parsedExt->exKeyUsage.oidList), idx ++) {
        ASSERT_COMPARE("Extedned key usage", oidBuff[idx].data, oidBuff[idx].dataLen, dataOid->data, dataOid->dataLen);
    }

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    BSL_LIST_DeleteAll(oidList, FreeListData);
    BSL_SAL_Free(oidList);
    remove(path);
    remove(expectPath);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_EXTKU_WITH_ANYKU_GEN_TEST_TC001(int isCritical, int algId, int hashId, int curveId)
{
    char *path = "tmp.cert";
    char *expectPath = "exp.cert";
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *parsedCert = NULL;
    BslList *dnList = NULL;
    HITLS_X509_ExtExKeyUsage exku = {0};
    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    BSL_Buffer data = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    BslList *oidList = BSL_LIST_New(sizeof(BSL_Buffer));
    ASSERT_NE(oidList, NULL);
    dnList = GenDNList();
    
    // set all purpose of extended keyUsage extension
    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, key), 0);
    HITLS_X509_Ext *ext = &cert->tbs.ext;
    exku.critical = isCritical;
    exku.oidList = oidList;
    BslOidString *oid = BSL_OBJ_GetOID(BSL_CID_ANYEXTENDEDKEYUSAGE);
    BSL_Buffer oidBuff = {(uint8_t *)oid->octs, (uint32_t)oid->octetLen};
    ASSERT_EQ(BSL_LIST_AddElement(oidList, &oidBuff, BSL_LIST_POS_END), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_EXKUSAGE,
        &exku, sizeof(HITLS_X509_ExtExKeyUsage)), HITLS_PKI_SUCCESS);
    ASSERT_NE(ext->flag & HITLS_X509_EXT_FLAG_GEN, 0);

    // sign the cert
    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, NULL, cert), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, &algParam, cert), HITLS_PKI_SUCCESS);
    }
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path), HITLS_PKI_SUCCESS);

    // cert print compare
    data.data = (uint8_t *)cert;
    data.dataLen = sizeof(HITLS_X509_Cert *);
    ASSERT_EQ(GetPrintBuff(&data, expectPath), 0);
    Hex expect = {(uint8_t *)expectPath, 0};
    ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);

    // cert parsed fields compare
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, 0), 0);
    HITLS_X509_CertExt *parsedExt = parsedExt = (HITLS_X509_CertExt *)parsedCert->tbs.ext.extData;
    ASSERT_EQ(parsedExt->exKeyUsage.critical, isCritical);
    ASSERT_EQ(BSL_LIST_COUNT(parsedExt->exKeyUsage.oidList), 1);
    BSL_Buffer *dataOid = BSL_LIST_GET_FIRST(parsedExt->exKeyUsage.oidList);
    ASSERT_COMPARE("Extedned key usage", oidBuff.data, oidBuff.dataLen, dataOid->data, dataOid->dataLen);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    BSL_LIST_DeleteAll(oidList, FreeListData);
    BSL_SAL_Free(oidList);
    remove(path);
    remove(expectPath);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_ILLEGAL_EXTKU_GEN_TEST_TC001(int isCritical, int algId, int curveId)
{
    HITLS_X509_Cert *cert = NULL;
    BslList *dnList = NULL;
    HITLS_X509_ExtExKeyUsage exku = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    BslList *oidList = BSL_LIST_New(sizeof(BSL_Buffer));
    ASSERT_NE(oidList, NULL);

    dnList = GenDNList();
    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, key), 0);
    exku.critical = isCritical;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_EXKUSAGE, &exku,
        sizeof(HITLS_X509_ExtExKeyUsage)), HITLS_X509_ERR_EXT_EXTENDED_KU); // exku->oidList is NULL
    exku.oidList = oidList;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_EXKUSAGE, &exku,
        sizeof(HITLS_X509_ExtExKeyUsage)), HITLS_X509_ERR_EXT_EXTENDED_KU); // exku->oidList is Empty

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_DnListFree(dnList);
    BSL_LIST_DeleteAll(oidList, FreeListData);
    BSL_SAL_Free(oidList);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_EXTKU_PARSE_TEST_TC001(int isCritical, int oidNum, char *path, int isEdited)
{
    HITLS_X509_Cert *parsedCert = NULL;
    HITLS_X509_CertExt *parsedExt = NULL;
    BslList *dnList = GenDNList();
    BslList *oidList = BSL_LIST_New(sizeof(BSL_Buffer));
    ASSERT_NE(oidList, NULL);
    int cur = 0;
    BslOidString *oid[6];
    BSL_Buffer oidBuff[6];
    oid[cur++] = BSL_OBJ_GetOID(BSL_CID_KP_SERVERAUTH);
    oid[cur++] = BSL_OBJ_GetOID(BSL_CID_KP_CLIENTAUTH);
    oid[cur++] = BSL_OBJ_GetOID(BSL_CID_KP_CODESIGNING);
    oid[cur++] = BSL_OBJ_GetOID(BSL_CID_KP_EMAILPROTECTION);
    oid[cur++] = BSL_OBJ_GetOID(BSL_CID_KP_TIMESTAMPING);
    oid[cur++] = BSL_OBJ_GetOID(BSL_CID_KP_OCSPSIGNING);
    for (int i = 0; i < oidNum; i++) {
        ASSERT_NE(oid[i], NULL);
        oidBuff[i].data = (uint8_t *)oid[i]->octs;
        oidBuff[i].dataLen = (uint32_t)oid[i]->octetLen;
        ASSERT_EQ(BSL_LIST_AddElement(oidList, &oidBuff[i], BSL_LIST_POS_END), 0);
    }

    // cert parsed fields compare
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum,
        sizeof(g_serialNum), &g_beforeTime, &g_afterTime, dnList, dnList, isEdited), 0);
    parsedExt = (HITLS_X509_CertExt *)parsedCert->tbs.ext.extData;
    ASSERT_EQ(parsedExt->exKeyUsage.critical, isCritical);
    ASSERT_EQ(BSL_LIST_COUNT(parsedExt->exKeyUsage.oidList), oidNum);
    uint32_t idx = 0;
    for (BSL_Buffer *data = BSL_LIST_GET_FIRST(parsedExt->exKeyUsage.oidList); data != NULL;
        data = BSL_LIST_GET_NEXT(parsedExt->exKeyUsage.oidList), idx ++) {
        ASSERT_COMPARE("Extedned key usage", oidBuff[idx].data, oidBuff[idx].dataLen, data->data, data->dataLen);
    }

EXIT:
    TestRandDeInit();
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    BSL_LIST_DeleteAll(oidList, FreeListData);
    BSL_SAL_Free(oidList);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_EXTKU_WITH_ANYKU_PARSE_TEST_TC001(int isCritical, char *path, int isEdited)
{
    HITLS_X509_Cert *parsedCert = NULL;
    
    BslList *dnList = GenDNList();
    BslList *oidList = BSL_LIST_New(sizeof(BSL_Buffer));
    ASSERT_NE(oidList, NULL);
    BslOidString *oid = BSL_OBJ_GetOID(BSL_CID_ANYEXTENDEDKEYUSAGE);
    BSL_Buffer oidBuff = {(uint8_t *)oid->octs, (uint32_t)oid->octetLen};

    // cert parsed fields compare
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, isEdited), 0);
    HITLS_X509_CertExt *parsedExt = (HITLS_X509_CertExt *)parsedCert->tbs.ext.extData;
    ASSERT_EQ(parsedExt->exKeyUsage.critical, isCritical);
    ASSERT_EQ(BSL_LIST_COUNT(parsedExt->exKeyUsage.oidList), 1);
    BSL_Buffer *data = BSL_LIST_GET_FIRST(parsedExt->exKeyUsage.oidList);
    ASSERT_COMPARE("Extedned key usage", oidBuff.data, oidBuff.dataLen, data->data, data->dataLen);

EXIT:
    TestRandDeInit();
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    BSL_LIST_DeleteAll(oidList, FreeListData);
    BSL_SAL_Free(oidList);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_DUPLICATE_EXT_GEN_TEST_TC001(int isCritical, Hex *kid, int algId, int hashId, int curveId)
{
    char *path = "tmp.cert";
    char *expectPath = "exp.cert";
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *parsedCert = NULL;
    HITLS_X509_ExtAki parsedAki = {0};
    BslList *dnList = NULL;
    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    BSL_Buffer data = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    dnList = GenDNList();
    ASSERT_NE(dnList, NULL);

    // set aki
    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, key), 0);
    HITLS_X509_Ext *ext = &cert->tbs.ext;
    HITLS_X509_ExtAki aki1 = {isCritical, {kid->x, kid->len}, NULL, {0}};
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_AKI, &aki1, sizeof(HITLS_X509_ExtAki)), HITLS_PKI_SUCCESS);
    // set aki once more
    HITLS_X509_ExtAki aki2 = {isCritical, {kid->x, kid->len}, NULL, {0}};
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_AKI, &aki2, sizeof(HITLS_X509_ExtAki)), HITLS_PKI_SUCCESS);
    ASSERT_NE(ext->flag & HITLS_X509_EXT_FLAG_GEN, 0);

    // sign the cert
    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, NULL, cert), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, &algParam, cert), HITLS_PKI_SUCCESS);
    }
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path), HITLS_PKI_SUCCESS);

    // cert print compare
    data.data = (uint8_t *)cert;
    data.dataLen = sizeof(HITLS_X509_Cert *);
    ASSERT_EQ(GetPrintBuff(&data, expectPath), 0);
    Hex expect = {(uint8_t *)expectPath, 0};
    ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);

    // cert parsed fields compare
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, 0), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_AKI,
        &parsedAki, sizeof(HITLS_X509_ExtAki)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedAki.critical, isCritical);
    ASSERT_COMPARE("Get parsedAki", parsedAki.kid.data, parsedAki.kid.dataLen, kid->x, kid->len);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    remove(path);
    remove(expectPath);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_DUP_EXTAKI_PARSE_TEST_TC001(char *certPath)
{
    HITLS_X509_Cert *parsedCert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &parsedCert), HITLS_X509_ERR_PARSE_EXT_REPEAT);
EXIT:
    HITLS_X509_CertFree(parsedCert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_ALL_EXT_GEN_TEST_TC001(Hex *kid, int algId, int hashId, int curveId)
{
    char *path = "tmp.cert";
    char *expectPath = "exp.cert";
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *parsedCert = NULL;
    HITLS_X509_ExtAki parsedAki = {0};
    HITLS_X509_ExtSki parsedSki = {0};
    HITLS_X509_ExtSan parsedSan = {0};
    HITLS_X509_ExtBCons parsedBCons = {0};
    uint32_t parsedKeyUsage = 0;
    BslList *dnList = NULL;
    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    BSL_Buffer data = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    dnList = GenDNList();
    ASSERT_NE(dnList, NULL);

    ASSERT_EQ(SetCertBasic(cert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, key), 0);

    // set aki
    HITLS_X509_Ext *ext = &cert->tbs.ext;
    HITLS_X509_ExtAki aki = {true, {kid->x, kid->len}, NULL, {0}};
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_AKI, &aki,
        sizeof(HITLS_X509_ExtAki)), HITLS_PKI_SUCCESS);

    // set ski
    HITLS_X509_ExtSki ski = {true, {kid->x, kid->len}};
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SKI, &ski,
        sizeof(HITLS_X509_ExtSki)), HITLS_PKI_SUCCESS);

    // set keyusage
    uint32_t ku = HITLS_X509_EXT_KU_DIGITAL_SIGN;
    HITLS_X509_ExtKeyUsage keyUsage = {true, ku};
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE,
        &keyUsage, sizeof(HITLS_X509_ExtKeyUsage)), HITLS_PKI_SUCCESS);

    // set san
    BslList *list = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
    ASSERT_NE(list, NULL);
    char *nameValue = "test@openhitls.com";
    HITLS_X509_GeneralName generalName = {HITLS_X509_GN_EMAIL, {(uint8_t *)nameValue, strlen(nameValue)}};
    ASSERT_EQ(BSL_LIST_AddElement(list, &generalName, BSL_LIST_POS_END), 0);
    HITLS_X509_ExtSan san = {true, list};
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SAN, &san, sizeof(HITLS_X509_ExtSan)), HITLS_PKI_SUCCESS);

    // set bcons
    HITLS_X509_ExtBCons bCons = {true, true, 1};
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_BCONS, &bCons,
        sizeof(HITLS_X509_ExtBCons)), HITLS_PKI_SUCCESS);

    // set extku
    BslList *oidList = BSL_LIST_New(sizeof(BSL_Buffer));
    ASSERT_NE(oidList, NULL);
    BslOidString *oid = BSL_OBJ_GetOID(BSL_CID_ANYEXTENDEDKEYUSAGE);
    BSL_Buffer oidBuff = {(uint8_t *)oid->octs, (uint32_t)oid->octetLen};
    ASSERT_EQ(BSL_LIST_AddElement(oidList, &oidBuff, BSL_LIST_POS_END), 0);
    HITLS_X509_ExtExKeyUsage exku = {true, oidList};
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_EXKUSAGE, &exku,
        sizeof(HITLS_X509_ExtExKeyUsage)), HITLS_PKI_SUCCESS);
    ASSERT_NE(ext->flag & HITLS_X509_EXT_FLAG_GEN, 0);

    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, NULL, cert), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, &algParam, cert), HITLS_PKI_SUCCESS);
    }
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path), HITLS_PKI_SUCCESS);

    // cert print compare
    data.data = (uint8_t *)cert;
    data.dataLen = sizeof(HITLS_X509_Cert *);
    ASSERT_EQ(GetPrintBuff(&data, expectPath), 0);
    Hex expect = {(uint8_t *)expectPath, 0};
    ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);

    // cert parsed fields compare
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_PKI_SUCCESS);

    // compare basic fields
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, 0), 0);

    // compare aki
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_AKI, &parsedAki,
        sizeof(HITLS_X509_ExtAki)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedAki.critical, true);
    ASSERT_COMPARE("Get parsedAki", parsedAki.kid.data, parsedAki.kid.dataLen, kid->x, kid->len);

    // compare ski
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_SKI, &parsedSki,
        sizeof(HITLS_X509_ExtSki)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedSki.critical, true);
    ASSERT_COMPARE("Get parsedAki", parsedSki.kid.data, parsedSki.kid.dataLen, kid->x, kid->len);

    // compare keyusage
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_KUSAGE, &parsedKeyUsage,
        sizeof(parsedKeyUsage)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedKeyUsage, HITLS_X509_EXT_KU_DIGITAL_SIGN);

    // compare san
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_SAN, &parsedSan,
        sizeof(HITLS_X509_ExtSan)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedSan.critical, true);
    ASSERT_EQ(BSL_LIST_COUNT(parsedSan.names), 1);
    HITLS_X509_GeneralName *gn = BSL_LIST_GET_FIRST(parsedSan.names);
    ASSERT_EQ(gn->type, HITLS_X509_GN_EMAIL);
    ASSERT_EQ(gn->value.dataLen, strlen(nameValue));
    ASSERT_COMPARE("subject Alternative Name", gn->value.data, gn->value.dataLen, nameValue, strlen(nameValue));

    // compare bcon
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_BCONS, &parsedBCons,
        sizeof(HITLS_X509_ExtBCons)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBCons.critical, true);
    ASSERT_EQ(parsedBCons.isCa, true);
    ASSERT_EQ(parsedBCons.maxPathLen, 1);

    // compare extku
    HITLS_X509_CertExt *parsedExt = (HITLS_X509_CertExt *)parsedCert->tbs.ext.extData;
    ASSERT_EQ(parsedExt->exKeyUsage.critical, true);
    ASSERT_EQ(BSL_LIST_COUNT(parsedExt->exKeyUsage.oidList), 1);
    BSL_Buffer *OidData = BSL_LIST_GET_FIRST(parsedExt->exKeyUsage.oidList);
    ASSERT_COMPARE("Extedned key usage", oidBuff.data, oidBuff.dataLen, OidData->data, OidData->dataLen);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    HITLS_X509_ClearSubjectAltName(&parsedSan);
    BSL_LIST_FREE(oidList, FreeListData);
    BSL_LIST_FREE(list, FreeListData);
    BSL_SAL_FREE(oidList);
    BSL_SAL_FREE(list);
    remove(path);
    remove(expectPath);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_ALL_EXT_PARSE_TEST_TC001(Hex *kid, char *path, int isEdited)
{
    HITLS_X509_Cert *parsedCert = NULL;
    HITLS_X509_ExtAki parsedAki = {0};
    HITLS_X509_ExtSki parsedSki = {0};
    HITLS_X509_ExtSan parsedSan = {0};
    HITLS_X509_ExtBCons parsedBCons = {0};
    HITLS_X509_CertExt *parsedExt = NULL;
    uint32_t parsedKeyUsage = 0;
    BslList *dnList = GenDNList();
    char *nameValue = "test@openhitls.com";

    // cert parsed fields compare
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_PKI_SUCCESS);

    // compare basic fields
    ASSERT_EQ(parsedBasicFieldsCheck(parsedCert, g_version, g_serialNum, sizeof(g_serialNum),
        &g_beforeTime, &g_afterTime, dnList, dnList, isEdited), 0);

    // get aki
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_AKI, &parsedAki,
        sizeof(HITLS_X509_ExtAki)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedAki.critical, false);
    ASSERT_COMPARE("Get parsedAki", parsedAki.kid.data, parsedAki.kid.dataLen, kid->x, kid->len);

    // get ski
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_SKI, &parsedSki,
        sizeof(HITLS_X509_ExtSki)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedSki.critical, false);
    ASSERT_COMPARE("Get parsedAki", parsedSki.kid.data, parsedSki.kid.dataLen, kid->x, kid->len);

    // get keyusage
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_KUSAGE, &parsedKeyUsage,
        sizeof(parsedKeyUsage)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedKeyUsage, HITLS_X509_EXT_KU_NON_REPUDIATION);

    // get san
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_SAN, &parsedSan,
        sizeof(HITLS_X509_ExtSan)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedSan.critical, false);
    ASSERT_EQ(BSL_LIST_COUNT(parsedSan.names), 1);
    HITLS_X509_GeneralName *gn = BSL_LIST_GET_FIRST(parsedSan.names);
    ASSERT_EQ(gn->type, HITLS_X509_GN_EMAIL);
    ASSERT_EQ(gn->value.dataLen, strlen(nameValue));
    ASSERT_COMPARE("subject Alternative Name", gn->value.data, gn->value.dataLen, nameValue, strlen(nameValue));

    // get bcon
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_BCONS, &parsedBCons,
        sizeof(HITLS_X509_ExtBCons)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedBCons.critical, true);
    ASSERT_EQ(parsedBCons.isCa, true);
    ASSERT_EQ(parsedBCons.maxPathLen, 1);

    // get extku
    parsedExt = (HITLS_X509_CertExt *)parsedCert->tbs.ext.extData;
    BslOidString *oid = BSL_OBJ_GetOID(BSL_CID_ANYEXTENDEDKEYUSAGE);
    BSL_Buffer oidBuff = {(uint8_t *)oid->octs, (uint32_t)oid->octetLen};
    ASSERT_EQ(parsedExt->exKeyUsage.critical, false);
    ASSERT_EQ(BSL_LIST_COUNT(parsedExt->exKeyUsage.oidList), 1);
    BSL_Buffer *OidData = BSL_LIST_GET_FIRST(parsedExt->exKeyUsage.oidList);
    ASSERT_COMPARE("Extedned key usage", oidBuff.data, oidBuff.dataLen, OidData->data, OidData->dataLen);

EXIT:
    TestRandDeInit();
    HITLS_X509_CertFree(parsedCert);
    HITLS_X509_DnListFree(dnList);
    HITLS_X509_ClearSubjectAltName(&parsedSan);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_WITH_CUSTOM_EXT_PARSE_TEST_TC001(char *path, Hex *customExtValue1, Hex *customExtValue2,
    char *exceptPrintFile, Hex *expectKeyUsage)
{
    HITLS_X509_Cert *parsedCert = NULL;
    BslCid keyUsageCid = BSL_CID_CE_KEYUSAGE;
    char *customOid1 = "1.2.3.4.5.6.7.8.9.1";
    char *customOid2 = "1.2.3.4.5.6.7.8.9.2";
    uint8_t *customOidData = NULL;
    uint32_t customOidLen = 0;
    BslOidString *keyUsageOid = NULL;
    HITLS_X509_ExtGeneric customExt = {0};
    HITLS_X509_ExtGeneric keyUsageExt = {0};
    BSL_Buffer data = {0};
    Hex expect = {(uint8_t *)exceptPrintFile, 0};

    TestMemInit();

    // SetUp
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &parsedCert), HITLS_PKI_SUCCESS);

    // Get and check custom ext 1
    customOidData = BSL_OBJ_GetOidFromNumericString(customOid1, strlen(customOid1), &customOidLen);
    ASSERT_NE(customOidData, NULL);
    customExt.oid.data = customOidData;
    customExt.oid.dataLen = customOidLen;
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_GENERIC, &customExt, sizeof(HITLS_X509_ExtGeneric)),
        HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("custom ext1", customExt.value.data, customExt.value.dataLen, customExtValue1->x,
        customExtValue1->len);
    ASSERT_EQ(customExt.critical, true);
    BSL_SAL_FREE(customOidData);
    BSL_SAL_FREE(customExt.value.data);

    // Get and check custom ext 2
    customOidData = BSL_OBJ_GetOidFromNumericString(customOid2, strlen(customOid2), &customOidLen);
    ASSERT_NE(customOidData, NULL);
    customExt.oid.data = customOidData;
    customExt.oid.dataLen = customOidLen;
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_GENERIC, &customExt, sizeof(HITLS_X509_ExtGeneric)),
        HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("custom ext2", customExt.value.data, customExt.value.dataLen, customExtValue2->x,
        customExtValue2->len);
    ASSERT_EQ(customExt.critical, false);

    // Get keyusage byt HITLS_X509_EXT_GET_GENERIC
    keyUsageOid = BSL_OBJ_GetOID(keyUsageCid);
    keyUsageExt.oid.data = (uint8_t *)keyUsageOid->octs;
    keyUsageExt.oid.dataLen = keyUsageOid->octetLen;
    ASSERT_EQ(HITLS_X509_CertCtrl(parsedCert, HITLS_X509_EXT_GET_GENERIC, &keyUsageExt, sizeof(HITLS_X509_ExtGeneric)),
        HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("key usage", keyUsageExt.value.data, keyUsageExt.value.dataLen, expectKeyUsage->x,
        expectKeyUsage->len);

    // Print cert buffer compare
    data.data = (uint8_t *)parsedCert;
    data.dataLen = sizeof(HITLS_X509_Cert *);
    ASSERT_EQ(PrintBuffTest(HITLS_PKI_PRINT_CERT, &data, "Print cert buffer", &expect, true), 0);

EXIT:
    HITLS_X509_CertFree(parsedCert);
    BSL_SAL_FREE(customOidData);
    BSL_SAL_FREE(customExt.value.data);
    BSL_SAL_FREE(keyUsageExt.value.data);
}
/* END_CASE */

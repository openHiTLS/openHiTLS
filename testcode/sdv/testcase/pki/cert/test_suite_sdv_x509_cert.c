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

#include "bsl_sal.h"
#include "securec.h"
#include "stub_utils.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_csr.h"
#include "hitls_pki_errno.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "hitls_pki_utils.h"
#include "hitls_pki_types.h"
#include "bsl_types.h"
#include "bsl_log.h"
#include "hitls_cert_local.h"
#include "bsl_init.h"
#include "bsl_obj_internal.h"
#include "sal_time.h"
#include "sal_file.h"
#include "crypt_codecskey.h"
#include "crypt_eal_codecs.h"
#include "hitls_x509_local.h"
#include "stub_utils.h"

/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
#if defined(HITLS_PKI_X509_CRT_PARSE) && defined(HITLS_CRYPTO_PROVIDER)
STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);
#endif
STUB_DEFINE_RET2(int32_t, HITLS_X509_ParseCertTbs, BSL_ASN1_Buffer *, HITLS_X509_Cert *);

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_FUNC_TC001(int format, char *path)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_Cert *cert = NULL;
    int32_t ret = HITLS_X509_CertParseFile(format, path, &cert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_PUBKEY_FUNC_TC002(int format, char *path, Hex *key)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(format, path, &cert), HITLS_PKI_SUCCESS);
    void *pkey = cert->tbs.ealPubKey;
    uint8_t buf[68] = {0};
    CRYPT_EAL_PkeyPub pubKey = {.id = CRYPT_PKEY_XMSS, .key.xmssPub = {.seed = buf + 4 + 32,
        .root = buf + 4, .len = 32}};
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("root", pubKey.key.xmssPub.root, 32, key->x + 4, (key->len - 4) / 2);
    ASSERT_COMPARE("seed", pubKey.key.xmssPub.seed, 32, key->x + 36, (key->len - 4) / 2);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_XMSS_XDR_ALG_TYPE, buf, 4), HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("xdr", buf, 4, key->x, 4);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_VERSION_FUNC_TC001(char *path, int version)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(cert->tbs.version, version);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SERIALNUM_FUNC_TC001(char *path, Hex *serialNum)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(cert->tbs.serialNum.tag, 2);
    ASSERT_COMPARE("serialNum", cert->tbs.serialNum.buff, cert->tbs.serialNum.len,
        serialNum->x, serialNum->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_TBS_SIGNALG_FUNC_TC001(char *path, int signAlg,
    int rsaPssHash, int rsaPssMgf1, int rsaPssSaltLen)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);

    ASSERT_EQ(cert->tbs.signAlgId.algId, signAlg);
    ASSERT_EQ(cert->tbs.signAlgId.rsaPssParam.mdId, rsaPssHash);
    ASSERT_EQ(cert->tbs.signAlgId.rsaPssParam.mgfId, rsaPssMgf1);
    ASSERT_EQ(cert->tbs.signAlgId.rsaPssParam.saltLen, rsaPssSaltLen);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_ISSUERNAME_FUNC_TC001(char *path, int count,
    Hex *type1, int tag1, Hex *value1,
    Hex *type2, int tag2, Hex *value2,
    Hex *type3, int tag3, Hex *value3,
    Hex *type4, int tag4, Hex *value4,
    Hex *type5, int tag5, Hex *value5,
    Hex *type6, int tag6, Hex *value6)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);

    BSL_ASN1_Buffer expAsan1Arr[] = {
        {6, type1->len, type1->x}, {(uint8_t)tag1, value1->len, value1->x},
        {6, type2->len, type2->x}, {(uint8_t)tag2, value2->len, value2->x},
        {6, type3->len, type3->x}, {(uint8_t)tag3, value3->len, value3->x},
        {6, type4->len, type4->x}, {(uint8_t)tag4, value4->len, value4->x},
        {6, type5->len, type5->x}, {(uint8_t)tag5, value5->len, value5->x},
        {6, type6->len, type6->x}, {(uint8_t)tag6, value6->len, value6->x},
    };
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.issuerName), count);
    HITLS_X509_NameNode **nameNode = NULL;
    nameNode = BSL_LIST_First(cert->tbs.issuerName);
    for (int i = 0; i < count; i += 2) {
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 1);
        ASSERT_EQ((*nameNode)->nameType.tag, 0);
        ASSERT_EQ((*nameNode)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode)->nameType.len, 0);
        ASSERT_EQ((*nameNode)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode)->nameValue.len, 0);

        nameNode = BSL_LIST_Next(cert->tbs.issuerName);
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 2);
        ASSERT_EQ((*nameNode)->nameType.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("nameType", (*nameNode)->nameType.buff, (*nameNode)->nameType.len,
            expAsan1Arr[i].buff, expAsan1Arr[i].len);

        ASSERT_EQ((*nameNode)->nameValue.tag, expAsan1Arr[i + 1].tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode)->nameValue.buff, (*nameNode)->nameValue.len,
            expAsan1Arr[i + 1].buff, expAsan1Arr[i + 1].len);
        nameNode = BSL_LIST_Next(cert->tbs.issuerName);
    }
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_ISSUERNAME_FUNC_TC002(char *path, int count,
    Hex *type1, int tag1, Hex *value1)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    BSL_ASN1_Buffer expAsan1Arr[] = {
        {6, type1->len, type1->x}, {(uint8_t)tag1, value1->len, value1->x}
    };
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.issuerName), count);
    HITLS_X509_NameNode **nameNode = NULL;
    nameNode = BSL_LIST_First(cert->tbs.issuerName);
    for (int i = 0; i < count; i += 2) {
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 1);
        ASSERT_EQ((*nameNode)->nameType.tag, 0);
        ASSERT_EQ((*nameNode)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode)->nameType.len, 0);
        ASSERT_EQ((*nameNode)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode)->nameValue.len, 0);

        nameNode = BSL_LIST_Next(cert->tbs.issuerName);
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 2);
        ASSERT_EQ((*nameNode)->nameType.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("nameType", (*nameNode)->nameType.buff, (*nameNode)->nameType.len,
            expAsan1Arr[i].buff, expAsan1Arr[i].len);

        ASSERT_EQ((*nameNode)->nameValue.tag, expAsan1Arr[i + 1].tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode)->nameValue.buff, (*nameNode)->nameValue.len,
            expAsan1Arr[i + 1].buff, expAsan1Arr[i + 1].len);
        nameNode = BSL_LIST_Next(cert->tbs.issuerName);
    }
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_ISSUERNAME_FUNC_TC003(char *path, int count,
    Hex *type1, int tag1, Hex *value1,
    Hex *type2, int tag2, Hex *value2,
    Hex *type3, int tag3, Hex *value3,
    Hex *type4, int tag4, Hex *value4,
    Hex *type5, int tag5, Hex *value5)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);

    BSL_ASN1_Buffer expAsan1Arr[] = {
        {6, type1->len, type1->x}, {(uint8_t)tag1, value1->len, value1->x},
        {6, type2->len, type2->x}, {(uint8_t)tag2, value2->len, value2->x},
        {6, type3->len, type3->x}, {(uint8_t)tag3, value3->len, value3->x},
        {6, type4->len, type4->x}, {(uint8_t)tag4, value4->len, value4->x},
        {6, type5->len, type5->x}, {(uint8_t)tag5, value5->len, value5->x}
    };
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.issuerName), count);
    HITLS_X509_NameNode **nameNode = NULL;
    nameNode = BSL_LIST_First(cert->tbs.issuerName);
    for (int i = 0; i < count; i += 2) {
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 1);
        ASSERT_EQ((*nameNode)->nameType.tag, 0);
        ASSERT_EQ((*nameNode)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode)->nameType.len, 0);
        ASSERT_EQ((*nameNode)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode)->nameValue.len, 0);

        nameNode = BSL_LIST_Next(cert->tbs.issuerName);
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 2);
        ASSERT_EQ((*nameNode)->nameType.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("nameType", (*nameNode)->nameType.buff, (*nameNode)->nameType.len,
            expAsan1Arr[i].buff, expAsan1Arr[i].len);

        ASSERT_EQ((*nameNode)->nameValue.tag, expAsan1Arr[i + 1].tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode)->nameValue.buff, (*nameNode)->nameValue.len,
            expAsan1Arr[i + 1].buff, expAsan1Arr[i + 1].len);
        nameNode = BSL_LIST_Next(cert->tbs.issuerName);
    }
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_TIME_FUNC_TC001(char *path)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_X509_ERR_CHECK_TAG);

EXIT:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_START_TIME_FUNC_TC001(char *path,
    int year, int month, int day, int hour, int minute, int second)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);

    ASSERT_EQ(cert->tbs.validTime.start.year, year);
    ASSERT_EQ(cert->tbs.validTime.start.month, month);
    ASSERT_EQ(cert->tbs.validTime.start.day, day);
    ASSERT_EQ(cert->tbs.validTime.start.hour, hour);
    ASSERT_EQ(cert->tbs.validTime.start.minute, minute);
    ASSERT_EQ(cert->tbs.validTime.start.second, second);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERTPEM_PARSE_START_TIME_FUNC_TC001(char *path,
    int year, int month, int day, int hour, int minute, int second)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, path, &cert), HITLS_PKI_SUCCESS);

    ASSERT_EQ(cert->tbs.validTime.start.year, year);
    ASSERT_EQ(cert->tbs.validTime.start.month, month);
    ASSERT_EQ(cert->tbs.validTime.start.day, day);
    ASSERT_EQ(cert->tbs.validTime.start.hour, hour);
    ASSERT_EQ(cert->tbs.validTime.start.minute, minute);
    ASSERT_EQ(cert->tbs.validTime.start.second, second);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERTPEM_PARSE_END_TIME_FUNC_TC001(char *path,
    int year, int month, int day, int hour, int minute, int second)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_PEM, path, &cert), HITLS_PKI_SUCCESS);

    ASSERT_EQ(cert->tbs.validTime.end.year, year);
    ASSERT_EQ(cert->tbs.validTime.end.month, month);
    ASSERT_EQ(cert->tbs.validTime.end.day, day);
    ASSERT_EQ(cert->tbs.validTime.end.hour, hour);
    ASSERT_EQ(cert->tbs.validTime.end.minute, minute);
    ASSERT_EQ(cert->tbs.validTime.end.second, second);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_END_TIME_FUNC_TC001(char *path,
    int year, int month, int day, int hour, int minute, int second)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);

    ASSERT_EQ(cert->tbs.validTime.end.year, year);
    ASSERT_EQ(cert->tbs.validTime.end.month, month);
    ASSERT_EQ(cert->tbs.validTime.end.day, day);
    ASSERT_EQ(cert->tbs.validTime.end.hour, hour);
    ASSERT_EQ(cert->tbs.validTime.end.minute, minute);
    ASSERT_EQ(cert->tbs.validTime.end.second, second);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SUBJECTNAME_FUNC_TC001(char *path, int count,
    Hex *type1, int tag1, Hex *value1,
    Hex *type2, int tag2, Hex *value2,
    Hex *type3, int tag3, Hex *value3,
    Hex *type4, int tag4, Hex *value4,
    Hex *type5, int tag5, Hex *value5,
    Hex *type6, int tag6, Hex *value6)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);

    BSL_ASN1_Buffer expAsan1Arr[] = {
        {6, type1->len, type1->x}, {(uint8_t)tag1, value1->len, value1->x},
        {6, type2->len, type2->x}, {(uint8_t)tag2, value2->len, value2->x},
        {6, type3->len, type3->x}, {(uint8_t)tag3, value3->len, value3->x},
        {6, type4->len, type4->x}, {(uint8_t)tag4, value4->len, value4->x},
        {6, type5->len, type5->x}, {(uint8_t)tag5, value5->len, value5->x},
        {6, type6->len, type6->x}, {(uint8_t)tag6, value6->len, value6->x},
    };
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.subjectName), count);
    HITLS_X509_NameNode **nameNode = NULL;
    nameNode = BSL_LIST_First(cert->tbs.subjectName);
    for (int i = 0; i < count; i += 2) {
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 1);
        ASSERT_EQ((*nameNode)->nameType.tag, 0);
        ASSERT_EQ((*nameNode)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode)->nameType.len, 0);
        ASSERT_EQ((*nameNode)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode)->nameValue.len, 0);

        nameNode = BSL_LIST_Next(cert->tbs.subjectName);
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 2);
        ASSERT_EQ((*nameNode)->nameType.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("nameType", (*nameNode)->nameType.buff, (*nameNode)->nameType.len,
            expAsan1Arr[i].buff, expAsan1Arr[i].len);

        ASSERT_EQ((*nameNode)->nameValue.tag, expAsan1Arr[i + 1].tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode)->nameValue.buff, (*nameNode)->nameValue.len,
            expAsan1Arr[i + 1].buff, expAsan1Arr[i + 1].len);
        nameNode = BSL_LIST_Next(cert->tbs.subjectName);
    }
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SUBJECTNAME_FUNC_TC002(char *path, int count,
    Hex *type1, int tag1, Hex *value1)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);

    BSL_ASN1_Buffer expAsan1Arr[] = {
        {6, type1->len, type1->x}, {(uint8_t)tag1, value1->len, value1->x}
    };
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.subjectName), count);
    HITLS_X509_NameNode **nameNode = NULL;
    nameNode = BSL_LIST_First(cert->tbs.subjectName);
    for (int i = 0; i < count; i += 2) {
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 1);
        ASSERT_EQ((*nameNode)->nameType.tag, 0);
        ASSERT_EQ((*nameNode)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode)->nameType.len, 0);
        ASSERT_EQ((*nameNode)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode)->nameValue.len, 0);

        nameNode = BSL_LIST_Next(cert->tbs.subjectName);
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 2);
        ASSERT_EQ((*nameNode)->nameType.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("nameType", (*nameNode)->nameType.buff, (*nameNode)->nameType.len,
            expAsan1Arr[i].buff, expAsan1Arr[i].len);

        ASSERT_EQ((*nameNode)->nameValue.tag, expAsan1Arr[i + 1].tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode)->nameValue.buff, (*nameNode)->nameValue.len,
            expAsan1Arr[i + 1].buff, expAsan1Arr[i + 1].len);
        nameNode = BSL_LIST_Next(cert->tbs.subjectName);
    }
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SUBJECTNAME_FUNC_TC003(char *path, int count,
    Hex *type1, int tag1, Hex *value1,
    Hex *type2, int tag2, Hex *value2,
    Hex *type3, int tag3, Hex *value3,
    Hex *type4, int tag4, Hex *value4,
    Hex *type5, int tag5, Hex *value5)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);

    BSL_ASN1_Buffer expAsan1Arr[] = {
        {6, type1->len, type1->x}, {(uint8_t)tag1, value1->len, value1->x},
        {6, type2->len, type2->x}, {(uint8_t)tag2, value2->len, value2->x},
        {6, type3->len, type3->x}, {(uint8_t)tag3, value3->len, value3->x},
        {6, type4->len, type4->x}, {(uint8_t)tag4, value4->len, value4->x},
        {6, type5->len, type5->x}, {(uint8_t)tag5, value5->len, value5->x}
    };
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.subjectName), count);
    HITLS_X509_NameNode **nameNode = NULL;
    nameNode = BSL_LIST_First(cert->tbs.subjectName);
    for (int i = 0; i < count; i += 2) {
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 1);
        ASSERT_EQ((*nameNode)->nameType.tag, 0);
        ASSERT_EQ((*nameNode)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode)->nameType.len, 0);
        ASSERT_EQ((*nameNode)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode)->nameValue.len, 0);

        nameNode = BSL_LIST_Next(cert->tbs.subjectName);
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 2);
        ASSERT_EQ((*nameNode)->nameType.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("nameType", (*nameNode)->nameType.buff, (*nameNode)->nameType.len,
            expAsan1Arr[i].buff, expAsan1Arr[i].len);

        ASSERT_EQ((*nameNode)->nameValue.tag, expAsan1Arr[i + 1].tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode)->nameValue.buff, (*nameNode)->nameValue.len,
            expAsan1Arr[i + 1].buff, expAsan1Arr[i + 1].len);
        nameNode = BSL_LIST_Next(cert->tbs.subjectName);
    }
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_CTRL_FUNC_TC001(char *path, int expRawDataLen, int expSignAlg, int expSignMdAlg,
    int expKuDigitailSign, int expKuCertSign, int expKuKeyAgreement, int expKeyUsage)
{
    HITLS_X509_Cert *cert = NULL;
    uint32_t keyUsage = 0;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);
    int32_t rawDataLen;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ENCODELEN, &rawDataLen, sizeof(rawDataLen)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(rawDataLen, expRawDataLen);

    uint8_t *rawData = NULL;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ENCODE, &rawData, 0), HITLS_PKI_SUCCESS);
    ASSERT_NE(rawData, NULL);

    void *ealKey = NULL;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &ealKey, 0), HITLS_PKI_SUCCESS);
    ASSERT_NE(ealKey, NULL);
    CRYPT_EAL_PkeyFreeCtx(ealKey);

    int32_t alg = 0;
    int32_t mdAlg = 0;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SIGNALG, &alg, sizeof(alg)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(alg, expSignAlg);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SIGN_MDALG, &mdAlg, sizeof(mdAlg) - 1), HITLS_X509_ERR_INVALID_PARAM);
    TestErrClear();
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SIGN_MDALG, &mdAlg, sizeof(mdAlg)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(mdAlg, expSignMdAlg);

    int32_t ref = 0;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(ref)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(ref, 2);
    HITLS_X509_CertFree(cert);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_KUSAGE, &keyUsage, sizeof(keyUsage)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(keyUsage, expKeyUsage);
    if (expKeyUsage != HITLS_X509_EXT_KU_NONE) {
        ASSERT_EQ((keyUsage & HITLS_X509_EXT_KU_DIGITAL_SIGN) != 0, expKuDigitailSign);
        ASSERT_EQ((keyUsage & HITLS_X509_EXT_KU_KEY_CERT_SIGN) != 0, expKuCertSign);
        ASSERT_EQ((keyUsage & HITLS_X509_EXT_KU_KEY_AGREEMENT) != 0, expKuKeyAgreement);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_CTRL_FUNC_TC002(char *path, char *expectedSerialNum, char *expectedSubjectName,
    char *expectedIssueName, char *expectedBeforeTime, char *expectedAfterTime)
{
    HITLS_X509_Cert *cert = NULL;
    BSL_Buffer subjectName = { NULL, 0 };
    BSL_Buffer issuerName = { NULL, 0 };
    BSL_Buffer serialNum = { NULL, 0 };
    BSL_Buffer beforeTime = { NULL, 0 };
    BSL_Buffer afterTime = { NULL, 0 };

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SUBJECT_DN_STR, &subjectName, sizeof(BSL_Buffer)), 0);
    ASSERT_NE(subjectName.data, NULL);
    ASSERT_EQ(subjectName.dataLen, strlen(expectedSubjectName));
    ASSERT_EQ(strcmp((char *)subjectName.data, expectedSubjectName), 0);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN_STR, &issuerName, sizeof(BSL_Buffer)), 0);
    ASSERT_NE(issuerName.data, NULL);
    ASSERT_EQ(issuerName.dataLen, strlen(expectedIssueName));
    ASSERT_EQ(strcmp((char *)issuerName.data, expectedIssueName), 0);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM_STR, &serialNum, sizeof(BSL_Buffer)), 0);
    ASSERT_NE(serialNum.data, NULL);
    ASSERT_EQ(serialNum.dataLen, strlen(expectedSerialNum));
    ASSERT_EQ(strcmp((char *)serialNum.data, expectedSerialNum), 0);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_BEFORE_TIME_STR, &beforeTime, sizeof(BSL_Buffer)), 0);
    ASSERT_NE(beforeTime.data, NULL);
    ASSERT_EQ(beforeTime.dataLen, strlen(expectedBeforeTime));
    ASSERT_EQ(strcmp((char *)beforeTime.data, expectedBeforeTime), 0);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_AFTER_TIME_STR, &afterTime, sizeof(BSL_Buffer)), 0);
    ASSERT_NE(afterTime.data, NULL);
    ASSERT_EQ (afterTime.dataLen, strlen(expectedAfterTime));
    ASSERT_EQ(strcmp((char *)afterTime.data, expectedAfterTime), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
    BSL_SAL_FREE(subjectName.data);
    BSL_SAL_FREE(issuerName.data);
    BSL_SAL_FREE(serialNum.data);
    BSL_SAL_FREE(beforeTime.data);
    BSL_SAL_FREE(afterTime.data);
}

/* END_CASE */
// subkey
/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_PUBKEY_FUNC_TC001(char *path, char *path2)
{
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *cert2 = NULL;

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path2, &cert2), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CheckSignature(cert2->tbs.ealPubKey, cert->tbs.tbsRawData, cert->tbs.tbsRawDataLen,
        &cert->signAlgId, &cert->signature), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(cert2);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_DUP_FUNC_TC001(char *path, int expSignAlg,
    int expKuDigitailSign, int expKuCertSign, int expKuKeyAgreement, int expKeyUsage)
{
    uint32_t keyUsage = 0;
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *dest = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);

    dest = HITLS_X509_CertDup(cert);
    ASSERT_NE(dest, NULL);

    int32_t alg = 0;
    ASSERT_EQ(HITLS_X509_CertCtrl(dest, HITLS_X509_GET_SIGNALG, &alg, sizeof(alg)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(alg, expSignAlg);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_KUSAGE, &keyUsage, sizeof(keyUsage)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(keyUsage, expKeyUsage);
    if (expKeyUsage != HITLS_X509_EXT_KU_NONE) {
        ASSERT_EQ((keyUsage & HITLS_X509_EXT_KU_DIGITAL_SIGN) != 0, expKuDigitailSign);
        ASSERT_EQ((keyUsage & HITLS_X509_EXT_KU_KEY_CERT_SIGN) != 0, expKuCertSign);
        ASSERT_EQ((keyUsage & HITLS_X509_EXT_KU_KEY_AGREEMENT) != 0, expKuKeyAgreement);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(dest);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_EXT_ERROR_TC001(char *path, int ret)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), ret);

EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_EXTENSIONS_FUNC_TC001(char *path, int extNum, int isCA, int maxPathLen, int keyUsage,
    int cid1, Hex *oid1, int cr1, Hex *val1,
    int cid2, Hex *oid2, int cr2, Hex *val2,
    int cid3, Hex *oid3, int cr3, Hex *val3)
{
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_ExtEntry **node = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);
    HITLS_X509_CertExt *certExt = (HITLS_X509_CertExt *)cert->tbs.ext.extData;
    ASSERT_EQ(certExt->isCa, isCA);
    ASSERT_EQ(certExt->maxPathLen, maxPathLen);
    ASSERT_EQ(certExt->keyUsage, keyUsage);
    ASSERT_EQ(BSL_LIST_COUNT(cert->tbs.ext.extList), extNum);

    HITLS_X509_ExtEntry arr[] = {
        {cid1, {BSL_ASN1_TAG_OBJECT_ID, oid1->len, oid1->x}, cr1, {BSL_ASN1_TAG_OCTETSTRING, val1->len, val1->x}},
        {cid2, {BSL_ASN1_TAG_OBJECT_ID, oid2->len, oid2->x}, cr2, {BSL_ASN1_TAG_OCTETSTRING, val2->len, val2->x}},
        {cid3, {BSL_ASN1_TAG_OBJECT_ID, oid3->len, oid3->x}, cr3, {BSL_ASN1_TAG_OCTETSTRING, val3->len, val3->x}},
    };
    node = BSL_LIST_First(cert->tbs.ext.extList);
    for (int i = 0; i < 3; i++) { // Check the first 3 extensions
        ASSERT_NE((*node), NULL);
        ASSERT_EQ((*node)->critical, arr[i].critical);
        ASSERT_EQ((*node)->extnId.tag, arr[i].extnId.tag);
        ASSERT_COMPARE("oid", (*node)->extnId.buff, (*node)->extnId.len, arr[i].extnId.buff, arr[i].extnId.len);
        ASSERT_EQ((*node)->extnValue.tag, arr[i].extnValue.tag);
        ASSERT_COMPARE(
            "value", (*node)->extnValue.buff, (*node)->extnValue.len, arr[i].extnValue.buff, arr[i].extnValue.len);
        node = BSL_LIST_Next(cert->tbs.ext.extList);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

// sign alg
/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SIGNALG_FUNC_TC001(char *path, int signAlg,
    int rsaPssHash, int rsaPssMgf1, int rsaPssSaltLen)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);

    ASSERT_EQ(cert->signAlgId.algId, signAlg);
    ASSERT_EQ(cert->signAlgId.rsaPssParam.mdId, rsaPssHash);
    ASSERT_EQ(cert->signAlgId.rsaPssParam.mgfId, rsaPssMgf1);
    ASSERT_EQ(cert->signAlgId.rsaPssParam.saltLen, rsaPssSaltLen);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

// signature
/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_SIGNATURE_FUNC_TC001(char *path, Hex *buff, int unusedBits)
{
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(cert->signature.len, buff->len);
    ASSERT_COMPARE("signature", cert->signature.buff, cert->signature.len, buff->x, buff->len);
    ASSERT_EQ(cert->signature.unusedBits, unusedBits);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_MUL_CERT_PARSE_FUNC_TC001(int format, char *path, int certNum)
{
    TestMemInit();
    HITLS_X509_List *list = NULL;
    int32_t ret = HITLS_X509_CertParseBundleFile(format, path, &list);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(list), certNum);
EXIT:
    BSL_LIST_FREE(list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_BUNDLE_BUFF_FUNC_TC001(int format, char *path, int certNum)
{
    TestMemInit();
    HITLS_X509_List *list = NULL;
    BSL_Buffer encodeData = {0};
    
    // Read certificate bundle file into buffer
    ASSERT_EQ(BSL_SAL_ReadFile(path, &encodeData.data, &encodeData.dataLen), BSL_SUCCESS);
    
    // Parse certificates from buffer
    ASSERT_EQ(HITLS_X509_CertParseBundleBuff(format, &encodeData, &list), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(list), certNum);
    ASSERT_TRUE(TestIsErrStackEmpty());
    
EXIT:
    BSL_LIST_FREE(list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_SAL_Free(encodeData.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_PROVIDER_CERT_PARSE_BUNDLE_BUFF_FUNC_TC001(char *format, char *path, int certNum)
{
    TestMemInit();
    HITLS_X509_List *list = NULL;
    BSL_Buffer encodeData = {0};
    
    // Read certificate bundle file into buffer
    ASSERT_EQ(BSL_SAL_ReadFile(path, &encodeData.data, &encodeData.dataLen), BSL_SUCCESS);
    
    // Parse certificates from buffer using provider mechanism
    ASSERT_EQ(HITLS_X509_ProviderCertParseBundleBuff(NULL, NULL, format, &encodeData, &list), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(list), certNum);
    ASSERT_TRUE(TestIsErrStackEmpty());
    
EXIT:
    BSL_LIST_FREE(list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    BSL_SAL_Free(encodeData.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_SET_VERIOSN_FUNC_TC001(void)
{
    TestMemInit();
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_EQ(cert->tbs.version, HITLS_X509_VERSION_1);

    int32_t version = HITLS_X509_VERSION_2;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(int32_t)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(cert->tbs.version, version);

    version = HITLS_X509_VERSION_3;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(int32_t)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(cert->tbs.version, version);
    ASSERT_TRUE(TestIsErrStackEmpty());

    // valLen
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, 1), HITLS_X509_ERR_INVALID_PARAM);

    // val
    version = HITLS_X509_VERSION_3 + 1;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(int32_t)),
              HITLS_X509_ERR_INVALID_PARAM);

EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_SET_SERIAL_FUNC_TC001(Hex *serial)
{
    TestMemInit();
    uint8_t *val = serial->x;
    uint32_t valLen = serial->len;

    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_EQ(cert->tbs.serialNum.len, 0);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, val, 0), HITLS_X509_ERR_CERT_INVALID_SERIAL_NUM);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, val, valLen), HITLS_PKI_SUCCESS);
    ASSERT_EQ(cert->tbs.serialNum.len, valLen);
    ASSERT_COMPARE("serial", cert->tbs.serialNum.buff, valLen, val, valLen);

EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_SET_TIME_FUNC_TC001(void)
{
    TestMemInit();
    BSL_TIME time = {2024, 8, 22, 1, 1, 0, 1, 0};

    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    ASSERT_EQ(cert->tbs.validTime.flag, 0);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &time, 0), HITLS_X509_ERR_INVALID_PARAM);
    TestErrClear();

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &time, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE((cert->tbs.validTime.flag & BSL_TIME_BEFORE_SET) != 0);
    ASSERT_EQ(BSL_SAL_DateTimeCompare(&cert->tbs.validTime.start, &time, NULL), BSL_TIME_CMP_EQUAL);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &time, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE((cert->tbs.validTime.flag & BSL_TIME_AFTER_SET) != 0);
    ASSERT_EQ(BSL_SAL_DateTimeCompare(&cert->tbs.validTime.end, &time, NULL), BSL_TIME_CMP_EQUAL);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_ENCODE_CERT_EXT_TC001(char *path, Hex *expectExt)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_Cert *cert = NULL;
    BSL_ASN1_Buffer ext = {0};

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, path, &cert), HITLS_PKI_SUCCESS);
    uint8_t tag = 0xA3;
    ASSERT_EQ(HITLS_X509_EncodeExt(tag, cert->tbs.ext.extList, &ext), HITLS_PKI_SUCCESS);

    ASSERT_EQ(ext.len, expectExt->len);
    if (expectExt->len != 0) {
        ASSERT_EQ(ext.tag, tag);
        ASSERT_COMPARE("extensions", ext.buff, ext.len, expectExt->x, expectExt->len);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CertFree(cert);
    BSL_SAL_Free(ext.buff);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_GEN_BUFF_API_TC001(void)
{
    TestMemInit();
    BSL_GLOBAL_Init();

    BSL_Buffer buff = {0};
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_UNKNOWN, cert, &buff), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, NULL, &buff), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, NULL), HITLS_X509_ERR_INVALID_PARAM);

    cert->tbs.version = HITLS_X509_VERSION_1;
    cert->tbs.ext.extList->count = 1;
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &buff), HITLS_X509_ERR_CERT_NOT_SIGNED);

EXIT:
    HITLS_X509_CertFree(cert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_GEN_FILE_API_TC001(char *destPath)
{
    TestMemInit();

    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_TRUE(cert != NULL);

    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_UNKNOWN, cert, destPath), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, NULL, destPath), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, NULL), HITLS_X509_ERR_INVALID_PARAM);

EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_SIGN_API_TC001(void)
{
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_SignAlgParam algParam = {0};

    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);
    prvKey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_NE(prvKey, NULL);

    // Test null parameters
    ASSERT_EQ(HITLS_X509_CertSign(BSL_CID_SHA256, NULL, &algParam, cert), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertSign(BSL_CID_SHA256, prvKey, &algParam, NULL), HITLS_X509_ERR_INVALID_PARAM);

EXIT:
    HITLS_X509_CertFree(cert);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_FORMAT_CONVERT_FUNC_TC001(char *inCert, int inForm, char *outCert, int outForm)
{
    TestRandInit();
    HITLS_X509_Cert *cert = NULL;
    BSL_Buffer encodeCert = {0};
    BSL_Buffer expectCert = {0};

    ASSERT_EQ(HITLS_X509_CertParseFile(inForm, inCert, &cert), 0);
    ASSERT_EQ(BSL_SAL_ReadFile(outCert, &expectCert.data, &expectCert.dataLen), 0);
    ASSERT_EQ(HITLS_X509_CertGenBuff(outForm, cert, &encodeCert), 0);

    ASSERT_COMPARE("Format convert", expectCert.data, expectCert.dataLen, encodeCert.data, encodeCert.dataLen);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CertFree(cert);
    BSL_SAL_Free(expectCert.data);
    BSL_SAL_Free(encodeCert.data);
}
/* END_CASE */

static int32_t SetCert(HITLS_X509_Cert *raw, HITLS_X509_Cert *new)
{
    int32_t ret = 1;
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_VERSION, &raw->tbs.version, sizeof(int32_t)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_SERIALNUM, raw->tbs.serialNum.buff, raw->tbs.serialNum.len), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_BEFORE_TIME, &raw->tbs.validTime.start, sizeof(BSL_TIME)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_AFTER_TIME, &raw->tbs.validTime.end, sizeof(BSL_TIME)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_PUBKEY, raw->tbs.ealPubKey, sizeof(void *)), 0);

    BslList *rawSubject = NULL;
    ASSERT_EQ(HITLS_X509_CertCtrl(raw, HITLS_X509_GET_SUBJECT_DN, &rawSubject, sizeof(BslList *)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_SUBJECT_DN, rawSubject, sizeof(BslList)), 0);

    BslList *rawIssuer = NULL;
    ASSERT_EQ(HITLS_X509_CertCtrl(raw, HITLS_X509_GET_ISSUER_DN, &rawIssuer, sizeof(BslList *)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(new, HITLS_X509_SET_ISSUER_DN, rawIssuer, sizeof(BslList)), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

    ret = 0;
EXIT:
    return ret;
}

/* BEGIN_CASE */
void SDV_X509_CERT_SETANDGEN_TC001(char *derCertPath, char *privPath, int keyType, int pkeyId, int pad, int mdId,
    int mgfId, int saltLen)
{
    HITLS_X509_Cert *raw = NULL;
    HITLS_X509_Cert *new = NULL;
    HITLS_X509_Cert *parse = NULL;
    CRYPT_EAL_PkeyCtx *privKey = NULL;
    BSL_Buffer encodeRaw = {0};
    BSL_Buffer encodeNew = {0};
    BslList *tmp = NULL;
    HITLS_X509_SignAlgParam algParam = {0};
    HITLS_X509_SignAlgParam *algParamPtr = NULL;
    memset_s(&algParam, sizeof(HITLS_X509_SignAlgParam), 0, sizeof(HITLS_X509_SignAlgParam));
    if (pad == 0) {
        algParamPtr = NULL;
    } else if (pad == CRYPT_EMSA_PSS) {
        algParam.algId = BSL_CID_RSASSAPSS;
        algParam.rsaPss.mdId = mdId;
        algParam.rsaPss.mgfId = mgfId;
        algParam.rsaPss.saltLen = saltLen;
        algParamPtr = &algParam;
    }

    TestMemInit();
    TestRandInit();
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, keyType, privPath, NULL, 0, &privKey), 0);
    ASSERT_EQ(BSL_SAL_ReadFile(derCertPath, &encodeRaw.data, &encodeRaw.dataLen), 0);
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &encodeRaw, &raw), 0);

    // generate new cert
    new = HITLS_X509_CertNew();
    ASSERT_TRUE(new != NULL);
    ASSERT_EQ(SetCert(raw, new), 0);
    // Skip extension settings, directly use the extensions from raw certificate
    tmp = new->tbs.ext.extList;
    new->tbs.ext.extList = raw->tbs.ext.extList;

    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, algParamPtr, new), 0);
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, new, &encodeNew), 0);
    if (pkeyId == CRYPT_PKEY_RSA && pad == CRYPT_EMSA_PKCSV15) {
        ASSERT_COMPARE("Gen cert", encodeNew.data, encodeNew.dataLen, encodeRaw.data, encodeRaw.dataLen);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CertFree(raw);
    BSL_SAL_Free(encodeRaw.data);
    if (tmp != NULL) {
        new->tbs.ext.extList = tmp;
    }
    HITLS_X509_CertFree(new);
    HITLS_X509_CertFree(parse);
    CRYPT_EAL_PkeyFreeCtx(privKey);
    BSL_SAL_Free(encodeNew.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_GEN_PROCESS_TC001(char *derCertPath, char *privPath, int keyType, int mdId)
{
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *privKey = NULL;
    int32_t ver = 0;
    BSL_Buffer encodeCert = {0};

    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, keyType, privPath, NULL, 0, &privKey), 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, derCertPath, &cert), HITLS_PKI_SUCCESS);

    /* Cannot repeat parse */
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, derCertPath, &cert), HITLS_X509_ERR_INVALID_PARAM);

    /* Sign with invalid parameters */
    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, NULL, NULL), HITLS_X509_ERR_INVALID_PARAM);

    /* Cannot sign after parsing */
    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, NULL, cert), HITLS_X509_ERR_SIGN_AFTER_PARSE);

    /* Cannot set after parsing */
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &ver, sizeof(int32_t)), HITLS_X509_ERR_SET_AFTER_PARSE);

    /* Generate cert after parsing is allowed. */
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &encodeCert), 0);
    BSL_SAL_Free(encodeCert.data);
    encodeCert.data = NULL;
    encodeCert.dataLen = 0;
    /* Repeat generate is allowed. */
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &encodeCert), 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(privKey);
    HITLS_X509_CertFree(cert);
    BSL_SAL_Free(encodeCert.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_GEN_PROCESS_TC002(char *csrPath, char *privPath, int keyType, int mdId, Hex *serial)
{
    HITLS_X509_Csr *csr = NULL;
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *privKey = NULL;
    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    uint8_t md[64] = {0}; // 64 : max md len
    uint32_t mdLen = 64;  // 64 : max md len
    BslList *tmp = NULL;
    BSL_TIME beforeTime = {2024, 8, 22, 1, 1, 0, 1, 0};
    BSL_TIME afterTime = {2050, 8, 22, 1, 1, 0, 1, 0};
    BSL_Buffer encodeCert = {0};

    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, keyType, privPath, NULL, 0, &privKey), 0);
    ASSERT_EQ(HITLS_X509_CsrParseFile(BSL_FORMAT_ASN1, csrPath, &csr), HITLS_PKI_SUCCESS);

    cert = HITLS_X509_CertNew();
    ASSERT_TRUE(cert != NULL);

    /* Cannot parse after new */
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &encodeCert, &cert), HITLS_X509_ERR_INVALID_PARAM);

    /* Cannot digest before signing */
    ASSERT_EQ(HITLS_X509_CertDigest(cert, mdId, md, &mdLen), HITLS_X509_ERR_CERT_NOT_SIGNED);

    /* Cannot generate before signing */
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &encodeCert), HITLS_X509_ERR_CERT_NOT_SIGNED);

    /* Invalid parameters */
    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, NULL, NULL), HITLS_X509_ERR_INVALID_PARAM);

    /* Cannot sign before setting serial number */
    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, NULL, cert), HITLS_X509_ERR_CERT_INVALID_SERIAL_NUM);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serial->x, serial->len), 0);

    /* Cannot sign before setting issuer and subject */
    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, NULL, cert), HITLS_X509_ERR_CERT_INVALID_DN);

    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_GET_SUBJECT_DN, &tmp, sizeof(BslList *)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, tmp, sizeof(BslList)), 0);
    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, NULL, cert), HITLS_X509_ERR_CERT_INVALID_DN);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, tmp, sizeof(BslList)), 0);

    /* Cannot sign before setting after time and before time */
    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, NULL, cert), HITLS_X509_ERR_CERT_INVALID_TIME);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), 0);
    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, NULL, cert), HITLS_X509_ERR_CERT_INVALID_TIME);

    /* Before time is later than after time */
    afterTime.year = beforeTime.year - 1;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), 0);
    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, NULL, cert), HITLS_X509_ERR_CERT_START_TIME_LATER);
    afterTime.year = beforeTime.year + 1;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), 0);

    /* Cannot sign before setting public key */
    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, NULL, cert), HITLS_X509_ERR_CERT_INVALID_PUBKEY);

    /* Set public key */
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_GET_PUBKEY, &pubKey, 0), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, pubKey, 0), 0);

    /* Cannot generate before signing */
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &encodeCert), HITLS_X509_ERR_CERT_NOT_SIGNED);

    /* Repeat sign is allowed. */
    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, NULL, cert), 0);
    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, NULL, cert), 0);

    /* Cannot parse after signing */
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &encodeCert, &cert), HITLS_X509_ERR_INVALID_PARAM);

    /* Sing after generating is allowed. */
    ASSERT_EQ(HITLS_X509_CertSign(mdId, privKey, NULL, cert), 0);

    /* Repeat digest is allowed. */
    ASSERT_EQ(HITLS_X509_CertDigest(cert, mdId, md, &mdLen), 0);
    ASSERT_EQ(HITLS_X509_CertDigest(cert, mdId, md, &mdLen), 0);

    /* Repeat generate is allowed. */
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &encodeCert), 0);
    BSL_SAL_Free(encodeCert.data);
    encodeCert.data = NULL;
    encodeCert.dataLen = 0;
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &encodeCert), 0);

    /* Cannot parse after generating */
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &encodeCert, &cert), HITLS_X509_ERR_INVALID_PARAM);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(privKey);
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    HITLS_X509_CsrFree(csr);
    HITLS_X509_CertFree(cert);
    BSL_SAL_Free(encodeCert.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_DIGEST_API_TC001(char *inCert, int inForm, int mdId)
{
    TestRandInit();
    HITLS_X509_Cert *cert = NULL;
    uint8_t md[64] = {0}; // 64 : max md len
    uint32_t mdLen = 64;  // 64 : max md len

    ASSERT_EQ(HITLS_X509_CertParseFile(inForm, inCert, &cert), 0);

    /* Invalid parameters */
    ASSERT_EQ(HITLS_X509_CertDigest(NULL, mdId, md, &mdLen), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertDigest(cert, mdId, NULL, &mdLen), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CertDigest(cert, mdId, md, NULL), HITLS_X509_ERR_INVALID_PARAM);

EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_DIGEST_FUNC_TC001(char *inCert, int inForm, int mdId, Hex *expect)
{
    TestRandInit();
    BSL_Buffer encodeRaw = {0};
    BSL_Buffer encodeNew = {0};
    HITLS_X509_Cert *cert = NULL;
    uint8_t md[64] = {0}; // 64 : max md len
    uint32_t mdLen = 64;  // 64 : max md len

    ASSERT_EQ(BSL_SAL_ReadFile(inCert, &encodeRaw.data, &encodeRaw.dataLen), 0);
    ASSERT_EQ(HITLS_X509_CertParseBuff(inForm, &encodeRaw, &cert), 0);

    ASSERT_EQ(HITLS_X509_CertDigest(cert, mdId, md, &mdLen), 0);
    ASSERT_COMPARE("cert digest", expect->x, expect->len, md, mdLen);

    ASSERT_EQ(HITLS_X509_CertGenBuff(inForm, cert, &encodeNew), 0);
    ASSERT_COMPARE("digest then gen", encodeRaw.data, encodeRaw.dataLen, encodeNew.data, encodeNew.dataLen);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_X509_CertFree(cert);
    BSL_SAL_Free(encodeRaw.data);
    BSL_SAL_Free(encodeNew.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_SET_CSR_EXT_FUNC_TC001(int inForm, char *inCsr, int ret, Hex *expect)
{
    TestRandInit();

    BSL_ASN1_Buffer encodeExt = {0};
    HITLS_X509_Csr *csr = NULL;
    HITLS_X509_Cert *cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    ASSERT_EQ(HITLS_X509_CsrParseFile(inForm, inCsr, &csr), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_CSR_EXT, csr, 0), ret);
    TestErrClear();
    ASSERT_EQ(HITLS_X509_EncodeExt(0, cert->tbs.ext.extList, &encodeExt), 0);
    if (expect->len != 0) {
        ASSERT_TRUE((cert->tbs.ext.flag & HITLS_X509_EXT_FLAG_PARSE) == 0);
        ASSERT_TRUE((cert->tbs.ext.flag & HITLS_X509_EXT_FLAG_GEN) != 0);
        ASSERT_COMPARE("Csr ext", encodeExt.buff, encodeExt.len, expect->x, expect->len);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
    HITLS_X509_CsrFree(csr);
    BSL_SAL_Free(encodeExt.buff);
}
/* END_CASE */

static int32_t STUB_HITLS_X509_ParseCertTbs(BSL_ASN1_Buffer *asnArr, HITLS_X509_Cert *cert)
{
    (void)asnArr;
    (void)cert;
    return BSL_MALLOC_FAIL;
}

/* BEGIN_CASE */
void SDV_X509_CERT_INVALIED_TEST_TC001(int format, char *path)
{
    TestMemInit();
    STUB_REPLACE(HITLS_X509_ParseCertTbs, STUB_HITLS_X509_ParseCertTbs);
    HITLS_X509_Cert *cert = NULL;
    ASSERT_NE(HITLS_X509_CertParseFile(format, path, &cert), HITLS_PKI_SUCCESS);
EXIT:
    STUB_RESTORE(HITLS_X509_ParseCertTbs);
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_GET_BCONS_TEST_TC001(int format, char *path, int critical, int isCa, int pathLen)
{
    TestMemInit();
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(format, path, &cert), HITLS_PKI_SUCCESS);
    HITLS_X509_ExtBCons bc = {0};
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_BCONS, &bc, sizeof(HITLS_X509_ExtBCons)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(bc.isCa, isCa);
    ASSERT_EQ(bc.maxPathLen, pathLen);
    ASSERT_EQ(bc.critical, critical);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CERT_GET_BCONS_TEST_TC002(int format, char *path)
{
    TestMemInit();
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseFile(format, path, &cert), HITLS_PKI_SUCCESS);
    HITLS_X509_ExtBCons bc = {0};
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_BCONS, &bc, sizeof(HITLS_X509_ExtBCons)),
        HITLS_X509_ERR_EXT_NO_BCONS);
EXIT:
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/**
 * @test SDV_X509_CERT_PARSE_STUB_TC001
 * title 1. Test the cert parse with stub malloc fail (adaptive)
 *
 */
/* BEGIN_CASE */
void SDV_X509_CERT_PARSE_STUB_TC001(int format, char *path)
{
#if !defined(HITLS_PKI_X509_CRT_PARSE) || !defined(HITLS_CRYPTO_PROVIDER)
    (void)format;
    (void)path;
    SKIP_TEST();
#else
    TestMemInit();
    int32_t ret;
    HITLS_X509_Cert *cert = NULL;
    uint32_t totalMallocCount = 0;

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    /* Phase 1: Probe - count malloc calls during successful execution */
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_X509_CertParseFile(format, path, &cert), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    HITLS_X509_CertFree(cert);
    cert = NULL;

    /* Phase 2: Test - iteratively fail each malloc */
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ret = HITLS_X509_CertParseFile(format, path, &cert);
        if (ret == HITLS_PKI_SUCCESS) {
            HITLS_X509_CertFree(cert);
            cert = NULL;
            ASSERT_TRUE(TestIsErrStackEmpty());
        }
    }

EXIT:
    HITLS_X509_CertFree(cert);
    STUB_RESTORE(BSL_SAL_Malloc);
#endif
}
/* END_CASE */

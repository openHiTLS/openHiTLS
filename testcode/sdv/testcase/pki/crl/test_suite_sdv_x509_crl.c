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
#include "hitls_pki_crl.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_errno.h"
#include "bsl_types.h"
#include "bsl_log.h"
#include "bsl_obj.h"
#include "crypt_codecskey.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_pkey.h"
#include "eal_pkey_local.h"
#include "sal_file.h"
#include "bsl_init.h"
#include "crypt_errno.h"
#include "hitls_crl_local.h"
#include "hitls_cert_local.h"
#include "stub_utils.h"
#include "hitls_pki_utils.h"

static char g_sm2DefaultUserid[] = "1234567812345678";
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET2(int32_t, HITLS_X509_ParseNameList, BSL_ASN1_Buffer *, BSL_ASN1_List *);

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_FUNC_TC001(int format, char *path)
{
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_Crl *crl = NULL;

    ASSERT_EQ(HITLS_X509_CrlParseFile((int32_t)format, path, &crl), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_CrlFree(crl);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_CTRL_FUNC_TC001(char *path)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path, &crl), HITLS_PKI_SUCCESS);

    int32_t ref = 0;
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_REF_UP, &ref, sizeof(ref)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(ref, 2);
    HITLS_X509_CrlFree(crl);

EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_VERSION_FUNC_TC001(char *path, int version)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path, &crl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(crl->tbs.version, version);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_TBS_SIGNALG_FUNC_TC001(char *path, int signAlg,
    int rsaPssHash, int rsaPssMgf1, int rsaPssSaltLen)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path, &crl), HITLS_PKI_SUCCESS);

    ASSERT_EQ(crl->tbs.signAlgId.algId, signAlg);
    ASSERT_EQ(crl->tbs.signAlgId.rsaPssParam.mdId, rsaPssHash);
    ASSERT_EQ(crl->tbs.signAlgId.rsaPssParam.mgfId, rsaPssMgf1);
    ASSERT_EQ(crl->tbs.signAlgId.rsaPssParam.saltLen, rsaPssSaltLen);

EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_ISSUERNAME_FUNC_TC001(char *path, int count,
    Hex *type1, int tag1, Hex *value1,
    Hex *type2, int tag2, Hex *value2,
    Hex *type3, int tag3, Hex *value3,
    Hex *type4, int tag4, Hex *value4,
    Hex *type5, int tag5, Hex *value5)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path, &crl), HITLS_PKI_SUCCESS);

    BSL_ASN1_Buffer expAsan1Arr[] = {
        {6, type1->len, type1->x}, {(uint8_t)tag1, value1->len, value1->x},
        {6, type2->len, type2->x}, {(uint8_t)tag2, value2->len, value2->x},
        {6, type3->len, type3->x}, {(uint8_t)tag3, value3->len, value3->x},
        {6, type4->len, type4->x}, {(uint8_t)tag4, value4->len, value4->x},
        {6, type5->len, type5->x}, {(uint8_t)tag5, value5->len, value5->x},
    };
    ASSERT_EQ(BSL_LIST_COUNT(crl->tbs.issuerName), count);
    HITLS_X509_NameNode **nameNode = NULL;
    nameNode = BSL_LIST_First(crl->tbs.issuerName);
    for (int i = 0; i < count; i += 2) { // Iteration with step=2
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 1);
        ASSERT_EQ((*nameNode)->nameType.tag, 0);
        ASSERT_EQ((*nameNode)->nameType.buff, NULL);
        ASSERT_EQ((*nameNode)->nameType.len, 0);
        ASSERT_EQ((*nameNode)->nameValue.tag, 0);
        ASSERT_EQ((*nameNode)->nameValue.buff, NULL);
        ASSERT_EQ((*nameNode)->nameValue.len, 0);

        nameNode = BSL_LIST_Next(crl->tbs.issuerName);
        ASSERT_NE((*nameNode), NULL);
        ASSERT_EQ((*nameNode)->layer, 2);
        ASSERT_EQ((*nameNode)->nameType.tag, expAsan1Arr[i].tag);
        ASSERT_COMPARE("nameType", (*nameNode)->nameType.buff, (*nameNode)->nameType.len,
            expAsan1Arr[i].buff, expAsan1Arr[i].len);

        ASSERT_EQ((*nameNode)->nameValue.tag, expAsan1Arr[i + 1].tag);
        ASSERT_COMPARE("nameVlaue", (*nameNode)->nameValue.buff, (*nameNode)->nameValue.len,
            expAsan1Arr[i + 1].buff, expAsan1Arr[i + 1].len);
        nameNode = BSL_LIST_Next(crl->tbs.issuerName);
    }
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_REVOKED_FUNC_TC001(char *path)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path, &crl), BSL_SAL_ERR_FILE_LENGTH);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_REVOKED_FUNC_TC003(char *path, int count, int num,
    int tag1, Hex *value1, int year1, int month1, int day1, int hour1, int minute1, int second1)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path, &crl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(crl->tbs.revokedCerts), count);
    HITLS_X509_CrlEntry *nameNode = NULL;
    nameNode = BSL_LIST_GET_FIRST(crl->tbs.revokedCerts);
    for (int i = 1; i < num; i++) {
        nameNode = BSL_LIST_GET_NEXT(crl->tbs.revokedCerts);
    }

    ASSERT_EQ(nameNode->serialNumber.tag, tag1);
    ASSERT_COMPARE("", nameNode->serialNumber.buff, nameNode->serialNumber.len,
        value1->x, value1->len);
    ASSERT_EQ(nameNode->time.year, year1);
    ASSERT_EQ(nameNode->time.month, month1);
    ASSERT_EQ(nameNode->time.day, day1);
    ASSERT_EQ(nameNode->time.hour, hour1);
    ASSERT_EQ(nameNode->time.minute, minute1);
    ASSERT_EQ(nameNode->time.second, second1);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_TIME_FUNC_TC001(char *path)
{
    HITLS_X509_Crl *crl = NULL;
    // BSL_ASN1_DecodePrimitiveItem fails because the tag is still a choice(193).
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path, &crl), BSL_ASN1_FAIL);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_START_TIME_FUNC_TC001(char *path,
    int year, int month, int day, int hour, int minute, int second)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path, &crl), HITLS_PKI_SUCCESS);

    ASSERT_EQ(crl->tbs.validTime.start.year, year);
    ASSERT_EQ(crl->tbs.validTime.start.month, month);
    ASSERT_EQ(crl->tbs.validTime.start.day, day);
    ASSERT_EQ(crl->tbs.validTime.start.hour, hour);
    ASSERT_EQ(crl->tbs.validTime.start.minute, minute);
    ASSERT_EQ(crl->tbs.validTime.start.second, second);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_END_TIME_FUNC_TC001(char *path,
    int year, int month, int day, int hour, int minute, int second)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path, &crl), HITLS_PKI_SUCCESS);

    ASSERT_EQ(crl->tbs.validTime.end.year, year);
    ASSERT_EQ(crl->tbs.validTime.end.month, month);
    ASSERT_EQ(crl->tbs.validTime.end.day, day);
    ASSERT_EQ(crl->tbs.validTime.end.hour, hour);
    ASSERT_EQ(crl->tbs.validTime.end.minute, minute);
    ASSERT_EQ(crl->tbs.validTime.end.second, second);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_EXTENSIONS_FUNC_TC001(char *path,
    int tag1, Hex *value1, int tag2, Hex *value2)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path, &crl), HITLS_PKI_SUCCESS);

    ASSERT_EQ(BSL_LIST_COUNT(crl->tbs.crlExt.extList), 1);
    HITLS_X509_ExtEntry **nameNode = NULL;
    nameNode = BSL_LIST_First(crl->tbs.crlExt.extList);
    ASSERT_NE((*nameNode), NULL);
    ASSERT_EQ((*nameNode)->critical, 0);
    ASSERT_EQ((*nameNode)->extnId.tag, tag1);
    ASSERT_COMPARE("extnId", (*nameNode)->extnId.buff, (*nameNode)->extnId.len, value1->x, value1->len);
    ASSERT_EQ((*nameNode)->extnValue.tag, tag2);
    ASSERT_COMPARE("extnValue", (*nameNode)->extnValue.buff, (*nameNode)->extnValue.len, value2->x, value2->len);
EXIT:
    HITLS_X509_CrlFree(crl);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_SIGNALG_FUNC_TC001(char *path, int signAlg,
    int rsaPssHash, int rsaPssMgf1, int rsaPssSaltLen)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path, &crl), HITLS_PKI_SUCCESS);

    ASSERT_EQ(crl->signAlgId.algId, signAlg);
    ASSERT_EQ(crl->signAlgId.rsaPssParam.mdId, rsaPssHash);
    ASSERT_EQ(crl->signAlgId.rsaPssParam.mgfId, rsaPssMgf1);
    ASSERT_EQ(crl->signAlgId.rsaPssParam.saltLen, rsaPssSaltLen);

EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_SIGNATURE_FUNC_TC001(char *path, Hex *buff, int unusedBits)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path, &crl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(crl->signature.len, buff->len);
    ASSERT_COMPARE("signature", crl->signature.buff, crl->signature.len, buff->x, buff->len);
    ASSERT_EQ(crl->signature.unusedBits, unusedBits);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_MUL_CRL_PARSE_FUNC_TC001(int format, char *path, int crlNum)
{
    BSL_GLOBAL_Init();
    HITLS_X509_List *list = NULL;
    int32_t ret = HITLS_X509_CrlParseBundleFile(format, path, &list);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_LIST_COUNT(list), crlNum);
EXIT:
    BSL_LIST_FREE(list, (BSL_LIST_PFUNC_FREE)HITLS_X509_CrlFree);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_Encode_TC001(int format, char *path)
{
    BSL_GLOBAL_Init();
    HITLS_X509_Crl *crl = NULL;
    BSL_Buffer encode = {0};
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    ASSERT_EQ(ret, BSL_SUCCESS);

    BSL_Buffer ori = {data, dataLen};
    ret = HITLS_X509_CrlParseBuff(format, &ori, &crl);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CrlGenBuff(format, crl, &encode);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    if (format == BSL_FORMAT_ASN1) {
        ASSERT_EQ(dataLen, encode.dataLen);
    } else {
        ASSERT_EQ(dataLen, strlen((char *)encode.data));
    }
    ASSERT_EQ(memcmp(encode.data, data, dataLen), 0);

EXIT:
    BSL_SAL_Free(data);
    HITLS_X509_CrlFree(crl);
    BSL_SAL_Free(encode.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_EncodeParam_TC001(void)
{
    BSL_GLOBAL_Init();
    HITLS_X509_Crl *crl = NULL;
    BSL_Buffer encode = {0};
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    ASSERT_EQ(BSL_SAL_ReadFile("../testdata/cert/pem/crl/crl_v2.pem", &data, &dataLen), BSL_SUCCESS);

    BSL_Buffer ori = {data, dataLen};
    ASSERT_EQ(HITLS_X509_CrlParseBuff(BSL_FORMAT_PEM, &ori, &crl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlGenBuff(BSL_FORMAT_ASN1, NULL, &encode), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CrlGenBuff(BSL_FORMAT_ASN1, crl, NULL), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CrlGenBuff(BSL_FORMAT_UNKNOWN, crl, &encode), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CrlGenBuff(BSL_FORMAT_ASN1, crl, &encode), 0);
EXIT:
    BSL_SAL_Free(data);
    HITLS_X509_CrlFree(crl);
    BSL_SAL_Free(encode.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_EncodeFile_TC001(int format, char *path)
{
    BSL_GLOBAL_Init();
    HITLS_X509_Crl *crl = NULL;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    uint8_t *res = NULL;
    uint32_t resLen;
    int32_t ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    ASSERT_EQ(ret, BSL_SUCCESS);

    BSL_Buffer ori = {data, dataLen};
    ret = HITLS_X509_CrlParseBuff(format, &ori, &crl);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_X509_CrlGenFile(format, crl, "res.crl");
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_SAL_ReadFile("res.crl", &res, &resLen), BSL_SUCCESS);
    ASSERT_COMPARE("crl_file com", data, dataLen, res, resLen);
EXIT:
    BSL_SAL_Free(data);
    HITLS_X509_CrlFree(crl);
    BSL_SAL_Free(res);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_Check_TC001(char *capath, char *crlpath, int res)
{
    BSL_GLOBAL_Init();
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Cert *cert = NULL;
    void *pubKey = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_UNKNOWN, crlpath, &crl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, capath, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &pubKey, sizeof(void *)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlVerify(pubKey, crl), res);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CertFree(cert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_CTRL_ParamCheck_TC001(void)
{
    HITLS_X509_Crl *crl = NULL;
    BSL_TIME time = {0};
    BSL_ASN1_List *issuer = NULL;
    uint32_t version = 1;

    // Test null pointer parameter
    ASSERT_EQ(HITLS_X509_CrlCtrl(NULL, HITLS_X509_SET_VERSION, &version, sizeof(version)),
        HITLS_X509_ERR_INVALID_PARAM);

    // Create a CRL object for subsequent tests
    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);

    // Test invalid command
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, 0x7FFFFFFF, &version, sizeof(version)), HITLS_X509_ERR_INVALID_PARAM);

    // Test null value pointer
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_VERSION, NULL, sizeof(uint8_t)), HITLS_X509_ERR_INVALID_PARAM);

    // Test incorrect length for version parameter
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_VERSION, &version, 0), HITLS_X509_ERR_INVALID_PARAM);

    // Test invalid version number
    version = 3;  // Out of valid range
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_X509_ERR_INVALID_PARAM);

    // Test incorrect length for time parameter
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_BEFORE_TIME, &time, sizeof(time) - 1),
        HITLS_X509_ERR_INVALID_PARAM);

    // Test incorrect length for issuer parameter
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_ISSUER_DN, issuer, sizeof(BSL_ASN1_List) - 1),
        HITLS_X509_ERR_INVALID_PARAM);

    // Test empty buffer for get command
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_VERSION, NULL, sizeof(version)), HITLS_X509_ERR_INVALID_PARAM);

    // Test incorrect buffer length for get command
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_VERSION, &version, 0), HITLS_X509_ERR_INVALID_PARAM);

    // Test normal parameters - set version number
    version = 1;
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);

    // Test normal parameters - get version number
    uint32_t getVersion = 0;
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_VERSION, &getVersion, sizeof(getVersion)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(getVersion, version);

    // Test normal parameters - set last update time
    ASSERT_EQ(BSL_SAL_SysTimeGet(&time), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_BEFORE_TIME, &time, sizeof(time)), HITLS_PKI_SUCCESS);

    // Test normal parameters - get last update time
    BSL_TIME getTime = {0};
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_BEFORE_TIME, &getTime, sizeof(getTime)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(memcmp(&getTime, &time, sizeof(BSL_TIME)), 0);
EXIT:
    // Clean up resources
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_CTRL_RevokedParamCheck_TC001(void)
{
    HITLS_X509_CrlEntry *entry = NULL;
    BSL_TIME time = {0};

    // Test HITLS_X509_CrlEntryNew
    entry = HITLS_X509_CrlEntryNew();
    ASSERT_NE(entry, NULL);

    // Test HITLS_X509_CrlEntryCtrl with invalid command
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, 0xFFFF, &time, sizeof(time)), HITLS_X509_ERR_INVALID_PARAM);

    // Test HITLS_X509_CrlEntryCtrl with NULL entry
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(NULL, HITLS_X509_CRL_GET_REVOKED_REVOKE_TIME, &time, sizeof(time)),
        HITLS_X509_ERR_INVALID_PARAM);

    // Test HITLS_X509_CrlEntryCtrl with NULL value pointer
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_REVOKE_TIME, NULL, sizeof(time)),
        HITLS_X509_ERR_INVALID_PARAM);

    // Test HITLS_X509_CrlEntryCtrl with invalid value length
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_REVOKE_TIME, &time, 0),
        HITLS_X509_ERR_INVALID_PARAM);

    // Test setting/getting revoke time
    ASSERT_EQ(BSL_SAL_SysTimeGet(&time), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME, &time, sizeof(time)),
        HITLS_PKI_SUCCESS);

    BSL_TIME getTime = {0};
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_REVOKE_TIME, &getTime, sizeof(getTime)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(memcmp(&time, &getTime, sizeof(BSL_TIME)), 0);

    // Test setting/getting reason
    HITLS_X509_RevokeExtReason reasonExt = {false, 1};
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REASON, &reasonExt,
        sizeof(HITLS_X509_RevokeExtReason)), HITLS_PKI_SUCCESS);

    int32_t getReason = 0;
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_REASON, &getReason, sizeof(getReason)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(reasonExt.reason, getReason);

    // Test setting/getting serial number
    uint8_t serial[] = {0x01, 0x02, 0x03, 0x04};
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_SERIALNUM, serial, 4),
        HITLS_PKI_SUCCESS);

    BSL_Buffer getSerial = {0};
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_SERIALNUM, &getSerial, sizeof(getSerial)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(4, getSerial.dataLen);
    ASSERT_EQ(memcmp(serial, getSerial.data, getSerial.dataLen), 0);

    // Test HITLS_X509_CrlEntryFree with NULL
    HITLS_X509_CrlEntryFree(NULL);  // Should not crash

    // Test HITLS_X509_CrlEntryFree with valid entry
    HITLS_X509_CrlEntryFree(entry);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_REVOKEDLIST_FUNC_TC001(char *parh, int revokedNum)
{
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_CrlEntry *entry = NULL;
    BslList *revokeList = NULL;
    BSL_TIME time = {0};
    int32_t reason = 0;
    BSL_Buffer serialNum = {0};

    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, parh, &crl), HITLS_PKI_SUCCESS);
    ASSERT_NE(crl, NULL);

    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_REVOKELIST, &revokeList, sizeof(BslList *)), HITLS_PKI_SUCCESS);
    ASSERT_NE(revokeList, NULL);
    ASSERT_EQ(BSL_LIST_COUNT(revokeList), revokedNum);
    for (entry = (HITLS_X509_CrlEntry *)BSL_LIST_GET_FIRST(revokeList); entry != NULL; entry =
        (HITLS_X509_CrlEntry *)BSL_LIST_GET_NEXT(revokeList)) {
        ASSERT_TRUE(entry->serialNumber.buff != NULL);
        ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_SERIALNUM, &serialNum,
            sizeof(BSL_Buffer)), HITLS_PKI_SUCCESS);
        ASSERT_TRUE(serialNum.dataLen > 0 && serialNum.dataLen <= 20);
        ASSERT_NE(serialNum.data, NULL);
        ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_REVOKE_TIME, &time, sizeof(BSL_TIME)),
            HITLS_PKI_SUCCESS);
        ASSERT_NE(time.year, 0);
        ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_REASON,
            &reason, sizeof(int32_t)), HITLS_PKI_SUCCESS);
        ASSERT_TRUE(reason >= 0 && reason <= 11);
        reason = 0;
        memset(&time, 0, sizeof(BSL_TIME));
        memset(&serialNum, 0, sizeof(serialNum));
    }
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_CTRL_GetFunc_TC001(void)
{
    HITLS_X509_Crl *crl = NULL;
    uint32_t version = 0;
    BSL_TIME beforeTime = {0};
    BSL_TIME afterTime = {0};
    BslList *issuerDN = NULL;
    BslList *revokeList = NULL;

    // Parse the test CRL file
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_PEM, "../testdata/cert/pem/crl/crl_v2.mul3.crl", &crl),
        HITLS_PKI_SUCCESS);
    ASSERT_NE(crl, NULL);

    // Test getting the version number
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_VERSION, &version, sizeof(uint32_t)), HITLS_PKI_SUCCESS);
    // The CRL version should be 0 (v1) or 1 (v2)
    ASSERT_TRUE(version == 1);

    // Test getting the last update time
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_NE(beforeTime.year, 0);

    // Test getting the next update time
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    // The next update time should be later than the last update time
    ASSERT_TRUE(afterTime.month > beforeTime.month);

    // Test getting the issuer DN name
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_ISSUER_DN, &issuerDN, sizeof(BslList *)), HITLS_PKI_SUCCESS);
    ASSERT_NE(issuerDN, NULL);
    ASSERT_NE(BSL_LIST_COUNT(issuerDN), 0);

    // Test getting extensions (using CRL Number as an example)
    ASSERT_NE(crl->tbs.crlExt.extList, NULL);
    ASSERT_EQ(crl->tbs.crlExt.type, HITLS_X509_EXT_TYPE_CRL);
    ASSERT_EQ(BSL_LIST_COUNT(crl->tbs.crlExt.extList), 1);

    // Test getting the revoke list
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_REVOKELIST, &revokeList, sizeof(BslList *)), HITLS_PKI_SUCCESS);
    ASSERT_NE(revokeList, NULL);
    ASSERT_EQ(BSL_LIST_COUNT(revokeList), 3);

EXIT:
    HITLS_X509_CrlFree(crl);
}

/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_ExtCtrl_FuncTest_TC001(void)
{
    uint8_t keyId[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};

    HITLS_X509_Crl *crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);

    // set CRL Number
    HITLS_X509_ExtCrlNumber crlNumberExt = {false, {serialNum, 4}};
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_SET_CRLNUMBER, &crlNumberExt, sizeof(HITLS_X509_ExtCrlNumber)),
        HITLS_PKI_SUCCESS);
    HITLS_X509_ExtCrlNumber crlNumExt = {0};
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_GET_CRLNUMBER, &crlNumExt, sizeof(HITLS_X509_ExtCrlNumber)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(crlNumExt.critical, crlNumberExt.critical);
    ASSERT_EQ(crlNumExt.crlNumber.dataLen, crlNumberExt.crlNumber.dataLen);
    ASSERT_EQ(memcmp(crlNumExt.crlNumber.data, crlNumberExt.crlNumber.data, crlNumberExt.crlNumber.dataLen), 0);

    HITLS_X509_ExtAki aki = {false, {keyId, sizeof(keyId)}, NULL, {NULL, 0}};
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_SET_AKI, &aki, sizeof(HITLS_X509_ExtAki)), HITLS_PKI_SUCCESS);
    HITLS_X509_ExtAki getaki = {0};
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_GET_AKI, &getaki, sizeof(HITLS_X509_ExtAki)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(getaki.critical, aki.critical);
    ASSERT_EQ(getaki.kid.dataLen, aki.kid.dataLen);
    ASSERT_EQ(memcmp(getaki.kid.data, aki.kid.data, aki.kid.dataLen), 0);

EXIT:
    HITLS_X509_CrlFree(crl);
}

/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_CTRL_SetFunc_TC001(char *capath)
{
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};
    BSL_TIME beforeTime = {0};
    BSL_TIME afterTime = {0};
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Crl *crl = HITLS_X509_CrlNew();
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, capath, &cert), HITLS_PKI_SUCCESS);
    ASSERT_NE(crl, NULL);
    uint32_t version = 1;
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_VERSION, &version, sizeof(uint32_t)), HITLS_PKI_SUCCESS);
    BslList *issuerDN = NULL;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN, &issuerDN, sizeof(BslList *)),
        HITLS_PKI_SUCCESS);
    ASSERT_NE(issuerDN, NULL);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_ISSUER_DN, issuerDN, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(BSL_SAL_SysTimeGet(&beforeTime), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);

    afterTime = beforeTime;
    afterTime.year += 1;
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);

    HITLS_X509_ExtSki ski = {0};
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SKI, &ski, sizeof(HITLS_X509_ExtSki)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(ski.kid.data != NULL);
    HITLS_X509_ExtAki aki = {false, {ski.kid.data, ski.kid.dataLen}, cert->tbs.issuerName,
        {cert->tbs.serialNum.buff, cert->tbs.serialNum.len}};
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_SET_AKI, &aki, sizeof(HITLS_X509_ExtAki)), HITLS_PKI_SUCCESS);
    HITLS_X509_ExtCrlNumber crlNumberExt = {false, {serialNum, 4}};
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_SET_CRLNUMBER, &crlNumberExt, sizeof(HITLS_X509_ExtCrlNumber)),
              HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_CertFree(cert);
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_Sign_ParamCheck_TC001(void)
{
    HITLS_X509_Crl *crl = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_SignAlgParam algParam = {0};

    // Create a basic CRL object
    TestMemInit();
    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);
    prvKey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_NE(prvKey, NULL);

    // Test null parameters
    ASSERT_EQ(HITLS_X509_CrlSign(BSL_CID_SHA256, NULL, &algParam, crl), HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CrlSign(BSL_CID_SHA256, prvKey, &algParam, NULL), HITLS_X509_ERR_INVALID_PARAM);

EXIT:
    HITLS_X509_CrlFree(crl);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_Gen_Process_TC001(void)
{
    HITLS_X509_Crl *crl = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_SignAlgParam algParam = {0};
    const char *keyPath = "../testdata/cert/asn1/rsa_cert/rsa_p1.key.der";
    const char *crlPath = "../testdata/cert/asn1/rsa_crl/crl_v1.der";
    uint32_t ver = 1;
    BSL_Buffer encodeCrl = {0};
    BslList *tmp = NULL;

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA, keyPath, NULL, 0, &prvKey), 0);
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, crlPath, &crl), HITLS_PKI_SUCCESS);

    /* Cannot repeat parse */
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, crlPath, &crl), HITLS_X509_ERR_INVALID_PARAM);

    /* Cannot sign after parsing */
    ASSERT_EQ(HITLS_X509_CrlSign(BSL_CID_SHA256, prvKey, &algParam, crl), HITLS_X509_ERR_SIGN_AFTER_PARSE);

    /* Cannot set after parsing */
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_VERSION, &ver, sizeof(uint32_t)), HITLS_X509_ERR_SET_AFTER_PARSE);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_GET_ISSUER_DN, &tmp, sizeof(BslList *)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_ISSUER_DN, tmp, 0), HITLS_X509_ERR_SET_AFTER_PARSE);

    /* Generate crl after parsing is allowed. */
    ASSERT_EQ(HITLS_X509_CrlGenBuff(BSL_FORMAT_ASN1, crl, &encodeCrl), 0);
    BSL_SAL_Free(encodeCrl.data);
    encodeCrl.data = NULL;
    encodeCrl.dataLen = 0;
    /* Repeat generate is allowed. */
    ASSERT_EQ(HITLS_X509_CrlGenBuff(BSL_FORMAT_ASN1, crl, &encodeCrl), 0);

EXIT:
    HITLS_X509_CrlFree(crl);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
    BSL_SAL_Free(encodeCrl.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_Gen_Process_TC002(void)
{
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    const char *keyPath = "../testdata/cert/asn1/rsa_cert/rsa_p8.key.der";
    const char *certPath = "../testdata/cert/asn1/rsa_cert/rsa_p8.crt.der";
    uint32_t mdId = BSL_CID_SHA256;
    BSL_TIME thisUpdate = {2024, 8, 22, 1, 1, 0, 1, 0};
    BSL_TIME nextUpdate = {2024, 8, 22, 1, 1, 0, 1, 0};
    BslList *issuerDN = NULL;
    BSL_Buffer encodeCrl = {0};

    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, keyPath, NULL, 0, &prvKey), 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &cert), 0);

    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);

    /* Invalid parameters */
    ASSERT_EQ(HITLS_X509_CrlSign(mdId, prvKey, NULL, NULL), HITLS_X509_ERR_INVALID_PARAM);

    /* Test Crl sign with invalid fields */
    /* Set invalid version number */
    crl->tbs.version = 2; // 2 is invalid
    ASSERT_EQ(HITLS_X509_CrlSign(mdId, prvKey, NULL, crl), HITLS_X509_ERR_CRL_INACCURACY_VERSION);

    /* Set invalid version number in extensions */
    crl->tbs.version = 0;
    BslList *extList = crl->tbs.crlExt.extList;
    crl->tbs.crlExt.extList = cert->tbs.ext.extList;
    ASSERT_EQ(HITLS_X509_CrlSign(mdId, prvKey, NULL, crl), HITLS_X509_ERR_CRL_INACCURACY_VERSION);
    crl->tbs.crlExt.extList = extList;

    /* issuer name is empty */
    ASSERT_EQ(HITLS_X509_CrlSign(mdId, prvKey, NULL, crl), HITLS_X509_ERR_CRL_ISSUER_EMPTY);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN, &issuerDN, sizeof(BslList *)), 0);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_ISSUER_DN, issuerDN, sizeof(BslList)), 0);

    /* thisUpdate is not set */
    ASSERT_EQ(HITLS_X509_CrlSign(mdId, prvKey, NULL, crl), HITLS_X509_ERR_CRL_THISUPDATE_UNEXIST);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_BEFORE_TIME, &thisUpdate, sizeof(BSL_TIME)), 0);

    /* nextUpdate is before thisUpdate */
    nextUpdate.year = thisUpdate.year - 1;
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_AFTER_TIME, &nextUpdate, sizeof(BSL_TIME)), 0);
    ASSERT_EQ(HITLS_X509_CrlSign(mdId, prvKey, NULL, crl), HITLS_X509_ERR_CRL_TIME_INVALID);
    nextUpdate.year = thisUpdate.year + 1;
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_AFTER_TIME, &nextUpdate, sizeof(BSL_TIME)), 0);

    /* Cannot generate before signing */
    ASSERT_EQ(HITLS_X509_CrlGenBuff(BSL_FORMAT_ASN1, crl, &encodeCrl), HITLS_X509_ERR_CRL_NOT_SIGNED);

    /* Cannot verify before signing */
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &pubKey, sizeof(CRYPT_EAL_PkeyCtx *)), 0);
    ASSERT_EQ(HITLS_X509_CrlVerify(pubKey, crl), HITLS_X509_ERR_CRL_NOT_SIGNED);

    /* Repeat sign is allowed. */
    ASSERT_EQ(HITLS_X509_CrlSign(mdId, prvKey, NULL, crl), 0);
    ASSERT_EQ(HITLS_X509_CrlSign(mdId, prvKey, NULL, crl), 0);

    /* Verify after signing is allowed. */
    ASSERT_EQ(HITLS_X509_CrlVerify(pubKey, crl), 0);

    /* Cannot parse after signing */
    ASSERT_EQ(HITLS_X509_CrlParseBuff(BSL_FORMAT_ASN1, &encodeCrl, &crl), HITLS_X509_ERR_INVALID_PARAM);

    /* Repeat generate is allowed. */
    ASSERT_EQ(HITLS_X509_CrlGenBuff(BSL_FORMAT_ASN1, crl, &encodeCrl), 0);
    BSL_SAL_Free(encodeCrl.data);
    encodeCrl.data = NULL;
    encodeCrl.dataLen = 0;
    ASSERT_EQ(HITLS_X509_CrlGenBuff(BSL_FORMAT_ASN1, crl, &encodeCrl), 0);

    /* Sing after generating is allowed. */
    ASSERT_EQ(HITLS_X509_CrlSign(mdId, prvKey, NULL, crl), 0);

    /* Verify after generating is allowed. */
    ASSERT_EQ(HITLS_X509_CrlVerify(pubKey, crl), 0);

    /* Cannot parse after generating */
    ASSERT_EQ(HITLS_X509_CrlParseBuff(BSL_FORMAT_ASN1, &encodeCrl, &crl), HITLS_X509_ERR_INVALID_PARAM);

EXIT:
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CertFree(cert);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    BSL_SAL_Free(encodeCrl.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_Sign_AlgParamCheck_TC001(void)
{
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    const char *keyPath = "../testdata/cert/asn1/rsa_cert/rsa_p1.key.der";
    const char *certPath = "../testdata/cert/asn1/rsa_cert/rsa_p8.crt.der";
    BSL_TIME thisUpdate = {2024, 8, 22, 1, 1, 0, 1, 0};
    BslList *issuerDN = NULL;

    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA, keyPath, NULL, 0, &prvKey), 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &cert), 0);

    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN, &issuerDN, sizeof(BslList *)), 0);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_ISSUER_DN, issuerDN, sizeof(BslList)), 0);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_BEFORE_TIME, &thisUpdate, sizeof(BSL_TIME)), 0);

    /* Test invalid mdId */
    ASSERT_EQ(HITLS_X509_CrlSign(BSL_CID_SHAKE128, prvKey, &algParam, crl), HITLS_X509_ERR_HASHID);

    /* Test empty algParam */
    ASSERT_EQ(HITLS_X509_CrlSign(BSL_CID_SHA256, prvKey, &algParam, crl), HITLS_X509_ERR_MD_NOT_MATCH);

    /* Test invalid mdId for RSA-PSS */
    algParam.algId = BSL_CID_RSASSAPSS;
    ASSERT_EQ(HITLS_X509_CrlSign(BSL_CID_SHA256, prvKey, &algParam, crl), HITLS_X509_ERR_MD_NOT_MATCH);

    /* Test invalid mgfId for RSA-PSS */
    algParam.rsaPss.mdId = (CRYPT_MD_AlgId)BSL_CID_SHA256;
    algParam.rsaPss.mgfId = (CRYPT_MD_AlgId)BSL_CID_UNKNOWN;
    algParam.rsaPss.saltLen = 32;
    ASSERT_EQ(HITLS_X509_CrlSign(BSL_CID_SHA256, prvKey, &algParam, crl), CRYPT_EAL_ERR_ALGID);

EXIT:
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CertFree(cert);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
}
/* END_CASE */

#if defined(HITLS_PKI_X509_CRL_GEN) || defined(HITLS_PKI_X509_CRT_GEN)
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
#endif

static BslList* GenGeneralNameList(void)
{
    char *str = "test";
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
    email->value.dataLen = strlen(str);
    dns->value.dataLen = strlen(str);
    uri->value.dataLen = strlen(str);
    dname->value.dataLen = sizeof(BslList *);
    ip->value.dataLen = strlen(str);
    email->value.data = BSL_SAL_Dump(str, strlen(str));
    dns->value.data = BSL_SAL_Dump(str, strlen(str));
    uri->value.data = BSL_SAL_Dump(str, strlen(str));
    dname->value.data = (uint8_t *)GenDNList();
    ip->value.data = BSL_SAL_Dump(str, strlen(str));
    ASSERT_TRUE(email->value.data != NULL && dns->value.data != NULL && uri->value.data != NULL
        && dname->value.data != NULL && ip->value.data != NULL);

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

static int32_t SetCrlRevoked(HITLS_X509_Crl *crl, int8_t ser)
{
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};
    serialNum[3] = ser;
    HITLS_X509_CrlEntry *entry = HITLS_X509_CrlEntryNew();
    ASSERT_NE(entry, NULL);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_SERIALNUM,
        serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);

    BSL_TIME revokeTime = {0};
    ASSERT_EQ(BSL_SAL_SysTimeGet(&revokeTime), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME, &revokeTime, sizeof(BSL_TIME)),
        HITLS_PKI_SUCCESS);
    HITLS_X509_RevokeExtReason reason = {0, 1};  // keyCompromise
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REASON, &reason,
        sizeof(HITLS_X509_RevokeExtReason)), HITLS_PKI_SUCCESS);

    // Set invalid time (optional)
    BSL_TIME invalidTime = revokeTime;
    HITLS_X509_RevokeExtTime invalidTimeExt = {false, invalidTime};
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_INVALID_TIME,
        &invalidTimeExt, sizeof(HITLS_X509_RevokeExtTime)), HITLS_PKI_SUCCESS);

    // Set certificate issuer (optional, only needed for indirect CRLs)
    HITLS_X509_RevokeExtCertIssuer certIssuer = {true, NULL};
    certIssuer.issuerName = GenGeneralNameList();
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_CERTISSUER,
        &certIssuer, sizeof(HITLS_X509_RevokeExtCertIssuer)), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_CRL_ADD_REVOKED_CERT, entry, sizeof(HITLS_X509_CrlEntry)),
        HITLS_PKI_SUCCESS);
    HITLS_X509_CrlEntryFree(entry);
    BSL_LIST_FREE(certIssuer.issuerName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
    return HITLS_PKI_SUCCESS;
EXIT:
    return -1;
}

/* BEGIN_CASE */
void SDV_X509_CRL_Sign_RevokedCheck_TC001(void)
{
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_SignAlgParam algParam = {0};
    HITLS_X509_CrlEntry *entry = NULL;
    BSL_TIME beforeTime = {0};
    BSL_TIME afterTime = {0};

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_RSA,
        "../testdata/cert/asn1/rsa_cert/rsa_p1.key.der", NULL, 0, &prvKey), 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/asn1/rsa_cert/rsa_p1_v1.crt.der", &cert),
        HITLS_PKI_SUCCESS);

    // Create a basic CRL object and set necessary fields
    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);
    BslList *issueList = crl->tbs.issuerName;
    // Set basic fields (version, time, issuer, etc.)
    crl->tbs.version = 1;
    crl->tbs.issuerName = cert->tbs.subjectName;
    ASSERT_EQ(BSL_SAL_SysTimeGet(&beforeTime), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);

    afterTime = beforeTime;
    afterTime.year += 1;
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);

    ASSERT_EQ(SetCrlRevoked(crl, 1), HITLS_PKI_SUCCESS);
    entry = BSL_LIST_GET_FIRST(crl->tbs.revokedCerts);
    ASSERT_TRUE(entry != NULL);

    crl->tbs.version = 0;
    ASSERT_EQ(HITLS_X509_CrlSign(BSL_CID_SHA256, prvKey, &algParam, crl), HITLS_X509_ERR_CRL_INACCURACY_VERSION);

    crl->tbs.version = 1;
    uint8_t *serialNum = entry->serialNumber.buff;
    entry->serialNumber.buff = NULL;
    ASSERT_EQ(HITLS_X509_CrlSign(BSL_CID_SHA256, prvKey, &algParam, crl), HITLS_X509_ERR_CRL_ENTRY);

    entry->serialNumber.buff = serialNum;
    uint32_t year = entry->time.year;
    entry->time.year = 0;
    ASSERT_EQ(HITLS_X509_CrlSign(BSL_CID_SHA256, prvKey, &algParam, crl), HITLS_X509_ERR_CRL_TIME_INVALID);

    entry->time.year = year;
EXIT:
    crl->tbs.issuerName = issueList;
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CertFree(cert);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
}
/* END_CASE */

static int32_t SetCrl(HITLS_X509_Crl *crl, HITLS_X509_Cert *cert, bool isV2)
{
    BSL_TIME beforeTime = {0};
    BSL_TIME afterTime = {0};
    BslList *issuerDN = NULL;
    uint8_t crlNumber[1] = {0x01};
    // Set CRL version (v2)
    uint32_t version = 1;
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);

    // Set issuer DN from certificate
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SUBJECT_DN, &issuerDN, sizeof(BslList *)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_ISSUER_DN, issuerDN, sizeof(BslList)),
        HITLS_PKI_SUCCESS);

    // Set validity period
    ASSERT_EQ(BSL_SAL_SysTimeGet(&beforeTime), BSL_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)),
        HITLS_PKI_SUCCESS);

    afterTime = beforeTime;
    afterTime.year += 1;
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)),
        HITLS_PKI_SUCCESS);
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ(SetCrlRevoked(crl, i), HITLS_PKI_SUCCESS);
    }
    if (isV2) {
        HITLS_X509_ExtSki ski = {0};
        int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SKI, &ski, sizeof(HITLS_X509_ExtSki));
        if (ret == HITLS_PKI_SUCCESS) {
            HITLS_X509_ExtAki aki = {false, {ski.kid.data, ski.kid.dataLen}, NULL, {NULL, 0}};
            // Set SKI extension
            ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_SET_AKI, &aki, sizeof(HITLS_X509_ExtAki)),
                HITLS_PKI_SUCCESS);
        }

        // Set CRL Number extension
        HITLS_X509_ExtCrlNumber crlNumberExt = {
            false,  // non-critical
            {crlNumber, sizeof(crlNumber)}
        };
        ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_SET_CRLNUMBER, &crlNumberExt,
            sizeof(HITLS_X509_ExtCrlNumber)), HITLS_PKI_SUCCESS);
    }
    return HITLS_PKI_SUCCESS;
EXIT:
    return -1;
}

/* BEGIN_CASE */
void SDV_X509_CRL_Sign_Func_TC001(char *cert, char *key, int keytype, int pad, int mdId, int isV2,
    char *tmp, int isUseSm2UserId)
{
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Crl *parseCrl = NULL;
    HITLS_X509_Cert *issuerCert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_SignAlgParam algParam = {0};
    TestRandInit();
    // Parse issuer certificate and private key
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, cert, &issuerCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, keytype, key, NULL, 0, &prvKey), 0);

    // Create and initialize CRL
    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);
    ASSERT_EQ(SetCrl(crl, issuerCert, (bool)isV2), 0);
    // Set signature algorithm parameters
    if (pad == CRYPT_EMSA_PSS) {
        algParam.algId = BSL_CID_RSASSAPSS;
        CRYPT_RSA_PssPara pssParam = {0};
        pssParam.mdId = mdId;
        pssParam.mgfId = mdId;
        pssParam.saltLen = 32;
        algParam.rsaPss = pssParam;
    } else if (isUseSm2UserId != 0) {
        algParam.algId = BSL_CID_SM2DSAWITHSM3;
        algParam.sm2UserId.data = (uint8_t *)g_sm2DefaultUserid;
        algParam.sm2UserId.dataLen = (uint32_t)strlen(g_sm2DefaultUserid);
    }

    if (pad == CRYPT_EMSA_PSS || isUseSm2UserId != 0) {
        ASSERT_EQ(HITLS_X509_CrlSign(mdId, prvKey, &algParam, crl), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CrlSign(mdId, prvKey, NULL, crl), HITLS_PKI_SUCCESS);
    }

    // Verify the signature is present
    ASSERT_NE(crl->signature.buff, NULL);
    ASSERT_NE(crl->signature.len, 0);
    ASSERT_EQ(HITLS_X509_CrlGenFile(BSL_FORMAT_ASN1, crl, tmp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlVerify(issuerCert->tbs.ealPubKey, crl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_UNKNOWN, tmp, &parseCrl), HITLS_PKI_SUCCESS);
    ASSERT_NE(parseCrl, NULL);
    if (isUseSm2UserId != 0) {
        ASSERT_EQ(HITLS_X509_CrlCtrl(parseCrl, HITLS_X509_SET_VFY_SM2_USER_ID, g_sm2DefaultUserid,
            strlen(g_sm2DefaultUserid)), HITLS_PKI_SUCCESS);
    }

    ASSERT_EQ(HITLS_X509_CrlVerify(issuerCert->tbs.ealPubKey, parseCrl), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CrlFree(parseCrl);
    HITLS_X509_CertFree(issuerCert);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
}
/* END_CASE */

static int32_t PrintToFile(int cmd, BSL_Buffer *data, char *outputPath)
{
    int32_t ret = -1;
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_FileMethod());
    ASSERT_NE(uio, NULL);
    ASSERT_EQ(BSL_UIO_Ctrl(uio, BSL_UIO_FILE_OPEN, BSL_UIO_FILE_WRITE, outputPath), 0);
    ASSERT_EQ(HITLS_PKI_PrintCtrl(cmd, data->data, data->dataLen, uio), 0);
    (void)SAL_Flush(BSL_UIO_GetCtx(uio));
    ret = 0;
    
EXIT:
    BSL_UIO_Free(uio);
    return ret;
}

static int32_t PrintTest(int cmd, BSL_Buffer *data, char *log, Hex *expect, char *outputPath)
{
    int32_t ret = -1;
    uint8_t *printBuf = NULL;
    uint32_t printBufLen = 0;
    uint8_t *expectBuf = NULL;
    uint32_t expectBufLen = 0;

    TestMemInit();
    ASSERT_EQ(PrintToFile(cmd, data, outputPath), 0);
    ASSERT_EQ(BSL_SAL_ReadFile(outputPath, &printBuf, &printBufLen), 0);

    ASSERT_EQ(BSL_SAL_ReadFile((char *)expect->x, &expectBuf, &expectBufLen), 0);
    ASSERT_COMPARE(log, expectBuf, expectBufLen, printBuf, printBufLen);
    ret = 0;

EXIT:
    BSL_SAL_Free(printBuf);
    BSL_SAL_FREE(expectBuf);
    return ret;
}

static int32_t SetCrlAllRevoked(HITLS_X509_Crl *crl, int8_t reasonCode, bool useGMT)
{
    // Set serial number
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};
    int endNum = 3;
    serialNum[endNum] = reasonCode;
    HITLS_X509_CrlEntry *entry = HITLS_X509_CrlEntryNew();
    ASSERT_NE(entry, NULL);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_SERIALNUM,
        serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);

    // Set revoke time
    BSL_TIME revokeTime = {2050, 1, 1, 0, 0, 0, 0, 0};
    if (!useGMT) {
        ASSERT_EQ(BSL_SAL_SysTimeGet(&revokeTime), BSL_SUCCESS);
    }
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME, &revokeTime, sizeof(BSL_TIME)),
        HITLS_PKI_SUCCESS);

    // Set reason code
    HITLS_X509_RevokeExtReason reason = {0, reasonCode};
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REASON, &reason,
        sizeof(HITLS_X509_RevokeExtReason)), HITLS_PKI_SUCCESS);

    // Set invalid time
    BSL_TIME invalidTime = revokeTime;
    invalidTime.year -= 1;
    HITLS_X509_RevokeExtTime invalidTimeExt = {false, invalidTime};
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_INVALID_TIME,
        &invalidTimeExt, sizeof(HITLS_X509_RevokeExtTime)), HITLS_PKI_SUCCESS);
        
    // Set certificate issuer
    HITLS_X509_RevokeExtCertIssuer certIssuer = {true, NULL};
    certIssuer.issuerName = GenGeneralNameList();
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_CERTISSUER,
        &certIssuer, sizeof(HITLS_X509_RevokeExtCertIssuer)), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_CRL_ADD_REVOKED_CERT, entry, sizeof(HITLS_X509_CrlEntry)),
        HITLS_PKI_SUCCESS);
    HITLS_X509_CrlEntryFree(entry);
    BSL_LIST_FREE(certIssuer.issuerName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);

    return HITLS_PKI_SUCCESS;
EXIT:
    if (entry != NULL) {
        HITLS_X509_CrlEntryFree(entry);
    }
    if (certIssuer.issuerName != NULL) {
        BSL_LIST_FREE(certIssuer.issuerName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
    }
    return -1;
}

static int32_t SetAllCrl(HITLS_X509_Crl *crl, HITLS_X509_Cert *cert, bool includeOptional, bool useGMT)
{
    BSL_TIME beforeTime = {2051, 1, 1, 0, 0, 0, 0, 0};
    BSL_TIME afterTime = {0};
    BslList *issuerDN = NULL;
    uint8_t crlNumber[1] = {0x01};
    int8_t reasonCodes[] = {0, 1, 2, 3, 4, 5, 6, 9, 10};
    // Set issuer DN from certificate
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SUBJECT_DN, &issuerDN, sizeof(BslList *)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_ISSUER_DN, issuerDN, sizeof(BslList)),
        HITLS_PKI_SUCCESS);

    // Set thisUpdate period
    if (!useGMT) {
        ASSERT_EQ(BSL_SAL_SysTimeGet(&beforeTime), BSL_SUCCESS);
    }
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)),
        HITLS_PKI_SUCCESS);

    // Set nextUpdate period
    afterTime = beforeTime;
    afterTime.year += 1;
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)),
        HITLS_PKI_SUCCESS);

    if (includeOptional) {
        // Set CRL version
        uint32_t version = 1;
        ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);

        // Set revoked certificates
        for (size_t i = 0; i < sizeof(reasonCodes)/sizeof(reasonCodes[0]); i++) {
            ASSERT_EQ(SetCrlAllRevoked(crl, reasonCodes[i], useGMT), HITLS_PKI_SUCCESS);
        }
        
        // Set AKI extension
        HITLS_X509_ExtSki ski = {0};
        BSL_Buffer serialNum = { NULL, 0 };
        ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SKI, &ski, sizeof(HITLS_X509_ExtSki)),
            HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM_STR, &serialNum, sizeof(BSL_Buffer)),
            HITLS_PKI_SUCCESS);
        HITLS_X509_ExtAki aki = {false, {ski.kid.data, ski.kid.dataLen}, issuerDN, serialNum};
        ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_SET_AKI, &aki, sizeof(HITLS_X509_ExtAki)), HITLS_PKI_SUCCESS);
        BSL_SAL_FREE(serialNum.data);

        // Set CRL Number extension
        HITLS_X509_ExtCrlNumber crlNumberExt = {false, {crlNumber, sizeof(crlNumber)}};
        ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_SET_CRLNUMBER, &crlNumberExt,
            sizeof(HITLS_X509_ExtCrlNumber)), HITLS_PKI_SUCCESS);
    }
    
    return HITLS_PKI_SUCCESS;
EXIT:
    return -1;
}

static int32_t CompareCrlExtLists(BslList *extList1, BslList *extList2)
{
    ASSERT_EQ(BSL_LIST_COUNT(extList1), BSL_LIST_COUNT(extList2));
    HITLS_X509_ExtEntry **extNode1 = BSL_LIST_First(extList1);
    HITLS_X509_ExtEntry **extNode2 = BSL_LIST_First(extList2);
    ASSERT_NE(*extNode1, NULL);
    ASSERT_NE(*extNode2, NULL);
    
    for (int32_t count = 0; count < BSL_LIST_COUNT(extList1); count++) {
        ASSERT_EQ((*extNode1)->critical, (*extNode2)->critical);
        ASSERT_EQ((*extNode1)->extnId.tag, (*extNode2)->extnId.tag);
        ASSERT_COMPARE("extnId",
            (*extNode1)->extnId.buff, (*extNode1)->extnId.len,
            (*extNode2)->extnId.buff, (*extNode2)->extnId.len);
        ASSERT_EQ((*extNode1)->extnValue.tag, (*extNode2)->extnValue.tag);
        ASSERT_COMPARE("extnValue",
            (*extNode1)->extnValue.buff, (*extNode1)->extnValue.len,
            (*extNode2)->extnValue.buff, (*extNode2)->extnValue.len);

        extNode1 = BSL_LIST_Next(extList1);
        extNode2 = BSL_LIST_Next(extList2);
    }
    return HITLS_PKI_SUCCESS;
EXIT:
    return -1;
}

static int32_t CompareSignAlgId(HITLS_X509_Asn1AlgId algId1, HITLS_X509_Asn1AlgId algId2, int isUseSm2UserId)
{
    ASSERT_EQ(algId1.algId, algId2.algId);

    if (isUseSm2UserId != 0) {
        ASSERT_EQ(algId1.sm2UserId.data, algId2.sm2UserId.data);
        ASSERT_EQ(algId1.sm2UserId.dataLen, algId2.sm2UserId.dataLen);
    } else {
        ASSERT_EQ(algId1.rsaPssParam.mdId, algId2.rsaPssParam.mdId);
        ASSERT_EQ(algId1.rsaPssParam.mgfId, algId2.rsaPssParam.mgfId);
        ASSERT_EQ(algId1.rsaPssParam.saltLen, algId2.rsaPssParam.saltLen);
    }
    return HITLS_PKI_SUCCESS;
EXIT:
    return -1;
}

static int32_t CompareBslTime(BSL_TIME time1, BSL_TIME time2, bool checkAll)
{
    ASSERT_EQ(time1.year, time2.year);
    ASSERT_EQ(time1.month, time2.month);
    ASSERT_EQ(time1.day, time2.day);
    ASSERT_EQ(time1.hour, time2.hour);
    ASSERT_EQ(time1.minute, time2.minute);
    ASSERT_EQ(time1.second, time2.second);
    if (checkAll) {
        ASSERT_EQ(time1.millSec, time2.millSec);
        ASSERT_EQ(time1.microSec, time2.microSec);
    }
    return HITLS_PKI_SUCCESS;
EXIT:
    return -1;
}

static int32_t ParseAllCrl(HITLS_X509_Crl *crl, HITLS_X509_Crl *parseCrl, bool includeOptional,
    bool useGMT, int isUseSm2UserId)
{
    int32_t count;
    // Parse TBS signatureAlgorithm
    ASSERT_EQ(CompareSignAlgId(crl->tbs.signAlgId, parseCrl->tbs.signAlgId, isUseSm2UserId), 0);

    // Parse issuer DN
    ASSERT_EQ(BSL_LIST_COUNT(crl->tbs.issuerName), BSL_LIST_COUNT(parseCrl->tbs.issuerName));
    HITLS_X509_NameNode **crlNameNode = BSL_LIST_First(crl->tbs.issuerName);
    HITLS_X509_NameNode **parseCrlNameNode = BSL_LIST_First(parseCrl->tbs.issuerName);
    ASSERT_NE(crlNameNode, NULL);
    ASSERT_NE(parseCrlNameNode, NULL);
    for (count = 0; count < BSL_LIST_COUNT(crl->tbs.issuerName); count++) {
        ASSERT_EQ((*crlNameNode)->layer, (*parseCrlNameNode)->layer);

        ASSERT_EQ((*crlNameNode)->nameType.tag, (*parseCrlNameNode)->nameType.tag);
        ASSERT_COMPARE("nameType", (*crlNameNode)->nameType.buff, (*crlNameNode)->nameType.len,
            (*parseCrlNameNode)->nameType.buff, (*parseCrlNameNode)->nameType.len);

        ASSERT_EQ((*crlNameNode)->nameValue.tag, (*parseCrlNameNode)->nameValue.tag);
        ASSERT_COMPARE("nameVlaue", (*crlNameNode)->nameValue.buff, (*crlNameNode)->nameValue.len,
            (*parseCrlNameNode)->nameValue.buff, (*parseCrlNameNode)->nameValue.len);

        crlNameNode = BSL_LIST_Next(crl->tbs.issuerName);
        parseCrlNameNode = BSL_LIST_Next(parseCrl->tbs.issuerName);
    }

    // Parse thisUpdate period
    if (useGMT) {
        ASSERT_EQ(crl->tbs.validTime.flag & BSL_TIME_BEFORE_IS_UTC, 0);
        ASSERT_EQ(parseCrl->tbs.validTime.flag & BSL_TIME_BEFORE_IS_UTC, 0);
    } else {
        ASSERT_NE(crl->tbs.validTime.flag & BSL_TIME_BEFORE_IS_UTC, 0);
        ASSERT_NE(parseCrl->tbs.validTime.flag & BSL_TIME_BEFORE_IS_UTC, 0);
    }
    ASSERT_EQ(CompareBslTime(crl->tbs.validTime.start, parseCrl->tbs.validTime.start, false), 0);

    if (includeOptional) {
        // Parse CRL version
        ASSERT_EQ(crl->tbs.version, parseCrl->tbs.version);

        // Parse nextUpdate period
        if (useGMT) {
            ASSERT_EQ(crl->tbs.validTime.flag & BSL_TIME_AFTER_IS_UTC, 0);
            ASSERT_EQ(parseCrl->tbs.validTime.flag & BSL_TIME_AFTER_IS_UTC, 0);
        } else {
            ASSERT_NE(crl->tbs.validTime.flag & BSL_TIME_AFTER_IS_UTC, 0);
            ASSERT_NE(parseCrl->tbs.validTime.flag & BSL_TIME_AFTER_IS_UTC, 0);
        }
        ASSERT_EQ(CompareBslTime(crl->tbs.validTime.end, parseCrl->tbs.validTime.end, false), 0);

        // Parse revoked certificates
        ASSERT_EQ(BSL_LIST_COUNT(crl->tbs.revokedCerts), BSL_LIST_COUNT(parseCrl->tbs.revokedCerts));
        HITLS_X509_CrlEntry *crlEntryNode = BSL_LIST_GET_FIRST(crl->tbs.revokedCerts);
        HITLS_X509_CrlEntry *parseCrlEntryNode = BSL_LIST_GET_FIRST(parseCrl->tbs.revokedCerts);
        ASSERT_NE(crlEntryNode, NULL);
        ASSERT_NE(parseCrlEntryNode, NULL);
        for (count = 0; count < BSL_LIST_COUNT(crl->tbs.revokedCerts); count++) {
            // Parse CRL serial number
            ASSERT_EQ(crlEntryNode->serialNumber.tag, parseCrlEntryNode->serialNumber.tag);
            ASSERT_COMPARE("serialNumber",
                crlEntryNode->serialNumber.buff, crlEntryNode->serialNumber.len,
                parseCrlEntryNode->serialNumber.buff, parseCrlEntryNode->serialNumber.len);
            // Parse CRL revoke time
            if (useGMT) {
                ASSERT_NE(crlEntryNode->flag & BSL_TIME_REVOKE_TIME_IS_GMT, 0);
                ASSERT_NE(parseCrlEntryNode->flag & BSL_TIME_REVOKE_TIME_IS_GMT, 0);
            } else {
                ASSERT_EQ(crlEntryNode->flag & BSL_TIME_REVOKE_TIME_IS_GMT, 0);
                ASSERT_EQ(parseCrlEntryNode->flag & BSL_TIME_REVOKE_TIME_IS_GMT, 0);
            }
            ASSERT_EQ(CompareBslTime(crlEntryNode->time, parseCrlEntryNode->time, false), 0);

            // Parse CRL entry extension
            ASSERT_EQ(CompareCrlExtLists(crlEntryNode->extList, parseCrlEntryNode->extList), 0);

            crlEntryNode = BSL_LIST_GET_NEXT(crl->tbs.revokedCerts);
            parseCrlEntryNode = BSL_LIST_GET_NEXT(parseCrl->tbs.revokedCerts);
        }

        // Parse CRL extension
        ASSERT_EQ(CompareCrlExtLists(crl->tbs.crlExt.extList, parseCrl->tbs.crlExt.extList), 0);
    }
    // Parse signatureAlgorithm
    ASSERT_EQ(CompareSignAlgId(crl->signAlgId, parseCrl->signAlgId, isUseSm2UserId), 0);

    // Parse signatureValue
    ASSERT_EQ(crl->signature.len, parseCrl->signature.len);
    ASSERT_COMPARE("signatureValue", crl->signature.buff, crl->signature.len, parseCrl->signature.buff,
        parseCrl->signature.len);
    ASSERT_EQ(crl->signature.unusedBits, parseCrl->signature.unusedBits);

    return HITLS_PKI_SUCCESS;
EXIT:
    return -1;
}

/* BEGIN_CASE */
void SDV_X509_CRL_GENCONSISTANT_FUNC_TC001(char *cert, char *key, int keyType, int pad, int mdId, int includeOptional,
    int useGMT, int isUseSm2UserId, char *crlFile, int printFlag, char *printCrlFile, char *printParseCrlFile)
{
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Crl *parseCrl = NULL;
    HITLS_X509_Cert *issuerCert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_SignAlgParam algParam = {0};
    TestRandInit();
    // Parse issuer certificate and private key
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, cert, &issuerCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, keyType, key, NULL, 0, &prvKey), 0);

    // Create and initialize CRL
    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);
    ASSERT_EQ(SetAllCrl(crl, issuerCert, (bool)includeOptional, (bool)useGMT), 0);
    // Set signature algorithm parameters
    if (pad == CRYPT_EMSA_PSS) {
        algParam.algId = BSL_CID_RSASSAPSS;
        CRYPT_RSA_PssPara pssParam = {0};
        int32_t saltLen = 32;
        pssParam.mdId = mdId;
        pssParam.mgfId = mdId;
        pssParam.saltLen = saltLen;
        algParam.rsaPss = pssParam;
    } else if (isUseSm2UserId != 0) {
        algParam.algId = BSL_CID_SM2DSAWITHSM3;
        algParam.sm2UserId.data = (uint8_t *)g_sm2DefaultUserid;
        algParam.sm2UserId.dataLen = (uint32_t)strlen(g_sm2DefaultUserid);
    }

    if (pad == CRYPT_EMSA_PSS || isUseSm2UserId != 0) {
        ASSERT_EQ(HITLS_X509_CrlSign(mdId, prvKey, &algParam, crl), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CrlSign(mdId, prvKey, NULL, crl), HITLS_PKI_SUCCESS);
    }

    ASSERT_NE(crl->signature.buff, NULL);
    ASSERT_NE(crl->signature.len, 0);
    ASSERT_EQ(HITLS_X509_CrlGenFile(BSL_FORMAT_ASN1, crl, crlFile), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlVerify(issuerCert->tbs.ealPubKey, crl), HITLS_PKI_SUCCESS);
    BSL_Buffer data = {(uint8_t *)crl, sizeof(HITLS_X509_Crl *)};
    ASSERT_EQ(HITLS_PKI_PrintCtrl(HITLS_PKI_SET_PRINT_FLAG, &printFlag, sizeof(int), NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(PrintToFile(HITLS_PKI_PRINT_CRL, &data, printCrlFile), 0);

    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_UNKNOWN, crlFile, &parseCrl), HITLS_PKI_SUCCESS);
    ASSERT_NE(parseCrl, NULL);
    if (isUseSm2UserId != 0) {
        ASSERT_EQ(HITLS_X509_CrlCtrl(parseCrl, HITLS_X509_SET_VFY_SM2_USER_ID, g_sm2DefaultUserid,
            strlen(g_sm2DefaultUserid)), HITLS_PKI_SUCCESS);
    }
    ASSERT_EQ(HITLS_X509_CrlVerify(issuerCert->tbs.ealPubKey, parseCrl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(ParseAllCrl(crl, parseCrl, (bool)includeOptional, (bool)useGMT, isUseSm2UserId), 0);

    BSL_Buffer parseData = {(uint8_t *)parseCrl, sizeof(HITLS_X509_Crl *)};
    Hex expect = {(uint8_t *)printCrlFile, 0};
    ASSERT_EQ(PrintTest(HITLS_PKI_PRINT_CRL, &parseData, "Print parse crl file", &expect, printParseCrlFile), 0);

EXIT:
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CrlFree(parseCrl);
    HITLS_X509_CertFree(issuerCert);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_PARSE_ERRORPARAM_FUNC_TC001(char *path, int res)
{
    HITLS_X509_Crl *crl = NULL;
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, path, &crl), res);
EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_GEN_SETVER0NOEXT_FUNC_TC001(char *cert, char *key, char *crlFile)
{
    uint32_t version = 0;
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Crl *parseCrl = NULL;
    HITLS_X509_Cert *issuerCert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    TestRandInit();

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, cert, &issuerCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, CRYPT_PRIKEY_PKCS8_UNENCRYPT, key, NULL, 0, &prvKey), 0);

    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);
    ASSERT_EQ(SetAllCrl(crl, issuerCert, 0, 0), 0);
    // Set CRL version
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlSign(CRYPT_MD_SHA384, prvKey, NULL, crl), HITLS_PKI_SUCCESS);

    ASSERT_NE(crl->signature.buff, NULL);
    ASSERT_NE(crl->signature.len, 0);
    ASSERT_EQ(HITLS_X509_CrlGenFile(BSL_FORMAT_ASN1, crl, crlFile), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlVerify(issuerCert->tbs.ealPubKey, crl), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_UNKNOWN, crlFile, &parseCrl), HITLS_PKI_SUCCESS);
    ASSERT_NE(parseCrl, NULL);
    ASSERT_EQ(HITLS_X509_CrlVerify(issuerCert->tbs.ealPubKey, parseCrl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(crl->tbs.version, parseCrl->tbs.version);
    ASSERT_EQ(parseCrl->tbs.version, version);

EXIT:
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CrlFree(parseCrl);
    HITLS_X509_CertFree(issuerCert);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_GEN_SETEXTERRVER_FUNC_TC001(char *cert, char *key, int withExt, int withEntryExt)
{
    uint32_t version = 0;
    uint8_t crlNumber[1] = {0x01};
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Cert *issuerCert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    TestRandInit();

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, cert, &issuerCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, CRYPT_PRIKEY_PKCS8_UNENCRYPT, key, NULL, 0, &prvKey), 0);

    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);
    ASSERT_EQ(SetAllCrl(crl, issuerCert, 0, 0), 0);
    if (withExt && !withEntryExt) {
         // Set CRL Number extension
        HITLS_X509_ExtCrlNumber crlNumberExt = {false, {crlNumber, sizeof(crlNumber)}};
        ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_SET_CRLNUMBER, &crlNumberExt,
            sizeof(HITLS_X509_ExtCrlNumber)), HITLS_PKI_SUCCESS);
        ASSERT_EQ(HITLS_X509_CrlSign(CRYPT_MD_SHA384, prvKey, NULL, crl), HITLS_X509_ERR_CRL_INACCURACY_VERSION);
    } else if (!withExt && withEntryExt) {
        // Set revoked certificates
        ASSERT_EQ(SetCrlAllRevoked(crl, 0, 0), HITLS_PKI_SUCCESS);
    } else if (withExt && withEntryExt) {
        ASSERT_EQ(SetAllCrl(crl, issuerCert, 1, 0), 0);
    }
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlSign(CRYPT_MD_SHA384, prvKey, NULL, crl), HITLS_X509_ERR_CRL_INACCURACY_VERSION);

EXIT:
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CertFree(issuerCert);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_GEN_ERRPRVKEY_FUNC_TC001(char *cert, char *key)
{
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Cert *issuerCert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    TestRandInit();

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, cert, &issuerCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, CRYPT_PRIKEY_PKCS8_UNENCRYPT, key, NULL, 0, &prvKey), 0);

    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);
    ASSERT_EQ(SetAllCrl(crl, issuerCert, 0, 0), 0);
    prvKey->id = CRYPT_PKEY_RSA;
    ASSERT_EQ(HITLS_X509_CrlSign(CRYPT_MD_SHA384, prvKey, NULL, crl), CRYPT_ECC_PKEY_ERR_UNSUPPORTED_CTRL_OPTION);

    prvKey->id = CRYPT_PKEY_X25519;
    ASSERT_EQ(HITLS_X509_CrlSign(CRYPT_MD_SHA384, prvKey, NULL, crl), HITLS_X509_ERR_CERT_SIGN_ALG);

    prvKey->id = (CRYPT_PKEY_AlgId)0xFFFF;
    ASSERT_EQ(HITLS_X509_CrlSign(CRYPT_MD_SHA384, prvKey, NULL, crl), HITLS_X509_ERR_CERT_SIGN_ALG);

    prvKey->id = CRYPT_PKEY_ECDSA;
    ASSERT_EQ(HITLS_X509_CrlSign(CRYPT_MD_SHA384, prvKey, NULL, crl), HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CertFree(issuerCert);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_GEN_ERRBSLTIME_FUNC_TC001(char *cert, char *key, char *crlFile)
{
    BSL_TIME time = {0};
    BSL_TIME parseTime = {0};
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Crl *parseCrl = NULL;
    HITLS_X509_Cert *issuerCert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_CrlEntry *entry = HITLS_X509_CrlEntryNew();
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};
    TestRandInit();

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, cert, &issuerCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, CRYPT_PRIKEY_PKCS8_UNENCRYPT, key, NULL, 0, &prvKey), 0);

    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);
    ASSERT_EQ(SetAllCrl(crl, issuerCert, 0, 0), 0);

    BSL_TIME errorTime = {2025, 2, 30, 0, 0, 0, 0, 0};
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_BEFORE_TIME, &errorTime, sizeof(BSL_TIME)),
        HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_AFTER_TIME, &errorTime, sizeof(BSL_TIME)),
        HITLS_X509_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME, &errorTime, sizeof(BSL_TIME)),
        HITLS_X509_ERR_INVALID_PARAM);
    HITLS_X509_RevokeExtTime invalidTimeExt1 = {false, errorTime};
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_INVALID_TIME,
        &invalidTimeExt1, sizeof(HITLS_X509_RevokeExtTime)), BSL_ASN1_ERR_CHECK_TIME);

    BSL_TIME testTime1 = {2025, 1, 1, 0, 0, 999, 59, 999};
    BSL_TIME nextUpdateTime1 = {2025, 1, 2, 0, 0, 999, 59, 999};
    BSL_TIME testTime2 = {2025, 1, 1, 0, 0, 0, 59, 0};
    BSL_TIME nextUpdateTime2 = {2025, 1, 2, 0, 0, 0, 59, 0};
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_BEFORE_TIME, &testTime1, sizeof(BSL_TIME)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_AFTER_TIME, &nextUpdateTime1, sizeof(BSL_TIME)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_SERIALNUM,
        serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME, &testTime1, sizeof(BSL_TIME)),
        HITLS_PKI_SUCCESS);
    HITLS_X509_RevokeExtTime invalidTimeExt2 = {false, testTime1};
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_INVALID_TIME,
        &invalidTimeExt2, sizeof(HITLS_X509_RevokeExtTime)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_CRL_ADD_REVOKED_CERT, entry, sizeof(HITLS_X509_CrlEntry)),
        HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CrlSign(CRYPT_MD_SHA384, prvKey, NULL, crl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlGenFile(BSL_FORMAT_ASN1, crl, crlFile), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlVerify(issuerCert->tbs.ealPubKey, crl), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_UNKNOWN, crlFile, &parseCrl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlVerify(issuerCert->tbs.ealPubKey, parseCrl), HITLS_PKI_SUCCESS);
    HITLS_X509_CrlEntry *parseEntry = BSL_LIST_GET_FIRST(parseCrl->tbs.revokedCerts);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_INVALID_TIME, &time, sizeof(BSL_TIME)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(parseEntry, HITLS_X509_CRL_GET_REVOKED_INVALID_TIME, &parseTime,
        sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CompareBslTime(crl->tbs.validTime.start, testTime1, true), 0);
    ASSERT_EQ(CompareBslTime(crl->tbs.validTime.end, nextUpdateTime1, true), 0);
    ASSERT_EQ(CompareBslTime(entry->time, testTime1, true), 0);
    ASSERT_EQ(CompareBslTime(time, testTime2, true), 0);
    ASSERT_EQ(CompareBslTime(parseCrl->tbs.validTime.start, testTime2, true), 0);
    ASSERT_EQ(CompareBslTime(parseCrl->tbs.validTime.end, nextUpdateTime2, true), 0);
    ASSERT_EQ(CompareBslTime(parseEntry->time, testTime2, true), 0);
    ASSERT_EQ(CompareBslTime(parseTime, testTime2, true), 0);

EXIT:
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CrlFree(parseCrl);
    HITLS_X509_CrlEntryFree(entry);
    HITLS_X509_CertFree(issuerCert);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_GEN_NULLISSUER_FUNC_TC001(void)
{
    HITLS_X509_Crl *crl = NULL;
    BslList *issuerDN = NULL;
    TestRandInit();

    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_ISSUER_DN, issuerDN, sizeof(BslList)),
        HITLS_X509_ERR_INVALID_PARAM);

EXIT:
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_GEN_NULLREVOKED_FUNC_TC001(char *cert, int timeNull)
{
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Cert *issuerCert = NULL;
    HITLS_X509_CrlEntry *entry = HITLS_X509_CrlEntryNew();
    TestRandInit();

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, cert, &issuerCert), HITLS_PKI_SUCCESS);

    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);
    ASSERT_EQ(SetAllCrl(crl, issuerCert, 0, 0), 0);
    if (timeNull) {
        uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};
        ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_SERIALNUM,
            serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);
    } else {
        BSL_TIME revokeTime = {0};
        ASSERT_EQ(BSL_SAL_SysTimeGet(&revokeTime), BSL_SUCCESS);
        ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME, &revokeTime, sizeof(BSL_TIME)),
            HITLS_PKI_SUCCESS);
    }
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_CRL_ADD_REVOKED_CERT, entry, sizeof(HITLS_X509_CrlEntry)),
        HITLS_X509_ERR_CRL_ENTRY);

EXIT:
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CrlEntryFree(entry);
    HITLS_X509_CertFree(issuerCert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_GEN_NULLAKI_FUNC_TC001(char *cert)
{
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Cert *issuerCert = NULL;
    TestRandInit();

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, cert, &issuerCert), HITLS_PKI_SUCCESS);
    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);
    ASSERT_EQ(SetAllCrl(crl, issuerCert, 0, 0), 0);

    HITLS_X509_ExtSki ski = {0};
    HITLS_X509_ExtAki aki = {false, {ski.kid.data, ski.kid.dataLen}, NULL, {NULL, 0}};
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_SET_AKI, &aki, sizeof(HITLS_X509_ExtAki)), HITLS_X509_ERR_EXT_KID);

EXIT:
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CertFree(issuerCert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_GEN_ERRCRLNUMBER_FUNC_TC001(char *cert)
{
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Cert *issuerCert = NULL;
    uint8_t errLen[21] = {0};
    TestRandInit();

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, cert, &issuerCert), HITLS_PKI_SUCCESS);
    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);
    ASSERT_EQ(SetAllCrl(crl, issuerCert, 0, 0), 0);

    HITLS_X509_ExtCrlNumber crlNumberExt = {false, {errLen, sizeof(errLen)}};
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_SET_CRLNUMBER, &crlNumberExt,
        sizeof(HITLS_X509_ExtCrlNumber)), HITLS_X509_ERR_EXT_CRLNUMBER);

EXIT:
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CertFree(issuerCert);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_GEN_ERRREASONCODE_FUNC_TC001(char *cert, char *key, char *crlFile)
{
    uint32_t version = 1;
    HITLS_X509_Crl *crl = NULL;
    HITLS_X509_Cert *issuerCert = NULL;
    CRYPT_EAL_PkeyCtx *prvKey = NULL;
    HITLS_X509_CrlEntry *entry = HITLS_X509_CrlEntryNew();
    int errReasonCode1 = 7;
    int errReasonCode2 = 11;
    int removeFromCRL = 8;
    TestRandInit();

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_UNKNOWN, cert, &issuerCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, CRYPT_PRIKEY_PKCS8_UNENCRYPT, key, NULL, 0, &prvKey), 0);
    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);
    ASSERT_EQ(SetAllCrl(crl, issuerCert, 0, 0), 0);

    HITLS_X509_RevokeExtReason reason = {0, errReasonCode1};
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REASON, &reason,
        sizeof(HITLS_X509_RevokeExtReason)), HITLS_X509_ERR_INVALID_PARAM);
    reason.reason = errReasonCode2;
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REASON, &reason,
        sizeof(HITLS_X509_RevokeExtReason)), HITLS_X509_ERR_INVALID_PARAM);

    ASSERT_EQ(SetCrlAllRevoked(crl, removeFromCRL, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlSign(CRYPT_MD_SHA384, prvKey, NULL, crl), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlGenFile(BSL_FORMAT_ASN1, crl, crlFile), HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CrlEntryFree(entry);
    HITLS_X509_CertFree(issuerCert);
    CRYPT_EAL_PkeyFreeCtx(prvKey);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_X509_CRL_GEN_NULLCERTISSUER_FUNC_TC001(void)
{
    HITLS_X509_CrlEntry *entry = HITLS_X509_CrlEntryNew();
    HITLS_X509_RevokeExtCertIssuer certIssuer = {true, NULL};
    TestRandInit();

    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_CERTISSUER,
        &certIssuer, sizeof(HITLS_X509_RevokeExtCertIssuer)), HITLS_X509_ERR_EXT_SAN);

EXIT:
    HITLS_X509_CrlEntryFree(entry);
}
/* END_CASE */

static int32_t STUB_HITLS_X509_ParseNameList(BSL_ASN1_Buffer *name, BSL_ASN1_List *list)
{
    (void)name;
    (void)list;
    return BSL_MALLOC_FAIL;
}

/* BEGIN_CASE */
void SDV_X509_CRL_INVALIED_TEST_TC001(int format, char *path)
{
    TestMemInit();
    STUB_REPLACE(HITLS_X509_ParseNameList, STUB_HITLS_X509_ParseNameList);
    HITLS_X509_Crl *crl = NULL;
    ASSERT_NE(HITLS_X509_CrlParseFile((int32_t)format, path, &crl), HITLS_PKI_SUCCESS);
EXIT:
    STUB_RESTORE(HITLS_X509_ParseNameList);
    HITLS_X509_CrlFree(crl);
}
/* END_CASE */

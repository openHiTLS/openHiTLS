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
#include "hitls_x509.h"
#include "hitls_x509_errno.h"
#include "bsl_type.h"
#include "bsl_log.h"
#include "sal_file.h"
#include "bsl_init.h"
#include "hitls_pkcs12_local.h"
#include "hitls_crl_local.h"
#include "hitls_cert_type.h"
#include "hitls_cert_local.h"
#include "bsl_type.h"
#include "crypt_errno.h"

/* END_HEADER */

static void BagListsDestroyCb(void *bag)
{
    HTILS_PKCS12_SafeBagFree((HTILS_PKCS12_SafeBag *)bag);
}

static void AttributesFree(void *attribute)
{
    HTILS_PKCS12_SafeBagAttr *input = (HTILS_PKCS12_SafeBagAttr *)attribute;
    BSL_SAL_FREE(input->attrValue->data);
    BSL_SAL_FREE(input->attrValue);
    BSL_SAL_FREE(input);
}

/**
 * For test parse safeBag-p8shroudkeyBag of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_SAFEBAGS_OF_PKCS8SHROUDEDKEYBAG_TC001(int algId, Hex *buff, int keyBits)
{
    BSL_Buffer safeContent = {0};
    BSL_ASN1_List *bagLists = BSL_LIST_New(sizeof(HTILS_PKCS12_SafeBag));
    ASSERT_NE(bagLists, NULL);

    char *pwd = "123456";
    uint32_t len = strlen(pwd);
    int32_t bits = 0;

    // parse contentInfo
    int32_t ret = HITLS_PKCS12_ParseContentInfo((BSL_Buffer *)buff, NULL, 0, &safeContent);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    HTILS_PKCS12_p12Info *p12 = HTILS_PKCS12_p12_InfoNew();
    ASSERT_NE(p12, NULL);

    // get the safeBag of safeContents, and put in list.
    ret = HITLS_PKCS12_ParseAsn1AddList(&safeContent, bagLists, BSL_CID_SAFECONTENT);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    // get key of the bagList.
    ret = HITLS_PKCS12_ParseSafeBagList(bagLists, (const uint8_t *)pwd, len, p12);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(p12->key->value.key, NULL);
    bits = CRYPT_EAL_PkeyGetKeyBits(p12->key->value.key);
    if (algId == CRYPT_PKEY_ECDSA) {
        ASSERT_EQ(((((keyBits - 1) / 8) + 1) * 2 + 1) * 8, bits); // cal len of pub
    } else if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(bits, keyBits);
    }
exit:
    BSL_SAL_Free(safeContent.data);
    BSL_LIST_DeleteAll(bagLists, BagListsDestroyCb);
    BSL_SAL_Free(bagLists);
    HTILS_PKCS12_p12_InfoFree(p12);
}
/* END_CASE */

/**
 * For test parse safeBag-cert of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_SAFEBAGS_OF_CERTBAGS_TC001(Hex *buff)
{
    BSL_ASN1_List *bagLists = BSL_LIST_New(sizeof(HTILS_PKCS12_SafeBag));
    ASSERT_NE(bagLists, NULL);

    HTILS_PKCS12_p12Info *p12 = HTILS_PKCS12_p12_InfoNew();
    ASSERT_NE(p12, NULL);

    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);
    BSL_Buffer safeContent = {0};

    // parse contentInfo
    int32_t ret = HITLS_PKCS12_ParseContentInfo((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, &safeContent);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    // get the safeBag of safeContents, and put int list.
    ret = HITLS_PKCS12_ParseAsn1AddList(&safeContent, bagLists, BSL_CID_SAFECONTENT);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    // get cert of the bagList.
    ret = HITLS_PKCS12_ParseSafeBagList(bagLists, NULL, 0, p12);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

exit:
    BSL_SAL_Free(safeContent.data);
    BSL_LIST_DeleteAll(bagLists, BagListsDestroyCb);
    HTILS_PKCS12_p12_InfoFree(p12);
    BSL_SAL_Free(bagLists);
}
/* END_CASE */

/**
 * For test parse attributes of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_SAFEBAGS_OF_ATTRIBUTE_TC001(Hex *buff, Hex *friendlyName, Hex *locatedId)
{
    BSL_ASN1_List *attrbutes = BSL_LIST_New(sizeof(HTILS_PKCS12_SafeBagAttr));
    ASSERT_NE(attrbutes, NULL);

    BSL_ASN1_Buffer asn = {
        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET,
        buff->len,
        buff->x,
    };
    int32_t ret = HITLS_PKCS12_ParseSafeBagAttr(&asn, attrbutes);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    HTILS_PKCS12_SafeBagAttr *firstAttr = BSL_LIST_GET_FIRST(attrbutes);
    HTILS_PKCS12_SafeBagAttr *second = BSL_LIST_GET_NEXT(attrbutes);
    if (firstAttr->attrId == BSL_CID_FRIENDLYNAME) {
        ASSERT_EQ(memcmp(firstAttr->attrValue->data, friendlyName->x, friendlyName->len), 0);
    }
    if (firstAttr->attrId == BSL_CID_LOCATEDID) {
        ASSERT_EQ(memcmp(firstAttr->attrValue->data, locatedId->x, locatedId->len), 0);
    }
    if (second == NULL) {
        ASSERT_EQ(friendlyName->len, 0);
    } else {
        if (second->attrId == BSL_CID_FRIENDLYNAME) {
            ASSERT_EQ(memcmp(second->attrValue->data, friendlyName->x, friendlyName->len), 0);
        }
        if (second->attrId == BSL_CID_LOCATEDID) {
            ASSERT_EQ(memcmp(second->attrValue->data, locatedId->x, locatedId->len), 0);
        }
    }
exit:
    BSL_LIST_DeleteAll(attrbutes, AttributesFree);
    BSL_SAL_FREE(attrbutes);
}
/* END_CASE */

/**
 * For test parse attributes in the incorrect condition.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_SAFEBAGS_OF_ATTRIBUTE_TC002(Hex *buff)
{
    BSL_ASN1_List *attrbutes = BSL_LIST_New(sizeof(HTILS_PKCS12_SafeBagAttr));
    ASSERT_NE(attrbutes, NULL);

    BSL_ASN1_Buffer asn = {
        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET,
        0,
        buff->x,
    };
    int32_t ret = HITLS_PKCS12_ParseSafeBagAttr(&asn, attrbutes);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS); //  bagAttributes are OPTIONAL
    asn.len = buff->len;
    ret = HITLS_PKCS12_ParseSafeBagAttr(&asn, attrbutes);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    buff->x[4] = 0x00; // 4 is a random number.
    ret = HITLS_PKCS12_ParseSafeBagAttr(&asn, attrbutes);
    ASSERT_NE(ret, HITLS_X509_SUCCESS);
exit:
    BSL_LIST_DeleteAll(attrbutes, AttributesFree);
    BSL_SAL_FREE(attrbutes);
}
/* END_CASE */

/**
 * For test parse authSafedata of tampering Cert-info with encrypted data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_AUTHSAFE_TC001(Hex *wrongCert)
{
    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);
    // parse authSafe
    HTILS_PKCS12_p12Info *p12 = HTILS_PKCS12_p12_InfoNew();
    int32_t ret = HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)wrongCert, (const uint8_t *)pwd, pwdlen, p12);
    ASSERT_NE(ret, HITLS_X509_SUCCESS);

    char *pwd1 = "123456-789";
    uint32_t pwdlen1 = strlen(pwd1);
    ret = HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)wrongCert, (const uint8_t *)pwd1, pwdlen1, p12);
    ASSERT_EQ(ret, CRYPT_EAL_CIPHER_DATA_ERROR);

    char *pwd2 = "";
    uint32_t pwdlen2 = strlen(pwd2);
    ret = HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)wrongCert, (const uint8_t *)pwd2, pwdlen2, p12);
    ASSERT_EQ(ret, CRYPT_EAL_CIPHER_DATA_ERROR);

exit:
    HTILS_PKCS12_p12_InfoFree(p12);
    return;
}
/* END_CASE */

/**
 * For test parse authSafedata of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_AUTHSAFE_TC002(Hex *buff)
{
    HTILS_PKCS12_p12Info *p12 = HTILS_PKCS12_p12_InfoNew();

    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);
    // parse authSafe
    int32_t ret = HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, p12);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(p12->key, NULL);
    ASSERT_NE(p12->entityCert, NULL);
exit:
    HTILS_PKCS12_p12_InfoFree(p12);
    return;
}
/* END_CASE */

/**
 * For test parse 12 of macData parse.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_MACDATA_TC001(Hex *buff, int alg, Hex *digest, Hex *salt, int iterations)
{
    HTILS_PKCS12_MacData *macData = HTILS_PKCS12_p12_macDataNew();
    int32_t ret = HITLS_PKCS12_ParseMacData((BSL_Buffer *)buff, macData);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(macData->alg, alg);
    ASSERT_EQ(macData->interation, iterations);
    ASSERT_EQ(memcmp(macData->macSalt->data, salt->x, salt->len), 0);
    ASSERT_EQ(memcmp(macData->mac->data, digest->x, digest->len), 0);
exit:
    HTILS_PKCS12_p12_macDataFree(macData);
    return;
}
/* END_CASE */

/**
 * For test parse 12 of wrong macData parse.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_MACDATA_TC002(Hex *buff)
{
    HTILS_PKCS12_MacData *macData = HTILS_PKCS12_p12_macDataNew();
    int32_t ret = HITLS_PKCS12_ParseMacData(NULL, macData);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_ParseMacData((BSL_Buffer *)buff, macData);
    ASSERT_EQ(ret, CRYPT_DECODE_UNKNOWN_OID);
exit:
    HTILS_PKCS12_p12_macDataFree(macData);
    return;
}
/* END_CASE */

/**
 * For test parse 12 of macData cal.
*/
/* BEGIN_CASE */
void SDV_PKCS12_CAL_MACDATA_TC001(Hex *initData, Hex *salt, int alg, int iter, Hex *mac)
{
    HTILS_PKCS12_MacData *macData = HTILS_PKCS12_p12_macDataNew();
    macData->alg = alg;
    macData->macSalt->data = salt->x;
    macData->macSalt->dataLen = salt->len;
    macData->interation = iter;
    char *pwdData = "123456";
    uint32_t pwdlen = strlen(pwdData);
    BSL_Buffer output = {0};
    BSL_Buffer pwd = {(uint8_t *)pwdData, pwdlen};
    int32_t ret = HTILS_PKCS12_CalMac(&output, &pwd, (BSL_Buffer *)initData, macData);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(memcmp(output.data, mac->x, mac->len), 0);
exit:
    BSL_SAL_FREE(macData->mac);
    BSL_SAL_FREE(macData->macSalt);
    BSL_SAL_FREE(macData);
    BSL_SAL_Free(output.data);
    return;
}
/* END_CASE */

/**
 * For test cal key according to salt, alg, etc.
*/
/* BEGIN_CASE */
void SDV_PKCS12_CAL_KDF_TC001(Hex *pwd, Hex *salt, int alg, int iter, Hex *key)
{
    HTILS_PKCS12_MacData *macData = HTILS_PKCS12_p12_macDataNew();
    macData->alg = alg;
    macData->macSalt->data = salt->x;
    macData->macSalt->dataLen = salt->len;
    macData->interation = iter;
    uint8_t outData[64] = {0};
    BSL_Buffer output = {outData, 64};
    int32_t ret = HTILS_PKCS12_KDF(&output, pwd->x, pwd->len, HITLS_PKCS12_KDF_MACKEY_ID, macData);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(memcmp(output.data, key->x, key->len), 0);
exit:
    BSL_SAL_FREE(macData->mac);
    BSL_SAL_FREE(macData->macSalt);
    BSL_SAL_FREE(macData);
    return;
}
/* END_CASE */

/**
 * For test parse 12 of right conditions.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_P12_TC001(Hex *encode, Hex *cert)
{
    char *pwd = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);

    HTILS_PKCS12_p12Info *p12 = HTILS_PKCS12_p12_InfoNew();
    ASSERT_NE(p12, NULL);
    HTILS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &encPwd,
    };
    int32_t ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(p12->key, NULL);
    ASSERT_NE(p12->entityCert, NULL);
    BSL_Buffer encodeCert = {0};
    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12->entityCert->value.cert, &encodeCert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(memcmp(encodeCert.data, cert->x, cert->len), 0);
exit:
    BSL_SAL_Free(encodeCert.data);
    HTILS_PKCS12_p12_InfoFree(p12);
    return;
}
/* END_CASE */

/**
 * For test parse 12 of right conditions (no Mac).
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_P12_TC002(Hex *encode, Hex *cert)
{
    char *pwd = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);

    HTILS_PKCS12_p12Info *p12 = HTILS_PKCS12_p12_InfoNew();
    ASSERT_NE(p12, NULL);
    HTILS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
    };
    int32_t ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, false);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(p12->key, NULL);
    ASSERT_NE(p12->entityCert, NULL);
    BSL_Buffer encodeCert = {0};
    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12->entityCert->value.cert, &encodeCert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(memcmp(encodeCert.data, cert->x, cert->len), 0);
exit:
    BSL_SAL_Free(encodeCert.data);
    HTILS_PKCS12_p12_InfoFree(p12);
    return;
}
/* END_CASE */

/**
 * For test parse 12 of wrong conditions.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_P12_WRONG_CONDITIONS_TC001(Hex *encode)
{
    char *pwd1 = "1234567";
    char *pwd2 = "1234567";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd1;
    encPwd.dataLen = strlen(pwd1);
    BSL_Buffer macPwd;
    macPwd.data = (uint8_t *)pwd2;
    macPwd.dataLen = strlen(pwd2);

    HTILS_PKCS12_p12Info *p12 = HTILS_PKCS12_p12_InfoNew();
    ASSERT_NE(p12, NULL);
    HTILS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &macPwd,
    };

    int32_t ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, NULL, &param, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, NULL, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, NULL, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

    char *pwd3 = "";
    macPwd.data = (uint8_t *)pwd3;
    macPwd.dataLen = strlen(pwd3);
    param.macPwd = &macPwd;
    ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

    param.macPwd = NULL;
    ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

    param.encPwd = NULL;
    ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    char *pwd4 = "123456";
    param.encPwd = &encPwd;
    macPwd.data = (uint8_t *)pwd4;
    macPwd.dataLen = strlen(pwd4);
    param.macPwd = &macPwd;
    ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, CRYPT_EAL_CIPHER_DATA_ERROR);

    encPwd.data = (uint8_t *)pwd4;
    encPwd.dataLen = strlen(pwd4);
    ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    encode->x[6] = 0x04; // Modify the version = 4.
    ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_INVALID_PFX);
exit:
    HTILS_PKCS12_p12_InfoFree(p12);
    return;
}
/* END_CASE */

/**
 * For test parse 12 of wrong p12-file.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_P12_WRONG_P12FILE_TC001(Hex *encode)
{
    char *pwd1 = "123456";
    char *pwd2 = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd1;
    encPwd.dataLen = strlen(pwd1);
    BSL_Buffer macPwd;
    macPwd.data = (uint8_t *)pwd2;
    macPwd.dataLen = strlen(pwd2);

    HTILS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &macPwd,
    };

    HTILS_PKCS12_p12Info *p12_1 = HTILS_PKCS12_p12_InfoNew();
    ASSERT_NE(p12_1, NULL);
    HTILS_PKCS12_p12Info *p12_2 = HTILS_PKCS12_p12_InfoNew();
    ASSERT_NE(p12_2, NULL);
    int32_t ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12_1, true);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    encode->x[encode->len - 2] = 0x04; // modify the iteration = 1024;
    ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12_2, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

    encode->x[encode->len - 2] = 0x08; // recover the iteration = 2048;
    (void)memset_s(encode->x + 96, 16, 0, 16); // modify the contentInfo
    ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12_2, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

exit:
    HTILS_PKCS12_p12_InfoFree(p12_1);
    HTILS_PKCS12_p12_InfoFree(p12_2);
    return;
}
/* END_CASE */

/**
 * For test parse 12 of wrong p12-file, which miss a part of data randomly.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_P12_WRONG_P12FILE_TC002(Hex *encode)
{
    char *pwd1 = "123456";
    char *pwd2 = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd1;
    encPwd.dataLen = strlen(pwd1);
    BSL_Buffer macPwd;
    macPwd.data = (uint8_t *)pwd2;
    macPwd.dataLen = strlen(pwd2);

    HTILS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &macPwd,
    };

    HTILS_PKCS12_p12Info *p12 = HTILS_PKCS12_p12_InfoNew();
    ASSERT_NE(p12, NULL);
    int32_t ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_NE(ret, HITLS_X509_SUCCESS);

    ret = HITLS_PKCS12_ParseBuffer(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, false);
    ASSERT_NE(ret, HITLS_X509_SUCCESS);
exit:
    HTILS_PKCS12_p12_InfoFree(p12);
    return;
}
/* END_CASE */

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

static void BagFree(void *value)
{
    HTILS_PKCS12_Bag *bag = (HTILS_PKCS12_Bag *)value;
    HITLS_X509_CertFree(bag->value.cert);
    BSL_LIST_DeleteAll(bag->attributes, HTILS_PKCS12_AttributesFree);
    BSL_SAL_FREE(bag->attributes);
    BSL_SAL_FREE(bag);
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
    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();
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
    HTILS_PKCS12_P12_InfoFree(p12);
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

    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();
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
    HTILS_PKCS12_P12_InfoFree(p12);
    BSL_SAL_Free(bagLists);
}
/* END_CASE */

/**
 * For test parse attributes of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_SAFEBAGS_OF_ATTRIBUTE_TC001(Hex *buff, Hex *friendlyName, Hex *localKeyId)
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
        BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_BMPSTRING, (uint32_t)friendlyName->len, friendlyName->x};
        BSL_ASN1_Buffer encode = {0};
        ret = BSL_ASN1_DecodePrimitiveItem(&asn, &encode);
        ASSERT_EQ(ret, BSL_SUCCESS);
        ASSERT_COMPARE("friendly name", firstAttr->attrValue->data, firstAttr->attrValue->dataLen,
            encode.buff, encode.len);
        BSL_SAL_FREE(encode.buff);
    }
    if (firstAttr->attrId == BSL_CID_LOCALKEYID) {
        ASSERT_EQ(memcmp(firstAttr->attrValue->data, localKeyId->x, localKeyId->len), 0);
    }
    if (second == NULL) {
        ASSERT_EQ(friendlyName->len, 0);
    } else {
        if (second->attrId == BSL_CID_FRIENDLYNAME) {
            BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_BMPSTRING, (uint32_t)friendlyName->len, friendlyName->x};
            BSL_ASN1_Buffer encode = {0};
            ret = BSL_ASN1_DecodePrimitiveItem(&asn, &encode);
            ASSERT_EQ(ret, BSL_SUCCESS);
            ASSERT_COMPARE("friendly name", firstAttr->attrValue->data, firstAttr->attrValue->dataLen,
                encode.buff, encode.len);
            BSL_SAL_FREE(encode.buff);
        }
        if (second->attrId == BSL_CID_LOCALKEYID) {
            ASSERT_EQ(memcmp(second->attrValue->data, localKeyId->x, localKeyId->len), 0);
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
    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();
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
    HTILS_PKCS12_P12_InfoFree(p12);
    return;
}
/* END_CASE */

/**
 * For test parse authSafedata of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_AUTHSAFE_TC002(Hex *buff)
{
    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();

    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);
    // parse authSafe
    int32_t ret = HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, p12);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(p12->key->value.key, NULL);
    ASSERT_NE(p12->entityCert->value.cert, NULL);
exit:
    HTILS_PKCS12_P12_InfoFree(p12);
    return;
}
/* END_CASE */

/**
 * For test parse 12 of macData parse.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_MACDATA_TC001(Hex *buff, int alg, Hex *digest, Hex *salt, int iterations)
{
    HTILS_PKCS12_MacData *macData = HTILS_PKCS12_P12_MacDataNew();
    int32_t ret = HITLS_PKCS12_ParseMacData((BSL_Buffer *)buff, macData);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(macData->alg, alg);
    ASSERT_EQ(macData->interation, iterations);
    ASSERT_EQ(memcmp(macData->macSalt->data, salt->x, salt->len), 0);
    ASSERT_EQ(memcmp(macData->mac->data, digest->x, digest->len), 0);
exit:
    HTILS_PKCS12_p12_MacDataFree(macData);
    return;
}
/* END_CASE */

/**
 * For test parse 12 of wrong macData parse.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_MACDATA_TC002(Hex *buff)
{
    HTILS_PKCS12_MacData *macData = HTILS_PKCS12_P12_MacDataNew();
    int32_t ret = HITLS_PKCS12_ParseMacData(NULL, macData);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_ParseMacData((BSL_Buffer *)buff, macData);
    ASSERT_EQ(ret, CRYPT_DECODE_UNKNOWN_OID);
exit:
    HTILS_PKCS12_p12_MacDataFree(macData);
    return;
}
/* END_CASE */

/**
 * For test parse 12 of macData cal.
*/
/* BEGIN_CASE */
void SDV_PKCS12_CAL_MACDATA_TC001(Hex *initData, Hex *salt, int alg, int iter, Hex *mac)
{
    HTILS_PKCS12_MacData *macData = HTILS_PKCS12_P12_MacDataNew();
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
    HTILS_PKCS12_MacData *macData = HTILS_PKCS12_P12_MacDataNew();
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

    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();
    ASSERT_NE(p12, NULL);
    HTILS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &encPwd,
    };
    int32_t ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(p12->key->value.key, NULL);
    ASSERT_NE(p12->entityCert->value.cert, NULL);
    BSL_Buffer encodeCert = {0};
    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12->entityCert->value.cert, &encodeCert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(memcmp(encodeCert.data, cert->x, cert->len), 0);
exit:
    BSL_SAL_Free(encodeCert.data);
    HTILS_PKCS12_P12_InfoFree(p12);
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

    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();
    ASSERT_NE(p12, NULL);
    HTILS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
    };
    int32_t ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_NE(ret, HITLS_X509_SUCCESS);
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, false);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(p12->key->value.key, NULL);
    ASSERT_NE(p12->entityCert->value.cert, NULL);
    BSL_Buffer encodeCert = {0};
    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12->entityCert->value.cert, &encodeCert);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(memcmp(encodeCert.data, cert->x, cert->len), 0);
exit:
    BSL_SAL_Free(encodeCert.data);
    HTILS_PKCS12_P12_InfoFree(p12);
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

    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();
    ASSERT_NE(p12, NULL);
    HTILS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &macPwd,
    };

    int32_t ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, NULL, &param, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, NULL, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, NULL, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

    char *pwd3 = "";
    macPwd.data = (uint8_t *)pwd3;
    macPwd.dataLen = strlen(pwd3);
    param.macPwd = &macPwd;
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

    param.macPwd = NULL;
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

    param.encPwd = NULL;
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    char *pwd4 = "123456";
    param.encPwd = &encPwd;
    macPwd.data = (uint8_t *)pwd4;
    macPwd.dataLen = strlen(pwd4);
    param.macPwd = &macPwd;
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, CRYPT_EAL_CIPHER_DATA_ERROR);

    encPwd.data = (uint8_t *)pwd4;
    encPwd.dataLen = strlen(pwd4);
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    encode->x[6] = 0x04; // Modify the version = 4.
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_INVALID_PFX);
exit:
    HTILS_PKCS12_P12_InfoFree(p12);
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

    HTILS_PKCS12_P12Info *p12_1 = HTILS_PKCS12_P12_InfoNew();
    ASSERT_NE(p12_1, NULL);
    HTILS_PKCS12_P12Info *p12_2 = HTILS_PKCS12_P12_InfoNew();
    ASSERT_NE(p12_2, NULL);
    int32_t ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12_1, true);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    encode->x[encode->len - 2] = 0x04; // modify the iteration = 1024;
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12_2, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

    encode->x[encode->len - 2] = 0x08; // recover the iteration = 2048;
    (void)memset_s(encode->x + 96, 16, 0, 16); // modify the contentInfo
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12_2, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

exit:
    HTILS_PKCS12_P12_InfoFree(p12_1);
    HTILS_PKCS12_P12_InfoFree(p12_2);
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

    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();
    ASSERT_NE(p12, NULL);
    int32_t ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, true);
    ASSERT_NE(ret, HITLS_X509_SUCCESS);

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, p12, false);
    ASSERT_NE(ret, HITLS_X509_SUCCESS);
exit:
    HTILS_PKCS12_P12_InfoFree(p12);
    return;
}
/* END_CASE */

/**
 * For test encode safeBag-p8shroudkeyBag of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_SAFEBAGS_OF_PKCS8SHROUDEDKEYBAG_TC001(Hex *buff)
{
    TestRandInit();
    BSL_ASN1_List *bagLists = BSL_LIST_New(sizeof(HTILS_PKCS12_SafeBag));
    ASSERT_NE(bagLists, NULL);

    char *pwd = "123456";
    uint32_t len = strlen(pwd);

    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();
    ASSERT_NE(p12, NULL);

    // get the safeBag of safeContents, and put in list.
    int32_t ret = HITLS_PKCS12_ParseAsn1AddList((BSL_Buffer *)buff, bagLists, BSL_CID_SAFECONTENT);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    // get key of the bagList.
    ret = HITLS_PKCS12_ParseSafeBagList(bagLists, (const uint8_t *)pwd, len, p12);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(p12->key->value.key, NULL);

    BSL_ASN1_List *list = BSL_LIST_New(sizeof(HTILS_PKCS12_Bag));
    HTILS_PKCS12_Bag *bag = BSL_SAL_Malloc(sizeof(HTILS_PKCS12_Bag));
    bag->attributes = p12->key->attributes;
    bag->value = p12->key->value;
    ret = BSL_LIST_AddElement(list, bag, BSL_LIST_POS_END);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    CRYPT_Pbkdf2Param param = {0};

    param.pbesId = BSL_CID_PBES2;
    param.pbkdfId = BSL_CID_PBKDF2;
    param.hmacId = CRYPT_MAC_HMAC_SHA256;
    param.symId = CRYPT_CIPHER_AES256_CBC;
    param.pwd = (uint8_t *)pwd;
    param.saltLen = 16;
    param.pwdLen = len;
    param.itCnt = 2048;
    CRYPT_EncodeParam paramEx = {CRYPT_DERIVE_PBKDF2, &param};

    BSL_Buffer encode = {0};
    ret = HITLS_PKCS12_EncodeAsn1List(list, BSL_CID_PKCS8SHROUDEDKEYBAG, &paramEx, &encode);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(encode.dataLen, buff->len);
    ret = memcmp(encode.data + encode.dataLen - 37, buff->x + buff->len - 37, 37);
    ASSERT_EQ(ret, 0);

exit:
    BSL_SAL_Free(encode.data);
    BSL_LIST_DeleteAll(bagLists, BagListsDestroyCb);
    BSL_SAL_Free(bagLists);
    BSL_LIST_FREE(list, NULL);
    HTILS_PKCS12_P12_InfoFree(p12);
}
/* END_CASE */

/**
 * For test encode encrypted-safecontent.
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_SAFEBAGS_OF_CERTBAGS_TC001(Hex *buff)
{
    TestRandInit();
    BSL_ASN1_List *bagLists = BSL_LIST_New(sizeof(HTILS_PKCS12_SafeBag));
    ASSERT_NE(bagLists, NULL);

    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();
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

    CRYPT_Pbkdf2Param param = {0};
    param.pbesId = BSL_CID_PBES2;
    param.pbkdfId = BSL_CID_PBKDF2;
    param.hmacId = CRYPT_MAC_HMAC_SHA256;
    param.symId = CRYPT_CIPHER_AES256_CBC;
    param.pwd = (uint8_t *)pwd;
    param.saltLen = 16;
    param.pwdLen = pwdlen;
    param.itCnt = 2048;
    CRYPT_EncodeParam paramEx = {CRYPT_DERIVE_PBKDF2, &param};

    BSL_Buffer encode = {0};
    ret = HITLS_PKCS12_EncodeAsn1List(p12->certList, BSL_CID_CERTBAG, &paramEx, &encode);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_Buffer output = {0};
    ret = HITLS_PKCS12_EncodeContentInfo(&encode, BSL_CID_ENCRYPTEDDATA, &paramEx, &output);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(output.dataLen, buff->len);
    ret = memcmp(output.data, buff->x, 69);
    ASSERT_EQ(ret, 0);

exit:
    BSL_SAL_Free(safeContent.data);
    BSL_SAL_Free(encode.data);
    BSL_SAL_Free(output.data);
    BSL_LIST_DeleteAll(bagLists, BagListsDestroyCb);
    HTILS_PKCS12_P12_InfoFree(p12);
    BSL_SAL_Free(bagLists);
}
/* END_CASE */

/**
 * For test encode authSafedata of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_AUTHSAFE_TC001(Hex *buff)
{
    TestRandInit();
    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();

    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);
    // parse authSafe
    int32_t ret = HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, p12);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(p12->key->value.key, NULL);
    ASSERT_NE(p12->entityCert->value.cert, NULL);

    CRYPT_Pbkdf2Param param = {0};
    param.pbesId = BSL_CID_PBES2;
    param.pbkdfId = BSL_CID_PBKDF2;
    param.hmacId = CRYPT_MAC_HMAC_SHA256;
    param.symId = CRYPT_CIPHER_AES256_CBC;
    param.pwd = (uint8_t *)pwd;
    param.saltLen = 16;
    param.pwdLen = pwdlen;
    param.itCnt = 2048;
    CRYPT_EncodeParam paramEx = {CRYPT_DERIVE_PBKDF2, &param};

    HTILS_PKCS12_Bag *bag = BSL_SAL_Malloc(sizeof(HTILS_PKCS12_Bag));
    bag->attributes = p12->entityCert->attributes;
    bag->value.cert = p12->entityCert->value.cert;
    ret = BSL_LIST_AddElement(p12->certList, bag, BSL_LIST_POS_BEGIN);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    p12->entityCert->attributes = NULL;
    p12->entityCert->value.cert = NULL;
    BSL_Buffer *encode1 = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
    ASSERT_NE(encode1, NULL);

    ret = HITLS_PKCS12_EncodeAsn1List(p12->certList, BSL_CID_CERTBAG, &paramEx, encode1);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_Buffer *encode2 = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
    ASSERT_NE(encode2, NULL);

    ret = HITLS_PKCS12_EncodeContentInfo(encode1, BSL_CID_ENCRYPTEDDATA, &paramEx, encode2);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_ASN1_List *keyList = BSL_LIST_New(sizeof(HTILS_PKCS12_Bag));
    HTILS_PKCS12_Bag *bagKey = BSL_SAL_Malloc(sizeof(HTILS_PKCS12_Bag));
    bagKey->attributes = p12->key->attributes;
    bagKey->value = p12->key->value;
    ret = BSL_LIST_AddElement(keyList, bagKey, BSL_LIST_POS_END);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_Buffer *encode3 = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
    ASSERT_NE(encode3, NULL);
    ret = HITLS_PKCS12_EncodeAsn1List(keyList, BSL_CID_PKCS8SHROUDEDKEYBAG, &paramEx, encode3);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_Buffer *encode4 = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
    ASSERT_NE(encode4, NULL);
    ret = HITLS_PKCS12_EncodeContentInfo(encode3, BSL_CID_DATA, &paramEx, encode4);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_ASN1_List *list = BSL_LIST_New(sizeof(BSL_Buffer));
    ret = BSL_LIST_AddElement(list, encode2, BSL_LIST_POS_END);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ret = BSL_LIST_AddElement(list, encode4, BSL_LIST_POS_END);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_Buffer encode5 = {0};
    ret = HITLS_PKCS12_EncodeAsn1List(list, BSL_CID_CONTENTINFO, &paramEx, &encode5);
    ASSERT_EQ(encode5.dataLen, buff->len);

exit:
    BSL_SAL_Free(encode1->data);
    BSL_SAL_Free(encode2->data);
    BSL_SAL_Free(encode3->data);
    BSL_SAL_Free(encode4->data);
    BSL_SAL_Free(encode1);
    BSL_SAL_Free(encode3);
    BSL_SAL_Free(encode5.data);
    BSL_LIST_FREE(list, NULL);
    BSL_LIST_FREE(keyList, NULL);
    HTILS_PKCS12_P12_InfoFree(p12);
    return;
}
/* END_CASE */

/**
 * For test encode authSafedata of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_MACDATA_TC001(Hex *buff, Hex *initData, Hex *expectData)
{
    TestRandInit();
    char *pwd = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);

    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();
    ASSERT_NE(p12, NULL);
    HTILS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &encPwd,
    };
    int32_t ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)buff, &param, p12, true);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    HTILS_PKCS12_HmacParam hmacParam = {0};
    hmacParam.macId = CRYPT_MD_SHA224;
    hmacParam.pwd = (uint8_t *)pwd;
    hmacParam.saltLen = p12->macData->macSalt->dataLen;
    hmacParam.pwdLen = strlen(pwd);
    hmacParam.itCnt = 2048;
    BSL_Buffer output = {0};
    BSL_Buffer output1 = {0};

    ret = HITLS_PKCS12_EncodeMacData((BSL_Buffer *)initData, &hmacParam, p12->macData, &output);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ret = memcmp(output.data, expectData->x, expectData->len);
    ASSERT_EQ(ret, 0);

    HTILS_PKCS12_MacData *macData = HTILS_PKCS12_P12_MacDataNew();
    hmacParam.itCnt = 999;
    ret = HITLS_PKCS12_EncodeMacData((BSL_Buffer *)initData, &hmacParam, macData, &output);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_INVALID_INTERATION);

    hmacParam.itCnt = 1024;
    hmacParam.saltLen = 0;
    ret = HITLS_PKCS12_EncodeMacData((BSL_Buffer *)initData, &hmacParam, macData, &output);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_INVALID_SALTLEN);

    hmacParam.saltLen = 16;
    ret = HITLS_PKCS12_EncodeMacData((BSL_Buffer *)initData, &hmacParam, macData, &output1);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
exit:
    BSL_SAL_Free(output.data);
    BSL_SAL_Free(output1.data);
    HTILS_PKCS12_p12_MacDataFree(macData);
    HTILS_PKCS12_P12_InfoFree(p12);
    return;
}
/* END_CASE */

/**
 * For test encode P12 of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_P12_TC001(Hex *buff, Hex *cert)
{
    TestRandInit();
    char *pwd = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);

    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();
    ASSERT_NE(p12, NULL);
    HTILS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &encPwd,
    };
    int32_t ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)buff, &param, p12, true);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    HTILS_PKCS12_EncodeParam encodeParam = {0};

    CRYPT_Pbkdf2Param pbParam = {0};
    pbParam.pbesId = BSL_CID_PBES2;
    pbParam.pbkdfId = BSL_CID_PBKDF2;
    pbParam.hmacId = CRYPT_MAC_HMAC_SHA256;
    pbParam.symId = CRYPT_CIPHER_AES256_CBC;
    pbParam.pwd = (uint8_t *)pwd;
    pbParam.saltLen = 16;
    pbParam.pwdLen = strlen(pwd);
    pbParam.itCnt = 2048;

    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    encodeParam.certEncParam = encParam;
    encodeParam.keyEncParam = encParam;

    HTILS_PKCS12_HmacParam macParam = {0};
    macParam.macId = p12->macData->alg;
    macParam.pwd = (uint8_t *)pwd;
    macParam.saltLen = p12->macData->macSalt->dataLen;
    macParam.pwdLen = strlen(pwd);
    macParam.itCnt = 2048;
    encodeParam.macParam = macParam;
    BSL_Buffer output = {0};
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(output.dataLen, buff->len);

    HTILS_PKCS12_P12Info *p12_1 = HTILS_PKCS12_P12_InfoNew();
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &param, p12_1, true);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(p12_1->key->value.key, NULL);
    ASSERT_NE(p12_1->entityCert->value.cert, NULL);

    BSL_Buffer encodeCert1 = {0};
    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12->entityCert->value.cert, &encodeCert1);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_Buffer encodeCert2 = {0};
    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12_1->entityCert->value.cert, &encodeCert2);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(memcmp(encodeCert1.data, encodeCert2.data, encodeCert1.dataLen), 0);
    ASSERT_EQ(memcmp(encodeCert1.data, cert->x, cert->len), 0);

    if (BSL_LIST_COUNT(p12->certList) > 0) {
        HTILS_PKCS12_Bag *node1 = BSL_LIST_GET_FIRST(p12->certList);
        BSL_Buffer encodeCert3 = {0};
        ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, node1->value.cert, &encodeCert3);
        ASSERT_EQ(ret, HITLS_X509_SUCCESS);

        HTILS_PKCS12_Bag *node2 = BSL_LIST_GET_FIRST(p12_1->certList);
        BSL_Buffer encodeCert4 = {0};
        ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, node2->value.cert, &encodeCert4);
        ASSERT_EQ(ret, HITLS_X509_SUCCESS);
        ASSERT_EQ(memcmp(encodeCert1.data, encodeCert2.data, encodeCert1.dataLen), 0);
        BSL_SAL_Free(encodeCert3.data);
        BSL_SAL_Free(encodeCert4.data);
    }
exit:
    BSL_SAL_Free(output.data);
    BSL_SAL_Free(encodeCert1.data);
    BSL_SAL_Free(encodeCert2.data);
    HTILS_PKCS12_P12_InfoFree(p12);
    HTILS_PKCS12_P12_InfoFree(p12_1);
    return;
}
/* END_CASE */

/**
 * For test encode P12 of correct data(no mac).
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_P12_TC002(Hex *buff, Hex *cert)
{
    TestRandInit();
    char *pwd = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);

    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();
    ASSERT_NE(p12, NULL);
    HTILS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &encPwd,
    };
    int32_t ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)buff, &param, p12, false);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    HTILS_PKCS12_EncodeParam encodeParam = {0};

    CRYPT_Pbkdf2Param pbParam = {0};
    pbParam.pbesId = BSL_CID_PBES2;
    pbParam.pbkdfId = BSL_CID_PBKDF2;
    pbParam.hmacId = CRYPT_MAC_HMAC_SHA256;
    pbParam.symId = CRYPT_CIPHER_AES256_CBC;
    pbParam.pwd = (uint8_t *)pwd;
    pbParam.saltLen = 16;
    pbParam.pwdLen = strlen(pwd);
    pbParam.itCnt = 2048;

    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    encodeParam.certEncParam = encParam;
    encodeParam.keyEncParam = encParam;

    HTILS_PKCS12_HmacParam macParam = {0};
    macParam.macId = p12->macData->alg;
    macParam.pwd = (uint8_t *)pwd;
    macParam.saltLen = 8;
    macParam.pwdLen = strlen(pwd);
    macParam.itCnt = 2048;
    encodeParam.macParam = macParam;
    BSL_Buffer output = {0};
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output);
    ASSERT_NE(ret, HITLS_X509_SUCCESS);

    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, false, &output);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(output.dataLen, buff->len);

    HTILS_PKCS12_P12Info *p12_1 = HTILS_PKCS12_P12_InfoNew();
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &param, p12_1, false);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_NE(p12_1->key->value.key, NULL);
    ASSERT_NE(p12_1->entityCert->value.cert, NULL);

    BSL_Buffer encodeCert1 = {0};
    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12->entityCert->value.cert, &encodeCert1);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_Buffer encodeCert2 = {0};
    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12_1->entityCert->value.cert, &encodeCert2);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ASSERT_EQ(memcmp(encodeCert1.data, encodeCert2.data, encodeCert1.dataLen), 0);
    ASSERT_EQ(memcmp(encodeCert1.data, cert->x, cert->len), 0);

exit:
    BSL_SAL_Free(output.data);
    BSL_SAL_Free(encodeCert1.data);
    BSL_SAL_Free(encodeCert2.data);
    HTILS_PKCS12_P12_InfoFree(p12);
    HTILS_PKCS12_P12_InfoFree(p12_1);
    return;
}
/* END_CASE */

/**
 * For test encode P12 of insufficient data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_P12_TC003(Hex *buff)
{
    TestRandInit();
    char *pwd = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);

    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();
    ASSERT_NE(p12, NULL);
    HTILS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &encPwd,
    };

    HTILS_PKCS12_EncodeParam encodeParam = {0};

    CRYPT_Pbkdf2Param pbParam = {0};
    pbParam.pbesId = BSL_CID_PBES2;
    pbParam.pbkdfId = BSL_CID_PBKDF2;
    pbParam.hmacId = CRYPT_MAC_HMAC_SHA256;
    pbParam.symId = CRYPT_CIPHER_AES256_CBC;
    pbParam.pwd = (uint8_t *)pwd;
    pbParam.saltLen = 16;
    pbParam.pwdLen = strlen(pwd);
    pbParam.itCnt = 2048;

    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    encodeParam.certEncParam = encParam;
    encodeParam.keyEncParam = encParam;

    BSL_Buffer output1 = {0};

    // For test p12 has none data, isNeedMac = true.
    int32_t ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, false, &output1);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NONE_DATA);
    // For test p12 has none data, isNeedMac = false.
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output1);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NONE_DATA);

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)buff, &param, p12, true);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    HTILS_PKCS12_HmacParam macParam = {0};
    macParam.macId = p12->macData->alg;
    macParam.pwd = (uint8_t *)pwd;
    macParam.saltLen = 8;
    macParam.pwdLen = strlen(pwd);
    macParam.itCnt = 2048;
    encodeParam.macParam = macParam;
    HTILS_PKCS12_P12Info p12_1 = {0};

    //  For test gen p12 of wrong input
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_UNKNOWN, &p12_1, &encodeParam, true, &output1);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NOT_SUPPORT_FORMAT);

    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, NULL, true, &output1);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, NULL);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    (void)memcpy(&p12_1, p12, sizeof(HTILS_PKCS12_P12Info));
    CRYPT_EAL_PkeyCtx *temKey = p12_1.key->value.key;
    HITLS_X509_Cert *entityCert = p12_1.entityCert->value.cert;
    p12_1.key->value.key = NULL;
    p12_1.entityCert->value.cert = NULL; // test p12-encode of key and entityCert = NULL.
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, &output1);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_Buffer output2 = {0};
    p12_1.key->value.key = NULL; // test p12-encode of key = NULL.
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, &output2);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    p12_1.key->value.key = temKey;
    p12_1.entityCert->value.cert = NULL; // test p12-encode of entityCert = NULL.
    BSL_Buffer output3 = {0};
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, &output3);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    p12_1.entityCert->value.cert = entityCert;
    BSL_Buffer output4 = {0};
    BSL_LIST_DeleteAll(p12_1.entityCert->attributes, AttributesFree); // test p12-encode of entityCert attribute = NULL.
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, &output4);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_Buffer output5 = {0};
    BSL_LIST_DeleteAll(p12_1.key->attributes, AttributesFree); // test p12-encode of key attribute = NULL.
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, &output5);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    BSL_LIST_DeleteAll(p12_1.certList, BagFree); // test p12-encode of key attribute = NULL.
    BSL_Buffer output6 = {0};
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, &output6);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
exit:
    BSL_SAL_Free(output1.data);
    BSL_SAL_Free(output2.data);
    BSL_SAL_Free(output3.data);
    BSL_SAL_Free(output4.data);
    BSL_SAL_Free(output5.data);
    BSL_SAL_Free(output6.data);
    HTILS_PKCS12_P12_InfoFree(p12);
    return;
}
/* END_CASE */

/**
 * For test gen and parse p12-file.
*/
/* BEGIN_CASE */
void SDV_PKCS12_GEN_PARASE_P12FILE_TC003(void)
{
    TestRandInit();
    char *pwd = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);

    HTILS_PKCS12_P12Info *p12 = HTILS_PKCS12_P12_InfoNew();
    ASSERT_NE(p12, NULL);
    HTILS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &encPwd,
    };

    HTILS_PKCS12_EncodeParam encodeParam = {0};

    CRYPT_Pbkdf2Param pbParam = {0};
    pbParam.pbesId = BSL_CID_PBES2;
    pbParam.pbkdfId = BSL_CID_PBKDF2;
    pbParam.hmacId = CRYPT_MAC_HMAC_SHA256;
    pbParam.symId = CRYPT_CIPHER_AES256_CBC;
    pbParam.pwd = (uint8_t *)pwd;
    pbParam.saltLen = 16;
    pbParam.pwdLen = strlen(pwd);
    pbParam.itCnt = 2048;

    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    encodeParam.certEncParam = encParam;
    encodeParam.keyEncParam = encParam;

    const char *path = "../testdata/cert/asn1/pkcs12/chain.p12";
    const char *writePath = "../testdata/cert/asn1/pkcs12/chain_cp.p12";

    int32_t ret = HITLS_PKCS12_ParseFile(BSL_FORMAT_ASN1, NULL, &param, p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);
    ret = HITLS_PKCS12_ParseFile(BSL_FORMAT_ASN1, path, &param, p12, true);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    HTILS_PKCS12_HmacParam macParam = {0};
    macParam.macId = p12->macData->alg;
    macParam.pwd = (uint8_t *)pwd;
    macParam.saltLen = 8;
    macParam.pwdLen = strlen(pwd);
    macParam.itCnt = 2048;
    encodeParam.macParam = macParam;

    ret = HITLS_PKCS12_GenFile(BSL_FORMAT_ASN1, p12, &encodeParam, true, NULL);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);
    ret = HITLS_PKCS12_GenFile(BSL_FORMAT_ASN1, p12, &encodeParam, true, writePath);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    HTILS_PKCS12_P12Info *p12_1 = HTILS_PKCS12_P12_InfoNew();
    ASSERT_NE(p12_1, NULL);
    ret = HITLS_PKCS12_ParseFile(BSL_FORMAT_ASN1, writePath, &param, p12_1, true);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
exit:
    HTILS_PKCS12_P12_InfoFree(p12);
    HTILS_PKCS12_P12_InfoFree(p12_1);
    return;
}
/* END_CASE */

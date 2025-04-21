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
#include "hitls_pki_pkcs12.h"
#include "hitls_pki_errno.h"
#include "bsl_types.h"
#include "bsl_log.h"
#include "sal_file.h"
#include "bsl_init.h"
#include "hitls_pkcs12_local.h"
#include "hitls_crl_local.h"
#include "hitls_cert_type.h"
#include "hitls_cert_local.h"
#include "bsl_types.h"
#include "crypt_errno.h"

/* END_HEADER */

#if defined(HITLS_PKI_PKCS12_PARSE) && defined(HITLS_PKI_PKCS12_GEN)
static void BagFree(void *value)
{
    HITLS_PKCS12_Bag *bag = (HITLS_PKCS12_Bag *)value;
    HITLS_X509_CertFree(bag->value.cert);
    HITLS_X509_AttrsFree(bag->attributes, HITLS_PKCS12_AttributesFree);
    bag->attributes = NULL;
    BSL_SAL_FREE(bag);
}
#endif
/**
 * For test parse safeBag-p8shroudkeyBag of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_SAFEBAGS_OF_PKCS8SHROUDEDKEYBAG_TC001(int algId, Hex *buff, int keyBits)
{
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)algId;
    (void)buff;
    (void)keyBits;
    SKIP_TEST();
#else
    BSL_Buffer safeContent = {0};
    char *pwd = "123456";
    uint32_t len = strlen(pwd);
    int32_t bits = 0;

    TestMemInit();
    BSL_ASN1_List *bagLists = BSL_LIST_New(sizeof(HITLS_PKCS12_SafeBag));
    HITLS_PKCS12 *p12  = HITLS_PKCS12_New();
    ASSERT_NE(bagLists, NULL);
    ASSERT_NE(p12, NULL);

    // parse contentInfo
    int32_t ret = HITLS_PKCS12_ParseContentInfo(NULL, NULL, (BSL_Buffer *)buff, NULL, 0, &safeContent);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // get the safeBag of safeContents, and put in list.
    ret = HITLS_PKCS12_ParseAsn1AddList(&safeContent, bagLists, BSL_CID_SAFECONTENTSBAG);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // get key of the bagList.
    ret = HITLS_PKCS12_ParseSafeBagList(bagLists, (const uint8_t *)pwd, len, p12);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(p12->key->value.key, NULL);
    bits = CRYPT_EAL_PkeyGetKeyBits(p12->key->value.key);
    if (algId == CRYPT_PKEY_ECDSA) {
        ASSERT_EQ(((((keyBits - 1) / 8) + 1) * 2 + 1) * 8, bits); // cal len of pub
    } else if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(bits, keyBits);
    }
EXIT:
    BSL_SAL_Free(safeContent.data);
    BSL_LIST_DeleteAll(bagLists, (BSL_LIST_PFUNC_FREE)HITLS_PKCS12_SafeBagFree);
    BSL_SAL_Free(bagLists);
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

/**
 * For test parse safeBag-cert of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_SAFEBAGS_OF_CERTBAGS_TC001(Hex *buff)
{
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)buff;
    SKIP_TEST();
#else
    BSL_Buffer safeContent = {0};
    HITLS_PKCS12 *p12 = NULL;
    BSL_ASN1_List *bagLists = BSL_LIST_New(sizeof(HITLS_PKCS12_SafeBag));
    ASSERT_NE(bagLists, NULL);

    p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);

    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);

    // parse contentInfo
    int32_t ret = HITLS_PKCS12_ParseContentInfo(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen,
        &safeContent);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // get the safeBag of safeContents, and put int list.
    ret = HITLS_PKCS12_ParseAsn1AddList(&safeContent, bagLists, BSL_CID_SAFECONTENTSBAG);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // get cert of the bagList.
    ret = HITLS_PKCS12_ParseSafeBagList(bagLists, NULL, 0, p12);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

EXIT:
    BSL_SAL_Free(safeContent.data);
    BSL_LIST_DeleteAll(bagLists, (BSL_LIST_PFUNC_FREE)HITLS_PKCS12_SafeBagFree);
    HITLS_PKCS12_Free(p12);
    BSL_SAL_Free(bagLists);
#endif
}
/* END_CASE */

/**
 * For test parse attributes of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_SAFEBAGS_OF_ATTRIBUTE_TC001(Hex *buff, Hex *friendlyName, Hex *localKeyId)
{
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)buff;
    (void)friendlyName;
    (void)localKeyId;
    SKIP_TEST();
#else
    HITLS_X509_Attrs *attrbutes = HITLS_X509_AttrsNew();
    ASSERT_NE(attrbutes, NULL);

    BSL_ASN1_Buffer asn = {
        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET,
        buff->len,
        buff->x,
    };
    int32_t ret = HITLS_PKCS12_ParseSafeBagAttr(&asn, attrbutes);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    HITLS_PKCS12_SafeBagAttr *firstAttr = BSL_LIST_GET_FIRST(attrbutes->list);
    HITLS_PKCS12_SafeBagAttr *second = BSL_LIST_GET_NEXT(attrbutes->list);
    if (firstAttr->attrId == BSL_CID_FRIENDLYNAME) {
        BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_BMPSTRING, (uint32_t)friendlyName->len, friendlyName->x};
        BSL_ASN1_Buffer encode = {0};
        ret = BSL_ASN1_DecodePrimitiveItem(&asn, &encode);
        ASSERT_EQ(ret, BSL_SUCCESS);
        ASSERT_COMPARE("friendly name", firstAttr->attrValue.data, firstAttr->attrValue.dataLen,
            encode.buff, encode.len);
        BSL_SAL_FREE(encode.buff);
    }
    if (firstAttr->attrId == BSL_CID_LOCALKEYID) {
        ASSERT_EQ(memcmp(firstAttr->attrValue.data, localKeyId->x, localKeyId->len), 0);
    }
    if (second == NULL) {
        ASSERT_EQ(friendlyName->len, 0);
    } else {
        if (second->attrId == BSL_CID_FRIENDLYNAME) {
            BSL_ASN1_Buffer asn = {BSL_ASN1_TAG_BMPSTRING, (uint32_t)friendlyName->len, friendlyName->x};
            BSL_ASN1_Buffer encode = {0};
            ret = BSL_ASN1_DecodePrimitiveItem(&asn, &encode);
            ASSERT_EQ(ret, BSL_SUCCESS);
            ASSERT_COMPARE("friendly name", firstAttr->attrValue.data, firstAttr->attrValue.dataLen,
                encode.buff, encode.len);
            BSL_SAL_FREE(encode.buff);
        }
        if (second->attrId == BSL_CID_LOCALKEYID) {
            ASSERT_EQ(memcmp(second->attrValue.data, localKeyId->x, localKeyId->len), 0);
        }
    }
EXIT:
    HITLS_X509_AttrsFree(attrbutes, HITLS_PKCS12_AttributesFree);
#endif
}
/* END_CASE */

/**
 * For test parse attributes in the incorrect condition.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_SAFEBAGS_OF_ATTRIBUTE_TC002(Hex *buff)
{
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)buff;
    SKIP_TEST();
#else
    HITLS_X509_Attrs *attrbutes = HITLS_X509_AttrsNew();
    ASSERT_NE(attrbutes, NULL);

    BSL_ASN1_Buffer asn = {
        BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET,
        0,
        buff->x,
    };
    int32_t ret = HITLS_PKCS12_ParseSafeBagAttr(&asn, attrbutes);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS); //  bagAttributes are OPTIONAL
    asn.len = buff->len;
    ret = HITLS_PKCS12_ParseSafeBagAttr(&asn, attrbutes);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    buff->x[4] = 0x00; // 4 is a random number.
    ret = HITLS_PKCS12_ParseSafeBagAttr(&asn, attrbutes);
    ASSERT_NE(ret, HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_AttrsFree(attrbutes, HITLS_PKCS12_AttributesFree);
#endif
}
/* END_CASE */

/**
 * For test parse authSafedata of tampering Cert-info with encrypted data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_AUTHSAFE_TC001(Hex *wrongCert)
{
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)wrongCert;
    SKIP_TEST();
#else
    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);
    // parse authSafe
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    int32_t ret = HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)wrongCert, (const uint8_t *)pwd, pwdlen, p12);
    ASSERT_NE(ret, HITLS_PKI_SUCCESS);

    char *pwd1 = "123456-789";
    uint32_t pwdlen1 = strlen(pwd1);
    ret = HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)wrongCert, (const uint8_t *)pwd1, pwdlen1, p12);
    ASSERT_EQ(ret, CRYPT_EAL_CIPHER_DATA_ERROR);

    char *pwd2 = "";
    uint32_t pwdlen2 = strlen(pwd2);
    ret = HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)wrongCert, (const uint8_t *)pwd2, pwdlen2, p12);
    ASSERT_EQ(ret, CRYPT_EAL_CIPHER_DATA_ERROR);

EXIT:
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

/**
 * For test parse authSafedata of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_AUTHSAFE_TC002(Hex *buff)
{
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)buff;
    SKIP_TEST();
#else
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();

    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);
    // parse authSafe
    int32_t ret = HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, p12);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(p12->key->value.key, NULL);
    ASSERT_NE(p12->entityCert->value.cert, NULL);
EXIT:
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

/**
 * For test parse 12 of macData parse.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_MACDATA_TC001(Hex *buff, int alg, Hex *digest, Hex *salt, int iterations)
{
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)buff;
    (void)alg;
    (void)digest;
    (void)salt;
    (void)iterations;
    SKIP_TEST();
#else
    HITLS_PKCS12_MacData *macData = HITLS_PKCS12_MacDataNew();
    int32_t ret = HITLS_PKCS12_ParseMacData((BSL_Buffer *)buff, macData);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(macData->alg, alg);
    ASSERT_EQ(macData->iteration, iterations);
    ASSERT_EQ(memcmp(macData->macSalt->data, salt->x, salt->len), 0);
    ASSERT_EQ(memcmp(macData->mac->data, digest->x, digest->len), 0);
EXIT:
    HITLS_PKCS12_MacDataFree(macData);
#endif
}
/* END_CASE */

/**
 * For test parse 12 of wrong macData parse.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_MACDATA_TC002(Hex *buff)
{
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)buff;
    SKIP_TEST();
#else
    HITLS_PKCS12_MacData *macData = HITLS_PKCS12_MacDataNew();
    int32_t ret = HITLS_PKCS12_ParseMacData(NULL, macData);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_ParseMacData((BSL_Buffer *)buff, macData);
    ASSERT_EQ(ret, HITLS_CMS_ERR_PARSE_TYPE);
EXIT:
    HITLS_PKCS12_MacDataFree(macData);
#endif
}
/* END_CASE */

/**
 * For test parse 12 of macData cal.
*/
/* BEGIN_CASE */
void SDV_PKCS12_CAL_MACDATA_TC001(Hex *initData, Hex *salt, int alg, int iter, Hex *mac)
{
    BSL_Buffer output = {0};
    TestMemInit();
    HITLS_PKCS12_MacData *macData = HITLS_PKCS12_MacDataNew();
    ASSERT_NE(macData, NULL);
    macData->alg = alg;
    macData->macSalt->data = salt->x;
    macData->macSalt->dataLen = salt->len;
    macData->iteration = iter;
    char *pwdData = "123456";
    uint32_t pwdlen = strlen(pwdData);
    BSL_Buffer pwd = {(uint8_t *)pwdData, pwdlen};
    int32_t ret = HITLS_PKCS12_CalMac(&output, &pwd, (BSL_Buffer *)initData, macData);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(memcmp(output.data, mac->x, mac->len), 0);
EXIT:
    BSL_SAL_FREE(macData->mac);
    BSL_SAL_FREE(macData->macSalt);
    BSL_SAL_FREE(macData);
    BSL_SAL_Free(output.data);
}
/* END_CASE */

/**
 * For test cal key according to salt, alg, etc.
*/
/* BEGIN_CASE */
void SDV_PKCS12_CAL_KDF_TC001(Hex *pwd, Hex *salt, int alg, int iter, Hex *key)
{
    TestMemInit();
    HITLS_PKCS12_MacData *macData = HITLS_PKCS12_MacDataNew();
    ASSERT_NE(macData, NULL);
    macData->alg = alg;
    macData->macSalt->data = salt->x;
    macData->macSalt->dataLen = salt->len;
    macData->iteration = iter;
    uint8_t outData[64] = {0};
    BSL_Buffer output = {outData, 64};
    int32_t ret = HITLS_PKCS12_KDF(&output, pwd->x, pwd->len, HITLS_PKCS12_KDF_MACKEY_ID, macData);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(memcmp(output.data, key->x, key->len), 0);
EXIT:
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
    (void)cert;
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)encode;
    SKIP_TEST();
#else
    char *pwd = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);

    BSL_Buffer encodeCert = {0};
    HITLS_PKCS12 *p12 = NULL;
    HITLS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &encPwd,
    };
    TestMemInit();
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12, true), HITLS_PKI_SUCCESS);
    ASSERT_NE(p12->key->value.key, NULL);
    ASSERT_NE(p12->entityCert->value.cert, NULL);
#ifdef HITLS_PKI_PKCS12_GEN
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12->entityCert->value.cert, &encodeCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(memcmp(encodeCert.data, cert->x, cert->len), 0);
#endif
EXIT:
    BSL_SAL_Free(encodeCert.data);
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

/**
 * For test parse 12 of right conditions (no Mac).
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_P12_TC002(Hex *encode, Hex *cert)
{
    (void)cert;
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)encode;
    SKIP_TEST();
#else
    char *pwd = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);

    BSL_Buffer encodeCert = {0};
    HITLS_PKCS12 *p12 = NULL;
    HITLS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
    };
    TestMemInit();
    ASSERT_NE(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12, true), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12, false), HITLS_PKI_SUCCESS);
    ASSERT_NE(p12->key->value.key, NULL);
    ASSERT_NE(p12->entityCert->value.cert, NULL);
#ifdef HITLS_PKI_PKCS12_GEN
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12->entityCert->value.cert, &encodeCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(memcmp(encodeCert.data, cert->x, cert->len), 0);
#endif
EXIT:
    BSL_SAL_Free(encodeCert.data);
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

/**
 * For test parse 12 of right conditions (different keys).
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_P12_TC003(char *path, char *pwd)
{
#if !defined(HITLS_PKI_PKCS12_PARSE) || !defined(HITLS_BSL_SAL_FILE)
    (void)path;
    (void)pwd;
    SKIP_TEST();
#else
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);

    HITLS_PKCS12 *p12 = NULL;
    HITLS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &encPwd,
    };
    TestMemInit();
    int32_t ret = HITLS_PKCS12_ParseFile(BSL_FORMAT_ASN1, path, &param, &p12, true);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(p12->key->value.key, NULL);
    ASSERT_NE(p12->entityCert->value.cert, NULL);
EXIT:
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

/**
 * For test parse 12 of wrong conditions.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_P12_WRONG_CONDITIONS_TC001(Hex *encode)
{
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)encode;
    SKIP_TEST();
#else
    char *pwd1 = "1234567";
    char *pwd2 = "1234567";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd1;
    encPwd.dataLen = strlen(pwd1);
    BSL_Buffer macPwd;
    macPwd.data = (uint8_t *)pwd2;
    macPwd.dataLen = strlen(pwd2);

    HITLS_PKCS12 *p12 = NULL;
    HITLS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &macPwd,
    };

    TestMemInit();
    int32_t ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, NULL, &param, &p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, NULL, &p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, NULL, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

    char *pwd3 = "";
    macPwd.data = (uint8_t *)pwd3;
    macPwd.dataLen = strlen(pwd3);
    param.macPwd = &macPwd;
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

    param.macPwd = NULL;
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

    param.encPwd = NULL;
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    char *pwd4 = "123456";
    param.encPwd = &encPwd;
    macPwd.data = (uint8_t *)pwd4;
    macPwd.dataLen = strlen(pwd4);
    param.macPwd = &macPwd;
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12, true);
    ASSERT_EQ(ret, CRYPT_EAL_CIPHER_DATA_ERROR);

    encPwd.data = (uint8_t *)pwd4;
    encPwd.dataLen = strlen(pwd4);
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12, true);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_INVALID_PARAM);

    HITLS_PKCS12_Free(p12);
    p12 = NULL;
    encode->x[6] = 0x04; // Modify the version = 4.
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_INVALID_PFX);
EXIT:
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

/**
 * For test parse 12 of wrong p12-file.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_P12_WRONG_P12FILE_TC001(Hex *encode)
{
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)encode;
    SKIP_TEST();
#else
    char *pwd1 = "123456";
    char *pwd2 = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd1;
    encPwd.dataLen = strlen(pwd1);
    BSL_Buffer macPwd;
    macPwd.data = (uint8_t *)pwd2;
    macPwd.dataLen = strlen(pwd2);

    HITLS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &macPwd,
    };

    HITLS_PKCS12 *p12_1 = NULL;
    HITLS_PKCS12 *p12_2 = NULL;

    TestMemInit();
    int32_t ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12_1, true);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    encode->x[encode->len - 2] = 0x04; // modify the iteration = 1024;
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12_2, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

    encode->x[encode->len - 2] = 0x08; // recover the iteration = 2048;
    (void)memset_s(encode->x + 96, 16, 0, 16); // modify the contentInfo
    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12_2, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_VERIFY_FAIL);

EXIT:
    HITLS_PKCS12_Free(p12_1);
    HITLS_PKCS12_Free(p12_2);
#endif
}
/* END_CASE */

/**
 * For test parse 12 of wrong p12-file, which miss a part of data randomly.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_P12_WRONG_P12FILE_TC002(Hex *encode)
{
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)encode;
    SKIP_TEST();
#else
    char *pwd1 = "123456";
    char *pwd2 = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd1;
    encPwd.dataLen = strlen(pwd1);
    BSL_Buffer macPwd;
    macPwd.data = (uint8_t *)pwd2;
    macPwd.dataLen = strlen(pwd2);

    HITLS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &macPwd,
    };

    HITLS_PKCS12 *p12 = NULL;
    TestMemInit();
    int32_t ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12, true);
    ASSERT_NE(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12, false);
    ASSERT_NE(ret, HITLS_PKI_SUCCESS);
EXIT:
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

/**
 * For test encode safeBag-p8shroudkeyBag of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_SAFEBAGS_OF_PKCS8SHROUDEDKEYBAG_TC001(Hex *buff)
{
#if !defined(HITLS_PKI_PKCS12_GEN) || !defined(HITLS_PKI_PKCS12_PARSE)
    (void)buff;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), 0);

    char *pwd = "123456";
    uint32_t len = strlen(pwd);
    BSL_Buffer encode = {0};
    BSL_ASN1_List *bagLists = BSL_LIST_New(sizeof(HITLS_PKCS12_SafeBag));
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    BSL_ASN1_List *list = BSL_LIST_New(sizeof(HITLS_PKCS12_Bag));
    ASSERT_NE(bagLists, NULL);
    ASSERT_NE(p12, NULL);
    ASSERT_NE(list, NULL);

    // get the safeBag of safeContents, and put in list.
    int32_t ret = HITLS_PKCS12_ParseAsn1AddList((BSL_Buffer *)buff, bagLists, BSL_CID_SAFECONTENTSBAG);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // get key of the bagList.
    ret = HITLS_PKCS12_ParseSafeBagList(bagLists, (const uint8_t *)pwd, len, p12);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(p12->key->value.key, NULL);

    HITLS_PKCS12_Bag *bag = BSL_SAL_Malloc(sizeof(HITLS_PKCS12_Bag));
    bag->attributes = p12->key->attributes;
    bag->value = p12->key->value;
    ret = BSL_LIST_AddElement(list, bag, BSL_LIST_POS_END);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
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

    ret = HITLS_PKCS12_EncodeAsn1List(list, BSL_CID_PKCS8SHROUDEDKEYBAG, &paramEx, &encode);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(encode.dataLen, buff->len);
    ret = memcmp(encode.data + encode.dataLen - 37, buff->x + buff->len - 37, 37);
    ASSERT_EQ(ret, 0);

EXIT:
    BSL_SAL_Free(encode.data);
    BSL_LIST_DeleteAll(bagLists, (BSL_LIST_PFUNC_FREE)HITLS_PKCS12_SafeBagFree);
    BSL_SAL_Free(bagLists);
    BSL_LIST_FREE(list, NULL);
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

/**
 * For test encode encrypted-safecontent.
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_SAFEBAGS_OF_CERTBAGS_TC001(Hex *buff)
{
#if !defined(HITLS_PKI_PKCS12_GEN) || !defined(HITLS_PKI_PKCS12_PARSE)
    (void)buff;
    SKIP_TEST();
#else
    ASSERT_EQ(TestRandInit(), 0);
    BSL_Buffer encode = {0};
    BSL_Buffer safeContent = {0};
    BSL_Buffer output = {0};
    BSL_ASN1_List *bagLists = BSL_LIST_New(sizeof(HITLS_PKCS12_SafeBag));
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(bagLists, NULL);
    ASSERT_NE(p12, NULL);

    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);
    // parse contentInfo
    int32_t ret = HITLS_PKCS12_ParseContentInfo(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen,
        &safeContent);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // get the safeBag of safeContents, and put int list.
    ret = HITLS_PKCS12_ParseAsn1AddList(&safeContent, bagLists, BSL_CID_SAFECONTENTSBAG);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // get cert of the bagList.
    ret = HITLS_PKCS12_ParseSafeBagList(bagLists, NULL, 0, p12);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

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

    ret = HITLS_PKCS12_EncodeAsn1List(p12->certList, BSL_CID_CERTBAG, &paramEx, &encode);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_EncodeContentInfo(NULL, NULL, &encode, BSL_CID_PKCS7_ENCRYPTEDDATA, &paramEx, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(output.dataLen, buff->len);
    ret = memcmp(output.data, buff->x, 69);
    ASSERT_EQ(ret, 0);

EXIT:
    BSL_SAL_Free(safeContent.data);
    BSL_SAL_Free(encode.data);
    BSL_SAL_Free(output.data);
    BSL_LIST_DeleteAll(bagLists, (BSL_LIST_PFUNC_FREE)HITLS_PKCS12_SafeBagFree);
    HITLS_PKCS12_Free(p12);
    BSL_SAL_Free(bagLists);
#endif
}
/* END_CASE */

/**
 * For test encode authSafedata of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_AUTHSAFE_TC001(Hex *buff)
{
#if !defined(HITLS_PKI_PKCS12_GEN) || !defined(HITLS_PKI_PKCS12_PARSE)
    (void)buff;
    SKIP_TEST();
#else
    ASSERT_EQ(TestRandInit(), 0);
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    BSL_Buffer *encode1 = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
    BSL_Buffer *encode2 = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
    BSL_Buffer *encode3 = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
    BSL_Buffer *encode4 = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
    BSL_ASN1_List *list = BSL_LIST_New(sizeof(BSL_Buffer));
    BSL_ASN1_List *keyList = BSL_LIST_New(sizeof(HITLS_PKCS12_Bag));
    BSL_Buffer encode5 = {0};
    HITLS_PKCS12_Bag *bagKey = NULL;
    ASSERT_NE(p12, NULL);
    ASSERT_NE(encode1, NULL);
    ASSERT_NE(encode2, NULL);
    ASSERT_NE(encode3, NULL);
    ASSERT_NE(encode4, NULL);
    ASSERT_NE(list, NULL);
    ASSERT_NE(keyList, NULL);

    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);
    // parse authSafe
    int32_t ret = HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, p12);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
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

    HITLS_PKCS12_Bag *bag = BSL_SAL_Malloc(sizeof(HITLS_PKCS12_Bag));
    bag->attributes = p12->entityCert->attributes;
    bag->value.cert = p12->entityCert->value.cert;
    ret = BSL_LIST_AddElement(p12->certList, bag, BSL_LIST_POS_BEGIN);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    p12->entityCert->attributes = NULL;
    p12->entityCert->value.cert = NULL;

    ret = HITLS_PKCS12_EncodeAsn1List(p12->certList, BSL_CID_CERTBAG, &paramEx, encode1);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_EncodeContentInfo(NULL, NULL, encode1, BSL_CID_PKCS7_ENCRYPTEDDATA, &paramEx, encode2);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    bagKey = BSL_SAL_Malloc(sizeof(HITLS_PKCS12_Bag));
    bagKey->attributes = p12->key->attributes;
    bagKey->value = p12->key->value;
    ret = BSL_LIST_AddElement(keyList, bagKey, BSL_LIST_POS_END);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_EncodeAsn1List(keyList, BSL_CID_PKCS8SHROUDEDKEYBAG, &paramEx, encode3);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_EncodeContentInfo(NULL, NULL, encode3, BSL_CID_PKCS7_SIMPLEDATA, &paramEx, encode4);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = BSL_LIST_AddElement(list, encode2, BSL_LIST_POS_END);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = BSL_LIST_AddElement(list, encode4, BSL_LIST_POS_END);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_EncodeAsn1List(list, BSL_CID_PKCS7_CONTENTINFO, &paramEx, &encode5);
    ASSERT_EQ(encode5.dataLen, buff->len);

EXIT:
    BSL_SAL_Free(encode1->data);
    BSL_SAL_Free(encode2->data);
    BSL_SAL_Free(encode3->data);
    BSL_SAL_Free(encode4->data);
    BSL_SAL_Free(encode1);
    BSL_SAL_Free(encode3);
    BSL_SAL_Free(encode5.data);
    BSL_LIST_FREE(list, NULL);
    BSL_LIST_FREE(keyList, NULL);
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

/**
 * For test encode authSafedata of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_MACDATA_TC001(Hex *buff, Hex *initData, Hex *expectData)
{
#if !defined(HITLS_PKI_PKCS12_GEN) || !defined(HITLS_PKI_PKCS12_PARSE)
    (void)buff;
    (void)initData;
    (void)expectData;
    SKIP_TEST();
#else
    ASSERT_EQ(TestRandInit(), 0);
    char *pwd = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);

    BSL_Buffer output = {0};
    BSL_Buffer output1 = {0};
    HITLS_PKCS12 *p12 = NULL;
    HITLS_PKCS12_MacData *macData = HITLS_PKCS12_MacDataNew();
    ASSERT_NE(macData, NULL);

    HITLS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &encPwd,
    };
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)buff, &param, &p12, true), HITLS_PKI_SUCCESS);

    HITLS_PKCS12_KdfParam hmacParam = {0};
    hmacParam.macId = CRYPT_MD_SHA224;
    hmacParam.pwd = (uint8_t *)pwd;
    hmacParam.saltLen = p12->macData->macSalt->dataLen;
    hmacParam.pwdLen = strlen(pwd);
    hmacParam.itCnt = 2048;

    HITLS_PKCS12_MacParam macParam = {.para = &hmacParam, .algId = BSL_CID_PKCS12KDF};
    ASSERT_EQ(HITLS_PKCS12_EncodeMacData((BSL_Buffer *)initData, &macParam, p12->macData, &output), HITLS_PKI_SUCCESS);
    ASSERT_EQ(memcmp(output.data, expectData->x, expectData->len), 0);

    hmacParam.itCnt = 999;
    ASSERT_EQ(HITLS_PKCS12_EncodeMacData((BSL_Buffer *)initData, &macParam, macData, &output),
        HITLS_PKCS12_ERR_INVALID_ITERATION);

    hmacParam.itCnt = 1024;
    hmacParam.saltLen = 0;
    ASSERT_EQ(HITLS_PKCS12_EncodeMacData((BSL_Buffer *)initData, &macParam, macData, &output),
        HITLS_PKCS12_ERR_INVALID_SALTLEN);

    hmacParam.saltLen = 16;
    ASSERT_EQ(HITLS_PKCS12_EncodeMacData((BSL_Buffer *)initData, &macParam, macData, &output1), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(output.data);
    BSL_SAL_Free(output1.data);
    HITLS_PKCS12_MacDataFree(macData);
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

/**
 * For test encode P12 of correct data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_P12_TC001(Hex *buff, Hex *cert)
{
#if !defined(HITLS_PKI_PKCS12_GEN) || !defined(HITLS_PKI_PKCS12_PARSE)
    (void)buff;
    (void)cert;
    SKIP_TEST();
#else
    char *pwd = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);

    BSL_Buffer output = {0};
    BSL_Buffer encodeCert1 = {0};
    BSL_Buffer encodeCert2 = {0};
    HITLS_PKCS12 *p12 = NULL;
    HITLS_PKCS12 *p12_1 = NULL;

    HITLS_PKCS12_PwdParam param = {.encPwd = &encPwd, .macPwd = &encPwd};
    int32_t ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)buff, &param, &p12, true);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_PKCS12_EncodeParam encodeParam = {0};

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

    HITLS_PKCS12_KdfParam macParam = {0};
    macParam.macId = p12->macData->alg;
    macParam.pwd = (uint8_t *)pwd;
    macParam.saltLen = p12->macData->macSalt->dataLen;
    macParam.pwdLen = strlen(pwd);
    macParam.itCnt = 2048;
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    encodeParam.macParam = paramTest;

    ASSERT_EQ(TestRandInit(), 0);
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(output.dataLen, buff->len);

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &param, &p12_1, true);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(p12_1->key->value.key, NULL);
    ASSERT_NE(p12_1->entityCert->value.cert, NULL);

    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12->entityCert->value.cert, &encodeCert1);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12_1->entityCert->value.cert, &encodeCert2);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(memcmp(encodeCert1.data, encodeCert2.data, encodeCert1.dataLen), 0);
    ASSERT_EQ(memcmp(encodeCert1.data, cert->x, cert->len), 0);

    if (BSL_LIST_COUNT(p12->certList) > 0) {
        HITLS_PKCS12_Bag *node1 = BSL_LIST_GET_FIRST(p12->certList);
        BSL_Buffer encodeCert3 = {0};
        ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, node1->value.cert, &encodeCert3);
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

        HITLS_PKCS12_Bag *node2 = BSL_LIST_GET_FIRST(p12_1->certList);
        BSL_Buffer encodeCert4 = {0};
        ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, node2->value.cert, &encodeCert4);
        ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
        ASSERT_EQ(memcmp(encodeCert1.data, encodeCert2.data, encodeCert1.dataLen), 0);
        BSL_SAL_Free(encodeCert3.data);
        BSL_SAL_Free(encodeCert4.data);
    }
EXIT:
    BSL_SAL_Free(output.data);
    BSL_SAL_Free(encodeCert1.data);
    BSL_SAL_Free(encodeCert2.data);
    HITLS_PKCS12_Free(p12);
    HITLS_PKCS12_Free(p12_1);
#endif
}
/* END_CASE */

/**
 * For test encode P12 of correct data(no mac).
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_P12_TC002(Hex *buff, Hex *cert)
{
#if !defined(HITLS_PKI_PKCS12_GEN) || !defined(HITLS_PKI_PKCS12_PARSE)
    (void)buff;
    (void)cert;
    SKIP_TEST();
#else
    ASSERT_EQ(TestRandInit(), 0);
    char *pwd = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);

    BSL_Buffer output = {0};
    BSL_Buffer encodeCert1 = {0};
    BSL_Buffer encodeCert2 = {0};
    HITLS_PKCS12 *p12 = NULL;
    HITLS_PKCS12 *p12_1 = NULL;

    HITLS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &encPwd,
    };
    int32_t ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)buff, &param, &p12, false);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_PKCS12_EncodeParam encodeParam = {0};

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

    HITLS_PKCS12_KdfParam macParam = {0};
    macParam.macId = p12->macData->alg;
    macParam.pwd = (uint8_t *)pwd;
    macParam.saltLen = 8;
    macParam.pwdLen = strlen(pwd);
    macParam.itCnt = 2048;
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    encodeParam.macParam = paramTest;

    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output);
    ASSERT_NE(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, false, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(output.dataLen, buff->len);

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &param, &p12_1, false);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(p12_1->key->value.key, NULL);
    ASSERT_NE(p12_1->entityCert->value.cert, NULL);

    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12->entityCert->value.cert, &encodeCert1);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12_1->entityCert->value.cert, &encodeCert2);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(memcmp(encodeCert1.data, encodeCert2.data, encodeCert1.dataLen), 0);
    ASSERT_EQ(memcmp(encodeCert1.data, cert->x, cert->len), 0);

EXIT:
    BSL_SAL_Free(output.data);
    BSL_SAL_Free(encodeCert1.data);
    BSL_SAL_Free(encodeCert2.data);
    HITLS_PKCS12_Free(p12);
    HITLS_PKCS12_Free(p12_1);
#endif
}
/* END_CASE */

/**
 * For test encode P12 of insufficient data.
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_P12_TC003(Hex *buff)
{
#if !defined(HITLS_PKI_PKCS12_GEN) || !defined(HITLS_PKI_PKCS12_PARSE)
    (void)buff;
    SKIP_TEST();
#else
    ASSERT_EQ(TestRandInit(), 0);
    char *pwd = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);

    HITLS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &encPwd,
    };

    HITLS_PKCS12_EncodeParam encodeParam = {0};

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
    BSL_Buffer output2 = {0};
    BSL_Buffer output3 = {0};
    BSL_Buffer output4 = {0};
    BSL_Buffer output5 = {0};
    BSL_Buffer output6 = {0};
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);

    // For test p12 has none data, isNeedMac = true.
    int32_t ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, false, &output1);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NONE_DATA);
    // For test p12 has none data, isNeedMac = false.
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output1);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NONE_DATA);
    HITLS_PKCS12_Free(p12);
    p12 = NULL;

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)buff, &param, &p12, true);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_PKCS12_KdfParam macParam = {0};
    macParam.macId = p12->macData->alg;
    macParam.pwd = (uint8_t *)pwd;
    macParam.saltLen = 8;
    macParam.pwdLen = strlen(pwd);
    macParam.itCnt = 2048;
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    encodeParam.macParam = paramTest;
    HITLS_PKCS12 p12_1 = {0};

    //  For test gen p12 of wrong input
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_UNKNOWN, &p12_1, &encodeParam, true, &output1);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_FORMAT_UNSUPPORT);

    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, NULL, true, &output1);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, NULL);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    (void)memcpy(&p12_1, p12, sizeof(HITLS_PKCS12));
    CRYPT_EAL_PkeyCtx *temKey = p12_1.key->value.key;
    HITLS_X509_Cert *entityCert = p12_1.entityCert->value.cert;
    p12_1.key->value.key = NULL;
    p12_1.entityCert->value.cert = NULL; // test p12-encode of key and entityCert = NULL.
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, &output1);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    p12_1.key->value.key = NULL; // test p12-encode of key = NULL.
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, &output2);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    p12_1.key->value.key = temKey;
    p12_1.entityCert->value.cert = NULL; // test p12-encode of entityCert = NULL.
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, &output3);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // test p12-encode of entityCert attribute = NULL.
    p12_1.entityCert->value.cert = entityCert;
    HITLS_X509_AttrsFree(p12_1.entityCert->attributes, HITLS_PKCS12_AttributesFree);
    p12_1.entityCert->attributes = NULL;
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, &output4);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    // test p12-encode of key attribute = NULL.
    HITLS_X509_AttrsFree(p12_1.key->attributes, HITLS_PKCS12_AttributesFree);
    p12_1.key->attributes = NULL;
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, &output5);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    BSL_LIST_DeleteAll(p12_1.certList, BagFree); // test p12-encode of key attribute = NULL.
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, &output6);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(output1.data);
    BSL_SAL_Free(output2.data);
    BSL_SAL_Free(output3.data);
    BSL_SAL_Free(output4.data);
    BSL_SAL_Free(output5.data);
    BSL_SAL_Free(output6.data);
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

/**
 * For test gen p12-file of different password.
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_P12_TC004(char *pkeyPath, char *certPath)
{
#if !defined(HITLS_PKI_PKCS12_GEN) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_CRYPTO_KEY_DECODE)
    (void)pkeyPath;
    (void)certPath;
    SKIP_TEST();
#else
    ASSERT_EQ(TestRandInit(), 0);
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *enCert = NULL;
    HITLS_PKCS12_Bag *certBag = NULL;
    HITLS_PKCS12_Bag *keyBag = NULL;
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pkeyPath, NULL, 0, &pkey), 0);

    keyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, pkey);
    ASSERT_NE(keyBag, NULL);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &enCert), HITLS_PKI_SUCCESS);

    certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, enCert);
    ASSERT_NE(certBag, NULL);

    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_KEYBAG, keyBag, 0), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_CERTBAG, certBag, 0), HITLS_PKI_SUCCESS);

    HITLS_PKCS12_EncodeParam encodeParam = {0};

    BSL_Buffer output = {0};
    // While the encrypted data is null of cert and key
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, false, &output), HITLS_PKCS12_ERR_INVALID_PARAM);

    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), HITLS_PKCS12_ERR_INVALID_PARAM);

    char *pwd = "123456";
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
    HITLS_PKCS12_KdfParam macParam = {0};
    macParam.macId = BSL_CID_SHA256;
    macParam.pwd = (uint8_t *)pwd;
    macParam.saltLen = 8;
    macParam.pwdLen = strlen(pwd);
    macParam.itCnt = 2048;
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    encodeParam.keyEncParam = encParam;

    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), HITLS_PKCS12_ERR_INVALID_PARAM);

    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, false, &output), HITLS_PKI_SUCCESS);

    BSL_SAL_Free(output.data);
    output.data = NULL;
    encodeParam.certEncParam = encParam;
    paramTest.algId = BSL_CID_MAX;
    encodeParam.macParam = paramTest;
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), HITLS_PKCS12_ERR_INVALID_ALGO);

    paramTest.algId = BSL_CID_PKCS12KDF;
    paramTest.para = NULL;
    encodeParam.macParam = paramTest;
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), HITLS_PKCS12_ERR_NULL_POINTER);
    paramTest.para = &macParam;

    BSL_Buffer output1 = {0};
    char *pwd1 = "1234567";
    CRYPT_Pbkdf2Param pbParam1 = {0};
    pbParam1.pbesId = BSL_CID_PBES2;
    pbParam1.pbkdfId = BSL_CID_PBKDF2;
    pbParam1.hmacId = CRYPT_MAC_HMAC_SHA256;
    pbParam1.symId = CRYPT_CIPHER_AES256_CBC;
    pbParam1.pwd = (uint8_t *)pwd1;
    pbParam1.saltLen = 16;
    pbParam1.pwdLen = strlen(pwd1);
    pbParam1.itCnt = 2048;
    CRYPT_EncodeParam encParam1 = {CRYPT_DERIVE_PBKDF2, &pbParam1};
    encodeParam.certEncParam = encParam;
    encodeParam.keyEncParam = encParam1;
    encodeParam.macParam = paramTest;
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output1), HITLS_PKCS12_ERR_INVALID_PARAM);

    encodeParam.keyEncParam = encParam;
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output1), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output1), HITLS_PKCS12_ERR_INVALID_PARAM);

    BSL_Buffer output2 = {0};
    pbParam1.pwd = NULL;
    pbParam.pwd = NULL;
    pbParam1.pwdLen = 0;
    pbParam.pwdLen = 0;
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output2), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(output.data);
    BSL_SAL_Free(output1.data);
    BSL_SAL_Free(output2.data);
    HITLS_PKCS12_Free(p12);
    HITLS_X509_CertFree(enCert);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_PKCS12_BagFree(keyBag);
    HITLS_PKCS12_BagFree(certBag);
#endif
}
/* END_CASE */

/**
 * For test gen and parse p12-file.
*/
/* BEGIN_CASE */
void SDV_PKCS12_GEN_PARSE_P12FILE_TC001(void)
{
#if !defined(HITLS_PKI_PKCS12_GEN) || !defined(HITLS_PKI_PKCS12_PARSE)
    SKIP_TEST();
#else
    ASSERT_EQ(TestRandInit(), 0);
    char *pwd = "123456";
    BSL_Buffer encPwd;
    encPwd.data = (uint8_t *)pwd;
    encPwd.dataLen = strlen(pwd);
    HITLS_PKCS12 *p12 = NULL;
    HITLS_PKCS12 *p12_1 = NULL;

    HITLS_PKCS12_PwdParam param = {
        .encPwd = &encPwd,
        .macPwd = &encPwd,
    };

    HITLS_PKCS12_EncodeParam encodeParam = {0};

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

    int32_t ret = HITLS_PKCS12_ParseFile(BSL_FORMAT_ASN1, NULL, &param, &p12, true);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);
    ret = HITLS_PKCS12_ParseFile(BSL_FORMAT_ASN1, path, &param, &p12, true);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    HITLS_PKCS12_KdfParam macParam = {0};
    macParam.macId = p12->macData->alg;
    macParam.pwd = (uint8_t *)pwd;
    macParam.saltLen = 8;
    macParam.pwdLen = strlen(pwd);
    macParam.itCnt = 2048;
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    encodeParam.macParam = paramTest;

    ret = HITLS_PKCS12_GenFile(BSL_FORMAT_ASN1, p12, &encodeParam, true, NULL);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);
    ret = HITLS_PKCS12_GenFile(BSL_FORMAT_ASN1, p12, &encodeParam, true, writePath);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_ParseFile(BSL_FORMAT_ASN1, writePath, &param, &p12_1, true);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
EXIT:
    HITLS_PKCS12_Free(p12);
    HITLS_PKCS12_Free(p12_1);
#endif
}
/* END_CASE */

/**
 * For test p12-ctrl.
*/
/* BEGIN_CASE */
void SDV_PKCS12_CTRL_TEST_TC001(char *pkeyPath, char *enCertPath, char *caCertPath)
{
#if !defined(HITLS_PKI_PKCS12_PARSE) || !defined(HITLS_PKI_PKCS12_GEN)
    (void)pkeyPath;
    (void)enCertPath;
    (void)caCertPath;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), 0);
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *enCert = NULL;
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_Cert *targetCert = NULL;
    CRYPT_EAL_PkeyCtx *targetKey = NULL;
    HITLS_PKCS12_Bag *caBag = NULL;
    HITLS_PKCS12_Bag *pkeyBag = NULL;
    HITLS_PKCS12_Bag *encertBag = NULL;
    int32_t mdId = CRYPT_MD_SHA1;
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);

    int32_t ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pkeyPath, NULL, 0, &pkey);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, enCertPath, &enCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, caCertPath, &caCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    caBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, caCert);
    ASSERT_NE(caBag, NULL);

    pkeyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, pkey);
    ASSERT_NE(pkeyBag, NULL);

    encertBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, enCert);
    ASSERT_NE(encertBag, NULL);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_KEYBAG, pkeyBag, 0);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_CERTBAG, encertBag, 0);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_ENTITY_CERT, &targetCert, 0);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(targetCert, NULL);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_ENTITY_KEY, &targetKey, 0);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(targetKey, NULL);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GEN_LOCALKEYID, &mdId, sizeof(CRYPT_MD_AlgId));
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GEN_LOCALKEYID, &mdId, 0);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_INVALID_PARAM);

    mdId = BSL_CID_MD4 - 1;
    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GEN_LOCALKEYID, &mdId, sizeof(CRYPT_MD_AlgId));
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_INVALID_PARAM);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_CERTBAG, caBag, 0);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ASSERT_NE(p12->key->value.key, NULL);
    ASSERT_NE(p12->entityCert->value.cert, NULL);
    ASSERT_EQ(BSL_LIST_COUNT(p12->key->attributes->list), 1);
    ASSERT_EQ(BSL_LIST_COUNT(p12->entityCert->attributes->list), 1);
    ASSERT_EQ(BSL_LIST_COUNT(p12->certList), 1);

EXIT:
    HITLS_X509_CertFree(targetCert);
    CRYPT_EAL_PkeyFreeCtx(targetKey);
    HITLS_PKCS12_BagFree(pkeyBag);
    HITLS_PKCS12_BagFree(encertBag);
    HITLS_PKCS12_BagFree(caBag);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_PKCS12_Free(p12);
    HITLS_X509_CertFree(enCert);
    HITLS_X509_CertFree(caCert);
#endif
}
/* END_CASE */

/**
 * For test p12-ctrl in invalid params.
*/
/* BEGIN_CASE */
void SDV_PKCS12_CTRL_TEST_TC002(char *enCertPath)
{
#if !defined(HITLS_PKI_PKCS12_PARSE) || !defined(HITLS_PKI_PKCS12_GEN)
    (void)enCertPath;
    SKIP_TEST();
#else
    HITLS_X509_Cert *enCert = NULL;
    HITLS_X509_Cert *target = NULL;
    HITLS_PKCS12_Bag *certBag = NULL;
    HITLS_PKCS12_Bag keyBag = {0};
    HITLS_PKCS12_Bag *entityCertBag = NULL;
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);
    int32_t mdId = CRYPT_MD_SHA1;
    int32_t ret = HITLS_PKCS12_Ctrl(NULL, HITLS_PKCS12_SET_ENTITY_KEYBAG, &keyBag, 0); // p12 == NULL.
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_KEYBAG, NULL, 0); // keyBag == NULL.
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GEN_LOCALKEYID - 1, &mdId, sizeof(CRYPT_MD_AlgId)); // cmd is invalid.
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_INVALID_PARAM);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_ENTITY_CERT, &target, 0); // no cert to obtain.
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NO_ENTITYCERT);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GEN_LOCALKEYID, &mdId, sizeof(CRYPT_MD_AlgId)); // no key and cert
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_CERTBAG, entityCertBag, 0); // enCertBag is invalid.
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

#if defined(HITLS_CRYPTO_KEY_DECODE) && defined(HITLS_BSL_SAL_FILE)
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, enCertPath, &enCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    entityCertBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, enCert);
    ASSERT_NE(entityCertBag, NULL);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_CERTBAG, entityCertBag, 0);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
#else
    (void)enCertPath;
    SKIP_TEST();
#endif

    // no key to set localKeyId.
    p12->key = &keyBag;
    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GEN_LOCALKEYID, &mdId, sizeof(CRYPT_MD_AlgId));
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NO_PAIRED_CERT_AND_KEY);
    p12->key = NULL;

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_CERTBAG, certBag, 0); // certBag is NULL.
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    keyBag.type = BSL_CID_PKCS8SHROUDEDKEYBAG;
    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_CERTBAG, &keyBag, 0); // certBag-type is wrong.
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_INVALID_PARAM);

EXIT:
    HITLS_PKCS12_Free(p12);
    HITLS_X509_CertFree(enCert);
    HITLS_PKCS12_BagFree(entityCertBag);
#endif
}
/* END_CASE */

/**
 * For test p12-bag creat, set, and free.
*/
/* BEGIN_CASE */
void SDV_PKCS12_BAG_TEST_TC001(char *pkeyPath, char *certPath)
{
#if !defined(HITLS_PKI_PKCS12_PARSE) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_PKI_PKCS12_GEN)
    (void)pkeyPath;
    (void)certPath;
    SKIP_TEST();
#else
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *enCert = NULL;
    HITLS_PKCS12_Bag *keyBag = NULL;
    HITLS_PKCS12_Bag *certBag = NULL;
    char *name = "friendlyName";
    uint32_t nameLen = strlen(name);
    BSL_Buffer buffer = {.data = (uint8_t *)name, .dataLen = nameLen};

    int32_t ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pkeyPath, NULL, 0, &pkey);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    keyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, pkey);
    ASSERT_NE(keyBag, NULL);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &enCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, enCert);
    ASSERT_NE(certBag, NULL);

    ret = HITLS_PKCS12_BagAddAttr(keyBag, BSL_CID_FRIENDLYNAME, &buffer);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_BagAddAttr(certBag, BSL_CID_FRIENDLYNAME, &buffer);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
EXIT:
    HITLS_PKCS12_BagFree(keyBag);
    HITLS_PKCS12_BagFree(certBag);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(enCert);
#endif
}
/* END_CASE */

/**
 * For test p12-bag in invalid params.
*/
/* BEGIN_CASE */
void SDV_PKCS12_BAG_TEST_TC002(char *pkeyPath)
{
#if !defined(HITLS_CRYPTO_KEY_DECODE) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_PKI_PKCS12_GEN)
    (void)pkeyPath;
    SKIP_TEST();
#else
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_PKCS12_Bag *keyBag = NULL;

    BSL_Buffer buffer = {0};
    int32_t ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pkeyPath, NULL, 0, &pkey);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    keyBag = HITLS_PKCS12_BagNew(BSL_CID_MAX, pkey); // invalid bag-id.
    ASSERT_EQ(keyBag, NULL);
    keyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, pkey);
    ASSERT_NE(keyBag, NULL);

    ret = HITLS_PKCS12_BagAddAttr(keyBag, BSL_CID_FRIENDLYNAME, NULL); // Attribute is null.
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    char *name = "friendlyName";
    uint32_t nameLen = strlen(name);
    buffer.data = (uint8_t *)name;
    buffer.dataLen = nameLen;
    ret = HITLS_PKCS12_BagAddAttr(NULL, BSL_CID_FRIENDLYNAME, &buffer);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_BagAddAttr(keyBag, BSL_CID_EXTEND, &buffer);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES);

    ret = HITLS_PKCS12_BagAddAttr(keyBag, BSL_CID_FRIENDLYNAME, &buffer);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_BagAddAttr(keyBag, BSL_CID_FRIENDLYNAME, &buffer);
    ASSERT_EQ(ret, HITLS_X509_ERR_SET_ATTR_REPEAT);
EXIT:
    HITLS_PKCS12_BagFree(keyBag);
    CRYPT_EAL_PkeyFreeCtx(pkey);
#endif
}
/* END_CASE */


/**
 * For test p12-ctrl in invalid params of repeated attributes.
*/
/* BEGIN_CASE */
void SDV_PKCS12_BAG_TEST_TC003(char *pkeyPath, char *certPath)
{
#if !defined(HITLS_CRYPTO_KEY_DECODE) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_PKI_PKCS12_GEN)
    (void)pkeyPath;
    (void)certPath;
    SKIP_TEST();
#else
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *enCert = NULL;
    HITLS_PKCS12_Bag *certBag = NULL;
    HITLS_PKCS12_Bag *keyBag = NULL;
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);
    int32_t mdId = CRYPT_MD_SHA1;

    int32_t ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pkeyPath, NULL, 0, &pkey);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    keyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, pkey);
    ASSERT_NE(keyBag, NULL);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &enCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, enCert);
    ASSERT_NE(certBag, NULL);

    uint8_t keyId[32] = {0};
    uint32_t idLen = 32;
    BSL_Buffer attr = {.data = keyId, .dataLen = idLen};
    ret = HITLS_PKCS12_BagAddAttr(certBag, BSL_CID_LOCALKEYID, &attr);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_KEYBAG, keyBag, 0);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_KEYBAG, keyBag, 0);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_REPEATED_SET_KEY); // Repeat setting.

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_CERTBAG, certBag, 0);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_CERTBAG, certBag, 0);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_REPEATED_SET_ENTITYCERT); // Repeat setting.

    // The key bag has pushed the localKey-id attribute.
    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GEN_LOCALKEYID, &mdId, sizeof(CRYPT_MD_AlgId));
    ASSERT_EQ(ret, HITLS_X509_ERR_SET_ATTR_REPEAT);

EXIT:
    HITLS_PKCS12_Free(p12);
    HITLS_X509_CertFree(enCert);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_PKCS12_BagFree(keyBag);
    HITLS_PKCS12_BagFree(certBag);
#endif
}
/* END_CASE */

/**
 * For test generating a .p12 from reading buffer.
*/
/* BEGIN_CASE */
void SDV_PKCS12_GEN_FROM_DATA_TC001(char *pkeyPath, char *enCertPath, char *ca1CertPath, char *otherCertPath)
{
#ifndef HITLS_PKI_PKCS12_GEN
    (void)pkeyPath;
    (void)enCertPath;
    (void)ca1CertPath;
    (void)otherCertPath;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), 0);
    char *pwd = "123456";
    CRYPT_Pbkdf2Param pbParam = {BSL_CID_PBES2, BSL_CID_PBKDF2, CRYPT_MAC_HMAC_SHA256, CRYPT_CIPHER_AES256_CBC,
        16, (uint8_t *)pwd, strlen(pwd), 2048};
    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    HITLS_PKCS12_KdfParam macParam = {8, 2048, BSL_CID_SHA256, (uint8_t *)pwd, strlen(pwd)};
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    HITLS_PKCS12_EncodeParam encodeParam = {encParam, encParam, paramTest};

#ifdef HITLS_PKI_PKCS12_PARSE
    BSL_Buffer encPwd = {.data = (uint8_t *)pwd, .dataLen = strlen(pwd)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &encPwd, .macPwd = &encPwd};
#endif

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *enCert = NULL;
    HITLS_X509_Cert *ca1Cert = NULL;
    HITLS_X509_Cert *otherCert = NULL;

    HITLS_PKCS12_Bag *pkeyBag = NULL;
    HITLS_PKCS12_Bag *encertBag = NULL;
    HITLS_PKCS12_Bag *ca1Bag = NULL;
    HITLS_PKCS12_Bag *otherCertBag = NULL;

    HITLS_X509_Cert *targetCert = NULL;
    CRYPT_EAL_PkeyCtx *targetKey = NULL;

    char *name = "entity";
    uint32_t nameLen = strlen(name);
    BSL_Buffer buffer1 = {0};
    buffer1.data = (uint8_t *)name;
    buffer1.dataLen = nameLen;

    char *name1 = "ca1";
    uint32_t nameLen1 = strlen(name1);
    BSL_Buffer buffer2 = {0};
    buffer2.data = (uint8_t *)name1;
    buffer2.dataLen = nameLen1;

    BSL_Buffer output = {0};

    int32_t mdId = CRYPT_MD_SHA1;
    HITLS_PKCS12 *p12_1 = NULL;
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pkeyPath, NULL, 0, &pkey), 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, enCertPath, &enCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, ca1CertPath, &ca1Cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, otherCertPath, &otherCert), HITLS_PKI_SUCCESS);

    pkeyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, pkey); // new a key Bag
    ASSERT_NE(pkeyBag, NULL);

    ca1Bag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, ca1Cert); // new a cert Bag
    ASSERT_NE(ca1Bag, NULL);

    encertBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, enCert); // new a cert Bag
    ASSERT_NE(encertBag, NULL);

    otherCertBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, otherCert);
    ASSERT_NE(otherCertBag, NULL);

    // Add a attribute to the keyBag.
    ASSERT_EQ(HITLS_PKCS12_BagAddAttr(pkeyBag, BSL_CID_FRIENDLYNAME, &buffer1), 0);
    // Add a attribute to the certBag.
    ASSERT_EQ(HITLS_PKCS12_BagAddAttr(encertBag, BSL_CID_FRIENDLYNAME, &buffer1), 0);
    ASSERT_EQ(HITLS_PKCS12_BagAddAttr(ca1Bag, BSL_CID_FRIENDLYNAME, &buffer2), 0);
    // Set entity-key to p12.
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_KEYBAG, pkeyBag, 0), 0);
    // Set entity-cert to p12.
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_CERTBAG, encertBag, 0), 0);
    // Set ca-cert to p12.
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_CERTBAG, ca1Bag, 0), 0);
    // Set the second cert, which has no attr.
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_CERTBAG, otherCertBag, 0), 0);
    // Cal localKeyId to p12.
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GEN_LOCALKEYID, &mdId, sizeof(CRYPT_MD_AlgId)), 0);

    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), 0);

#ifdef HITLS_PKI_PKCS12_PARSE
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &pwdParam, &p12_1, true), 0);

    // Attempt to get a entity-cert from p12 we parsed.
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_ENTITY_CERT, &targetCert, 0), 0);
    ASSERT_NE(targetCert, NULL);

    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_ENTITY_KEY, &targetKey, 0), 0); // Attempt to get a entity-key.
    ASSERT_NE(targetKey, NULL);

    ASSERT_EQ(BSL_LIST_COUNT(p12_1->certList), 2);
#endif
EXIT:
    HITLS_X509_CertFree(targetCert);
    CRYPT_EAL_PkeyFreeCtx(targetKey);
    HITLS_PKCS12_BagFree(pkeyBag);
    HITLS_PKCS12_BagFree(encertBag);
    HITLS_PKCS12_BagFree(ca1Bag);
    HITLS_PKCS12_BagFree(otherCertBag);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(enCert);
    HITLS_X509_CertFree(ca1Cert);
    HITLS_X509_CertFree(otherCert);
    HITLS_PKCS12_Free(p12);
    HITLS_PKCS12_Free(p12_1);
    BSL_SAL_Free(output.data);
#endif
}
/* END_CASE */
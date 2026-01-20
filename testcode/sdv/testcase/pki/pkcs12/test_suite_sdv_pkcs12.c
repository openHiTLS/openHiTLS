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
#include "stub_utils.h"
#include "bsl_list_internal.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET3(int32_t, HITLS_X509_AddListItemDefault, void *, uint32_t, BSL_ASN1_List *);
STUB_DEFINE_RET3(int32_t, HITLS_PKCS12_ParseAsn1AddList, BSL_Buffer *, BSL_ASN1_List *, uint32_t);
STUB_DEFINE_RET6(int32_t, HITLS_PKCS12_ParseContentInfo, HITLS_PKI_LibCtx *, const char *, BSL_Buffer *, const uint8_t *, uint32_t, BSL_Buffer *);
STUB_DEFINE_RET8(int32_t, CRYPT_EAL_ProviderDecodeBuffKey, CRYPT_EAL_LibCtx *, const char *, int32_t, const char *, const char *, BSL_Buffer *, const BSL_Buffer *, CRYPT_EAL_PkeyCtx **);
STUB_DEFINE_RET3(int32_t, HITLS_X509_CertParseBuff, int32_t, const BSL_Buffer *, HITLS_X509_Cert **);
STUB_DEFINE_RET3(HITLS_PKCS12_Bag *, HITLS_PKCS12_BagNew, uint32_t, uint32_t, void *);
STUB_DEFINE_RET3(int32_t, BSL_LIST_AddElement, BslList *, void *, BslListPosition);

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
    ASSERT_TRUE(TestIsErrStackEmpty());
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
    ASSERT_TRUE(TestIsErrStackEmpty());

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
    ASSERT_TRUE(TestIsErrStackEmpty());
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
    ASSERT_TRUE(TestIsErrStackEmpty());

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
    ASSERT_TRUE(TestIsErrStackEmpty());
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
    ASSERT_TRUE(TestIsErrStackEmpty());
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
    TestMemInit();
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);
    BSL_Buffer output = {0};
    HITLS_PKCS12_MacData *macData = p12->macData;
    macData->alg = alg;
    macData->macSalt->data = BSL_SAL_Dump(salt->x, salt->len);
    ASSERT_NE(macData->macSalt->data, NULL);
    macData->macSalt->dataLen = salt->len;
    macData->iteration = iter;
    char *pwdData = "123456";
    uint32_t pwdlen = strlen(pwdData);
    BSL_Buffer pwd = {(uint8_t *)pwdData, pwdlen};
    int32_t ret = HITLS_PKCS12_CalMac(p12, &pwd, (BSL_Buffer *)initData, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(memcmp(output.data, mac->x, mac->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(output.data);
    HITLS_PKCS12_Free(p12);
}
/* END_CASE */

/**
 * For test cal key according to salt, alg, etc.
*/
/* BEGIN_CASE */
void SDV_PKCS12_CAL_KDF_TC001(Hex *pwd, Hex *salt, int alg, int iter, Hex *key)
{
    TestMemInit();
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);
    HITLS_PKCS12_MacData *macData = p12->macData;
    macData->alg = alg;
    macData->macSalt->data = BSL_SAL_Dump(salt->x, salt->len);
    ASSERT_NE(macData->macSalt->data, NULL);
    macData->macSalt->dataLen = salt->len;
    macData->iteration = iter;
    uint8_t outData[64] = {0};
    BSL_Buffer output = {outData, 64};
    int32_t ret = HITLS_PKCS12_KDF(p12, pwd->x, pwd->len, HITLS_PKCS12_KDF_MACKEY_ID, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(memcmp(output.data, key->x, key->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_PKCS12_Free(p12);
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
    ASSERT_TRUE(TestIsErrStackEmpty());
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
    TestErrClear();
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, (BSL_Buffer *)encode, &param, &p12, false), HITLS_PKI_SUCCESS);
    ASSERT_NE(p12->key->value.key, NULL);
    ASSERT_NE(p12->entityCert->value.cert, NULL);
#ifdef HITLS_PKI_PKCS12_GEN
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, p12->entityCert->value.cert, &encodeCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(memcmp(encodeCert.data, cert->x, cert->len), 0);
#endif
    ASSERT_TRUE(TestIsErrStackEmpty());
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
    ASSERT_TRUE(TestIsErrStackEmpty());
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
    bag->value.key = p12->key->value.key;
    bag->id = BSL_CID_PKCS8SHROUDEDKEYBAG;
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

    ret = HITLS_PKCS12_EncodeAsn1List(p12, list, BSL_CID_PKCS8SHROUDEDKEYBAG, &paramEx, &encode);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(encode.dataLen, buff->len);
    ret = memcmp(encode.data + encode.dataLen - 37, buff->x + buff->len - 37, 37);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

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

    ret = HITLS_PKCS12_EncodeAsn1List(p12, p12->certList, BSL_CID_CERTBAG, &paramEx, &encode);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_EncodeContentInfo(NULL, NULL, &encode, BSL_CID_PKCS7_ENCRYPTEDDATA, &paramEx, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(output.dataLen, buff->len);
    ret = memcmp(output.data, buff->x, 69);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

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

    HITLS_PKCS12_Bag *bag = BSL_SAL_Calloc(1u, sizeof(HITLS_PKCS12_Bag));
    bag->attributes = p12->entityCert->attributes;
    bag->value.cert = p12->entityCert->value.cert;
    bag->id = BSL_CID_CERTBAG;
    bag->type = BSL_CID_X509CERTIFICATE;
    ret = BSL_LIST_AddElement(p12->certList, bag, BSL_LIST_POS_BEGIN);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    p12->entityCert->attributes = NULL;
    p12->entityCert->value.cert = NULL;

    ret = HITLS_PKCS12_EncodeAsn1List(p12, p12->certList, BSL_CID_CERTBAG, &paramEx, encode1);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_EncodeContentInfo(NULL, NULL, encode1, BSL_CID_PKCS7_ENCRYPTEDDATA, &paramEx, encode2);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    bagKey = BSL_SAL_Calloc(1u, sizeof(HITLS_PKCS12_Bag));
    bagKey->attributes = p12->key->attributes;
    bagKey->value = p12->key->value;
    bagKey->id = BSL_CID_PKCS8SHROUDEDKEYBAG;
    ret = BSL_LIST_AddElement(keyList, bagKey, BSL_LIST_POS_END);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_EncodeAsn1List(p12, keyList, BSL_CID_PKCS8SHROUDEDKEYBAG, &paramEx, encode3);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_EncodeContentInfo(NULL, NULL, encode3, BSL_CID_PKCS7_SIMPLEDATA, &paramEx, encode4);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = BSL_LIST_AddElement(list, encode2, BSL_LIST_POS_END);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = BSL_LIST_AddElement(list, encode4, BSL_LIST_POS_END);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_EncodeAsn1List(p12, list, BSL_CID_PKCS7_CONTENTINFO, &paramEx, &encode5);
    ASSERT_EQ(encode5.dataLen, buff->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

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
    HITLS_PKCS12 *p12_1 = NULL;

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
    ASSERT_EQ(HITLS_PKCS12_EncodeMacData(p12, (BSL_Buffer *)initData, &macParam, &output), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(memcmp(output.data, expectData->x, expectData->len), 0);
    p12_1 = HITLS_PKCS12_New();
    ASSERT_NE(p12_1, NULL);
    hmacParam.itCnt = 999;
    ASSERT_EQ(HITLS_PKCS12_EncodeMacData(p12_1, (BSL_Buffer *)initData, &macParam, &output),
        HITLS_PKCS12_ERR_INVALID_ITERATION);

    hmacParam.itCnt = 1024;
    hmacParam.saltLen = 0;
    ASSERT_EQ(HITLS_PKCS12_EncodeMacData(p12_1, (BSL_Buffer *)initData, &macParam, &output),
        HITLS_PKCS12_ERR_INVALID_SALTLEN);

    hmacParam.saltLen = 16;
    ASSERT_EQ(HITLS_PKCS12_EncodeMacData(p12_1, (BSL_Buffer *)initData, &macParam, &output1), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(output.data);
    BSL_SAL_Free(output1.data);
    HITLS_PKCS12_Free(p12);
    HITLS_PKCS12_Free(p12_1);
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
    encodeParam.encParam = encParam;

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
    ASSERT_TRUE(TestIsErrStackEmpty());
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
    encodeParam.encParam = encParam;

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
    encodeParam.encParam = encParam;

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
    TestErrClear();

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

    BSL_LIST_DeleteAll(p12_1.certList, (BSL_LIST_PFUNC_FREE)HITLS_PKCS12_BagFree); // test p12-encode of key attribute = NULL.
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, &p12_1, &encodeParam, true, &output6);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
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

    keyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, 0, pkey);
    ASSERT_NE(keyBag, NULL);

    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &enCert), HITLS_PKI_SUCCESS);

    certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, enCert);
    ASSERT_NE(certBag, NULL);

    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_KEYBAG, keyBag, 0), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_CERTBAG, certBag, 0), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    HITLS_PKCS12_EncodeParam encodeParam = {0};

    BSL_Buffer output = {0};
    // While the encrypted data is null of cert and key
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, false, &output), HITLS_PKCS12_ERR_NO_ENCRYPT_PARAM);
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), HITLS_PKCS12_ERR_NO_ENCRYPT_PARAM);

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
    encodeParam.encParam = encParam;
    encodeParam.macParam = paramTest;
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, false, &output), HITLS_PKI_SUCCESS);

    BSL_SAL_Free(output.data);
    output.data = NULL;
    paramTest.algId = BSL_CID_MAX;
    encodeParam.macParam = paramTest;
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), HITLS_PKCS12_ERR_INVALID_ALGO);

    paramTest.algId = BSL_CID_PKCS12KDF;
    paramTest.para = NULL;
    encodeParam.macParam = paramTest;
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), HITLS_PKCS12_ERR_NO_MAC_PARAM);
EXIT:
    BSL_SAL_Free(output.data);
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
    encodeParam.encParam = encParam;

    const char *path = "../testdata/cert/asn1/pkcs12/chain.p12";
    const char *writePath = "./chain_cp.p12";

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
    remove(writePath);
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
    HITLS_PKCS12_Bag *pkeyBagTmp = NULL;
    HITLS_PKCS12_Bag *encertBagTmp = NULL;
    HITLS_X509_Cert *tmpCert = NULL;
    CRYPT_EAL_PkeyCtx *tmpKey = NULL;
    int32_t mdId = CRYPT_MD_SHA1;
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);

    int32_t ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pkeyPath, NULL, 0, &pkey);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, enCertPath, &enCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, caCertPath, &caCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    caBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, caCert);
    ASSERT_NE(caBag, NULL);

    pkeyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, 0, pkey);
    ASSERT_NE(pkeyBag, NULL);

    encertBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, enCert);
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
    ASSERT_TRUE(TestIsErrStackEmpty());

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GEN_LOCALKEYID, &mdId, 0);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_INVALID_PARAM);

    mdId = BSL_CID_MD4 - 1;
    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GEN_LOCALKEYID, &mdId, sizeof(CRYPT_MD_AlgId));
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_INVALID_PARAM);
    TestErrClear();

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_CERTBAG, caBag, 0);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ASSERT_NE(p12->key->value.key, NULL);
    ASSERT_NE(p12->entityCert->value.cert, NULL);
    ASSERT_EQ(BSL_LIST_COUNT(p12->key->attributes->list), 1);
    ASSERT_EQ(BSL_LIST_COUNT(p12->entityCert->attributes->list), 1);
    ASSERT_EQ(BSL_LIST_COUNT(p12->certList), 1);

    // get bag from p12-ctx.
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_ENTITY_CERTBAG, &encertBagTmp, 0), HITLS_PKI_SUCCESS);
    ASSERT_NE(encertBagTmp, NULL);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_ENTITY_KEYBAG, &pkeyBagTmp, 0), HITLS_PKI_SUCCESS);
    ASSERT_NE(pkeyBagTmp, NULL);

    // get value from bag.
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(encertBagTmp, HITLS_PKCS12_BAG_GET_VALUE, &tmpCert, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(tmpCert, p12->entityCert->value.cert);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(pkeyBagTmp, HITLS_PKCS12_BAG_GET_VALUE, &tmpKey, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(tmpKey, p12->key->value.key);
    ASSERT_TRUE(TestIsErrStackEmpty());
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
    HITLS_X509_CertFree(tmpCert);
    CRYPT_EAL_PkeyFreeCtx(tmpKey);
    HITLS_PKCS12_BagFree(encertBagTmp);
    HITLS_PKCS12_BagFree(pkeyBagTmp);
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

    entityCertBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, enCert);
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
    int32_t id = 0;
    int32_t type = 0;
    int32_t ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pkeyPath, NULL, 0, &pkey);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    keyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, 0, pkey);
    ASSERT_NE(keyBag, NULL);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &enCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, enCert);
    ASSERT_NE(certBag, NULL);

    ASSERT_EQ(HITLS_PKCS12_BagCtrl(NULL, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME),
        HITLS_PKCS12_ERR_NULL_POINTER);

    ASSERT_EQ(HITLS_PKCS12_BagCtrl(keyBag, HITLS_PKCS12_BAG_GET_ID, NULL, sizeof(uint32_t)),
        HITLS_PKCS12_ERR_NULL_POINTER);

    ASSERT_EQ(HITLS_PKCS12_BagCtrl(keyBag, HITLS_PKCS12_BAG_GET_TYPE, NULL, sizeof(uint32_t)),
        HITLS_PKCS12_ERR_NULL_POINTER);

    ASSERT_EQ(HITLS_PKCS12_BagCtrl(keyBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME), 0);

    ASSERT_EQ(HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_GET_ID, &id, sizeof(uint8_t)),
        HITLS_PKCS12_ERR_INVALID_PARAM);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_GET_TYPE, &type, sizeof(uint8_t)),
        HITLS_PKCS12_ERR_INVALID_PARAM);

    ASSERT_EQ(HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_GET_ID, &id, sizeof(uint32_t)), 0);
    ASSERT_EQ(id, BSL_CID_CERTBAG);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_GET_TYPE, &type, sizeof(uint32_t)), 0);
    ASSERT_EQ(type, BSL_CID_X509CERTIFICATE);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME), 0);

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
    HITLS_PKCS12_Bag *crlBag = NULL;

    BSL_Buffer buffer = {0};
    int32_t ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pkeyPath, NULL, 0, &pkey);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    keyBag = HITLS_PKCS12_BagNew(BSL_CID_MAX, 0, pkey); // invalid bag-id.
    ASSERT_EQ(keyBag, NULL);
    keyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, 0, pkey);
    ASSERT_NE(keyBag, NULL);
    crlBag = HITLS_PKCS12_BagNew(BSL_CID_CRLBAG, BSL_CID_CRLBAG, pkey);
    ASSERT_EQ(crlBag, NULL);

    ret = HITLS_PKCS12_BagCtrl(keyBag, HITLS_PKCS12_BAG_ADD_ATTR, NULL, BSL_CID_FRIENDLYNAME); // Attribute is null.
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    char *name = "friendlyName";
    uint32_t nameLen = strlen(name);
    buffer.data = (uint8_t *)name;
    buffer.dataLen = nameLen;
    ret = HITLS_PKCS12_BagCtrl(NULL, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_NULL_POINTER);

    ret = HITLS_PKCS12_BagCtrl(keyBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_EXTEND);
    ASSERT_EQ(ret, HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES);

    ret = HITLS_PKCS12_BagCtrl(keyBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ret = HITLS_PKCS12_BagCtrl(keyBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME);
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

    keyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, 0, pkey);
    ASSERT_NE(keyBag, NULL);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &enCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, enCert);
    ASSERT_NE(certBag, NULL);

    uint8_t keyId[32] = {0};
    uint32_t idLen = 32;
    BSL_Buffer attr = {.data = keyId, .dataLen = idLen};
    ret = HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_ADD_ATTR, &attr, BSL_CID_LOCALKEYID);
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
    HITLS_PKCS12_EncodeParam encodeParam = {encParam, paramTest};

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

    pkeyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, 0, pkey); // new a key Bag
    ASSERT_NE(pkeyBag, NULL);

    ca1Bag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, ca1Cert); // new a cert Bag
    ASSERT_NE(ca1Bag, NULL);

    encertBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, enCert); // new a cert Bag
    ASSERT_NE(encertBag, NULL);

    otherCertBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, otherCert);
    ASSERT_NE(otherCertBag, NULL);

    // Add a attribute to the keyBag.
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(pkeyBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer1, BSL_CID_FRIENDLYNAME), 0);
    // Add a attribute to the certBag.
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(encertBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer1, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(ca1Bag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer2, BSL_CID_FRIENDLYNAME), 0);
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
    ASSERT_TRUE(TestIsErrStackEmpty());
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

/**
 * For test generating a .p12, which including a secret-bag.
*/
/* BEGIN_CASE */
void SDV_PKCS12_GEN_SECRET_BAG_TC001(char *pkeyPath, char *certPath)
{
#if !defined(HITLS_PKI_PKCS12_PARSE) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_PKI_PKCS12_GEN)
    (void)pkeyPath;
    (void)certPath;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), 0);
    const char *writePath = "../testdata/cert/asn1/pkcs12/secret.p12";

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *enCert = NULL;
    HITLS_PKCS12_Bag *keyBag = NULL;
    HITLS_PKCS12_Bag *certBag = NULL;
    char *pwd = "123456";
    // All adopt smX algorithms
    CRYPT_Pbkdf2Param pbParam = {BSL_CID_PBES2, BSL_CID_PBKDF2, CRYPT_MAC_HMAC_SM3, CRYPT_CIPHER_SM4_CBC,
        16, (uint8_t *)pwd, strlen(pwd), 2048};
    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    HITLS_PKCS12_KdfParam macParam = {8, 2048, BSL_CID_SM3, (uint8_t *)pwd, strlen(pwd)};
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    HITLS_PKCS12_EncodeParam encodeParam = {encParam, paramTest};
    BSL_Buffer encPwd = {.data = (uint8_t *)pwd, .dataLen = strlen(pwd)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &encPwd, .macPwd = &encPwd};
    HITLS_PKCS12_Bag *secretBag = NULL;
    uint8_t secretData[20] = {1};
    uint32_t secretDataLen = 20;
    BSL_Buffer secret = {.data = (uint8_t *)secretData, .dataLen = secretDataLen};
    char *name = "secret";
    uint32_t nameLen = strlen(name);
    BSL_Buffer friendlyName = {.data = (uint8_t *)name, .dataLen = nameLen};
    BSL_Buffer output = {0};
    HITLS_PKCS12 *p12_1 = NULL;
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);

    secretBag = HITLS_PKCS12_BagNew(BSL_CID_SECRETBAG, BSL_CID_CE_EXTKEYUSAGE, &secret);
    ASSERT_NE(secretBag, NULL);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pkeyPath, NULL, 0, &pkey), 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &enCert), 0);

    keyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, 0, pkey);
    ASSERT_NE(keyBag, NULL);

    certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, enCert);
    ASSERT_NE(certBag, NULL);

    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_KEYBAG, keyBag, 0), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_CERTBAG, certBag, 0), 0);

    // Add a attribute to the secretBag.
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(secretBag, HITLS_PKCS12_BAG_ADD_ATTR, &friendlyName, BSL_CID_FRIENDLYNAME), 0);
    // Set the secretBag to p12.
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_SECRETBAG, secretBag, 0), 0);
    // no mac
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, false, &output), 0);
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &pwdParam, &p12_1, false), HITLS_PKI_SUCCESS);
    BSL_SAL_FREE(output.data);
    HITLS_PKCS12_Free(p12_1);
    p12_1 = NULL;
    // with mac
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), 0);
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &pwdParam, &p12_1, true), HITLS_PKI_SUCCESS);
    HITLS_PKCS12_Free(p12_1);
    p12_1 = NULL;
    // no mac
    ASSERT_EQ(HITLS_PKCS12_GenFile(BSL_FORMAT_ASN1, p12, &encodeParam, false, writePath), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_PKCS12_ParseFile(BSL_FORMAT_ASN1, writePath, &pwdParam, &p12_1, false), HITLS_PKI_SUCCESS);
    HITLS_PKCS12_Free(p12_1);
    p12_1 = NULL;
    // with mac
    ASSERT_EQ(HITLS_PKCS12_GenFile(BSL_FORMAT_ASN1, p12, &encodeParam, true, writePath), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_PKCS12_ParseFile(BSL_FORMAT_ASN1, writePath, &pwdParam, &p12_1, true), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(enCert);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_PKCS12_BagFree(secretBag);
    HITLS_PKCS12_BagFree(keyBag);
    HITLS_PKCS12_BagFree(certBag);
    HITLS_PKCS12_Free(p12);
    HITLS_PKCS12_Free(p12_1);
    BSL_SAL_Free(output.data);
    remove(writePath);
#endif
}
/* END_CASE */

/**
 * For test bag-ctrl, including get-id, get-type, get-value in secret-bag.
*/
/* BEGIN_CASE */
void SDV_PKCS12_BAG_CTRL_TC001(void)
{
#if !defined(HITLS_PKI_PKCS12_PARSE) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_PKI_PKCS12_GEN)
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
    HITLS_PKCS12_EncodeParam encodeParam = {encParam, paramTest};

    BSL_Buffer encPwd = {.data = (uint8_t *)pwd, .dataLen = strlen(pwd)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &encPwd, .macPwd = &encPwd};

    uint32_t id;
    uint32_t type;
    BSL_ASN1_List *secretBags = NULL;
    HITLS_PKCS12_Bag *secretBag1 = NULL;
    HITLS_PKCS12_Bag *secretBag2 = NULL;

    uint8_t secretData1[20];
    uint32_t secretDataLen1 = 20;
    (void)memset_s(secretData1, secretDataLen1, 'F', secretDataLen1);
    BSL_Buffer secret1 = {.data = (uint8_t *)secretData1, .dataLen = secretDataLen1};
    uint8_t secretData2[30];
    uint32_t secretDataLen2 = 30;
    (void)memset_s(secretData2, secretDataLen2, 'A', secretDataLen2);
    BSL_Buffer secret2 = {.data = (uint8_t *)secretData2, .dataLen = secretDataLen2};

    uint8_t outputSecret[30] = {2};
    uint32_t outputSecretLen = 30;
    BSL_Buffer outBuf = {.data = (uint8_t *)outputSecret, .dataLen = outputSecretLen};

    char *name = "secret1"; // friendlyName of secretBag1
    uint32_t nameLen = strlen(name);
    BSL_Buffer friendlyName1 = {.data = (uint8_t *)name, .dataLen = nameLen};
    char *name2 = "secret2"; // friendlyName of secretBag2
    uint32_t nameLen2 = strlen(name2);
    BSL_Buffer friendlyName2 = {.data = (uint8_t *)name2, .dataLen = nameLen2};
    BSL_Buffer output = {0};

    HITLS_PKCS12_Bag *tmpBag = NULL;
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);
    HITLS_PKCS12 *p12_1 = NULL;
    secretBag1 = HITLS_PKCS12_BagNew(BSL_CID_SECRETBAG, BSL_CID_CE_EXTKEYUSAGE, &secret1);
    ASSERT_NE(secretBag1, NULL);
    secretBag2 = HITLS_PKCS12_BagNew(BSL_CID_SECRETBAG, BSL_CID_CE_KEYUSAGE, &secret2);
    ASSERT_NE(secretBag2, NULL);

    // Add a attribute to the secretBag.
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(secretBag1, HITLS_PKCS12_BAG_ADD_ATTR, &friendlyName1, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(secretBag2, HITLS_PKCS12_BAG_ADD_ATTR, &friendlyName2, BSL_CID_FRIENDLYNAME), 0);
    // Set the secretBag to p12.
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_SECRETBAG, secretBag1, 0), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_SECRETBAG, secretBag2, 0), 0);

    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), 0);
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &pwdParam, &p12_1, true), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_SECRETBAGS, &secretBags, 0), 0);
    ASSERT_EQ(BSL_LIST_COUNT(secretBags), 2);
    tmpBag = BSL_LIST_GET_FIRST(secretBags);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(tmpBag, HITLS_PKCS12_BAG_GET_ID, &id, sizeof(uint32_t)), 0);
    ASSERT_EQ(id, BSL_CID_SECRETBAG);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(tmpBag, HITLS_PKCS12_BAG_GET_TYPE, &type, sizeof(uint32_t)), 0);
    ASSERT_EQ(type, BSL_CID_CE_EXTKEYUSAGE);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(tmpBag, HITLS_PKCS12_BAG_GET_VALUE, &outBuf, sizeof(BSL_Buffer)), 0);
    ASSERT_COMPARE("compare secret1", outBuf.data, outBuf.dataLen, secretData1, secretDataLen1);

    outBuf.dataLen = 30; // init len is 30.
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(tmpBag, HITLS_PKCS12_BAG_GET_ATTR, &outBuf, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_COMPARE("compare attr1", outBuf.data, outBuf.dataLen, name, nameLen);

    tmpBag = (HITLS_PKCS12_Bag *)BSL_LIST_GET_LAST(secretBags);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(tmpBag, HITLS_PKCS12_BAG_GET_ID, &id, sizeof(uint32_t)), 0);
    ASSERT_EQ(id, BSL_CID_SECRETBAG);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(tmpBag, HITLS_PKCS12_BAG_GET_TYPE, &type, sizeof(uint32_t)), 0);
    ASSERT_EQ(type, BSL_CID_CE_KEYUSAGE);
    outBuf.dataLen = 30; // init len is 30.
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(tmpBag, HITLS_PKCS12_BAG_GET_ATTR, &outBuf, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_COMPARE("compare attr2", outBuf.data, outBuf.dataLen, name2, nameLen2);

    outBuf.dataLen = 30; // init len is 30.
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(tmpBag, HITLS_PKCS12_BAG_GET_VALUE, &outBuf, sizeof(BSL_Buffer)), 0);
    ASSERT_COMPARE("compare secret2", outBuf.data, outBuf.dataLen, secretData2, secretDataLen2);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_PKCS12_BagFree(secretBag1);
    HITLS_PKCS12_BagFree(secretBag2);
    HITLS_PKCS12_Free(p12);
    HITLS_PKCS12_Free(p12_1);
    BSL_SAL_Free(output.data);
#endif
}
/* END_CASE */

/**
 * For test bag-ctrl, including get-id, get-type, get-value in cert-bag and key-bag.
*/
/* BEGIN_CASE */
void SDV_PKCS12_BAG_CTRL_TC002(char *pkeyPath, char *certPath)
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
    CRYPT_EAL_PkeyCtx *tmpKey = NULL;
    HITLS_X509_Cert *tmpCert = NULL;
    uint32_t id;
    uint32_t type;
    uint8_t keyId[32] = {0};
    uint32_t idLen = 32;
    BSL_Buffer attr = {.data = keyId, .dataLen = idLen};

    int32_t ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pkeyPath, NULL, 0, &pkey);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    keyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, 0, pkey);
    ASSERT_NE(keyBag, NULL);

    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, certPath, &enCert);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, enCert);
    ASSERT_NE(certBag, NULL);

    ASSERT_EQ(HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_ADD_ATTR, &attr, BSL_CID_LOCALKEYID), 0);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(keyBag, HITLS_PKCS12_BAG_ADD_ATTR, &attr, BSL_CID_LOCALKEYID), 0);

    ASSERT_EQ(HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_GET_ID, &id, sizeof(uint32_t)), 0);
    ASSERT_EQ(id, BSL_CID_CERTBAG);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_GET_TYPE, &type, sizeof(uint32_t)), 0);
    ASSERT_EQ(type, BSL_CID_X509CERTIFICATE);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_GET_VALUE, NULL, 0), HITLS_PKCS12_ERR_NULL_POINTER);
    TestErrClear();
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_GET_VALUE, &tmpCert, 0), 0);
    ASSERT_NE(tmpCert, NULL);

    ASSERT_EQ(HITLS_PKCS12_BagCtrl(keyBag, HITLS_PKCS12_BAG_GET_ID, &id, sizeof(uint32_t)), 0);
    ASSERT_EQ(id, BSL_CID_PKCS8SHROUDEDKEYBAG);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(keyBag, HITLS_PKCS12_BAG_GET_TYPE, &type, sizeof(uint32_t)), 0);
    ASSERT_EQ(type, 0);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(keyBag, HITLS_PKCS12_BAG_GET_VALUE, &tmpKey, 0), 0);
    ASSERT_NE(tmpKey, NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_X509_CertFree(enCert);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(tmpCert);
    CRYPT_EAL_PkeyFreeCtx(tmpKey);
    HITLS_PKCS12_BagFree(keyBag);
    HITLS_PKCS12_BagFree(certBag);
#endif
}
/* END_CASE */

/**
 * For test secret-bag with custom oid.
*/
/* BEGIN_CASE */
void SDV_PKCS12_BAG_CUSTOM_OID_TC001(void)
{
#if !defined(HITLS_CRYPTO_KEY_DECODE) || !defined(HITLS_BSL_SAL_FILE) || !defined(HITLS_PKI_PKCS12_GEN) || \
    !defined(HITLS_BSL_OBJ_CUSTOM)
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), 0);
    const char *writePath = "../testdata/cert/asn1/pkcs12/secret.p12";
    HITLS_PKCS12_Bag *tmpBag = NULL;
    BSL_ASN1_List *secretBags = NULL;
    char *pwd = "123456";
    // All adopt smX algorithms
    CRYPT_Pbkdf2Param pbParam = {BSL_CID_PBES2, BSL_CID_PBKDF2, CRYPT_MAC_HMAC_SM3, CRYPT_CIPHER_SM4_CBC,
        16, (uint8_t *)pwd, strlen(pwd), 2048};
    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    HITLS_PKCS12_KdfParam macParam = {8, 2048, BSL_CID_SM3, (uint8_t *)pwd, strlen(pwd)};
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    HITLS_PKCS12_EncodeParam encodeParam = {encParam, paramTest};
    BSL_Buffer encPwd = {.data = (uint8_t *)pwd, .dataLen = strlen(pwd)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &encPwd, .macPwd = &encPwd};
    HITLS_PKCS12_Bag *secretBag = NULL;

    uint8_t secretData1[20];
    uint32_t secretDataLen1 = 20;
    (void)memset_s(secretData1, secretDataLen1, 'F', secretDataLen1);
    BSL_Buffer secret = {.data = (uint8_t *)secretData1, .dataLen = secretDataLen1};

    char *name = "secret";
    uint32_t nameLen = strlen(name);
    BSL_Buffer friendlyName = {.data = (uint8_t *)name, .dataLen = nameLen};
    BSL_Buffer output = {0};
    uint32_t id;
    uint32_t type;
    char *oid = "\1\1\1\3\1";
    int32_t ourCid = BSL_CID_MAX + 1;
    HITLS_PKCS12 *p12_1 = NULL;
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);
    
    ASSERT_EQ(BSL_OBJ_Create(oid, (uint32_t)strlen(oid), "Our OID", ourCid), HITLS_PKI_SUCCESS);

    secretBag = HITLS_PKCS12_BagNew(BSL_CID_SECRETBAG, ourCid, &secret);
    ASSERT_NE(secretBag, NULL);

    ASSERT_EQ(HITLS_PKCS12_BagCtrl(secretBag, HITLS_PKCS12_BAG_GET_TYPE, &type, sizeof(uint32_t)), 0);
    ASSERT_EQ(type, ourCid);
    // Add a attribute to the secretBag.
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(secretBag, HITLS_PKCS12_BAG_ADD_ATTR, &friendlyName, BSL_CID_FRIENDLYNAME), 0);

    // Set the secretBag to p12.
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_SECRETBAG, secretBag, 0), 0);

    // with mac
    ASSERT_EQ(HITLS_PKCS12_GenFile(BSL_FORMAT_ASN1, p12, &encodeParam, false, writePath), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_PKCS12_ParseFile(BSL_FORMAT_ASN1, writePath, &pwdParam, &p12_1, false), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_SECRETBAGS, &secretBags, 0), 0);
    ASSERT_EQ(BSL_LIST_COUNT(secretBags), 1);
    tmpBag = BSL_LIST_GET_FIRST(secretBags);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(tmpBag, HITLS_PKCS12_BAG_GET_ID, &id, sizeof(uint32_t)), 0);
    ASSERT_EQ(id, BSL_CID_SECRETBAG);
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(tmpBag, HITLS_PKCS12_BAG_GET_TYPE, &type, sizeof(uint32_t)), 0);
    ASSERT_EQ(type, ourCid);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HITLS_PKCS12_BagFree(secretBag);
    HITLS_PKCS12_Free(p12);
    HITLS_PKCS12_Free(p12_1);
    BSL_SAL_Free(output.data);
    remove(writePath);
#endif
}
/* END_CASE */

#ifdef HITLS_PKI_PKCS12_PARSE
static int32_t STUB_HITLS_X509_AddListItemDefault1(void *item, uint32_t len, BSL_ASN1_List *list)
{
    (void)item;
    (void)len;
    (void)list;
    return BSL_MALLOC_FAIL;
}

static int32_t marked = 0;

static int32_t STUB_HITLS_X509_AddListItemDefault2(void *item, uint32_t len, BSL_ASN1_List *list)
{
    if (marked < 2) {
        marked++;
        void *node = BSL_SAL_Malloc(len);
        if (node == NULL) {
            return BSL_MALLOC_FAIL;
        }
        (void)memcpy_s(node, len, item, len);
        return BSL_LIST_AddElement(list, node, BSL_LIST_POS_AFTER);
    }
    return BSL_MALLOC_FAIL;
}
#endif

/**
 * For test parse safeBag-cert in incorrect condition.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_SAFEBAGS_INVALID_TC001(Hex *buff)
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

    STUB_REPLACE(HITLS_X509_AddListItemDefault, STUB_HITLS_X509_AddListItemDefault1);

    // get the safeBag of safeContents, and put int list.
    ret = HITLS_PKCS12_ParseAsn1AddList(&safeContent, bagLists, BSL_CID_SAFECONTENTSBAG);
    ASSERT_NE(ret, HITLS_PKI_SUCCESS);


    STUB_REPLACE(HITLS_X509_AddListItemDefault, STUB_HITLS_X509_AddListItemDefault2);
    // get the safeBag of safeContents, and put int list.
    ret = HITLS_PKCS12_ParseAsn1AddList(&safeContent, bagLists, BSL_CID_SAFECONTENTSBAG);
    ASSERT_NE(ret, HITLS_PKI_SUCCESS);

EXIT:
    marked = 0;
    BSL_SAL_Free(safeContent.data);
    BSL_LIST_DeleteAll(bagLists, (BSL_LIST_PFUNC_FREE)HITLS_PKCS12_SafeBagFree);
    HITLS_PKCS12_Free(p12);
    BSL_SAL_Free(bagLists);

#endif
}
/* END_CASE */

#ifdef HITLS_PKI_PKCS12_PARSE
static int32_t STUB_HITLS_PKCS12_ParseAsn1AddList(BSL_Buffer *encode, BSL_ASN1_List *list, uint32_t parseType)
{
    (void)encode;
    (void)list;
    (void)parseType;
    return BSL_MALLOC_FAIL;
}

static int32_t STUB_HITLS_PKCS12_ParseContentInfo(HITLS_PKI_LibCtx *libCtx, const char *attrName, BSL_Buffer *encode,
    const uint8_t *password, uint32_t passLen, BSL_Buffer *data)
{
    (void)libCtx;
    (void)attrName;
    (void)encode;
    (void)password;
    (void)passLen;
    (void)data;
    return BSL_MALLOC_FAIL;
}

static int32_t STUB_CRYPT_EAL_ProviderDecodeBuffKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, int32_t keyType,
    const char *format, const char *type, BSL_Buffer *encode, const BSL_Buffer *pwd, CRYPT_EAL_PkeyCtx **ealPKey)
{
    (void)libCtx;
    (void)attrName;
    (void)keyType;
    (void)format;
    (void)type;
    (void)encode;
    (void)pwd;
    (void)ealPKey;
    return BSL_MALLOC_FAIL;
}

static HITLS_PKCS12_Bag *STUB_HITLS_PKCS12_BagNew(uint32_t bagId, uint32_t bagType, void *bagValue)
{
    (void)bagId;
    (void)bagType;
    (void)bagValue;
    return NULL;
}

static int32_t STUB_HITLS_X509_CertParseBuff(int32_t format, const BSL_Buffer *encode, HITLS_X509_Cert **cert)
{
    (void)format;
    (void)encode;
    (void)cert;
    return BSL_MALLOC_FAIL;
}

static int32_t test;

static int32_t STUB_BSL_LIST_AddElement(BslList *pList, void *pData, BslListPosition enPosition)
{
    if (marked <= test) { // It takes 53 triggers to prevent cert from entering p12
        marked++;
        return (int32_t)BSL_LIST_AddElementInt(pList, pData, enPosition);
    }
    return BSL_MALLOC_FAIL;
}

#ifdef HITLS_CRYPTO_PROVIDER
    #define MAX_TRIGGERS 103
#else
    #define MAX_TRIGGERS 51
#endif

#endif
/**
 * For test parse authSafe in incorrect condition.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_AUTHSAFE_INVALID_TC001(Hex *buff)
{
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)buff;
    SKIP_TEST();
#else
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);

    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);
    STUB_REPLACE(HITLS_PKCS12_ParseAsn1AddList, STUB_HITLS_PKCS12_ParseAsn1AddList);
    ASSERT_NE(HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, p12), HITLS_PKI_SUCCESS);


    STUB_REPLACE(HITLS_PKCS12_ParseContentInfo, STUB_HITLS_PKCS12_ParseContentInfo);
    ASSERT_NE(HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, p12), HITLS_PKI_SUCCESS);


    STUB_REPLACE(HITLS_X509_AddListItemDefault, STUB_HITLS_X509_AddListItemDefault1);
    ASSERT_NE(HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, p12), HITLS_PKI_SUCCESS);


    STUB_REPLACE(HITLS_X509_AddListItemDefault, STUB_HITLS_X509_AddListItemDefault2);
    ASSERT_NE(HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, p12), HITLS_PKI_SUCCESS);


    STUB_REPLACE(HITLS_X509_AddListItemDefault, STUB_HITLS_X509_AddListItemDefault2);
    ASSERT_NE(HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, p12), HITLS_PKI_SUCCESS);


    STUB_REPLACE(CRYPT_EAL_ProviderDecodeBuffKey, STUB_CRYPT_EAL_ProviderDecodeBuffKey);
    ASSERT_NE(HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, p12), HITLS_PKI_SUCCESS);


    STUB_REPLACE(HITLS_X509_CertParseBuff, STUB_HITLS_X509_CertParseBuff);
    ASSERT_NE(HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, p12), HITLS_PKI_SUCCESS);


    STUB_REPLACE(HITLS_PKCS12_BagNew, STUB_HITLS_PKCS12_BagNew);
    ASSERT_NE(HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, p12), HITLS_PKI_SUCCESS);


    test = MAX_TRIGGERS; // It takes fixed triggers to parse cert from entering p12
    marked = 0;
    STUB_REPLACE(BSL_LIST_AddElement, STUB_BSL_LIST_AddElement);
    HITLS_PKCS12_Free(p12);
    p12 = NULL;
    for (int i = MAX_TRIGGERS; i > 0; i--) {
        p12 = HITLS_PKCS12_New();
        marked = 0;
        test--;
        ASSERT_NE(HITLS_PKCS12_ParseAuthSafeData((BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, p12),
            HITLS_PKI_SUCCESS);
        HITLS_PKCS12_Free(p12);
        p12 = NULL;
    }
EXIT:
    HITLS_PKCS12_Free(p12);

#endif
}
/* END_CASE */

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
#include "bsl_types.h"
#include "bsl_log.h"
#include "sal_file.h"
#include "bsl_init.h"
#include "crypt_codecskey.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "hitls_cms_local.h"
#include "hitls_pki_errno.h"

/* END_HEADER */

/**
 * For test parse p7-encryptData of wrong conditions.
*/
/* BEGIN_CASE */
void SDV_CMS_PARSE_ENCRYPTEDDATA_TC001(Hex *buff)
{
#if !defined(HITLS_PKI_CMS_ENCRYPTDATA)
    (void)buff;
    SKIP_TEST();
#else
    BSL_Buffer output = {0};
    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);

    int32_t ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    BSL_SAL_Free(output.data);
    output.data = NULL;

    ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, NULL, (const uint8_t *)pwd, pwdlen, &output);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, NULL, pwdlen, &output);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd, 8192, &output);
    ASSERT_EQ(ret, CRYPT_INVALID_ARG);

    char *pwd1 = "123456@123";
    ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd1, strlen(pwd1),
        &output);
    ASSERT_EQ(ret, CRYPT_EAL_CIPHER_DATA_ERROR);

    char *pwd2 = "";
    ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd2, strlen(pwd2),
        &output);
    ASSERT_EQ(ret, CRYPT_EAL_CIPHER_DATA_ERROR);

    (void)memset_s(buff->x + buff->len - 20, 16, 0, 16); // modify the ciphertext, 16 and 20 are random number.
    ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen,
        &output);
    ASSERT_EQ(ret, CRYPT_EAL_CIPHER_DATA_ERROR);
EXIT:
    return;
#endif
}
/* END_CASE */

/**
 * For test parse p7-encryptData of right conditions.
*/
/* BEGIN_CASE */
void SDV_CMS_PARSE_ENCRYPTEDDATA_TC002(Hex *buff)
{
#if !defined(HITLS_PKI_CMS_ENCRYPTDATA)
    (void)buff;
    SKIP_TEST();
#else
    BSL_Buffer output = {0};
    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);
    int32_t ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen,
        &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(output.data);
    return;
#endif
}
/* END_CASE */

/**
 * For test parse p7-DigestInfo of wrong conditions.
*/
/* BEGIN_CASE */
void SDV_CMS_PARSE_DIGESTINFO_TC001(Hex *buff, int alg, Hex *digest)
{
#if !defined(HITLS_PKI_CMS_DIGESTINFO)
    (void)buff;
    (void)alg;
    (void)digest;
    SKIP_TEST();
#else
    BSL_Buffer output = {0};
    BslCid cid = BSL_CID_UNKNOWN;
    int32_t ret = HITLS_CMS_ParseDigestInfo(NULL, &cid, &output);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);

    ret = HITLS_CMS_ParseDigestInfo((BSL_Buffer *)buff, &cid, NULL);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);

    ret = HITLS_CMS_ParseDigestInfo((BSL_Buffer *)buff, &cid, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ASSERT_EQ(alg, cid);
    ASSERT_EQ(memcmp(output.data, digest->x, digest->len), 0);
EXIT:
    BSL_SAL_Free(output.data);
    return;
#endif
}
/* END_CASE */

/**
 * For test parse p7-DigestInfo of right conditions.
*/
/* BEGIN_CASE */
void SDV_CMS_PARSE_DIGESTINFO_TC002(Hex *buff, int alg, Hex *digest)
{
#if !defined(HITLS_PKI_CMS_DIGESTINFO)
    (void)buff;
    (void)alg;
    (void)digest;
    SKIP_TEST();
#else
    BSL_Buffer output = {0};
    BslCid cid = BSL_CID_UNKNOWN;
    int32_t ret =  HITLS_CMS_ParseDigestInfo((BSL_Buffer *)buff, &cid, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(alg, cid);
    ASSERT_EQ(memcmp(output.data, digest->x, digest->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(output.data);
    return;
#endif
}
/* END_CASE */

/**
 * For test encode p7-encryptData.
*/
/* BEGIN_CASE */
void SDV_CMS_ENCODE_ENCRYPTEDDATA_TC001(Hex *buff)
{
#if !defined(HITLS_PKI_CMS_ENCRYPTDATA)
    (void)buff;
    SKIP_TEST();
#else
    BSL_Buffer data = {buff->x, buff->len};
    BSL_Buffer output = {0};
    BSL_Buffer verify = {0};
    char *pwd = "123456";
    CRYPT_Pbkdf2Param param = {0};
    param.pbesId = BSL_CID_PBES2;
    param.pbkdfId = BSL_CID_PBKDF2;
    param.hmacId = CRYPT_MAC_HMAC_SHA256;
    param.symId = CRYPT_CIPHER_AES256_CBC;
    param.pwd = (uint8_t *)pwd;
    param.pwdLen = strlen(pwd);
    param.saltLen = 16;
    param.itCnt = 2048;
    CRYPT_EncodeParam paramEx = {CRYPT_DERIVE_PBKDF2, &param};

    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);
    int32_t ret = CRYPT_EAL_EncodePKCS7EncryptDataBuff(NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_EncodePKCS7EncryptDataBuff(NULL, NULL, &data, NULL, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_EncodePKCS7EncryptDataBuff(NULL, NULL, &data, &paramEx, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    param.hmacId = CRYPT_MAC_MAX;
    ret =  CRYPT_EAL_EncodePKCS7EncryptDataBuff(NULL, NULL, &data, &paramEx, &output);
    ASSERT_EQ(ret, CRYPT_ERR_ALGID);
    param.hmacId = CRYPT_MAC_HMAC_SHA256;
    ret = CRYPT_EAL_EncodePKCS7EncryptDataBuff(NULL, NULL, &data, &paramEx, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, &output, (const uint8_t *)pwd, strlen(pwd), &verify);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("encode p7-encryptData", data.data, data.dataLen, verify.data, verify.dataLen);
EXIT:
    TestRandDeInit();
    BSL_SAL_FREE(verify.data);
    BSL_SAL_FREE(output.data);
    return;
#endif
}
/* END_CASE */

/**
 * For test encode p7-DigestInfo.
*/
/* BEGIN_CASE */
void SDV_CMS_ENCODE_DIGESTINFO_TC001()
{
#if !defined(HITLS_PKI_CMS_DIGESTINFO)
    SKIP_TEST();
#else
    BSL_Buffer input = {0};
    BSL_Buffer output = {0};
    BslCid cid = 0;
    BSL_Buffer digest = {0};
    int32_t ret = HITLS_CMS_EncodeDigestInfoBuff(BSL_CID_MD5, NULL, NULL);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    ret = HITLS_CMS_EncodeDigestInfoBuff(BSL_CID_MD5, &input, NULL);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    input.dataLen = 1;
    ret = HITLS_CMS_EncodeDigestInfoBuff(BSL_CID_MD5, &input, &output);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    input.dataLen = 0;
    ret = HITLS_CMS_EncodeDigestInfoBuff(BSL_CID_MD5, &input, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_CMS_ParseDigestInfo(&output, &cid, &digest);
    ASSERT_EQ(ret, HITLS_CMS_ERR_INVALID_DATA);
    BSL_SAL_FREE(output.data);
    input.data = (uint8_t *)"123456";
    input.dataLen = 6;
    ret = HITLS_CMS_EncodeDigestInfoBuff(BSL_CID_MD5, &input, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_CMS_ParseDigestInfo(&output, &cid, &digest);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(cid, BSL_CID_MD5);
EXIT:
    BSL_SAL_FREE(digest.data);
    BSL_SAL_FREE(output.data);
    return;
#endif
}
/* END_CASE */

/**
 * For test encode p7-DigestInfo vector.
*/
/* BEGIN_CASE */
void SDV_CMS_ENCODE_DIGESTINFO_TC002(int algid, Hex *in)
{
#if !defined(HITLS_PKI_CMS_DIGESTINFO)
    (void)algid;
    (void)in;
    SKIP_TEST();
#else
    BSL_Buffer input = {in->x, in->len};
    BSL_Buffer output = {0};
    BslCid cid = 0;
    BSL_Buffer digest = {0};
    int32_t ret = HITLS_CMS_EncodeDigestInfoBuff(algid, &input, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_CMS_ParseDigestInfo(&output, &cid, &digest);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(cid, algid);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_FREE(digest.data);
    BSL_SAL_FREE(output.data);
    return;
#endif
}
/* END_CASE */

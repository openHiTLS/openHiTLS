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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "sal_file.h"
#include "bsl_pem_internal.h"

/* END_HEADER */

/* BEGIN_CASE */
void SDV_BSL_PEM_ISPEM_FUNC_TC001(char *data, int expflag)
{
    char *encode = data;
    uint32_t encodeLen = strlen(data);
    bool isPem = BSL_PEM_IsPemFormat(encode, encodeLen);
    ASSERT_TRUE(isPem == (bool)expflag);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_ISPEM_FUNC_TC002(void)
{
    char *aa = "aaaaaaaa";
    ASSERT_TRUE(BSL_PEM_IsPemFormat(NULL, 0) == false);
    ASSERT_TRUE(BSL_PEM_IsPemFormat(aa, strlen(aa)) == false);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_PARSE_FUNC_TC001(char *encode, char *head, char *tail, int expRes)
{
    BSL_PEM_Symbol sym = {head, tail};
    char *pemdata = encode;
    uint32_t len = strlen(encode);
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len;
    TestMemInit();
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&pemdata, &len, &sym, &asn1Encode, &asn1Len), expRes);
EXIT:
    BSL_SAL_Free(asn1Encode);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_PARSE_FUNC_TC002(void)
{
    BSL_PEM_Symbol sym = {BSL_PEM_EC_PRI_KEY_BEGIN_STR, BSL_PEM_EC_PRI_KEY_END_STR};
    char *pemdata = "-----BEGIN EC PRIVATE KEY-----\n"
                    "MHcCAQEEIAadtjyegBKXLH9xvNDvH24j7cn3PsaNSXSMIVmvJZM7oAoGCCqGSM49\n"
                    "AwEHoUQDQgAEPFKNDGyE7HES1hPd8mXydX4QunGvk37ISPOhXJStzxTt8sWdcEtV\n"
                    "gaXhArNx9Dz8pKIhoGcviy8xML3wPICv9Q==\n"
                    "-----END EC PRIVATE KEY-----\n"
                    "-----BEGIN EC PRIVATE KEY-----\n"
                    "MHcCAQEEIAadtjyegBKXLH9xvNDvH24j7cn3PsaNSXSMIVmvJZM7oAoGCCqGSM49\n"
                    "AwEHoUQDQgAEPFKNDGyE7HES1hPd8mXydX4QunGvk37ISPOhXJStzxTt8sWdcEtV\n"
                    "gaXhArNx9Dz8pKIhoGcviy8xML3wPICv9Q==\n"
                    "-----END EC PRIVATE KEY-----\n";
    int32_t len = strlen(pemdata);
    char *next = pemdata;
    uint32_t nextLen = len;
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len;
    TestMemInit();
    ASSERT_TRUE(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &sym, &asn1Encode, &asn1Len) == BSL_SUCCESS);
    BSL_SAL_Free(asn1Encode);
    ASSERT_TRUE(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &sym, &asn1Encode, &asn1Len) == BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(asn1Encode);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_PARSE_FUNC_TC003(void)
{
    BSL_PEM_Symbol sym = {BSL_PEM_EC_PRI_KEY_BEGIN_STR, BSL_PEM_EC_PRI_KEY_END_STR};
    char *pemdata = "-----BEGIN EC PRIVATE KEY-----END EC PRIVATE KEY------------------END-----\n";
    int32_t len = strlen(pemdata);
    char *next = pemdata;
    uint32_t nextLen = len;
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len;
    ASSERT_TRUE(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &sym, &asn1Encode, &asn1Len) == BSL_PEM_SYMBOL_NOT_FOUND);
EXIT:
    BSL_SAL_Free(asn1Encode);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_BINARY_INPUT_TC001(void)
{
    uint8_t binData[] = {0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
                         0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01};
    ASSERT_TRUE(BSL_PEM_IsPemFormat((char *)binData, sizeof(binData)) == false);

    BSL_PEM_Symbol symbol;
    const char *type = NULL;
    ASSERT_EQ(BSL_PEM_GetSymbolAndType((char *)binData, sizeof(binData), &symbol, &type), BSL_PEM_INVALID);

    char partialPem[] = {'-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N', ' ', 'C', 'E', 'R', 'T'};
    ASSERT_TRUE(BSL_PEM_IsPemFormat(partialPem, sizeof(partialPem)) == false);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_BINARY_INPUT_TC002(void)
{
    char validPem[] = "-----BEGIN CERTIFICATE-----\n"
                      "AAAA\n"
                      "-----END CERTIFICATE-----\n";
    uint32_t validLen = strlen(validPem);
    ASSERT_TRUE(BSL_PEM_IsPemFormat(validPem, validLen) == true);

    ASSERT_TRUE(BSL_PEM_IsPemFormat(validPem, 10) == false);
    ASSERT_TRUE(BSL_PEM_IsPemFormat(validPem, 28) == false);
    ASSERT_TRUE(BSL_PEM_IsPemFormat(validPem, 33) == false);

    BSL_PEM_Symbol symbol;
    const char *type = NULL;
    ASSERT_EQ(BSL_PEM_GetSymbolAndType(validPem, 10, &symbol, &type), BSL_PEM_INVALID);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_BINARY_INPUT_TC003(void)
{
    BSL_PEM_Symbol sym = {BSL_PEM_CERT_BEGIN_STR, BSL_PEM_CERT_END_STR};
    char pemdata[] = "-----BEGIN CERTIFICATE-----AAAA-----END CERTIFICATE-----\n";
    uint32_t fullLen = strlen(pemdata);

    char *next = pemdata;
    uint32_t nextLen = fullLen;
    char *realEncode = NULL;
    uint32_t realLen = 0;
    ASSERT_EQ(BSL_PEM_GetPemRealEncode(&next, &nextLen, &sym, &realEncode, &realLen), BSL_SUCCESS);
    ASSERT_TRUE(realLen == 4);

    next = pemdata;
    nextLen = 30;
    ASSERT_EQ(BSL_PEM_GetPemRealEncode(&next, &nextLen, &sym, &realEncode, &realLen), BSL_PEM_INVALID);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_BINARY_INPUT_TC004(void)
{
    ASSERT_TRUE(BSL_PEM_IsPemFormat(NULL, 0) == false);
    ASSERT_TRUE(BSL_PEM_IsPemFormat(NULL, 100) == false);

    char empty[] = "";
    ASSERT_TRUE(BSL_PEM_IsPemFormat(empty, 0) == false);

    char oneChar[] = "A";
    ASSERT_TRUE(BSL_PEM_IsPemFormat(oneChar, 1) == false);

    BSL_PEM_Symbol symbol;
    const char *type = NULL;
    ASSERT_EQ(BSL_PEM_GetSymbolAndType(NULL, 0, &symbol, &type), BSL_PEM_INVALID);
    ASSERT_EQ(BSL_PEM_GetSymbolAndType(empty, 0, &symbol, &type), BSL_PEM_INVALID);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_BINARY_INPUT_TC005(void)
{
    uint8_t binWithBegin[64];
    memset(binWithBegin, 0xFF, sizeof(binWithBegin));
    memcpy(binWithBegin, "-----BEGIN CERT-----", 20);
    ASSERT_TRUE(BSL_PEM_IsPemFormat((char *)binWithBegin, sizeof(binWithBegin)) == false);

    uint8_t binWithBoth[128];
    memset(binWithBoth, 0xAB, sizeof(binWithBoth));
    memcpy(binWithBoth, "-----BEGIN X-----", 17);
    memcpy(binWithBoth + 64, "-----END X-----", 15);
    ASSERT_TRUE(BSL_PEM_IsPemFormat((char *)binWithBoth, sizeof(binWithBoth)) == true);
    ASSERT_TRUE(BSL_PEM_IsPemFormat((char *)binWithBoth, 60) == false);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_BINARY_INPUT_TC006(void)
{
    uint8_t derCert[] = {
        0x30, 0x82, 0x02, 0x10, 0x30, 0x82, 0x01, 0xB9, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
        0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x45, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55,
        0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C
    };
    ASSERT_TRUE(BSL_PEM_IsPemFormat((char *)derCert, sizeof(derCert)) == false);

    BSL_PEM_Symbol symbol;
    const char *type = NULL;
    ASSERT_EQ(BSL_PEM_GetSymbolAndType((char *)derCert, sizeof(derCert), &symbol, &type), BSL_PEM_INVALID);

    BSL_PEM_Symbol certSym = {BSL_PEM_CERT_BEGIN_STR, BSL_PEM_CERT_END_STR};
    char *next = (char *)derCert;
    uint32_t nextLen = sizeof(derCert);
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len = 0;
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &certSym, &asn1Encode, &asn1Len), BSL_PEM_INVALID);
    ASSERT_TRUE(asn1Encode == NULL);
EXIT:
    BSL_SAL_Free(asn1Encode);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_BINARY_INPUT_TC007(void)
{
    uint8_t derKey[] = {
        0x30, 0x82, 0x01, 0x22, 0x02, 0x01, 0x00, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
        0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x01, 0x0C, 0x30, 0x82, 0x01, 0x08, 0x02, 0x82,
        0x01, 0x01, 0x00, 0xC4, 0xA1, 0xB2, 0xD3, 0xE4, 0xF5, 0x06, 0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C,
        0x7D, 0x8E, 0x9F, 0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C
    };
    ASSERT_TRUE(BSL_PEM_IsPemFormat((char *)derKey, sizeof(derKey)) == false);

    BSL_PEM_Symbol keySym = {BSL_PEM_RSA_PRI_KEY_BEGIN_STR, BSL_PEM_RSA_PRI_KEY_END_STR};
    char *next = (char *)derKey;
    uint32_t nextLen = sizeof(derKey);
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len = 0;
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &keySym, &asn1Encode, &asn1Len), BSL_PEM_INVALID);
    ASSERT_TRUE(asn1Encode == NULL);

    BSL_PEM_Symbol ecSym = {BSL_PEM_EC_PRI_KEY_BEGIN_STR, BSL_PEM_EC_PRI_KEY_END_STR};
    next = (char *)derKey;
    nextLen = sizeof(derKey);
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &ecSym, &asn1Encode, &asn1Len), BSL_PEM_INVALID);

    BSL_PEM_Symbol pkcs8Sym = {BSL_PEM_P8_PRI_KEY_BEGIN_STR, BSL_PEM_P8_PRI_KEY_END_STR};
    next = (char *)derKey;
    nextLen = sizeof(derKey);
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &pkcs8Sym, &asn1Encode, &asn1Len), BSL_PEM_INVALID);
EXIT:
    BSL_SAL_Free(asn1Encode);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_BINARY_INPUT_TC008(void)
{
    uint8_t tricky[80];
    memset(tricky, 0x2D, sizeof(tricky));
    tricky[10] = 'B'; tricky[11] = 'E'; tricky[12] = 'G'; tricky[13] = 'I'; tricky[14] = 'N';
    ASSERT_TRUE(BSL_PEM_IsPemFormat((char *)tricky, sizeof(tricky)) == false);

    BSL_PEM_Symbol symbol;
    const char *type = NULL;
    ASSERT_EQ(BSL_PEM_GetSymbolAndType((char *)tricky, sizeof(tricky), &symbol, &type), BSL_PEM_INVALID);

    BSL_PEM_Symbol certSym = {BSL_PEM_CERT_BEGIN_STR, BSL_PEM_CERT_END_STR};
    char *next = (char *)tricky;
    uint32_t nextLen = sizeof(tricky);
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len = 0;
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &certSym, &asn1Encode, &asn1Len), BSL_PEM_INVALID);
EXIT:
    BSL_SAL_Free(asn1Encode);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_BINARY_INPUT_TC009(void)
{
    char validPem[] = "-----BEGIN CERTIFICATE-----\n"
                      "AAAA\n"
                      "-----END CERTIFICATE-----\n";
    uint32_t fullLen = strlen(validPem);
    BSL_PEM_Symbol certSym = {BSL_PEM_CERT_BEGIN_STR, BSL_PEM_CERT_END_STR};

    char *next = validPem;
    uint32_t nextLen = fullLen;
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len = 0;
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &certSym, &asn1Encode, &asn1Len), BSL_SUCCESS);
    ASSERT_TRUE(asn1Encode != NULL);
    BSL_SAL_Free(asn1Encode);
    asn1Encode = NULL;

    next = validPem;
    nextLen = 30;
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &certSym, &asn1Encode, &asn1Len), BSL_PEM_INVALID);
    ASSERT_TRUE(asn1Encode == NULL);

    next = validPem;
    nextLen = 0;
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &certSym, &asn1Encode, &asn1Len), BSL_PEM_INVALID);
EXIT:
    BSL_SAL_Free(asn1Encode);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_BINARY_INPUT_TC010(void)
{
    char multiPem[] = "-----BEGIN CERTIFICATE-----\n"
                      "AAAA\n"
                      "-----END CERTIFICATE-----\n"
                      "-----BEGIN CERTIFICATE-----\n"
                      "BBBB\n"
                      "-----END CERTIFICATE-----\n";
    uint32_t fullLen = strlen(multiPem);
    BSL_PEM_Symbol certSym = {BSL_PEM_CERT_BEGIN_STR, BSL_PEM_CERT_END_STR};

    char *next = multiPem;
    uint32_t nextLen = fullLen;
    uint8_t *asn1First = NULL;
    uint32_t asn1FirstLen = 0;
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &certSym, &asn1First, &asn1FirstLen), BSL_SUCCESS);
    ASSERT_TRUE(asn1First != NULL);
    ASSERT_TRUE(nextLen > 0);

    uint8_t *asn1Second = NULL;
    uint32_t asn1SecondLen = 0;
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &certSym, &asn1Second, &asn1SecondLen), BSL_SUCCESS);
    ASSERT_TRUE(asn1Second != NULL);
EXIT:
    BSL_SAL_Free(asn1First);
    BSL_SAL_Free(asn1Second);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_REAL_CERT_PEM_TC001(char *pemPath)
{
    uint8_t *fileData = NULL;
    uint32_t fileLen = 0;
    ASSERT_EQ(BSL_SAL_ReadFile(pemPath, &fileData, &fileLen), BSL_SUCCESS);
    ASSERT_TRUE(fileData != NULL && fileLen > 0);

    ASSERT_TRUE(BSL_PEM_IsPemFormat((char *)fileData, fileLen) == true);

    BSL_PEM_Symbol symbol;
    const char *type = NULL;
    ASSERT_EQ(BSL_PEM_GetSymbolAndType((char *)fileData, fileLen, &symbol, &type), BSL_SUCCESS);

    char *next = (char *)fileData;
    uint32_t nextLen = fileLen;
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len = 0;
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &symbol, &asn1Encode, &asn1Len), BSL_SUCCESS);
    ASSERT_TRUE(asn1Encode != NULL && asn1Len > 0);
EXIT:
    BSL_SAL_Free(fileData);
    BSL_SAL_Free(asn1Encode);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_REAL_CERT_DER_TC001(char *derPath)
{
    uint8_t *fileData = NULL;
    uint32_t fileLen = 0;
    ASSERT_EQ(BSL_SAL_ReadFile(derPath, &fileData, &fileLen), BSL_SUCCESS);
    ASSERT_TRUE(fileData != NULL && fileLen > 0);

    ASSERT_TRUE(BSL_PEM_IsPemFormat((char *)fileData, fileLen) == false);

    BSL_PEM_Symbol symbol;
    const char *type = NULL;
    ASSERT_EQ(BSL_PEM_GetSymbolAndType((char *)fileData, fileLen, &symbol, &type), BSL_PEM_INVALID);

    BSL_PEM_Symbol certSym = {BSL_PEM_CERT_BEGIN_STR, BSL_PEM_CERT_END_STR};
    char *next = (char *)fileData;
    uint32_t nextLen = fileLen;
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len = 0;
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &certSym, &asn1Encode, &asn1Len), BSL_PEM_INVALID);
    ASSERT_TRUE(asn1Encode == NULL);
EXIT:
    BSL_SAL_Free(fileData);
    BSL_SAL_Free(asn1Encode);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_REAL_KEY_PEM_TC001(char *pemPath, char *beginStr, char *endStr)
{
    uint8_t *fileData = NULL;
    uint32_t fileLen = 0;
    ASSERT_EQ(BSL_SAL_ReadFile(pemPath, &fileData, &fileLen), BSL_SUCCESS);
    ASSERT_TRUE(fileData != NULL && fileLen > 0);

    ASSERT_TRUE(BSL_PEM_IsPemFormat((char *)fileData, fileLen) == true);

    BSL_PEM_Symbol symbol = {beginStr, endStr};
    char *next = (char *)fileData;
    uint32_t nextLen = fileLen;
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len = 0;
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &symbol, &asn1Encode, &asn1Len), BSL_SUCCESS);
    ASSERT_TRUE(asn1Encode != NULL && asn1Len > 0);
EXIT:
    BSL_SAL_Free(fileData);
    BSL_SAL_Free(asn1Encode);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_REAL_KEY_DER_TC001(char *derPath)
{
    uint8_t *fileData = NULL;
    uint32_t fileLen = 0;
    ASSERT_EQ(BSL_SAL_ReadFile(derPath, &fileData, &fileLen), BSL_SUCCESS);
    ASSERT_TRUE(fileData != NULL && fileLen > 0);

    ASSERT_TRUE(BSL_PEM_IsPemFormat((char *)fileData, fileLen) == false);

    BSL_PEM_Symbol symbol;
    const char *type = NULL;
    ASSERT_EQ(BSL_PEM_GetSymbolAndType((char *)fileData, fileLen, &symbol, &type), BSL_PEM_INVALID);

    BSL_PEM_Symbol keySym = {BSL_PEM_PRI_KEY_BEGIN_STR, BSL_PEM_PRI_KEY_END_STR};
    char *next = (char *)fileData;
    uint32_t nextLen = fileLen;
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len = 0;
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &keySym, &asn1Encode, &asn1Len), BSL_PEM_INVALID);
    ASSERT_TRUE(asn1Encode == NULL);
EXIT:
    BSL_SAL_Free(fileData);
    BSL_SAL_Free(asn1Encode);
    return;
}
/* END_CASE */

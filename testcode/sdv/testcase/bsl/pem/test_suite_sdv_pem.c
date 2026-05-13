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
#include "bsl_base64.h"
#include "bsl_sal.h"
#include "sal_file.h"
#include "bsl_pem_internal.h"
#include "stub_utils.h"

/* END_HEADER */

STUB_DEFINE_RET4(int32_t, BSL_BASE64_Encode, const uint8_t *, const uint32_t, char *, uint32_t *);

/**
 * @test SDV_BSL_PEM_ISPEM_FUNC_TC001
 * @spec  -
 * @title  PEM format detection for marker patterns
 * @precon  nan
 * @brief   1. Call BSL_PEM_IsPemFormat with the input buffer from the data file.
            2. Compare the return value with the expected PEM format flag.
 * @expect  1. The function returns the expected flag.
            2. The error stack remains empty.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_ISPEM_FUNC_TC002
 * @spec  -
 * @title  PEM format detection for null and non-PEM input
 * @precon  nan
 * @brief   1. Call BSL_PEM_IsPemFormat with NULL input.
            2. Call BSL_PEM_IsPemFormat with a plain text buffer.
 * @expect  1. The NULL input is not recognized as PEM.
            2. The plain text input is not recognized as PEM.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_PARSE_FUNC_TC001
 * @spec  -
 * @title  PEM decoding with configured begin and end symbols
 * @precon  nan
 * @brief   1. Build a BSL_PEM_Symbol from the begin and end strings.
            2. Call BSL_PEM_DecodePemToAsn1 with the encoded input.
            3. Compare the return value with the expected result.
 * @expect  1. Valid PEM data is decoded successfully.
            2. Missing or mismatched PEM symbols return the expected error code.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_PARSE_FUNC_TC002
 * @spec  -
 * @title  Sequential decoding of multiple PEM objects
 * @precon  nan
 * @brief   1. Prepare two consecutive EC private key PEM objects.
            2. Decode the first PEM object and update the remaining input pointer.
            3. Decode the second PEM object from the remaining input.
 * @expect  1. Both PEM objects are decoded successfully.
            2. The error stack remains empty.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_PARSE_FUNC_TC003
 * @spec  -
 * @title  PEM decoding when the end symbol is malformed
 * @precon  nan
 * @brief   1. Prepare PEM-like data with an invalid EC private key end marker.
            2. Call BSL_PEM_DecodePemToAsn1 with the EC private key symbol.
 * @expect  1. The decoder reports BSL_PEM_SYMBOL_NOT_FOUND.
 * @prior  Level 1
 * @auto  TRUE
 */
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

static int32_t STUB_BSL_BASE64_Encode_LargeOutput(const uint8_t *srcBuf, const uint32_t srcBufLen,
    char *dstBuf, uint32_t *dstBufLen)
{
    (void)srcBuf;
    (void)srcBufLen;
    (void)dstBuf;
    *dstBufLen = UINT32_MAX - 1;
    return BSL_SUCCESS;
}

/**
 * @test SDV_BSL_PEM_ENCODE_ASN1_OVERFLOW_TC001
 * @spec  -
 * @title  ASN.1 to PEM encoding length overflow checks
 * @precon  nan
 * @brief   1. Call BSL_PEM_EncodeAsn1ToPem with an ASN.1 length whose Base64 output exceeds uint32_t.
 *          2. Stub BSL_BASE64_Encode to report a near-uint32_t output length and encode a small ASN.1 buffer.
 * @expect  1. The encoder rejects the input before allocation.
 *          2. The PEM formatted length overflow is rejected.
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_PEM_ENCODE_ASN1_OVERFLOW_TC001(void)
{
    uint8_t asn1 = 0;
    char *encode = NULL;
    uint32_t encodeLen = 0;
    BSL_PEM_Symbol sym = {BSL_PEM_CERT_BEGIN_STR, BSL_PEM_CERT_END_STR};

    ASSERT_EQ(BSL_PEM_EncodeAsn1ToPem(&asn1, 0xC0000000U, &sym, &encode, &encodeLen), BSL_INVALID_ARG);
    ASSERT_TRUE(encode == NULL);
    TestErrClear();

    STUB_REPLACE(BSL_BASE64_Encode, STUB_BSL_BASE64_Encode_LargeOutput);
    ASSERT_EQ(BSL_PEM_EncodeAsn1ToPem(&asn1, sizeof(asn1), &sym, &encode, &encodeLen),
        BSL_BASE64_BUF_NOT_ENOUGH);
    ASSERT_TRUE(encode == NULL);

EXIT:
    STUB_RESTORE(BSL_BASE64_Encode);
    BSL_SAL_Free(encode);
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_PEM_BINARY_INPUT_TC001
 * @spec  -
 * @title  PEM APIs reject binary and incomplete marker input
 * @precon  nan
 * @brief   1. Call BSL_PEM_IsPemFormat with DER-like binary data.
            2. Call BSL_PEM_GetSymbolAndType with the same binary data.
            3. Call BSL_PEM_IsPemFormat with an incomplete BEGIN marker.
 * @expect  1. Binary data is not recognized as PEM.
            2. Symbol detection returns BSL_PEM_INVALID.
            3. The incomplete marker is not recognized as PEM.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_BINARY_INPUT_TC002
 * @spec  -
 * @title  PEM detection rejects truncated valid PEM buffers
 * @precon  nan
 * @brief   1. Verify that a complete certificate PEM buffer is recognized as PEM.
            2. Verify several truncated lengths of the same buffer.
            3. Call BSL_PEM_GetSymbolAndType with a truncated buffer.
 * @expect  1. The complete buffer is recognized as PEM.
            2. Truncated buffers are not recognized as PEM.
            3. Symbol detection returns BSL_PEM_INVALID for truncated input.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_BINARY_INPUT_TC003
 * @spec  -
 * @title  Extract real PEM payload with complete and truncated input
 * @precon  nan
 * @brief   1. Call BSL_PEM_GetPemRealEncode with a complete certificate PEM buffer.
            2. Verify the extracted payload length.
            3. Call BSL_PEM_GetPemRealEncode with a truncated buffer length.
 * @expect  1. The complete buffer returns BSL_SUCCESS.
            2. The payload length is correct.
            3. The truncated buffer returns BSL_PEM_INVALID.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_BINARY_INPUT_TC004
 * @spec  -
 * @title  PEM APIs reject null, empty, and minimal input
 * @precon  nan
 * @brief   1. Call BSL_PEM_IsPemFormat with NULL, empty, and one-character inputs.
            2. Call BSL_PEM_GetSymbolAndType with NULL and empty inputs.
 * @expect  1. All invalid inputs are not recognized as PEM.
            2. Symbol detection returns BSL_PEM_INVALID.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_BINARY_INPUT_TC005
 * @spec  -
 * @title  PEM detection on binary buffers containing marker fragments
 * @precon  nan
 * @brief   1. Create a binary buffer containing only a BEGIN-like marker.
            2. Create a binary buffer containing BEGIN and END marker strings.
            3. Verify detection with the full and truncated binary buffers.
 * @expect  1. The BEGIN-only buffer is not recognized as PEM.
            2. The full buffer containing both markers is recognized as PEM.
            3. The truncated buffer is not recognized as PEM.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_BINARY_INPUT_TC006
 * @spec  -
 * @title  Certificate PEM APIs reject DER certificate input
 * @precon  nan
 * @brief   1. Call BSL_PEM_IsPemFormat with DER certificate-like bytes.
            2. Call BSL_PEM_GetSymbolAndType with the DER buffer.
            3. Call BSL_PEM_DecodePemToAsn1 with certificate PEM symbols.
 * @expect  1. DER input is not recognized as PEM.
            2. Symbol detection returns BSL_PEM_INVALID.
            3. PEM decoding returns BSL_PEM_INVALID and does not allocate output.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_BINARY_INPUT_TC007
 * @spec  -
 * @title  Private key PEM decoders reject DER key input
 * @precon  nan
 * @brief   1. Verify that DER private key-like bytes are not recognized as PEM.
            2. Try to decode the buffer as RSA private key PEM.
            3. Try to decode the buffer as EC private key PEM.
            4. Try to decode the buffer as PKCS8 private key PEM.
 * @expect  1. DER input is not recognized as PEM.
            2. Each PEM decode attempt returns BSL_PEM_INVALID.
            3. No ASN.1 output is allocated.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_BINARY_INPUT_TC008
 * @spec  -
 * @title  PEM APIs reject malformed dash-heavy marker input
 * @precon  nan
 * @brief   1. Create a dash-filled buffer containing a BEGIN substring.
            2. Call BSL_PEM_IsPemFormat and BSL_PEM_GetSymbolAndType.
            3. Call BSL_PEM_DecodePemToAsn1 with certificate PEM symbols.
 * @expect  1. The malformed buffer is not recognized as PEM.
            2. Symbol detection returns BSL_PEM_INVALID.
            3. PEM decoding returns BSL_PEM_INVALID.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_BINARY_INPUT_TC009
 * @spec  -
 * @title  PEM decoding rejects truncated certificate buffers
 * @precon  nan
 * @brief   1. Decode a complete certificate PEM buffer.
            2. Decode the same buffer with a truncated length.
            3. Decode the same buffer with zero length.
 * @expect  1. The complete buffer is decoded successfully.
            2. Truncated and zero-length buffers return BSL_PEM_INVALID.
            3. Invalid decode attempts do not allocate ASN.1 output.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_BINARY_INPUT_TC010
 * @spec  -
 * @title  Sequential decoding of multiple certificate PEM buffers
 * @precon  nan
 * @brief   1. Prepare two consecutive certificate PEM objects.
            2. Decode the first object and verify that remaining input exists.
            3. Decode the second object from the updated input pointer.
 * @expect  1. Both PEM objects are decoded successfully.
            2. Both ASN.1 output buffers are allocated.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_MEMSTR_BOUNDARY_TC001
 * @spec  -
 * @title  Boundary coverage for the bounded PEM substring search
 * @precon  nan
 * @brief   1. Search PEM markers when the target marker starts at the last valid position.
            2. Search PEM markers when the search range length equals the marker length.
            3. Search PEM markers when the remaining search range is shorter than the marker length.
            4. Search PEM markers after false matches on the marker's first character.
            5. Search PEM markers in length-bounded buffers that contain NUL bytes or excluded trailing data.
            6. Search PEM markers with empty symbol strings.
 * @expect  1. Markers at the last valid position are found.
            2. Exact-length marker ranges are handled correctly.
            3. Short ranges and mismatched exact-length ranges are rejected.
            4. False first-character matches do not stop later valid matches.
            5. The provided buffer length, not a C-string terminator, bounds the search.
            6. Empty symbol strings are rejected.
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_PEM_MEMSTR_BOUNDARY_TC001(void)
{
    BSL_PEM_Symbol certSym = {BSL_PEM_CERT_BEGIN_STR, BSL_PEM_CERT_END_STR};
    char *realEncode = NULL;
    uint32_t realLen = 0;

    char tailAtLastPos[] = "-----BEGIN CERTIFICATE-----AAAA-----END CERTIFICATE-----";
    char *next = tailAtLastPos;
    uint32_t nextLen = strlen(tailAtLastPos);
    ASSERT_EQ(BSL_PEM_GetPemRealEncode(&next, &nextLen, &certSym, &realEncode, &realLen), BSL_SUCCESS);
    ASSERT_TRUE(realLen == 4);
    ASSERT_TRUE(nextLen == 0);

    char emptyPayloadPem[] = "-----BEGIN CERTIFICATE----------END CERTIFICATE-----";
    next = emptyPayloadPem;
    nextLen = strlen(emptyPayloadPem);
    ASSERT_EQ(BSL_PEM_GetPemRealEncode(&next, &nextLen, &certSym, &realEncode, &realLen), BSL_SUCCESS);
    ASSERT_TRUE(realLen == 0);
    ASSERT_TRUE(nextLen == 0);

    const char *beginStr = "-----BEGIN";
    uint32_t beginLen = strlen(beginStr);
    char beginAtEnd[32];
    memset(beginAtEnd, 'X', sizeof(beginAtEnd));
    memcpy(beginAtEnd + sizeof(beginAtEnd) - beginLen, beginStr, beginLen);
    ASSERT_TRUE(BSL_PEM_IsPemFormat(beginAtEnd, sizeof(beginAtEnd)) == false);

    char exactEndMismatch[] = "XXX-----BEGIN A----------ENX";
    ASSERT_TRUE(BSL_PEM_IsPemFormat(exactEndMismatch, strlen(exactEndMismatch)) == false);

    char falsePrefixThenBegin[] = "----X-----BEGIN A----------END A-----";
    ASSERT_TRUE(BSL_PEM_IsPemFormat(falsePrefixThenBegin, strlen(falsePrefixThenBegin)) == true);

    uint8_t binaryPem[40];
    memset(binaryPem, 0, sizeof(binaryPem));
    const char *shortPem = "-----BEGIN A----------END A-----";
    uint32_t shortPemLen = strlen(shortPem);
    memcpy(binaryPem + 3, shortPem, shortPemLen);
    ASSERT_TRUE(BSL_PEM_IsPemFormat((char *)binaryPem, shortPemLen + 3) == true);

    char excludedEnd[] = "-----BEGIN A-----AAAAAAAAAAA-----END A-----";
    uint32_t excludedLen = strlen("-----BEGIN A-----AAAAAAAAAAA");
    ASSERT_TRUE(BSL_PEM_IsPemFormat(excludedEnd, excludedLen) == false);

    BSL_PEM_Symbol emptyHeadSym = {"", BSL_PEM_CERT_END_STR};
    next = tailAtLastPos;
    nextLen = strlen(tailAtLastPos);
    ASSERT_EQ(BSL_PEM_GetPemRealEncode(&next, &nextLen, &emptyHeadSym, &realEncode, &realLen),
        BSL_PEM_SYMBOL_NOT_FOUND);

    BSL_PEM_Symbol emptyTailSym = {BSL_PEM_CERT_BEGIN_STR, ""};
    next = tailAtLastPos;
    nextLen = strlen(tailAtLastPos);
    ASSERT_EQ(BSL_PEM_GetPemRealEncode(&next, &nextLen, &emptyTailSym, &realEncode, &realLen),
        BSL_PEM_SYMBOL_NOT_FOUND);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_PEM_REAL_CERT_PEM_TC001
 * @spec  -
 * @title  Decode real certificate or CRL PEM files
 * @precon  nan
 * @brief   1. Read the PEM file from the configured path.
            2. Verify that the file is recognized as PEM.
            3. Detect the PEM symbol and type.
            4. Decode the PEM payload to ASN.1.
 * @expect  1. File reading succeeds.
            2. PEM format and symbol detection succeed.
            3. ASN.1 output is decoded successfully and is non-empty.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_REAL_CERT_DER_TC001
 * @spec  -
 * @title  Certificate or CRL DER files are rejected by PEM APIs
 * @precon  nan
 * @brief   1. Read the DER file from the configured path.
            2. Verify that the file is not recognized as PEM.
            3. Try to detect a PEM symbol and decode with certificate PEM symbols.
 * @expect  1. File reading succeeds.
            2. PEM format and symbol detection reject the DER input.
            3. PEM decoding returns BSL_PEM_INVALID and does not allocate output.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_REAL_KEY_PEM_TC001
 * @spec  -
 * @title  Decode real private key PEM files
 * @precon  nan
 * @brief   1. Read the private key PEM file from the configured path.
            2. Verify that the file is recognized as PEM.
            3. Decode the PEM payload with the configured key symbol.
 * @expect  1. File reading succeeds.
            2. The input is recognized as PEM.
            3. ASN.1 output is decoded successfully and is non-empty.
 * @prior  Level 1
 * @auto  TRUE
 */
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

/**
 * @test SDV_BSL_PEM_REAL_KEY_DER_TC001
 * @spec  -
 * @title  Private key DER files are rejected by PEM APIs
 * @precon  nan
 * @brief   1. Read the DER private key file from the configured path.
            2. Verify that the file is not recognized as PEM.
            3. Try to detect a PEM symbol and decode with private key PEM symbols.
 * @expect  1. File reading succeeds.
            2. PEM format and symbol detection reject the DER input.
            3. PEM decoding returns BSL_PEM_INVALID and does not allocate output.
 * @prior  Level 1
 * @auto  TRUE
 */
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

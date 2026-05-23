/* Copyright (c) 2025，Shandong University — School of Cyber Science and Technology
* Contributor: Mingzhang Sun
 * Instructor:  Weijia Wang
*/
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
#include <stdlib.h>
#include <string.h>
#include "bsl_uio.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "sal_file.h"
#include "uio_abstraction.h"
#include "app_opt.h"
#include "app_print.h"
#include "app_errno.h"
#include "app_function.h"
#include "app_asn1parse.h"

/* END_HEADER */

#define ASN1PARSE_MAX_ARGC (20)

/* Test data constants for ASN.1 structures */
#define ASN1_INTEGER_TAG_VALUE (0x02)
#define ASN1_LENGTH_ONE_BYTE (0x01)
#define ASN1_TEST_VALUE_ONE (0x01)
#define ASN1_ARRAY_INDEX_TAG (0)
#define ASN1_ARRAY_INDEX_LENGTH (1)
#define ASN1_ARRAY_INDEX_VALUE (2)
#define ASN1_SIMPLE_TLV_LENGTH (3)  /* Tag(1) + Length(1) + Value(1) */
#define ASN1_SHORT_HEADER_LEN (2)   /* Tag(1) + Length(1) */
#define ASN1_LONG_FORM_HEADER_LEN (4)  /* Tag(1) + Length header(3) */
#define TEST_BUFFER_SIZE (10)

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

static void PreProcArgs(char *args, int *argc, char **argv)
{
    uint32_t len = strlen(args);
    argv[(*argc)++] = args;
    for (uint32_t i = 0; i < len; i++) {
        if (args[i] == ' ') {
            args[i] = '\0';
            argv[(*argc)++] = args + i + 1;
        }
    }
}

/* INCLUDE_SOURCE ${HITLS_ROOT_PATH}/apps/src/app_print.c
 * ${HITLS_ROOT_PATH}/apps/src/app_asn1parse.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c */

/**
 * @test UT_HITLS_APP_ASN1PARSE_HELP_TC001
 * @title Test asn1parse -help option
 * @precon None
 * @brief Test that the -help option displays help information and returns success
 * @expect HITLS_APP_SUCCESS
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ASN1PARSE_HELP_TC001(void)
{
    char *argv[] = {"asn1parse", "-help"};
    int argc = 2;
    int ret;

    if (AppPrintErrorUioInit(stderr) != HITLS_APP_SUCCESS) {
        return;
    }
    
    ret = HITLS_Asn1Main(argc, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ASN1PARSE_NO_INPUT_TC001
 * @title Test asn1parse core parsing function with empty buffer
 * @precon None
 * @brief Test that parsing an empty buffer returns an error
 * @expect Error return (HITLS_APP_INVALID_ARG)
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ASN1PARSE_NO_INPUT_TC001(void)
{
    /* Test parsing empty buffer - should fail */
    uint8_t empty_buf[1] = {0};
    size_t emptyLen = 0;
    int ret;
    
    /* Don't initialize UIO since we're testing the core function directly */
    /* Call the parsing function with empty buffer */
    ret = AppAsn1ParseBuffer(empty_buf, emptyLen, 0, 1);
    
    /* Empty buffer should return error (HITLS_APP_INVALID_ARG) */
    ASSERT_EQ(ret, HITLS_APP_INVALID_ARG);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ASN1PARSE_PARSE_BUFFER_TC001
 * @title Test asn1parse buffer parsing function
 * @precon None
 * @brief Test parsing a simple ASN.1 SEQUENCE structure
 * @expect Success (return HITLS_APP_SUCCESS)
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ASN1PARSE_PARSE_BUFFER_TC001(void)
{
    /* ASN.1 SEQUENCE containing two INTEGERs */
    uint8_t buf[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    size_t bufLen = sizeof(buf);

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    int ret = AppAsn1ParseBuffer(buf, bufLen, 0, 1);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ASN1PARSE_PARSE_SEQUENCE_TC001
 * @title Test parsing ASN.1 SEQUENCE structure
 * @precon None
 * @brief Test parsing a SEQUENCE containing two INTEGERs
 * @expect Success (return HITLS_APP_SUCCESS)
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ASN1PARSE_PARSE_SEQUENCE_TC001(void)
{
    /* ASN.1 SEQUENCE containing two INTEGERs:
     * 30 06        SEQUENCE (length 6)
     *    02 01 01  INTEGER 1
     *    02 01 02  INTEGER 2
     */
    uint8_t buf[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    size_t bufLen = sizeof(buf);

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    int ret = AppAsn1ParseBuffer(buf, bufLen, 0, 1);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ASN1PARSE_PARSE_WITH_INDENT_TC001
 * @title Test parsing with indented display
 * @precon None
 * @brief Test parsing with -i option (indented display)
 * @expect Success (return HITLS_APP_SUCCESS)
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ASN1PARSE_PARSE_WITH_INDENT_TC001(void)
{
    /* Simple INTEGER to test indent display */
    uint8_t buf[] = {0x02, 0x01, 0x01};
    size_t bufLen = sizeof(buf);

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    int ret = AppAsn1ParseBuffer(buf, bufLen, 1, 1);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ASN1PARSE_PARSE_NOOUT_TC001
 * @title Test parsing with -noout option
 * @precon None
 * @brief Test parsing with value display suppressed
 * @expect Success (return HITLS_APP_SUCCESS)
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ASN1PARSE_PARSE_NOOUT_TC001(void)
{
    uint8_t buf[] = {0x02, 0x01, 0x2A};
    size_t bufLen = sizeof(buf);

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    /* show_indent=0, show_value=0 simulates -noout */
    int ret = AppAsn1ParseBuffer(buf, bufLen, 0, 0);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ASN1PARSE_GET_NODE_BYTES_TC001
 * @title Test extracting node bytes at offset
 * @precon None
 * @brief Test AppAsn1GetNodeBytes function to extract a sub-node
 * @expect Success and correct node extracted
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ASN1PARSE_GET_NODE_BYTES_TC001(void)
{
    /* ASN.1 SEQUENCE containing two INTEGERs:
     * offset 0: 30 06        SEQUENCE (length 6)
     * offset 2:    02 01 01  INTEGER 1
     * offset 5:    02 01 02  INTEGER 2
     */
    uint8_t buf[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    size_t bufLen = sizeof(buf);
    uint8_t *outBuf = NULL;
    size_t outLen = 0;

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    
    /* Extract node at offset 2 (first INTEGER) */
    int ret = AppAsn1GetNodeBytes(buf, bufLen, 2, &outBuf, &outLen);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);
    ASSERT_NE(outBuf, NULL);
    ASSERT_EQ(outLen, ASN1_SIMPLE_TLV_LENGTH); /* 02 01 01 = 3 bytes */
    ASSERT_EQ(outBuf[ASN1_ARRAY_INDEX_TAG], ASN1_INTEGER_TAG_VALUE); /* INTEGER tag */
    ASSERT_EQ(outBuf[ASN1_ARRAY_INDEX_LENGTH], ASN1_LENGTH_ONE_BYTE); /* length 1 */
    ASSERT_EQ(outBuf[ASN1_ARRAY_INDEX_VALUE], ASN1_TEST_VALUE_ONE); /* value 1 */

EXIT:
    BSL_SAL_FREE(outBuf);
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ASN1PARSE_COMPUTE_HEADER_LEN_TC001
 * @title Test computing header length of TLV structure
 * @precon None
 * @brief Test AppAsn1ComputeHeaderLenOfTlv function
 * @expect Success and correct header length
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ASN1PARSE_COMPUTE_HEADER_LEN_TC001(void)
{
    /* Simple INTEGER: 02 01 2A
     * Tag: 02 (1 byte)
     * Length: 01 (1 byte)
     * Value: 2A (1 byte)
     * Header length = 2
     */
    uint8_t buf[] = {0x02, 0x01, 0x2A};
    size_t bufLen = sizeof(buf);
    size_t hdrLen = 0;

    int ret = AppAsn1ComputeHeaderLenOfTlv(buf, bufLen, &hdrLen);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);
    ASSERT_EQ(hdrLen, ASN1_SHORT_HEADER_LEN); /* Tag (1 byte) + Length (1 byte) */

EXIT:
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ASN1PARSE_COMPUTE_HEADER_LEN_TC002
 * @title Test computing header length with long-form length
 * @precon None
 * @brief Test header length calculation for long-form length encoding
 * @expect Success and correct header length
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ASN1PARSE_COMPUTE_HEADER_LEN_TC002(void)
{
    /* SEQUENCE with long-form length: 30 82 00 10 ...
     * Tag: 30 (1 byte)
     * Length: 82 00 10 (3 bytes, encoding length 16)
     * Header length = 4
     */
    uint8_t buf[] = {0x30, 0x82, 0x00, 0x10, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02,
                     0x02, 0x01, 0x03, 0x02, 0x01, 0x04, 0x02, 0x01, 0x05, 0x02};
    size_t bufLen = sizeof(buf);
    size_t hdrLen = 0;

    int ret = AppAsn1ComputeHeaderLenOfTlv(buf, bufLen, &hdrLen);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);
    ASSERT_EQ(hdrLen, ASN1_LONG_FORM_HEADER_LEN); /* Tag (1 byte) + Length field (3 bytes) */

EXIT:
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ASN1PARSE_PARSE_OID_TC001
 * @title Test parsing ASN.1 OBJECT IDENTIFIER
 * @precon None
 * @brief Test parsing an OID structure
 * @expect Success (return HITLS_APP_SUCCESS)
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ASN1PARSE_PARSE_OID_TC001(void)
{
    /* ASN.1 OID for rsaEncryption (1.2.840.113549.1.1.1)
     * 06 09 2A 86 48 86 F7 0D 01 01 01
     */
    uint8_t buf[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
    size_t bufLen = sizeof(buf);

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    int ret = AppAsn1ParseBuffer(buf, bufLen, 0, 1);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ASN1PARSE_PARSE_OCTET_STRING_TC001
 * @title Test parsing ASN.1 OCTET STRING
 * @precon None
 * @brief Test parsing an OCTET STRING structure
 * @expect Success (return HITLS_APP_SUCCESS)
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ASN1PARSE_PARSE_OCTET_STRING_TC001(void)
{
    /* ASN.1 OCTET STRING: 04 05 "Hello"
     * 04 05 48 65 6C 6C 6F
     */
    uint8_t buf[] = {0x04, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F};
    size_t bufLen = sizeof(buf);

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    int ret = AppAsn1ParseBuffer(buf, bufLen, 0, 1);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ASN1PARSE_INVALID_BUFFER_TC001
 * @title Test parsing with invalid buffer
 * @precon None
 * @brief Test that parsing fails gracefully with NULL or empty buffer
 * @expect Failure (return HITLS_APP_INVALID_ARG)
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ASN1PARSE_INVALID_BUFFER_TC001(void)
{
    int ret;

    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    
    /* Test NULL buffer */
    ret = AppAsn1ParseBuffer(NULL, TEST_BUFFER_SIZE, 0, 1);
    ASSERT_EQ(ret, HITLS_APP_INVALID_ARG);

    /* Test zero-length buffer */
    uint8_t buf[] = {0x02, 0x01, 0x2A};
    ret = AppAsn1ParseBuffer(buf, 0, 0, 1);
    ASSERT_EQ(ret, HITLS_APP_INVALID_ARG);

EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ASN1PARSE_INVALID_OPTIONS_TC001
 * @title Test asn1parse with invalid options
 * @precon None
 * @brief Test that invalid command-line options are handled properly
 * @expect HITLS_APP_OPT_ERR (-1)
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ASN1PARSE_INVALID_OPTIONS_TC001(void)
{
    char *opts = "asn1parse -invalid-option";
    int argc = 0;
    char *argv[ASN1PARSE_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    ASSERT_NE(tmp, NULL);
    
    PreProcArgs(tmp, &argc, argv);
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    
    int ret = HITLS_Asn1Main(argc, argv);
    /* Invalid option returns HITLS_APP_OPT_ERR which is -1 or HITLS_APP_OPT_UNKOWN */
    ASSERT_TRUE(ret == HITLS_APP_OPT_ERR || ret == HITLS_APP_OPT_UNKOWN);

EXIT:
    AppPrintErrorUioUnInit();
    BSL_SAL_Free(tmp);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_ASN1PARSE_NEGATIVE_STRPARSE_TC001
 * @title Test asn1parse with invalid -strparse offset
 * @precon None
 * @brief Test that negative offset for -strparse is rejected
 * @expect HITLS_APP_OPT_ERR or HITLS_APP_OPT_UNKOWN
 */
/* BEGIN_CASE */
void UT_HITLS_APP_ASN1PARSE_NEGATIVE_STRPARSE_TC001(void)
{
    char *opts = "asn1parse -in dummy.pem -strparse -5";
    int argc = 0;
    char *argv[ASN1PARSE_MAX_ARGC] = {0};
    char *tmp = strdup(opts);
    ASSERT_NE(tmp, NULL);
    
    PreProcArgs(tmp, &argc, argv);
    if (AppPrintErrorUioInit(stderr) != HITLS_APP_SUCCESS) {
        BSL_SAL_Free(tmp);
        return;
    }
    
    int ret = HITLS_Asn1Main(argc, argv);
    /* Negative number is treated as invalid option, returns -1 or UNKOWN */
    ASSERT_TRUE(ret == HITLS_APP_OPT_ERR || ret == HITLS_APP_OPT_UNKOWN);

EXIT:
    AppPrintErrorUioUnInit();
    BSL_SAL_Free(tmp);
    return;
}
/* END_CASE */

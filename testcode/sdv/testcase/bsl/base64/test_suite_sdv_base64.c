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
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_base64.h"
#include "bsl_uio.h"
#include "bsl_base64.h"

/* END_HEADER */
static const uint8_t src_01[] = "123";
static const char encodeResult_01[] = "MTIz";

static const uint8_t src_02[] = "a";
static const char encodeResult_02[] = "YQ==";

static const uint8_t src_03[] = " ";
static const char encodeResult_03[] = "IA==";

static const uint8_t src_04[] = "\r";
static const char encodeResult_04[] = "DQ==";

static const uint8_t src_05[] = "\n";
static const char encodeResult_05[] = "Cg==";

static const uint8_t src_06[] = "\r\n";
static const char encodeResult_06[] = "DQo=";

static const uint8_t src_07[] = "bas64eVBFH2 46 JF   \n  3274jg891    \n  12974";
static const char encodeResult_07[] = "YmFzNjRlVkJGSDIgNDYgSkYgICAKICAzMjc0amc4OTEgICAgCiAgMTI5NzQ=";

static const uint8_t src_08[] = "EIR234hdi234 0  idd3     12EH9kfhwu0914l   39u14109u4        8214 klhr184yu h    "
                                "0923174 hfweh7e0124W  R2342E\nWF9\niofh392   281h236891FHWY1990hf732";
static const char encodeResult_08[] =
    "RUlSMjM0aGRpMjM0IDAgIGlkZDMgICAgIDEyRUg5a2Zod3UwOTE0bCAgIDM5dTE0MTA5dTQgICAgICAgIDgyMTQga2xocjE4NHl1IGggICAgMDkyMz"
    "E3NCBoZndlaDdlMDEyNFcgIFIyMzQyRQpXRjkKaW9maDM5MiAgIDI4MWgyMzY4OTFGSFdZMTk5MGhmNzMy";
static const char encodeResult_08_withNL[] =
    "RUlSMjM0aGRpMjM0IDAgIGlkZDMgICAgIDEyRUg5a2Zod3UwOTE0bCAgIDM5dTE0\nMTA5dTQgICAgICAgIDgyMTQga2xocjE4NHl1IGggICAgMDky"
    "MzE3NCBoZndlaDdl\nMDEyNFcgIFIyMzQyRQpXRjkKaW9maDM5MiAgIDI4MWgyMzY4OTFGSFdZMTk5MGhm\nNzMy\n";
static const char encodeResult_09[] =
    "YUVJUjIzNGhkaTIzNCAwICBpZGQzICAgICAxMkVIOWtmaHd1MDkxNGwgICAzOXUx\nNDEwOXU0ICAgICAgICA4MjE0IGtsaHIxODR5dSBoICAgIDA5"
    "MjMxNzQgaGZ3ZWg3\nZTAxMjRXICBSMjM0MkUKV0Y5CmlvZmgzOTIgICAyODFoMjM2ODkxRkhXWTE5OTBo\nZjczMmJhczY0ZVZCRkgyIDQ2IEpGIC"
    "AgCiAgMzI3NGpnODkxICAgIAogIDEyOTc0\n";
static const uint8_t src_09[] = "Base64编码和解码测试ChineseVersion";
static const uint8_t src_10[] = "ZnUzeWU4R0hFNzEzMjY0RU5EUUlZSFI4OWhoODlURjczVUhGRElVSDMyOThZZk5FMzE4aGQyODNlajMwNEg0";
static const uint8_t src_11[] =
    "aEVXVURKRFE5MkVVMTkwMzcxMzBSSkkyM1VSMDkyMzIzNEQyMUUxMjhZM0UxODI5NEVZM05SRDMyUjI0MjM0RkdG";
static const uint8_t src_12[] =
    "ZnUzeWU4R0hFNzEzMjY0RU5EUUlZSFI4OWhoODlURjczVUhGRElVSDMyOThZZk5FMzE4aGQyODNlajMwNEg0emY=";
static const uint8_t src_13[] = "fu3ye8GHE713264ENDQIYHR89hh89TF73UHFDIUH3298Yf";
static const uint8_t src_14[] = "fu3ye8GHE713264ENDQIYHR89hh89TF73UHFDIUH3298Yf2";
static const uint8_t src_15[] = "fu3ye8GHE713264ENDQIYHR89hh89TF73UHFDIUH3298Yf2k";
static const uint8_t src_16[] = "fu3ye8GHE713264ENDQIYHR89hh89TF73UHFDIUH3298YfNE318hd283ej304H";
static const uint8_t src_17[] = "fu3ye8GHE713264ENDQIYHR89hh89TF73UHFDIUH3298YfNE318hd283ej304Hf";
static const uint8_t src_18[] = "fu3ye8GHE713264ENDQIYHR89hh89TF73UHFDIUH3298YfNE318hd283ej304Hfe";
static const uint8_t src_19[] =
    "HD13fdwCr23r2t4UI3QW1t2vs23F432R1FChfu3ye8GHE713264ENDQIYHR89hh89TF73UHFDIUH3298Yf23hoifdh3f9832yf3ihnfdkJM32RE832"
    "URDOjdjOWIHFD9832RDJkwmdcOJD38E12U38RDHi3ndewifdh3uiry298398r3843nhrdkncihfhHR2398RE2RFQ32";
typedef struct {
    const uint8_t *src;
    const uint32_t srcLen;
    const char *encodeResult;
    const uint32_t encodeResultLen;
} BASE64_TEST_DATA;

static const BASE64_TEST_DATA testData[] = {
    {
        .src = src_01,
        .srcLen = (const uint32_t)sizeof(src_01) - 1,
        .encodeResult = encodeResult_01,
        .encodeResultLen = (const uint32_t)sizeof(encodeResult_01) - 1,
    },
    {
        .src = src_02,
        .srcLen = (const uint32_t)sizeof(src_02) - 1,
        .encodeResult = encodeResult_02,
        .encodeResultLen = (const uint32_t)sizeof(encodeResult_02) - 1,
    },
    {
        .src = src_03,
        .srcLen = (const uint32_t)sizeof(src_03) - 1,
        .encodeResult = encodeResult_03,
        .encodeResultLen = (const uint32_t)sizeof(encodeResult_03) - 1,
    },
    {
        .src = src_04,
        .srcLen = (const uint32_t)sizeof(src_04) - 1,
        .encodeResult = encodeResult_04,
        .encodeResultLen = (const uint32_t)sizeof(encodeResult_04) - 1,
    },
    {
        .src = src_05,
        .srcLen = (const uint32_t)sizeof(src_05) - 1,
        .encodeResult = encodeResult_05,
        .encodeResultLen = (const uint32_t)sizeof(encodeResult_05) - 1,
    },
    {
        .src = src_06,
        .srcLen = (const uint32_t)sizeof(src_06) - 1,
        .encodeResult = encodeResult_06,
        .encodeResultLen = (const uint32_t)sizeof(encodeResult_06) - 1,
    },
    {
        .src = src_07,
        .srcLen = (const uint32_t)sizeof(src_07) - 1,
        .encodeResult = encodeResult_07,
        .encodeResultLen = (const uint32_t)sizeof(encodeResult_07) - 1,
    },
    {
        .src = src_08,
        .srcLen = (const uint32_t)sizeof(src_08) - 1,
        .encodeResult = encodeResult_08,
        .encodeResultLen = (const uint32_t)sizeof(encodeResult_08) - 1,
    },
    {
        .src = src_09,
        .srcLen = (const uint32_t)sizeof(src_09) - 1,
        .encodeResult = NULL,
        .encodeResultLen = 0,
    },
    {
        .src = src_10,
        .srcLen = (const uint32_t)sizeof(src_10) - 1,
        .encodeResult = NULL,
        .encodeResultLen = 0,
    },
    {
        .src = src_11,
        .srcLen = (const uint32_t)sizeof(src_11) - 1,
        .encodeResult = NULL,
        .encodeResultLen = 0,
    },
    {
        .src = src_12,
        .srcLen = (const uint32_t)sizeof(src_12) - 1,
        .encodeResult = NULL,
        .encodeResultLen = 0,
    },
    {
        .src = src_13,
        .srcLen = (const uint32_t)sizeof(src_13) - 1,
        .encodeResult = NULL,
        .encodeResultLen = 0,
    },
    {
        .src = src_14,
        .srcLen = (const uint32_t)sizeof(src_14) - 1,
        .encodeResult = NULL,
        .encodeResultLen = 0,
    },
    {
        .src = src_15,
        .srcLen = (const uint32_t)sizeof(src_15) - 1,
        .encodeResult = NULL,
        .encodeResultLen = 0,
    },
    {
        .src = src_16,
        .srcLen = (const uint32_t)sizeof(src_16) - 1,
        .encodeResult = NULL,
        .encodeResultLen = 0,
    },
    {
        .src = src_17,
        .srcLen = (const uint32_t)sizeof(src_17) - 1,
        .encodeResult = NULL,
        .encodeResultLen = 0,
    },
    {
        .src = src_18,
        .srcLen = (const uint32_t)sizeof(src_18) - 1,
        .encodeResult = NULL,
        .encodeResultLen = 0,
    },
    {
        .src = src_19,
        .srcLen = (const uint32_t)sizeof(src_19) - 1,
        .encodeResult = NULL,
        .encodeResultLen = 0,
    },
};

static const int32_t testCnt = sizeof(testData) / sizeof(testData[0]);

/**
 * @test SDV_BSL_BASE64_FUNC_TC001
 * @spec  -
 * @title  Block coding/decoding test
 * @precon  nan
 * @brief   1. Call BSL_Base64Encode
            2. Check whether the encoded result is correct.
            3. Call BSL_Base64Decode
            4. Check whether the decoded buffer is the same as the original buffer.
            5. Check whether the decoded buffer length is the same as the original buffer length.
            
 * @expect  1. BSL_SUCCESS
            2. same
            3. BSL_SUCCESS
            4. same
            5. same
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_BASE64_FUNC_TC001(void)
{
    TestMemInit();
    for (int32_t i = 0; i < 7; i++) {
        const uint8_t *srcBuf = testData[i].src;
        const uint32_t srcLen = testData[i].srcLen;

        uint32_t encodeBufLen = HITLS_BASE64_ENCODE_LENGTH(srcLen);
        char encodeBuf[encodeBufLen];
        uint32_t decodeBufLen = HITLS_BASE64_DECODE_LENGTH(encodeBufLen);
        uint8_t decodeBuf[decodeBufLen];

        ASSERT_TRUE(BSL_BASE64_Encode(srcBuf, srcLen, encodeBuf, &encodeBufLen) == BSL_SUCCESS);
        ASSERT_TRUE(memcmp((const char *)encodeBuf, testData[i].encodeResult, testData[i].encodeResultLen) == 0);
        ASSERT_TRUE(encodeBufLen == testData[i].encodeResultLen);

        ASSERT_TRUE(BSL_BASE64_Decode((const char *)encodeBuf, testData[i].encodeResultLen, decodeBuf,
            &decodeBufLen) == BSL_SUCCESS);
        ASSERT_TRUE(memcmp((const uint8_t *)decodeBuf, srcBuf, srcLen) == 0);
        ASSERT_TRUE(decodeBufLen == srcLen);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_BASE64_FUNC_TC002
 * @spec  -
 * @title  Encoding and decoding test for short input streams without line breaks
 * @precon  nan
 * @brief   1. Call BSL_Base64EncodeInit
            2. Call BSL_Base64EncodeUpdate
            3. Call BSL_Base64EncodeFinal
            4. Check whether the encoded result is correct.
            5. Check whether the encoded length is correct.
            6. Call BSL_Base64DecodeInit
            7. Call BSL_Base64DecodeUpdate
            8. Call BSL_Base64DecodeFinal
            9. Check whether the decoded buffer is the same as the original buffer.
            10. Check whether the decoded buffer length is the same as the original buffer length.
            
 * @expect  1. BSL_SUCCESS
            2. BSL_SUCCESS
            3. handling the tail
            4. same
            5. same
            6. BSL_SUCCESS
            7. BSL_SUCCESS
            8. BSL_SUCCESS
            9. same
            10. same
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_BASE64_FUNC_TC002(void)
{
    for (int32_t i = 0; i < 6; i++) {
        const uint8_t *srcBuf = testData[i].src;
        const uint32_t srcLen = testData[i].srcLen;

        uint32_t encodeBufLen = HITLS_BASE64_ENCODE_LENGTH(srcLen);
        char *encodeBuf = malloc(encodeBufLen);
        uint32_t decodeBufLen = HITLS_BASE64_DECODE_LENGTH(encodeBufLen);
        uint8_t *decodeBuf = malloc(HITLS_BASE64_DECODE_LENGTH(encodeBufLen));

        uint32_t tmpLen = encodeBufLen;
        uint32_t total = 0;

        BSL_Base64Ctx *ctx = BSL_BASE64_CtxNew();
        ASSERT_TRUE(encodeBuf != NULL);
        ASSERT_TRUE(decodeBuf != NULL);
        BSL_BASE64_EncodeInit(ctx);
        BSL_BASE64_SetFlags(ctx, BSL_BASE64_FLAGS_NO_NEWLINE);
        ASSERT_TRUE(BSL_BASE64_EncodeUpdate(ctx, srcBuf, srcLen, encodeBuf, &tmpLen) == BSL_SUCCESS);
        encodeBufLen -= tmpLen;
        total += tmpLen;
        tmpLen = encodeBufLen;
        ASSERT_TRUE(BSL_BASE64_EncodeFinal(ctx, encodeBuf + total, &tmpLen) == BSL_SUCCESS);
        total += tmpLen;

        ASSERT_TRUE(total == testData[i].encodeResultLen);
        ASSERT_TRUE(memcmp((const char *)encodeBuf, testData[i].encodeResult, testData[i].encodeResultLen) == 0);

        BSL_BASE64_CtxClear(ctx);

        tmpLen = decodeBufLen;
        BSL_BASE64_DecodeInit(ctx);
        ASSERT_TRUE(BSL_BASE64_DecodeUpdate(ctx, encodeBuf, (const uint32_t)total, decodeBuf, &tmpLen) == BSL_SUCCESS);
        total = 0;
        decodeBufLen -= tmpLen;
        total += tmpLen;
        tmpLen = decodeBufLen;
        ASSERT_TRUE(BSL_BASE64_DecodeFinal(ctx, decodeBuf + total, &tmpLen) == BSL_SUCCESS);
        total += tmpLen;
        ASSERT_TRUE(total == srcLen);
        ASSERT_TRUE(memcmp((const uint8_t *)decodeBuf, srcBuf, srcLen) == 0);

        free(encodeBuf);
        free(decodeBuf);
        BSL_BASE64_CtxFree(ctx);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_BASE64_FUNC_TC003
 * @spec  -
 * @title  Encoding test for long input streams that require line breaks
 * @precon  nan
 * @brief   1. Call BSL_Base64EncodeInit
            2. Call BSL_Base64EncodeUpdate
            3. Call BSL_Base64EncodeFinal
            4. Check whether the encoded result is correct.
            5. Check whether the encoded length is correct.
 * @expect  1. BSL_SUCCESS
            2. BSL_SUCCESS
            3. handling the tail
            4. same
            5. same
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_BASE64_FUNC_TC003(void)
{
    const uint8_t *srcBuf = src_08;
    const uint32_t srcLen = (const uint32_t)sizeof(src_08) - 1;

    uint32_t encodeBufLen = HITLS_BASE64_ENCODE_LENGTH(srcLen);
    char *encodeBuf = malloc(encodeBufLen);
    uint32_t tmpLen = encodeBufLen;
    uint32_t total = 0;

    BSL_Base64Ctx *ctx = BSL_BASE64_CtxNew();
    ASSERT_TRUE(encodeBuf != NULL);
    BSL_BASE64_EncodeInit(ctx);
    ASSERT_TRUE(BSL_BASE64_EncodeUpdate(ctx, srcBuf, srcLen, encodeBuf, &tmpLen) == BSL_SUCCESS);
    encodeBufLen -= tmpLen;
    total += tmpLen;
    tmpLen = encodeBufLen;
    // encode and check tail for consistency, encodeBuf tail has\n
    ASSERT_TRUE(BSL_BASE64_EncodeFinal(ctx, encodeBuf + total, &tmpLen) == BSL_SUCCESS);
    total += tmpLen;

    ASSERT_TRUE(total == sizeof(encodeResult_08_withNL) - 1);
    ASSERT_TRUE(memcmp((const char *)encodeBuf, encodeResult_08_withNL, total) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    free(encodeBuf);
    BSL_BASE64_CtxFree(ctx);
}
/* END_CASE */

/**
 * @test SDV_BSL_BASE64_FUNC_TC004
 * @spec  -
 * @title  Decoding test for long input streams that require line breaks
 * @precon  nan
 * @brief   1. Call BSL_Base64DecodeInit
            2. Call BSL_Base64DecodeUpdate
            3. Call BSL_Base64DecodeFinal
            4. Check whether the decoded buffer is the same as the original buffer.
            5. Check whether the decoded buffer length is the same as the original buffer length.
 * @expect  1. BSL_SUCCESS
            2. BSL_SUCCESS
            3. BSL_SUCCESS
            4. same
            5. same
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_BASE64_FUNC_TC004(void)
{
    const uint8_t *srcBuf = src_08;
    const uint32_t srcLen = (const uint32_t)sizeof(src_08) - 1;
    uint32_t encodeBufLen = sizeof(encodeResult_08_withNL) - 1;

    uint32_t decodeBufLen = HITLS_BASE64_DECODE_LENGTH(encodeBufLen);
    uint8_t *decodeBuf = malloc(decodeBufLen);
    uint32_t tmpLen = decodeBufLen;
    uint32_t total = 0;

    BSL_Base64Ctx *ctx = BSL_BASE64_CtxNew();
    ASSERT_TRUE(decodeBuf != NULL);
    BSL_BASE64_DecodeInit(ctx);
    ASSERT_TRUE(BSL_BASE64_DecodeUpdate(ctx, encodeResult_08_withNL, encodeBufLen, decodeBuf, &tmpLen) == BSL_SUCCESS);
    encodeBufLen -= tmpLen;
    total += tmpLen;
    tmpLen = encodeBufLen;
    ASSERT_TRUE(BSL_BASE64_DecodeFinal(ctx, decodeBuf + total, &tmpLen) == BSL_SUCCESS);
    total += tmpLen;

    ASSERT_TRUE(total == srcLen);
    ASSERT_TRUE(memcmp((const uint8_t *)decodeBuf, srcBuf, total) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    free(decodeBuf);
    BSL_BASE64_CtxFree(ctx);
}
/* END_CASE */

/**
 * @test SDV_BSL_BASE64_FUNC_TC005
 * @spec  -
 * @title  Encoding and decoding test of the block that generates errors
 * @precon  nan
 * @brief   1. Call BSL_Base64Encode
            2. Check whether the encoded result is correct.
            3. Call BSL_Base64Decode
            4. Check whether the decoded buffer is the same as the original buffer.
            5. Check whether the decoded buffer length is the same as the original buffer length.
            
 * @expect  1. BSL_SUCCESS
            2. same
            3. BSL_SUCCESS
            4. same
            5. same
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_BASE64_FUNC_TC005(void)
{
    const char illEncodeResult[] = "MT-1";
    uint8_t decodeBuf[4] = {0};
    uint32_t decodeBufLen = HITLS_BASE64_DECODE_LENGTH(4);
    ASSERT_TRUE(BSL_BASE64_Decode(illEncodeResult, 4, decodeBuf, &decodeBufLen) != BSL_SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_BASE64_FUNC_TC006
 * @spec  -
 * @title  Stream Decoding Test with Errors
 * @precon  nan
 * @brief   1. Call BSL_Base64DecodeInit
            2. Call BSL_Base64DecodeUpdate
            3. Call BSL_Base64DecodeUpdate
            
 * @expect  1. BSL_SUCCESS
            2. data after padding error
            3. EOF Error in Middle of Block
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_BASE64_FUNC_TC006(void)
{
    const char illEncodeResult_1[] = "MT=1";
    const char illEncodeResult_2[] = "MT-1";
    const char illEncodeResult_3[] = "MT#1";
    uint32_t decodeBufLen = HITLS_BASE64_DECODE_LENGTH(4);
    uint8_t *decodeBuf = malloc(decodeBufLen);
    ASSERT_TRUE(decodeBuf != NULL);
    BSL_Base64Ctx *ctx = BSL_BASE64_CtxNew();
    BSL_BASE64_SetFlags(ctx, BSL_BASE64_FLAGS_NO_NEWLINE);

    BSL_BASE64_DecodeInit(ctx);
    ASSERT_TRUE(BSL_BASE64_DecodeUpdate(ctx, illEncodeResult_1, sizeof(illEncodeResult_1),
        decodeBuf, &decodeBufLen) == BSL_BASE64_DATA_AFTER_PADDING);

    BSL_BASE64_CtxClear(ctx);
    BSL_BASE64_DecodeInit(ctx);
    /* If the BSL interface is not invoked to parse the PEM file, the returned value is an error code. */
    ASSERT_TRUE(BSL_BASE64_DecodeUpdate(ctx, illEncodeResult_2, sizeof(illEncodeResult_2),
        decodeBuf, &decodeBufLen) == BSL_BASE64_HEADER);

    BSL_BASE64_CtxClear(ctx);
    BSL_BASE64_DecodeInit(ctx);
    ASSERT_TRUE(BSL_BASE64_DecodeUpdate(ctx, illEncodeResult_3, sizeof(illEncodeResult_3),
        decodeBuf, &decodeBufLen) == BSL_INVALID_ARG);
EXIT:
    free(decodeBuf);
    BSL_BASE64_CtxFree(ctx);
}
/* END_CASE */

/**
 * @test SDV_BSL_BASE64_FUNC_TC007
 * @spec  -
 * @title  Empty input test
 * @precon  nan
 * @brief   1. Call BSL_Base64Encode
            2. Call BSL_Base64Encode
            3. Call BSL_Base64Decode
            4. Call BSL_Base64Decode
            5. Call BSL_Base64EncodeUpdate
            6. Call BSL_Base64EncodeFinal
            7. Call BSL_Base64DecodeUpdate
            8. Call BSL_Base64DecodeFinal
            
 * @expect  1. BSL_NULL_INPUT
            2. dstBufLen is insufficient:BSL_BASE64_BUF_NOT_ENOUGH
            3. BSL_NULL_INPUT
            4. dstBufLen is insufficient:BSL_BASE64_BUF_NOT_ENOUGH
            5. BSL_NULL_INPUT
            6. BSL_SUCCESS
            7. BSL_NULL_INPUT
            8. BSL_SUCCESS
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_BASE64_FUNC_TC007(void)
{
    uint32_t zeroLen = 0;
    const uint32_t srcLen = (const uint32_t)sizeof(src_01);

    uint32_t encodeBufLen = HITLS_BASE64_ENCODE_LENGTH(srcLen);
    char *encodeBuf = malloc(encodeBufLen);
    uint32_t decodeBufLen = HITLS_BASE64_DECODE_LENGTH(encodeBufLen);
    uint8_t *decodeBuf = malloc(decodeBufLen);
    ASSERT_TRUE(encodeBuf != NULL);
    ASSERT_TRUE(decodeBuf != NULL);
    /* Block codec empty input test */
    ASSERT_TRUE(BSL_BASE64_Encode(NULL, zeroLen, encodeBuf, &encodeBufLen) == BSL_NULL_INPUT);
    ASSERT_TRUE(BSL_BASE64_Encode(src_01, sizeof(src_01) - 1, encodeBuf, &zeroLen) == BSL_BASE64_BUF_NOT_ENOUGH);
    ASSERT_TRUE(BSL_BASE64_Decode(NULL, 0, decodeBuf, &decodeBufLen) == BSL_NULL_INPUT);
    ASSERT_TRUE(BSL_BASE64_Decode(encodeResult_01, 4, decodeBuf, &zeroLen) == BSL_BASE64_BUF_NOT_ENOUGH);

    /* Stream encoding/decoding empty input test */
    BSL_Base64Ctx *ctx = BSL_BASE64_CtxNew();
    BSL_BASE64_EncodeInit(ctx);
    ASSERT_TRUE(BSL_BASE64_EncodeUpdate(ctx, NULL, zeroLen, encodeBuf, &encodeBufLen) == BSL_NULL_INPUT);
    ASSERT_TRUE(BSL_BASE64_EncodeFinal(ctx, encodeBuf, &encodeBufLen) == BSL_SUCCESS);

    BSL_BASE64_CtxClear(ctx);
    BSL_BASE64_DecodeInit(ctx);
    ASSERT_TRUE(BSL_BASE64_DecodeUpdate(ctx, NULL, (const uint32_t)encodeBufLen,
        decodeBuf, &decodeBufLen) == BSL_NULL_INPUT);
    ASSERT_TRUE(BSL_BASE64_DecodeFinal(ctx, decodeBuf, &decodeBufLen) == BSL_SUCCESS);
EXIT:
    free(encodeBuf);
    free(decodeBuf);
    BSL_BASE64_CtxFree(ctx);
}
/* END_CASE */

/**
 * @test SDV_BSL_BASE64_FUNC_TC008
 * @spec  -
 * @title  Multiple update tests
 * @precon  nan
 * @brief   1. Call BSL_Base64EncodeUpdate
            2. Call BSL_Base64EncodeUpdate
            3. Call BSL_Base64EncodeUpdate
            4. Call BSL_Base64EncodeFinal
            5. Call BSL_Base64DecodeUpdate
            6. Call BSL_Base64DecodeUpdate
            7. Call BSL_Base64DecodeUpdate
            8. Call BSL_Base64DecodeFinal
            
 * @expect  1. BSL_SUCCESS -> The data is not encoded and is cached in the buffer. dstBufLen is set to 0.
            2. BSL_SUCCESS
            3. BSL_SUCCESS -> 3 + 44 < 48, The srcBuf is shorter than the length of a buffer. The data is cached in the
                              buffer, and dstBufLen is set to 0.
            4. BSL_SUCCESS -> Handles 3 + 44 characters
            5. BSL_SUCCESS -> Data that is not decoded is stored in the buffer, and dstBufLen is set to 0.
            6. BSL_SUCCESS
            7. BSL_SUCCESS
            8. BSL_SUCCESS
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_BASE64_FUNC_TC008(void)
{
    uint32_t srcLen = testData[0].srcLen + testData[7].srcLen + testData[6].srcLen;
    uint32_t encodeBufLen = HITLS_BASE64_ENCODE_LENGTH(srcLen);
    char *encodeBuf = malloc(encodeBufLen);
    uint32_t decodeBufLen = HITLS_BASE64_DECODE_LENGTH(encodeBufLen);
    uint8_t *decodeBuf = malloc(HITLS_BASE64_DECODE_LENGTH(encodeBufLen));

    /*
     * The output parameter dstBufLen needs to be updated in real time when the update operation is performed for
     * multiple times.
     */
    uint32_t tmpLen = encodeBufLen;
    uint32_t total = 0;
    ASSERT_TRUE(encodeBuf != NULL);
    ASSERT_TRUE(decodeBuf != NULL);
    /* encode */
    BSL_Base64Ctx *ctx = BSL_BASE64_CtxNew();
    BSL_BASE64_EncodeInit(ctx);
    ASSERT_TRUE(BSL_BASE64_EncodeUpdate(ctx, testData[1].src, testData[1].srcLen, encodeBuf, &tmpLen) ==
        BSL_SUCCESS); /* 1bytes */
    encodeBufLen -= tmpLen;
    total += tmpLen;
    tmpLen = encodeBufLen;
    ASSERT_TRUE(BSL_BASE64_EncodeUpdate(ctx, testData[7].src, testData[7].srcLen, encodeBuf + total, &tmpLen) ==
        BSL_SUCCESS); /* 147bytes */
    encodeBufLen -= tmpLen;
    total += tmpLen;
    tmpLen = encodeBufLen;
    ASSERT_TRUE(BSL_BASE64_EncodeUpdate(ctx, testData[6].src, testData[6].srcLen, encodeBuf + total, &tmpLen) ==
        BSL_SUCCESS); /* 44bytes */
    encodeBufLen -= tmpLen;
    total += tmpLen;
    tmpLen = encodeBufLen;
    ASSERT_TRUE(BSL_BASE64_EncodeFinal(ctx, encodeBuf + total, &tmpLen) == BSL_SUCCESS);
    total += tmpLen;

    ASSERT_TRUE((sizeof(encodeResult_09) - 1) == total);
    ASSERT_TRUE(memcmp((const char *)encodeBuf, encodeResult_09, total) == 0);

    BSL_BASE64_CtxClear(ctx);

    /* decode */
    tmpLen = decodeBufLen;
    total = 0;
    BSL_BASE64_DecodeInit(ctx);
    ASSERT_TRUE(BSL_BASE64_DecodeUpdate(ctx, testData[0].encodeResult,
        (const uint32_t)testData[0].encodeResultLen, decodeBuf, &tmpLen) == BSL_SUCCESS); /* 4bytes */
    decodeBufLen -= tmpLen;
    total += tmpLen;
    tmpLen = decodeBufLen;
    ASSERT_TRUE(BSL_BASE64_DecodeUpdate(ctx, testData[7].encodeResult,
        (const uint32_t)testData[7].encodeResultLen, decodeBuf + total, &tmpLen) == BSL_SUCCESS); /* 196bytes */
    decodeBufLen -= tmpLen;
    total += tmpLen;
    tmpLen = decodeBufLen;
    ASSERT_TRUE(BSL_BASE64_DecodeUpdate(ctx, testData[6].encodeResult,
        (const uint32_t)testData[6].encodeResultLen, decodeBuf + total, &tmpLen) == BSL_SUCCESS); /* 60bytes */
    decodeBufLen -= tmpLen;
    total += tmpLen;
    tmpLen = decodeBufLen;
    ASSERT_TRUE(BSL_BASE64_DecodeFinal(ctx, decodeBuf + total, &tmpLen) == BSL_SUCCESS);
    total += tmpLen;

    ASSERT_TRUE(srcLen == total);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    free(encodeBuf);
    free(decodeBuf);
    BSL_BASE64_CtxFree(ctx);
}
/* END_CASE */

void Base64BlockEncDec(const uint8_t *buf, const uint32_t len)
{
    const uint8_t *src = buf;
    const uint32_t srcLen = len;

    uint32_t hitlsEncLen = HITLS_BASE64_ENCODE_LENGTH(len);
    char *hitlsEncResult = BSL_SAL_Malloc(hitlsEncLen);

    uint32_t hitlsDecLen = HITLS_BASE64_DECODE_LENGTH(hitlsEncLen);
    uint8_t *hitlsDecResult = BSL_SAL_Malloc(hitlsDecLen);
    TRUE_OR_EXIT(BSL_BASE64_Encode(src, srcLen, hitlsEncResult, &hitlsEncLen) == BSL_SUCCESS);

    TRUE_OR_EXIT(BSL_BASE64_Decode(hitlsEncResult, hitlsEncLen, hitlsDecResult, &hitlsDecLen) == BSL_SUCCESS);
    TRUE_OR_EXIT(hitlsDecLen == srcLen);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(hitlsEncResult);
    BSL_SAL_Free(hitlsDecResult);
}

/**
 * @test SDV_BSL_BASE64_FUNC_TC009
 * @spec  -
 * @title  Block coding/decoding test
 * @precon  nan
 * @brief   1. Call BSL_Base64Encode/EVP_EncodeBlock
            2. Check whether the encoded result is correct.
            3. Call BSL_Base64Decode/EVP_DecodeBlock
            4. Check whether the decoded buffer is the same as the original buffer.
            5. Check whether the decoded buffer length is the same as the original buffer length.
            
 * @expect  1. Succeeded
            2. same
            3. Succeeded
            4. same
            5. same
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_BASE64_FUNC_TC009(void)
{
    Base64BlockEncDec(testData[0].src, testData[0].srcLen);
    for (int i = 8; i < testCnt; i++) {
        Base64BlockEncDec(testData[i].src, testData[i].srcLen);
    }
}
/* END_CASE */

void Base64Stream(const uint8_t *buf, const uint32_t len)
{
    const uint8_t *src = buf;
    const uint32_t srcLen = len;

    uint32_t hitlsEncLen = HITLS_BASE64_ENCODE_LENGTH(len);
    char *hitlsEncResult = BSL_SAL_Malloc(hitlsEncLen);

    uint32_t hitlsDecLen = HITLS_BASE64_DECODE_LENGTH(hitlsEncLen);
    uint8_t *hitlsDecResult = BSL_SAL_Malloc(hitlsDecLen);

    /* encode */
    // hitls stream encoding
    uint32_t tmpLen = hitlsEncLen;
    uint32_t total = 0;
    BSL_Base64Ctx *ctx = BSL_BASE64_CtxNew();
    BSL_BASE64_EncodeInit(ctx);
    TRUE_OR_EXIT(BSL_BASE64_EncodeUpdate(ctx, src, srcLen, hitlsEncResult, &tmpLen) == BSL_SUCCESS);
    hitlsEncLen -= tmpLen;
    total += tmpLen;
    tmpLen = hitlsEncLen;
    TRUE_OR_EXIT(BSL_BASE64_EncodeFinal(ctx, hitlsEncResult + total, &tmpLen) == BSL_SUCCESS);
    total += tmpLen;

    /* decode */
    // hitls stream encoding
    BSL_BASE64_CtxClear(ctx);
    tmpLen = hitlsDecLen;
    BSL_BASE64_DecodeInit(ctx);
    TRUE_OR_EXIT(BSL_BASE64_DecodeUpdate(ctx, hitlsEncResult, (const uint32_t)total, hitlsDecResult, &tmpLen) ==
        BSL_SUCCESS);
    total = 0;
    hitlsDecLen -= tmpLen;
    total += tmpLen;
    tmpLen = hitlsDecLen;
    TRUE_OR_EXIT(BSL_BASE64_DecodeFinal(ctx, hitlsDecResult + total, &tmpLen) == BSL_SUCCESS);
    total += tmpLen;
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_Free(hitlsEncResult);
    BSL_SAL_Free(hitlsDecResult);
    BSL_BASE64_CtxFree(ctx);
}

/**
 * @test SDV_BSL_BASE64_FUNC_TC010
 * @spec  -
 * @title  Single-flow encoding/decoding test
 * @precon  nan
 * @brief   1. Call BSL_Base64EncodeInit/EVP_EncodeInit
            2. Call BSL_Base64EncodeUpdate/EVP_EncodeUpdate
            3. Call BSL_Base64EncodeFinal/EVP_EncodeFinal
            4. Check whether the encoded result is correct.
            5. Check whether the encoded length is correct.
            6. Call BSL_Base64DecodeInit/EVP_DecodeInit
            7. Call BSL_Base64DecodeUpdate/EVP_DecodeUpdate
            8. Call BSL_Base64DecodeFinal/EVP_DecodeFinal
            9. Check whether the decoded buffer is the same as the original buffer.
            10. Check whether the decoded buffer length is the same as the original buffer length.
            
 * @expect  1. Succeeded
            2. BSL_SUCCESS
            3. handling the tail
            4. same
            5. same
            6. Succeeded
            7. BSL_SUCCESS
            8. BSL_SUCCESS
            9. same
            10. same
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_BASE64_FUNC_TC010(void)
{
    for (int i = 0; i < testCnt; i++) {
        Base64Stream(testData[i].src, testData[i].srcLen);
    }
}
/* END_CASE */

void Base64StreamMultiUpdate(const BASE64_TEST_DATA data[])
{
    uint32_t hitlsEncLen = HITLS_BASE64_ENCODE_LENGTH(512);
    char *hitlsEncResult = malloc(hitlsEncLen);

    uint32_t hitlsDecLen = HITLS_BASE64_DECODE_LENGTH(hitlsEncLen);
    uint8_t *hitlsDecResult = malloc(hitlsDecLen);
    /* encode */
    // hitls stream encoding
    uint32_t tmpLen = hitlsEncLen;
    uint32_t total = 0;
    BSL_Base64Ctx *ctx = BSL_BASE64_CtxNew();
    ASSERT_TRUE(hitlsEncResult != NULL);
    ASSERT_TRUE(hitlsDecResult != NULL);
    BSL_BASE64_EncodeInit(ctx);
    TRUE_OR_EXIT(BSL_BASE64_EncodeUpdate(ctx, data[12].src, data[12].srcLen, hitlsEncResult, &tmpLen) == BSL_SUCCESS);
    hitlsEncLen -= tmpLen;
    total += tmpLen;
    tmpLen = hitlsEncLen;
    TRUE_OR_EXIT(BSL_BASE64_EncodeUpdate(ctx, data[13].src, data[13].srcLen, hitlsEncResult + total, &tmpLen) ==
        BSL_SUCCESS);
    hitlsEncLen -= tmpLen;
    total += tmpLen;
    tmpLen = hitlsEncLen;
    TRUE_OR_EXIT(BSL_BASE64_EncodeUpdate(ctx, data[14].src, data[14].srcLen, hitlsEncResult + total, &tmpLen) ==
        BSL_SUCCESS);
    hitlsEncLen -= tmpLen;
    total += tmpLen;
    tmpLen = hitlsEncLen;
    TRUE_OR_EXIT(BSL_BASE64_EncodeFinal(ctx, hitlsEncResult + total, &tmpLen) == BSL_SUCCESS);
    total += tmpLen;

    /* decode */
    // hitls stream encoding
    BSL_BASE64_CtxClear(ctx);
    total = 0;
    tmpLen = hitlsDecLen;
    BSL_BASE64_DecodeInit(ctx);
    TRUE_OR_EXIT(BSL_BASE64_DecodeUpdate(ctx, (const char *)data[9].src, data[9].srcLen, hitlsDecResult, &tmpLen) ==
        BSL_SUCCESS);
    hitlsDecLen -= tmpLen;
    total += tmpLen;
    tmpLen = hitlsDecLen;
    TRUE_OR_EXIT(BSL_BASE64_DecodeUpdate(ctx, (const char *)data[10].src, data[10].srcLen, hitlsDecResult + total,
        &tmpLen) == BSL_SUCCESS);
    hitlsDecLen -= tmpLen;
    total += tmpLen;
    tmpLen = hitlsDecLen;
    TRUE_OR_EXIT(BSL_BASE64_DecodeUpdate(ctx, (const char *)data[11].src, data[11].srcLen, hitlsDecResult + total,
        &tmpLen) == BSL_SUCCESS);
    hitlsDecLen -= tmpLen;
    total += tmpLen;
    tmpLen = hitlsDecLen;
    TRUE_OR_EXIT(BSL_BASE64_DecodeFinal(ctx, hitlsDecResult + total, &tmpLen) == BSL_SUCCESS);
    total += tmpLen;
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    free(hitlsEncResult);
    free(hitlsDecResult);
    BSL_BASE64_CtxFree(ctx);
}

/**
 * @test SDV_BSL_BASE64_FUNC_TC011
 * @spec  -
 * @title  Multiple update tests
 * @precon  nan
 * @brief   1. Call BSL_Base64EncodeUpdate/EVP_EncodeUpdate
            2. Call BSL_Base64EncodeUpdate/EVP_EncodeUpdate
            3. Call BSL_Base64EncodeUpdate/EVP_EncodeUpdate
            4. Call BSL_Base64EncodeFinal/EVP_EncodeFinal
            5. memcmp encode result
            6. Call BSL_Base64DecodeUpdate/EVP_DecodeUpdate
            7. Call BSL_Base64DecodeUpdate/EVP_DecodeUpdate
            8. Call BSL_Base64DecodeUpdate/EVP_DecodeUpdate
            9. Call BSL_Base64DecodeFinal/EVP_DecodeFinal
            10. memcmp decode result
 * @expect  1.2.3.4. succeeded
            5.same
            6.7.8.9. succeeded
            10.same
 * @prior  Level 1
 * @auto  TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_BASE64_FUNC_TC011(void)
{
    Base64StreamMultiUpdate(testData);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_BASE64_FUNC_TC012(char *src, int expectRes)
{
    uint32_t srcBufLen = strlen(src);
    uint32_t dstBufLen = HITLS_BASE64_DECODE_LENGTH(srcBufLen);
    uint8_t *dst = BSL_SAL_Malloc(dstBufLen);
    ASSERT_TRUE(dst != NULL);
    ASSERT_EQ(BSL_BASE64_Decode(src, srcBufLen, dst, &dstBufLen), (int32_t)expectRes);
EXIT:
    BSL_SAL_Free(dst);
}
/* END_CASE */
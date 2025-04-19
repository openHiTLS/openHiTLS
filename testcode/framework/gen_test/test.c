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

#include "securec.h"
#include "helper.h"
#include "test.h"

TestInfo g_testResult;

int ConvertInt(const char *intStr, int *outNum)
{
    int *num = outNum;
    uint32_t i = 0;
    if (intStr[0] == '-') {
        i = 1;
    }

    for (; i < strlen(intStr); i++) {
        if (intStr[i] > '9' || intStr[i] < '0') {
            return 1;
        }
    }
    // Decimal
    *num = strtol(intStr, NULL, 10);

    return 0;
}

int ConvertString(char **str)
{
    if ((*str)[0] != '"') {
        return 1;
    }
    uint32_t back = strlen(*str) - 1;
    if ((*str)[back] != '"') {
        back--;
        if ((*str)[back] != '"') {
            return 1;
        }
    }
    (*str)[back] = '\0';
    (*str)++;

    return 0;
}

int IsValidHexChar(char c)
{
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
        return 0;
    }
    return 1;
}

int ConvertHex(const char *str, Hex *output)
{
    uint32_t len = strlen(str);
    if (len == 0) {
        output->x = NULL;
        output->len = 0;
        return 0;
    }
    // The length of a hex string must be a multiple of 2.
    if (len % 2 != 0) {
        return 1;
    }
    // Length of the hex string/2 = Length of the byte stream
    len = len / 2;
    output->x = (uint8_t *)malloc(len * sizeof(uint8_t));
    if (output->x == NULL) {
        return 1;
    }
    output->len = len;

    // Every 2 bytes in a group
    for (uint32_t i = 0; i < 2 * len; i += 2) {
        if ((IsValidHexChar(str[i]) == 1) || (IsValidHexChar(str[i + 1]) == 1)) {
            goto ERR;
        }
        // hex to int formulas: (Hex % 32 + 9) % 25 = int, hex
        output->x[i / 2] = (str[i] % 32 + 9) % 25 * 16 + (str[i + 1] % 32 + 9) % 25;
    }
    return 0;

ERR:
    free(output->x);
    output->len = 0;
    return 1;
}

void RecordFailure(const char *test, const char *filename)
{
    g_testResult.result = TEST_RESULT_FAILED;
    if (strcpy_s(g_testResult.test, sizeof(g_testResult.test), test) != 0) {
        Print("failure log failed: message too long\n");
    }
    if (strcpy_s(g_testResult.filename, sizeof(g_testResult.filename), filename) != 0) {
        Print("failure log failed: filename too long\n");
    }
}

void SkipTest(const char *filename)
{
    g_testResult.result = TEST_RESULT_SKIPPED;
    if (strcpy_s(g_testResult.filename, sizeof(g_testResult.filename), filename) != 0) {
        Print("failure log failed: filename too long\n");
    }
}
void PrintResult(bool showDetail, char *vectorName, time_t useTime)
{
    if (showDetail) {
        if (g_testResult.result == TEST_RESULT_SUCCEED) {
            Print("pass. use sec:%d\n", useTime);
        } else if (g_testResult.result == TEST_RESULT_SKIPPED) {
            Print("skip\n");
        } else {
            Print("failed\n");
            Print("at: (%s) in %s\n", g_testResult.test, g_testResult.filename);
        }
    } else if (g_testResult.result == TEST_RESULT_FAILED) {
        Print("\nfailed at vector: %s\n", vectorName);
        Print("at: (%s) in %s\n", g_testResult.test, g_testResult.filename);
    }
}

void PrintLog(FILE *logFile)
{
    int ret;
    if (g_testResult.result == TEST_RESULT_SUCCEED) {
        ret = fprintf(logFile, "pass\n");
        if (ret < 0) {
            Print("write to log file failed\n");
        }
    } else if (g_testResult.result == TEST_RESULT_SKIPPED) {
        ret = fprintf(logFile, "skip\n");
        if (ret < 0) {
            Print("write to log file failed\n");
        }
    } else {
        ret = fprintf(logFile, "failed\n");
        if (ret < 0) {
            Print("write to log file failed\n");
        }
        ret = fprintf(logFile, "at: (%s) in in %s\n", g_testResult.test, g_testResult.filename);
        if (ret < 0) {
            Print("write to log file failed\n");
        }
    }
}

void PrintDiff(const uint8_t *str1, uint32_t size1, const uint8_t *str2, uint32_t size2)
{
    Print("\nCompare different:\nstr1: ");
    uint32_t i;
    for (i = 0; i < size1; i++) {
        Print("%02X ", str1[i]);
    }
    Print("\nstr2: ");
    for (i = 0; i < size2; i++) {
        Print("%02X ", str2[i]);
    }
    Print("\n");
}
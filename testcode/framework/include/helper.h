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

#ifndef HELPER_H
#define HELPER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_TEST_FUCNTION_COUNT 100
#define MAX_TEST_FUNCTION_NAME 500
#define MAX_ARGUMENT_COUNT 50
#define MAX_EXPRESSION_COUNT 100
#define MAX_EXPRESSION_LEN 100
#define MAX_DATA_LINE_LEN 3500000
#define MAX_FUNCTION_LINE_LEN 512
#define MAX_FILE_PATH_LEN 300
#define MAX_SUITE_COUNT 600
#define MAX_LOG_LEN 500

#define TAG_NOT_TAG 0
#define TAG_BEGIN_HEADER 1
#define TAG_END_HEADER 2
#define TAG_BEGIN_CASE 3
#define TAG_END_CASE 4
#define TAG_INCLUDE_BASE 5

#define SPILT_HEX_BLOCK_SIZE 4

#define ARG_TYPE_INT 1
#define ARG_TYPE_STR 2
#define ARG_TYPE_HEX 3

#define BASE_FILE_FORMAT "%s/%s.base.c"
#define LOG_FILE_DIR "./log/"
#define LOG_FILE_FORMAT "./log/%s"
#define FUZZ_PRINT_EXECUTES "\r%d"

typedef struct {
    char name[MAX_FILE_PATH_LEN];
    int total;
    int pass;
    int skip;
    int line;
} TestSuiteResult;

typedef struct {
    char name[MAX_TEST_FUNCTION_NAME];
    int id;
    int argType[MAX_ARGUMENT_COUNT];
    uint32_t argCount;
} FunctionTable;

typedef struct {
    uint8_t *x;
    uint32_t len;
} Hex;

extern FunctionTable g_testFunc[MAX_TEST_FUCNTION_COUNT];
extern int g_testFuncCount;
extern char g_expTable[MAX_EXPRESSION_COUNT][MAX_EXPRESSION_LEN];
extern int g_expCount;

void Print(const char *fmt, ...);

void SetOutputFile(FILE *fp);

FILE *GetOutputFile(void);

void FreeHex(Hex *data);

Hex *NewHex(void);

int IsInt(const char *str);

int ReadLine(FILE *file, char *buf, uint32_t bufLen, bool skipHash, bool skipEmptyLine);

int SplitArguments(char *inStr, uint32_t inLen, char **outParam, uint32_t *paramLen);

int ReadFunction(const char *in, const uint32_t inLen, char *outFuncName, uint32_t outLen, int argv[MAX_ARGUMENT_COUNT],
    uint32_t *argCount);

int AddFunction(const char *funcName, int argv[MAX_ARGUMENT_COUNT], const uint32_t argCount);

int CheckTag(char *in, uint32_t len);

int GenFunctionWrapper(FILE *file, FunctionTable *function);

int ScanAllFunction(FILE *inFile, FILE *outFile);

int ScanHeader(FILE *inFile, FILE *outFile, const char *dir);

int GenFunctionPointer(FILE *file);

int GenDatax(FILE *inFile, FILE *outFile);

int GenExpTable(FILE *outFile);

int LoadFunctionName(FILE *outFile);

int LoadHelper(FILE *inFile, FILE *outFile);

int ScanFunctionFile(FILE *fpIn, FILE *fpOut, const char *dir);

int StripDir(const char *in, char *suiteName, const uint32_t suiteNameLen, char *dir, const uint32_t dirNameLen);

FILE *OpenFile(const char *name, const char *option, const char *format);

int GenResult(void);

int SplitHex(Hex *src, Hex *dest, int max);

int SplitHexRand(Hex *src, Hex *dest, int max);

int WriteHeader(FILE *outFile);
#ifdef __cplusplus
}
#endif

#endif // HELPER_H
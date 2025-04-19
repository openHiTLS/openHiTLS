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

#include <signal.h>
#include <stdarg.h>
#include <unistd.h>
#include "securec.h"

#define BUF_SIZE (65536 * 17)
#define MAX_RAND_SIZE (1024 * 16)
#define MAX_PATH 1024
#define MAX_FILE_NAME 200
#define MAX_IN_CASES 100000
#define OUTPUT_LINE_LENGTH 60

#ifdef FAIL_REPEAT_RUN
#define FAIL_TRY_TIMES 3
#else
#define FAIL_TRY_TIMES 0
#endif

#define FUNCTION_LOG_FORMAT "./log/%s.%s.log"
#define SUITE_LOG_FORMAT "./log/%s.log"
#define LOCAL_DIR "./"

typedef struct {
    char buf[MAX_DATA_LINE_LEN];
    char *arg[MAX_ARGUMENT_COUNT];
    char testVectorName[MAX_FILE_NAME];
    uint32_t argLen;
} TestArgs;

typedef struct {
    void *param[MAX_ARGUMENT_COUNT];
    int paramCount;
    int intParam[MAX_ARGUMENT_COUNT];
    int intParamCount;
    Hex hexParam[MAX_ARGUMENT_COUNT];
    int hexParamCount;
} TestParam;

static TestArgs *g_executeCases[MAX_IN_CASES];
static int g_executeCount = 0;

static int ConvertStringCase(const TestArgs *arg)
{
    for (uint32_t i = 1; i < arg->argLen; i += 2) {
        if (strcmp(arg->arg[i], "char") == 0 || strcmp(arg->arg[i], "Hex") == 0) {
            if (ConvertString((char **)&(arg->arg[i+1])) != 0) {
                return 1;
            }
        }
    }
    return 0;
}

static int LoadDataFile(const char *fileName)
{
    if (g_executeCount > 0) {
        return 0;
    }
    FILE *fpDatax = fopen(fileName, "r");
    if (fpDatax == NULL) {
        Print("Error opening file\n");
        return (-1);
    }
    int rt = 0;
    for (int i = 0; i < MAX_IN_CASES; i++) {
        g_executeCases[i] = (TestArgs *)malloc(sizeof(TestArgs));
        if (g_executeCases[i] == NULL) {
            rt = -1;
            goto EXIT;
        }
        g_executeCases[i]->argLen = MAX_ARGUMENT_COUNT;
        if (ReadLine(fpDatax, g_executeCases[i]->testVectorName, MAX_FILE_NAME, 1, 1) != 0) {
            free(g_executeCases[i]);
            goto EXIT;
        }
        if (ReadLine(fpDatax, g_executeCases[i]->buf, MAX_DATA_LINE_LEN, 1, 1) != 0) {
            free(g_executeCases[i]);
            Print("Read vector failed, test vector should have 2 lines, here there's only one\n");
            rt = -1;
            goto EXIT;
        }
        if (SplitArguments(g_executeCases[i]->buf, strlen(g_executeCases[i]->buf),
            g_executeCases[i]->arg, &(g_executeCases[i]->argLen)) != 0) {
            free(g_executeCases[i]);
            rt = -1;
            goto EXIT;
        }
        if (ConvertStringCase(g_executeCases[i]) == 1) {
            free(g_executeCases[i]);
            rt = -1;
            goto EXIT;
        }
        g_executeCount += 1;
    }
    char tmpName[MAX_FILE_NAME];
    if (ReadLine(fpDatax, tmpName, MAX_FILE_NAME, 1, 1) == 0) {
        Print("More test cases than max case num %d\n", MAX_IN_CASES);
        rt = -1;
    }

EXIT:
    if (rt != 0) {
        for (int i = 0; i < g_executeCount; i++) {
            free(g_executeCases[i]);
        }
        g_executeCount = 0;
    }
    (void)fclose(fpDatax);
    return rt;
}
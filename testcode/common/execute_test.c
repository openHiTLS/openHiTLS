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

#include <setjmp.h>
#include <time.h>
#include <sys/time.h>

static sigjmp_buf env;
static int isSubProc = 0;
int *GetJmpAddress(void)
{
    return &isSubProc;
}

void handleSignal()
{
    siglongjmp(env, 1);
}

static void PrintCaseName(FILE *logFile, bool showDetail, const char *name)
{
    // print a minimum of 4 dots
    int32_t dotCount = (OUTPUT_LINE_LENGTH - (int32_t)strlen(name) >= 4) ?
        (OUTPUT_LINE_LENGTH - (int32_t)strlen(name)) : 4;
    if (showDetail) {
        Print("%s", name);
        for (int32_t j = 0; j < dotCount; j++) {
            Print(".");
        }
    }
    (void)fprintf(logFile, "%s", name);
    for (int32_t j = 0; j < dotCount; j++) {
        (void)fprintf(logFile, ".");
    }
}

static int ParseArgs(const TestArgs *arg, TestParam *info)
{
    info->hexParamCount = 0;
    info->intParamCount = 0;
    info->paramCount = 0;
    for (uint32_t i = 1; i < arg->argLen; i += 2) { // 2
        if (strcmp(arg->arg[i], "int") == 0) {
            if (ConvertInt(arg->arg[i + 1], &(info->intParam[info->intParamCount])) == 0) {
                info->param[info->paramCount] = &(info->intParam[info->intParamCount]);
                info->intParamCount++;
            } else {
                Print("\nERROR: Int param conversion failed for:\n\"%s\"\n", arg->arg[i + 1]);
                return 1;
            }
        } else if (strcmp(arg->arg[i], "char") == 0) {
            info->param[info->paramCount] = arg->arg[i+1];
        } else if (strcmp(arg->arg[i], "Hex") == 0) {
            if (ConvertHex(arg->arg[i + 1], &(info->hexParam[info->hexParamCount])) != 0) {
                Print("\nERROR: Hex param conversion failed for:\n\"%s\"\n", arg->arg[i + 1]);
                return 1;
            }
            info->param[info->paramCount] = &(info->hexParam[info->hexParamCount]);
            info->hexParamCount++;
        } else if (strcmp(arg->arg[i], "exp") == 0) {
            int expId = 0;
            if (ConvertInt(arg->arg[i + 1], &expId) != 0 ||
                getExpression(expId, &(info->intParam[info->intParamCount])) != 0) {
                Print("\nERROR: Macro param conversion failed\n");
                return 1;
            }
            info->param[info->paramCount] = &(info->intParam[info->intParamCount]);
            info->intParamCount++;
        } else {
            return 1;
        }
        info->paramCount++;
    }

    return 0;
}

static int PrintCaseNameResult(FILE *logFile, int vectorCount, int skipCount, int passCount, time_t beginTime)
{
    char suitePrefix[OUTPUT_LINE_LENGTH] = {0};
    (void)snprintf_truncated_s(suitePrefix, sizeof(suitePrefix), "%s", suiteName);
    size_t leftSize = sizeof(suitePrefix) - 1 - strlen(suitePrefix);
    if (leftSize > 0) {
        (void)memset_s(suitePrefix + strlen(suitePrefix), sizeof(suitePrefix) - strlen(suitePrefix), '.', leftSize);
    }
    int failCount = vectorCount - passCount - skipCount;
    if (failCount == 0) {
        Print("%sPASS || Run %-6d testcases, passed: %-6d, skipped: %-6d, failed: %-6d useSec:%-5lu\n", suitePrefix,
            vectorCount, passCount, skipCount, failCount, time(NULL) - beginTime);
    } else {
        Print("%sFAIL || Run %-6d testcases, passed: %-6d, skipped: %-6d, failed: %-6d useSec:%-5lu\n", suitePrefix,
            vectorCount, passCount, skipCount, failCount, time(NULL) - beginTime);
    }

    time_t rawtime;
    struct tm *timeinfo;
    (void)time(&rawtime);
    timeinfo = localtime(&rawtime);
    (void)fprintf(logFile, "End time: %s", asctime(timeinfo));
    (void)fprintf(logFile, "Result: Run %d tests, Passed: %d, Skipped: %d, Failed: %d\n", vectorCount, passCount,
        skipCount, failCount);
    return failCount;
}

static int ProcessCases(FILE *logFile, bool showDetail, int targetFuncId)
{
    (void)logFile;
    volatile int vectorCount = 0;
    volatile int passCount = 0;
    volatile int skipCount = 0;
    volatile int tryNum;
    time_t beginTime = time(NULL);
    struct timespec start, end;
      
    for (volatile int i = 0; i < g_executeCount; i++) {
        int funcId = strtoul(g_executeCases[i]->arg[0], NULL, 10); // 10
        if (funcId < 0 || funcId > ((int)(sizeof(test_funcs)/sizeof(TestWrapper)))) {
            Print("funcId false!\n");
            return 1;
        }
        if ((targetFuncId != -1) && (funcId != targetFuncId)) {
            continue;
        }
        (void)fprintf(logFile, "%s ", funcName[funcId]);
        PrintCaseName(logFile, showDetail, g_executeCases[i]->testVectorName);
        TestParam io;
        if (ParseArgs(g_executeCases[i], &io) != 0) {
            return -1;
        }
        TestWrapper fp = test_funcs[funcId];
        g_testResult.result = TEST_RESULT_SUCCEED;
        tryNum = 0;
        clock_gettime(CLOCK_REALTIME, &start);
        do {
            if (tryNum > 0) {
                sleep(10);
                g_testResult.result = TEST_RESULT_SUCCEED;
            }
            tryNum++;
#ifdef  ASAN
            fp(io.param);
#else
        // Executing Function
        if (signal(SIGSEGV, handleSignal) == SIG_ERR) {
            return -1;
        }
        int r = sigsetjmp(env, 1);
        if (r == 0) {
            fp(io.param);
        } else if (r == 1){
            g_testResult.result = TEST_RESULT_FAILED;
        }
        if (isSubProc != 0) {
            break;
        }
#endif
        } while ((g_testResult.result == TEST_RESULT_FAILED) && (tryNum < FAIL_TRY_TIMES));
        if (g_testResult.result == TEST_RESULT_SUCCEED) {
            passCount++;
        } else if (g_testResult.result == TEST_RESULT_SKIPPED) {
            skipCount++;
        }
        vectorCount++;
        clock_gettime(CLOCK_REALTIME, &end);
        uint64_t elapsedms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
        PrintResult(showDetail, g_executeCases[i]->testVectorName, elapsedms);
        PrintLog(logFile);
        for (int j = 0; j < io.hexParamCount; j++) {
            FreeHex(&io.hexParam[j]);
        }
        if (isSubProc != 0) {
            break;
        }
    }

    return PrintCaseNameResult(logFile, vectorCount, skipCount, passCount, beginTime);
}

static int ExecuteTest(const char *fileName, bool showDetail, int targetFuncId)
{
    if (LoadDataFile(fileName) != 0) {
        return -1;
    }
    FILE *logFile = NULL;
    char logFileName[MAX_FILE_NAME] = {0};
    if (targetFuncId == -1) {
        if (sprintf_s(logFileName, MAX_FILE_NAME, SUITE_LOG_FORMAT, suiteName) <= 0) {
            Print("An error occurred while creating the log file\n");
            return (-1);
        }
    } else {
        if (sprintf_s(logFileName, MAX_FILE_NAME, FUNCTION_LOG_FORMAT, suiteName, funcName[targetFuncId]) <= 0) {
            Print("An error occurred while creating the log file\n");
            return (-1);
        }
    }
    time_t rawtime = time(NULL);
    if (rawtime == 0) {
        return -1;
    }
    logFile = fopen(logFileName, "w");
    if (logFile != NULL) {
        struct tm *timeinfo;
        timeinfo = localtime(&rawtime);
        if (fprintf(logFile, "Begin time: %s", asctime(timeinfo)) <= 0) {
            fclose(logFile);
            return -1;
        }
    }
    int rt = ProcessCases(logFile, showDetail, targetFuncId);
    if (logFile != NULL) {
        fclose(logFile);
    }
    return rt;
}

int ProcessMutiArgs(int argc, char **argv, const char *fileName)
{
    int printDetail = 1;
    int curTestCnt = 0;
    int ret = -1;
    int testCnt = sizeof(test_funcs) / sizeof(test_funcs[0]);
    int *funcIndex = malloc(sizeof(int) * testCnt);
    int found;

    if (funcIndex == NULL) {
        return ret;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "NO_DETAIL") == 0) {
            printDetail = 0;
            continue;
        }
        found = 0;
        for (int j = 0; j < testCnt; j++) {
            if (strcmp(argv[i], funcName[j]) == 0) {
                funcIndex[curTestCnt++] = j;
                found = 1;
                break;
            }
        }
        if (found != 1) {
            Print("test function '%s' do not exist\n", argv[i]);
            goto EXIT;
        }
    }

    if (curTestCnt == 0) {
        ret = ExecuteTest(fileName, printDetail, -1);
        goto EXIT;
    }

    for (int i = 0; i < curTestCnt; i++) {
        if (ExecuteTest(fileName, printDetail, funcIndex[i]) != 0) {
            goto EXIT;
        }
    }
    ret = 0;

EXIT:
    free(funcIndex);
    return ret;
}

int main(int argc, char **argv)
{
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    int ret = 0;
#ifndef PRINT_TO_TERMINAL
    char testOutputName[MAX_FILE_NAME] = {0};
    if (sprintf_s(testOutputName, MAX_FILE_NAME, "%s.output", suiteName) <= 0) {
        return 0;
    }
    FILE *fp = fopen(testOutputName, "w");
    if (fp == NULL) {
        return 1;
    }
    SetOutputFile(fp);
#endif

    char testName[MAX_FILE_PATH_LEN];
    if (sprintf_s(testName, MAX_FILE_PATH_LEN, "%s.datax", suiteName) <= 0) {
        goto EXIT;
    }
    if (argc == 1) {
        ret = ExecuteTest(testName, 1, -1);
    } else {
        ret = ProcessMutiArgs(argc, argv, testName);
    }
    if (ret != 0) {
        Print("execute test failed\n");
    }
    for (int i = 0; i < g_executeCount; i++) {
        free(g_executeCases[i]);
    }
EXIT:
#ifndef PRINT_TO_TERMINAL
    (void)fclose(fp);
#endif
    return ret;
}

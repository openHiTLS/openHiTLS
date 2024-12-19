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

#define EXECUTE_BASE_FILE "../common/execute_base.c"
#define EXECUTE_TEST_FILE "../common/execute_test.c"

typedef struct {
    char suiteName[MAX_FILE_PATH_LEN];
    char dir[MAX_FILE_PATH_LEN];
    FILE *fpIn;
    FILE *fpOut;
    FILE *fpData;
    FILE *fpBase;
    FILE *fpDatax;
    FILE *fpHelper;
} GenTestParams;

int WriteToFile(GenTestParams *genParam)
{
    int ret = 0;
    ret = WriteHeader(genParam->fpOut);
    if (ret != 0) {
        return ret;
    }

    // Scanned test_suite_xxx.c, and write fpOut
    ret = ScanFunctionFile(genParam->fpIn, genParam->fpOut, genParam->dir);
    if (ret != 0) {
        return ret;
    }

    ret = GenFunctionPointer(genParam->fpOut);
    if (ret != 0) {
        return ret;
    }

    ret = GenDatax(genParam->fpData, genParam->fpDatax);
    if (ret != 0) {
        Print("gen datax failed\n");
        return ret;
    }
    ret = GenExpTable(genParam->fpOut);
    if (ret != 0) {
        return ret;
    }
    ret = LoadFunctionName(genParam->fpOut);
    if (ret != 0) {
        return ret;
    }

    (void)fprintf(genParam->fpOut, "char suiteName[200] = \"%s\";\n\n", genParam->suiteName);
    // Write execute_base.c to fpOut
    ret = LoadHelper(genParam->fpBase, genParam->fpOut);
    if (ret != 0) {
        return ret;
    }
    // Write execute_test.c to fpOut
    return LoadHelper(genParam->fpHelper, genParam->fpOut);
}

int main(int argc, char **argv)
{
    (void)argc;
#ifndef PRINT_TO_TERMINAL
    FILE *fp = fopen("GenTest.output", "a");
    if (fp == NULL) {
        return 1;
    }
    SetOutputFile(fp);
#endif

    if (strcmp(argv[1], "GenReport") == 0) {
        int resultRet = GenResult();
#ifndef PRINT_TO_TERMINAL
        (void)fclose(fp);
#endif
        return resultRet;
    }

    int ret = 0;
    GenTestParams genParam = {0};
    StripDir(argv[1], genParam.suiteName, MAX_FILE_PATH_LEN, genParam.dir, MAX_FILE_PATH_LEN);
    // Read test_suite_xxx.c
    genParam.fpIn = OpenFile(argv[1], "r", "%s.c");
    if (genParam.fpIn == NULL) {
        Print("Open %s.c error occurred while file\n", argv[1]);
#ifndef PRINT_TO_TERMINAL
        (void)fclose(fp);
#endif
        return -1;
    }
    // Output file testcode/output/test_suite_xxx.c
    genParam.fpOut = OpenFile(genParam.suiteName, "w", "%s.c");
    if (genParam.fpOut == NULL) {
        Print("Error generating c file\n");
        ret = 1;
        goto END_FP_IN;
    }

    genParam.fpData = OpenFile(argv[1], "r", "%s.data");
    if (genParam.fpData == NULL) {
        Print("An error occurred while opening the data file.\n");
        ret = 1;
        goto END_FP_OUT;
    }

    genParam.fpDatax = OpenFile(genParam.suiteName, "w", "%s.datax");
    if (genParam.fpDatax == NULL) {
        Print("Error generating datax file\n");
        ret = 1;
        goto END_FP_DATA;
    }

    genParam.fpBase = fopen(EXECUTE_BASE_FILE, "r");
    if (genParam.fpBase == NULL) {
        Print("An error occurred when opening the base file.\n");
        ret = 1;
        goto END_FP_DATAX;
    }

    genParam.fpHelper = fopen(EXECUTE_TEST_FILE, "r");
    if (genParam.fpHelper == NULL) {
        Print("Error opening secondary file\n");
        ret = 1;
        goto END_FP_BASE;
    }

    ret = WriteToFile(&genParam);

    (void)fclose(genParam.fpHelper);

END_FP_BASE:
    (void)fclose(genParam.fpBase);

END_FP_DATAX:
    (void)fclose(genParam.fpDatax);

END_FP_DATA:
    (void)fclose(genParam.fpData);

END_FP_OUT:
    (void)fclose(genParam.fpOut);

END_FP_IN:
    (void)fclose(genParam.fpIn);
#ifndef PRINT_TO_TERMINAL
    (void)fclose(fp);
#endif
    return ret;
}

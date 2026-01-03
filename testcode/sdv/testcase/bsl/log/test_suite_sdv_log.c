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
#include <stdint.h>
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"

static uintptr_t g_binlogFlag = 0;

// Binlog fixed-length callback
static void BinLogFix(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para1, void *para2, void *para3, void *para4)
{
    (void)logId;
    (void)logLevel;
    (void)logType;
    (void)format;
    (void)para2;
    (void)para3;
    (void)para4;
    g_binlogFlag = (uintptr_t)para1;
}

// Binlog variable-length callback
static void BinLogVar(uint32_t logId, uint32_t logLevel, uint32_t logType, void *format, void *para)
{
    (void)logId;
    (void)logLevel;
    (void)logType;
    (void)format;
    g_binlogFlag = (uintptr_t)para;
}

void BinLogFixLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para1, void *para2, void *para3, void *para4)
{
    (void)logId;
    (void)logLevel;
    (void)logType;
    (void)format;
    (void)para1;
    (void)para2;
    (void)para3;
    (void)para4;
}

void BinLogVarLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para)
{
    (void)logId;
    (void)logLevel;
    (void)logType;
    (void)format;
    (void)para;
}

static FILE *g_LogOutput = NULL;

// Binlog fixed-length callback, output to a file
static void BinLogFixFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para1, void *para2, void *para3, void *para4)
{
    uint8_t *pucFormat = (uint8_t *)format;
    uint8_t ucTemp;
    uint8_t ucNo = 0;

    if (g_LogOutput == NULL) {
        return;
    }
    fprintf(g_LogOutput, "HITLS_BIN_LOG[FIXLEN]: logId=%u, logLevel=%u, logType=%u.\n", logId, logLevel, logType);

    /* Search for all format specifiers */
    while (*pucFormat != '\0') {
        if (*pucFormat == '%') {
            /* Get the second character */
            ucTemp  = *(pucFormat + 1);
            if ((ucTemp == 'd') || (ucTemp == 'l') || (ucTemp == 'p') || (ucTemp == 'u') || (ucTemp == 'x')) {
                ucNo++;
            }
        }
        pucFormat++;
    }

    switch(ucNo) {
        case 0: // Pure character strings are not output.
            break;
        case 1: // Output parameters only
            fprintf(g_LogOutput, "0x%lX\n", (uint64_t)para1);
            break;
        case 2: // Output parameters only
            fprintf(g_LogOutput, "0x%lX 0x%lX\n", (uint64_t)para1, (uint64_t)para2);
            break;
        case 3: // Output parameters only
            fprintf(g_LogOutput, "0x%lX 0x%lX 0x%lX\n", (uint64_t)para1, (uint64_t)para2, (uint64_t)para3);
            break;
        case 4: // Output parameters only
            fprintf(g_LogOutput, "0x%lX 0x%lX 0x%lX 0x%lX\n", (uint64_t)para1, (uint64_t)para2, (uint64_t)para3,
                (uint64_t)para4);
            break;
        default: // The number of parameters is incorrect.
            fprintf(g_LogOutput, "Invalid Number of Format Specifiers in LOG\n");
            return;
    }
}

// Binlog variable-length callback, output to a file
static void BinLogVarFunc(uint32_t logId, uint32_t logLevel, uint32_t logType, void *format, void *para)
{
    uint8_t *pucFormat = (uint8_t *)format;
    uint8_t ucTemp;
    uint8_t ucValidNo = 0;

    if (g_LogOutput == NULL) {
        return;
    }
    fprintf(g_LogOutput, "HITLS_BIN_LOG[VARLEN]: logId=%u, logLevel=%u, logType=%u.\n", logId, logLevel, logType);

    while (*pucFormat != '\0') {
        if (*pucFormat == '%') {
            /* Get the second character */
            ucTemp  = *(pucFormat + 1);
            if (ucTemp == 's') { // Only the %s parameter can be contained.
                ucValidNo++;
            }
        }
        pucFormat++;
    }

    if (ucValidNo != 1) {
        fprintf(g_LogOutput, "Invalid Number of %%s present in Var Len LOG\n");
    }

    fprintf(g_LogOutput, "%s\n", (const char *)para);
}

/* END_HEADER */

/**
 * @test SDV_BSL_LOG_VERSION_API_TC001
 * @title Obtaining the HiTLS version number of the log submodule of the BSL module
 * @precon nan
 * @brief
 *    1. The buffer of the received version string is empty
 *       or the buffer length of the received version string is empty. Expected result 1 is obtained.
 *    2. The buffer length of the received version string is less than the minimum length.
 *       Expected result 2 is obtained.
 *    3. Received version and length of memory application. Expected result 3 is obtained.
 * @expect
 *    1. Return BSL_LOG_ERR_BAD_PARAM
 *    2. Return BSL_LOG_ERR_BAD_PARAM
 *    3. Succeeded. The version length is equal to the current version length,
*        and the version string content is equal to the current version string content.
 */
/* BEGIN_CASE */
void SDV_BSL_LOG_VERSION_API_TC001(void)
{
    char version[200];
    uint32_t versionLen = 100;
    ASSERT_TRUE(BSL_LOG_GetVersion(NULL, NULL) == BSL_LOG_ERR_BAD_PARAM);
    ASSERT_TRUE(BSL_LOG_GetVersion((char *)version, &versionLen) == BSL_LOG_ERR_BAD_PARAM);

    versionLen = 200;
    ASSERT_TRUE(BSL_LOG_GetVersion((char *)version, &versionLen) == BSL_SUCCESS);
    ASSERT_TRUE(versionLen == strlen("openHiTLS 0.3.0 31 Dec 2025"));
    ASSERT_TRUE(memcmp(version, "openHiTLS 0.3.0 31 Dec 2025", versionLen) == 0);
    uint64_t versionNum = BSL_LOG_GetVersionNum();
    ASSERT_EQ(versionNum, 0x00300000ULL);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_REG_BIN_LOG_FUNC_TC001
 * @title  Setting the Log Callback Hook
 * @precon  nan
 * @brief
 *    1. Call the BSL_LOG_RegBinLogFunc interface and leave the input parameter empty. Expected result 1 is obtained.
 *    2. Call BSL_LOG_RegBinLogFunc. If funcs is not empty, fixLenFunc is empty,
 *       and varLenFunc is empty, expected result 2 is obtained.
 *    3. Call BSL_LOG_RegBinLogFunc. If funcs is not empty, fixLenFunc is empty,
 *       and varLenFunc is not empty, expected result 3 is obtained.
 *    4. Call BSL_LOG_RegBinLogFunc. If funcs, fixLenFunc, and varLenFunc are not empty, expected result 4 is obtained.
 *    5. Call BSL_LOG_RegBinLogFunc. Ensure that funcs and fixLenFunc are not empty,
 *       and varLenFunc are empty. Expected result 5 is obtained.
 *    6. Call BSL_LOG_RegBinLogFunc repeatedly. If funcs, fixLenFunc, and varLenFunc are not empty.
 *       Expected result 6 is obtained.
 * @expect
 *    1.BSL_NULL_INPUT
 *    2.BSL_NULL_INPUT
 *    3.BSL_NULL_INPUT
 *    4.BSL_SUCCESS
 *    5.BSL_NULL_INPUT
 *    6.BSL_SUCCESS
 */
/* BEGIN_CASE */
void SDV_BSL_REG_BIN_LOG_FUNC_TC001(void)
{
    TestMemInit();

    BSL_LOG_BinLogFuncs func = {0};
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(NULL) == BSL_NULL_INPUT);

    func.fixLenFunc = NULL;
    func.varLenFunc = NULL;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_NULL_INPUT);

    func.fixLenFunc = NULL;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_NULL_INPUT);

    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);

    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = NULL;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_NULL_INPUT);

    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LOG_RegBinLogFunc(&func) == BSL_SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_BIN_LOG_API_TC001
 * @title Testing the Log Recording of the Log Submodule of the BSL Module
 * @precon
 * @brief
 *    1. Setting an invalid dotting log level. Expected result 1 is obtained.
 *    2. Set a valid dotting log level and obtain the dotting log level. Expected result 2 is obtained.
 *    3. Set the parameter of the dotting log callback function to NULL. Expected result 3 is obtained.
 *    4. The parameter and member of the callback function for setting dotting logs are not NULL.
 *       Expected result 4 is obtained.
 *    5. The parameter of the callback function for setting dotting logs is not NULL.
 *       The callback function for four parameters is not NULL, and the callback function for one parameter is NULL.
 *       Expected result 5 is obtained.
 *    6. The parameter of the callback function for setting dotting logs is not NULL.
 *       The value 1 of the callback function is not NULL. The value 4 of the callback function is NULL.
 *       Expected result 6 is obtained.
 *    7. The parameter and member of the callback function for setting dotting logs are not NULL.
 *       Expected result 7 is obtained.
 *    8. Overwrite the callback function for setting dotting logs. Expected result 8 is obtained.
 *    9. Invoke the 4 parameter dotting to filter logs by log level. Expected result 9 is obtained.
 *    10. Invoke the 4 parameter dotting, and the log level is not filtered. Expected result 10 is obtained.
 *    11. Invoke variable parameter dotting and log level filtering. Expected result 11 is obtained.
 *    12. Invoke variable parameter dotting, and log level filtering is not performed. Expected result 12 is obtained.
 * @expect
 *    1. BSL_LOG_ERR_BAD_PARAM
 *    2. BSL_LOG_LEVEL_ERR
 *    3. BSL_LOG_LEVEL_ERR
 *    4. BSL_LOG_ERR_BAD_PARAM
 *    5. BSL_LOG_LEVEL_ERR
 *    6. BSL_NULL_INPUT
 *    7. BSL_SUCCESS
 *    8. BSL_SUCCESS
 *    9. The global return value is not modified.
 *    10. The global return value is changed to para1.
 *    11. The global return value is not modified.
 *    12. The global return value is changed to para.
 */
/* BEGIN_CASE */
void SDV_BSL_BIN_LOG_API_TC001(void)
{
    int32_t ret;
    int32_t retlevel;

    ret = BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_DEBUG + 1);
    ASSERT_TRUE(ret != BSL_SUCCESS);
    /*
     * The get loglevel command is used to obtain the default value
     * when the loglevel command fails to be set for the first time.
     */
    retlevel = BSL_LOG_GetBinLogLevel();
    ASSERT_TRUE(retlevel == BSL_LOG_LEVEL_ERR);

    ret = BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_ERR);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    // The BSL_LOG_GetBinLogLevel function is replaced.
    retlevel = BSL_LOG_GetBinLogLevel();
    ASSERT_TRUE(retlevel == BSL_LOG_LEVEL_ERR);

    // If the set loglevel operation fails, get loglevel to obtain the original value.
    ret = BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_DEBUG + 1);
    ASSERT_TRUE(ret != BSL_SUCCESS);
    retlevel = BSL_LOG_GetBinLogLevel();
    ASSERT_TRUE(retlevel == BSL_LOG_LEVEL_ERR);

    ret = BSL_LOG_RegBinLogFunc(NULL);
    ASSERT_TRUE(ret != BSL_SUCCESS);

    BSL_LOG_BinLogFuncs funcs = {NULL, NULL};
    ret = BSL_LOG_RegBinLogFunc(&funcs);
    ASSERT_TRUE(ret != BSL_SUCCESS);

    funcs.fixLenFunc = BinLogFix;
    funcs.varLenFunc = NULL;
    ret = BSL_LOG_RegBinLogFunc(&funcs);
    ASSERT_TRUE(ret != BSL_SUCCESS);

    funcs.fixLenFunc = NULL;
    funcs.varLenFunc = BinLogVar;
    ret = BSL_LOG_RegBinLogFunc(&funcs);
    ASSERT_TRUE(ret != BSL_SUCCESS);

    funcs.fixLenFunc = BinLogFix;
    funcs.varLenFunc = BinLogVar;
    ret = BSL_LOG_RegBinLogFunc(&funcs);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    g_binlogFlag = 0;
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05001, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN, "this is test %d %d", 1, 2, 0, 0);
    ASSERT_TRUE(g_binlogFlag == 0);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05001, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "this is test %d %d", 1, 2, 0, 0);
    ASSERT_TRUE(g_binlogFlag == 1);

    const char *s = "abc";
    g_binlogFlag = 0;
    BSL_LOG_BINLOG_VARLEN(BINLOG_ID05001, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN, "this is test %s", s);
    ASSERT_TRUE(g_binlogFlag == 0);
    BSL_LOG_BINLOG_VARLEN(BINLOG_ID05001, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "this is test %s", s);
    ASSERT_TRUE(g_binlogFlag == (uintptr_t)s);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_BSL_SET_BIN_LOG_LEVEL_API_TC001
 * @title  Setting the log level
 * @precon  nan
 * @brief
 *    1. Call the BSL_LOG_SetBinLogLevel interface with the input parameter BSL_LOG_LEVEL_SEC - 1.
 *       Expected result 1 is obtained.
 *    2. Call the BSL_LOG_SetBinLogLevel interface with the input parameter BSL_LOG_LEVEL_SEC.
 *       Expected result 2 is obtained.
 *    3. Call the BSL_LOG_SetBinLogLevel interface with the input parameter BSL_LOG_LEVEL_FATAL.
 *       Expected result 3 is obtained.
 *    4. Call the BSL_LOG_SetBinLogLevel interface with the input parameter BSL_LOG_LEVEL_ERR.
 *       Expected result 4 is obtained.
 *    5. Call the BSL_LOG_SetBinLogLevel interface with the input parameter BSL_LOG_LEVEL_WARN.
 *       Expected result 5 is obtained.
 *    6. Call the BSL_LOG_SetBinLogLevel interface with the input parameter BSL_LOG_LEVEL_INFO.
 *       Expected result 6 is obtained.
 *    7. Call the BSL_LOG_SetBinLogLevel interface with the input parameter BSL_LOG_LEVEL_DEBUG.
 *       Expected result 7 is obtained.
 *    8. Call the BSL_LOG_SetBinLogLevel interface with the input parameter BSL_LOG_LEVEL_DEBUG + 1.
 *       Expected result 8 is obtained.
 * @expect
 *    1.BSL_LOG_ERR_BAD_PARAM
 *    2.BSL_SUCCESS
 *    3.BSL_SUCCESS
 *    4.BSL_SUCCESS
 *    5.BSL_SUCCESS
 *    6.BSL_SUCCESS
 *    7.BSL_SUCCESS
 *    8.BSL_LOG_ERR_BAD_PARAM
 */
/* BEGIN_CASE */
void SDV_BSL_SET_BIN_LOG_LEVEL_API_TC001(void)
{
    TestMemInit();

    ASSERT_TRUE(BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_SEC - 1) == BSL_LOG_ERR_BAD_PARAM);
    ASSERT_TRUE(BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_SEC) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_FATAL) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_ERR) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_WARN) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_INFO) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_DEBUG) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_DEBUG + 1) == BSL_LOG_ERR_BAD_PARAM);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_BSL_BIN_LOG_FUNC_TC001
 * @title Demo of dotting logs of the BSL module. The log file is /tmp/HITLS_binlog_test.log.
 * @precon nan
 * @brief
 *    1. Clean up and reopen the file. Expected result 1 is obtained.
 *    2. Setting the log level. Expected result 2 is obtained.
 *    3. Registering the Dotting Log Function. Expected result 3 is obtained.
 *    4. Invoke the 4 parameter dotting to filter logs by log level. Expected result 4 is obtained.
 *    5. Invoke the four-parameter dot. Expected result 5 is obtained.
 *    6. Invoke the 1 parameter measurement point.
 * @expect
 *    1. Succeeded in clearing the remaining log files.
 *    2. BSL_SUCCESS
 *    3. BSL_SUCCESS
 *    4. No output is generated in the log file.
 *    5. The log file has output.
 *    6. The log file has output.
 */
/* BEGIN_CASE */
void SDV_BSL_BIN_LOG_FUNC_TC001(void)
{
    int32_t ret;
    const char *filename = "./HITLS_binlog_test.log";
    remove(filename);

    g_LogOutput = fopen(filename, "w");
    ASSERT_TRUE(g_LogOutput != NULL);

    ret = BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_ERR);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    BSL_LOG_BinLogFuncs funcs = {BinLogFixFunc, BinLogVarFunc};
    ret = BSL_LOG_RegBinLogFunc(&funcs);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05001, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
        "this is test %d %d", 1, 2, 0, 0);

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05002, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "this is test %d %d", 1, 2, 2147483647, 4294967295);

    BSL_LOG_BINLOG_VARLEN(BINLOG_ID05003, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
        "this is test msg: %s", "hello world");

EXIT:
    fclose(g_LogOutput); // flush and close
    g_LogOutput = NULL;
}
/* END_CASE */
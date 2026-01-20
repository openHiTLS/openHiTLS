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
#include <stdlib.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "sal_dlimpl.h"
/* END_HEADER */

/**
 * @test SDV_BSL_SAL_DL_FUNC_TC001
 * @title BSL SAL Provider functionality test
 * @precon None
 * @brief
 *    1. Call BSL_SAL_LoadLib with valid inputs. Expected result 1 is obtained.
 *    2. Call BSL_SAL_LoadLib with NULL filename. Expected result 2 is obtained.
 *    3. Call BSL_SAL_LoadLib with NULL handle pointer. Expected result 3 is obtained.
 *    4. Call BSL_SAL_LoadLib with non-existent library. Expected result 4 is obtained.
 *    5. Call BSL_SAL_GetFuncAddress with valid inputs. Expected result 5 is obtained.
 *    6. Call BSL_SAL_GetFuncAddress with provider lacking init function. Expected result 6 is obtained.
 *    7. Call BSL_SAL_GetFuncAddress with NULL handle. Expected result 7 is obtained.
 *    8. Call BSL_SAL_GetFuncAddress with NULL function pointer. Expected result 8 is obtained.
 *    9. Call BSL_SAL_UnLoadLib with valid inputs. Expected result 9 is obtained.
 *    10. Call BSL_SAL_UnLoadLib with NULL handle. Expected result 10 is obtained.
 * @expect
 *    1. BSL_SUCCESS, handle is not NULL
 *    2. BSL_SAL_ERR_BAD_PARAM
 *    3. BSL_SAL_ERR_BAD_PARAM
 *    4. BSL_SAL_ERR_DL_NOT_FOUND
 *    5. BSL_SUCCESS, function pointer is not NULL
 *    6. BSL_SAL_ERR_DL_NON_FUNCTION
 *    7. BSL_SAL_ERR_BAD_PARAM
 *    8. BSL_SAL_ERR_BAD_PARAM
 *    9. BSL_SUCCESS
 *    10. BSL_SAL_ERR_BAD_PARAM
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_DL_FUNC_TC001(char *test1, char *test2, char *testNoInit, char *funcName)
{
#ifndef HITLS_CRYPTO_PROVIDER
    /* Skip test in no-provider mode: provider test libraries are not built */
    (void)test1;
    (void)test2;
    (void)testNoInit;
    (void)funcName;
    SKIP_TEST();
#else
    void *handle1 = NULL;
    void *handle2 = NULL;
    void *handleNoInit = NULL;
    void *func = NULL;
    void *nonExistentLib = NULL;
    int32_t ret;

    /* Skip test data that doesn't match current platform */
    const char *ext = strrchr(test1, '.');
    if (ext != NULL) {
#if defined(HITLS_BSL_SAL_DARWIN)
        /* On Darwin, skip .so test data */
        if (strcmp(ext, ".so") == 0) {
            return;
        }
#else  /* HITLS_BSL_SAL_LINUX and other Unix-like systems */
        /* On Linux, skip .dylib test data */
        if (strcmp(ext, ".dylib") == 0) {
            return;
        }
#endif
    }

    // Test BSL_SAL_LoadLib with valid input
    ret = BSL_SAL_LoadLib(test1, &handle1);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(handle1 != NULL);

    ret = BSL_SAL_LoadLib(test2, &handle2);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(handle2 != NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());

    // Test BSL_SAL_LoadLib with invalid input
    ret = BSL_SAL_LoadLib(NULL, &handle1);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

    ret = BSL_SAL_LoadLib(test1, NULL);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

    ret = BSL_SAL_LoadLib("nonExistentLib", &nonExistentLib);
    ASSERT_EQ(ret, BSL_SAL_ERR_DL_NOT_FOUND);
    TestErrClear();

    // Test BSL_SAL_GetFuncAddress with valid input
    ret = BSL_SAL_GetFuncAddress(handle1, funcName, &func);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(func != NULL);

    // Test BSL_SAL_GetFuncAddress with provider lacking init function
    ret = BSL_SAL_LoadLib(testNoInit, &handleNoInit);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    
    ret = BSL_SAL_GetFuncAddress(handleNoInit, funcName, &func);
    ASSERT_EQ(ret, BSL_SAL_ERR_DL_NON_FUNCTION);

    // Test BSL_SAL_GetFuncAddress with invalid input
    ret = BSL_SAL_GetFuncAddress(NULL, funcName, &func);
#ifdef HITLS_BSL_SAL_DARWIN
    ASSERT_EQ(ret, BSL_SAL_ERR_DL_LOOKUP_METHOD);
#else
    ASSERT_EQ(ret, BSL_SAL_ERR_DL_NON_FUNCTION);
#endif
    ret = BSL_SAL_GetFuncAddress(handle1, funcName, NULL);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);
    TestErrClear();

    // Test BSL_SAL_UnLoadLib with valid input
    ret = BSL_SAL_UnLoadLib(handle1);
    ASSERT_EQ(ret, BSL_SUCCESS);
    handle1 = NULL;

    ret = BSL_SAL_UnLoadLib(handle2);
    ASSERT_EQ(ret, BSL_SUCCESS);
    handle2 = NULL;
    ASSERT_TRUE(TestIsErrStackEmpty());

    // Test BSL_SAL_UnLoadLib with invalid input
    ret = BSL_SAL_UnLoadLib(NULL);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

EXIT:
    if (handle1 != NULL) {
        BSL_SAL_UnLoadLib(handle1);
    }
    if (handle2 != NULL) {
        BSL_SAL_UnLoadLib(handle2);
    }
    if (handleNoInit != NULL) {
        BSL_SAL_UnLoadLib(handleNoInit);
    }
    return;
#endif /* HITLS_CRYPTO_PROVIDER */
}
/* END_CASE */

#define INVALID_COMMEND 5

/**
 * @test SDV_BSL_SAL_CONVERTER_NAME_FUNC_TC001
 * @title BSL SAL ConverterName functionality test
 * @precon None
 * @brief
 *    1. Call BSL_SAL_LibNameFormat with valid inputs. Expected result 1 is obtained.
 *    2. Call BSL_SAL_LibNameFormat with insufficient buffer size. Expected result 2 is obtained.
 *    3. Call BSL_SAL_LibNameFormat with NULL filename. Expected result 3 is obtained.
 *    4. Call BSL_SAL_LibNameFormat with NULL output name pointer. Expected result 4 is obtained.
 *    5. Call BSL_SAL_LibNameFormat with invalid command. Expected result 5 is obtained.
 * @expect
 *    1. BSL_SUCCESS, converted name matches aimResult
 *    2. BSL_SAL_ERR_DL_PATH_EXCEED
 *    3. BSL_SAL_ERR_BAD_PARAM
 *    4. BSL_SAL_ERR_BAD_PARAM
 *    5. BSL_SAL_ERR_BAD_PARAM
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_CONVERTER_NAME_TC001(char *name, int cmd, char *aimResult)
{
    char *convertedName = NULL;
    int32_t ret;

    TestMemInit();

    /* Skip test data that doesn't match current platform */
    const char *ext = strrchr(aimResult, '.');
    if (ext != NULL) {
#if defined(HITLS_BSL_SAL_DARWIN)
        /* On Darwin, skip .so test data */
        if (strcmp(ext, ".so") == 0) {
            return;
        }
#else  /* HITLS_BSL_SAL_LINUX and other Unix-like systems */
        /* On Linux, skip .dylib test data */
        if (strcmp(ext, ".dylib") == 0) {
            return;
        }
#endif
    }

    ret = BSL_SAL_LibNameFormat(cmd, name, &convertedName);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(convertedName != NULL);
    ASSERT_TRUE(strcmp(convertedName, aimResult) == 0);
    BSL_SAL_FREE(convertedName);

    // Test with NULL inputs
    ret = BSL_SAL_LibNameFormat(cmd, NULL, &convertedName);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

    ret = BSL_SAL_LibNameFormat(cmd, name, NULL);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

    // Test with invalid command
    ret = BSL_SAL_LibNameFormat(INVALID_COMMEND, name, &convertedName);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

EXIT:
    return;
}

/* END_CASE */

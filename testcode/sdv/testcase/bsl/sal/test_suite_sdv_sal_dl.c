/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
    void *handle1 = NULL;
    void *handle2 = NULL;
    void *handleNoInit = NULL;
    void *func = NULL;
    void *nonExistentLib = NULL;
    int32_t ret;

    // Test BSL_SAL_LoadLib with valid input
    ret = BSL_SAL_LoadLib(test1, &handle1);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(handle1 != NULL);

    ret = BSL_SAL_LoadLib(test2, &handle2);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(handle2 != NULL);

    // Test BSL_SAL_LoadLib with invalid input
    ret = BSL_SAL_LoadLib(NULL, &handle1);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

    ret = BSL_SAL_LoadLib(test1, NULL);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

    ret = BSL_SAL_LoadLib("nonExistentLib", &nonExistentLib);
    ASSERT_EQ(ret, BSL_SAL_ERR_DL_NOT_FOUND);

    // Test BSL_SAL_GetFuncAddress with valid input
    ret = BSL_SAL_GetFuncAddress(handle1, funcName, &func);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(func != NULL);

    // Test BSL_SAL_GetFuncAddress with provider lacking init function
    ret = BSL_SAL_LoadLib(testNoInit, &handleNoInit);
    ASSERT_EQ(ret, BSL_SUCCESS);
    
    ret = BSL_SAL_GetFuncAddress(handleNoInit, funcName, &func);
    ASSERT_EQ(ret, BSL_SAL_ERR_DL_NON_FUNCTION);

    // Test BSL_SAL_GetFuncAddress with invalid input
    ret = BSL_SAL_GetFuncAddress(NULL, funcName, &func);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

    ret = BSL_SAL_GetFuncAddress(handle1, funcName, NULL);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

    // Test BSL_SAL_UnLoadLib with valid input
    ret = BSL_SAL_UnLoadLib(handle1);
    ASSERT_EQ(ret, BSL_SUCCESS);

    ret = BSL_SAL_UnLoadLib(handle2);
    ASSERT_EQ(ret, BSL_SUCCESS);

    // Test BSL_SAL_UnLoadLib with invalid input
    ret = BSL_SAL_UnLoadLib(NULL);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

exit:
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
}
/* END_CASE */

#define INVALID_COMMEND 5

/**
 * @test SDV_BSL_SAL_CONVERTER_NAME_FUNC_TC001
 * @title BSL SAL ConverterName functionality test
 * @precon None
 * @brief
 *    1. Call BSL_SAL_ConverterName with valid inputs. Expected result 1 is obtained.
 *    2. Call BSL_SAL_ConverterName with insufficient buffer size. Expected result 2 is obtained.
 *    3. Call BSL_SAL_ConverterName with NULL filename. Expected result 3 is obtained.
 *    4. Call BSL_SAL_ConverterName with NULL directory name. Expected result 4 is obtained.
 *    5. Call BSL_SAL_ConverterName with NULL output name pointer. Expected result 5 is obtained.
 *    6. Call BSL_SAL_ConverterName with invalid command. Expected result 6 is obtained.
 * @expect
 *    1. BSL_SUCCESS, converted name matches aimResult
 *    2. BSL_SAL_ERR_DL_PATH_EXCEED
 *    3. BSL_SAL_ERR_BAD_PARAM
 *    4. BSL_SAL_ERR_BAD_PARAM
 *    5. BSL_SAL_ERR_BAD_PARAM
 *    6. BSL_SUCCESS, converted name matches aimResult of BSL_SAL_CONVERTER_SO
 * @prior Level 1
 * @auto TRUE
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_CONVERTER_NAME_TC001(char *path, char *name, int cmd, char *aimResult)
{
    char *convertedName = NULL;
    int32_t ret;

    ret = BSL_SAL_ConverterName(cmd, name, path, &convertedName);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(convertedName != NULL);
    ASSERT_TRUE(strcmp(convertedName, aimResult) == 0);
    BSL_SAL_FREE(convertedName);

    // Test with NULL inputs
    ret = BSL_SAL_ConverterName(cmd, NULL, path, &convertedName);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

    ret = BSL_SAL_ConverterName(cmd, name, NULL, &convertedName);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

    ret = BSL_SAL_ConverterName(cmd, name, path, NULL);
    ASSERT_EQ(ret, BSL_SAL_ERR_BAD_PARAM);

    // Test with invalid command
    ret = BSL_SAL_ConverterName(INVALID_COMMEND, name, path, &convertedName);
    ASSERT_EQ(ret, BSL_SUCCESS);
    if (cmd == BSL_SAL_CONVERTER_SO) {
        ASSERT_TRUE(strcmp(convertedName, aimResult) == 0);
    }
    BSL_SAL_FREE(convertedName);

exit:
    return;
}

/* END_CASE */

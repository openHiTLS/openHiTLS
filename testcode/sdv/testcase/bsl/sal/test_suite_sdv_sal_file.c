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

#include <string.h>
#include <stdio.h>
#include "bsl_errno.h"
#include "bsl_sal.h"

#define MAX_PATH_LEN 4096
#define MAX_FILE_LEN 4096

void CreateFile(const char *fileName)
{
    FILE *fp = fopen(fileName, "rb");
    if (fp == NULL) {
        fp = fopen(fileName, "wb");
    }
    fclose(fp);
}

void RemoveFile(const char *fileName)
{
    remove(fileName);
}

/* END_HEADER */

static void *TestFileOpenFunc(void *args)
{
    bsl_sal_file_handle stream = NULL;
    char mode[] = "rb";
    char path[MAX_PATH_LEN];
    (void)args;
    (void)strcpy(path, "");
    int ret;

    // 1.If the setting path is empty, the system fails to open the path, and BSL_NULL_INPUT is returned.
    ret = BSL_SAL_FileOpen(&stream, path, mode);
    ASSERT_EQ(ret, BSL_NULL_INPUT);

    // 2.If the build does not exist, the file path fails to be opened and BSL_SAL_ERR_FILE_Open is returned.
    (void)strcpy(path, "ret/sd/s.s");
    ret = BSL_SAL_FileOpen(&stream, path, mode);
    ASSERT_EQ(ret, BSL_SAL_ERR_FILE_OPEN);

    // 3.Create a new file and open it. If the operation is successful, BSL_SUCCESS is returned.
    (void)strcpy(path, "test.txt");
    CreateFile(path);
    ret = BSL_SAL_FileOpen(&stream, path, mode);
    ASSERT_EQ(ret, BSL_SUCCESS);

    BSL_SAL_FileClose(stream);

EXIT:
    RemoveFile(path);
    return NULL;
}

/**
 * @test SDV_BSL_SAL_FILE_OPEN_FUNC_TC001
 * @title  Test the file opening operation.
 * @precon  nan
 * @brief
 *    1. Open the file and leave the path empty. Expected result 1 is obtained.
 *    2. Open the file but the file does not exist. Expected result 2 is obtained.
 *    3. Create a file and then open the file. The operation is successful. Expected result 3 is obtained.
 * @expect
 *    1. BSL_NULL_INPUT
 *    2. BSL_SAL_ERR_FILE_OPEN
 *    3. BSL_SUCCESS
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_FILE_OPEN_FUNC_TC001(void)
{
    TestFileOpenFunc(NULL);
}
/* END_CASE */

static void *TestFileLengthFunc(void *args)
{
    bsl_sal_file_handle stream = NULL;
    char path[MAX_PATH_LEN];
    char writeBuffer[MAX_FILE_LEN] = "we come from same country!";
    char readBuffer[MAX_FILE_LEN];
    int ret;
    size_t len = 0;
    (void)args;
    (void)strcpy(path, "test.txt");
    CreateFile(path);

    ret = BSL_SAL_FileOpen(&stream, path, "wb");
    ASSERT_EQ(ret, BSL_SUCCESS);

    ret = BSL_SAL_FileWrite(stream, writeBuffer, 1, 10);
    ASSERT_EQ(ret, BSL_SUCCESS);

    BSL_SAL_FileClose(stream);

    ret = BSL_SAL_FileOpen(&stream, path, "rb");
    ASSERT_EQ(ret, BSL_SUCCESS);

    ret = BSL_SAL_FileRead(stream, readBuffer, 1, 10, &len); // Reads the file content to the buffer.
    ASSERT_TRUE(len > 0); // The read length is greater than 0.
    ASSERT_EQ(ret, BSL_SUCCESS);

    ret = BSL_SAL_FileLength(path, &len);

    ASSERT_TRUE(len > 0); // The length of the existing file is greater than 0.
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_FileClose(stream);
    RemoveFile(path);
    return NULL;
}
/**
 * @test SDV_BSL_SAL_FILE_LENGTH_FUNC_TC001
 * @title  Write content to a file and obtain the file length.
 * @precon  nan
 * @brief
 *    1. Create a file. Expected result 1 is obtained.
 *    2. Write data to a file. After the write operation is performed,
 *       perform the close operation to write the buffer data to the file. Expected result 2 is obtained.
 *    3. Open the file again and read the file content. Because the file contains information,
 *       the read length is greater than 0. Expected result 3 is obtained.
 *    4. Obtain the file length, which is greater than 0. Expected result 4 is obtained.
 * @expect
 *    1. File created successfully.
 *    2. BSL_SUCCESS
 *    3. BSL_SUCCESS
 *    4. BSL_SUCCESS
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_FILE_LENGTH_FUNC_TC001(void)
{
    TestFileLengthFunc(NULL);
}
/* END_CASE */

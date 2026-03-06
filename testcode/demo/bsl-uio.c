/* Copyright (c) 2025, Shandong University — School of Cyber Science and Technology
 * Contributor: Ziwei Hu
 * Instructor:  Weijia Wang
 */
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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "bsl_err.h"
#include "bsl_uio.h"

#define DEMO_BUF_SIZE 128
#define DEMO_FILE_NAME "demo_output.txt"
#define DEMO_DATA_STR "Hello openHiTLS via Official Method!\n"

static int32_t RunFileDemo(BSL_UIO *uio)
{
    int32_t flags = BSL_UIO_FILE_APPEND | BSL_UIO_FILE_READ;
    uint32_t len = 0;
    char buf[DEMO_BUF_SIZE] = {0};

    if (uio == NULL) {
        return -1;
    }

    if (BSL_UIO_Ctrl(uio, BSL_UIO_FILE_OPEN, flags, (void *)DEMO_FILE_NAME) != 0) {
        return -1;
    }

    if (BSL_UIO_Write(uio, DEMO_DATA_STR, (uint32_t)strlen(DEMO_DATA_STR), &len) != 0) {
        return -1;
    }
    printf("Write success: %u bytes\n", len);

    BSL_UIO_Ctrl(uio, BSL_UIO_FLUSH, 0, NULL);

    if (BSL_UIO_Ctrl(uio, BSL_UIO_RESET, 0, NULL) != 0) {
        return -1;
    }

    if (BSL_UIO_Read(uio, buf, sizeof(buf) - 1, &len) != 0) {
        return -1;
    }

    buf[len] = '\0';
    printf("Read back: %s\n", buf);

    return 0;
}

int main(void)
{
    const BSL_UIO_Method *fileMethod = NULL;
    BSL_UIO *uio = NULL;
    int32_t ret = -1;

    if (BSL_ERR_Init() != 0) {
        return -1;
    }

    fileMethod = BSL_UIO_FileMethod();
    if (fileMethod != NULL) {
        uio = BSL_UIO_New(fileMethod);
    }

    if (uio != NULL) {
        ret = RunFileDemo(uio);
    }

    if (uio != NULL) {
        BSL_UIO_Free(uio);
    }

    BSL_ERR_DeInit();

    return (int)ret;
}

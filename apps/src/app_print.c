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
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include "securec.h"
#include "bsl_uio.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "app_errno.h"

#define X509_PRINT_MAX_LAYER 10
#define X509_PRINT_LAYER_INDENT 4
#define X509_PRINT_MAX_INDENT (X509_PRINT_MAX_LAYER * X509_PRINT_LAYER_INDENT)
#define LOG_BUFFER_LEN 2048
static BSL_UIO *g_errorUIO = NULL;

int32_t AppUioVPrint(BSL_UIO *uio, const char *format, va_list args)
{
    int32_t ret = 0;
    if (uio == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    uint32_t writeLen = 0;
    char *buf = (char *)BSL_SAL_Calloc(LOG_BUFFER_LEN + 1, 1);
    if (buf == NULL) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }

    ret = vsnprintf_s(buf, LOG_BUFFER_LEN + 1, LOG_BUFFER_LEN, format, args);
    if (ret < EOK) {
        BSL_SAL_FREE(buf);
        return HITLS_APP_SECUREC_FAIL;
    }
    ret = BSL_UIO_Write(uio, buf, ret, &writeLen);
    BSL_SAL_FREE(buf);
    return ret;
}

int32_t AppPrint(BSL_UIO *uio, const char *format, ...)
{
    if (uio == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    va_list args;
    va_start(args, format);
    int32_t ret = AppUioVPrint(uio, format, args);
    va_end(args);
    return ret;
}

void AppPrintError(const char *format, ...)
{
    if (g_errorUIO == NULL) {
        return;
    }
    va_list args;
    va_start(args, format);
    (void)AppUioVPrint(g_errorUIO, format, args);
    va_end(args);
    return;
}


int32_t AppPrintErrorUioInit(FILE *fp)
{
    if (fp == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    if (g_errorUIO != NULL) {
        return HITLS_APP_SUCCESS;
    }
    g_errorUIO = BSL_UIO_New(BSL_UIO_FileMethod());
    if (g_errorUIO == NULL) {
        return BSL_UIO_MEM_ALLOC_FAIL;
    }
    return BSL_UIO_Ctrl(g_errorUIO, BSL_UIO_FILE_PTR, 0, (void *)fp);
}

void AppPrintErrorUioUnInit(void)
{
    if (g_errorUIO != NULL) {
        BSL_UIO_Free(g_errorUIO);
        g_errorUIO = NULL;
    }
}
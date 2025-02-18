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
#include <stdint.h>
#include "securec.h"
#include "bsl_uio.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"

#define BSL_ASN1_PRINT_LEN 1024
#define X509_PRINT_MAX_LAYER 10
#define X509_PRINT_EACH_LAYER_INDENT 4
#define X509_PRINT_MAX_INDENT ((X509_PRINT_EACH_LAYER_INDENT) * (X509_PRINT_MAX_LAYER))

int32_t BSL_ASN1_PrintfBuff(uint32_t layer, BSL_UIO *uio, const void *buff, uint32_t buffLen)
{
    int32_t ret;
    uint32_t writeLen = 0;
    char *indent[X509_PRINT_MAX_INDENT + 1] = {};
    (void)memset_s(indent, X509_PRINT_MAX_INDENT, ' ', X509_PRINT_MAX_INDENT);
    if (layer > 0) {
        ret = BSL_UIO_Write(uio, indent, layer * X509_PRINT_EACH_LAYER_INDENT, &writeLen);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (writeLen != (layer * X509_PRINT_EACH_LAYER_INDENT)) {
            BSL_ERR_PUSH_ERROR(BSL_ASN1_ERR_PRINTF_IO_ERR);
            return BSL_ASN1_ERR_PRINTF_IO_ERR;
        }
    }
    if (buffLen == 0) {
        return BSL_SUCCESS;
    }
    writeLen = 0;
    ret = BSL_UIO_Write(uio, buff, buffLen, &writeLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (writeLen != buffLen) {
        BSL_ERR_PUSH_ERROR(BSL_ASN1_ERR_PRINTF_IO_ERR);
        return BSL_ASN1_ERR_PRINTF_IO_ERR;
    }

    return BSL_SUCCESS;
}

int32_t BSL_ASN1_Printf(uint32_t layer, BSL_UIO *uio, const char *fmt, ...)
{
    if (layer > X509_PRINT_MAX_LAYER || uio == NULL || fmt == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    va_list args;
    va_start(args, fmt);
    char buff[BSL_ASN1_PRINT_LEN + 1] = {0};
    if (vsprintf_s(buff, BSL_ASN1_PRINT_LEN + 1, fmt, args) == -1) {
        va_end(args);
        BSL_ERR_PUSH_ERROR(BSL_ASN1_ERR_PRINTF);
        return BSL_ASN1_ERR_PRINTF;
    }
    int32_t ret = BSL_ASN1_PrintfBuff(layer, uio, buff, (uint32_t)strlen(buff));
    va_end(args);

    return ret;
}

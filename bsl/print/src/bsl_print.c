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
#include <inttypes.h>
#include <string.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "bsl_print.h"

#define BSL_PRINT_LEN 1024
#define BSL_PRINT_MAX_LAYER 10
#define BSL_PRINT_EACH_LAYER_INDENT 4
#define BSL_PRINT_MAX_INDENT ((BSL_PRINT_EACH_LAYER_INDENT) * (BSL_PRINT_MAX_LAYER))

#define BSL_PRINT_WIDTH 16
#define BSL_PRINT_MAX_WIDTH 20  // If the data length is less than or equal to 20, the data is printed in one line.
#define BSL_ASN1_HEX_TO_COLON_HEX 3  // "XX:" Use 3 bytes.
#define BSL_PRINT_HEX_LEN (BSL_PRINT_MAX_WIDTH * BSL_ASN1_HEX_TO_COLON_HEX + 1)

#define BSL_PRINT_NEW_LINE "\n"

static int32_t WriteBuff(BSL_UIO *uio, const void *buff, uint32_t buffLen)
{
    uint32_t writeLen = 0;
    int32_t ret = BSL_UIO_Write(uio, buff, buffLen, &writeLen);
    return ret != BSL_SUCCESS ? ret : (writeLen != buffLen ? BSL_PRINT_ERR_BUF : BSL_SUCCESS);
}

static int32_t PrintBuff(uint32_t layer, BSL_UIO *uio, const void *buff, uint32_t buffLen)
{
    int32_t ret;
    char *indent[BSL_PRINT_MAX_INDENT + 1] = {0};
    (void)memset_s(indent, BSL_PRINT_MAX_INDENT, ' ', BSL_PRINT_MAX_INDENT);
    if (layer > 0) {
        ret = WriteBuff(uio, indent, layer * BSL_PRINT_EACH_LAYER_INDENT);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if (buffLen == 0) {
        return BSL_SUCCESS;
    }
    ret = WriteBuff(uio, buff, buffLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t BSL_PRINT_Buff(uint32_t layer, BSL_UIO *uio, const void *buff, uint32_t buffLen)
{
    if (layer > BSL_PRINT_MAX_LAYER || uio == NULL || (buffLen != 0 && buff == NULL)) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    return PrintBuff(layer, uio, buff, buffLen);
}

static int32_t PrintHexOnOneLine(uint32_t layer, const uint8_t *data, uint32_t dataLen, BSL_UIO *uio)
{
    char hexStr[BSL_PRINT_HEX_LEN] = {0};
    uint32_t strIdx = 0;
    bool isEnd;
    bool needIndent = true;
    int32_t ret;
    for (uint32_t i = 0; i < dataLen; i++) {
        isEnd = (i + 1) == dataLen;
        if (sprintf_s(hexStr + strIdx * BSL_ASN1_HEX_TO_COLON_HEX,
            BSL_PRINT_HEX_LEN - strIdx * BSL_ASN1_HEX_TO_COLON_HEX, isEnd ? "%02x\n" : "%02x:", data[i]) == -1) {
            BSL_ERR_PUSH_ERROR(BSL_PRINT_ERR_BUF);
            return BSL_PRINT_ERR_BUF;
        }
        strIdx++;
        if (isEnd || strIdx == BSL_PRINT_MAX_WIDTH) {
            ret = PrintBuff(needIndent ? layer : 0, uio, hexStr, strIdx * BSL_ASN1_HEX_TO_COLON_HEX);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            needIndent = false;
            strIdx = 0;
        }
    }
    return BSL_SUCCESS;
}

int32_t BSL_PRINT_Hex(uint32_t layer, bool oneLine, const uint8_t *data, uint32_t dataLen, BSL_UIO *uio)
{
    if (layer > BSL_PRINT_MAX_LAYER || data == NULL || dataLen == 0 || uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    if (oneLine) {
        return PrintHexOnOneLine(layer, data, dataLen, uio);
    }

    char hexStr[BSL_PRINT_HEX_LEN] = {0};
    uint32_t lineLen = dataLen <= BSL_PRINT_MAX_WIDTH ? BSL_PRINT_MAX_WIDTH : BSL_PRINT_WIDTH;
    char *format = NULL;
    uint32_t strIdx = 0;
    bool isLineEnd;

    for (uint32_t i = 0; i < dataLen; i++) {
        isLineEnd = (i + 1) % lineLen == 0 || (i + 1) == dataLen;
        format = isLineEnd ? "%02x\n" : "%02x:";
        if (sprintf_s(hexStr + strIdx * BSL_ASN1_HEX_TO_COLON_HEX,
            BSL_PRINT_HEX_LEN - strIdx * BSL_ASN1_HEX_TO_COLON_HEX, format, data[i]) == -1) {
            BSL_ERR_PUSH_ERROR(BSL_PRINT_ERR_BUF);
            return BSL_PRINT_ERR_BUF;
        }
        strIdx++;
        if (!isLineEnd) {
            continue;
        }
        if (PrintBuff(layer, uio, hexStr, strIdx * BSL_ASN1_HEX_TO_COLON_HEX) != 0) {
            BSL_ERR_PUSH_ERROR(BSL_PRINT_ERR_BUF);
            return BSL_PRINT_ERR_BUF;
        }
        strIdx = 0;
    }
    return BSL_SUCCESS;
}

int32_t BSL_PRINT_Fmt(uint32_t layer, BSL_UIO *uio, const char *fmt, ...)
{
    if (layer > BSL_PRINT_MAX_LAYER || uio == NULL || fmt == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    va_list args;
    va_start(args, fmt);
    char buff[BSL_PRINT_LEN + 1] = {0};
    if (vsprintf_s(buff, BSL_PRINT_LEN + 1, fmt, args) == -1) {
        va_end(args);
        BSL_ERR_PUSH_ERROR(BSL_PRINT_ERR_FMT);
        return BSL_PRINT_ERR_FMT;
    }
    int32_t ret = BSL_PRINT_Buff(layer, uio, buff, (uint32_t)strlen(buff));
    va_end(args);
    return ret != 0 ? BSL_PRINT_ERR_FMT : BSL_SUCCESS;
}

// rfc822: https://www.w3.org/Protocols/rfc822/
static const char MONTH_STR[12][4] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

int32_t BSL_PRINT_Time(uint32_t layer, const BSL_TIME *time, BSL_UIO *uio)
{
    if (time == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }
    return BSL_PRINT_Fmt(layer, uio, "%s %u %02u:%02u:%02u %u GMT\n", MONTH_STR[time->month - 1],
        time->day, time->hour, time->minute, time->second, time->year);
}

/**
 * Only positive numbers can be printed.
 */
int32_t BSL_PRINT_Number(uint32_t layer, const char *title, const uint8_t *data, uint32_t dataLen, BSL_UIO *uio)
{
    if (title == NULL || data == NULL || dataLen == 0 || uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    if (dataLen > (sizeof(uint64_t))) {
        if (BSL_PRINT_Fmt(layer, uio, "%s:\n", title) != 0) {
            BSL_ERR_PUSH_ERROR(BSL_PRINT_ERR_NUMBER);
            return BSL_PRINT_ERR_NUMBER;
        }
        return BSL_PRINT_Hex(layer + 1, false, data, dataLen, uio);
    }

    uint64_t num = 0;
    for (uint32_t i = 0; i < dataLen; i++) {
        num |= (uint64_t)data[i] << (8 * (dataLen - i - 1));  // 8: bits
    }
    return BSL_PRINT_Fmt(layer, uio, "%s: %"PRIu64" (0x%"PRIX64")\n", title, num, num);
}

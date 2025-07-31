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

#include "hitls_build.h"
#ifdef HITLS_BSL_UI

#include <stdio.h>
#include <termios.h>
#include "securec.h"
#include "bsl_sal.h"
#include "sal_file.h"
#include "ui_type.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "bsl_ui.h"

#define DEV_TTY "/dev/tty"

int32_t UI_Open(BSL_UI *ui)
{
    if (ui == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    (void)BSL_SAL_ThreadWriteLock(ui->lock);

    int32_t ret = BSL_SAL_FileOpen(&(ui->in), DEV_TTY, "r");
    if (ret != BSL_SUCCESS) {
        (void)BSL_SAL_ThreadUnlock(ui->lock);
        return ret;
    }

    ret = BSL_SAL_FileOpen(&(ui->out), DEV_TTY, "w");
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FileClose(ui->in);
        (void)BSL_SAL_ThreadUnlock(ui->lock);
        return ret;
    }

    return BSL_SUCCESS;
}

static int32_t UI_CheckDataCommonParam(BSL_UI *ui, BSL_UI_DataPack *data)
{
    if (ui == NULL || data == NULL || data->data == NULL || data->dataLen == 0) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    return BSL_SUCCESS;
}

static int32_t UI_CheckDataWriteParam(BSL_UI *ui, BSL_UI_DataPack *data)
{
    int32_t ret = UI_CheckDataCommonParam(ui, data);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    if (ui->out == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    return BSL_SUCCESS;
}

int32_t UI_Write(BSL_UI *ui, BSL_UI_DataPack *data)
{
    int32_t ret = UI_CheckDataWriteParam(ui, data);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    if (SAL_FPuts(ui->out, data->data)) {
        (void)SAL_Flush(ui->out);
        return BSL_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(BSL_UI_WRITE_ERROR);
    return BSL_UI_WRITE_ERROR;
}

static int32_t UI_ReadInternal(BSL_UI *ui, char *result, int32_t resultLen)
{
    if (SAL_FGets(ui->in, result, resultLen) == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UI_FGETS_ERROR);
        return BSL_UI_FGETS_ERROR;
    }
    int32_t ret = SAL_Feof(ui->in);
    if (ret == BSL_SUCCESS || ret == BSL_SAL_FILE_NO_REG_FUNC) {
        // The input stream will be closed when Ctrl+D is pressed, or func is not regeister.
        BSL_ERR_PUSH_ERROR(BSL_UI_STDIN_END_ERROR);
        return BSL_UI_STDIN_END_ERROR;
    }

    if (SAL_FileError(ui->in)) { // Previous file operation error
        BSL_ERR_PUSH_ERROR(BSL_UI_OPERATION_ERROR);
        return BSL_UI_OPERATION_ERROR;
    }
    // 2 is before the last one
    if ((strlen(result) == (size_t)resultLen - 1) && (result[resultLen - 2] != '\n')) {
        BSL_ERR_PUSH_ERROR(BSL_UI_READ_BUFF_TOO_LONG);
        return BSL_UI_READ_BUFF_TOO_LONG;
    }
    return BSL_SUCCESS;
}

static int32_t UI_ReadSetFlag(BSL_UI *ui, uint32_t flags, struct termios *origTerm)
{
    struct termios newTerm;
    if (!BSL_UI_SUPPORT_ABILITY(flags, BSL_UI_DATA_FLAG_ECHO)) {
        (void)memcpy_s(&newTerm, sizeof(newTerm), origTerm, sizeof(struct termios));
        newTerm.c_lflag &= ~ECHO;
        return SAL_FSetAttr(ui->in, TCSANOW, (void *)&newTerm);
    }
    return BSL_SUCCESS;
}

static int32_t UI_ReadRecoverFlag(BSL_UI *ui, uint32_t flags, struct termios *origTerm)
{
    BSL_UI_DataPack endData = {0};
    char endStr[] = "\n";
    if (!BSL_UI_SUPPORT_ABILITY(flags, BSL_UI_DATA_FLAG_ECHO)) {
        int32_t ret = SAL_FSetAttr(ui->in, TCSANOW, (void *)origTerm);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        endData.data = endStr;
        endData.dataLen = (uint32_t)strlen(endStr) + 1;
        ret = UI_Write(ui, &endData);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    }
    return BSL_SUCCESS;
}

static int32_t UI_CheckDataReadParam(BSL_UI *ui, BSL_UI_DataPack *data)
{
    int32_t ret = UI_CheckDataCommonParam(ui, data);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    if (ui->in == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    return BSL_SUCCESS;
}

int32_t UI_Read(BSL_UI *ui, BSL_UI_DataPack *data)
{
    struct termios origTerm;
    char result[BSL_UI_READ_BUFF_MAX_LEN + 1]; // real buff + '\n' + '\0'
    int32_t ret = UI_CheckDataReadParam(ui, data);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = SAL_FGetAttr(ui->in, (void *)&origTerm);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = UI_ReadSetFlag(ui, data->flags, &origTerm);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    do {
        ret = UI_ReadInternal(ui, result, (int32_t)sizeof(result));
        if (ret != BSL_SUCCESS) {
            (void)UI_ReadRecoverFlag(ui, data->flags, &origTerm);
            break;
        }
        ret = UI_ReadRecoverFlag(ui, data->flags, &origTerm);
        if (ret != BSL_SUCCESS) {
            break;
        }
        char *pos = strchr(result, '\n');
        if (pos != NULL) {
            *pos = '\0';
        }
        if (strlen(result) == 0) {
            ret = BSL_UI_READ_LEN_TOO_SHORT;
            break;
        }
        if (data->dataLen < (strlen(result) + 1)) {
            ret = BSL_UI_OUTPUT_BUFF_TOO_SHORT;
            break;
        }
        if (data->verifyData != NULL && strcmp(data->verifyData, result) != 0) {
            ret = BSL_UI_VERIFY_BUFF_FAILED;
            break;
        }
        (void)strcpy_s(data->data, data->dataLen, result);
        data->dataLen = (uint32_t)strlen(result) + 1;
    } while (0);
    (void)memset_s(result, sizeof(result), 0, sizeof(result));
    return ret;
}

int32_t UI_Close(BSL_UI *ui)
{
    if (ui == NULL) {
        return BSL_SUCCESS;
    }
    if (ui->in != NULL) {
        BSL_SAL_FileClose(ui->in);
    }
    if (ui->out != NULL) {
        BSL_SAL_FileClose(ui->out);
    }
    (void)BSL_SAL_ThreadUnlock(ui->lock);
    return BSL_SUCCESS;
}

static BSL_UI_Method g_defaultUiMethod = {
    UI_Open,
    UI_Write,
    UI_Read,
    UI_Close
};


const BSL_UI_Method *BSL_UI_GetOperMethod(const BSL_UI *ui)
{
    if (ui == NULL) {
        return &g_defaultUiMethod;
    }
    return ui->method;
}
#endif /* HITLS_BSL_UI */

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
#include "securec.h"
#include "bsl_sal.h"
#include "ui_type.h"
#include "bsl_errno.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_binlog_id.h"
#include "bsl_ui.h"

#define BSL_UI_PROMPT_PART_MAX_LEN 200

BSL_UI *BSL_UI_New(const BSL_UI_Method *method)
{
    BSL_UI *ui = (BSL_UI *)BSL_SAL_Malloc(sizeof(BSL_UI));
    if (ui == NULL) {
        return NULL;
    }
    (void)memset_s(ui, sizeof(BSL_UI), 0, sizeof(BSL_UI));
    int32_t ret = BSL_SAL_ThreadLockNew(&(ui->lock));
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(ui);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05061, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ui new: new thread lock error ret = %u.", (uint32_t)ret, 0, 0, 0);
        return NULL;
    }
    if (method == NULL) {
        ui->method = BSL_UI_GetOperMethod(NULL);
    } else {
        ui->method = method;
    }
    return ui;
}

void BSL_UI_Free(BSL_UI *ui)
{
    if (ui == NULL) {
        return;
    }
    BSL_SAL_ThreadLockFree(ui->lock);
    BSL_SAL_FREE(ui);
}

BSL_UI_Method *BSL_UI_MethodNew(void)
{
    BSL_UI_Method *method = (BSL_UI_Method *)BSL_SAL_Malloc(sizeof(BSL_UI_Method));
    if (method == NULL) {
        return method;
    }
    (void)memset_s(method, sizeof(BSL_UI_Method), 0, sizeof(BSL_UI_Method));
    return method;
}

void BSL_UI_MethodFree(BSL_UI_Method *method)
{
    if (method == NULL) {
        return;
    }
    BSL_SAL_FREE(method);
}

int32_t BSL_UI_SetMethod(BSL_UI_Method *method, uint8_t type, void *func)
{
    if (method == NULL || func == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    switch (type) {
        case BSL_UIM_OPEN:
            method->uiOpen = func;
            break;
        case BSL_UIM_WRITE:
            method->uiWrite = func;
            break;
        case BSL_UIM_READ:
            method->uiRead = func;
            break;
        case BSL_UIM_CLOSE:
            method->uiClose = func;
            break;
        default:
            BSL_ERR_PUSH_ERROR(BSL_UI_METHOD_INVALID_TYPE);
            return BSL_UI_METHOD_INVALID_TYPE;
    }
    return BSL_SUCCESS;
}


int32_t BSL_UI_GetMethod(const BSL_UI_Method *method, uint8_t type, void **func)
{
    if (method == NULL || func == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    switch (type) {
        case BSL_UIM_OPEN:
            *func = method->uiOpen;
            break;
        case BSL_UIM_WRITE:
            *func = method->uiWrite;
            break;
        case BSL_UIM_READ:
            *func = method->uiRead;
            break;
        case BSL_UIM_CLOSE:
            *func = method->uiClose;
            break;
        default:
            BSL_ERR_PUSH_ERROR(BSL_UI_METHOD_INVALID_TYPE);
            return BSL_UI_METHOD_INVALID_TYPE;
    }
    return BSL_SUCCESS;
}

char *BSL_UI_ConstructPrompt(const char *objectDesc, const char *objectName)
{
    if (objectDesc == NULL) {
        return NULL;
    }
    if (strlen(objectDesc) > BSL_UI_PROMPT_PART_MAX_LEN) {
        return NULL;
    }
    char *outString = NULL;
    char start[] = "Please input ";
    char middle[] = " for ";
    char end[] = ":";
    uint32_t outLen = (uint32_t)strlen(start) + (uint32_t)strlen(objectDesc) + (uint32_t)strlen(end) + 1;
    if (objectName != NULL) {
        if (strlen(objectName) > BSL_UI_PROMPT_PART_MAX_LEN) {
            return NULL;
        }
        outLen += (uint32_t)strlen(middle) + (uint32_t)strlen(objectName);
    }
    outString = (char *)BSL_SAL_Malloc(outLen);
    if (outString == NULL) {
        return NULL;
    }
    (void)strcpy_s(outString, outLen, start);
    (void)strcat_s(outString, outLen, objectDesc);
    if (objectName != NULL) {
        (void)strcat_s(outString, outLen, middle);
        (void)strcat_s(outString, outLen, objectName);
    }
    (void)strcat_s(outString, outLen, end);
    return outString;
}

static int32_t BSL_UI_OperDataOnce(BSL_UI *ui, BSL_UI_DataPack *writeData, BSL_UI_DataPack *readData)
{
    int32_t ret = ui->method->uiWrite(ui, writeData);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05082, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ui pwd util: write error:%u.", (uint32_t)ret, 0, 0, 0);
        return ret;
    }
    ret = ui->method->uiRead(ui, readData);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05084, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ui pwd util: read error:%u.", (uint32_t)ret, 0, 0, 0);
        return ret;
    }
    return BSL_SUCCESS;
}

static int32_t BSL_UI_OperVerifyData(BSL_UI *ui, const char *promptStr, BSL_UI_DataPack *firstReadData)
{
    BSL_UI_DataPack writeData = {0};
    BSL_UI_DataPack readData = {0};
    char verifyRes[BSL_UI_READ_BUFF_MAX_LEN] = {0};
    uint32_t verifyResLen = BSL_UI_READ_BUFF_MAX_LEN;
    char verifyPrompt[] = "Verify---";
    char verifyFailPrompt[] = "Verify failed!\n";
    uint32_t verifyLen = (uint32_t)strlen(promptStr) + (uint32_t)strlen(verifyPrompt) + 1;
    char *verifyStr = BSL_SAL_Malloc(verifyLen);
    if (verifyStr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UI_MEM_ALLOC_FAIL);
        return BSL_UI_MEM_ALLOC_FAIL;
    }
    (void)memset_s(verifyStr, verifyLen, 0, verifyLen);
    (void)strcpy_s(verifyStr, verifyLen, verifyPrompt);
    (void)strcat_s(verifyStr, verifyLen, promptStr);
    writeData.data = verifyStr;
    writeData.dataLen = (uint32_t)strlen(verifyStr) + 1;
    readData.data = verifyRes;
    readData.dataLen = verifyResLen;
    int32_t ret = BSL_UI_OperDataOnce(ui, &writeData, &readData);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(verifyStr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (readData.dataLen != firstReadData->dataLen || strcmp(verifyRes, firstReadData->data) != 0) {
        writeData.data = verifyFailPrompt;
        writeData.dataLen = (uint32_t)strlen(verifyFailPrompt) + 1;
        (void)ui->method->uiWrite(ui, &writeData);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05069, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ui pwd util: verify failed.", 0, 0, 0, 0);
        ret = BSL_UI_VERIFY_BUFF_FAILED;
    }
    BSL_SAL_FREE(verifyStr);
    (void)memset_s(verifyRes, sizeof(verifyRes), 0, sizeof(verifyRes));
    BSL_ERR_PUSH_ERROR(ret);
    return ret;
}

static int32_t BSL_UI_OperInputData(BSL_UI *ui, BSL_UI_ReadPwdParam *param, BSL_UI_DataPack *readData,
    char **prompt, const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    BSL_UI_DataPack writeData = {0};
    char *promptStr = BSL_UI_ConstructPrompt(param->desc, param->name);
    if (promptStr == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UI_CONSTRUCT_PROMPT_ERROR);
        return BSL_UI_CONSTRUCT_PROMPT_ERROR;
    }
    writeData.data = promptStr;
    writeData.dataLen = (uint32_t)strlen(promptStr) + 1;
    int32_t ret = BSL_UI_OperDataOnce(ui, &writeData, readData);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(promptStr);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (checkDataCallBack != NULL) {
        ret = checkDataCallBack(ui, readData->data, readData->dataLen, callBackData);
        if (ret != BSL_SUCCESS) {
            BSL_SAL_FREE(promptStr);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05104, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "ui pwd util: callback check data failed:%u.", (uint32_t)ret, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    *prompt = promptStr;
    return BSL_SUCCESS;
}

int32_t BSL_UI_ReadPwdUtil(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen,
    const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    char result[BSL_UI_READ_BUFF_MAX_LEN] = {0};
    char *promptStr = NULL;
    if (param == NULL || buff == NULL || buffLen == NULL || *buffLen == 0) {
        return BSL_NULL_INPUT;
    }
    BSL_UI *ui = BSL_UI_New(NULL);
    if (ui == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UI_CREATE_OBJECT_ERROR);
        return BSL_UI_CREATE_OBJECT_ERROR;
    }
    int32_t ret = ui->method->uiOpen(ui);
    if (ret != BSL_SUCCESS) {
        BSL_UI_Free(ui);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05083, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ui pwd util: open error:%u.", (uint32_t)ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    do {
        BSL_UI_DataPack readData = {0, 0, result, BSL_UI_READ_BUFF_MAX_LEN, NULL};
        ret = BSL_UI_OperInputData(ui, param, &readData, &promptStr, checkDataCallBack, callBackData);
        if (ret != BSL_SUCCESS) {
            break;
        }
        if (*buffLen < readData.dataLen) {
            ret = BSL_UI_OUTPUT_BUFF_TOO_SHORT;
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05066, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "ui pwd util: buff len is too short.", 0, 0, 0, 0);
            break;
        }
        if (param->verify) {
            ret = BSL_UI_OperVerifyData(ui, promptStr, &readData);
            if (ret != BSL_SUCCESS) {
                break;
            }
        }
        if (strcpy_s(buff, *buffLen, result) != EOK) {
            ret = BSL_UI_OUTPUT_BUFF_TOO_SHORT;
            break;
        }
        *buffLen = (uint32_t)strlen(buff) + 1;
    } while (0);
    ui->method->uiClose(ui);
    BSL_UI_Free(ui);
    BSL_SAL_FREE(promptStr);
    (void)memset_s(result, sizeof(result), 0, sizeof(result));
    return ret;
}

static int32_t BSL_UI_DataReadProcess(BSL_UI_DataPack *data, void *parg, uint32_t larg)
{
    if (parg == NULL || larg != sizeof(BSL_UI_CtrlRGetParam)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05062, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ui data process: read param larg error.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(BSL_UI_INVALID_DATA_ARG);
        return BSL_UI_INVALID_DATA_ARG;
    }
    BSL_UI_CtrlRGetParam *param = (BSL_UI_CtrlRGetParam *)parg;
    data->type = BSL_UI_DATA_READ;
    data->flags = param->flags;
    data->data = param->buff;
    data->dataLen = param->buffLen;
    data->verifyData = param->verifyBuff;
    return BSL_SUCCESS;
}

static int32_t BSL_UI_DataWriteProcess(BSL_UI_DataPack *data, void *parg, uint32_t larg)
{
    data->type = BSL_UI_DATA_WRITE;
    data->data = parg;
    data->dataLen = larg;
    return BSL_SUCCESS;
}

BSL_UI_DataPack *BSL_UI_DataPackNew(void)
{
    BSL_UI_DataPack *data = (BSL_UI_DataPack *)BSL_SAL_Malloc(sizeof(BSL_UI_DataPack));
    if (data == NULL) {
        return NULL;
    }
    (void)memset_s(data, sizeof(BSL_UI_DataPack), 0, sizeof(BSL_UI_DataPack));
    return data;
}

void BSL_UI_DataPackFree(BSL_UI_DataPack *data)
{
    if (data == NULL) {
        return;
    }
    BSL_SAL_FREE(data);
}

int32_t BSL_UI_DataCtrl(BSL_UI_DataPack *data, uint32_t type, void *parg, uint32_t larg)
{
    int32_t ret = BSL_UI_INVALID_DATA_TYPE;
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    switch (type) {
        case BSL_UI_DATA_READ:
            ret = BSL_UI_DataReadProcess(data, parg, larg);
            break;
        case BSL_UI_DATA_WRITE:
            ret = BSL_UI_DataWriteProcess(data, parg, larg);
            break;
        default:
            break;
    }
    return ret;
}

int32_t BSL_UI_GetDataResult(BSL_UI_DataPack *data, char **result, uint32_t *resultLen)
{
    if (data == NULL || result == NULL || resultLen == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (data->data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UI_INVALID_DATA_RESULT);
        return BSL_UI_INVALID_DATA_RESULT;
    }
    *result = data->data;
    *resultLen = data->dataLen;
    return BSL_SUCCESS;
}
#endif /* HITLS_BSL_UI */

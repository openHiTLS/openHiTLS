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
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include "hlt.h"
#include "handle_cmd.h"
#include "tls_res.h"
#include "logger.h"
#include "lock.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "tls.h"
#include "alert.h"
#include "hitls.h"
#include "common_func.h"
#include "sctp_channel.h"
#include "rpc_func.h"

#define HITLS_READBUF_MAXLEN (20 * 1024) /* 20K */
#define SUCCESS 0
#define ERROR (-1)

#define ASSERT_RETURN(condition)          \
    do {                                  \
        if (!(condition)) {               \
            LOG_ERROR("snprintf Error"); \
            return ERROR;                 \
        }                                 \
    } while (0)

RpcFunList g_rpcFuncList[] = {
#ifdef HITLS_TLS_FEATURE_PROVIDER
    {"HLT_RpcProviderTlsNewCtx", RpcProviderTlsNewCtx},
#else
    {"HLT_RpcTlsNewCtx", RpcTlsNewCtx},
#endif
    {"HLT_RpcTlsSetCtx", RpcTlsSetCtx},
    {"HLT_RpcTlsNewSsl", RpcTlsNewSsl},
    {"HLT_RpcTlsSetSsl", RpcTlsSetSsl},
    {"HLT_RpcTlsListen", RpcTlsListen},
    {"HLT_RpcTlsAccept", RpcTlsAccept},
    {"HLT_RpcTlsConnect", RpcTlsConnect},
    {"HLT_RpcTlsRead", RpcTlsRead},
    {"HLT_RpcTlsWrite", RpcTlsWrite},
    {"HLT_RpcTlsRenegotiate", RpcTlsRenegotiate},
    {"HLT_RpcDataChannelAccept", RpcDataChannelAccept},
    {"HLT_RpcDataChannelConnect", RpcDataChannelConnect},
    {"HLT_RpcProcessExit", RpcProcessExit},
    {"HLT_RpcTlsRegCallback", RpcTlsRegCallback},
    {"HLT_RpcTlsGetStatus", RpcTlsGetStatus},
    {"HLT_RpcTlsGetAlertFlag", RpcTlsGetAlertFlag},
    {"HLT_RpcTlsGetAlertLevel", RpcTlsGetAlertLevel},
    {"HLT_RpcTlsGetAlertDescription", RpcTlsGetAlertDescription},
    {"HLT_RpcTlsClose", RpcTlsClose},
    {"HLT_RpcFreeResFormSsl", RpcFreeResFormSsl},
    {"HLT_RpcCloseFd", RpcCloseFd},
    {"HLT_RpcTlsSetMtu", RpcTlsSetMtu},
    {"HLT_RpcTlsGetErrorCode", RpcTlsGetErrorCode},
    {"HLT_RpcDataChannelBind", RpcDataChannelBind},
    {"HLT_RpcTlsVerifyClientPostHandshake", RpcTlsVerifyClientPostHandshake},
    {"HLT_RpcTlsWriteExportMaterial", RpcTlsWriteExportMaterial},
};

RpcFunList *GetRpcFuncList(void)
{
    return g_rpcFuncList;
}

int GetRpcFuncNum(void)
{
    return sizeof(g_rpcFuncList) / sizeof(g_rpcFuncList[0]);
}

#ifdef HITLS_TLS_FEATURE_PROVIDER
/**
 * Parse the provider string in format "name1,fmt1:name2,fmt2:...:nameN,fmtN"
 */
static int ParseProviderString(const char *providerStr, char (*providerNames)[MAX_PROVIDER_NAME_LEN],
    int32_t *providerLibFmts, int32_t *providerCnt)
{
    if (providerStr == NULL) {
        LOG_DEBUG("Provider names is NULL");
        return SUCCESS;
    }

    if (providerLibFmts == NULL || providerCnt == NULL) {
        LOG_ERROR("Invalid input parameters");
        return ERROR;
    }

    int count = 1;
    const char *ptr = providerStr;
    while (*ptr) {
        if (*ptr == ':') {
            count++;
        }
        ptr++;
    }
    *providerCnt = count;
    if (count == 0) {
        LOG_ERROR("Provider string is empty");
        return SUCCESS;
    }
    
    char *tempStr = strdup(providerStr);
    if (tempStr == NULL) {
        LOG_ERROR("Failed to duplicate provider string");
        return ERROR;
    }

    char *saveptr1 = NULL;
    char *saveptr2 = NULL;
    char *token = strtok_r(tempStr, ":", &saveptr1);
    int i = 0;

    while (token != NULL && i < count) {
        char *name = strtok_r(token, ",", &saveptr2);
        char *fmt = strtok_r(NULL, ",", &saveptr2);

        if (name == NULL || fmt == NULL) {
            LOG_ERROR("Invalid provider format");
            free(tempStr);
            return ERROR;
        }

        {
            int n = snprintf(providerNames[i], MAX_PROVIDER_NAME_LEN, "%s", name);
            if (n < 0 || (size_t)n >= MAX_PROVIDER_NAME_LEN) {
                LOG_ERROR("Failed to allocate memory for provider name");
                free(tempStr);
                return ERROR;
            }
        }

        providerLibFmts[i] = atoi(fmt);

        token = strtok_r(NULL, ":", &saveptr1);
        i++;
    }

    free(tempStr);
    return SUCCESS;
}

int RpcProviderTlsNewCtx(CmdData *cmdData)
{
    int id, n;
    TLS_VERSION tlsVersion;
    memset(cmdData->result, 0, sizeof(cmdData->result));

    tlsVersion = atoi(cmdData->paras[0]);
    char *providerNames = strlen(cmdData->paras[2]) > 0 ? cmdData->paras[2] : NULL;
    char *attrName = strlen(cmdData->paras[3]) > 0 ? cmdData->paras[3] : NULL;
    char *providerPath = strlen(cmdData->paras[4]) > 0 ? cmdData->paras[4] : NULL;
    char parsedProviderNames[MAX_PROVIDER_COUNT][MAX_PROVIDER_NAME_LEN] = {0};
    int32_t providerLibFmts[MAX_PROVIDER_COUNT] = {0};
    int32_t providerCnt = 0;
    
    if (ParseProviderString(providerNames, parsedProviderNames, providerLibFmts, &providerCnt) != SUCCESS) {
        LOG_ERROR("Failed to parse provider string");
        id = ERROR;
        goto EXIT;
    }

    // Invoke the corresponding function.
    void *ctx = HLT_TlsProviderNewCtx(providerPath, parsedProviderNames, providerLibFmts, providerCnt, attrName,
        tlsVersion);
    if (ctx == NULL) {
        LOG_ERROR("HLT_TlsProviderNewCtx Return NULL");
        id = ERROR;
        goto EXIT;
    }

    // Insert to CTX linked list
    id = InsertCtxToList(ctx);

EXIT:
    // Return Result
    n = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, id);
    if (n < 0 || (size_t)n >= sizeof(cmdData->result)) {
        return ERROR;
    }
    return SUCCESS;
}
#endif

int RpcTlsNewCtx(CmdData *cmdData)
{
    int id, n;
    TLS_VERSION tlsVersion;
    memset(cmdData->result, 0, sizeof(cmdData->result));

    tlsVersion = atoi(cmdData->paras[0]);
    // Invoke the corresponding function.
    void* ctx = HLT_TlsNewCtx(tlsVersion);
    if (ctx == NULL) {
        LOG_ERROR("HLT_TlsNewCtx Return NULL");
        id = ERROR;
        goto EXIT;
    }

    // Insert to CTX linked list
    id = InsertCtxToList(ctx);

EXIT:
    // Return Result
    n = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, id);
    if (n < 0 || (size_t)n >= sizeof(cmdData->result)) {
        return ERROR;
    }
    return SUCCESS;
}

int RpcTlsSetCtx(CmdData *cmdData)
{
    int ret;
    memset(cmdData->result, 0, sizeof(cmdData->result));

    // Find the corresponding CTX.
    ResList *ctxList = GetCtxList();
    int ctxId = atoi(cmdData->paras[0]);
    void *ctx = GetTlsResFromId(ctxList, ctxId);
    if (ctx == NULL) {
        LOG_ERROR("GetResFromId Error");
        ret = ERROR;
        goto EXIT;
    }

    // Configurations related to parsing
    HLT_Ctx_Config ctxConfig = {0};
    ret = ParseCtxConfigFromString(cmdData->paras, &ctxConfig);
    if (ret != SUCCESS) {
        LOG_ERROR("ParseCtxConfigFromString Error");
        ret = ERROR;
        goto EXIT;
    }

    // Configure the data
    ret = HLT_TlsSetCtx(ctx, &ctxConfig);

EXIT:
    // Return the result
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsNewSsl(CmdData *cmdData)
{
    int id, ret;
    memset(cmdData->result, 0, sizeof(cmdData->result));

    // Invoke the corresponding function.
    ResList *ctxList = GetCtxList();
    int ctxId = atoi(cmdData->paras[0]);
    void *ctx = GetTlsResFromId(ctxList, ctxId);
    if (ctx == NULL) {
        LOG_ERROR("Not Find Ctx");
        id = ERROR;
        goto EXIT;
    }

    void *ssl = HLT_TlsNewSsl(ctx);
    if (ssl == NULL) {
        LOG_ERROR("HLT_TlsNewSsl Return NULL");
        id = ERROR;
        goto EXIT;
    }

    // Insert to the SSL linked list.
    id = InsertSslToList(ctx, ssl);

EXIT:
    // Return the result.
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, id);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsSetSsl(CmdData *cmdData)
{
    int ret;

    memset(cmdData->result, 0, sizeof(cmdData->result));

    ResList *sslList = GetSslList();
    int sslId = atoi(cmdData->paras[0]);
    void *ssl = GetTlsResFromId(sslList, sslId);
    if (ssl == NULL) {
        LOG_ERROR("Not Find Ssl");
        ret = ERROR;
        goto EXIT;
    }

    HLT_Ssl_Config sslConfig = {0};
    sslConfig.sockFd = atoi(cmdData->paras[1]); // The first parameter indicates the FD value.
    sslConfig.connType = atoi(cmdData->paras[2]); // The second parameter indicates the link type.
    // The third parameter of indicates the Ctrl command that needs to register the hook.
    sslConfig.connPort = atoi(cmdData->paras[3]);
    ret = HLT_TlsSetSsl(ssl, &sslConfig);
EXIT:
    // Return the result.
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsListen(CmdData *cmdData)
{
    int ret;
    int sslId;
    memset(cmdData->result, 0, sizeof(cmdData->result));
    ResList *sslList = GetSslList();
    sslId = strtol(cmdData->paras[0], NULL, 10); // Convert to a decimal number
    void *ssl = GetTlsResFromId(sslList, sslId);
    if (ssl == NULL) {
        LOG_ERROR("Not Find Ssl");
        ret = ERROR;
        goto EXIT;
    }

    ret = HLT_TlsListenBlock(ssl);

EXIT:
    // Return the result
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsAccept(CmdData *cmdData)
{
    int ret;

    memset(cmdData->result, 0, sizeof(cmdData->result));
    ResList *sslList = GetSslList();
    int sslId = atoi(cmdData->paras[0]);
    void *ssl = GetTlsResFromId(sslList, sslId);
    if (ssl == NULL) {
        LOG_ERROR("Not Find Ssl");
        ret = ERROR;
        goto EXIT;
    }

    // If there is a problem, the user must use non-blocking, and the remote call must use blocking
    ret = HLT_TlsAcceptBlock(ssl);

EXIT:
    // Return the result
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsConnect(CmdData *cmdData)
{
    int ret;

    memset(cmdData->result, 0, sizeof(cmdData->result));

    ResList *sslList = GetSslList();
    int sslId = atoi(cmdData->paras[0]);
    void *ssl = GetTlsResFromId(sslList, sslId);
    if (ssl == NULL) {
        LOG_ERROR("Not Find Ssl");
        ret = ERROR;
        goto EXIT;
    }

    ret = HLT_TlsConnect(ssl);

EXIT:
    // Return the result
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsRead(CmdData *cmdData)
{
    int ret = SUCCESS;

    memset(cmdData->result, 0, sizeof(cmdData->result));
    ResList *sslList = GetSslList();
    int sslId = atoi(cmdData->paras[0]);
    void *ssl = GetTlsResFromId(sslList, sslId);
    if (ssl == NULL) {
        LOG_ERROR("Not Find Ssl");
        ret = ERROR;
        goto ERR;
    }

    int dataLen = atoi(cmdData->paras[1]);
    uint32_t readLen = 0;
    if (dataLen == 0) {
        LOG_ERROR("dataLen is 0");
        ret = ERROR;
        goto ERR;
    }
    uint8_t *data = (uint8_t *)calloc(1u, dataLen);
    if (data == NULL) {
        LOG_ERROR("Calloc Error");
        ret = ERROR;
        goto ERR;
    }
    ret = HLT_TlsRead(ssl, data, dataLen, &readLen);

    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d|%u|%s",
                    cmdData->id, cmdData->funcId, ret, readLen, data);
    free(data);
    if (ret < 0 || (size_t)ret >= sizeof(cmdData->result)) {
        return ERROR;
    }
    return SUCCESS;
ERR:
    // Return the result
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d|", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsWrite(CmdData *cmdData)
{
    int ret;
    memset(cmdData->result, 0, sizeof(cmdData->result));

    ResList *sslList = GetSslList();
    int sslId = atoi(cmdData->paras[0]);
    void *ssl = GetTlsResFromId(sslList, sslId);
    if (ssl == NULL) {
        LOG_ERROR("Not Find Ssl");
        ret = ERROR;
        goto ERR;
    }

    int dataLen = atoi(cmdData->paras[1]); // The first parameter indicates the data length.
    if (dataLen == 0) {
        LOG_ERROR("dataLen is 0");
        ret = ERROR;
        goto ERR;
    }
    uint8_t *data = (uint8_t *)calloc(1u, dataLen);
    if (data == NULL) {
        LOG_ERROR("Calloc Error");
        ret = ERROR;
        goto ERR;
    }
    if (dataLen >= CONTROL_CHANNEL_MAX_MSG_LEN) {
        free(data);
        ret = ERROR;
        goto ERR;
    }
    // The second parameter of indicates the content of the write data.
    memcpy(data, cmdData->paras[2], dataLen);
    ret = HLT_TlsWrite(ssl, data, dataLen);
    free(data);
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
ERR:
    // Return the result
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsRenegotiate(CmdData *cmdData)
{
    int ret = ERROR;
    ResList *sslList = GetSslList();
    int sslId = (int)strtol(cmdData->paras[0], NULL, 10); // Convert to a decimal number
    void *ssl = GetTlsResFromId(sslList, sslId);
    if (ssl == NULL) {
        LOG_ERROR("Not Find Ssl");
        goto EXIT;
    }

    ret = HLT_TlsRenegotiate(ssl);

EXIT:
    // Return the result
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsVerifyClientPostHandshake(CmdData *cmdData)
{
    int ret = ERROR;
    ResList *sslList = GetSslList();
    int sslId = (int)strtol(cmdData->paras[0], NULL, 10); // Convert to a decimal number
    void *ssl = GetTlsResFromId(sslList, sslId);
    if (ssl == NULL) {
        LOG_ERROR("Not Find Ssl");
        goto EXIT;
    }

    ret = HLT_TlsVerifyClientPostHandshake(ssl);

EXIT:
    // Return Result
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcProcessExit(CmdData *cmdData)
{
    int ret;
    // If 1 is returned, the process needs to exit
    memset(cmdData->result, 0, sizeof(cmdData->result));
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, getpid());
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return 1;
}

int RpcDataChannelAccept(CmdData *cmdData)
{
    int sockFd, ret;
    DataChannelParam channelParam;

    memset(cmdData->result, 0, sizeof(cmdData->result));
    memset(&channelParam, 0, sizeof(DataChannelParam));

    channelParam.type = atoi(cmdData->paras[0]);
    channelParam.port = atoi(cmdData->paras[1]); // The first parameter of indicates the port number
    channelParam.isBlock = atoi(cmdData->paras[2]); // The second parameter of indicates whether to block
    channelParam.bindFd = atoi(cmdData->paras[3]); // The third parameter of indicates whether the cis blocked.

    // Invoke the blocking interface
    sockFd = RunDataChannelAccept(&channelParam);

    // Return the result.
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, sockFd);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcDataChannelBind(CmdData *cmdData)
{
    int sockFd, ret;
    DataChannelParam channelParam;

    memset(cmdData->result, 0, sizeof(cmdData->result));
    memset(&channelParam, 0, sizeof(DataChannelParam));

    channelParam.type = atoi(cmdData->paras[0]);
    channelParam.port = atoi(cmdData->paras[1]); // The first parameter of  indicates the port number
    channelParam.isBlock = atoi(cmdData->paras[2]); // The second parameter of indicates whether to block
    channelParam.bindFd = atoi(cmdData->paras[3]); // The third parameter of indicates whether the cis blocked.

    // Invoke the blocking interface
    sockFd = RunDataChannelBind(&channelParam);

    // Return the result.
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d|%d", cmdData->id, cmdData->funcId,
        sockFd, channelParam.port);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}


int RpcDataChannelConnect(CmdData *cmdData)
{
    int ret, sockFd;
    DataChannelParam channelParam;

    memset(cmdData->result, 0, sizeof(cmdData->result));
    memset(&channelParam, 0, sizeof(DataChannelParam));

    channelParam.type = atoi(cmdData->paras[0]);
    channelParam.port = atoi(cmdData->paras[1]); // The first parameter of  indicates the port number.
    channelParam.isBlock = atoi(cmdData->paras[2]); // The second parameter of indicates whether the is blocked

    sockFd = HLT_DataChannelConnect(&channelParam);

    // Return the result.
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, sockFd);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsRegCallback(CmdData *cmdData)
{
    int ret;
    TlsCallbackType type;
    memset(cmdData->result, 0, sizeof(cmdData->result));

    type = atoi(cmdData->paras[0]);
    // Invoke the corresponding function
    ret = HLT_TlsRegCallback(type);

    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsGetStatus(CmdData *cmdData)
{
    int ret, sslId;
    uint32_t sslState = 0;
    memset(cmdData->result, 0, sizeof(cmdData->result));

    ResList *sslList = GetSslList();
    sslId = atoi(cmdData->paras[0]);
    void *ssl = GetTlsResFromId(sslList, sslId);
    if (ssl != NULL) {
        sslState = ((HITLS_Ctx *)ssl)->state;
    }

    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%u", cmdData->id, cmdData->funcId, sslState);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsGetAlertFlag(CmdData *cmdData)
{
    int ret, sslId;
    ALERT_Info alertInfo = {0};
    memset(cmdData->result, 0, sizeof(cmdData->result));

    ResList *sslList = GetSslList();
    sslId = atoi(cmdData->paras[0]);
    void *ssl = GetTlsResFromId(sslList, sslId);
    if (ssl != NULL) {
        ALERT_GetInfo(ssl, &alertInfo);
    }

    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d",
        cmdData->id, cmdData->funcId, alertInfo.flag);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsGetAlertLevel(CmdData *cmdData)
{
    int ret, sslId;
    ALERT_Info alertInfo = {0};
    memset(cmdData->result, 0, sizeof(cmdData->result));

    ResList *sslList = GetSslList();
    sslId = atoi(cmdData->paras[0]);
    void *ssl = GetTlsResFromId(sslList, sslId);
    if (ssl != NULL) {
        ALERT_GetInfo(ssl, &alertInfo);
    }

    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d",
        cmdData->id, cmdData->funcId, alertInfo.level);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsGetAlertDescription(CmdData *cmdData)
{
    int ret, sslId;
    ALERT_Info alertInfo = {0};
    memset(cmdData->result, 0, sizeof(cmdData->result));

    ResList *sslList = GetSslList();
    sslId = atoi(cmdData->paras[0]);
    void *ssl = GetTlsResFromId(sslList, sslId);
    if (ssl != NULL) {
        ALERT_GetInfo(ssl, &alertInfo);
    }

    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d",
        cmdData->id, cmdData->funcId, alertInfo.description);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsClose(CmdData *cmdData)
{
    int ret, sslId;
    void *ssl = NULL;
    char *endPtr = NULL;

    memset(cmdData->result, 0, sizeof(cmdData->result));
    ResList *sslList = GetSslList();
    sslId = (int)strtol(cmdData->paras[0], &endPtr, 0);
    ssl = GetTlsResFromId(sslList, sslId);
    ASSERT_RETURN(ssl != NULL);

    ret = HLT_TlsClose(ssl);

    // Return the result
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcFreeResFormSsl(CmdData *cmdData)
{
    int ret, sslId;
    void *ssl = NULL;
    char *endPtr = NULL;

    memset(cmdData->result, 0, sizeof(cmdData->result));
    ResList *sslList = GetSslList();
    sslId = (int)strtol(cmdData->paras[0], &endPtr, 0);
    ssl = GetTlsResFromId(sslList, sslId);
    ASSERT_RETURN(ssl != NULL);

    ret = HLT_FreeResFromSsl(ssl);

    // Return the result
    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcCloseFd(CmdData *cmdData)
{
    int ret, fd, linkType;
    char *endPtr = NULL;
    memset(cmdData->result, 0, sizeof(cmdData->result));

    fd = (int)strtol(cmdData->paras[0], &endPtr, 0);
    linkType = (int)strtol(cmdData->paras[1], &endPtr, 0);

    ret = SUCCESS;
    HLT_CloseFd(fd, linkType);

    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsSetMtu(CmdData *cmdData)
{
    int ret, sslId;
    uint16_t mtu;
    void *ssl = NULL;
    char *endPtr = NULL;
    memset(cmdData->result, 0, sizeof(cmdData->result));

    ResList *sslList = GetSslList();
    sslId = (int)strtol(cmdData->paras[0], &endPtr, 0);
    mtu = (int)strtol(cmdData->paras[1], &endPtr, 0);
    ssl = GetTlsResFromId(sslList, sslId);
    ASSERT_RETURN(ssl != NULL);

    ret = HLT_TlsSetMtu(ssl, mtu);

    ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

int RpcTlsGetErrorCode(CmdData *cmdData)
{
    int sslId;
    int errorCode;
    void *ssl = NULL;
    char *endPtr = NULL;
    memset(cmdData->result, 0, sizeof(cmdData->result));

    ResList *sslList = GetSslList();
    sslId = (int)strtol(cmdData->paras[0], &endPtr, 0);
    ssl = GetTlsResFromId(sslList, sslId);
    ASSERT_RETURN(ssl != NULL);

    errorCode = HLT_TlsGetErrorCode(ssl);

    int ret = snprintf(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, errorCode);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}

static uint8_t *Convert2Buf(char *buf, size_t *len)
{
    static uint8_t ret[MAX_EXPORT_MATERIAL_BUF] = {0};
    memset(ret, 0, MAX_EXPORT_MATERIAL_BUF);
    if (strcmp(buf, "NULL") == 0) {
        *len = 0;
        return NULL;
    }
    size_t bufLen = strlen(buf) / 2;
    if (bufLen > MAX_EXPORT_MATERIAL_BUF) {
        *len = 0;
        return NULL;
    }
    for (size_t i = 0; i < bufLen; ++i) {
        size_t tmpVal = 0;
#if (__SIZEOF_SIZE_T__ == 8)
        sscanf(&buf[i * 2], "%02lx", &tmpVal);
#else
        sscanf(&buf[i * 2], "%02x", &tmpVal);
#endif
        ret[i] = tmpVal;
    }
    *len = bufLen;
    return ret;
}

static void Convert2Data(const char *buf, ExportMaterialParam *data)
{
#if (__SIZEOF_SIZE_T__ == 8)
    sscanf(buf, "outLen=%lu label=%s labelLen=%lu context=%s contextLen=%lu useContext=%d",
        &data->outLen, data->label, &data->labelLen,
        data->context, &data->contextLen, &data->useContext);
#else
    sscanf(buf, "outLen=%u label=%s labelLen=%u context=%s contextLen=%u useContext=%d",
        &data->outLen, data->label, &data->labelLen,
        data->context, &data->contextLen, &data->useContext);
#endif

    size_t len = 0;
    uint8_t *value = Convert2Buf(data->label, &len);
    if (value != NULL) {
        memset(data->label, 0, MAX_EXPORT_MATERIAL_BUF);
        if (len <= MAX_EXPORT_MATERIAL_BUF) {
            memcpy(data->label, value, len);
        }
    }
    value = Convert2Buf(data->context, &len);
    if (value != NULL) {
        memset(data->context, 0, MAX_EXPORT_MATERIAL_BUF);
        if (len <= MAX_EXPORT_MATERIAL_BUF) {
            memcpy(data->context, value, len);
        }
    }
    return;
}

int RpcTlsWriteExportMaterial(CmdData *cmdData)
{
    int ret;
    memset(cmdData->result, 0, sizeof(cmdData->result));

    ResList *sslList = GetSslList();
    int sslId = atoi((char *)cmdData->paras[0]);
    void *ssl = GetTlsResFromId(sslList, sslId);
    if (ssl == NULL) {
        LOG_ERROR("Not Find Ssl");
        ret = ERROR;
        goto ERR;
    }
    ExportMaterialParam param = {0};
    Convert2Data((char *)cmdData->paras[1], &param);
    ret =  HLT_TLSWriteExportMaterial(ssl, &param);
    ret = snprintf((char *)cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
ERR:
    // Return the result
    ret = snprintf((char *)cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ret);
    ASSERT_RETURN(ret >= 0 && (size_t)ret < sizeof(cmdData->result));
    return SUCCESS;
}
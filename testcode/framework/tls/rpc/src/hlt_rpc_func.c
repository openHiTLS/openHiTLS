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

#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include "logger.h"
#include "process.h"
#include "hlt_type.h"
#include "control_channel.h"
#include "channel_res.h"
#include "handle_cmd.h"
#include "securec.h"

#define SUCCESS 0
#define ERROR (-1)

uint64_t g_cmdIndex = 0;
pthread_mutex_t g_cmdMutex = PTHREAD_MUTEX_INITIALIZER;

#define ASSERT_RETURN(condition, log) \
    do {                              \
        if (!(condition)) {           \
            LOG_ERROR(log);           \
            return ERROR;             \
        }                             \
    } while (0)

void InitCmdIndex(void)
{
    g_cmdIndex = 0;
}

static int WaitResult(CmdData *expectCmdData, int cmdIndex, const char *funcName)
{
    int ret;
    ret = sprintf_s(expectCmdData->id, sizeof(expectCmdData->id), "%d", cmdIndex);
    ASSERT_RETURN(ret > 0, "sprintf_s Error");
    ret = sprintf_s(expectCmdData->funcId, sizeof(expectCmdData->funcId), "%s", funcName);
    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    // Receive the result.
    ret = WaitResultFromPeer(expectCmdData);
    ASSERT_RETURN(ret == SUCCESS, "WaitResultFromPeer Error");
    return SUCCESS;
}

int HLT_RpcProviderTlsNewCtx(HLT_Process *peerProcess, TLS_VERSION tlsVersion, bool isClient, char *providerPath,
    char (*providerNames)[MAX_PROVIDER_NAME_LEN], int32_t *providerLibFmts, int32_t providerCnt, char *attrName)
{
    int ret;
    uint64_t cmdIndex;
    Process *srcProcess = NULL;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;
    uint32_t offset = 0;

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsNewCtx");

    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data),
        "%llu|%s|%d|%d|",
        g_cmdIndex, __FUNCTION__, tlsVersion, isClient);
    ASSERT_RETURN(ret > 0, "sprintf_s Error");
    offset += ret;
    if (providerCnt == 0 || providerNames == NULL || providerLibFmts == NULL) {
        ret = sprintf_s(dataBuf.data + offset, sizeof(dataBuf.data) - offset, "|");
        ASSERT_RETURN(ret > 0, "sprintf_s Error");
        offset += ret;
    }

    for (int i = 0; i < providerCnt - 1; i++) {
        ret = sprintf_s(dataBuf.data + offset, sizeof(dataBuf.data) - offset, "%s,%d:", providerNames[i],
            providerLibFmts[i]);
        ASSERT_RETURN(ret > 0, "sprintf_s Error");
        offset += ret;
    }
    if (providerCnt >= 1) {
        ret = sprintf_s(dataBuf.data + offset, sizeof(dataBuf.data) - offset, "%s,%d|", providerNames[providerCnt - 1],
            providerLibFmts[providerCnt - 1]);
        ASSERT_RETURN(ret > 0, "sprintf_s Error");
        offset += ret;
    }
    if (attrName != NULL && strlen(attrName) > 0) {
        ret = sprintf_s(dataBuf.data + offset, sizeof(dataBuf.data) - offset, "%s|", attrName);
    } else {
        ret = sprintf_s(dataBuf.data + offset, sizeof(dataBuf.data) - offset, "|");
    }
    ASSERT_RETURN(ret > 0, "sprintf_s Error");
    offset += ret;
    if (providerPath != NULL && strlen(providerPath) > 0) {
        ret = sprintf_s(dataBuf.data + offset, sizeof(dataBuf.data) - offset, "%s|", providerPath);
    } else {
        ret = sprintf_s(dataBuf.data + offset, sizeof(dataBuf.data) - offset, "|");
    }
    ASSERT_RETURN(ret > 0, "sprintf_s Error");
    offset += ret;

    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");

    return atoi(expectCmdData.paras[0]);
}

int HLT_RpcTlsNewCtx(HLT_Process *peerProcess, TLS_VERSION tlsVersion, bool isClient)
{
    int ret;
    uint64_t cmdIndex;
    Process *srcProcess = NULL;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsNewCtx");

    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d|%d", g_cmdIndex, __FUNCTION__, tlsVersion, isClient);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");

    return atoi(expectCmdData.paras[0]);
}

int HLT_RpcTlsSetCtx(HLT_Process *peerProcess, int ctxId, HLT_Ctx_Config *config)
{
    int ret;
    uint64_t cmdIndex;
    Process *srcProcess = NULL;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;

    ASSERT_RETURN(peerProcess->remoteFlag ==  1, "Only Remote Process Support Call HLT_RpcTlsSetCtx");

    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data),
    "%llu|%s|%d|"
    "%u|%u|%s|%s|"
    "%s|%s|%s|%d|"
    "%d|%d|%d|%s|"
    "%s|%s|%s|%s|"
    "%s|%s|%s|%d|"
    "%d|%s|%d|%s|"
    "%s|%s|%s|%s|"
    "%s|%d|%d|"
    "%u|%d|%d|"
    "%d|%d|%d|"
    "%d|%u|%d|%d|"
    "%u|%d",
    g_cmdIndex, __FUNCTION__, ctxId,
    config->minVersion, config->maxVersion, config->cipherSuites, config->tls13CipherSuites,
    config->pointFormats, config->groups, config->signAlgorithms, config->isSupportRenegotiation,
    config->isSupportClientVerify, config->isSupportNoClientCert, config->isSupportExtendMasterSecret, config->eeCert,
    config->privKey, config->password, config->caCert, config->chainCert,
    config->signCert, config->signPrivKey, config->psk, config->isSupportSessionTicket,
    config->setSessionCache, config->ticketKeyCb, config->isFlightTransmitEnable, config->serverName,
    config->sniDealCb, config->sniArg, config->alpnList, config->alpnSelectCb,
    config->alpnUserData, config->securitylevel, config->isSupportDhAuto,
    config->keyExchMode, config->SupportType, config->isSupportPostHandshakeAuth,
    config->readAhead, config->needCheckKeyUsage, config->isSupportVerifyNone,
    config->allowClientRenegotiate, config->emptyRecordsNum, config->allowLegacyRenegotiate, config->isEncryptThenMac,
    config->modeSupport, config->isSupportDtlsCookieExchange);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd,  peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Wait to receive the result.
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return atoi(expectCmdData.paras[0]);
}

int HLT_RpcTlsNewSsl(HLT_Process *peerProcess, int ctxId)
{
    int ret;
    uint64_t cmdIndex;
    CmdData expectCmdData = {0};
    Process *srcProcess = NULL;
    ControlChannelBuf dataBuf;

    ASSERT_RETURN(peerProcess->remoteFlag ==  1, "Only Remote Process Support Call HLT_RpcTlsNewSsl");

    // Constructing Commands
    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, ctxId);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd,  peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Wait to receive the result.
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return atoi(expectCmdData.paras[0]);
}

int HLT_RpcTlsSetSsl(HLT_Process *peerProcess, int sslId, HLT_Ssl_Config *config)
{
    int ret;
    uint64_t cmdIndex;
    Process *srcProcess = NULL;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;

    ASSERT_RETURN(peerProcess->remoteFlag ==  1, "Only Remote Process Support Call HLT_RpcTlsSetSsl");

    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d|%d|%d|%d",
                    g_cmdIndex, __FUNCTION__, sslId, config->sockFd, config->connType, config->connPort);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd,  peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Wait to receive the result.
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return atoi(expectCmdData.paras[0]);
}

int HLT_RpcTlsListen(HLT_Process *peerProcess, int sslId)
{
    int ret;
    uint64_t acceptId;
    Process *srcProcess = NULL;
    ControlChannelBuf dataBuf;
    srcProcess = GetProcess();

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsListen");

    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, sslId);
    dataBuf.dataLen = strlen(dataBuf.data);
    acceptId = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd,  peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");
    return acceptId;
}

int HLT_RpcTlsAccept(HLT_Process *peerProcess, int sslId)
{
    int ret;
    uint64_t acceptId;
    Process *srcProcess = NULL;
    ControlChannelBuf dataBuf;
    srcProcess = GetProcess();

    ASSERT_RETURN(peerProcess->remoteFlag ==  1, "Only Remote Process Support Call HLT_RpcTlsAccept");

    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, sslId);
    dataBuf.dataLen = strlen(dataBuf.data);
    acceptId = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd,  peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");
    return acceptId;
}

int HLT_RpcGetTlsListenResult(int acceptId)
{
    int ret;
    CmdData expectCmdData = {0};
    ret = WaitResult(&expectCmdData, acceptId, "HLT_RpcTlsListen");
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return (int)strtol(expectCmdData.paras[0], NULL, 10); // Convert to a decimal number
}

int HLT_RpcGetTlsAcceptResult(int acceptId)
{
    int ret;
    char *endPtr = NULL;
    CmdData expectCmdData = {0};
    ret = WaitResult(&expectCmdData, acceptId, "HLT_RpcTlsAccept");
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return (int)strtol(expectCmdData.paras[0], &endPtr, 0);
}

int HLT_RpcTlsConnect(HLT_Process *peerProcess, int sslId)
{
    int ret;
    uint64_t cmdIndex;
    Process *srcProcess = NULL;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;

    ASSERT_RETURN(peerProcess->remoteFlag ==  1, "Only Remote Process Support Call HLT_RpcTlsConnect");

    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, sslId);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd,  peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Waiting for the result returned by the peer
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");

    return atoi(expectCmdData.paras[0]);
}

int HLT_RpcTlsConnectUnBlock(HLT_Process *peerProcess, int sslId)
{
    uint64_t cmdIndex;
    Process *srcProcess = NULL;
    ControlChannelBuf dataBuf;

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsConnect");

    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    int ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, "HLT_RpcTlsConnect", sslId);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    return cmdIndex;
}

int HLT_RpcGetTlsConnectResult(int cmdIndex)
{
    int ret;
    CmdData expectCmdData = {0};
    // Waiting for the result returned by the peer
    ret = WaitResult(&expectCmdData, cmdIndex, "HLT_RpcTlsConnect");
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");

    return atoi(expectCmdData.paras[0]);
}

int HLT_RpcTlsRead(HLT_Process *peerProcess, int sslId, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    int ret;
    uint64_t cmdIndex;
    Process *srcProcess = NULL;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsRead");

    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d|%u", g_cmdIndex, __FUNCTION__, sslId, bufSize);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Waiting for the result returned by the peer
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");

    // Parsing result
    ret = atoi(expectCmdData.paras[0]);
    if (ret == SUCCESS) {
        *readLen = atoi(expectCmdData.paras[1]);  // The first parameter indicates the read length.
        memcpy_s(
            data, bufSize, expectCmdData.paras[2], *readLen);  // The second parameter indicates the content to be read.
    }

    return ret;
}

int HLT_RpcTlsReadUnBlock(HLT_Process *peerProcess, int sslId, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    (void)data;
    (void)readLen;
    int ret;
    uint64_t cmdIndex;
    Process *srcProcess = NULL;
    ControlChannelBuf dataBuf;

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsRead");

    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d|%u", g_cmdIndex, "HLT_RpcTlsRead", sslId, bufSize);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    return cmdIndex;
}

int HLT_RpcGetTlsReadResult(int cmdIndex, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    int ret;
    char *endPtr = NULL;
    CmdData expectCmdData = {0};
    ret = WaitResult(&expectCmdData, cmdIndex, "HLT_RpcTlsRead");
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");

    // Parsing result
    ret = (int)strtol(expectCmdData.paras[0], &endPtr, 0);
    if (ret == SUCCESS) {
        *readLen = (int)strtol(expectCmdData.paras[1], &endPtr, 0); // The first parameter indicates the read length.
        // The second parameter indicates the content to be read.
        memcpy_s(data, bufSize, expectCmdData.paras[2], *readLen);
    }
    return ret;
}

int HLT_RpcTlsWrite(HLT_Process *peerProcess, int sslId, uint8_t *data, uint32_t bufSize)
{
    int ret;
    uint64_t cmdIndex;
    Process *srcProcess = NULL;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsWrite");

    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d|%u|%s",
                    g_cmdIndex, __FUNCTION__, sslId, bufSize, data);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Waiting for the result returned by the peer
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return atoi(expectCmdData.paras[0]);
}

int HLT_RpcTlsWriteUnBlock(HLT_Process *peerProcess, int sslId, uint8_t *data, uint32_t bufSize)
{
    int ret;
    uint64_t cmdIndex;
    Process *srcProcess = NULL;
    ControlChannelBuf dataBuf;

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsWrite");

    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d|%u|%s",
                    g_cmdIndex, "HLT_RpcTlsWrite", sslId, bufSize, data);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Do not wait for the result returned by the peer.
    return cmdIndex;
}

int HLT_RpcGetTlsWriteResult(int cmdIndex)
{
    int ret;
    CmdData expectCmdData = {0};

    ret = WaitResult(&expectCmdData, cmdIndex, "HLT_RpcTlsWrite");
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return (int)strtol(expectCmdData.paras[0], NULL, 10); // Convert to a decimal number
}

int HLT_RpcTlsRenegotiate(HLT_Process *peerProcess, int sslId)
{
    int ret;
    uint64_t cmdIndex;
    char *endPtr = NULL;
    Process *srcProcess = NULL;
    ControlChannelBuf dataBuf;
    CmdData expectCmdData = {0};
    srcProcess = GetProcess();

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsRenegotiate");

    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, sslId);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");
    // Waiting for the result
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return (int)strtol(expectCmdData.paras[0], &endPtr, 0);
}


int HLT_RpcTlsVerifyClientPostHandshake(HLT_Process *peerProcess, int sslId)
{
    int ret;
    uint64_t cmdIndex;
    char *endPtr = NULL;
    Process *srcProcess = NULL;
    ControlChannelBuf dataBuf;
    CmdData expectCmdData = {0};
    srcProcess = GetProcess();

    ASSERT_RETURN(peerProcess->remoteFlag ==  1, "Only Remote Process Support Call RpcTlsVerifyClientPostHandshake");

    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, sslId);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd,  peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");
    // Waiting for the result
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return (int)strtol(expectCmdData.paras[0], &endPtr, 0);
}

int HLT_RpcDataChannelConnect(HLT_Process *peerProcess, DataChannelParam *channelParam)
{
    int ret;
    uint64_t cmdIndex;
    Process *srcProcess = NULL;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcDataChannelConnect");

    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d|%d|%d", g_cmdIndex, __FUNCTION__,
                    channelParam->type, channelParam->port, channelParam->isBlock);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Waiting for the result returned by the peer
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");

    return atoi(expectCmdData.paras[0]);
}

int HLT_RpcDataChannelBind(HLT_Process *peerProcess, DataChannelParam *channelParam)
{
    int ret;
    uint64_t bindId;
    Process *srcProcess = NULL;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;
    ASSERT_RETURN(peerProcess->remoteFlag ==  1, "Only Remote Process Support Call HLT_RpcDataChannelBind");
    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d|%d|%d|%d", g_cmdIndex, __FUNCTION__,
                    channelParam->type, channelParam->port, channelParam->isBlock, channelParam->bindFd);
    dataBuf.dataLen = strlen(dataBuf.data);
    bindId = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);
    ASSERT_RETURN(ret > 0, "sprintf_s Error");
    ret = ControlChannelWrite(srcProcess->controlChannelFd,  peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Waiting for the result returned by the peer
    ret = WaitResult(&expectCmdData, bindId, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    channelParam->port = atoi(expectCmdData.paras[1]);
    return atoi(expectCmdData.paras[0]);
}

int HLT_RpcDataChannelAccept(HLT_Process *peerProcess, DataChannelParam *channelParam)
{
    int ret;
    uint64_t acceptId;
    Process *srcProcess = NULL;
    ControlChannelBuf dataBuf;

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcDataChannelAccept");

    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d|%d|%d|%d", g_cmdIndex, __FUNCTION__,
                    channelParam->type, channelParam->port, channelParam->isBlock, channelParam->bindFd);
    dataBuf.dataLen = strlen(dataBuf.data);
    acceptId = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");
    return acceptId;
}

int HLT_RpcGetAcceptFd(int acceptId)
{
    int ret;
    CmdData expectCmdData = {0};

    ret = WaitResult(&expectCmdData, acceptId, "HLT_RpcDataChannelAccept");
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");

    return atoi(expectCmdData.paras[0]);
}

int HLT_RpcTlsRegCallback(HLT_Process *peerProcess, TlsCallbackType type)
{
    int ret;
    uint64_t cmdIndex;
    Process *srcProcess;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsRegCallback");

    srcProcess = GetProcess();
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, type);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Waiting for the result
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return atoi(expectCmdData.paras[0]);
}

int HLT_RpcProcessExit(HLT_Process *peerProcess)
{
    int ret;
    uint64_t cmdIndex;
    Process *srcProcess;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;
    srcProcess = GetProcess();

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcProcessExit");

    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, peerProcess->connFd);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Waiting for the result
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return SUCCESS;
}

int HLT_RpcTlsGetStatus(HLT_Process *peerProcess, int sslId)
{
    ASSERT_RETURN(peerProcess != NULL, "HLT_RpcTlsGetStatus Parameter Error");
    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsGetStatus");

    int ret;
    uint64_t cmdIndex;
    char *endPtr = NULL;
    Process *srcProcess;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;
    srcProcess = GetProcess();

    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, sslId);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Waiting for the result
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return (int)strtol(expectCmdData.paras[0], &endPtr, 0);
}

int HLT_RpcTlsGetAlertFlag(HLT_Process *peerProcess, int sslId)
{
    ASSERT_RETURN(peerProcess != NULL, "HLT_RpcTlsGetAlertFlag Parameter Error");
    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcProcessExit");

    int ret;
    uint64_t cmdIndex;
    char *endPtr = NULL;
    Process *srcProcess;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;
    srcProcess = GetProcess();

    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, sslId);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Waiting for the result
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return (int)strtol(expectCmdData.paras[0], &endPtr, 0);
}

int HLT_RpcTlsGetAlertLevel(HLT_Process *peerProcess, int sslId)
{
    ASSERT_RETURN(peerProcess != NULL, "HLT_RpcTlsGetAlertLevel Parameter Error");
    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsGetAlertLevel");

    int ret;
    uint64_t cmdIndex;
    char *endPtr = NULL;
    Process *srcProcess;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;
    srcProcess = GetProcess();

    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, sslId);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Waiting for the result
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return (int)strtol(expectCmdData.paras[0], &endPtr, 0);
}

int HLT_RpcTlsGetAlertDescription(HLT_Process *peerProcess, int sslId)
{
    ASSERT_RETURN(peerProcess != NULL, "HLT_RpcTlsGetAlertDescription Parameter Error");
    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsGetAlertDescription");

    int ret;
    uint64_t cmdIndex;
    char *endPtr = NULL;
    Process *srcProcess;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;
    srcProcess = GetProcess();

    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, sslId);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Waiting for the result
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return (int)strtol(expectCmdData.paras[0], &endPtr, 0);
}

int HLT_RpcTlsClose(HLT_Process *peerProcess, int sslId)
{
    int ret;
    uint64_t cmdIndex;
    char *endPtr = NULL;
    Process *srcProcess = NULL;
    ControlChannelBuf dataBuf;
    CmdData expectCmdData = {0};
    srcProcess = GetProcess();

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsClose");

    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, sslId);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");
    // Waiting for the result
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return (int)strtol(expectCmdData.paras[0], &endPtr, 0);
}

int HLT_RpcFreeResFormSsl(HLT_Process *peerProcess, int sslId)
{
    int ret;
    uint64_t cmdIndex;
    char *endPtr = NULL;
    Process *srcProcess = NULL;
    ControlChannelBuf dataBuf;
    CmdData expectCmdData = {0};
    srcProcess = GetProcess();

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcFreeResFormSsl");

    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, sslId);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");
    // Waiting for the result
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return (int)strtol(expectCmdData.paras[0], &endPtr, 0);
}

int HLT_RpcSctpClose(HLT_Process *peerProcess, int fd)
{
    int ret;
    uint64_t cmdIndex;
    char *endPtr = NULL;
    Process *srcProcess = NULL;
    ControlChannelBuf dataBuf;
    CmdData expectCmdData = {0};
    srcProcess = GetProcess();

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcSctpClose");

    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, fd);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");
    // Waiting for the result
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return (int)strtol((const char *)expectCmdData.paras[0], &endPtr, 0);
}

int HLT_RpcCloseFd(HLT_Process *peerProcess, int fd, int linkType)
{
    int ret;
    uint64_t cmdIndex;
    Process *srcProcess = NULL;
    ControlChannelBuf dataBuf;
    srcProcess = GetProcess();

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcCloseFd");
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d|%d", g_cmdIndex, __FUNCTION__, fd, linkType);

    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");
    // The close fd does not need to wait for the result.
    return ret;
}

int HLT_RpcTlsSetMtu(HLT_Process *peerProcess, int sslId, uint16_t mtu)
{
    int ret;
    uint64_t cmdIndex;
    char *endPtr = NULL;
    Process *srcProcess = NULL;
    ControlChannelBuf dataBuf;
    CmdData expectCmdData = {0};
    srcProcess = GetProcess();

    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsSetMtu");
    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d|%d", g_cmdIndex, __FUNCTION__, sslId, mtu);

    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");
    // Waiting for the result
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return (int)strtol(expectCmdData.paras[0], &endPtr, 0);
}

int HLT_RpcTlsGetErrorCode(HLT_Process *peerProcess, int sslId)
{
    ASSERT_RETURN(peerProcess != NULL, "HLT_RpcTlsGetStatus Parameter Error");
    ASSERT_RETURN(peerProcess->remoteFlag == 1, "Only Remote Process Support Call HLT_RpcTlsGetErrorCode");

    int ret;
    uint64_t cmdIndex;
    char *endPtr = NULL;
    Process *srcProcess;
    CmdData expectCmdData = {0};
    ControlChannelBuf dataBuf;
    srcProcess = GetProcess();

    pthread_mutex_lock(&g_cmdMutex);
    ret = sprintf_s(dataBuf.data, sizeof(dataBuf.data), "%llu|%s|%d", g_cmdIndex, __FUNCTION__, sslId);
    dataBuf.dataLen = strlen(dataBuf.data);
    cmdIndex = g_cmdIndex;
    g_cmdIndex++;
    pthread_mutex_unlock(&g_cmdMutex);

    ASSERT_RETURN(ret > 0, "sprintf_s Error");

    ret = ControlChannelWrite(srcProcess->controlChannelFd, peerProcess->srcDomainPath, &dataBuf);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelWrite Error");

    // Waiting for the result
    ret = WaitResult(&expectCmdData, cmdIndex, __FUNCTION__);
    ASSERT_RETURN(ret == SUCCESS, "WaitResult Error");
    return (int)strtol(expectCmdData.paras[0], &endPtr, 0);
}
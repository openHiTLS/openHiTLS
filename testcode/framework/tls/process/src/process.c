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
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <libgen.h>
#include "lock.h"
#include "hlt.h"
#include "logger.h"
#include "tls_res.h"
#include "channel_res.h"
#include "control_channel.h"
#include "rpc_func.h"
#include "hitls.h"
#include "hitls_config.h"
#include "process.h"

#define SUCCESS 0
#define ERROR (-1)
#define CMD_MAX_LEN (512)
#define DOMAIN_PATH_LEN (128)
#define START_PROCESS_CMD "./process %d ./%s_%d ./%s %d > ./%s_%d.log &"

#define ASSERT_RETURN(condition, log) \
    do {                              \
        if (!(condition)) {           \
            LOG_ERROR(log);           \
            return ERROR;             \
        }                             \
    } while (0)

typedef struct ProcessRes {
    Process *process;
    struct ProcessRes *next;
} ProcessRes;

typedef struct ProcessList {
    ProcessRes *processRes;
    uint8_t num;
} ProcessList;

static ProcessList g_processList;
static Process *g_process = NULL;
static int g_processIndex = 0;

// Initialization process linked list, which is used only in the Local Process process and is used to save the Remote
// Process.
int InitProcessList(void)
{
    g_processList.processRes = (ProcessRes*)malloc(sizeof(ProcessRes));
    ASSERT_RETURN(g_processList.processRes != NULL, "Malloc ProcessRes Error");
    memset_s(g_processList.processRes, sizeof(ProcessRes), 0, sizeof(ProcessRes));
    g_processList.num = 0;
    return SUCCESS;
}

// Inserts a process to a linked list. Currently, only remote processes are stored.
int InsertProcessToList(Process *tmpProcess)
{
    ProcessRes *frontProcessRes = g_processList.processRes;
    ProcessRes *nextProcessRes = NULL;
    ProcessRes *tmpProcessRes;
    ASSERT_RETURN(tmpProcess != NULL, "TmpProcess is NULL");
    // Find the last process resource. The obtained frontProcessRes is the last process resource.
    nextProcessRes = frontProcessRes->next;
    while (nextProcessRes != NULL) {
        frontProcessRes = nextProcessRes;
        nextProcessRes = frontProcessRes->next;
    }
    // Applying for Process Resources
    tmpProcessRes = (ProcessRes*)malloc(sizeof(ProcessRes));
    ASSERT_RETURN(tmpProcessRes != NULL, "Malloc ProcessRes Error");
    tmpProcessRes->process = tmpProcess;
    tmpProcessRes->next = NULL;
    frontProcessRes->next = tmpProcessRes;
    g_processList.num++;
    return SUCCESS;
}

Process *GetProcessFromList(void)
{
    ProcessRes *headProcessRes = g_processList.processRes;
    ProcessRes *firstProcessRes, *nextProcessRes;
    Process* resultProcess;

    if (g_processList.num == 0) {
        return NULL;
    }

    // Find the last element
    firstProcessRes = headProcessRes->next;
    nextProcessRes = firstProcessRes;
    while ((nextProcessRes != NULL) && (nextProcessRes->next != NULL)) {
        firstProcessRes = nextProcessRes;
        nextProcessRes = firstProcessRes->next;
    }
    resultProcess = firstProcessRes->process;
    firstProcessRes->next = NULL;
    g_processList.num--;
    return resultProcess;
}

void FreeProcessResList(void)
{
    ProcessRes *frontProcessRes = g_processList.processRes;
    ProcessRes *nextProcessRes = NULL;
    ProcessRes *tmpProcessRes = NULL;

    nextProcessRes = frontProcessRes->next;
    while (nextProcessRes != NULL) {
        tmpProcessRes = nextProcessRes->next;
        free(nextProcessRes);
        nextProcessRes = tmpProcessRes;
    }

    free(g_processList.processRes);
    memset_s(&g_processList, sizeof(g_processList), 0, sizeof(g_processList));
    return;
}

int InitProcess(void)
{
    g_process= (Process*)malloc(sizeof(Process));
    ASSERT_RETURN(g_process != NULL, "Malloc ProcessRes Error");
    (void)memset_s(g_process, sizeof(Process), 0, sizeof(Process));
    return SUCCESS;
}

Process *GetProcess(void)
{
    return g_process;
}

void FreeProcess(void)
{
    if (g_process != NULL) {
        free(g_process);
        g_process = NULL;
    }
    return;
}

void MonitorControlChannel(void)
{
    fd_set fdSet;
    char *endPtr = NULL;
    int ret, fdMax, index;
    /* Allocate buffer on heap to avoid stack overflow (20KB is too large for stack) */
    ControlChannelBuf *dataBuf = (ControlChannelBuf *)malloc(sizeof(ControlChannelBuf));
    if (dataBuf == NULL) {
        LOG_ERROR("Failed to allocate ControlChannelBuf");
        return;
    }
    ControlChannelRes *channelInfo;
    channelInfo = GetControlChannelRes();
    int32_t fd = channelInfo->sockFd;
    fdMax = fd + 1;
    struct timeval stTimeOut = {0};
    while (!channelInfo->isExit) {
        stTimeOut.tv_sec = 1;
        stTimeOut.tv_usec = 0;
        FD_ZERO(&fdSet);
        FD_SET(fd, &fdSet);
        ret = select(fdMax, &fdSet, NULL, NULL, &stTimeOut);
        if (ret <= 0) {
            LOG_ERROR("Select Error");
            continue;
        }

        if (FD_ISSET(fd, &fdSet)) {
            ret = ControlChannelRead(fd, dataBuf);
            if (ret != SUCCESS) {
                LOG_ERROR("ControlChannelRead Error");
                continue;
            }
            /* Allocate CmdData on heap to avoid stack overflow (2MB is too large for stack) */
            CmdData *cmdData = (CmdData *)calloc(1, sizeof(CmdData));
            if (cmdData == NULL) {
                LOG_ERROR("Failed to allocate CmdData");
                free(dataBuf);
                return;
            }
            ret = ParseCmdFromStr(dataBuf->data, cmdData);
            index = (int)strtol(cmdData->id, &endPtr, 0) % MAX_RCV_BUFFER_NUM;
            ret = PushResultToChannelIdBuffer(channelInfo, dataBuf->data, index);
            free(cmdData);
            if (ret != SUCCESS) {
                LOG_ERROR("PushResultToChannelRcvBuffer Error");
                free(dataBuf);
                return;
            }
            LOG_DEBUG("Local Process Rcv is %s", dataBuf->data);
        } else {
            LOG_ERROR("FD_ISSET Error");
        }
    }
    free(dataBuf);
}

HLT_Process *InitSrcProcess(TLS_TYPE tlsType, char *srcDomainPath)
{
    int ret, srcPathLen;
    ControlChannelRes *channelInfo;
    char srcControlDomainPath[DOMAIN_PATH_LEN] = {0};
    HLT_Process *process;

    // Check whether the call is the first time.
    process = GetProcess();
    if (process != NULL) {
        LOG_ERROR("Repeat Init LocalProcess Is Not Support");
        return NULL;
    }

    // The printf output buffer is not set.
    setbuf(stdout, NULL);

    // Initializes the command statistics global variable, which is required only by the local process.
    InitCmdIndex();

    srcPathLen = strlen(srcDomainPath);
    if (srcPathLen == 0) {
        LOG_ERROR("srcDomainPath is NULL");
        return NULL;
    }

    ret = sprintf_s(srcControlDomainPath, DOMAIN_PATH_LEN, "%s.%u.sock", basename(srcDomainPath), getpid());

    ret = InitProcess();
    if (ret != SUCCESS) {
        LOG_ERROR("InitProcess Error");
        return NULL;
    }

    process = GetProcess();

    if (HLT_LibraryInit(tlsType) != SUCCESS) {
        LOG_ERROR("HLT_TlsRegCallback ERROR is %d", ret);
        goto ERR;
    }

    // Initialize the process resource linked list, which is used to store remote process resources.
    ret = InitProcessList();
    if (ret != SUCCESS) {
        LOG_ERROR("InitProcessList ERROR");
        goto ERR;
    }

    // Initializes the CTX SSL resource linked list.
    ret = InitTlsResList();
    if (ret != SUCCESS) {
        LOG_ERROR("InitTlsResList ERROR");
        goto ERR;
    }

    // Initialize the control link.
    ret = InitControlChannelRes(srcControlDomainPath, strlen(srcControlDomainPath), NULL, 0);
    if (ret != SUCCESS) {
        LOG_ERROR("InitControlChannelRes ERROR");
        goto ERR;
    }

    channelInfo = GetControlChannelRes();

    // Create control link UDP domain socket
    ret = ControlChannelInit(channelInfo);
    if (ret != SUCCESS) {
        LOG_ERROR("ControlChannelInit ERROR");
        goto ERR;
    }

    // Start a thread to listen to the control link. The link is used to receive the results returned by other processes
    pthread_t tId;
    channelInfo->isExit = false;
    if (pthread_create(&tId, NULL, (void*)MonitorControlChannel, NULL) != 0) {
        LOG_ERROR("Create MonitorControlChannel Thread Error ...");
        goto ERR;
    }
    channelInfo->tid = tId;

    // Populate Process Information
    process->tlsType = tlsType;
    process->controlChannelFd = channelInfo->sockFd;
    process->remoteFlag = 0;
    process->tlsResNum = 0;
    process->hltTlsResNum = 0;
    process->connType = NONE_TYPE;
    process->connFd = 0;
    ret = memcpy_s(process->srcDomainPath, DOMAIN_PATH_LEN, srcControlDomainPath, strlen(srcControlDomainPath));
    if (ret != EOK) {
        LOG_ERROR("memcpy_s process->srcDomainPath ERROR");
        goto ERR;
    }
    LOG_DEBUG("Init Local Process Successful");
    return (HLT_Process*)process;

ERR:
    free(process);
    return NULL;
}

HLT_Process *InitPeerProcess(TLS_TYPE tlsType, HILT_TransportType connType, int port, bool isBlock)
{
    // peerDomainPath address, which is the IP address of the monitoring process.
    // Creating a Process
    int ret, peerPathLen, tryNum;
    char startCmd[CMD_MAX_LEN] = {0};
    HLT_Process *localProcess;
    HLT_Process *process = NULL;

    localProcess = GetProcess();
    if (localProcess == NULL) {
        LOG_ERROR("Must Call HLT_InitLocalProcess First");
        return NULL;
    }

    peerPathLen = strlen(localProcess->srcDomainPath);
    if (peerPathLen == 0) {
        LOG_ERROR("peerDomainPath is NULL");
        return NULL;
    }

    process = (HLT_Process*)malloc(sizeof(HLT_Process));
    if (process == NULL) {
        LOG_ERROR("Malloc Process is NULL");
        return NULL;
    }
    (void)memset_s(process, sizeof(HLT_Process), 0, sizeof(HLT_Process));
    pid_t localpid = getpid();
    ret = sprintf_s(startCmd,
        CMD_MAX_LEN,
        START_PROCESS_CMD,
        tlsType,
        localProcess->srcDomainPath,
        g_processIndex,
        localProcess->srcDomainPath,
        localpid,
        localProcess->srcDomainPath,
        g_processIndex);
    if (ret == 0) {
        LOG_ERROR("sprintf_s Error");
        free(process);
        return NULL;
    }

    LOG_DEBUG("Exect Cmd is %s", startCmd);
    ret = system(startCmd);
    if (ret == ERROR) {
        LOG_ERROR("System Error");
        free(process);
        return NULL;
    }

    // After the remote process is started successfully, the remote process is stored in the linked list.
    InsertProcessToList(process);

    // The message is received, indicating that the peer end is in the receiveable state.
    CmdData expectCmdData = {0};
    (void)sprintf_s(expectCmdData.id, sizeof(expectCmdData.id), "0");
    (void)sprintf_s(expectCmdData.funcId, sizeof(expectCmdData.funcId), "HEART");
    tryNum = 0;
    do {
        ret = WaitResultFromPeer(&expectCmdData);
        tryNum++;
    } while ((ret == ERROR) && (tryNum < 2)); // Retry once

    if (ret == ERROR) {
        LOG_ERROR("WaitResultFromPeer Error");
        goto ERR;
    }

    // Populate Process Information
    process->connType = NONE_TYPE;
    process->connFd = 0;
    process->tlsType = tlsType;
    process->remoteFlag = 1;
    ret = sprintf_s(process->srcDomainPath, DOMAIN_PATH_LEN, "%s_%d", localProcess->srcDomainPath, g_processIndex);
    if (ret <= 0) {
        LOG_ERROR("sprintf_s Error");
        goto ERR;
    }
    // Creating a Data Link
    if (connType != NONE_TYPE) {
        DataChannelParam channelParam;
        HLT_FD sockFd = {0};
        channelParam.port = port;
        channelParam.type = connType;
        channelParam.isBlock = isBlock; // The SCTP link is set to non-block. Otherwise, the SCTP link may be suspended.
        sockFd = HLT_CreateDataChannel(process, localProcess, channelParam);
        localProcess->connType = connType;
        localProcess->connFd = sockFd.peerFd;
        localProcess->sockAddr = sockFd.sockAddr;
        process->connType = connType;
        process->connFd = sockFd.srcFd;
        process->connPort = sockFd.connPort;
        if ((sockFd.srcFd <= 0) || (sockFd.peerFd <= 0)) {
            LOG_ERROR("Create CHANNEL ERROR");
            goto ERR;
        }
    }
    g_processIndex++;
    return (HLT_Process*)process;
ERR:
    // You do not need to release the process. If you can go to this point,
    // the process is successfully created and inserted into the table.
    // The process resource is released in the HLT_FreeAllProcess function.
    // If the remote process is released in advance, the remote process may be successfully started but cannot be exited
    g_processIndex++;
    return NULL;
}

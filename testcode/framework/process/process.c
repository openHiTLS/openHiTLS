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
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <semaphore.h>

#include "securec.h"
#include "channel_res.h"
#include "handle_cmd.h"
#include "tls_res.h"
#include "control_channel.h"
#include "logger.h"
#include "lock.h"
#include "rpc_func.h"
#include "hlt_type.h"
#include "hlt.h"
#include "process.h"

#define DOMAIN_PATH_LEN (128)
#define SUCCESS 0
#define ERROR (-1)

#define ASSERT_RETURN(condition, log) \
    do {                              \
        if (!(condition)) {           \
            LOG_ERROR(log);           \
            return ERROR;             \
        }                             \
    } while (0)

int IsFeedbackResult(ControlChannelRes *channelInfo)
{
    int i, ret;
    ControlChannelBuf dataBuf = {0};

    OsLock(channelInfo->sendBufferLock);
    if (channelInfo->sendBufferNum == 0) {
        OsUnLock(channelInfo->sendBufferLock);
        return SUCCESS;
    }
    i = 0;
    while (channelInfo->sendBufferNum > 0) {
        ret = memcpy_s(dataBuf.data, CONTROL_CHANNEL_MAX_MSG_LEN,
                       channelInfo->sendBuffer[i], strlen((char*)(channelInfo->sendBuffer[i])));
        if (ret != EOK) {
            LOG_ERROR("MemCpy Error");
            OsUnLock(channelInfo->sendBufferLock);
            return ERROR;
        }
        dataBuf.dataLen = strlen((char*)channelInfo->sendBuffer[i]);
        LOG_DEBUG("Remote Process Send Result %s", dataBuf.data);
        ret = ControlChannelWrite(channelInfo->sockFd, channelInfo->peerDomainPath, &dataBuf);
        if (ret != EOK) {
            LOG_ERROR("ControlChannelWrite Error, Msg is %s, ret is %d\n", dataBuf.data, ret);
            OsUnLock(channelInfo->sendBufferLock);
            return ERROR;
        }
        LOG_DEBUG("Remote Process Send Result %s Success", dataBuf.data);
        channelInfo->sendBufferNum--;
        i++;
    }
    OsUnLock(channelInfo->sendBufferLock);
    return SUCCESS;
}

void FreeThreadRes(pthread_t *threadList, int threadNum)
{
    for (int i = 0; i < threadNum; i++) {
        pthread_cancel(threadList[i]);
        pthread_join(threadList[i], NULL);
    }
    return;
}

void ThreadExcuteCmd(void *param)
{
    CmdData cmdData = {0};
    if (memcpy_s(&cmdData, sizeof(cmdData), (CmdData *)param, sizeof(CmdData)) != EOK) {
        free(param);
        return;
    }
    free(param);
    ControlChannelRes *channelInfo = GetControlChannelRes();
    (void)ExecuteCmd(&cmdData);  // Cast to void to suppress unused-value warning
    PushResultToChannelSendBuffer(channelInfo, cmdData.result);
    return;
}

int main(int argc, char **argv)
{
    int ret, sctpFd = -1;  // Initialize sctpFd to -1 (invalid fd)
    ControlChannelRes* channelInfo = NULL;
    ControlChannelBuf dataBuf;
    CmdData exitCmdData = {0};
    CmdData* cmdData = NULL;
    Process* process = NULL;
    pid_t ppid = atoi(argv[4]);
    (void)ppid;
    // Do not set the output buffer
    setbuf(stdout, NULL);

    LOG_DEBUG("argv value is %d", argc);
    ret = InitProcess();
    ASSERT_RETURN(ret == SUCCESS, "InitProcess Error");

    process = GetProcess();
    process->remoteFlag = 1; // Must be marked as a remote process
    process->tlsType = atoi(argv[1]); // The first parameter indicates the Hitls function
    ret = memcpy_s(process->srcDomainPath, DOMAIN_PATH_LEN, argv[2],
        strlen(argv[2])); // The second parameter indicates the local IP address
    ASSERT_RETURN(ret == SUCCESS, "memcpy process->srcDomainPath Error");
    ret = memcpy_s(process->peerDomainPath, DOMAIN_PATH_LEN, argv[3],
        strlen(argv[3])); // The third parameter indicates the address of the control process
    ASSERT_RETURN(ret == SUCCESS, "memcpy process->srcDomainPath Error");

    // Dependent library initialization
    ret = HLT_LibraryInit(process->tlsType);
    ASSERT_RETURN(ret == SUCCESS, "HLT_TlsRegCallback Error");

    // Initialize the linked list for storing CTX and SSL
    ret = InitTlsResList();
    ASSERT_RETURN(ret == SUCCESS, "InitTlsResList Error");

    // Initializes the global variable that stores the control channel information.
    ret = InitControlChannelRes(process->srcDomainPath, strlen(process->srcDomainPath),
                                process->peerDomainPath, strlen(process->peerDomainPath));
    ASSERT_RETURN(ret == SUCCESS, "ChannelInfoInit Error");

    // Creating a Control Link UDP DOMAIN SOCKET
    channelInfo = GetControlChannelRes();
    ret = ControlChannelInit(channelInfo);
    ASSERT_RETURN(ret == SUCCESS, "ControlChannelInit Error");

    // Print information
    LOG_DEBUG("Create Remote Process Successful");
    // The message is sent to the peer end, indicating that the process is started successfully
    PushResultToChannelSendBuffer(channelInfo, "0|HEART");
    while (1) {
        if (kill(ppid, 0) != 0) {
            LOG_DEBUG("\nthe parent process [%u] does not exist, I want to exist\n", ppid);
            break;
        }
        // Waiting for the command from the peer end
        ret = ControlChannelRead(channelInfo->sockFd, &dataBuf);
        if (ret == 0) {
            // Receives a message, parses the message, and performs related operations
            LOG_DEBUG("Remote Process Rcv Cmd Is: %s", dataBuf.data);
            cmdData = (CmdData*)malloc(sizeof(CmdData));
            if (cmdData == NULL) {
                LOG_ERROR("Malloc cmdData Error");
                break;
            }
            ret = ParseCmdFromBuf(&dataBuf, cmdData);
            if (ret != SUCCESS) {
                LOG_ERROR("ParseCmdFromBuf Error ...");
                free(cmdData);
                break;
            }
            if (strncmp((char *)cmdData->funcId, "HLT_RpcProcessExit", strlen("HLT_RpcProcessExit")) == 0) {
                // Indicates that the process needs to exit
                sctpFd = atoi((char *)cmdData->paras[0]);
                (void)sprintf_s((char *)exitCmdData.result, sizeof(exitCmdData.result), "%s|%s|%d",
                                cmdData->id, cmdData->funcId, sctpFd);
                PushResultToChannelSendBuffer(channelInfo, exitCmdData.result);
                free(cmdData);
                break;
            }
            ThreadExcuteCmd(cmdData);
        }
        // Check whether feedback is required
        ret = IsFeedbackResult(channelInfo);
        if (ret != 0) {
            break;
        }
    }
    LOG_DEBUG("Process Return");
    (void)IsFeedbackResult(channelInfo);
    // Clearing Resources
    FreeControlChannelRes();
    FreeTlsResList();
    FreeProcess();
    if (sctpFd > 0) {
        close(sctpFd);
    }
    return SUCCESS;
}

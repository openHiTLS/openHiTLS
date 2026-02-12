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

#include <sys/time.h>
#include "logger.h"
#include <string.h>
#include "lock.h"
#include "channel_res.h"

#define SUCCESS 0
#define ERROR (-1)

static ControlChannelRes g_channelRes;

static int SetControlChannelRes(ControlChannelRes *channelInfo, char *srcDomainPath, char *peerDomainPath)
{
    size_t len;

    memset(&(channelInfo->srcAddr), 0, sizeof(struct sockaddr_un));

    if (strlen(srcDomainPath) >= DOMAIN_PATH_LEN) {
        LOG_ERROR("memcpy Error\n");
        return ERROR;
    }
    memcpy(channelInfo->srcDomainPath, srcDomainPath, strlen(srcDomainPath) + 1);

    channelInfo->srcAddr.sun_family = AF_UNIX;
    len = strlen(srcDomainPath) + 1;
    if (len > sizeof(channelInfo->srcAddr.sun_path)) {
        LOG_ERROR("strcpy Error");
        return ERROR;
    }
    memcpy(channelInfo->srcAddr.sun_path, srcDomainPath, len);

    memset(channelInfo->peerDomainPath, 0, sizeof(channelInfo->peerDomainPath));

    if (peerDomainPath != NULL) {
        if (strlen(peerDomainPath) >= DOMAIN_PATH_LEN) {
            LOG_ERROR("memcpy Error\n");
            return ERROR;
        }
        memcpy(channelInfo->peerDomainPath, peerDomainPath, strlen(peerDomainPath) + 1);

        channelInfo->peerAddr.sun_family = AF_UNIX;
        len = strlen(peerDomainPath) + 1;
        if (len > sizeof(channelInfo->peerAddr.sun_path)) {
            LOG_ERROR("strcpy Error");
            return ERROR;
        }
        memcpy(channelInfo->peerAddr.sun_path, peerDomainPath, len);
    }
    return SUCCESS;
}

int InitControlChannelRes(char *srcDomainPath, int srcDomainPathLen, char *peerDomainPath, int peerDomainPathLen)
{
    if ((srcDomainPathLen <= 0) && (peerDomainPathLen <= 0)) {
        LOG_ERROR("srcDomainPathLen or peerDomainPathLen is 0");
        return ERROR;
    }
    memset(&g_channelRes, 0, sizeof(ControlChannelRes));

    // Initializing the Send Buffer Lock
    g_channelRes.sendBufferLock = OsLockNew();
    if (g_channelRes.sendBufferLock == NULL) {
        LOG_ERROR("OsLockNew Error");
        return ERROR;
    }

    // Initialize the receive buffer lock.
    g_channelRes.rcvBufferLock = OsLockNew();
    if (g_channelRes.rcvBufferLock == NULL) {
        LOG_ERROR("OsLockNew Error");
        return ERROR;
    }

    // Initializes the communication address used for UDP Domain Socket communication.
    return SetControlChannelRes(&g_channelRes, srcDomainPath, peerDomainPath);
}

ControlChannelRes *GetControlChannelRes(void)
{
    return &g_channelRes;
}

int PushResultToChannelSendBuffer(ControlChannelRes *channelInfo, char *result)
{
    OsLock(channelInfo->sendBufferLock);
    if (channelInfo->sendBufferNum == MAX_SEND_BUFFER_NUM) {
        LOG_ERROR("Channel Send Buffer Is Full, Please Try Again");
        OsUnLock(channelInfo->sendBufferLock);
        return 1; // The value 1 indicates that the current buffer is full and needs to be retried.
    }
    memset(channelInfo->sendBuffer + channelInfo->sendBufferNum, 0, CONTROL_CHANNEL_MAX_MSG_LEN);
    if (strlen(result) >= CONTROL_CHANNEL_MAX_MSG_LEN) {
        LOG_ERROR("memcpy Error");
        OsUnLock(channelInfo->sendBufferLock);
        return ERROR;
    }
    memcpy(channelInfo->sendBuffer + channelInfo->sendBufferNum, result, strlen(result) + 1);
    channelInfo->sendBufferNum++;
    channelInfo->sendBufferNum %= MAX_SEND_BUFFER_NUM;
    OsUnLock(channelInfo->sendBufferLock);
    return SUCCESS;
}

int PushResultToChannelRcvBuffer(ControlChannelRes *channelInfo, char *result)
{
    OsLock(channelInfo->rcvBufferLock);
    if (channelInfo->rcvBufferNum == MAX_RCV_BUFFER_NUM) {
        LOG_ERROR("Channel Send Buffer Is Full, Please Try Again");
        OsUnLock(channelInfo->rcvBufferLock);
        return 1; // The value 1 indicates that the current buffer is full and needs to be retried.
    }
    memset(channelInfo->rcvBuffer + channelInfo->rcvBufferNum, 0, CONTROL_CHANNEL_MAX_MSG_LEN);
    if (strlen(result) >= CONTROL_CHANNEL_MAX_MSG_LEN) {
        LOG_ERROR("memcpy Error");
        OsUnLock(channelInfo->rcvBufferLock);
        return ERROR;
    }
    memcpy(channelInfo->rcvBuffer + channelInfo->rcvBufferNum, result, strlen(result) + 1);
    channelInfo->rcvBufferNum++;
    channelInfo->rcvBufferNum %= MAX_RCV_BUFFER_NUM;
    OsUnLock(channelInfo->rcvBufferLock);
    return SUCCESS;
}

int PushResultToChannelIdBuffer(ControlChannelRes *channelInfo, char *result, int id)
{
    OsLock(channelInfo->rcvBufferLock);
    memset(channelInfo->rcvBuffer + (id % MAX_RCV_BUFFER_NUM), 0, CONTROL_CHANNEL_MAX_MSG_LEN);
    if (strlen(result) >= CONTROL_CHANNEL_MAX_MSG_LEN) {
        LOG_ERROR("memcpy Error");
        OsUnLock(channelInfo->rcvBufferLock);
        return ERROR;
    }
    memcpy(channelInfo->rcvBuffer + (id % MAX_RCV_BUFFER_NUM), result, strlen(result) + 1);
    OsUnLock(channelInfo->rcvBufferLock);
    return SUCCESS;
}

void FreeControlChannelRes(void)
{
    if (g_channelRes.tid != 0) {
        g_channelRes.isExit = true;
        pthread_join(g_channelRes.tid, NULL);
    }
    if (g_channelRes.sockFd > 0) {
        close(g_channelRes.sockFd);
    }
    OsLockDestroy(g_channelRes.sendBufferLock);
    OsLockDestroy(g_channelRes.rcvBufferLock);
    memset(&g_channelRes, 0, sizeof(g_channelRes));
    return;
}

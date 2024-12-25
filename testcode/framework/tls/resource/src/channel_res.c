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
#include "securec.h"
#include "lock.h"
#include "channel_res.h"

#define SUCCESS 0
#define ERROR (-1)

static ControlChannelRes g_channelRes;

static int SetControlChannelRes(ControlChannelRes *channelInfo, char *srcDomainPath, char *peerDomainPath)
{
    int ret;

    // Translate the source address.
    ret = memset_s(&(channelInfo->srcAddr), sizeof(struct sockaddr_un), 0, sizeof(struct sockaddr_un));
    if (ret != EOK) {
        LOG_ERROR("memset_s Error\n");
        return ERROR;
    }

    ret = memcpy_s(channelInfo->srcDomainPath, DOMAIN_PATH_LEN, srcDomainPath, strlen(srcDomainPath));
    if (ret != EOK) {
        LOG_ERROR("memcpy_s Error\n");
        return ERROR;
    }

    channelInfo->srcAddr.sun_family = AF_UNIX;
    ret = strcpy_s(channelInfo->srcAddr.sun_path, strlen(srcDomainPath) + 1, srcDomainPath);
    if (ret != EOK) {
        LOG_ERROR("strcpy_s Error");
        return ERROR;
    }

    ret = memset_s(channelInfo->peerDomainPath, sizeof(channelInfo->peerDomainPath),
                   0, sizeof(channelInfo->peerDomainPath));
    if (ret != EOK) {
        LOG_ERROR("memset_s Error\n");
        return ERROR;
    }

    if (peerDomainPath != NULL) {
        ret = memcpy_s(channelInfo->peerDomainPath, DOMAIN_PATH_LEN, peerDomainPath, strlen(peerDomainPath));
        if (ret != EOK) {
            LOG_ERROR("memcpy_s Error\n");
            return ERROR;
        }

        channelInfo->peerAddr.sun_family = AF_UNIX;
        ret = strcpy_s(channelInfo->peerAddr.sun_path, strlen(peerDomainPath) + 1, peerDomainPath);
        if (ret != EOK) {
            LOG_ERROR("strcpy_s Error");
            return ERROR;
        }
    }
    return SUCCESS;
}

int InitControlChannelRes(char *srcDomainPath, int srcDomainPathLen, char *peerDomainPath, int peerDomainPathLen)
{
    int ret;
    if ((srcDomainPathLen <= 0) && (peerDomainPathLen <= 0)) {
        LOG_ERROR("srcDomainPathLen or peerDomainPathLen is 0");
        return ERROR;
    }
    ret = memset_s(&g_channelRes, sizeof(ControlChannelRes), 0, sizeof(ControlChannelRes));
    if (ret != EOK) {
        return ERROR;
    }

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
    int ret;
    OsLock(channelInfo->sendBufferLock);
    if (channelInfo->sendBufferNum == MAX_SEND_BUFFER_NUM) {
        LOG_ERROR("Channel Send Buffer Is Full, Please Try Again");
        OsUnLock(channelInfo->sendBufferLock);
        return 1; // The value 1 indicates that the current buffer is full and needs to be retried.
    }
    (void)memset_s(channelInfo->sendBuffer + channelInfo->sendBufferNum,
                   CONTROL_CHANNEL_MAX_MSG_LEN, 0, CONTROL_CHANNEL_MAX_MSG_LEN);
    ret = memcpy_s(channelInfo->sendBuffer + channelInfo->sendBufferNum,
                   CONTROL_CHANNEL_MAX_MSG_LEN, result, strlen(result));
    if (ret != EOK) {
        LOG_ERROR("memcpy_s Error");
        OsUnLock(channelInfo->sendBufferLock);
        return ERROR;
    }
    channelInfo->sendBufferNum++;
    channelInfo->sendBufferNum %= MAX_SEND_BUFFER_NUM;
    OsUnLock(channelInfo->sendBufferLock);
    return SUCCESS;
}

int PushResultToChannelRcvBuffer(ControlChannelRes *channelInfo, char *result)
{
    int ret;
    OsLock(channelInfo->rcvBufferLock);
    if (channelInfo->rcvBufferNum == MAX_RCV_BUFFER_NUM) {
        LOG_ERROR("Channel Send Buffer Is Full, Please Try Again");
        OsUnLock(channelInfo->rcvBufferLock);
        return 1; // The value 1 indicates that the current buffer is full and needs to be retried.
    }
    (void)memset_s(channelInfo->rcvBuffer + channelInfo->rcvBufferNum,
                   CONTROL_CHANNEL_MAX_MSG_LEN, 0, CONTROL_CHANNEL_MAX_MSG_LEN);
    ret = memcpy_s(channelInfo->rcvBuffer + channelInfo->rcvBufferNum,
                   CONTROL_CHANNEL_MAX_MSG_LEN, result, strlen(result));
    if (ret != EOK) {
        LOG_ERROR("memcpy_s Error");
        OsUnLock(channelInfo->rcvBufferLock);
        return ERROR;
    }
    channelInfo->rcvBufferNum++;
    channelInfo->rcvBufferNum %= MAX_RCV_BUFFER_NUM;
    OsUnLock(channelInfo->rcvBufferLock);
    return SUCCESS;
}

int PushResultToChannelIdBuffer(ControlChannelRes *channelInfo, char *result, int id)
{
    int ret;
    OsLock(channelInfo->rcvBufferLock);
    (void)memset_s(channelInfo->rcvBuffer + (id % MAX_RCV_BUFFER_NUM),
                   CONTROL_CHANNEL_MAX_MSG_LEN, 0, CONTROL_CHANNEL_MAX_MSG_LEN);
    ret = memcpy_s(channelInfo->rcvBuffer + (id % MAX_RCV_BUFFER_NUM),
                   CONTROL_CHANNEL_MAX_MSG_LEN, result, strlen(result));
    if (ret != EOK) {
        LOG_ERROR("memcpy_s Error");
        OsUnLock(channelInfo->rcvBufferLock);
        return ERROR;
    }
    OsUnLock(channelInfo->rcvBufferLock);
    return SUCCESS;
}

void FreeControlChannelRes(void)
{
    if (g_channelRes.tid != 0) {
        g_channelRes.isExit = true;
        pthread_join(g_channelRes.tid, NULL);
    }
    OsLockDestroy(g_channelRes.sendBufferLock);
    OsLockDestroy(g_channelRes.rcvBufferLock);
    memset_s(&g_channelRes, sizeof(g_channelRes), 0, sizeof(g_channelRes));
    return;
}

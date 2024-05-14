/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <sys/time.h>
#include "channel_res.h"
#include "logger.h"
#include "securec.h"

#define SUCCESS 0
#define ERROR (-1)

int ControlChannelInit(ControlChannelRes *channelInfo)
{
    int len;
    int sockFd;
    struct timeval timeOut;

    unlink(channelInfo->srcDomainPath);
    // Create a socket.
    sockFd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockFd < 0) {
        LOG_ERROR("Get SockFd Error");
        return ERROR;
    }
    // Set the non-blocking mode.
    timeOut.tv_sec = 0;      // Second
    timeOut.tv_usec = 10000; // 10000 microseconds
    if (setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeOut, sizeof(timeOut)) == -1) {
        LOG_ERROR("Setsockopt Fail");
        return ERROR;
    }
    // Binding ports.
    len = offsetof(struct sockaddr_un, sun_path) + strlen(channelInfo->srcDomainPath) + 1;
    if (bind(sockFd, (struct sockaddr *)&(channelInfo->srcAddr), len) < 0) {
        LOG_ERROR("Bind Error\n");
        return ERROR;
    }
    channelInfo->sockFd = sockFd;
    return 0;
}

int ControlChannelAcept(ControlChannelRes *channelInfo)
{
    (void)channelInfo;
    return SUCCESS;
}

int ControlChannelConnect(ControlChannelRes *channelInfo)
{
    (void)channelInfo;
    return SUCCESS;
}

int ControlChannelWrite(int32_t sockFd, char *peerDomainPath, ControlChannelBuf *dataBuf)
{
    int ret;
    uint32_t dataLen;
    uint32_t addrLen;
    struct sockaddr_un peerAddr;

    peerAddr.sun_family = AF_UNIX;
    ret = strcpy_s(peerAddr.sun_path, strlen(peerDomainPath) + 1, peerDomainPath);
    if (ret != EOK) {
        LOG_ERROR("strcpy_s Error");
        return ERROR;
    }
    addrLen = offsetof(struct sockaddr_un, sun_path) + strlen(peerDomainPath) + 1;
    dataLen = sendto(sockFd, dataBuf->data, dataBuf->dataLen, 0, (struct sockaddr *)&peerAddr, addrLen);
    if (dataLen != dataBuf->dataLen) {
        LOG_ERROR("Send Msg Error: %s\n", dataBuf->data);
        return ERROR;
    }
    return SUCCESS;
}

int ControlChannelRead(int32_t sockFd, ControlChannelBuf *dataBuf)
{
    struct sockaddr_un peerAddr;
    int dataLen;
    socklen_t addrLen = sizeof(struct sockaddr_un);
    (void)memset_s(dataBuf->data, CONTROL_CHANNEL_MAX_MSG_LEN, 0, CONTROL_CHANNEL_MAX_MSG_LEN);

    dataLen = recvfrom(sockFd, dataBuf->data, CONTROL_CHANNEL_MAX_MSG_LEN, 0,
                       (struct sockaddr *)(&peerAddr), &(addrLen));
    if (dataLen < 0) {
        return ERROR;
    }
    dataBuf->dataLen = dataLen;
    return SUCCESS;
}
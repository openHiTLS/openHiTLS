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
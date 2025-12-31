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
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>

#include "hitls_build.h"
#ifdef HITLS_BSL_UIO_UDP
#include "securec.h"
#include "bsl_uio.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls.h"
#include "tls.h"
#include "hs_ctx.h"
#include "bsl_errno.h"
#include "uio_base.h"

#include "logger.h"
#include "hlt_type.h"
#include "socket_common.h"
#include "udp_channel.h"

/**
 * @brief   Connects to the peer and returns a socket descriptor.
 *
 * @return  -1 is returned when an error occurs
 * */
int UdpConnect(const char *targetIP, const int targetPort)
{
    (void)targetIP;
    int fd = -1;
    struct sockaddr_in sockAddr;

    /* Create a socket */
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        LOG_ERROR("socket() fail");
        return -1;
    }

    /* Set the protocol, IP address, and port number */
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_port = htons(targetPort);
    sockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(fd, (struct sockaddr *)&sockAddr, sizeof(struct sockaddr_in)) != 0) {
        LOG_ERROR("connect() fail");
        close(fd);
        return -1;
    }
    SetBlockMode(fd, false);
    int32_t sendBytes = write(fd, "helloworld", sizeof("helloworld"));
    if (sendBytes < 0) {
        /* Non-fatal error */
        if (IsNonFatalErr(errno) == true) {
            return fd;
        }
        /* Fatal error */
        LOG_ERROR("error: write errno %d", errno);
        return -1;
    }
    return fd;
}

int UdpBind(const int localPort)
{
    int lisentFd, ret;
    struct sockaddr_in serverAddr;

    // Create a socket
    if ((lisentFd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        LOG_ERROR("create socket fail\n");
        return -1;
    }

    int option = 1;
    if (setsockopt(lisentFd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
        close(lisentFd);
        LOG_ERROR("setsockopt fail\n");
        return -1;
    }

    // Set the protocol and port number
    bzero(&serverAddr, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(localPort);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    uint32_t tryNum = 0;
    LOG_DEBUG("bind socket ing...\n");
    do {
        ret = bind(lisentFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
        usleep(1000); // 1000 microseconds, that is, 1 ms
        tryNum++;
    } while ((ret != 0) && (tryNum < 8000)); // 8000: indicates that the binding attempt is 8 seconds
    if (ret != 0) {
        close(lisentFd);
        LOG_DEBUG("bind socket fail\n");
        return -1;
    }

    SetBlockMode(lisentFd, false);
    return lisentFd;
}

int UdpAccept(int32_t fd, struct sockaddr *sockAddr)
{
    int32_t ret;
    int addrlen = sizeof(struct sockaddr_in);
    uint8_t buf[1024];
    do {
        ret = recvfrom(fd, buf, 1024, 0, sockAddr, (socklen_t *)&addrlen);
    } while (ret<0 && IsNonFatalErr(errno) == true);
    if (ret < 0) {
        LOG_ERROR("error: accept errno %d", errno);
        return -1;
    }

    /* Configure the peer IP address and port number in the FD to prepare for write operations */
    if (connect(fd, sockAddr, sizeof(struct sockaddr_in)) != 0) {
        LOG_ERROR("udp connect() fail");
        return -1;
    }
    return fd;
}

/* Disable the specified socket */
void UdpClose(int sd)
{
    close(sd);
}

int32_t UdpFrameWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    int32_t ret;
    uint8_t *newBuf = NULL;
    const void *sendBuf = buf;
    uint32_t sendLen = len;
    HLT_FrameHandle *frameHandle = GetFrameHandle();

    if (frameHandle->frameCallBack != NULL && frameHandle->pointType == POINT_SEND) {
        newBuf = GetNewBuf(buf, len, &sendLen);
        if (sendLen == 0) { // sendLen value changes and becomes 0, the value is IO_BUSY
            *writeLen = 0;
            return BSL_SUCCESS;
        }
        if (newBuf != NULL) {
            sendBuf = (void *)newBuf;
        }
    }
    ret = BSL_UIO_UdpMethod()->uioWrite(uio, sendBuf, sendLen, writeLen);
    if (sendLen != len && *writeLen != 0) {
        *writeLen = len;
    }
    FreeNewBuf(newBuf);
    return ret;
}

int32_t UdpFrameRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    int ret;
    ret = BSL_UIO_UdpMethod()->uioRead(uio, buf, len, readLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    uint8_t *newBuf = NULL;
    uint32_t packLen = *readLen;
    HLT_FrameHandle *frameHandle = GetFrameHandle();
    if (frameHandle->frameCallBack != NULL && frameHandle->pointType == POINT_RECV) {
        newBuf = GetNewBuf(buf, len, &packLen);
        if (packLen == 0) { // packLen changes and becomes 0, the value is IO_BUSY
            *readLen = 0;
            return BSL_SUCCESS;
        }
        if (newBuf != NULL) {
            if (memcpy_s(buf, len, (uint8_t *)newBuf, packLen) != EOK) {
                FreeNewBuf(newBuf);
                return BSL_UIO_IO_EXCEPTION;
            }
            *readLen = packLen;
        }
        FreeNewBuf(newBuf);
    }
    return BSL_SUCCESS;
}

int32_t SelectUdpWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    HLT_FrameHandle *frameHandle = GetFrameHandle();
    if (frameHandle->method.uioWrite != NULL) {
        return frameHandle->method.uioWrite(uio, buf, len, writeLen);
    }
    return UdpFrameWrite(uio, buf, len, writeLen);
}

int32_t SelectUdpRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    HLT_FrameHandle *frameHandle = GetFrameHandle();
    if (frameHandle->method.uioRead != NULL) {
        return frameHandle->method.uioRead(uio, buf, len, readLen);
    }
    return UdpFrameRead(uio, buf, len, readLen);
}

static BSL_UIO_Method g_UdpUioMethodDefault;

/* Provide the default Linux implementation method */
void *UdpGetDefaultMethod(void)
{
    const BSL_UIO_Method *ori = BSL_UIO_UdpMethod();
    memcpy_s(&g_UdpUioMethodDefault, sizeof(g_UdpUioMethodDefault), ori, sizeof(g_UdpUioMethodDefault));
    g_UdpUioMethodDefault.uioWrite = SelectUdpWrite;
    g_UdpUioMethodDefault.uioRead = SelectUdpRead;
    return &g_UdpUioMethodDefault;
}
#endif
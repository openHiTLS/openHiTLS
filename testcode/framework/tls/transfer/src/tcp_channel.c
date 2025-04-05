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
#include "tcp_channel.h"

/**
 * @brief   Connects to the peer and returns a socket descriptor.
 *
 * @return  -1 is returned when an error occurs
 * */
int TcpConnect(const char *targetIP, const int targetPort)
{
    (void)targetIP;
    int fd;
    struct sockaddr_in serverAddr;

    // Create a socket
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        LOG_ERROR("socket() fail\n");
        return -1;
    }
    int option = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
        close(fd);
        LOG_ERROR("setsockopt() fail\n");
        return -1;
    }

    struct linger so_linger;
    so_linger.l_onoff = true;
    so_linger.l_linger = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger)) < 0) {
        close(fd);
        LOG_ERROR("setsockopt() linger fail\n");
        return -1;
    }

    // Set the protocol and port number
    (void)memset_s(&serverAddr, sizeof(serverAddr), 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(targetPort);

    // Set the IP address
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connection
    int index = 0;
    const int maxConnTime = 8000;
    do {
        if (connect(fd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == 0) {
            break;
        }
        usleep(1000); // Delay 100000 us
        LOG_ERROR("Connect error try again\n");
    } while (index++ < maxConnTime);
    if (index >= maxConnTime) {
        close(fd);
        LOG_ERROR("Connect error\n");
        return -1;
    }
    SetBlockMode(fd, false);
    return fd;
}

int TcpBind(const int localPort)
{
    int lisentFd, ret;
    struct sockaddr_in serverAddr;

    // Create a socket
    if ((lisentFd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        LOG_ERROR("create socket fail\n");
        return -1;
    }

    int option = 1;
    if (setsockopt(lisentFd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
        close(lisentFd);
        LOG_ERROR("setsockopt fail\n");
        return -1;
    }

    struct linger so_linger;
    so_linger.l_onoff = true;
    so_linger.l_linger = 0;
    if (setsockopt(lisentFd, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger)) < 0) {
        close(lisentFd);
        LOG_ERROR("setsockopt() linger fail\n");
        return -1;
    }

    // Set the protocol and port number
    (void)memset_s(&serverAddr, sizeof(serverAddr), 0, sizeof(serverAddr));
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

    if (listen(lisentFd, 5) != 0) { // core should queue for the corresponding socket5
        close(lisentFd);
        LOG_DEBUG("listen socket fail\n");
        return -1;
    }
    SetBlockMode(lisentFd, false);
    return lisentFd;
}

int TcpAccept(char *ip, int listenFd, bool isBlock, bool needClose)
{
    (void)ip;
    int32_t ret;

    struct sockaddr_in clientAddr;
    unsigned int len = sizeof(struct sockaddr_in);
    int fd = -1;
    uint32_t tryNum = 0;
    LOG_DEBUG("tcp Accept ing...\n");
    do {
        fd = accept(listenFd, (struct sockaddr *)&clientAddr, &len);
        tryNum++;
        usleep(1000); // 1000 microseconds, that is, 1 ms
      // 10000: indicates that the system attempts to listen on the system for 10 seconds
    } while ((fd == -1) && (tryNum < 10000));
    if (fd == -1) {
        LOG_DEBUG("TCP accept fail\n");
        return -1;
    }

    // Whether to block the interface
    ret = SetBlockMode(fd, isBlock);
    if (ret != 0) {
        close(listenFd);
        close(fd);
        LOG_DEBUG("SetBlockMode ERROR");
    }
    // Disable listenFd
    if (needClose) {
        close(listenFd);
    }

    struct linger so_linger;
    so_linger.l_onoff = 1;
    so_linger.l_linger = 1;
    setsockopt(fd,SOL_SOCKET,SO_LINGER, &so_linger,sizeof(so_linger));

    LOG_DEBUG("accept a fd:%d\n", fd);
    return fd;
}

/* Disable the specified socket */
void TcpClose(int sd)
{
    close(sd);
}

int32_t TcpFrameWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
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
    ret = BSL_UIO_TcpMethod()->write(uio, sendBuf, sendLen, writeLen);
    if (sendLen != len && *writeLen != 0) {
        *writeLen = len;
    }
    FreeNewBuf(newBuf);
    return ret;
}

int32_t TcpFrameRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    int ret;
    ret = BSL_UIO_TcpMethod()->read(uio, buf, len, readLen);
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

int32_t SelectTcpWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    HLT_FrameHandle *frameHandle = GetFrameHandle();
    if (frameHandle->method.write != NULL) {
        return frameHandle->method.write(uio, buf, len, writeLen);
    }
    return TcpFrameWrite(uio, buf, len, writeLen);
}

int32_t SelectTcpRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    HLT_FrameHandle *frameHandle = GetFrameHandle();
    if (frameHandle->method.read != NULL) {
        return frameHandle->method.read(uio, buf, len, readLen);
    }
    return TcpFrameRead(uio, buf, len, readLen);
}

static BSL_UIO_Method g_TcpUioMethodDefault;

/* Provide the default Linux implementation method */
void *TcpGetDefaultMethod(void)
{
    const BSL_UIO_Method *ori = BSL_UIO_TcpMethod();
    memcpy(&g_TcpUioMethodDefault, ori, sizeof(g_TcpUioMethodDefault));
    g_TcpUioMethodDefault.write = SelectTcpWrite;
    g_TcpUioMethodDefault.read = SelectTcpRead;
    return &g_TcpUioMethodDefault;
}

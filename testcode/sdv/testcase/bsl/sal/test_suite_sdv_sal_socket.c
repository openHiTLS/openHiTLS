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

/* BEGIN_HEADER */

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include "bsl_sal.h"
#include "bsl_errno.h"

#define READ_TIME_OUT_SEC 3   // 3s timeout

/* END_HEADER */

/**
 * @test SDV_BSL_SAL_SOCKET_FUNC_TC001
 * @title Socket-related function test
 * @precon nan
 * @brief
 *    1. Call BSL_SAL_Socket to create a TCP socket. Expected result 1 is displayed.
 *    2. Set the TCP timeout period. Expected result 2 is obtained.
 *    3. Close tcp socket. Expected result 3 is obtained.
 *    4. Call BSL_SAL_Socket to create a UDP socket. Expected result 4 is displayed.
 *    5. Set the UDP timeout period. Expected result 5 is obtained.
 *    6. Close UDP socket. Expected result 6 is obtained.
 * @expect
 *    1. Created successfully.
 *    2. Setting successfully.
 *    3. Closed successfully.
 *    4. Created successfully.
 *    5. Setting successfully.
 *    6. Closed successfully.
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_SOCKET_FUNC_TC001(void)
{
    int32_t tcp = BSL_SAL_Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_TRUE(tcp != -1);
    struct timeval timeOut = { 0 };
    timeOut.tv_sec = READ_TIME_OUT_SEC;
    ASSERT_TRUE(BSL_SAL_SetSockopt(tcp, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeOut, sizeof(timeOut)) == 0);
    ASSERT_TRUE(BSL_SAL_SockClose(tcp) == 0);
    int32_t udp = BSL_SAL_Socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_TRUE(udp != -1);
    ASSERT_TRUE(BSL_SAL_SetSockopt(udp, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeOut, sizeof(timeOut)) == 0);
    ASSERT_TRUE(BSL_SAL_SockClose(udp) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    return;
}
/* END_CASE */

#ifdef HITLS_BSL_SAL_THREAD
static uint16_t GetPort()
{
    uint16_t port = 8888;
    char *userPort = getenv("FIXED_PORT");
    if (userPort == NULL) {
        const uint32_t basePort = 10000;
        port = basePort + getpid();
    }
    return port;
}

static void *TestTcpClient(void *args)
{
    (void)args;
    struct sockaddr_in remoteAddr;
    remoteAddr.sin_family = AF_INET;
    remoteAddr.sin_port = htons(GetPort());
    remoteAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    int32_t socketRemote = BSL_SAL_Socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_TRUE(socketRemote != -1);
    while(true) {
        int32_t ret = BSL_SAL_SockConnect(socketRemote, (BSL_SAL_SockAddr)&remoteAddr, sizeof(remoteAddr));
        if (ret == 0) {
            char *msg = "Hello,TCP!!";
            ASSERT_TRUE(BSL_SAL_SockSend(socketRemote, msg, strlen(msg), 0) >= 0);
            goto EXIT;
        }
        ASSERT_TRUE(BSL_SAL_SockGetLastSocketError() != 0);
    }
EXIT:
    BSL_SAL_SockClose(socketRemote);
    return NULL;
}

static void *TestTcpServer(void *args)
{
    (void)args;
    uint8_t buff[32] = {0};
    int serConn = -1;
    struct sockaddr_in localAddr = {0};
    struct sockaddr_in cliAddr = {0};
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(GetPort());
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    int32_t socketLocal = BSL_SAL_Socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_TRUE(socketLocal != -1);
    ASSERT_TRUE(BSL_SAL_SockBind(socketLocal, (BSL_SAL_SockAddr)&localAddr, sizeof(localAddr)) == 0);
    ASSERT_TRUE(BSL_SAL_SockListen(socketLocal, 5) == 0);
    socklen_t len = sizeof(cliAddr);
    serConn = accept(socketLocal, (struct sockaddr *)&cliAddr, &len);
    ASSERT_TRUE(serConn != -1);
    while(true) {
        if (BSL_SAL_SockRecv(serConn, buff, 32, 0) > 0) {
            goto EXIT;
        }
        ASSERT_TRUE(BSL_SAL_SockGetLastSocketError() != 0);
    }
EXIT:
    BSL_SAL_SockClose(socketLocal);
    BSL_SAL_SockClose(serConn);
    return NULL;
}
#endif

/**
 * @test SDV_BSL_SAL_SOCKET_FUNC_TC002
 * @title Socket-related function test
 * @precon nan
 * @brief
 *    1. Creating a TCP Server. Expected result 1 is obtained.
 *    2. Creating a TCP Client. Expected result 2 is obtained.
 * @expect
 *    1. Created successfully.
 *    2. Created successfully.
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_SOCKET_FUNC_TC002(void)
{
#ifndef HITLS_BSL_SAL_THREAD
    SKIP_TEST();
#else
    BSL_SAL_ThreadId serverThread = NULL;
    ASSERT_EQ(BSL_SAL_ThreadCreate(&serverThread, TestTcpServer, NULL), BSL_SUCCESS);
    BSL_SAL_ThreadId clientThread = NULL;
    ASSERT_EQ(BSL_SAL_ThreadCreate(&clientThread, TestTcpClient, NULL), BSL_SUCCESS);
EXIT:
    BSL_SAL_ThreadClose(serverThread);
    BSL_SAL_ThreadClose(clientThread);
#endif
}
/* END_CASE */

/**
 * @test  SDV_BSL_SAL_SELECT_FUNC_TC001
 * @title  Socket-related function test
 * @precon  nan
 * @brief
 *    1. Open the /dev/urandom file only. Expected result 1 is obtained.
 *    2. Call BSL_SAL_Select to check the number of open read-only descriptors.
         Expected result 2 is obtained.
 * @expect
 *    1. Opened successfully.
 *    2. Read-only descriptor open count is greater than 0
 */
/* BEGIN_CASE */
void SDV_BSL_SAL_SELECT_FUNC_TC001(void)
{
    const char *path = "/dev/urandom";
    int fd = open(path, O_RDONLY);
    ASSERT_TRUE(fd != -1);
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    ASSERT_TRUE(BSL_SAL_Select(fd + 1, &fds, NULL, NULL, &tv) > 0);
EXIT:
    close(fd);
}
/* END_CASE */
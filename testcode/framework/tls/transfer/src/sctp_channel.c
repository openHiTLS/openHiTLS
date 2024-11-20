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
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include "securec.h"
#include "logger.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls.h"
#include "tls.h"
#include "hs_ctx.h"
#include "bsl_errno.h"
#include "uio_base.h"
#include "hlt_type.h"
#include "socket_common.h"
#include "bsl_uio.h"
#include "uio_abstraction.h"
#define SUCCESS 0
#define ERROR (-1)

#define SCTP_DATA_CHUNK_TYPE 0x00
#define SCTP_FORWARD_TSN_CHUNK_TYPE 0xc0
#define SCTP_LISTEN_MAX 5
#define SCTP_GAUTH_CHUNKS_SIZE 256
#define SCTP_AUTH_ENABLE "echo 1 > /proc/sys/net/sctp/auth_enable"

int g_NeedCbsctpCtrlCmd;
int32_t SctpCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg);

/*
To enable the RFC 4895 about authenticating chunks:
$ sudo echo 1 > /proc/sys/net/sctp/auth_enable
To enable the RFC 5061 about dynamic address reconfiguration:
$ sudo echo 1 > /proc/sys/net/sctp/addip_enable
You may also want to use the dynamic address reconfiguration without necessarily enabling the chunk authentication:
$ sudo echo 1 > /proc/sys/net/sctp/addip_noauth_enable
*/
int32_t SctpEnableAuth(int32_t fd)
{
    /* To enable the RFC 4895 authentication block  */
    system(SCTP_AUTH_ENABLE);
    /* data chunks */
    struct sctp_authchunk auth;
    auth.sauth_chunk = SCTP_DATA_CHUNK_TYPE;
    int32_t ret = setsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_CHUNK, &auth, sizeof(struct sctp_authchunk));
    if (ret < 0) {
        LOG_ERROR("error while setsockopt SCTP_AUTH_CHUNK. ret is %d\n", ret);
        return ERROR;
    }
    /* FORWARD-TSN chunks */
    auth.sauth_chunk = SCTP_FORWARD_TSN_CHUNK_TYPE;
    ret = setsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_CHUNK, &auth,
        sizeof(struct sctp_authchunk));
    if (ret < 0) {
        LOG_ERROR("error while setsockopt SCTP_AUTH_CHUNK. ret is %d\n", ret);
        return ERROR;
    }
    LOG_DEBUG("SctpEnableAuth Success");
    return SUCCESS;
}

/* Obtain the number of transmitted streams */
static int32_t SctpGetSendStreamNum(int32_t fd, uint16_t *sendStreamNum)
{
    struct sctp_status status;
    socklen_t statusLen = sizeof(status);
    int32_t ret = getsockopt(fd, IPPROTO_SCTP, SCTP_STATUS, &status, &statusLen);
    if (ret < 0) {
        LOG_ERROR("error while geting socket option.\n");
        return ret;
    }
    *sendStreamNum = status.sstat_outstrms;
    return 0;
}

/* Connects to the peer and returns a socket descriptor.
   Currently, only one IP function is designed. If required, SCTP_Connect can be rewritten.
 */
int32_t SctpConnect(char *targetIP, int targetPort, bool isBlock)
{
    (void)targetIP;
    int32_t fd = 0;
    int32_t ret;
    struct sockaddr_in sockAddr;
    // Create a socket
    if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) == -1) {
        LOG_ERROR("Create Sock Fail");
        return ERROR;
    }

    int32_t option = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
        LOG_ERROR("Set Sock Opt Fail");
        goto ERR;
    }

    struct linger so_linger;
    so_linger.l_onoff = true;
    so_linger.l_linger = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger)) < 0) {
        close(fd);
        LOG_ERROR("setsockopt() linger fail\n");
        return -1;
    }

    /* Enable SCTP auth */
    ret = SctpEnableAuth(fd);
    if (ret != 0) {
        LOG_ERROR("SctpEnableAuth.");
        goto ERR;
    }

    /* Enable SCTP Events */
    struct sctp_event_subscribe events = {0};
    events.sctp_data_io_event = 1;
    ret = setsockopt(fd, SOL_SCTP, SCTP_EVENTS, (void *)&events, sizeof(events));
    if (ret < 0) {
        LOG_ERROR("setsockopt SCTP_EVENTS.");
        goto ERR;
    }

    // Set the protocol and port number
    bzero(&sockAddr, sizeof(struct sockaddr_in));
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_port = htons(targetPort);
    // Set the IP address
    sockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connection
    int16_t tryNum = 0;
    sctp_assoc_t assoc_id;
    LOG_DEBUG("Try Sctp Connect...");
    do {
        ret = sctp_connectx(fd, (struct sockaddr*)&sockAddr, 1, &assoc_id);
        tryNum++;
        usleep(1000);                      // 1000microseconds
    } while ((ret != 0) && (tryNum < 6000)); // 6000 indicates that the connection is attempted within 6 seconds
    if (ret != 0) {
        LOG_ERROR("Sctp Connect Fail, ret is %d error id: %d\n", ret, errno);
        goto ERR;
    }
    LOG_DEBUG("SCTP Connect Success");
    uint16_t sendStreamNum;
    ret = SctpGetSendStreamNum(fd, &sendStreamNum);
    if (ret != 0) {
        LOG_ERROR("SctpGetSendStreamNum error.");
        goto ERR;
    }
    // Whether to set the blocking interface
    ret = SetBlockMode(fd, isBlock);
    return fd;

ERR:
    close(fd);
    return ERROR;
}

int32_t SctpBind(int port)
{
    int32_t lisentFd;
    struct sockaddr_in serverAddr;
    int32_t ret;

    // Create a socket
    lisentFd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (lisentFd == -1) {
        LOG_ERROR("create socket() fail.");
        return ERROR;
    }

    int32_t option = 1;
    if (setsockopt(lisentFd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
        LOG_ERROR("setsockopt fail.");
        goto ERR;
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
    bzero(&serverAddr, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    const int32_t addr_count = 1;
    int32_t tryNum = 0;
    // Bind fails. Continue to bind
    LOG_DEBUG("Bind Ing...");
    do {
        ret = sctp_bindx(lisentFd, (struct sockaddr*)&serverAddr, addr_count, SCTP_BINDX_ADD_ADDR);
        usleep(1000); // 1000 microseconds, that is, 1 ms
        tryNum++;
    } while ((ret != 0) && (tryNum < 6000)); // 6000: indicates that the binding attempt is 6 seconds
    if (ret != 0) {
        LOG_ERROR("sctp_bindx socket fail error id: %d\n", errno);
        goto ERR;
    }
    LOG_DEBUG("SCTP BIND SUCCESS");
    /* Enable SCTP auth */
    ret = SctpEnableAuth(lisentFd);
    if (ret == ERROR) {
        LOG_ERROR("SctpEnableAuth Error");
        goto ERR;
    }

    /* Enable SCTP Events */
    struct sctp_event_subscribe events = {0};
    events.sctp_data_io_event = 1;
    ret = setsockopt(lisentFd, SOL_SCTP, SCTP_EVENTS, (void *)&events, sizeof(events));
    if (ret < 0) {
        LOG_ERROR("setsockopt SCTP_EVENTS error.");
        goto ERR;
    }

    if (listen(lisentFd, SCTP_LISTEN_MAX) != 0) {
        LOG_ERROR("listen socket fail, error id is %d\n", errno);
        goto ERR;
    }

    return lisentFd;

ERR:
    close(lisentFd);
    return ERROR;
}

int32_t SctpAccept(char* ip, int listenFd, bool isBlock)
{
    (void)ip;
    int32_t ret;
    struct sockaddr_in sockAddr;

    uint32_t len = sizeof(struct sockaddr_in);
    int32_t fd;
    uint32_t tryNum;
    tryNum = 0;
    do {
        fd = accept(listenFd, (struct sockaddr *)&sockAddr, &len);
        tryNum++;
        usleep(1000); // 1000 microseconds, that is, 1 ms
      // 10000: indicates that the system attempts to listen on the system for 10 seconds
    } while ((fd < 0) && (tryNum < 10000));
    if (fd < 0) {
        LOG_ERROR("SCTP Accept Fail, error id is %d\n", errno);
        close(listenFd);
        return ERROR;
    }

    LOG_DEBUG("SCTP Accept Success");
    uint16_t sendStreamNum;
    ret = SctpGetSendStreamNum(fd, &sendStreamNum);
    if (ret != 0) {
        LOG_ERROR("SctpGetSendStreamNum error.");
        close(listenFd);
        close(fd);
        return ERROR;
    }

    // Indicates whether to block the interface
    ret = SetBlockMode(fd, isBlock);
    if (ret != SUCCESS) {
        close(listenFd);
        close(fd);
        LOG_ERROR("SetBlockMode ERROR");
    }
    // Disable listenFd
    close(listenFd);
    return fd;
}

/* closes the given socket descriptor. */
void SctpClose(int32_t fd)
{
    close(fd);
}

void SetNeedCbSctpCtrlCmd(int cmd)
{
    g_NeedCbsctpCtrlCmd = cmd;
}



int32_t SctpFrameWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    int32_t ret;
    uint8_t *newBuf = NULL;
    const void *sendBuf = buf;
    uint32_t sendLen = len;
    HLT_FrameHandle *frameHandle = GetFrameHandle();

    if (frameHandle->frameCallBack != NULL && frameHandle->pointType == POINT_SEND) {
        newBuf = GetNewBuf(buf, len, &sendLen);
        if (sendLen == 0) { // when sendLen changes and becomes 0, the value is IO_BUSY
            *writeLen = 0;
            return BSL_SUCCESS;
        }
        if (newBuf != NULL) {
            sendBuf = (void *)newBuf;
        }
    }
    ret = BSL_UIO_SctpMethod()->write(uio, sendBuf, sendLen, writeLen);
    if (sendLen != len && *writeLen != 0) {
        *writeLen = len;
    }
    FreeNewBuf(newBuf);
    return ret;
}

int32_t SctpFrameRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    int ret;
    ret = BSL_UIO_SctpMethod()->read(uio, buf, len, readLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    uint8_t *newBuf = NULL;
    uint32_t packLen = *readLen;
    HLT_FrameHandle *frameHandle = GetFrameHandle();
    if (frameHandle->frameCallBack != NULL && frameHandle->pointType == POINT_RECV) {
        newBuf = GetNewBuf(buf, len, &packLen);
        if (packLen == 0) { // when packLen changes and becomes 0, the value is IO_BUSY
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

int32_t SelectSctpWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    HLT_FrameHandle *frameHandle = GetFrameHandle();
    if (frameHandle->method.write != NULL) {
        return frameHandle->method.write(uio, buf, len, writeLen);
    }
    return SctpFrameWrite(uio, buf, len, writeLen);
}

int32_t SelectSctpRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    HLT_FrameHandle *frameHandle = GetFrameHandle();
    if (frameHandle->method.read != NULL) {
        return frameHandle->method.read(uio, buf, len, readLen);
    }
    return SctpFrameRead(uio, buf, len, readLen);
}

int32_t SelectSctpCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *param)
{
    HLT_FrameHandle *frameHandle = GetFrameHandle();
    if (frameHandle->method.ctrl != NULL) {
        return frameHandle->method.ctrl(uio, cmd, larg, param);
    }
    return BSL_UIO_SctpMethod()->ctrl(uio, cmd, larg, param);
}

static BSL_UIO_Method g_SctpUioMethodDefault;

/* Provide the default Linux implementation method */
BSL_UIO_Method *SctpGetDefaultMethod(void)
{
    const BSL_UIO_Method *ori = BSL_UIO_SctpMethod();
    memcpy(&g_SctpUioMethodDefault, ori, sizeof(g_SctpUioMethodDefault));
    g_SctpUioMethodDefault.write = SelectSctpWrite;
    g_SctpUioMethodDefault.read = SelectSctpRead;
    g_SctpUioMethodDefault.ctrl = SelectSctpCtrl;
    return &g_SctpUioMethodDefault;
}

/**
 * @brief   Implement the write interface, specifying whether the flow is out of order and the flow ID
 *
 * @param   uio [IN] the point to the UIO.
 * @param   buf [IN] Transmitted data
 * @param   len [IN] Send length
 * @param   writeLen [IN] Length of the successfully sent message
 * @return  BSL_SUCCESS succeeded
            BSL_UIO_FAIL    failure
            BSL_UIO_IO_EXCEPTION   IOexception
 */
int32_t SctpDefaultWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    /* set flags */
    // is set to SCTP_UNORD:00-20:00, the messages are sent in disorder. 
    // Whether the messages are sent in disorder is defined by the user
    const uint32_t flags = SCTP_SACK_IMMEDIATELY;
    uint16_t sendStreamId = 0;
    int32_t ret = uio->method.ctrl(uio, BSL_UIO_SCTP_GET_SEND_STREAM_ID, sizeof(sendStreamId), &sendStreamId);
    if (ret != BSL_SUCCESS) {
        LOG_ERROR("error: get sctp send stream id fail %d", ret);
        return ret;
    }
    int32_t fd = BSL_UIO_GetFd(uio);
    if (fd < 0) {
        LOG_ERROR("error: get fd fail");
        return BSL_UIO_IO_EXCEPTION;
    }
    ret = sctp_sendmsg(fd, buf, len, NULL, 0, 0, flags, sendStreamId, 0, 0);
    if (ret < 0) {
        /* Fatal error */
        LOG_ERROR("SCTP ERROR IS %d", errno);
        return BSL_UIO_IO_EXCEPTION;
    } else if (ret == 0) {
        return BSL_UIO_IO_EXCEPTION;
    }
    *writeLen = ret;

    return BSL_SUCCESS;
}
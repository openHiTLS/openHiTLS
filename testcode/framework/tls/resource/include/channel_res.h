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

#ifndef CHANNEL_RES_H
#define CHANNEL_RES_H

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include "lock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CONTROL_CHANNEL_MAX_MSG_LEN (20 * 1024)
#define DOMAIN_PATH_LEN (128)
#define MAX_SEND_BUFFER_NUM (100)
#define MAX_RCV_BUFFER_NUM (100)

typedef struct {
    uint8_t *data;
    uint32_t dataLen;
} DataBuf;

typedef struct {
    char data[CONTROL_CHANNEL_MAX_MSG_LEN];
    uint32_t dataLen;
} ControlChannelBuf;

typedef struct {
    char srcDomainPath[DOMAIN_PATH_LEN];
    char peerDomainPath[DOMAIN_PATH_LEN];
    struct sockaddr_un srcAddr;
    struct sockaddr_un peerAddr;
    int32_t sockFd;
    char sendBuffer[MAX_SEND_BUFFER_NUM][CONTROL_CHANNEL_MAX_MSG_LEN];
    char rcvBuffer[MAX_RCV_BUFFER_NUM][CONTROL_CHANNEL_MAX_MSG_LEN];
    uint8_t sendBufferNum;
    Lock *sendBufferLock;
    uint8_t rcvBufferNum;
    Lock *rcvBufferLock;
    pthread_t tid;
    bool isExit;
} ControlChannelRes;

/**
* @brief  Control Link Resource Initialization
*/
int InitControlChannelRes(char *srcDomainPath, int srcDomainPathLen, char *peerDomainPath, int peerDomainPathLen);

/**
* @brief  Release control link resources.
*/
void FreeControlChannelRes(void);

/**
* @brief  Obtaining Control Link Resources
*/
ControlChannelRes* GetControlChannelRes(void);

/**
* @brief  Writes data to the control link
*/
int PushResultToChannelSendBuffer(ControlChannelRes *channelInfo, char *result);

/**
* @brief  Read data from the control link
*/
int PushResultToChannelRcvBuffer(ControlChannelRes *channelInfo, char *result);

/**
* @brief  Writes data to the control link by ID
*/
int PushResultToChannelIdBuffer(ControlChannelRes *channelInfo, char *result, int id);

#ifdef __cplusplus
}
#endif

#endif // CHANNEL_RES_H

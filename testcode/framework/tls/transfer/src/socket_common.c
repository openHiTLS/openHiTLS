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
#include <sys/time.h>

#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls.h"
#include "tls.h"
#include "hs_ctx.h"
#include "bsl_errno.h"
#include "uio_base.h"

#include "frame_msg.h"
#include "logger.h"
#include "hlt_type.h"

#define SUCCESS 0
#define ERROR (-1)

#define MAX_LEN (20 * 1024)

/* set block mode. */
int32_t SetBlockMode(int32_t sd, bool isBlock)
{
    if (isBlock) {
        LOG_DEBUG("Socket Set Block Mode");
        int flag;
        flag = fcntl(sd, F_GETFL, 0);
        flag &= ~O_NONBLOCK;
        if (fcntl(sd, F_SETFL, flag) < 0) {
            LOG_ERROR("fcntl fail");
            return ERROR;
        }
    } else {
        LOG_DEBUG("Socket Set Unblock Mode");
        int flag;
        flag = fcntl(sd, F_GETFL, 0);
        flag |= O_NONBLOCK;
        if (fcntl(sd, F_SETFL, flag) < 0) {
            LOG_ERROR("fcntl fail");
            return ERROR;
        }
    }
    return SUCCESS;
}

/**
 * @brief   Check whether there are fatal I/O errors
 *
 * @param   err [IN] Error type
 *
 * @return  true :A fatal error occurs
 *          false:No fatal error occurs
 */
bool IsNonFatalErr(int32_t err)
{
    bool ret = true;
    /** @alias Check whether err is a fatal error and modify ret */
    switch (err) {
#if defined(ENOTCONN)
        case ENOTCONN:
#endif

#ifdef EINTR
        case EINTR:
#endif

#ifdef EINPROGRESS
        case EINPROGRESS:
#endif

#ifdef EWOULDBLOCK
#if !defined(WSAEWOULDBLOCK) || WSAEWOULDBLOCK != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
#endif

#ifdef EAGAIN
#if EWOULDBLOCK != EAGAIN
        case EAGAIN:
#endif
#endif

#ifdef EALREADY
        case EALREADY:
#endif

#ifdef EPROTO
        case EPROTO:
#endif
            ret = true;
            break;
        default:
            ret = false;
            break;
    }
    return ret;
}

static HLT_FrameHandle g_frameHandle;

int32_t SetFrameHandle(HLT_FrameHandle *frameHandle)
{
    if (frameHandle == NULL || frameHandle->ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    g_frameHandle.ctx = frameHandle->ctx;
    g_frameHandle.frameCallBack = frameHandle->frameCallBack;
    g_frameHandle.userData = frameHandle->userData;
    g_frameHandle.expectHsType = frameHandle->expectHsType;
    g_frameHandle.expectReType = frameHandle->expectReType;
    g_frameHandle.ioState = frameHandle->ioState;
    g_frameHandle.pointType = frameHandle->pointType;
    g_frameHandle.method.write = frameHandle->method.write;
    g_frameHandle.method.read = frameHandle->method.read;
    g_frameHandle.method.ctrl = frameHandle->method.ctrl;

    return HITLS_SUCCESS;
}

void CleanFrameHandle(void)
{
    g_frameHandle.ctx = NULL;
    g_frameHandle.frameCallBack = NULL;
    g_frameHandle.userData = NULL;
    g_frameHandle.expectHsType = 0;
    g_frameHandle.expectReType = 0;
    g_frameHandle.ioState = 0;
    g_frameHandle.pointType = 0;
    g_frameHandle.method.write = NULL;
    g_frameHandle.method.read = NULL;
    g_frameHandle.method.ctrl = NULL;
}

HLT_FrameHandle *GetFrameHandle(void)
{
    return &g_frameHandle;
}

/* Obtain the frameType. The input parameters frameHandle and frameType must not be empty */
static int32_t GetFrameType(HLT_FrameHandle *frameHandle, FRAME_Type *frameType)
{
    if (frameHandle->ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    TLS_Ctx *tmpCtx = (TLS_Ctx *)frameHandle->ctx;
    frameType->versionType = tmpCtx->negotiatedInfo.version > 0 ?
        tmpCtx->negotiatedInfo.version : tmpCtx->config.tlsConfig.maxVersion;
    frameType->keyExType = tmpCtx->hsCtx->kxCtx->keyExchAlgo;
    frameType->recordType = frameHandle->expectReType;
    frameType->handshakeType = frameHandle->expectHsType;
    return HITLS_SUCCESS;
}

/* Verify whether the parsed msg meets the requirements. Restrict the msg input parameter */
static bool CheckHandleType(FRAME_Msg *msg)
{
    if (msg->recType.data != REC_TYPE_HANDSHAKE) {
        if ((int32_t)msg->recType.data == g_frameHandle.expectReType) {
            return true;
        }
    } else {
        if ((int32_t)msg->recType.data == g_frameHandle.expectReType &&
            (int32_t)msg->body.hsMsg.type.data == g_frameHandle.expectHsType) {
            return true;
        }
    }
    return false;
}

/* Release the newbuf */
void FreeNewBuf(void *newBuf)
{
    if (newBuf != NULL) {
        free(newBuf);
        newBuf = NULL;
    }
}

/* Obtain the newbuf by parsing the buffer. The input parameter of the packageLen constraint is not empty */
uint8_t *GetNewBuf(const void *buf, uint32_t len, uint32_t *packLen)
{
    uint32_t packLenTmp = 0;
    /* Obtain the frameType */
    FRAME_Type frameType = { 0 };
    if (GetFrameType(&g_frameHandle, &frameType) != HITLS_SUCCESS) {
        return NULL;
    }
    /* Unpack the buffer into the msg structure */
    uint32_t parseLen = 0;
    FRAME_Msg msg = { 0 };
    uint32_t offset = 0;
    uint8_t *newBuf = (uint8_t *)calloc(MAX_LEN, sizeof(uint8_t));
    uint32_t newOffset = 0;

    while (offset < *packLen) {
        /* Currently, encryption and decryption are not performed. 
         * Therefore, the return value is not determined 
         * because the encrypted messages such as finished messages will fail to be parsed 
         */
        (void)FRAME_ParseMsg(&frameType, &((uint8_t*)buf)[offset], len - offset, &msg, &parseLen);

        if (CheckHandleType(&msg)) {
            if (g_frameHandle.ioState == EXP_IO_BUSY) {
                FRAME_CleanMsg(&frameType, &msg);
                /* Set I/O to busy */
                *packLen = 0;
                FreeNewBuf(newBuf);
                return NULL;
            }
            if (g_frameHandle.userData == NULL) {
                g_frameHandle.userData = (void *)&frameType;
            }
            g_frameHandle.frameCallBack(&msg, g_frameHandle.userData);
            if (g_frameHandle.userData == (void *)&frameType) {
                g_frameHandle.userData = NULL;
            }
            /* Pack the newly constructed msg into a buffer */
            if (FRAME_PackMsg(&frameType, &msg, &newBuf[newOffset], MAX_LEN - newOffset, &packLenTmp) != HITLS_SUCCESS) {
                FRAME_CleanMsg(&frameType, &msg);
                FreeNewBuf(newBuf);
                return NULL;
            }
            newOffset += packLenTmp;
        } else {
            memcpy_s(&newBuf[newOffset], MAX_LEN - newOffset, &((uint8_t*)buf)[offset], parseLen);
            newOffset += parseLen;
        }
        offset += parseLen;
        FRAME_CleanMsg(&frameType, &msg);
    }

    /* Check whether the package is reassembled. If not, *packLen should not be changed */
    if (packLenTmp == 0) {
        FreeNewBuf(newBuf);
        return NULL;
    }

    *packLen = newOffset;
    return newBuf;
}
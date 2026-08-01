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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls.h"
#include "bsl_uio.h"
#include "tls.h"
#include "hs_ctx.h"
#include "bsl_errno.h"
#include "uio_base.h"

#include "frame_msg.h"
#include "logger.h"
#include "socket_common.h"

#define SUCCESS 0
#define ERROR (-1)

#define MAX_LEN (20 * 1024)
#define TLS_RECORD_HEADER_LEN 5u
#define TLS_RECORD_LENGTH_OFFSET 3u
#define FRAME_STREAM_STATE_NUM 32u
#define FRAME_STREAM_BUF_SIZE (MAX_LEN * 2u)

typedef struct {
    int32_t fd;
    HLT_PointType pointType;
    bool used;
    uint8_t inBuf[FRAME_STREAM_BUF_SIZE];
    uint32_t inLen;
    uint8_t outBuf[FRAME_STREAM_BUF_SIZE];
    uint32_t outOff;
    uint32_t outLen;
} FrameStreamState;

static FrameStreamState g_frameStreamState[FRAME_STREAM_STATE_NUM];

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
#ifdef EMSGSIZE
        case EMSGSIZE:
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
    g_frameHandle.method.uioWrite = frameHandle->method.uioWrite;
    g_frameHandle.method.uioRead = frameHandle->method.uioRead;
    g_frameHandle.method.uioCtrl = frameHandle->method.uioCtrl;

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
    g_frameHandle.method.uioWrite = NULL;
    g_frameHandle.method.uioRead = NULL;
    g_frameHandle.method.uioCtrl = NULL;
    CleanFrameStreamState();
}

void CleanFrameStreamState(void)
{
    memset(g_frameStreamState, 0, sizeof(g_frameStreamState));
}

void CleanFrameStreamStateByFd(int32_t fd)
{
    for (uint32_t i = 0; i < FRAME_STREAM_STATE_NUM; i++) {
        if (g_frameStreamState[i].used && g_frameStreamState[i].fd == fd) {
            memset(&g_frameStreamState[i], 0, sizeof(g_frameStreamState[i]));
        }
    }
}

HLT_FrameHandle *GetFrameHandle(void)
{
    return &g_frameHandle;
}

static bool UioChainHasTransport(void *uio, BSL_UIO_TransportType transportType)
{
    return uio != NULL && BSL_UIO_GetUioChainTransportType((BSL_UIO *)uio, transportType);
}

static bool CtxHasDatagramTransport(const TLS_Ctx *ctx)
{
    return UioChainHasTransport(ctx->uio, BSL_UIO_UDP) || UioChainHasTransport(ctx->rUio, BSL_UIO_UDP) ||
        UioChainHasTransport(ctx->uio, BSL_UIO_SCTP) || UioChainHasTransport(ctx->rUio, BSL_UIO_SCTP);
}

/* Obtain the frameType. The input parameters frameHandle and frameType must not be empty */
static int32_t GetFrameType(HLT_FrameHandle *frameHandle, FRAME_Type *frameType)
{
    if (frameHandle->ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    TLS_Ctx *tmpCtx = (TLS_Ctx *)frameHandle->ctx;
    if (tmpCtx->hsCtx == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    frameType->versionType = tmpCtx->negotiatedInfo.version > 0 ?
        tmpCtx->negotiatedInfo.version : tmpCtx->config.tlsConfig.maxVersion;
    frameType->keyExType = tmpCtx->hsCtx->kxCtx != NULL ? tmpCtx->hsCtx->kxCtx->keyExchAlgo : HITLS_KEY_EXCH_NULL;
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

static bool IsKnownTlsRecordType(uint8_t recordType)
{
    return recordType == REC_TYPE_CHANGE_CIPHER_SPEC || recordType == REC_TYPE_ALERT ||
        recordType == REC_TYPE_HANDSHAKE || recordType == REC_TYPE_APP;
}

static int32_t GetTlsRecordLen(const uint8_t *buf, uint32_t len, uint32_t *recordLen, bool *isComplete)
{
    if (buf == NULL || recordLen == NULL || isComplete == NULL) {
        return HITLS_NULL_INPUT;
    }
    *recordLen = 0;
    *isComplete = false;
    if (len < TLS_RECORD_HEADER_LEN) {
        return HITLS_SUCCESS;
    }
    if (!IsKnownTlsRecordType(buf[0])) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t bodyLen = ((uint32_t)buf[TLS_RECORD_LENGTH_OFFSET] << 8) | buf[TLS_RECORD_LENGTH_OFFSET + 1u];
    if (bodyLen > MAX_LEN - TLS_RECORD_HEADER_LEN) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    *recordLen = TLS_RECORD_HEADER_LEN + bodyLen;
    *isComplete = len >= *recordLen;
    return HITLS_SUCCESS;
}

static bool AppendFrameStreamOutput(FrameStreamState *state, const uint8_t *buf, uint32_t len)
{
    if (len > FRAME_STREAM_BUF_SIZE - state->outLen) {
        return false;
    }
    memcpy(&state->outBuf[state->outLen], buf, len);
    state->outLen += len;
    return true;
}

static uint32_t DrainFrameStreamOutput(FrameStreamState *state, void *buf, uint32_t len)
{
    uint32_t pending = state->outLen - state->outOff;
    uint32_t copyLen = len < pending ? len : pending;
    if (copyLen == 0) {
        return 0;
    }
    memcpy(buf, &state->outBuf[state->outOff], copyLen);
    state->outOff += copyLen;
    if (state->outOff == state->outLen) {
        state->outOff = 0;
        state->outLen = 0;
    }
    return copyLen;
}

static void ResetFrameStreamBuffer(FrameStreamState *state)
{
    state->inLen = 0;
    state->outOff = 0;
    state->outLen = 0;
}

static FrameStreamState *FindFrameStreamState(int32_t fd, HLT_PointType pointType)
{
    for (uint32_t i = 0; i < FRAME_STREAM_STATE_NUM; i++) {
        if (g_frameStreamState[i].used && g_frameStreamState[i].fd == fd &&
            g_frameStreamState[i].pointType == pointType) {
            return &g_frameStreamState[i];
        }
    }
    return NULL;
}

static FrameStreamState *GetFrameStreamState(int32_t fd, HLT_PointType pointType)
{
    FrameStreamState *state = FindFrameStreamState(fd, pointType);
    if (state != NULL) {
        return state;
    }
    for (uint32_t i = 0; i < FRAME_STREAM_STATE_NUM; i++) {
        if (!g_frameStreamState[i].used) {
            g_frameStreamState[i].used = true;
            g_frameStreamState[i].fd = fd;
            g_frameStreamState[i].pointType = pointType;
            return &g_frameStreamState[i];
        }
    }
    return NULL;
}

int32_t PopFrameStreamOutput(int32_t fd, HLT_PointType pointType, void *buf, uint32_t len, uint32_t *readLen)
{
    if (buf == NULL || readLen == NULL) {
        return HITLS_NULL_INPUT;
    }
    *readLen = 0;
    FrameStreamState *state = FindFrameStreamState(fd, pointType);
    if (state == NULL) {
        return HITLS_SUCCESS;
    }
    *readLen = DrainFrameStreamOutput(state, buf, len);
    return HITLS_SUCCESS;
}

int32_t PushFrameStreamInput(int32_t fd, HLT_PointType pointType, const void *in, uint32_t inLen,
    void *out, uint32_t outSize, uint32_t *outLen)
{
    if (out == NULL || outLen == NULL || (in == NULL && inLen != 0)) {
        return HITLS_NULL_INPUT;
    }
    *outLen = 0;
    FrameStreamState *state = GetFrameStreamState(fd, pointType);
    if (state == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    if (inLen > FRAME_STREAM_BUF_SIZE - state->inLen) {
        ResetFrameStreamBuffer(state);
        return HITLS_INTERNAL_EXCEPTION;
    }
    if (inLen != 0) {
        memcpy(&state->inBuf[state->inLen], in, inLen);
        state->inLen += inLen;
    }
    if (state->outLen != state->outOff) {
        *outLen = DrainFrameStreamOutput(state, out, outSize);
        return HITLS_SUCCESS;
    }

    uint32_t offset = 0;
    while (offset < state->inLen) {
        uint32_t recordLen = 0;
        bool isComplete = false;
        int32_t ret = GetTlsRecordLen(&state->inBuf[offset], state->inLen - offset, &recordLen, &isComplete);
        if (ret != HITLS_SUCCESS) {
            if (!AppendFrameStreamOutput(state, &state->inBuf[offset], state->inLen - offset)) {
                ResetFrameStreamBuffer(state);
                return HITLS_INTERNAL_EXCEPTION;
            }
            offset = state->inLen;
            break;
        }
        if (!isComplete) {
            break;
        }

        uint32_t packLen = recordLen;
        uint8_t *newBuf = GetNewBuf(&state->inBuf[offset], recordLen, &packLen);
        if (packLen == 0) {
            FreeNewBuf(newBuf);
            if (offset != 0) {
                uint32_t remain = state->inLen - offset;
                if (remain != 0) {
                    memmove(state->inBuf, &state->inBuf[offset], remain);
                }
                state->inLen = remain;
            }
            *outLen = DrainFrameStreamOutput(state, out, outSize);
            return HITLS_SUCCESS;
        }
        if (newBuf != NULL) {
            if (!AppendFrameStreamOutput(state, newBuf, packLen)) {
                FreeNewBuf(newBuf);
                ResetFrameStreamBuffer(state);
                return HITLS_INTERNAL_EXCEPTION;
            }
            FreeNewBuf(newBuf);
        } else if (!AppendFrameStreamOutput(state, &state->inBuf[offset], recordLen)) {
            ResetFrameStreamBuffer(state);
            return HITLS_INTERNAL_EXCEPTION;
        }
        offset += recordLen;
    }

    if (offset != 0) {
        uint32_t remain = state->inLen - offset;
        if (remain != 0) {
            memmove(state->inBuf, &state->inBuf[offset], remain);
        }
        state->inLen = remain;
    }
    *outLen = DrainFrameStreamOutput(state, out, outSize);
    return HITLS_SUCCESS;
}

static uint8_t *GetDatagramNewBuf(const void *buf, uint32_t *packLen, FRAME_Type *frameType)
{
    uint32_t packLenTmp = 0;
    bool isRepacked = false;
    uint32_t parseLen = 0;
    FRAME_Msg msg = { 0 };
    uint32_t offset = 0;
    uint8_t *newBuf = (uint8_t *)calloc(MAX_LEN, sizeof(uint8_t));
    if (newBuf == NULL) {
        return NULL;
    }
    uint32_t newOffset = 0;

    while (offset < *packLen) {
        parseLen = 0;
        memset(&msg, 0, sizeof(msg));
        int32_t ret = FRAME_ParseMsg(frameType, &((uint8_t*)buf)[offset], *packLen - offset, &msg, &parseLen);
        if (parseLen == 0 || parseLen > *packLen - offset) {
            FRAME_CleanMsg(frameType, &msg);
            FreeNewBuf(newBuf);
            return NULL;
        }

        if (ret != HITLS_SUCCESS) {
            if (newOffset > MAX_LEN - parseLen) {
                FRAME_CleanMsg(frameType, &msg);
                FreeNewBuf(newBuf);
                return NULL;
            }
            memcpy(&newBuf[newOffset], &((uint8_t*)buf)[offset], parseLen);
            newOffset += parseLen;
            offset += parseLen;
            FRAME_CleanMsg(frameType, &msg);
            continue;
        }

        if (CheckHandleType(&msg)) {
            if (g_frameHandle.ioState == EXP_IO_BUSY) {
                FRAME_CleanMsg(frameType, &msg);
                *packLen = 0;
                FreeNewBuf(newBuf);
                return NULL;
            }
            if (g_frameHandle.userData == NULL) {
                g_frameHandle.userData = (void *)frameType;
            }
            g_frameHandle.frameCallBack(&msg, g_frameHandle.userData);
            if (g_frameHandle.userData == (void *)frameType) {
                g_frameHandle.userData = NULL;
            }
            if (newOffset >= MAX_LEN) {
                FRAME_CleanMsg(frameType, &msg);
                FreeNewBuf(newBuf);
                return NULL;
            }
            packLenTmp = 0;
            if (FRAME_PackMsg(frameType, &msg, &newBuf[newOffset], MAX_LEN - newOffset, &packLenTmp) !=
                HITLS_SUCCESS) {
                FRAME_CleanMsg(frameType, &msg);
                FreeNewBuf(newBuf);
                return NULL;
            }
            if (packLenTmp > MAX_LEN - newOffset) {
                FRAME_CleanMsg(frameType, &msg);
                FreeNewBuf(newBuf);
                return NULL;
            }
            isRepacked = true;
            newOffset += packLenTmp;
        } else {
            if (newOffset > MAX_LEN - parseLen) {
                FRAME_CleanMsg(frameType, &msg);
                FreeNewBuf(newBuf);
                return NULL;
            }
            memcpy(&newBuf[newOffset], &((uint8_t*)buf)[offset], parseLen);
            newOffset += parseLen;
        }
        offset += parseLen;
        FRAME_CleanMsg(frameType, &msg);
    }

    if (!isRepacked) {
        FreeNewBuf(newBuf);
        return NULL;
    }

    *packLen = newOffset;
    return newBuf;
}

/* Obtain the newbuf by parsing the buffer. The input parameter of the packageLen constraint is not empty */
uint8_t *GetNewBuf(const void *buf, uint32_t len, uint32_t *packLen)
{
    if (buf == NULL || packLen == NULL || *packLen == 0 || *packLen > len) {
        return NULL;
    }
    uint32_t packLenTmp = 0;
    bool isRepacked = false;
    /* Obtain the frameType */
    FRAME_Type frameType = { 0 };
    if (GetFrameType(&g_frameHandle, &frameType) != HITLS_SUCCESS) {
        return NULL;
    }
    /*
     * Only TCP needs record-boundary recovery. Datagram HLT hooks keep the legacy
     * parser/packer transportType; switching it to UDP/SCTP repacks DTLS records
     * and changes existing callback-loop behavior.
     */
    if (CtxHasDatagramTransport((TLS_Ctx *)g_frameHandle.ctx)) {
        return GetDatagramNewBuf(buf, packLen, &frameType);
    }
    /* Unpack the buffer into the msg structure */
    uint32_t parseLen = 0;
    FRAME_Msg msg = { 0 };
    uint32_t offset = 0;
    uint8_t *newBuf = (uint8_t *)calloc(MAX_LEN, sizeof(uint8_t));
    if (newBuf == NULL) {
        return NULL;
    }
    uint32_t newOffset = 0;

    while (offset < *packLen) {
        parseLen = 0;
        memset(&msg, 0, sizeof(msg));
        uint32_t recordLen = 0;
        bool isComplete = false;
        if (GetTlsRecordLen(&((uint8_t*)buf)[offset], *packLen - offset, &recordLen, &isComplete) !=
            HITLS_SUCCESS || !isComplete) {
            FreeNewBuf(newBuf);
            return NULL;
        }
        /* Currently, encryption and decryption are not performed. 
         * Therefore, the return value is not determined 
         * because the encrypted messages such as finished messages will fail to be parsed 
         */
        int32_t ret = FRAME_ParseMsg(&frameType, &((uint8_t*)buf)[offset], recordLen, &msg, &parseLen);
        if (ret != HITLS_SUCCESS || parseLen == 0 || parseLen > recordLen) {
            if (newOffset > MAX_LEN - recordLen) {
                FreeNewBuf(newBuf);
                return NULL;
            }
            memcpy(&newBuf[newOffset], &((uint8_t*)buf)[offset], recordLen);
            newOffset += recordLen;
            offset += recordLen;
            FRAME_CleanMsg(&frameType, &msg);
            continue;
        }

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
            if (newOffset >= MAX_LEN) {
                FRAME_CleanMsg(&frameType, &msg);
                FreeNewBuf(newBuf);
                return NULL;
            }
            packLenTmp = 0;
            if (FRAME_PackMsg(&frameType, &msg, &newBuf[newOffset], MAX_LEN - newOffset, &packLenTmp) !=
                HITLS_SUCCESS) {
                FRAME_CleanMsg(&frameType, &msg);
                FreeNewBuf(newBuf);
                return NULL;
            }
            if (packLenTmp > MAX_LEN - newOffset) {
                FRAME_CleanMsg(&frameType, &msg);
                FreeNewBuf(newBuf);
                return NULL;
            }
            isRepacked = true;
            newOffset += packLenTmp;
        } else {
            if (newOffset > MAX_LEN - recordLen) {
                FRAME_CleanMsg(&frameType, &msg);
                FreeNewBuf(newBuf);
                return NULL;
            }
            memcpy(&newBuf[newOffset], &((uint8_t*)buf)[offset], recordLen);
            newOffset += recordLen;
        }
        offset += recordLen;
        FRAME_CleanMsg(&frameType, &msg);
    }

    /* Check whether the package is reassembled. If not, *packLen should not be changed */
    if (!isRepacked) {
        FreeNewBuf(newBuf);
        return NULL;
    }

    *packLen = newOffset;
    return newBuf;
}

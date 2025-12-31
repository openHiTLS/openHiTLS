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

#include "simulate_io.h"
#include "hitls_error.h"
#include "bsl_sal.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "securec.h"

#define FAKE_BSL_UIO_FD 666
#define IPV4_WITH_UDP_HEADER_LEN 28

FrameUioUserData *FRAME_IO_CreateUserData(void)
{
    FrameUioUserData *userData = BSL_SAL_Calloc(1u, sizeof(FrameUioUserData));
    if (userData == NULL) {
        return NULL;
    }
    return userData;
}

void FRAME_IO_FreeUserData(FrameUioUserData *userData)
{
    if (userData == NULL) {
        return;
    }

    BSL_SAL_FREE(userData);
    return;
}

int32_t FRAME_Write(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    *writeLen = 0;
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(uio);
    if (ioUserData == NULL) {
        return BSL_NULL_INPUT;
    }

    // This indicates that there is still a message in the buffer. The second message can be sent only after the peer
    // end receives the message.
    if (ioUserData->sndMsg.len != 0) {
        return BSL_SUCCESS;
    }

    memcpy_s(ioUserData->sndMsg.msg, MAX_RECORD_LENTH, buf, len);
    ioUserData->sndMsg.len = len;
    *writeLen = len;

    return BSL_SUCCESS;
}

int32_t FRAME_Read(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    *readLen = 0;
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(uio);
    if (ioUserData == NULL) {
        return BSL_NULL_INPUT;
    }
    // This indicates that the user inserts data. Therefore, the simulated data inserted by the user is received first.
    if (ioUserData->userInsertMsg.len != 0) {
        if (len < ioUserData->userInsertMsg.len) {
            return BSL_UIO_FAIL;
        }

        memcpy_s(buf, len, ioUserData->userInsertMsg.msg, ioUserData->userInsertMsg.len);
        *readLen = ioUserData->userInsertMsg.len;
        ioUserData->userInsertMsg.len = 0;
        return BSL_SUCCESS;
    } else if (ioUserData->recMsg.len != 0) {
        uint32_t copyLen = len < ioUserData->recMsg.len ? len : ioUserData->recMsg.len;
        memcpy_s(buf, len, ioUserData->recMsg.msg, copyLen);
        *readLen = copyLen;
        if (copyLen < ioUserData->recMsg.len) {
            memmove_s(ioUserData->recMsg.msg, ioUserData->recMsg.len,
                &ioUserData->recMsg.msg[copyLen], ioUserData->recMsg.len - copyLen);
        }
        ioUserData->recMsg.len -= copyLen;
        return BSL_SUCCESS;
    }  // If there is no data in the receive buffer, a success message is returned and *readLen is set to 0.

    return BSL_SUCCESS;
}

int32_t FRAME_Ctrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *param)
{
    (void)uio;
    (void)larg;
    if (cmd == BSL_UIO_SCTP_SND_BUFF_IS_EMPTY) {
        *(uint8_t *)param = true;
    }

    if (cmd == BSL_UIO_GET_FD) {
        *(int32_t *)param = FAKE_BSL_UIO_FD;
    }

    if (cmd == BSL_UIO_UDP_GET_MTU_OVERHEAD) {
        *(uint8_t *)param = IPV4_WITH_UDP_HEADER_LEN;
    }

    return BSL_SUCCESS;
}

/*
    Frame_TransportSendMsg: Sends messages in the send buffer in the I/O.
    Copy uio->userData to the buffer.
*/
int32_t FRAME_TransportSendMsg(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    *readLen = 0;
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(uio);
    if (ioUserData == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (ioUserData->sndMsg.len != 0) {
        // The length of the data in the buffer exceeds len.
        if (len < ioUserData->sndMsg.len) {
            return HITLS_UIO_FAIL;
        }

        memcpy_s(buf, len, ioUserData->sndMsg.msg, ioUserData->sndMsg.len);
        *readLen = ioUserData->sndMsg.len;
        ioUserData->sndMsg.len = 0;
    }  // If there is no data in the receive buffer, a success message is returned and *readLen is set to 0.

    return HITLS_SUCCESS;
}

/*
    Frame_TransportRecMsg simulates receiving messages from the I/O.
    Copy the data in the buffer to uio->userData.
*/
int32_t FRAME_TransportRecMsg(BSL_UIO *uio, void *buf, uint32_t len)
{
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(uio);
    if (ioUserData == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (ioUserData->recMsg.len != 0 || len > MAX_RECORD_LENTH) {
        return HITLS_UIO_FAIL;
    }

    memcpy_s(ioUserData->recMsg.msg, MAX_RECORD_LENTH, buf, len);
    ioUserData->recMsg.len = len;

    return HITLS_SUCCESS;
}

#ifdef __cplusplus
}
#endif

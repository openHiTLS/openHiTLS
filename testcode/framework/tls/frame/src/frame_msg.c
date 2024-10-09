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

#include "frame_msg.h"
#include "hitls_error.h"
#include "frame_tls.h"

FRAME_Msg *FRAME_GenerateMsgFromBuffer(const FRAME_LinkObj *linkObj, const uint8_t *buffer, uint32_t len)
{
    // Check whether the const Frame_LinkObj *linkObj parameter is required. If the parameter is not required, delete it
    (void)linkObj;
    (void)buffer;
    (void)len;
    return NULL;
}

/**
* @ingroup Obtain a message from the I/O receiving buffer of the connection
*
* @return Return the CTX object of the TLS
*/
int32_t FRAME_GetLinkRecMsg(FRAME_LinkObj *link, uint8_t *buffer, uint32_t len, uint32_t *msgLen)
{
    (void)link;
    (void)buffer;
    (void)len;
    (void)msgLen;
    return HITLS_SUCCESS;
}

/**
* @ingroup Obtain a message from the I/O sending buffer of the connection
*
* @return Return the CTX object of the TLS
*/
int32_t FRAME_GetLinkSndMsg(FRAME_LinkObj *link, uint8_t *buffer, uint32_t len, uint32_t *msgLen)
{
    (void)link;
    (void)buffer;
    (void)len;
    (void)msgLen;
    return HITLS_SUCCESS;
}
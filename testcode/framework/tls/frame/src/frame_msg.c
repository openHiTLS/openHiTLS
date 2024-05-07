/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "frame_msg.h"
#include "hitls_error.h"
#include "frame_tls.h"

FRAME_Msg *FRAME_GenerateMsgFromBuffer(const FRAME_LinkObj *linkObj, const uint8_t *buffer, uint32_t len)
{
    // Check whether the const Frame_LinkObj *linkObj parameter is required. If the parameter is not required, delete it
    return NULL;
}

/**
* @ingroup Obtain a message from the I/O receiving buffer of the connection
*
* @return Return the CTX object of the TLS
*/
int32_t FRAME_GetLinkRecMsg(FRAME_LinkObj *link, uint8_t *buffer, uint32_t len, uint32_t *msgLen)
{
    return HITLS_SUCCESS;
}

/**
* @ingroup Obtain a message from the I/O sending buffer of the connection
*
* @return Return the CTX object of the TLS
*/
int32_t FRAME_GetLinkSndMsg(FRAME_LinkObj *link, uint8_t *buffer, uint32_t len, uint32_t *msgLen)
{
    return HITLS_SUCCESS;
}
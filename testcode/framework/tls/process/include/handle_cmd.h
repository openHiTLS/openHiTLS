/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HANDLE_CMD_H
#define HANDLE_CMD_H

#include <stdint.h>
#include "hlt_type.h"
#include "channel_res.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_CMD_ID_LEN (15)
#define MAX_CMD_FUNCID_LEN (64)
#define MAX_CMD_PARAS_NUM (100)

typedef struct {
    uint8_t parasNum;
    uint8_t id[MAX_CMD_ID_LEN];
    uint8_t funcId[MAX_CMD_FUNCID_LEN];
    uint8_t paras[MAX_CMD_PARAS_NUM][CONTROL_CHANNEL_MAX_MSG_LEN];
    uint8_t result[CONTROL_CHANNEL_MAX_MSG_LEN];
} CmdData;

/**
* @brief  Expected result value
*/
int ExpectResult(CmdData *expectCmdData);

/**
* @brief  Waiting for the result of the peer end
*/
int WaitResultFromPeer(CmdData *expectCmdData);

/**
* @brief  Resolve instructions from a string
*/
int ParseCmdFromStr(uint8_t *str, CmdData *cmdData);

/**
* @brief  Parse the instruction from the buffer.
*/
int ParseCmdFromBuf(ControlChannelBuf *dataBuf, CmdData *cmdData);

/**
* @brief  Execute the corresponding command.
*/
int ExecuteCmd(CmdData *cmdData);

/**
* @brief  Obtain the CTX configuration content from the character string parsing.
*/
int ParseCtxConfigFromString(uint8_t (*string)[CONTROL_CHANNEL_MAX_MSG_LEN], HLT_Ctx_Config *ctxConfig);

#ifdef __cplusplus
}
#endif

#endif // HANDLE_CMD_H
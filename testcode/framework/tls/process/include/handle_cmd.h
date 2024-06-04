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
    char id[MAX_CMD_ID_LEN];
    char funcId[MAX_CMD_FUNCID_LEN];
    char paras[MAX_CMD_PARAS_NUM][CONTROL_CHANNEL_MAX_MSG_LEN];
    char result[CONTROL_CHANNEL_MAX_MSG_LEN];
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
int ParseCmdFromStr(char *str, CmdData *cmdData);

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
int ParseCtxConfigFromString(char (*string)[CONTROL_CHANNEL_MAX_MSG_LEN], HLT_Ctx_Config *ctxConfig);

#ifdef __cplusplus
}
#endif

#endif // HANDLE_CMD_H
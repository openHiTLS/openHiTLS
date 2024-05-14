/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef PARSER_FRAME_MSG_H
#define PARSER_FRAME_MSG_H

#include "frame_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ParserRecordHeader(FRAME_Msg *frameMsg, const uint8_t *buffer, uint32_t len, uint32_t *parserLen);
int32_t ParserRecordBody(const FRAME_LinkObj *linkObj, FRAME_Msg *frameMsg,
    const uint8_t *buffer, uint32_t len, uint32_t *parserLen);
int32_t ParserTotalRecord(const FRAME_LinkObj *linkObj, FRAME_Msg *frameMsg,
    const uint8_t *buffer, uint32_t len, uint32_t *parserLen);
void CleanRecordBody(FRAME_Msg *frameMsg);

#ifdef __cplusplus
}
#endif

#endif // PARSER_FRAME_MSG_H

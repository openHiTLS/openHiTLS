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

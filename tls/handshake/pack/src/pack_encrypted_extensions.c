/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdint.h>
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_extensions.h"
#include "pack_extensions.h"


static int32_t PackEncryptedSupportedGroups(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint16_t exMsgHeaderLen;
    uint16_t exMsgDataLen;
    uint32_t offset = 0u;
    const TLS_Config *config = &(ctx->config.tlsConfig);

    if (config->groupsSize == 0) {
        *usedLen = 0;
        return HITLS_SUCCESS;
    }

    if (config->groups == NULL) {
        return HITLS_SUCCESS;
    }

    /* Calculate the extension length */
    exMsgHeaderLen = sizeof(uint16_t);
    exMsgDataLen = sizeof(uint16_t) * (uint16_t)config->groupsSize;

    /* Pack the extension header */
    ret = PackExtensionHeader(HS_EX_TYPE_SUPPORTED_GROUPS, exMsgHeaderLen + exMsgDataLen, buf, bufLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    offset += HS_EX_HEADER_LEN;

    /* Pack the extended support group */
    BSL_Uint16ToByte(exMsgDataLen, &buf[offset]);
    offset += sizeof(uint16_t);
    for (uint32_t index = 0; index < config->groupsSize; index++) {
        BSL_Uint16ToByte(config->groups[index], &buf[offset]);
        offset += sizeof(uint16_t);
    }

    *usedLen = offset;
    return HITLS_SUCCESS;
}

/**
 * @brief Pack the Encrypted_extensions extension.
 *
 * @param ctx [IN] TLS context
 * @param buf [OUT] Return the handshake message buffer.
 * @param bufLen [IN] Maximum buffer size of the handshake message.
 * @param usedLen [OUT] Returned message length
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval For other error codes, see hitls_error.h.
 */
static int32_t PackEncryptedExs(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t listSize;
    uint32_t exLen = 0u;
    uint32_t offset = 0u;

    const PackExtInfo extMsgList[] = {
        {.exMsgType = HS_EX_TYPE_SUPPORTED_GROUPS,
         .needPack = true,
         .packFunc = PackEncryptedSupportedGroups},
        {.exMsgType = HS_EX_TYPE_EARLY_DATA,    /* This field is available only in 0-rrt mode */
         .needPack = false,
         .packFunc = NULL},
        {.exMsgType = HS_EX_TYPE_SERVER_NAME,    /* During extension, only empty SNI extensions are encapsulated. */
         .needPack = ctx->negotiatedInfo.isSniStateOK,
         .packFunc = NULL},
    };

    /* Calculate the number of extended types */
    listSize = sizeof(extMsgList) / sizeof(extMsgList[0]);

    /* Pack the Server Hello extension */
    for (uint32_t index = 0; index < listSize; index++) {
        if (extMsgList[index].needPack == false) {
            continue;
        }
        /* Empty extension */
        if (extMsgList[index].packFunc == NULL) {
            exLen = 0u;
            ret = PackEmptyExtension(extMsgList[index].exMsgType, extMsgList[index].needPack,
                &buf[offset], bufLen - offset, &exLen);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
            offset += exLen;
        }
        /* Non-empty extension */
        if (extMsgList[index].packFunc != NULL) {
            exLen = 0u;
            ret = extMsgList[index].packFunc(ctx, &buf[offset], bufLen - offset, &exLen);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
            offset += exLen;
        }
    }

    *usedLen = offset;
    return HITLS_SUCCESS;
}

/**
* @brief Pack the Encrypted_extensions message.
*
* @param ctx [IN] TLS context
* @param buf [OUT] Return the handshake message buffer.
* @param bufLen [IN] Maximum buffer size of the handshake message.
* @param len [OUT] Returned message length
*
* @retval HITLS_SUCCESS succeeded.
* @retval HITLS_PACK_NOT_ENOUGH_BUF_LENGTH The message buffer length is insufficient.
 */
int32_t PackEncryptedExtensions(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t headerLen = 0u;
    uint32_t exLen = 0u;

    /* Obtain the message header length */
    headerLen = sizeof(uint16_t);
    /* If the length of the message structure is smaller than the length of the message header,
     * return an error code */
    if (bufLen < headerLen) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15851, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the buffer length of Encrypted_extensions extension message is not enough.", 0, 0, 0, 0);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }

    /* Pack the encrypted_extensions extension */
    ret = PackEncryptedExs(ctx, &buf[headerLen], bufLen - headerLen, &exLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Update the message length */
    if (exLen > 0u) {
        BSL_Uint16ToByte((uint16_t)exLen, buf);
        *usedLen = exLen + headerLen;
    } else {
        BSL_Uint16ToByte((uint16_t) 0, buf);
        *usedLen = 0 + headerLen;
    }

    return HITLS_SUCCESS;
}

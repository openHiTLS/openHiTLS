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
#include "hitls_build.h"
#if defined(HITLS_TLS_PROTO_TLS13) && defined(HITLS_TLS_HOST_SERVER)
#include <stdint.h>
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_extensions.h"
#include "pack_common.h"
#include "pack_extensions.h"
#include "custom_extensions.h"

static int32_t PackEncryptedSupportedGroups(const TLS_Ctx *ctx, PackPacket *pkt)
{
    const TLS_Config *config = &(ctx->config.tlsConfig);

    if (config->groupsSize == 0 || config->groups == NULL) {
        return HITLS_SUCCESS;
    }

    /* Calculate the extension length */
    uint16_t exMsgHeaderLen = sizeof(uint16_t);
    uint16_t exMsgDataLen = sizeof(uint16_t) * (uint16_t)config->groupsSize;

    /* Pack the extension header */
    int32_t ret = PackExtensionHeader(HS_EX_TYPE_SUPPORTED_GROUPS, exMsgHeaderLen + exMsgDataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack the extended support group */
    (void)PackAppendUint16ToBuf(pkt, exMsgDataLen);

    for (uint32_t index = 0; index < config->groupsSize; index++) {
        (void)PackAppendUint16ToBuf(pkt, config->groups[index]);
    }

    return HITLS_SUCCESS;
}

/**
 * @brief Pack the Encrypted_extensions extension.
 *
 * @param ctx [IN] TLS context
 * @param pkt [IN/OUT] Context for packing
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval For other error codes, see hitls_error.h.
 */
static int32_t PackEncryptedExs(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t listSize;

    const PackExtInfo extMsgList[] = {
        {.exMsgType = HS_EX_TYPE_SUPPORTED_GROUPS,
         .needPack = true,
         .packFunc = PackEncryptedSupportedGroups},
        {.exMsgType = HS_EX_TYPE_EARLY_DATA,    /* This field is available only in 0-rrt mode */
         .needPack = false,
         .packFunc = NULL},
#ifdef HITLS_TLS_FEATURE_SNI
        {.exMsgType = HS_EX_TYPE_SERVER_NAME,    /* During extension, only empty SNI extensions are encapsulated. */
         .needPack = ctx->negotiatedInfo.isSniStateOK,
         .packFunc = NULL},
#endif /* HITLS_TLS_FEATURE_SNI */
#ifdef HITLS_TLS_FEATURE_RECORD_SIZE_LIMIT
        {.exMsgType = HS_EX_TYPE_RECORD_SIZE_LIMIT,
         .needPack = (ctx->negotiatedInfo.recordSizeLimit != 0),
         .packFunc = PackRecordSizeLimit},
#endif /* HITLS_TLS_FEATURE_RECORD_SIZE_LIMIT */
#ifdef HITLS_TLS_FEATURE_ALPN
        {.exMsgType = HS_EX_TYPE_APP_LAYER_PROTOCOLS,
         .needPack = (ctx->negotiatedInfo.alpnSelected != NULL),
         .packFunc = PackServerSelectAlpnProto},
#endif /* HITLS_TLS_FEATURE_ALPN */
    };
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
    if (IsPackNeedCustomExtensions(CUSTOM_EXT_FROM_CTX(ctx), HITLS_EX_TYPE_ENCRYPTED_EXTENSIONS)) {
        ret = PackCustomExtensions(ctx, pkt, HITLS_EX_TYPE_ENCRYPTED_EXTENSIONS, NULL, 0);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */

    /* Calculate the number of extended types */
    listSize = sizeof(extMsgList) / sizeof(extMsgList[0]);

    /* Pack the Server Hello extension */
    for (uint32_t index = 0; index < listSize; index++) {
        if (extMsgList[index].needPack == false) {
            continue;
        }
        /* Empty extension */
        if (extMsgList[index].packFunc == NULL) {
            ret = PackEmptyExtension(extMsgList[index].exMsgType, extMsgList[index].needPack, pkt);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }
        /* Non-empty extension */
        if (extMsgList[index].packFunc != NULL) {
            ret = extMsgList[index].packFunc(ctx, pkt);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }
    }

    return HITLS_SUCCESS;
}

/**
* @brief Pack the Encrypted_extensions message.
*
* @param ctx [IN] TLS context
* @param pkt [IN/OUT] Context for packing
*
* @retval HITLS_SUCCESS succeeded.
* @retval HITLS_PACK_NOT_ENOUGH_BUF_LENGTH The message buffer length is insufficient.
 */
int32_t PackEncryptedExtensions(const TLS_Ctx *ctx, PackPacket *pkt)
{
    uint32_t extensionsLenPosition = 0u;
    
    /* Start packing extensions length field */
    int32_t ret = PackStartLengthField(pkt, sizeof(uint16_t), &extensionsLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack the encrypted_extensions extension */
    ret = PackEncryptedExs(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Close extensions length field */
    PackCloseUint16Field(pkt, extensionsLenPosition);

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 && HITLS_TLS_HOST_SERVER */

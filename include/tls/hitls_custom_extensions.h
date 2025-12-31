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

/**
 * @defgroup hitls_custom_extensions
 * @ingroup  hitls
 * @brief    TLS Custom Extensions
 */

#ifndef HITLS_CUSTOM_EXTENSIONS_H
#define HITLS_CUSTOM_EXTENSIONS_H

#include <stdint.h>
#include "hitls_type.h"
#include "hitls_cert_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Extension context */

/**
 * @ingroup hitls_custom_extensions
 * @brief   Extension is used in ClientHello messages.
 */
#define HITLS_EX_TYPE_CLIENT_HELLO                    0x00001

/**
 * @ingroup hitls_custom_extensions
 * @brief   Extension is used in Tls1.2 ServerHello messages.
 */
#define HITLS_EX_TYPE_TLS1_2_SERVER_HELLO             0x00002

/**
 * @ingroup hitls_custom_extensions
 * @brief   Extension is used in Tls1.3 ServerHello messages.
 */
#define HITLS_EX_TYPE_TLS1_3_SERVER_HELLO             0x00004

/**
 * @ingroup hitls_custom_extensions
 * @brief   Extension is used in HelloRetryRequest messages (TLS 1.3).
 */
#define HITLS_EX_TYPE_HELLO_RETRY_REQUEST             0x00008

/**
 * @ingroup hitls_custom_extensions
 * @brief   Extension is used in EncryptedExtensions messages (TLS 1.3).
 */
#define HITLS_EX_TYPE_ENCRYPTED_EXTENSIONS            0x00010

/**
 * @ingroup hitls_custom_extensions
 * @brief   Extension is used in Certificate messages.
 */
#define HITLS_EX_TYPE_TLS1_3_CERTIFICATE                     0x00020

/**
 * @ingroup hitls_custom_extensions
 * @brief   Extension is used in CertificateRequest messages.
 */
#define HITLS_EX_TYPE_TLS1_3_CERTIFICATE_REQUEST         0x00040

/**
 * @ingroup hitls_custom_extensions
 * @brief   Extension is used in NewSessionTicket messages (TLS 1.3).
 */
#define HITLS_EX_TYPE_TLS1_3_NEW_SESSION_TICKET        0x00080


#define HITLS_ADD_CUSTOM_EXTENSION_RET_PACK            1
#define HITLS_ADD_CUSTOM_EXTENSION_RET_PASS            HITLS_SUCCESS

/**
 * @ingroup hitls_custom_extensions
 * @brief   Callback function to add a custom extension.
 *
 * This function is invoked when adding a custom extension to a TLS message.
 * It prepares the extension data to be sent, utilizing certificate information if necessary.
 *
 * @param   ctx     [IN]  TLS context
 * @param   extType [IN]  Extension type
 * @param   context [IN]  Context where the extension applies
 * @param   out     [OUT] Pointer to the extension data to be sent
 * @param   outLen  [OUT] Length of the extension data
 * @param   cert    [IN]  Pointer to the HITLS_CERT_X509 structure representing certificate information
 * @param   certIndex  [IN]  Certificate index indicating its position in the certificate chain
 * @param   alert   [OUT] Alert value provided by the user when requesting to add the custom extension
 * @param   addArg  [IN]  Additional argument provided when registering the callback
 * @retval  HITLS_ADD_CUSTOM_EXTENSION_RET_PACK if the extension needs to be packed,
 *          HITLS_ADD_CUSTOM_EXTENSION_RET_PASS if it does not need to be packed,
 *          otherwise, any other return value is considered a failure and will trigger a fatal alert based on the alert
 * value.
 */
typedef int (*HITLS_AddCustomExtCallback) (const HITLS_Ctx *ctx, uint16_t extType, uint32_t context, uint8_t **out,
    uint32_t *outLen, HITLS_CERT_X509 *cert, uint32_t certIndex, uint32_t *alert, void *addArg);

/**
 * @ingroup hitls_custom_extensions
 * @brief   Callback function to free a custom extension.
 *
 * This function is invoked to release resources allocated for a custom extension.
 *
 * @param   ctx      [IN] TLS context
 * @param   ext_type [IN] Extension type
 * @param   context  [IN] Context where the extension applies
 * @param   out      [IN] Extension data to be freed
 * @param   add_arg  [IN] Additional argument provided when registering the callback
 */
typedef void (*HITLS_FreeCustomExtCallback) (const HITLS_Ctx *ctx, uint16_t extType, uint32_t context,
    uint8_t *out, void *addArg);

/**
 * @ingroup hitls_custom_extensions
 * @brief   Callback function to parse a custom extension.
 *
 * This function is invoked when parsing a received custom extension. It interprets the
 * extension data and updates the TLS context based on certificate information if necessary.
 *
 * @param   ctx      [IN]  TLS context
 * @param   extType  [IN]  Extension type
 * @param   context  [IN]  Context where the extension applies
 * @param   in       [IN]  Pointer to the received extension data
 * @param   inlen    [IN]  Length of the extension data
 * @param   cert     [IN]  Pointer to the HITLS_CERT_X509 structure representing certificate information
 * @param   certIndex   [IN]  Certificate index indicating its position in the certificate chain
 * @param   alert    [OUT] Alert value provided by the user when requesting to add the custom extension
 * @param   parseArg [IN]  Additional argument provided when registering the callback
 * @retval  HITLS_SUCCESS if successful, otherwise an error code
 */
typedef int (*HITLS_ParseCustomExtCallback) (const HITLS_Ctx *ctx, uint16_t extType, uint32_t context,
    const uint8_t **in, uint32_t *inLen, HITLS_CERT_X509 *cert, uint32_t certIndex, uint32_t *alert, void *parseArg);


/**
 * @ingroup hitls_custom_extensions
 * @brief   Structure to hold parameters for adding a custom extension.
 */
typedef struct {
    uint16_t extType;                           /**< Extension type */
    uint32_t context;                           /**< Context where the extension applies */
    HITLS_AddCustomExtCallback addCb;           /**< Callback function to add the extension */
    HITLS_FreeCustomExtCallback freeCb;         /**< Callback function to free the extension */
    void *addArg;                            /**< Additional argument for add and free callbacks */
    HITLS_ParseCustomExtCallback parseCb;       /**< Callback function to parse the extension */
    void *parseArg;                          /**< Additional argument for parse callback */
} HITLS_CustomExtParams;

/**
 * @ingroup hitls_custom_extensions
 * @brief   Add a custom extension to the TLS context using a parameter structure.
 *
 * This function adds a custom extension to the specified TLS context using the provided
 * parameters encapsulated in the HITLS_CustomExtParams structure.
 *
 * @param   ctx     [IN] TLS context
 * @param   params  [IN] Pointer to the structure containing custom extension parameters
 * @retval  HITLS_SUCCESS if successful
 *          For other error codes, see hitls_error.h
 */
uint32_t HITLS_AddCustomExtension(HITLS_Ctx *ctx, const HITLS_CustomExtParams *params);

/**
 * @ingroup hitls_custom_extensions
 * @brief   Add a custom extension to the HITLS configuration using a parameter structure.
 *
 * This function adds a custom extension to the specified HITLS configuration using the provided
 * parameters encapsulated in the HITLS_CustomExtParams structure.
 *
 * @param   config  [IN] Pointer to the HITLS configuration
 * @param   params  [IN] Pointer to the structure containing custom extension parameters
 * @retval  HITLS_SUCCESS if successful
 *          For other error codes, see hitls_error.h
 */
uint32_t HITLS_CFG_AddCustomExtension(HITLS_Config *config, const HITLS_CustomExtParams *params);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CUSTOM_EXTENSIONS_H */

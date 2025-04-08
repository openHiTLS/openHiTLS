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

#ifdef __cplusplus
extern "C" {
#endif

    /* Extension context */
    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is only allowed in TLS (not DTLS).
     */
    #define HITLS_TLS_ONLY                        0x00001

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is only allowed in DTLS (not TLS).
     */
    #define HITLS_DTLS_ONLY                       0x00002

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is allowed in DTLS but not implemented for it.
     */
    #define HITLS_TLS_IMPLEMENTATION_ONLY         0x00004

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is allowed in SSLv3 (e.g., EXT_TYPE_renegotiate).
     */
    #define HITLS_SSL3_ALLOWED                    0x00008

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is only defined for TLS1.2 and below.
     */
    #define HITLS_TLS1_2_AND_BELOW_ONLY           0x00010

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is only defined for TLS1.3 and above.
     */
    #define HITLS_TLS1_3_ONLY                     0x00020

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Ignore this extension during parsing if resuming a session.
     */
    #define HITLS_IGNORE_ON_RESUMPTION            0x00040

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is used in ClientHello messages.
     */
    #define HITLS_CLIENT_HELLO                    0x00080

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is used in ServerHello messages for TLS1.2 and below.
     */
    #define HITLS_TLS1_2_SERVER_HELLO             0x00100

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is used in ServerHello messages for TLS1.3.
     */
    #define HITLS_TLS1_3_SERVER_HELLO             0x00200

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is used in EncryptedExtensions messages for TLS1.3.
     */
    #define HITLS_TLS1_3_ENCRYPTED_EXTENSIONS     0x00400

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is used in HelloRetryRequest messages for TLS1.3.
     */
    #define HITLS_TLS1_3_HELLO_RETRY_REQUEST      0x00800

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is used in Certificate messages for TLS1.3.
     */
    #define HITLS_TLS1_3_CERTIFICATE              0x01000

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is used in NewSessionTicket messages for TLS1.3.
     */
    #define HITLS_TLS1_3_NEW_SESSION_TICKET       0x02000

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is used in CertificateRequest messages for TLS1.3.
     */
    #define HITLS_TLS1_3_CERTIFICATE_REQUEST      0x04000

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is used for certificate compression in TLS1.3.
     */
    #define HITLS_TLS1_3_CERTIFICATE_COMPRESSION  0x08000

    /**
     * @ingroup hitls_custom_extensions
     * @brief   Extension is used when sending a raw public key in a certificate message.
     */
    #define HITLS_TLS1_3_RAW_PUBLIC_KEY           0x10000

// Callback function types for custom extensions
typedef int (*HITLS_CustomExt_Add_Callback)(const HITLS_Ctx *ctx, uint8_t ext_type,
                                         uint8_t context,
                                         uint8_t **out,
                                         uint32_t *outlen, void *msg,
                                         uint32_t *al, void *add_arg);

typedef void (*HITLS_CustomExt_Free_Callback)(const HITLS_Ctx *ctx, uint8_t ext_type,
                                           uint8_t context,
                                           uint8_t *out,
                                           void *add_arg);

typedef int (*HITLS_CustomExt_Parse_Callback)(const HITLS_Ctx *ctx, uint8_t ext_type,
                                           uint8_t context,
                                           const uint8_t **in,
                                           uint32_t *inlen, void *msg,
                                           uint32_t *al, void *parse_arg);

/**
 * @ingroup hitls_custom_extensions
 * @brief   Add a custom extension to the TLS context.
 *
 * @param   ctx [OUT] TLS context
 * @param   ext_type [IN] Extension type
 * @param   context [IN] Context where the extension applies
 * @param   add_cb [IN] Callback to add the extension
 * @param   free_cb [IN] Callback to free the extension
 * @param   add_arg [IN] Argument for add/free Callbacks
 * @param   parse_cb [IN] Callback to parse the extension
 * @param   parse_arg [IN] Argument for parse Callback
 * @retval  HITLS_SUCCESS if successful
 *          For other error codes, see hitls_error.h
 */
uint32_t HITLS_AddCustomExtension(HITLS_Ctx *ctx, uint8_t ext_type,
                                 uint8_t context,
                                 HITLS_CustomExt_Add_Callback add_cb,
                                 HITLS_CustomExt_Free_Callback free_cb,
                                 void *add_arg,
                                 HITLS_CustomExt_Parse_Callback parse_cb,
                                 void *parse_arg);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CUSTOM_EXTENSIONS_H */


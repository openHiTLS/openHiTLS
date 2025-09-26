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

#ifndef FRAME_TLS_H
#define FRAME_TLS_H

#include "bsl_uio.h"
#include "hs_ctx.h"
#include "frame_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FRAME_LinkObj_ FRAME_LinkObj;

typedef struct FRAME_CertInfo_ FRAME_CertInfo;

typedef struct SSL_LINK_OBJ_ SSL_LINK_OBJ;

HITLS_Ctx *FRAME_CreateDefaultDtlsObj(void);

/**
* @brief  Load the certificate to the connection configuration context resource.
*
* @return If the value 0 is returned, the certificate is loaded successfully.
*         Otherwise, the certificate fails to be loaded
*/
int32_t FRAME_LoadCertToConfig(HITLS_Config *config, const char *verifyCert, const char *chainCert, const char *eeCert,
    const char *prvKey);

/**
* @brief  Create a TLCP connection.
          This interface loads the certificate, applies for SSL CTX, and creates the underlying UIO
*
* @return Return the connection object, which can be used by the test framework to perform operations
*/
FRAME_LinkObj *FRAME_CreateTLCPLink(HITLS_Config *config, BSL_UIO_TransportType type, bool isClient);

/**
* @brief  Create an SSL connection. This interface will complete the SSL CTX application,
          bottom-layer UIO creation, and load the default certificate
*
* @return Return the connection object, which can be used by the test framework to perform operations
*/
FRAME_LinkObj *FRAME_CreateLink(HITLS_Config *config, BSL_UIO_TransportType type);

// This interface is used to create an SSL connection.
// The SSL CTX application and bottom-layer UIO creation are completed. The default certificate is not loaded.
FRAME_LinkObj *FRAME_CreateLinkEx(HITLS_Config *config, BSL_UIO_TransportType type);

FRAME_LinkObj *FRAME_CreateLinkWithCert(
    HITLS_Config *config, BSL_UIO_TransportType type, const FRAME_CertInfo *certInfo);

FRAME_LinkObj *FRAME_CreateLinkWithCerts(HITLS_Config *config, BSL_UIO_TransportType type,
    const FRAME_CertInfo* certInfo, size_t certInfoLen);
/**
 * @brief Create an SSL connection with configurable certificate loading.
 *        This interface will complete the SSL CTX application and bottom-layer UIO creation.
 *        The setCertFlag parameter controls whether to load the default certificate.
 *
 * @param config [IN] TLS configuration
 * @param type [IN] Transport type
 * @param setCertFlag [IN] Whether to load default certificate
 *
 * @return Return the connection object, which can be used by the test framework to perform operations
 */
FRAME_LinkObj *FRAME_CreateLinkBase(HITLS_Config *config, BSL_UIO_TransportType type, bool setCertFlag);

/**
* @brief  Releases an SSL connection, which corresponds to Frame_CreateLink
*
* @return
*/
void FRAME_FreeLink(FRAME_LinkObj *linkObj);

/**
* @brief Obtain the TLS ctx from the Frame_LinkObj to facilitate the test of HiTLS APIs because HiTLS APIs use
*          HITLS_Ctx as the input parameter.
*          Do not call HiTLS_Free to release the return values of this API.
*          The values will be released in the Frame_FreeLink.
*
* @return Return the CTX object of the TLS
*/
HITLS_Ctx *FRAME_GetTlsCtx(const FRAME_LinkObj *linkObj);

/*
* @brief Simulate link establishment or simulate an SSL link in a certain state.
*          For example, if state is TRY_RECV_SERVER_HELLO, the client is ready to receive the SERVER Hello message,
*          and The server link is just sent SERVER_HELLO.
*
* @return If the operation is successful, HITLS_SUCCESS is returned.
*/
int32_t FRAME_CreateConnection(FRAME_LinkObj *client, FRAME_LinkObj *server, bool isClient, HITLS_HandshakeState state);

/**
 * @brief   Simulate renegotiation
 * @attention Internally invokes HITLS_Write and HITLS_Read to perform renegotiation.
 *            Ensure that linkA is the initiator of the renegotiation request and
 *            linkB is the receiver of the renegotiation request
 *
 * @param   server [IN] Initiator of the renegotiation request
 * @param   client [IN] Recipient of the renegotiation request
 *
 * @return  If the operation is successful, HITLS_SUCCESS is returned
 */
int32_t FRAME_CreateRenegotiationServer(FRAME_LinkObj *server, FRAME_LinkObj *client);

/*
* @ingroup Simulate connection establishment or an SSL connection in a certain state.
*          For example, if the value of state is TRY_RECV_SERVER_HELLO,
*          the client is ready to receive the SERVER Hello message,
*          and the server connection is SERVER_HELLO has just been sent.
*
*
* @return If the operation is successful, HITLS_SUCCESS is returned
*/
int32_t FRAME_CreateRenegotiationState(FRAME_LinkObj *client, FRAME_LinkObj *server, bool isClient, HITLS_HandshakeState state);

/**
 * @brief   Simulate renegotiation

 * @attention Internally invokes HITLS_Write and HITLS_Read to perform renegotiation.
 *            Ensure that linkA is the initiator of the renegotiation request and
 *            linkB is the receiver of the renegotiation request
 *
 * @param   linkA [IN] Initiator of the renegotiation request
 * @param   linkB [IN] Recipient of the renegotiation request
 *
 * @return  If the operation is successful, HITLS_SUCCESS is returned
 */
int32_t FRAME_CreateRenegotiation(FRAME_LinkObj *linkA, FRAME_LinkObj *linkB);

/**
* @brief Obtain a message from the I/O receiving buffer of the connection
*
* @return If the operation is successful, HITLS_SUCCESS is returned
*/
int32_t FRAME_GetLinkRecMsg(FRAME_LinkObj *link, uint8_t *buffer, uint32_t len, uint32_t *msgLen);

/**
* @brief Obtain a message from the I/O sending buffer of the connection.
*
* @return If the operation is successful, HITLS_SUCCESS is returned.
*/
int32_t FRAME_GetLinkSndMsg(FRAME_LinkObj *link, uint8_t *buffer, uint32_t len, uint32_t *msgLen);

/**
* @brief Generate a framework message based on the content in the message buffer
*
* @return Return the Constructed Frame_Msg object
*/
FRAME_Msg *FRAME_GenerateMsgFromBuffer(const FRAME_LinkObj *linkObj, const uint8_t *buffer, uint32_t len);

/**
* @brief Send data from connection A to connection B
*
* @return If the operation is successful, HITLS_SUCCESS is returned
*/
int32_t FRAME_TrasferMsgBetweenLink(FRAME_LinkObj *linkA, FRAME_LinkObj *linkB);

/**
* @brief Initialize the framework
*/

void FRAME_Init(void);

/**
* @brief Deinitialize the framework
*/
void FRAME_DeInit(void);

#ifdef __cplusplus
}
#endif

#endif // FRAME_TLS_H

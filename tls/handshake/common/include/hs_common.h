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

#ifndef HS_COMMON_H
#define HS_COMMON_H

#include <stdint.h>
#include "tls.h"
#include "hs_ctx.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_CERT_TYPE_LISTS_SIZE 256        /* Maximum length of the certificate type list */
#define HS_DOWNGRADE_RANDOM_SIZE 8u         /* downgrade protection random number field */

#define HITLS_CLIENT_HELLO_MAX_SIZE         131396
#define HITLS_SERVER_HELLO_MAX_SIZE         65607
#define HITLS_HELLO_VERIFY_REQUEST_MAX_SIZE 258
#define HITLS_END_OF_EARLY_DATA_MAX_SIZE    0
#define HITLS_HELLO_RETRY_REQUEST_MAX_SIZE  20000
#define HITLS_ENCRYPTED_EXTENSIONS_MAX_SIZE 20000
#define HITLS_SESSION_TICKET_MAX_SIZE_TLS13 131338
#define HITLS_SESSION_TICKET_MAX_SIZE_TLS12 65541
#define HITLS_SERVER_KEY_EXCH_MAX_SIZE      102400
#define HITLS_SERVER_HELLO_DONE_MAX_SIZE    0
#define HITLS_KEY_UPDATE_MAX_SIZE           1
#define HITLS_CLIENT_KEY_EXCH_MAX_SIZE      2048
#define HITLS_NEXT_PROTO_MAX_SIZE           514
#define HITLS_FINISHED_MAX_SIZE             64
#define HITLS_HELLO_REQUEST_MAX_SIZE        0

enum HITLS_CryptInfoCmd {
    HITLS_CRYPT_INFO_CMD_GET_PUBLIC_KEY_LEN = 0, /* Get the length of the public key, param is HITLS_NamedGroup */
    HITLS_CRYPT_INFO_CMD_GET_SHARED_KEY_LEN,     /* Get the length of the shared key, param is HITLS_NamedGroup */
    HITLS_CRYPT_INFO_CMD_GET_CIPHERTEXT_LEN,     /* Get the length of the ciphertext, param is HITLS_NamedGroup */
    HITLS_CRYPT_INFO_CMD_GET_HASH_LEN,           /* Get the length of the hash, param is HITLS_HashAlgo */
};

/**
* @brief Obtain the random number of the hello retry request.
*
* @param len [OUT] Length of the returned array
*
* @return Random number array
*/
const uint8_t *HS_GetHrrRandom(uint32_t *len);

const uint8_t *HS_GetTls12DowngradeRandom(uint32_t *len);

/**
 * @brief   Obtains the type string of the handshake message.
 *
 * @param   type [IN] Handshake Message Type
 *
 * @return  Character string corresponding to the handshake message type.
 */
const char *HS_GetMsgTypeStr(HS_MsgType type);

/**
* @brief Obtain the type character string of the handshake message.
*
* @param type [IN] Handshake message type.
*
* @return Character string corresponding to the handshake message type.
*/
int32_t HS_ChangeState(TLS_Ctx *ctx, uint32_t nextState);

/**
* @brief Combine two random numbers.
*
* @param random1 [IN] Random number 1
* @param random2 [IN] Random number 2
* @param randomSize [IN] Random number length
* @param dest [OUT] Destination memory address
* @param destSize [IN] Target memory length
*
* @retval HITLS_SUCCESS parsed successfully.
* @retval HITLS_MEMCPY_FAIL Memory Copy Failure
* @retval HITLS_MSG_HANDLE_RANDOM_SIZE_ERR The random number length is incorrect.
 */
int32_t HS_CombineRandom(const uint8_t *random1, const uint8_t *random2, uint32_t randomSize,
                         uint8_t *dest, uint32_t destSize);

/**
 * @brief Obtain all signature data.
 *
 * @param ctx [IN] TLS context
 * @param partSignData [IN] key exchange message data
 * @param partSignDataLen [IN] key exchange message data length
 * @param signDataLen [OUT] Length of the signature data
 *
 * @retval Data to be signed
 */
uint8_t *HS_PrepareSignData(const TLS_Ctx *ctx, const uint8_t *partSignData,
    uint32_t partSignDataLen, uint32_t *signDataLen);

/**
 * @brief Obtain the signature data required by the TLCP.
 *
 * @param ctx [IN] TLS context
 * @param partSignData [IN] key exchange message data
 * @param partSignDataLen [IN] key exchange message data length
 * @param signDataLen [OUT] Length of the signature data
 * @retval Data to be signed
 */
uint8_t *HS_PrepareSignDataTlcp(
    const TLS_Ctx *ctx, const uint8_t *partSignData, uint32_t partSignDataLen, uint32_t *signDataLen);

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_SCTP)
/**
 * @brief Set the SCTP auth key to the SCTP.
 *
 * @attention If the UIO_SctpAddAuthKey is added but not activated, the UIO_SctpAddAuthKey returns a success message
 * when the interface is invoked again.
 * @param ctx [IN] TLS context
 *
 * @retval HITLS_SUCCESS Operation succeeded.
 * @retval HITLS_MSG_HANDLE_RANDOM_SIZE_ERR The random number length is incorrect.
 * @retval For details, see UIO_SctpAddAuthKey.
 */
int32_t HS_SetSctpAuthKey(TLS_Ctx *ctx);

/**
 * @brief Activate the sctp auth key.
 *
 * @param ctx [IN] TLS context
 *
 * @retval HITLS_SUCCESS operation succeeded.
 * @retval For details, see UIO_SctpIsSndBuffEmpty and UIO_SctpActiveAuthKey.
 */
int32_t HS_ActiveSctpAuthKey(TLS_Ctx *ctx);

/**
* @brief Delete the previous SCTP auth key.
*
* @param ctx [IN] TLS context
*
* @retval HITLS_SUCCESS Operation succeeded.
* @retval HITLS_REC_NORMAL_IO_BUSY The underlying I/O buffer is not empty.
* @retval For details, see UIO_SctpDelPreAuthKey.
*/
int32_t HS_DeletePreviousSctpAuthKey(TLS_Ctx *ctx);
#endif /* #if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_SCTP) */

bool IsNeedServerKeyExchange(const TLS_Ctx *ctx);

bool IsPskNegotiation(const TLS_Ctx *ctx);

bool IsNeedCertPrepare(const CipherSuiteInfo *cipherSuiteInfo);

bool IsTicketSupport(const TLS_Ctx *ctx);

int32_t CheckClientPsk(TLS_Ctx *ctx);

/**
 * @brief Expand the capacity of the msgBuf in the hsCtx based on the received message length.
 *
 * @param ctx [IN] TLS context
 * @param msgSize[IN] Expected length
 *
 * @retval HITLS_SUCCESS Operation succeeded.
 * @retval HITLS_MEMALLOC_FAIL failed to apply for memory.
 */
int32_t HS_ReSizeMsgBuf(TLS_Ctx *ctx, uint32_t msgSize);

/**
 * @brief Expand the capacity of the msgBuf in the hsCtx based on the length of the received message. The upper limit of
 * the capacity does not exceed upperBound bytes, And you can choose whether to retain the original data
 * @param ctx [IN] TLS context
 * @param msgSize[IN] Expected length
 * @param keepOldData[IN] Indicates whether to retain the old data.
 *
 * @retval HITLS_SUCCESS Operation succeeded.
 * @retval HITLS_MEMALLOC_FAIL failed to apply for memory.
 * @retval HITLS_MEMCPY_FAIL Data fails to be copied.
 */
int32_t HS_GrowMsgBuf(TLS_Ctx *ctx, uint32_t msgSize, bool keepOldData);

/**
 * @brief Return the maximum packet length allowed by the handshake status.
 *
 * @param ctx [IN] TLS context
 * @param type[IN] Handshake message type
 *
 * @retval Maximum message length allowed
 */
uint32_t HS_MaxMessageSize(TLS_Ctx *ctx, HS_MsgType type);

/**
 * @brief Obtain the Binder length.
 *
 * @param ctx [IN] TLS context
 * @param hashAlg [IN/OUT] Hash algorithm used in the process of calculating the binder
 *
 * @return Binder length
 */
uint32_t HS_GetBinderLen(HITLS_Session *session, HITLS_HashAlgo* hashAlg);

/**
 * @brief  Check whether the current version supports this group.
 *
 * @param   version [IN] current version
 * @param   group   [IN] group
 *
 * @return  true: valid; false: invalid
 */
bool GroupConformToVersion(const TLS_Ctx *ctx, uint16_t version, uint16_t group);

/**
 * @brief  Check whether the ciphersuite is valid
 *
 * @param   ctx [IN] TLS context
 * @param   cipherSuite  [IN] cipherSuite
 * @param   checkNegoVersion  [IN] whether need negotiated version check
 *
 * @return  true: valid; false: invalid
 */
bool IsCipherSuiteAllowed(const HITLS_Ctx *ctx, uint16_t cipherSuite, bool checkNegoVersion);

uint16_t *CheckSupportSignAlgorithms(const TLS_Ctx *ctx, const uint16_t *signAlgorithms,
    uint32_t signAlgorithmsSize, uint32_t *newSignAlgorithmsSize);

uint32_t HS_GetExtensionTypeId(uint32_t hsExtensionsType);

int32_t HS_CheckReceivedExtension(HITLS_Ctx *ctx, HS_MsgType hsType, uint64_t hsMsgExtensionsMask,
    uint64_t hsMsgAllowedExtensionsMask);


/**
 * @brief   Get cryptographic information about length
 *
 * @param ctx   [IN] TLS context
 * @param cmd   [IN] Command type, see enum HITLS_CryptInfoCmd
 * @param param [IN] Input parameter
 *
 * @return Returns key length and other info, returns 0 on failure
 */
uint32_t HS_GetCryptLength(const TLS_Ctx *ctx, int32_t cmd, int32_t param);

/**
 * @brief   get cert key type based on signScheme
 *
 * @param   signScheme [IN] signature algorithm
 *
 * @retval  cert key type
 */
HITLS_CERT_KeyType HS_SignScheme2CertKeyType(const HITLS_Ctx *ctx, HITLS_SignHashAlgo signScheme);

#ifdef __cplusplus
}
#endif

#endif
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
 * @file hitls_pki_cms.h
 * @brief CMS public APIs.
 */

/**
 * @defgroup cms
 * @ingroup pki
 * @brief CMS processing interfaces.
 */

#ifndef HITLS_PKI_CMS_H
#define HITLS_PKI_CMS_H

#include "hitls_pki_types.h"
#include "bsl_params.h"
#include "hitls_pki_cert.h"
#include "crypt_eal_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HITLS_CMS HITLS_CMS;

/* Recipient type used by EnvelopedData recipient parameters. */
typedef enum {
    HITLS_CMS_RECIPIENT_TYPE_KTRI = 1,
} HITLS_CMS_RecipientType;

/**
 * @ingroup cms
 * @brief Create a new CMS handle
 * @param libCtx library context
 * @param attrName Attribute/profile name
 * @param dataType CMS content/data type (e.g., SignedData, EnvelopedData)
 * @return Pointer to the newly created CMS handle on success, or NULL on failure
 */
HITLS_CMS *HITLS_CMS_ProviderNew(HITLS_PKI_LibCtx *libCtx, const char *attrName, int32_t dataType);

/**
 * @ingroup cms
 * @brief Free CMS structure
 * @param cms CMS structure to free
 */
void HITLS_CMS_Free(HITLS_CMS *cms);

/**
 * @ingroup cms
 * @brief cms parse
 * @par Description: parse cms buffer, and set the cms struct. Supports parsing SignedData and EnvelopedData.

 * @attention Supports parsing CMS buffers for SignedData and EnvelopedData.
 * @param libCtx         [IN] lib context
 * @param attrName       [IN] attribute name
 * @param param          [IN] parameter
 * @param encode         [IN] encode data
 * @param cms            [OUT] the cms struct.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_ProviderParseBuff(HITLS_PKI_LibCtx *libCtx, const char *attrName, const BSL_Param *param,
    const BSL_Buffer *encode, HITLS_CMS **cms);

/**
 * @ingroup cms
 * @brief cms parse file
 * @par Description: parse cms file, and set the cms struct. Supports parsing SignedData and EnvelopedData.

 * @attention Supports parsing CMS files for SignedData and EnvelopedData.
 * @param libCtx         [IN] lib context
 * @param attrName       [IN] attribute name
 * @param param          [IN] parameter
 * @param path           [IN] cms file path.
 * @param cms            [OUT] the cms struct.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_ProviderParseFile(HITLS_PKI_LibCtx *libCtx, const char *attrName, const BSL_Param *param,
    const char *path, HITLS_CMS **cms);

/**
 * @ingroup cms
 * @brief Create signer information and perform one-shot signing.
 * @par Description:
 *   - Always builds a CMS_SignerInfo from the supplied certificate using the requested version.
 *   - The function performs a complete one-shot signing flow and adds the generated SignerInfo
 *     into the CMS SignedData structure.
 *
 * @param cms             [IN] CMS SignedData handle that will own the signer (must be SignedData type)
 * @param prvKey          [IN] Private key used for signing
 * @param cert            [IN] Signer certificate used to derive identifier fields
 * @param msg             [IN] Message buffer to sign
 * @param optionalParam   [IN] Optional parameters (can be NULL). it may contains untrusted cert-list, ca-cert list,
 * @retval #HITLS_PKI_SUCCESS on success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_DataSign(HITLS_CMS *cms, CRYPT_EAL_PkeyCtx *prvKey, HITLS_X509_Cert *cert, BSL_Buffer *msg,
    const BSL_Param *optionalParam);

/**
 * @ingroup cms
 * @brief Verify CMS SignedData signatures
 * @par Description: Verify all signatures in the CMS SignedData structure.
 *
 * @attention The message data must be provided for detached SignedData; it is optional for non-detached.
 * @param cms             [IN] CMS structure containing signatures to verify
 * @param msg             [IN] Message data to verify (required for detached, optional for non-detached)
 * @param inputParam      [IN] Optional parameters (can be NULL). it may contains untrusted cert-list, ca-cert list,
 * @param output          [OUT] If not NULL, returns the actual message buffer used for verification
 *                             (points to msg for detached, or to embedded content for attached)
 * @retval #HITLS_PKI_SUCCESS on success (all signatures are valid).
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_DataVerify(HITLS_CMS *cms, BSL_Buffer *msg, const BSL_Param *inputParam, BSL_Buffer *output);

/**
 * @ingroup cms
 * @brief Encrypt data using EnvelopedData (one-shot operation).
 * @par Description:
 * Encrypts plaintext data using the CMS EnvelopedData structure. In one-shot mode,
 * this API completes one encryption operation with one set of recipient parameters:
 * it generates a random content encryption key (CEK), encrypts the plaintext, and
 * encrypts the CEK for the recipient.
 *
 *   - Recipient parameters are supplied through optionalParam using HITLS_CMS_PARAM_RECIPIENT_TYPE,
 *     HITLS_CMS_PARAM_RECIPIENT_CERT, HITLS_CMS_PARAM_RECIPIENT_KEY_ENC_ALG, etc.
 *   - After a successful one-shot encryption, the CEK remains in the CMS object so additional
 *     recipients can be added by subsequent calls with plaintext set to NULL.
 *     Free the CMS object promptly after all recipients are added and the encoded data is generated,
 *     so the retained CEK can be cleared with the EnvelopedData context.
 *   - In streaming encryption, call HITLS_CMS_DataInit first and then call this API one or more times
 *     to add recipients and wrap the stream CEK before HITLS_CMS_DataUpdateEx/HITLS_CMS_DataFinalEx.
 *
 * @param cms            [IN/OUT] CMS EnvelopedData handle (must be created with BSL_CID_PKCS7_ENVELOPEDDATA)
 * @param plaintext      [IN] Plaintext data to encrypt in the first one-shot call. Set to NULL when adding
 *                            another recipient after one-shot encryption, or in streaming encryption where this
 *                            API only adds a recipient and wraps the CEK.
 * @param optionalParam  [IN] Optional parameters. For encryption generation, it may include
 *                            recipient parameters, encryption algorithm and content type. RSA-OAEP recipients can
 *                            also pass CRYPT_PARAM_RSA_MD_ID, CRYPT_PARAM_RSA_MGF1_ID and
 *                            CRYPT_PARAM_RSA_OAEP_LABEL.
 * @retval #HITLS_PKI_SUCCESS on success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_DataEncrypt(HITLS_CMS *cms, const BSL_Buffer *plaintext, const BSL_Param *optionalParam);

/**
 * @ingroup cms
 * @brief Decrypt EnvelopedData (one-shot operation).
 * @par Description:
 * Decrypts a CMS EnvelopedData structure using recipient credentials provided through
 * recipient parameters. The function first decrypts the content encryption
 * key (CEK), and then uses the CEK to decrypt the encrypted content.
 * One-shot decryption accepts one set of recipient parameters and internally searches
 * the CMS RecipientInfos for a matching recipient.
 *
 * Streaming decryption obtains the recipient credentials from HITLS_CMS_DataInit; this
 * API is only used for one-shot decryption.
 *
 * @param cms         [IN] CMS EnvelopedData handle (must contain parsed EnvelopedData)
 * @param param       [IN] Optional parameters. EnvelopedData decryption uses
 *                         HITLS_CMS_PARAM_RECIPIENT_TYPE, HITLS_CMS_PARAM_RECIPIENT_CERT and
 *                         HITLS_CMS_PARAM_PRIVATE_KEY to provide recipient matching
 *                         information and private keys.
 * @param plaintext   [OUT] Decrypted plaintext buffer (caller must free plaintext->data).
 * @retval #HITLS_PKI_SUCCESS on success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_DataDecrypt(HITLS_CMS *cms, const BSL_Param *param, BSL_Buffer *plaintext);

/**
 * @ingroup cms
 * @brief Initialize streaming operation for CMS data processing (unified interface)
 * @par Description: Unified interface for initializing streaming operations.
 *
 * Useful to sign, verify, encrypt or decrypt large input data.
 *
 * @attention State must be HITLS_CMS_UNINIT.
 * @param cms             [IN/OUT] CMS structure to initialize
 * @param option           [IN] Operation option, ref hitls_pki_types.h
 * @param param            [IN] Parameters:
 *                            - For encryption: Optional parameters may include the content encryption algorithm
 *                              and content type. Recipients are added by subsequent HITLS_CMS_DataEncrypt calls.
 *                            - For decryption: Recipient credentials are provided here to unwrap the CEK and
 *                              initialize the decryption context.
 * @retval #HITLS_PKI_SUCCESS on success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_DataInit(int32_t option, HITLS_CMS *cms, const BSL_Param *param);

/**
 * @ingroup cms
 * @brief Update streaming SignedData operation with input data chunk.
 * @par Description: deal with a chunk of input data. This function can be
 * called multiple times to process the input data in chunks.
 *
 * This interface only supports SignedData sign and verify streaming operations.
 * EnvelopedData streaming encryption and decryption use HITLS_CMS_DataUpdateEx,
 * which returns the detached output chunk.
 *
 * @attention Call HITLS_CMS_DataInit before calling this function.
 * @param cms             [IN/OUT] CMS structure
 * @param input           [IN] Input data chunk to process
 * @retval #HITLS_PKI_SUCCESS on success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_DataUpdate(HITLS_CMS *cms, const BSL_Buffer *input);

/**
 * @ingroup cms
 * @brief Finalize streaming SignedData operation.
 * @par Description:
 * Finalize the streaming operation. For sign, this generates the signature and adds
 * the completed SignerInfo to the CMS structure. For verification, this finalizes the
 * digest computation, compares with message-digest attributes, and verifies all signatures.
 *
 * The function determines the operation type based on the option set in HITLS_CMS_DataInit.
 *
 * @attention Call HITLS_CMS_DataInit and at least one HITLS_CMS_DataUpdate before calling this function.
 * @param cms             [IN/OUT] CMS structure
 * @param param            [IN] Parameters:
 *                            - For signing: Optional parameters (can be NULL) for signature
 *                            - For verification: Optional parameters (can be NULL) containing untrusted cert-list,
 *                                              ca-cert list, etc.
 * @retval #HITLS_PKI_SUCCESS on success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_DataFinal(HITLS_CMS *cms, const BSL_Param *param);

/**
 * @ingroup cms
 * @brief Update streaming operation and return output data.
 * @par Description:
 * This interface supports SignedData and EnvelopedData streaming operations.
 * For SignedData, output is not used and may be NULL. For EnvelopedData, input
 * is a plaintext chunk during encryption or a detached ciphertext chunk during
 * decryption; output must provide a caller-owned buffer. Before the call,
 * output->dataLen is the output buffer capacity. After a successful call,
 * output->dataLen is the actual ciphertext or plaintext length.
 *
 * @attention Call HITLS_CMS_DataInit before calling this function. For streaming
 *            EnvelopedData encryption, add recipients with HITLS_CMS_DataEncrypt
 *            before the first update.
 * @param cms             [IN/OUT] CMS structure
 * @param input           [IN] Input data chunk to process
 * @param output          [IN/OUT] Output data chunk for EnvelopedData; unused for SignedData.
 * @retval #HITLS_PKI_SUCCESS on success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_DataUpdateEx(HITLS_CMS *cms, const BSL_Buffer *input, BSL_Buffer *output);

/**
 * @ingroup cms
 * @brief Finalize streaming operation and return final output data.
 * @par Description:
 * This interface supports SignedData and EnvelopedData streaming operations.
 * For SignedData, output is not used and may be NULL. For EnvelopedData, output
 * must provide a caller-owned buffer. Before the call, output->dataLen is the
 * output buffer capacity. After a successful call, output->dataLen is the actual
 * final detached ciphertext or plaintext length.
 *
 * @param cms             [IN/OUT] CMS structure
 * @param param           [IN] Optional parameters for SignedData; unused for EnvelopedData.
 * @param output          [IN/OUT] Final output data chunk for EnvelopedData; unused for SignedData.
 * @retval #HITLS_PKI_SUCCESS on success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_DataFinalEx(HITLS_CMS *cms, const BSL_Param *param, BSL_Buffer *output);

/**
 * @ingroup cms
 * @brief Control and modify CMS auxiliary data (certificates, CRLs, etc.)
 * @par Description:
 * Supported cmd values in hitls_pki_types.h: HITLS_CMS_Cmd.
 *
 * @param cms             [IN/OUT] CMS structure to modify
 * @param cmd             [IN] Control command (e.g., add cert, add crl)
 * @param val             [IN] Pointer to data or object for the command
 * @param valLen          [IN] Length of data pointed by val (if applicable)
 * @retval #HITLS_PKI_SUCCESS on success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_Ctrl(HITLS_CMS *cms, int32_t cmd, void *val, uint32_t valLen);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_CMS_H

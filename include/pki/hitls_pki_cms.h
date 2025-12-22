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

/**
 * @brief Create a new CMS handle
 * @param libCtx library context
 * @param attrName Attribute/profile name
 * @param dataType CMS content/data type (e.g., SignedData)
 * @return Pointer to the newly created CMS handle on success, or NULL on failure
 */
HITLS_CMS *HITLS_CMS_ProviderNew(HITLS_PKI_LibCtx *libCtx, const char *attrName, int32_t dataType);

/**
 * @brief Free CMS structure
 * @param cms CMS structure to free
 */
void HITLS_CMS_Free(HITLS_CMS *cms);

/**
 * @ingroup cms
 * @brief cms parse
 * @par Description: parse cms buffer, and set the cms struct. Now only support to parse signeddata.
 *
 * @attention Only support to parse cms buffer.
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
 * @par Description: parse cms file, and set the cms struct.
 *
 * @attention Only support to parse cms files.
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
 * @brief Create signer information and optionally perform one-shot signing.
 * @par Description:
 *   - Always builds a CMS_SignerInfo from the supplied certificate using the requested version.
 *   - When msg/prvKey are provided, the function performs a complete one-shot signing flow and adds the
 *     SignerInfo into the CMS SignedData structure.
 *   - When msg is NULL, only the SignerInfo is created. The caller can then use the streaming APIs
 *     (SignInit/Update/Final) to finish signing later.
 *
 * @param cms             [IN] CMS SignedData handle that will own the signer (must be SignedData type)
 * @param prvKey          [IN] Private key used for signing (required for one-shot signing, optional when msg is NULL)
 * @param cert            [IN] Signer certificate used to derive identifier fields
 * @param msg             [IN] Message buffer to sign; set to NULL to only create SignerInfo for streaming usage
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
 * @brief Initialize streaming operation for CMS SignedData (unified interface)
 * @par Description: Unified interface for initializing streaming operations.
 *
 * Useful for to deal sign or verify large input data.
 *
 * @attention State must be HITLS_CMS_UNINIT.
 * @param cms             [IN/OUT] CMS structure to initialize
 * @param option           [IN] Operation option，ref hitls_pki_types.h
 * @param param            [IN] Optional parameters (can be NULL).
 * @retval #HITLS_PKI_SUCCESS on success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_CMS_DataInit(int32_t option, HITLS_CMS *cms, const BSL_Param *param);

/**
 * @ingroup cms
 * @brief Update streaming operation with input data chunk (unified interface)
 * @par Description: deal with a chunk of input data. This function can be
 * called multiple times to process the input data in chunks.
 *
 * Works for both sign and verify.
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
 * @brief Finalize streaming operation (unified interface)
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

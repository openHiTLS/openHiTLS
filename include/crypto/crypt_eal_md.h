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
 * @defgroup crypt_eal_md
 * @ingroup crypt
 * @brief md algorithms of crypto module
 */

#ifndef CRYPT_EAL_MD_H
#define CRYPT_EAL_MD_H

#include <stdbool.h>
#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct EAL_MdCtx CRYPT_EAL_MdCTX;

/**
 * @ingroup crypt_eal_md
 * @brief   Create the MD context.
 *
 * After the calculation is complete, call the CRYPT_EAL_MdFreeCtx interface to release the memory.
 *
 * @param   id [IN] Algorithm ID
 * @retval  CRYPT_EAL_MdCTX, MD context pointer.
 *          NULL, if the operation fails.
 */
CRYPT_EAL_MdCTX *CRYPT_EAL_MdNewCtx(CRYPT_MD_AlgId id);

/**
 * @ingroup crypt_eal_md
 * @brief   Create a md context in the providers.
 *
 * @param libCtx [IN] Library context, if NULL, use the default provider
 * @param algId [IN] md algorithm ID.
 * @param attrName [IN] Specify expected attribute values
 *
 * @retval  CRYPT_EAL_PkeyCtx pointer.
 *          NULL, if the operation fails.
 */
CRYPT_EAL_MdCTX *CRYPT_EAL_ProviderMdNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName);

/**
 * @ingroup crypt_eal_md
 * @brief Check whether the id is valid MD algorithm ID. Not supported in provider
 *
 * @param   id [IN] MD algorithm ID.
 * @retval  true, If the value is valid.
 *          false, If the value is invalid.
 */
bool CRYPT_EAL_MdIsValidAlgId(CRYPT_MD_AlgId id);

/**
 * @ingroup crypt_eal_md
 * @brief   Return the MD algorithm ID.
 *
 * @param   pkey [IN] MD context
 * @retval  ID, MD algorithm ID.
 *          CRYPT_MD_MAX, which indicates invalid ID or the input parameter is null.
 */
int32_t CRYPT_EAL_MdGetId(CRYPT_EAL_MdCTX *ctx);

/**
 * @ingroup crypt_eal_md
 * @brief  Copy the MD context.
 *
 * @param   to [IN/OUT] Target MD context
 * @param   from [IN] Source MD context
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_MdCopyCtx(CRYPT_EAL_MdCTX *to, const CRYPT_EAL_MdCTX *from);

/**
 * @ingroup crypt_eal_md
 * @brief   Copy the MD context.
 *
 * Note that need to call the CRYPT_EAL_MdFreeCtx interface to release the memory after the duplication is complete.
 *
 * @param   ctx [IN] Source MD context
 * @retval  CRYPT_EAL_MdCTX, MD context pointer.
 *          NULL, if the operation fails.
 */
CRYPT_EAL_MdCTX *CRYPT_EAL_MdDupCtx(const CRYPT_EAL_MdCTX *ctx);

/**
 * @ingroup crypt_eal_md
 * @brief  Release the MD context.
 *
 * @param   ctx [IN] MD context. which is created by using the CRYPT_EAL_MdNewCtx interface and need to be set
 * NULL by caller.
 * @retval  Void, no return value.
 */
void CRYPT_EAL_MdFreeCtx(CRYPT_EAL_MdCTX *ctx);

/**
 * @ingroup crypt_eal_md
 * @brief  Initialize the MD context.
 *
 * @param   ctx [IN/OUT] MD context, which is created by using the CRYPT_EAL_MdNewCtx interface.
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_MdInit(CRYPT_EAL_MdCTX *ctx);

/**
 * @ingroup crypt_eal_md
 * @brief   Continuously input the data to be digested.
 *
 * @param   ctx [IN/OUT] MD context, which is created by using the CRYPT_EAL_MdNewCtx interface.
 * @param   data [IN] Data to be digested.
 * @param   len [IN] Data length.
 *                   The maximum length of sha384 and sha512 is [0, 2^128 bits).
 *                   The maximum total length of sha1, sha224, sha256, sm3, and md5 is [0, 2^64 bits).
 *                   The maximum length at a time is [0, 0xffffffff].
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_MdUpdate(CRYPT_EAL_MdCTX *ctx, const uint8_t *data, uint32_t len);

/**
 * @ingroup crypt_eal_md
 * @brief   Generate output from the sponge construction's squeezing phase.
 *
 * This interface implements the squeeze capability of sponge-based hash functions (e.g. SHAKE).
 * Can be called multiple times to generate additional output. Must be called after finalization.
 *
 * @param   ctx [IN/OUT] MD context (must be in squeezed state)
 * @param   out [OUT] Buffer to store squeezed output
 * @param   len [IN] Input: requested output length (must be <= buffer size)
 * @retval  #CRYPT_SUCCESS
 *          #CRYPT_E_SHORT_BUFFER if output buffer is too small
 *          For other error codes, see crypt_errno.h
 */
int32_t CRYPT_EAL_MdSqueeze(CRYPT_EAL_MdCTX *ctx, uint8_t *out, uint32_t len);

/**
 * @ingroup crypt_eal_md
 * @brief   Complete the digest and output the final digest result.
 *
 * @param   ctx [IN/OUT] MD context, which is created by using the CRYPT_EAL_MdNewCtx interface.
 * @param   out [OUT] Digest result cache, which needs to be created and managed by users.
 * @param   len [IN/OUT] The input parameter indicates the length of the buffer marked as "out", and the output
 * parameter indicates the valid length of the obtained "out". The length must be greater than or equal to
 * the hash length of the corresponding algorithm, the hash length can be obtained through the
 * CRYPT_EAL_MdGetDigestSize interface.
 * Requires user creation management.
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_MdFinal(CRYPT_EAL_MdCTX *ctx, uint8_t *out, uint32_t *len);

/**
 * @ingroup crypt_eal_md
 * @brief   Obtain the digest length of the algorithm output. Not supported in provider
 *
 * @param   id [IN] Algorithm ID
 * @retval  Digest length, if successful.
 *          0, if failed(in this case, the ID is invalid).
 */
uint32_t CRYPT_EAL_MdGetDigestSize(CRYPT_MD_AlgId id);

/**
 * @ingroup crypt_eal_md
 * @brief   Calculate the data digest. Not supported in provider
 *
 * @param   id [IN] Algorithm ID
 * @param   in [IN] Data to be digested
 * @param   len [IN] Data length
 * @param   out [OUT] Digest result
 * @param   len [IN/OUT] The input parameter indicates the length of the buffer marked as "out", and the output
 * parameter indicates the valid length of the obtained "out".
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_Md(CRYPT_MD_AlgId id, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

/**
 * @ingroup crypt_eal_md
 * @brief   Calculate the data digest. Supported in provider
 *
 * @param   libCtx [IN] Library context
 * @param   id [IN] Algorithm ID
 * @param   attrName [IN] Attribute name
 * @param   in [IN] Data to be digested
 * @param   len [IN] Data length
 * @param   out [OUT] Digest result
 * @param   len [IN/OUT] The input parameter indicates the length of the buffer marked as "out", and the output
 * parameter indicates the valid length of the obtained "out".
 * @retval  #CRYPT_SUCCESS.
 *          For other error codes, see crypt_errno.h.
 */
int32_t CRYPT_EAL_ProviderMd(CRYPT_EAL_LibCtx *libCtx, CRYPT_MD_AlgId id, const char *attrName,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

/**
 * @ingroup crypt_eal_md
 * @brief   Deinitialize the function.
 *
 * If need to be calculated after the CRYPT_EAL_MdDeinit is called, it needs to be initialized again.
 *
 * @param   ctx [IN] Md Context
 */
int32_t CRYPT_EAL_MdDeinit(CRYPT_EAL_MdCTX *ctx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_MD_H

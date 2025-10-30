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

#ifndef SPAKE2PLUS_H
#define SPAKE2PLUS_H

/**
* @defgroup spake2plus
* @ingroup pake
* @brief spake2+ of pake module
*/

#include "hitls_build.h"

#include <stdint.h>
#include "bsl_types.h"
#include "auth_pake.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HITLS_AUTH_PakeCtx HITLS_AUTH_PakeCtx;
typedef struct Spake2plusCtx Spake2plusCtx;

 /**
 * @ingroup spake2plus
 * @brief Create a new SPAKE2+ context
 *
 * @param curve [IN] Elliptic curve parameter identifier
 *
 * @retval Spake2plusCtx pointer if successful, NULL if failed
 */
Spake2plusCtx* Spake2PlusNewCtx(CRYPT_PKEY_ParaId curve);

 /**
 * @ingroup spake2plus
 * @brief Free SPAKE2+ context and associated resources
 *
 * @param ctx [IN] SPAKE2+ context to free
 */
void Spake2PlusFreeCtx(Spake2plusCtx* ctx);

 /**
 * @ingroup spake2plus
 * @brief Initialize the cipher suite for SPAKE2+ context
 *
 * @param ctx [IN] SPAKE2+ context
 * @param ciphersuite [IN] Cipher suite configuration containing cryptographic algorithms
 *
 * @retval #HITLS_AUTH_SUCCESS if successful
 *          Other error codes defined in hitls_errno.h if an error occurs
 */
int32_t Spake2PlusInitCipherSuite(Spake2plusCtx* ctx, HITLS_AUTH_PAKE_CipherSuite* ciphersuite);

 /**
 * @ingroup spake2plus
 * @brief Register pre-computed parameters for SPAKE2+ requester
 *
 * @param ctx [IN] PAKE context
 * @param kdfCtx [IN] KDF context
 * @param exist_w0 [IN] Pre-computed w0 parameter which can be null
 * @param exist_w1 [IN] Pre-computed w1 parameter which can be null
 * @param exist_l [IN] Pre-computed L point which can be null
 *
 * @retval #HITLS_AUTH_SUCCESS if successful
 *          Other error codes defined in hitls_errno.h if an error occurs
 */
int32_t HITLS_AUTH_Spake2plusReqRegister(HITLS_AUTH_PakeCtx* ctx, CRYPT_EAL_KdfCTX* kdfCtx,
    BSL_Buffer exist_w0, BSL_Buffer exist_w1, BSL_Buffer exist_l);

 /**
 * @ingroup spake2plus
 * @brief Register pre-computed parameters for SPAKE2+ responder
 *
 * @param ctx [IN] PAKE context
 * @param exist_w0 [IN] Pre-computed w0 parameter
 * @param exist_w1 [IN] Pre-computed w1 parameter
 * @param exist_l [IN] Pre-computed L point
 *
 * @retval #HITLS_AUTH_SUCCESS if successful
 *          Other error codes defined in hitls_errno.h if an error occurs
 */
int32_t HITLS_AUTH_Spake2plusRespRegister(HITLS_AUTH_PakeCtx* ctx,
    BSL_Buffer exist_w0, BSL_Buffer exist_w1, BSL_Buffer exist_l);

 /**
 * @ingroup spake2plus
 * @brief Perform SPAKE2+ requester setup phase
 *
 * @param ctx [IN] PAKE context
 * @param x [IN] random number for key generation which can be null
 * @param shareP [OUT] Output public share point to be sent to responder
 *
 * @retval #HITLS_AUTH_SUCCESS Setup successful
 *          Other error codes defined in hitls_errno.h if an error occurs
 */
int32_t HITLS_AUTH_Spake2plusReqSetup(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer x, BSL_Buffer *shareP);

 /**
 * @ingroup spake2plus
 * @brief Perform SPAKE2+ responder setup phase
 *
 * @param ctx [IN] PAKE context
 * @param y [IN] Input scalar for key generation which can be null
 * @param shareP [IN] Public share point received from requester
 * @param shareV [OUT] Output public share point to be sent to requester
 * @param confirmV [OUT] Output confirmation value for initial verification
 *
 * @retval #HITLS_AUTH_SUCCESS Setup successful
 *          Other error codes defined in hitls_errno.h if an error occurs
 */
int32_t HITLS_AUTH_Spake2plusRespSetup(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer y,
    BSL_Buffer shareP, BSL_Buffer *shareV, BSL_Buffer *confirmV);

 /**
 * @ingroup spake2plus
 * @brief Derive session keys for SPAKE2+ requester
 *
 * @param ctx [IN] PAKE context
 * @param shareV [IN] Public share point received from responder
 * @param confirmV [IN] Confirmation value received from responder
 * @param confirmP [OUT] Output confirmation value for responder verification
 * @param out [OUT] Output derived key material
 *
 * @retval #HITLS_AUTH_SUCCESS Key derivation successful
 *          Other error codes defined in hitls_errno.h if an error occurs
 */
int32_t HITLS_AUTH_Spake2plusReqDerive(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer shareV,
    BSL_Buffer confirmV, BSL_Buffer *confirmP, BSL_Buffer *out);

 /**
 * @ingroup spake2plus
 * @brief Derive session keys for SPAKE2+ responder
 *
 * @param ctx [IN] PAKE context
 * @param confirmP [IN] Confirmation value received from requester
 * @param out [OUT] Output derived key material
 *
 * @retval #HITLS_AUTH_SUCCESS Key derivation successful
 *          Other error codes defined in hitls_errno.h if an error occurs
 */
int32_t HITLS_AUTH_Spake2plusRespDerive(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer confirmP, BSL_Buffer *out);
 
 /**
 * @ingroup spake2plus
 * @brief Get internal context from PAKE context
 *
 * @param ctx [IN] PAKE context
 *
 * @retval non-NULL Internal SPAKE2+ context pointer
 *          NULL Invalid context
 */
void* HITLS_AUTH_PakeGetInternalCtx(HITLS_AUTH_PakeCtx *ctx);

 /**
 * @ingroup spake2plus
 * @brief Get password from PAKE context
 *
 * @param ctx [IN] PAKE context
 *
 * @retval BSL_Buffer containing the authentication password
 */
BSL_Buffer HITLS_AUTH_PakeGetPassword(HITLS_AUTH_PakeCtx *ctx);

 /**
 * @ingroup spake2plus
 * @brief Get prover from PAKE context
 *
 * @param ctx [IN] PAKE context
 *
 * @retval BSL_Buffer containing the prover information
 */
BSL_Buffer HITLS_AUTH_PakeGetProver(HITLS_AUTH_PakeCtx *ctx);

 /**
 * @ingroup spake2plus
 * @brief Get verifier identity from PAKE context
 *
 * @param ctx [IN] PAKE context
 *
 * @retval BSL_Buffer containing verifier identity information
 */
BSL_Buffer HITLS_AUTH_PakeGetVerifier(HITLS_AUTH_PakeCtx *ctx);

 /**
 * @ingroup spake2plus
 * @brief Get context data from PAKE context
 *
 * @param ctx [IN] PAKE context
 *
 * @retval BSL_Buffer containing additional protocol context data
 */
BSL_Buffer HITLS_AUTH_PakeGetContext(HITLS_AUTH_PakeCtx *ctx);

#ifdef __cplusplus
}
#endif

#endif // SPAKE2PLUS_H
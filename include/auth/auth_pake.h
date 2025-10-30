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
 * @defgroup auth_pake
 * @ingroup auth
 * @brief pake of crypto module
 */

#ifndef AUTH_PAKE_H
#define AUTH_PAKE_H

#include <stdint.h>
#include "crypt_algid.h"
#include "bsl_types.h"
#include "crypt_eal_provider.h"
#include "bsl_obj.h"
#include "crypt_eal_kdf.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HITLS_AUTH_PakeCtx HITLS_AUTH_PakeCtx;

typedef enum {
    HITLS_AUTH_PAKE_INVALID = 0,
    HITLS_AUTH_PAKE_SPAKE2PLUS = 1,
} HITLS_AUTH_PAKE_Type;

typedef enum {
    HITLS_AUTH_PAKE_REQ = 0,
    HITLS_AUTH_PAKE_RESP = 1,
} HITLS_AUTH_PAKE_Role;

typedef struct {
    HITLS_AUTH_PAKE_Type type;
    union {
        struct {
            CRYPT_PKEY_ParaId curve;
            CRYPT_MD_AlgId hash;
            CRYPT_KDF_HKDF_AlgId kdf;
            CRYPT_MAC_AlgId mac;
        } spake2plus;
    } params;
} HITLS_AUTH_PAKE_CipherSuite;

typedef struct {
    CRYPT_KDF_AlgId algId;
    union {
        struct {
            CRYPT_MAC_AlgId mac;
            int32_t iteration;
            BSL_Buffer salt;
        } pbkdf2;
    }param;
} HITLS_AUTH_PAKE_KDF;

typedef enum {
    HITLS_AUTH_PAKE_REQ_REGISTER = 0x1001,
    HITLS_AUTH_PAKE_RESP_REGISTER = 0x1002,
} HITLS_AUTH_PAKE_CtrlCmd;

/**
 * @ingroup auth_pake
 * @brief Create a new PAKE context
 *
 * @param libCtx [IN] Library context
 * @param attrName [IN] Provider attribute name
 * @param type [IN] PAKE protocol type
 * @param role [IN] Protocol role (requester or responder)
 * @param cipherSuite [IN] Cryptographic algorithms configuration
 * @param password [IN] User password for authentication
 * @param prover [IN] Prover identity information
 * @param verifier [IN] Verifier identity information
 * @param context [IN] Additional protocol context data
 *
 * @retval HITLS_AUTH_PakeCtx pointer if successful, NULL if failed
 */
HITLS_AUTH_PakeCtx *HITLS_AUTH_PakeNewCtx(CRYPT_EAL_LibCtx *libCtx, const char *attrName,
    HITLS_AUTH_PAKE_Type type, HITLS_AUTH_PAKE_Role role,
    HITLS_AUTH_PAKE_CipherSuite cipherSuite, BSL_Buffer password, BSL_Buffer prover,
    BSL_Buffer verifier, BSL_Buffer context);

/**
 * @ingroup auth_pake
 * @brief Free PAKE context and associated resources
 *
 * @param ctx [IN] PAKE context to free
 */
void HITLS_AUTH_PakeFreeCtx(HITLS_AUTH_PakeCtx *ctx);


/**
 * @ingroup auth_pake
 * @brief Register pre-computed parameters for PAKE requester
 *
 * @param ctx [IN] PAKE context
 * @param cmd [IN] Control command
 * @param kdfctx [IN] KDF context if needed(for sapke2+ verifier, can be null)
 * @param in0 [IN] First pre-computed parameter which can be null(for spake2+, w0)
 * @param in1 [IN] Second pre-computed parameter which can be null(for spake2+ w1)
 * @param in2 [IN] Third pre-computed parameter which can be null(for spake2+ L)
 *
 * @retval #HITLS_AUTH_SUCCESS if successful
 *          Other error codes defined in hitls_errno.h if an error occurs
 */
int32_t HITLS_AUTH_Pake_Ctrl(HITLS_AUTH_PakeCtx *ctx, HITLS_AUTH_PAKE_CtrlCmd cmd, CRYPT_EAL_KdfCTX *kdfctx,
    BSL_Buffer in0, BSL_Buffer in1, BSL_Buffer in2);

/**
 * @ingroup auth_pake
 * @brief Perform PAKE requester setup phase
 *
 * @param ctx [IN] PAKE context
 * @param in [IN] Input data for setup computation(for spake2+,x which can be null)
 * @param out [OUT] Output buffer for generated protocol message(for spake2+,shareP)
 *
 * @retval #HITLS_AUTH_SUCCESS Setup successful
 *          Other error codes defined in hitls_errno.h if an error occurs
 */
int32_t HITLS_AUTH_PakeReqSetup(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer in, BSL_Buffer *out);

/**
 * @ingroup auth_pake
 * @brief Perform PAKE responder setup phase
 *
 * @param ctx [IN] PAKE context
 * @param in0 [IN] First input message (for spake2+,y which can be null)
 * @param in1 [IN] Second input message (for spake2+,shareP)
 * @param out0 [OUT] First output response message(for spake2+,shareV)
 * @param out1 [OUT] Second output response message (for spake2+,confirmV)
 *
 * @retval #HITLS_AUTH_SUCCESS Setup successful
 *          Other error codes defined in hitls_errno.h if an error occurs
 */
int32_t HITLS_AUTH_PakeRespSetup(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer in0, BSL_Buffer in1,
    BSL_Buffer *out0, BSL_Buffer *out1);

/**
 * @ingroup auth_pake
 * @brief Derive session keys for PAKE requester
 *
 * @param ctx [IN] PAKE context
 * @param in0 [IN] First input message from responder(for spake2+,shareV)
 * @param in1 [IN] Second input message from responder(for spake2+,confirmV)
 * @param out0 [OUT] First output response message(for spake2+,confirmP)
 * @param out1 [OUT] Derived key material(for spake2+,kShared)
 *
 * @retval #HITLS_AUTH_SUCCESS Key derivation successful
 *          Other error codes defined in hitls_errno.h if an error occurs
 */
int32_t HITLS_AUTH_PakeReqDerive(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer in0, BSL_Buffer in1,
    BSL_Buffer *out0, BSL_Buffer *out1);

/**
 * @ingroup auth_pake
 * @brief Derive session keys for PAKE responder
 *
 * @param ctx [IN] PAKE context
 * @param in0 [IN] Input message from requester(for spake2+,confirmP)
 * @param out0 [OUT] Derived key material(for spake2+,kShared)
 *
 * @retval #HITLS_AUTH_SUCCESS Key derivation successful
 *          Other error codes defined in hitls_errno.h if an error occurs
 */
int32_t HITLS_AUTH_PakeRespDerive(HITLS_AUTH_PakeCtx *ctx, BSL_Buffer in0, BSL_Buffer *out0);

/**
 * @ingroup auth_pake
 * @brief Get KDF context for PAKE key derivation
 *
 * @param ctx [IN] PAKE context
 * @param kdf [IN] KDF algorithm configuration
 *
 * @retval #CRYPT_EAL_KdfCTX pointer if successful, NULL if failed
 */
CRYPT_EAL_KdfCTX* HITLS_AUTH_PakeGetKdfCtx(HITLS_AUTH_PakeCtx* ctx, HITLS_AUTH_PAKE_KDF kdf);
#ifdef __cplusplus
}
#endif // __cplusplus

#endif // AUTH_PAKE_H

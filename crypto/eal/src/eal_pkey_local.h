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

#ifndef EAL_PKEY_LOCAL_H
#define EAL_PKEY_LOCAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_PKEY)

#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_local_types.h"
#include "crypt_eal_pkey.h"
#include "sal_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
* @ingroup  EAL
*
* Pkey session structure
*/
struct EAL_PkeyCtx {
    bool isProvider;
    EAL_PkeyUnitaryMethod *method;
    void *key;
    void *extData;
    CRYPT_PKEY_AlgId id;
    BSL_SAL_RefCount references;
};

/**
 * @ingroup crypt_method
 * @brief Generate the default method of the signature algorithm.
 *
 * @param id [IN] Algorithm ID.
 *
 * @return success: Pointer to EAL_PkeyMethod
 * For other error codes, see crypt_errno.h.
 */
const EAL_PkeyMethod *CRYPT_EAL_PkeyFindMethod(CRYPT_PKEY_AlgId id);
#ifdef __cplusplus
}
#endif // __cplusplus

#ifdef HITLS_CRYPTO_SPAKE2P
/* Include for SPAKE2P context and control definitions */
#include "crypt_spake2p.h"

/*
 * SPAKE2+ EAL wrapper function declarations.
 * These functions are implemented in eal_pkey_method.c and are part
 * of the EAL_PkeyMethod structure for SPAKE2P.
 */
CRYPT_SPAKE2P_Ctx *EAL_SPAKE2P_NewCtx(void);
void EAL_SPAKE2P_FreeCtx(CRYPT_SPAKE2P_Ctx *ctx);
int32_t EAL_SPAKE2P_Ctrl(CRYPT_SPAKE2P_Ctx *ctx, int32_t opt, void *val, uint32_t len);
/*
 * EAL_SPAKE2P_ComputeShareKey:
 * For SPAKE2+, the primary key exchange and session key derivation (Ke, KcA, KcB)
 * are managed through the Ctrl interface. This function could be used to retrieve
 * the main derived key (Ke) after the protocol successfully completes, or it might
 * be set to NULL in the EAL_PkeyMethod if the Ctrl mechanism is solely used.
 * The 'peerKeyCtx' is not directly used in SPAKE2+ in the same way as in traditional DH;
 * peer's public message is passed via Ctrl.
 */
int32_t EAL_SPAKE2P_ComputeShareKey(CRYPT_SPAKE2P_Ctx *ctx, /* const CRYPT_SPAKE2P_Ctx *peerKeyCtx, (unused) */
                                   const void *peerKeyCtx_unused, /* Placeholder to match generic signature */
                                   uint8_t *secret, uint32_t *secretLen);
#endif // HITLS_CRYPTO_SPAKE2P


#endif // HITLS_CRYPTO_PKEY

#endif // EAL_PKEY_LOCAL_H

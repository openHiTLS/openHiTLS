/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
    const EAL_PkeyMethod *method;
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

#endif // HITLS_CRYPTO_PKEY

#endif // EAL_PKEY_LOCAL_H

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
    EAL_PkeyUnitaryMethod method;
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

/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef EAL_MD_LOCAL_H
#define EAL_MD_LOCAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_MD)

#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef enum {
    CRYPT_MD_STATE_NEW = 0,
    CRYPT_MD_STATE_INIT,
    CRYPT_MD_STATE_UPDATE,
    CRYPT_MD_STATE_FINAL
} CRYPT_MD_WORKSTATE;

struct EAL_MdCtx {
    const EAL_MdMethod *method;  /* algorithm operation entity */
    void *data;        /* Algorithm ctx, mainly context */
    uint32_t state;
    CRYPT_MD_AlgId id;
};

/**
 * @ingroup eal
 * @brief Method for generating the hash algorithm
 *
 * @param id [IN] Algorithm ID
 *
 * @return Pointer to CRYPT_MD_Method
 * For other error codes, see crypt_errno.h.
 */
const EAL_MdMethod *EAL_MdFindMethod(CRYPT_MD_AlgId id);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_MD

#endif // EAL_MD_LOCAL_H

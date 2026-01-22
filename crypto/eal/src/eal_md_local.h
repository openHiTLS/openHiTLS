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
    CRYPT_MD_STATE_FINAL,
    CRYPT_MD_STATE_SQUEEZE
} CRYPT_MD_WORKSTATE;

struct EAL_MdCtx {
    bool isProvider;
    EAL_MdUnitaryMethod *method;  /* algorithm operation entity */
#ifdef HITLS_CRYPTO_MD_MB
    EAL_MdMBMethod mbMethod; /* multi-buffer operation entity */
#endif
    void *data;        /* Algorithm ctx, mainly context */
    uint32_t state;
    CRYPT_MD_AlgId id;
};

#ifdef HITLS_CRYPTO_MD_MB
EAL_MdMBMethod *EAL_MdFindMbMethod(CRYPT_MD_AlgId id, EAL_MdMBMethod *method);
#endif

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

int32_t EAL_Md(CRYPT_MD_AlgId id, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_MD

#endif // EAL_MD_LOCAL_H

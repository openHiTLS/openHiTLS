/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef EAL_MAC_LOCAL_H
#define EAL_MAC_LOCAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_MAC)

#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef enum {
    CRYPT_MAC_STATE_NEW = 0,
    CRYPT_MAC_STATE_INIT,
    CRYPT_MAC_STATE_UPDATE,
    CRYPT_MAC_STATE_FINAL
} CRYPT_MAC_WORKSTATE;

typedef enum {
    CRYPT_MAC_HMAC = 0,
    CRYPT_MAC_INVALID
} CRYPT_MAC_ID;

struct EAL_MacCtx {
    union {
        const EAL_MacMethod *macMeth; // combined algorithm
        const EAL_CipherMethod *modeMeth;
        const void *masMeth;
    };
    void *ctx;  // MAC context
    CRYPT_MAC_AlgId id;
    CRYPT_MAC_WORKSTATE state;
};

typedef struct {
    uint32_t id;
    CRYPT_MAC_ID macId;
    union {
        CRYPT_MD_AlgId mdId;
        CRYPT_SYM_AlgId symId;
    };
} EAL_MacAlgMap;

int32_t EAL_MacFindMethod(CRYPT_MAC_AlgId id, EAL_MacMethLookup *lu);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_MAC

#endif // EAL_MAC_LOCAL_H

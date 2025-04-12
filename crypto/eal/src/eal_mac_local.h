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
    CRYPT_MAC_CMAC,
    CRYPT_MAC_CBC_MAC,
    CRYPT_MAC_SIPHASH,
    CRYPT_MAC_GMAC,
    CRYPT_MAC_INVALID
} CRYPT_MAC_ID;

struct EAL_MacCtx {
    bool isProvider;
    EAL_MacUnitaryMethod *macMeth; // combined algorithm
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

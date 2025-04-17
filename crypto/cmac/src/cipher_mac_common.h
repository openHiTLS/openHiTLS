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

#ifndef CIPHER_MAC_COMMON_H
#define CIPHER_MAC_COMMON_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_CBC_MAC) || defined(HITLS_CRYPTO_CMAC)
#include <stdint.h>
#include "crypt_local_types.h"
#include "crypt_cmac.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define CIPHER_MAC_MAXBLOCKSIZE 16

struct Cipher_MAC_Ctx {
    const EAL_SymMethod *method;
    void *key;
    /* Stores the intermediate process data of CBC_MAC. The length is the block size. */
    uint8_t data[CIPHER_MAC_MAXBLOCKSIZE];
    uint8_t left[CIPHER_MAC_MAXBLOCKSIZE];
    uint32_t len; /* Length of a non-integral data block */
};

typedef struct Cipher_MAC_Ctx Cipher_MAC_Common_Ctx;

#ifdef HITLS_CRYPTO_CBC_MAC
struct CBC_MAC_Ctx {
    Cipher_MAC_Common_Ctx common;
    CRYPT_PaddingType paddingType;
};
#endif

int32_t CipherMacInitCtx(Cipher_MAC_Common_Ctx *ctx, const EAL_SymMethod *method);

void CipherMacDeinitCtx(Cipher_MAC_Common_Ctx *ctx);

int32_t CipherMacInit(Cipher_MAC_Common_Ctx *ctx, const uint8_t *key, uint32_t len);

int32_t CipherMacUpdate(Cipher_MAC_Common_Ctx *ctx, const uint8_t *in, uint32_t len);

void CipherMacReinit(Cipher_MAC_Common_Ctx *ctx);

void CipherMacDeinit(Cipher_MAC_Common_Ctx *ctx);

int32_t CipherMacGetMacLen(const Cipher_MAC_Common_Ctx *ctx, void *val, uint32_t len);

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif // #if defined(HITLS_CRYPTO_CBC_MAC) || defined(HITLS_CRYPTO_CMAC)

#endif // CIPHER_MAC_COMMON_H

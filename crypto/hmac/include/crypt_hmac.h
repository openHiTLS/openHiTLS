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

#ifndef CRYPT_HMAC_H
#define CRYPT_HMAC_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HMAC

#include <stdint.h>
#include "crypt_local_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define HMAC_MAXBLOCKSIZE 144
#define HMAC_MAXOUTSIZE   64

typedef struct HMAC_Ctx CRYPT_HMAC_Ctx;

CRYPT_HMAC_Ctx *CRYPT_HMAC_NewCtx(CRYPT_MAC_AlgId id);
CRYPT_HMAC_Ctx *CRYPT_HMAC_NewCtxEx(void *libCtx, CRYPT_MAC_AlgId id);
int32_t CRYPT_HMAC_Init(CRYPT_HMAC_Ctx *ctx, const uint8_t *key, uint32_t len);
int32_t CRYPT_HMAC_InitEx(CRYPT_HMAC_Ctx *ctx, const uint8_t *key, uint32_t len, BSL_Param *param);
int32_t CRYPT_HMAC_Update(CRYPT_HMAC_Ctx *ctx, const uint8_t *in, uint32_t len);
int32_t CRYPT_HMAC_Final(CRYPT_HMAC_Ctx *ctx, uint8_t *out, uint32_t *len);
int32_t CRYPT_HMAC_Reinit(CRYPT_HMAC_Ctx *ctx);
int32_t CRYPT_HMAC_Deinit(CRYPT_HMAC_Ctx *ctx);
uint32_t CRYPT_HMAC_GetMacLen(CRYPT_HMAC_Ctx *ctx);
int32_t CRYPT_HMAC_Ctrl(CRYPT_HMAC_Ctx *ctx, uint32_t opt, void *val, uint32_t len);
#ifdef HITLS_CRYPTO_PROVIDER
int32_t CRYPT_HMAC_SetParam(CRYPT_HMAC_Ctx *ctx, const BSL_Param *param);
#else
#define CRYPT_HMAC_SetParam NULL
#endif // HITLS_CRYPTO_PROVIDER
void CRYPT_HMAC_FreeCtx(CRYPT_HMAC_Ctx *ctx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // HITLS_CRYPTO_HMAC

#endif // CRYPT_HMAC_H

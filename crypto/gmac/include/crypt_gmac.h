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

#ifndef CRYPT_GMAC_H
#define CRYPT_GMAC_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_GMAC
#include <stdint.h>
#include "crypt_types.h"
#include "crypt_modes_gcm.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

MODES_GCM_Ctx *CRYPT_GMAC_NewCtx(CRYPT_MAC_AlgId id);

int32_t CRYPT_GMAC_Init(MODES_GCM_Ctx *ctx, const uint8_t *key, uint32_t len, void *param);

int32_t CRYPT_GMAC_Update(MODES_GCM_Ctx *ctx, const uint8_t *in, uint32_t len);

int32_t CRYPT_GMAC_Final(MODES_GCM_Ctx *ctx, uint8_t *out, uint32_t *len);

void CRYPT_GMAC_FreeCtx(MODES_GCM_Ctx *ctx);

void CRYPT_GMAC_Deinit(MODES_GCM_Ctx *ctx);

int32_t CRYPT_GMAC_Ctrl(MODES_GCM_Ctx *ctx, int32_t opt, void *val, uint32_t len);

#define CRYPT_GMAC_DupCtx MODES_GCM_DupCtx

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif
#endif
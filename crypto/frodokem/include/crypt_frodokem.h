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

#ifndef CRYPT_FRODOKEM_H
#define CRYPT_FRODOKEM_H

#include <stdint.h>
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

// FrodoKEM key management context
typedef struct Frodokem_Ctx CRYPT_FRODOKEM_Ctx;

CRYPT_FRODOKEM_Ctx *CRYPT_FRODOKEM_NewCtx(void);
CRYPT_FRODOKEM_Ctx *CRYPT_FRODOKEM_NewCtxEx(void *libCtx);
int32_t CRYPT_FRODOKEM_Gen(CRYPT_FRODOKEM_Ctx *ctx);
int32_t CRYPT_FRODOKEM_SetPrvKeyEx(CRYPT_FRODOKEM_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_FRODOKEM_SetPubKeyEx(CRYPT_FRODOKEM_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_FRODOKEM_GetPrvKeyEx(CRYPT_FRODOKEM_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_FRODOKEM_GetPubKeyEx(CRYPT_FRODOKEM_Ctx *ctx, BSL_Param *param);
CRYPT_FRODOKEM_Ctx *CRYPT_FRODOKEM_DupCtx(CRYPT_FRODOKEM_Ctx *srcCtx);
int32_t CRYPT_FRODOKEM_Cmp(CRYPT_FRODOKEM_Ctx *ctx1, CRYPT_FRODOKEM_Ctx *ctx2);
int32_t CRYPT_FRODOKEM_Ctrl(CRYPT_FRODOKEM_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen);
void CRYPT_FRODOKEM_FreeCtx(CRYPT_FRODOKEM_Ctx *ctx);

int32_t CRYPT_FRODOKEM_EncapsInit(CRYPT_FRODOKEM_Ctx *ctx, const BSL_Param *params);
int32_t CRYPT_FRODOKEM_DecapsInit(CRYPT_FRODOKEM_Ctx *ctx, const BSL_Param *params);
int32_t CRYPT_FRODOKEM_Encaps(CRYPT_FRODOKEM_Ctx *ctx, uint8_t *ciphertext, uint32_t *ctLen, uint8_t *sharedSecret,
                              uint32_t *ssLen);
int32_t CRYPT_FRODOKEM_Decaps(CRYPT_FRODOKEM_Ctx *ctx, const uint8_t *ciphertext, uint32_t ctLen, uint8_t *sharedSecret,
                              uint32_t *ssLen);

#ifdef __cplusplus
}
#endif

#endif // CRYPT_FRODOKEM_H

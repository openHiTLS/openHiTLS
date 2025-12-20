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

#ifndef CRYPT_MCELIECE_H
#define CRYPT_MCELIECE_H

#include <stdint.h>
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Mceliece_Ctx CRYPT_MCELIECE_Ctx;

CRYPT_MCELIECE_Ctx *CRYPT_MCELIECE_NewCtx(void);
CRYPT_MCELIECE_Ctx *CRYPT_MCELIECE_NewCtxEx(void *libCtx);
int32_t CRYPT_MCELIECE_Gen(CRYPT_MCELIECE_Ctx *ctx);
int32_t CRYPT_MCELIECE_SetPrvKeyEx(CRYPT_MCELIECE_Ctx *ctx, const BSL_Param *param);
int32_t CRYPT_MCELIECE_SetPubKeyEx(CRYPT_MCELIECE_Ctx *ctx, const BSL_Param *param);
int32_t CRYPT_MCELIECE_GetPrvKeyEx(CRYPT_MCELIECE_Ctx *ctx, BSL_Param *param);
int32_t CRYPT_MCELIECE_GetPubKeyEx(CRYPT_MCELIECE_Ctx *ctx, BSL_Param *param);
CRYPT_MCELIECE_Ctx *CRYPT_MCELIECE_DupCtx(const CRYPT_MCELIECE_Ctx *src_ctx);
int32_t CRYPT_MCELIECE_Cmp(CRYPT_MCELIECE_Ctx *ctx1, CRYPT_MCELIECE_Ctx *ctx2);
int32_t CRYPT_MCELIECE_Ctrl(CRYPT_MCELIECE_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen);
void CRYPT_MCELIECE_FreeCtx(CRYPT_MCELIECE_Ctx *ctx);

int32_t CRYPT_MCELIECE_EncapsInit(CRYPT_MCELIECE_Ctx *ctx, const BSL_Param *params);
int32_t CRYPT_MCELIECE_DecapsInit(CRYPT_MCELIECE_Ctx *ctx, const BSL_Param *params);
int32_t CRYPT_MCELIECE_Encaps(CRYPT_MCELIECE_Ctx *ctx, uint8_t *ciphertext, uint32_t *ctLen, uint8_t *sharedSecret,
                              uint32_t *ssLen);
int32_t CRYPT_MCELIECE_Decaps(CRYPT_MCELIECE_Ctx *ctx, const uint8_t *ciphertext, uint32_t ctLen, uint8_t *sharedSecret,
                              uint32_t *ssLen);

#ifdef __cplusplus
}
#endif

#endif /* CRYPT_MCELIECE_H */

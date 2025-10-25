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

#ifndef MCELIECE_H
#define MCELIECE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "internal/mceliece_params.h"
#include "mceliece_types.h"
#include "bsl_params.h"

// Mceliece key management context
typedef struct {
    McelieceParams *para;
    CMPublicKey *publicKey;
    CMPrivateKey *privateKey;
} Mceliece_Ctx;

// Declare the top-level API functions that your test files will call.
// These names match the ones used in the Microsoft reference tests.

void *PQCP_MCELIECE_NewCtx(void);
int32_t PQCP_MCELIECE_Gen(Mceliece_Ctx *ctx);
int32_t PQCP_MCELIECE_SetPrvKey(Mceliece_Ctx *ctx, BSL_Param *param);
int32_t PQCP_MCELIECE_SetPubKey(Mceliece_Ctx *ctx, BSL_Param *param);
int32_t PQCP_MCELIECE_GetPrvKey(Mceliece_Ctx *ctx, BSL_Param *param);
int32_t PQCP_MCELIECE_GetPubKey(Mceliece_Ctx *ctx, BSL_Param *param);
Mceliece_Ctx *PQCP_MCELIECE_DupCtx(Mceliece_Ctx *src_ctx);
int32_t PQCP_MCELIECE_Cmp(Mceliece_Ctx *ctx1, Mceliece_Ctx *ctx2);
int32_t PQCP_MCELIECE_Ctrl(Mceliece_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen);
void PQCP_MCELIECE_FreeCtx(Mceliece_Ctx *ctx);

int32_t PQCP_MCELIECE_EncapsInit(Mceliece_Ctx *ctx, const BSL_Param *params);
int32_t PQCP_MCELIECE_DecapsInit(Mceliece_Ctx *ctx, const BSL_Param *params);
int32_t PQCP_MCELIECE_Encaps(
    Mceliece_Ctx *ctx, uint8_t *ciphertext, uint32_t *ctLen, uint8_t *sharedSecret, uint32_t *ssLen);
int32_t PQCP_MCELIECE_Decaps(
    Mceliece_Ctx *ctx, const uint8_t *ciphertext, uint32_t ctLen, uint8_t *sharedSecret, uint32_t *ssLen);

#ifdef __cplusplus
}
#endif

#endif  // MCELIECE_H

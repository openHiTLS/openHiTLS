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

#ifndef CRYPT_MODES_CCM_H
#define CRYPT_MODES_CCM_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CCM

#include <stdint.h>
#include <stdbool.h>
#include "crypt_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct ModesCcmCtx MODES_CCM_Ctx;
// CCM mode universal implementation
MODES_CCM_Ctx *MODES_CCM_NewCtx(int32_t algId);
int32_t MODES_CCM_InitCtx(MODES_CCM_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, const BSL_Param *param, bool enc);

int32_t MODES_CCM_Update(MODES_CCM_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int32_t MODES_CCM_Final(MODES_CCM_Ctx *modeCtx, uint8_t *out, uint32_t *outLen);
int32_t MODES_CCM_DeInitCtx(MODES_CCM_Ctx *modeCtx);
int32_t MODES_CCM_Ctrl(MODES_CCM_Ctx *modeCtx, int32_t opt, void *val, uint32_t len);
void MODES_CCM_FreeCtx(MODES_CCM_Ctx *modeCtx);

// AES CCM optimization implementation
int32_t AES_CCM_Update(MODES_CCM_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

int32_t MODES_CCM_UpdateEx(MODES_CCM_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CCM

#endif // CRYPT_MODES_CCM_H

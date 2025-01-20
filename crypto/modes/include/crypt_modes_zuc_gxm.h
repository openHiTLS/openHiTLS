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

#ifndef CRYPT_MODES_ZUC_GXM_H
#define CRYPT_MODES_ZUC_GXM_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ZUC_GXM

#include <stdint.h>
#include <stdbool.h>
#include "crypt_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct ModesZucGxmCtx MODES_ZUC_GXM_Ctx;

// GXM mode universal implementation
MODES_ZUC_GXM_Ctx *MODES_ZUC_GXM_NewCtx(int32_t algId);
int32_t MODES_ZUC_GXM_InitCtx(MODES_ZUC_GXM_Ctx *modeCtx, const uint8_t *key, uint32_t keyLen, const uint8_t *iv,
    uint32_t ivLen, const BSL_Param *param, bool enc);

int32_t MODES_ZUC_GXM_Update(MODES_ZUC_GXM_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int32_t MODES_ZUC_GXM_Final(MODES_ZUC_GXM_Ctx *modeCtx, uint8_t *out, uint32_t *outLen);
int32_t MODES_ZUC_GXM_DeInitCtx(MODES_ZUC_GXM_Ctx *modeCtx);
int32_t MODES_ZUC_GXM_Ctrl(MODES_ZUC_GXM_Ctx *modeCtx, int32_t cmd, void *val, uint32_t valLen);
void MODES_ZUC_GXM_FreeCtx(MODES_ZUC_GXM_Ctx *modeCtx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_GCM

#endif // CRYPT_MODES_GCM_H

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
 
#ifndef CRYPT_ML_DSA_H
#define CRYPT_ML_DSA_H
#include <stdint.h>
#include "crypt_types.h"
#include "bsl_params.h"

typedef struct CryptMlDsaCtx CRYPT_ML_DSA_Ctx;

CRYPT_ML_DSA_Ctx *CRYPT_ML_DSA_NewCtx(void);

CRYPT_ML_DSA_Ctx *CRYPT_ML_DSA_NewCtxEx(void *libCtx);

void CRYPT_ML_DSA_FreeCtx(CRYPT_ML_DSA_Ctx *ctx);

CRYPT_ML_DSA_Ctx *CRYPT_ML_DSA_DupCtx(CRYPT_ML_DSA_Ctx *ctx);

int32_t CRYPT_ML_DSA_Ctrl(CRYPT_ML_DSA_Ctx *ctx, CRYPT_PkeyCtrl opt, void *val, uint32_t len);

int32_t CRYPT_ML_DSA_GenKey(CRYPT_ML_DSA_Ctx *ctx);

int32_t CRYPT_ML_DSA_SignData(CRYPT_ML_DSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen);

int32_t CRYPT_ML_DSA_VerifyData(CRYPT_ML_DSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t signLen);

int32_t CRYPT_ML_DSA_Sign(CRYPT_ML_DSA_Ctx *ctx, int32_t hashId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen);

int32_t CRYPT_ML_DSA_Verify(CRYPT_ML_DSA_Ctx *ctx, int32_t hashId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t signLen);

int32_t CRYPT_ML_DSA_SetPrvKey(CRYPT_ML_DSA_Ctx *ctx, const BSL_Param *param);

int32_t CRYPT_ML_DSA_SetPubKey(CRYPT_ML_DSA_Ctx *ctx, const BSL_Param *param);

int32_t CRYPT_ML_DSA_GetPrvKey(const CRYPT_ML_DSA_Ctx *ctx, BSL_Param *param);

int32_t CRYPT_ML_DSA_GetPubKey(const CRYPT_ML_DSA_Ctx *ctx, BSL_Param *param);

int32_t CRYPT_ML_DSA_Cmp(const CRYPT_ML_DSA_Ctx *a, const CRYPT_ML_DSA_Ctx *b);

#endif    // CRYPT_ML_DSA_H